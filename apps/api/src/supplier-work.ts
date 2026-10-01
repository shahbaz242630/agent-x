// What every supplier use case does the same way (E1-2), as
// funding-source-work.ts is for sources': the organisation's transaction
// with its signed states, a write with its idempotency key claimed first, the
// member read again for the decision, a supplier read and verified, and a
// refusal thrown inside a write so everything it did rolls back. A supplier
// is answered with its current version and that version's contacts, opened
// only from the version read through its signed state.
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type IdentityTables, membershipOf, type Role } from '@agentx/core/modules/identity';
import {
  contactsOf,
  type SupplierContacts,
  SupplierContactsUnreadable,
  supplierOf,
  type SupplierRecord,
  type SuppliersTables,
  versionOf,
  type VersionRecord,
} from '@agentx/core/modules/suppliers';
import type { IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
import {
  createIdempotentWrites,
  type Database,
  type DatabaseTransaction,
  type IdempotentRequest,
  limitStatements,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** The tables the supplier use cases work on. */
export type SupplierTables = IdentityTables & SuppliersTables & DirectoryTables & AuditTables;
export type SupplierTx = DatabaseTransaction<SupplierTables>;

/** Who is acting: a signed-in member, in the organisation the access hook verified. */
export interface SupplierMember {
  readonly orgId: string;
  readonly userId: string;
}

/** A member acting in a session of theirs, which a step-up challenge is bound to. */
export interface SessionMember extends SupplierMember {
  readonly sessionId: string;
}

/** A refusal, as a use case answers it. */
export interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}

const refused = (status: number, code: ReasonCode): Refused => ({ outcome: 'refused', status, code });

/** A refusal thrown inside a transaction, so everything it did rolls back. */
export class SupplierRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`refused: ${code}`);
    this.name = 'SupplierRefused';
    this.status = status;
    this.code = code;
  }
}

/** A supplier as the members' routes show it: its signed state, its current version, and that version's contacts. */
export interface SupplierView {
  readonly supplier: SupplierRecord;
  readonly version: VersionRecord;
  readonly contacts: SupplierContacts;
}

/** A supplier read for a decision or a change: its record, and the state a change records from. */
type SupplierFound = Extract<Awaited<ReturnType<typeof supplierOf>>, { outcome: 'found' }>;

export function createSupplierWork({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<SupplierTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}) {
  const inOrganisation = <T>(
    orgId: string,
    correlationId: string,
    work: (tx: SupplierTx, states: SignedStates) => Promise<T>,
  ): Promise<T> =>
    withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }) }, async (tx, states) => {
      await limitStatements(tx);
      return work(tx, states);
    });

  /** A read in the organisation's transaction, a refusal inside it answered. */
  const answered = async <T extends object>(
    orgId: string,
    correlationId: string,
    work: (tx: SupplierTx, states: SignedStates) => Promise<T>,
  ): Promise<T | Refused> => {
    try {
      return await inOrganisation(orgId, correlationId, work);
    } catch (error) {
      if (error instanceof SupplierRefused) return refused(error.status, error.code);
      throw error;
    }
  };

  /** The supplier, read and verified: NOT_FOUND, or INTEGRITY_FAILED for one that can't be believed. */
  const supplierIn = async (
    tx: SupplierTx,
    states: SignedStates,
    key: { readonly orgId: string; readonly id: string },
    lock: 'share' | 'change',
  ): Promise<SupplierFound> => {
    const read = await supplierOf(tx, states, key, lock);
    if (read.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new SupplierRefused(404, 'NOT_FOUND');
    return read;
  };

  /**
   * The supplier with its current version and contacts, read (`share`) in the
   * organisation's transaction: NOT_FOUND for one it doesn't have;
   * INTEGRITY_FAILED for a supplier or version that can't be believed, or
   * contacts that won't open.
   */
  const viewIn = async (
    tx: SupplierTx,
    states: SignedStates,
    orgId: string,
    supplierId: string,
    correlationId: string,
  ): Promise<SupplierView> => {
    const { supplier } = await supplierIn(tx, states, { orgId, id: supplierId }, 'share');
    const current = await versionOf(tx, states, { orgId, id: supplier.currentVersionId }, supplier.id);
    if (current.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    // 0032's key holds a supplier to a current version of its own, and one removed past the app reads as tampered
    // (its events outlive it; supplier-registry.db.test.ts), so none is missing.
    if (current.outcome === 'missing') throw new Error(`A supplier has no current version of its own: ${supplier.id}`);
    try {
      return { supplier, version: current.version, contacts: await contactsOf(tx, keys, orgId, current.version) };
    } catch (error) {
      if (!(error instanceof SupplierContactsUnreadable)) throw error;
      // Logged by IDs alone, never a contact.
      logger
        .child({ correlationId, orgId })
        .error('suppliers.contacts_unreadable', { supplierId: supplier.id, versionId: current.version.id });
      throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    }
  };

  /** The write with its key claimed first; a refusal is answered, with everything it did rolled back. */
  const write = async (
    member: SupplierMember,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: SupplierTx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
    try {
      return await inOrganisation(member.orgId, correlationId, (tx, states) =>
        idempotency.run(tx, idempotent, () => work(tx, states)),
      );
    } catch (error) {
      if (error instanceof SupplierRefused) return refused(error.status, error.code);
      throw error;
    }
  };

  /** The supplier as the members' routes show it, in a transaction of its own. */
  const view = (orgId: string, supplierId: string, correlationId: string): Promise<SupplierView | Refused> =>
    answered(orgId, correlationId, (tx, states) => viewIn(tx, states, orgId, supplierId, correlationId));

  return {
    inOrganisation,
    answered,
    supplierIn,
    write,
    view,

    /** A write's answer: its refusal or its key's outcome as it is, otherwise the supplier it wrote as it now stands (on a retry too). */
    viewAfter: async (orgId: string, correlationId: string, done: Awaited<ReturnType<typeof write>>) => {
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return view(orgId, done.result.resourceId, correlationId);
    },

    /** The member's membership, read again for this decision: active in one of `roles`, or FORBIDDEN (INTEGRITY_FAILED if tampered with). */
    memberIn: async (tx: SupplierTx, states: SignedStates, member: SupplierMember, roles: readonly Role[]) => {
      const membership = await membershipOf(tx, states, member.orgId, member.userId);
      if (membership.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
      if (membership.outcome !== 'active' || !roles.includes(membership.role)) {
        throw new SupplierRefused(403, 'FORBIDDEN');
      }
      return membership;
    },
  };
}
