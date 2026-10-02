// What every supplier use case does the same way (E1-2), as
// funding-source-work.ts is for sources': the organisation's transaction
// with its signed states, a write with its idempotency key claimed first, the
// member read again for the decision, a supplier read and verified, and a
// refusal thrown inside a write so everything it did rolls back. A supplier
// is answered with its current version and that version's contacts, opened
// only from the version read through its signed state, and with its payee
// and any payee change waiting as the partner described them (E2-2b): what
// the call-back confirms (ADR-014 §3), never an account number.
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type IdentityTables, membershipOf, type Role } from '@agentx/core/modules/identity';
import type { Notice, NotificationsTables } from '@agentx/core/modules/notifications';
import {
  contactsOf,
  type NameCheck,
  registrationOf,
  type RegistrationRecord,
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

/** The tables the supplier use cases work on: the outbox too, for the notices a change writes (E2-2b). */
export type SupplierTables = IdentityTables & SuppliersTables & DirectoryTables & AuditTables & NotificationsTables;
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

/** A version's payee as the partner described it (E2): its registration, the masked hint, and the name check's answer. */
export interface PayeeShown {
  readonly registrationId: string;
  readonly payeeHint: string | null;
  readonly nameCheck: NameCheck | null;
  readonly maskedName: string | null;
}

/**
 * A supplier as the members' routes show it: its signed state, its current
 * version, that version's contacts and payee, and the payee change waiting
 * for its admin's confirmation, if any (E2-2b).
 */
export interface SupplierView {
  readonly supplier: SupplierRecord;
  readonly version: VersionRecord;
  readonly contacts: SupplierContacts;
  readonly payee: PayeeShown | null;
  readonly pending: { readonly version: VersionRecord; readonly payee: PayeeShown | null } | null;
}

/** A change of a supplier, as the use cases answer it: the supplier as it now stands, a step-up asked, or a refusal. */
export type SupplierChangeWrite =
  | ({ readonly outcome: 'changed' } & SupplierView)
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

/** A notice about a supplier, for every active member and for the contacts that count, as the sender finds them. */
export const toldEveryone = (
  orgId: string,
  supplierId: string,
  kind:
    | 'supplier_payee_changed'
    | 'supplier_verified'
    | 'supplier_details_changed'
    | 'supplier_suspended'
    | 'supplier_reactivated',
): Notice[] => {
  const about = { orgId, kind, membershipId: null, role: null, aboutId: supplierId };
  return [
    { ...about, recipientUserId: null },
    { ...about, recipientUserId: null, toContacts: true },
  ];
};

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

  /** A version of the supplier's, read and verified: INTEGRITY_FAILED for one that can't be believed. */
  const versionIn = async (tx: SupplierTx, states: SignedStates, orgId: string, supplierId: string, id: string) => {
    const read = await versionOf(tx, states, { orgId, id }, supplierId);
    if (read.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    // 0032's keys hold a supplier to versions of its own, and one removed past the app reads as tampered
    // (its events outlive it; supplier-registry.db.test.ts), so none is missing.
    if (read.outcome === 'missing') throw new Error(`A supplier names a version not its own: ${id}`);
    return read.version;
  };

  /**
   * The registration that gave a version its payee, read (`share`) and
   * verified, or null for a version with none yet: INTEGRITY_FAILED for one
   * that can't be believed. Versions are never locked for change, so reading
   * one before its registration waits on nothing.
   */
  const registrationFor = async (
    tx: SupplierTx,
    states: SignedStates,
    orgId: string,
    version: VersionRecord,
  ): Promise<RegistrationRecord | null> => {
    if (version.registrationId === null) return null;
    const read = await registrationOf(tx, states, { orgId, id: version.registrationId }, version.supplierId, 'share');
    if (read.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    // 0032's key holds a version to a registration, and addVersion to one of its own supplier's.
    if (read.outcome === 'missing') throw new Error(`A version names a registration not its supplier's: ${version.id}`);
    return read.registration;
  };

  /** A version's payee as the partner described it, or null for a version with none yet. */
  const payeeOf = async (
    tx: SupplierTx,
    states: SignedStates,
    orgId: string,
    version: VersionRecord,
  ): Promise<PayeeShown | null> => {
    const registration = await registrationFor(tx, states, orgId, version);
    if (registration === null) return null;
    const { nameCheck, maskedName } = registration;
    return { registrationId: registration.id, payeeHint: version.payeeHint, nameCheck, maskedName };
  };

  /**
   * A version's contacts, opened from a version read through its signed state
   * in this transaction: INTEGRITY_FAILED for contacts that won't open, logged
   * by IDs alone, never a contact.
   */
  const contactsIn = async (
    tx: SupplierTx,
    orgId: string,
    version: VersionRecord,
    correlationId: string,
  ): Promise<SupplierContacts> => {
    try {
      return await contactsOf(tx, keys, orgId, version);
    } catch (error) {
      if (!(error instanceof SupplierContactsUnreadable)) throw error;
      logger
        .child({ correlationId, orgId })
        .error('suppliers.contacts_unreadable', { supplierId: version.supplierId, versionId: version.id });
      throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    }
  };

  /**
   * The supplier with its current version, contacts and payee, and the change
   * waiting, read (`share`) in the organisation's transaction: NOT_FOUND for
   * one it doesn't have; INTEGRITY_FAILED for a supplier, version or
   * registration that can't be believed, or contacts that won't open.
   */
  const viewIn = async (
    tx: SupplierTx,
    states: SignedStates,
    orgId: string,
    supplierId: string,
    correlationId: string,
  ): Promise<SupplierView> => {
    const { supplier } = await supplierIn(tx, states, { orgId, id: supplierId }, 'share');
    const version = await versionIn(tx, states, orgId, supplier.id, supplier.currentVersionId);
    const pending =
      supplier.pendingVersionId === null
        ? null
        : await versionIn(tx, states, orgId, supplier.id, supplier.pendingVersionId);
    return {
      supplier,
      version,
      contacts: await contactsIn(tx, orgId, version, correlationId),
      payee: await payeeOf(tx, states, orgId, version),
      pending: pending === null ? null : { version: pending, payee: await payeeOf(tx, states, orgId, pending) },
    };
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

  type Written = Awaited<ReturnType<typeof write>>;

  /** A write's refusal, or its key's outcome, answered as it is. */
  const isAnswered = (done: Written): done is Extract<Written, { outcome: 'refused' | 'conflict' | 'busy' }> =>
    done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy';

  const viewAfter = async (orgId: string, correlationId: string, done: Written) =>
    isAnswered(done) ? done : view(orgId, done.result.resourceId, correlationId);

  return {
    inOrganisation,
    answered,
    supplierIn,
    versionIn,
    registrationFor,
    contactsIn,
    write,
    view,

    /** A write's answer: its refusal or its key's outcome as it is, otherwise the supplier it wrote as it now stands (on a retry too). */
    viewAfter,

    /** A change's answer: as viewAfter, the supplier `changed`. */
    changedAfter: async (orgId: string, correlationId: string, done: Written): Promise<SupplierChangeWrite> => {
      const answered = await viewAfter(orgId, correlationId, done);
      if ('outcome' in answered) return answered;
      return { outcome: 'changed', ...answered };
    },

    /** A step-up's ask answered: its refusal or its key's outcome as it is, otherwise the challenge opened (the write's resource). */
    askedAfter: (done: Written): SupplierChangeWrite =>
      isAnswered(done) ? done : { outcome: 'asked', stepUpChallengeId: done.result.resourceId },

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
