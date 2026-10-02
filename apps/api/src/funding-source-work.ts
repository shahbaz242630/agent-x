// What every funding-source use case does the same way (D2-3b, D2-4), as
// agent-writes.ts is for agents': the organisation's transaction with its
// signed states, a write with its idempotency key claimed first, the member
// read again for the decision, a source read and verified, a refusal thrown
// inside a write so everything it did rolls back, and the partner's answer
// told apart from its silence.
import { type FundingSourcesTables, sourceOf, type SourceRecord } from '@agentx/core/modules/funding-sources';
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type IdentityTables, membershipOf, type Role } from '@agentx/core/modules/identity';
import { RailUnavailable } from '@agentx/core/modules/providers';
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
import type { Refused } from './refused.ts';

/** The tables the funding-source use cases work on. */
export type FundingSourceTables = IdentityTables & FundingSourcesTables & DirectoryTables & AuditTables;
export type FundingSourceTx = DatabaseTransaction<FundingSourceTables>;

/** Who is acting: a signed-in member, in the organisation the access hook verified. */
export interface FundingSourceMember {
  readonly orgId: string;
  readonly userId: string;
}

export const refused = (status: number, code: ReasonCode): Refused => ({ outcome: 'refused', status, code });
export const PARTNER_UNAVAILABLE = refused(503, 'PARTNER_UNAVAILABLE');

/** A refusal thrown inside a transaction, so everything it did rolls back. */
export class FundingSourceRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`refused: ${code}`);
    this.name = 'FundingSourceRefused';
    this.status = status;
    this.code = code;
  }
}

/**
 * The partner says the person hasn't finished yet (at their bank, or at its
 * payee form): thrown inside the write, so nothing of it is kept, the key's
 * claim included, and asking again with the same key asks the partner again.
 */
export class StillWaiting extends Error {
  constructor() {
    super('still waiting at the partner');
    this.name = 'StillWaiting';
  }
}

/** A write's outcome, or `waiting` when the partner said StillWaiting inside it: nothing of it kept, the key's claim included. */
export async function orStillWaiting<T>(run: () => Promise<T>): Promise<T | { readonly outcome: 'waiting' }> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof StillWaiting) return { outcome: 'waiting' };
    throw error;
  }
}

/** The partner's answer, or `unavailable` when it didn't give one. */
export async function asked<T>(call: () => Promise<T>): Promise<T | 'unavailable'> {
  try {
    return await call();
  } catch (error) {
    if (error instanceof RailUnavailable) return 'unavailable';
    throw error;
  }
}

export function createFundingSourceWork({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<FundingSourceTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}) {
  const inOrganisation = <T>(
    orgId: string,
    correlationId: string,
    work: (tx: FundingSourceTx, states: SignedStates) => Promise<T>,
  ): Promise<T> =>
    withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }) }, async (tx, states) => {
      await limitStatements(tx);
      return work(tx, states);
    });

  return {
    inOrganisation,

    /** The write with its key claimed first; a refusal is answered, with everything it did rolled back. */
    write: async (
      member: FundingSourceMember,
      idempotent: IdempotentRequest,
      correlationId: string,
      work: (tx: FundingSourceTx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
    ) => {
      const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
      try {
        return await inOrganisation(member.orgId, correlationId, (tx, states) =>
          idempotency.run(tx, idempotent, () => work(tx, states)),
        );
      } catch (error) {
        if (error instanceof FundingSourceRefused) return refused(error.status, error.code);
        throw error;
      }
    },

    /** A read in the organisation's transaction, a refusal inside it answered. */
    answered: async <T extends object>(
      orgId: string,
      correlationId: string,
      work: (tx: FundingSourceTx, states: SignedStates) => Promise<T>,
    ): Promise<T | Refused> => {
      try {
        return await inOrganisation(orgId, correlationId, work);
      } catch (error) {
        if (error instanceof FundingSourceRefused) return refused(error.status, error.code);
        throw error;
      }
    },

    /** The member's membership, read again for this decision: active in one of `roles`, or FORBIDDEN (INTEGRITY_FAILED if tampered with). */
    memberIn: async (
      tx: FundingSourceTx,
      states: SignedStates,
      member: FundingSourceMember,
      roles: readonly Role[],
    ) => {
      const membership = await membershipOf(tx, states, member.orgId, member.userId);
      if (membership.outcome === 'tampered') throw new FundingSourceRefused(503, 'INTEGRITY_FAILED');
      if (membership.outcome !== 'active' || !roles.includes(membership.role)) {
        throw new FundingSourceRefused(403, 'FORBIDDEN');
      }
      return membership;
    },

    /** The source, read and verified: NOT_FOUND, or INTEGRITY_FAILED for one that can't be believed. */
    sourceIn: async (
      tx: FundingSourceTx,
      states: SignedStates,
      key: { readonly orgId: string; readonly id: string },
      lock: 'share' | 'change',
    ) => {
      const read = await sourceOf(tx, states, key, lock);
      if (read.outcome === 'tampered') throw new FundingSourceRefused(503, 'INTEGRITY_FAILED');
      if (read.outcome === 'missing') throw new FundingSourceRefused(404, 'NOT_FOUND');
      return read satisfies { source: SourceRecord };
    },
  };
}
