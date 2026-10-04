// What every funding-source use case does the same way (D2-3b, D2-4), on
// use-case-work.ts's shared transaction, write, read and member check: a
// source read and verified, and the partner's answer told apart from its
// silence.
import { type FundingSourcesTables, sourceOf, type SourceRecord } from '@agentx/core/modules/funding-sources';
import type { AuditTables, SignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import type { IdentityTables } from '@agentx/core/modules/identity';
import { RailUnavailable } from '@agentx/core/modules/providers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { refused } from './refused.ts';
import { createUseCaseWork, UseCaseRefused } from './use-case-work.ts';

/** The tables the funding-source use cases work on. */
export type FundingSourceTables = IdentityTables & FundingSourcesTables & DirectoryTables & AuditTables;
export type FundingSourceTx = DatabaseTransaction<FundingSourceTables>;

/** Who is acting: a signed-in member, in the organisation the access hook verified. */
export interface FundingSourceMember {
  readonly orgId: string;
  readonly userId: string;
}

export const PARTNER_UNAVAILABLE = refused(503, 'PARTNER_UNAVAILABLE');

/** A refusal thrown inside a transaction, so everything it did rolls back. */
export class FundingSourceRefused extends UseCaseRefused {}

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

export function createFundingSourceWork(services: {
  readonly database: Database<FundingSourceTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}) {
  return {
    ...createUseCaseWork({ ...services, Refusal: FundingSourceRefused }),

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
