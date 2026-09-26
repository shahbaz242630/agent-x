// The organisation's integrity hold, as its admin sees and investigates it
// (ADR-012 §2, SEC-DB-10's clearing; B3+-2b-2): the use case the API's routes
// call. The hold itself, and what an investigation records, are the audit
// module's (its signed states); this adds who may: the organisation's admin,
// read again inside the transaction, active and still an admin.
//
// Showing: the hold as its newest signed event records it.
// Recording (`integrity-hold.investigate`): the key claimed first; the
// admin's membership read again; then the investigation recorded, only while
// the hold is HELD (read with the chain head's lock, last of all, ADR-006 §6).
// No step-up: recording grants nothing; clearing, which rests on it, takes
// one (B3+-2c).
//
// A refusal inside the write throws, so the key's claim and anything written
// roll back. Each statement is limited to 10 seconds.
import { createIdempotentWrites, type IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql } from 'kysely';

import type { IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import {
  type AuditTables,
  type HoldInvestigation,
  type HoldRecord,
  type InvestigationConclusion,
  type SignedStates,
  withSignedStates,
} from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { membershipOf, type MembershipsTransaction } from './memberships.ts';
import type { IdentityTables } from './tables.ts';

/** Recording an investigation: its operation, as its idempotency keys name it. */
export const INVESTIGATE_OPERATION = 'integrity-hold.investigate';

/** Who is asking: the signed-in person, in the organisation the access hook verified. */
export interface HoldAdmin {
  readonly orgId: string;
  readonly userId: string;
}

/** A refusal, with the status and code the API answers it with. */
interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}

/** The hold, as shown: CLEAR or HELD, never one that can't be believed (refused, INTEGRITY_FAILED). */
export type HoldShown =
  { readonly outcome: 'shown'; readonly hold: Exclude<HoldRecord, { outcome: 'tampered' }> } | Refused;

/** What recording answers. */
export type InvestigationWrite =
  | { readonly outcome: 'written'; readonly status: number; readonly investigation: HoldInvestigation }
  | { readonly outcome: 'conflict' | 'busy' }
  | Refused;

export interface HoldInvestigations {
  show(admin: HoldAdmin, correlationId: string): Promise<HoldShown>;
  record(
    admin: HoldAdmin,
    idempotent: IdempotentRequest,
    investigation: { readonly conclusion: InvestigationConclusion; readonly reference: string },
    correlationId: string,
  ): Promise<InvestigationWrite>;
}

/** A refusal inside a write: thrown, so the claim and all the write did roll back. */
class WriteRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`an investigation's write refused: ${code}`);
    this.name = 'WriteRefused';
    this.status = status;
    this.code = code;
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables;

export function createHoldInvestigations({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): HoldInvestigations {
  /** The person's membership, read again for this decision: active and an admin, or a refusal. */
  const mustBeAdmin = async (tx: MembershipsTransaction, states: SignedStates, admin: HoldAdmin): Promise<void> => {
    const membership = await membershipOf(tx, states, admin.orgId, admin.userId);
    if (membership.outcome === 'tampered') throw new WriteRefused(503, 'INTEGRITY_FAILED');
    if (membership.outcome !== 'active' || membership.role !== 'admin') throw new WriteRefused(403, 'FORBIDDEN');
  };

  /** Runs the work in the organisation's transaction, each statement limited to 10 seconds; a refusal is answered. */
  const inOrganisation = async <T>(
    admin: HoldAdmin,
    correlationId: string,
    work: (tx: MembershipsTransaction, states: SignedStates) => Promise<T>,
  ): Promise<T | Refused> => {
    const services = { keys, ids, logger: logger.child({ correlationId }) };
    try {
      return await withSignedStates(database, admin.orgId, services, async (tx, states) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        return work(tx, states);
      });
    } catch (error) {
      if (error instanceof WriteRefused) return { outcome: 'refused', status: error.status, code: error.code };
      throw error;
    }
  };

  return {
    async show(admin, correlationId) {
      return inOrganisation(admin, correlationId, async (tx, states): Promise<HoldShown> => {
        await mustBeAdmin(tx, states, admin);
        const hold = await states.holdRecord(tx, admin.orgId);
        if (hold.outcome === 'tampered') throw new WriteRefused(503, 'INTEGRITY_FAILED');
        return { outcome: 'shown', hold };
      });
    },

    async record(admin, idempotent, { conclusion, reference }, correlationId) {
      const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
      const done = await inOrganisation(admin, correlationId, (tx, states) =>
        idempotency.run(tx, idempotent, async () => {
          await mustBeAdmin(tx, states, admin);
          const id = ids.next();
          const recorded = await states.recordInvestigation(tx, admin.orgId, {
            id,
            actor: { type: 'user', id: admin.userId },
            conclusion,
            reference,
          });
          if (recorded.outcome === 'not_held') throw new WriteRefused(409, 'NOT_ON_HOLD');
          if (recorded.outcome === 'tampered') throw new WriteRefused(503, 'INTEGRITY_FAILED');
          return { status: 201, resourceId: id };
        }),
      );
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      // Answered from the investigation's own event, re-read by the ID the answer names, on a replay too.
      const read = await inOrganisation(admin, correlationId, (tx, states) =>
        states.holdInvestigation(tx, admin.orgId, done.result.resourceId),
      );
      if (read.outcome === 'refused') return read;
      if (read.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
      if (read.outcome === 'missing') throw new Error('an investigation recorded, or recorded before, is not there');
      return { outcome: 'written', status: done.result.status, investigation: read.investigation };
    },
  };
}
