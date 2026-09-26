// Clearing the organisation's integrity hold (ADR-012 §2, invariant 13,
// SEC-DB-10's clearing; B3+-2c-2): the organisation's admin, with step-up
// (ADR-003 §8: it restores what the hold stopped), after the investigation of
// the hold as it now stands is recorded; never the app, nor an operator alone.
// The hold and the clearing step are the audit module's; this adds who may,
// and the step-up.
//
// 1. `ask` (`integrity-hold.clear`): the key claimed first; the admin read
//    again, active and still an admin; the hold, HELD; the investigation named,
//    of that HELD state; then a step-up challenge for the admin's own session,
//    bound to the organisation, the HELD state's event and the investigation.
//    The challenge is the write's resource, so a retry answers the same one.
// 2. `confirm` (`integrity-hold.clear.confirm`): the key claimed first; every
//    authority object of the organisation verified against the log, in the
//    lock order (ADR-006 §6: the organisation, then its invitations and
//    memberships), so a hold is never cleared over a record still tampered
//    with; the admin read again; the hold's HELD state, its event bound into
//    the hash; the challenge consumed only for this session, action and hash;
//    then the audit module clears it, reading the hold with the chain head's
//    lock, last of all, and refusing a hold set or cleared since.
//
// A refusal throws inside the write, so the claim and everything written roll
// back and the same key may be sent again. Each statement is limited to 10
// seconds.
import { createIdempotentWrites, type IdempotentRequest, type SignedStateTable } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql } from 'kysely';

import type { IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, type HoldRecord, type SignedStates, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { membershipOf, type MembershipsTransaction } from './memberships.ts';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

/** Asking to clear: its operation, which the step-up challenge names as its action too. */
export const CLEAR_OPERATION = 'integrity-hold.clear';
/** Clearing, once stepped up. */
export const CLEAR_CONFIRM_OPERATION = 'integrity-hold.clear.confirm';

/** The most authority objects of one table the check before clearing reads (verifyAll's limit), unless given. */
const OBJECTS_CHECKED = 10_000;

/** Who is clearing: the signed-in admin, in the organisation the access hook verified, and their session. */
export interface ClearingAdmin {
  readonly orgId: string;
  readonly userId: string;
  /** The session the step-up binds to (ADR-003 §7: the stable session record). */
  readonly sessionId: string;
}

interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}

/** What a clearing's write answers. */
export type ClearingWrite =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'cleared'; readonly hold: Exclude<HoldRecord, { outcome: 'tampered' }> }
  | { readonly outcome: 'conflict' | 'busy' }
  | Refused;

export interface HoldClearings {
  ask(
    admin: ClearingAdmin,
    idempotent: IdempotentRequest,
    investigationId: string,
    correlationId: string,
  ): Promise<ClearingWrite>;
  confirm(
    admin: ClearingAdmin,
    idempotent: IdempotentRequest,
    investigationId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<ClearingWrite>;
}

class ClearingRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`a clearing of the integrity hold refused: ${code}`);
    this.name = 'ClearingRefused';
    this.status = status;
    this.code = code;
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables;

/** The pending change's SHA-256: the organisation, the HELD state's event, the investigation, IDs in lower case. */
const clearingHash = (orgId: string, holdEventId: string, investigationId: string): Buffer =>
  changeHashOf([orgId.toLowerCase(), holdEventId.toLowerCase(), investigationId.toLowerCase()]);

export function createHoldClearings({
  database,
  keys,
  ids,
  challenges,
  logger,
  authorityTables,
  objectsChecked = OBJECTS_CHECKED,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
  /** Every authority table, in the lock order (the product's AUTHORITY_TABLES). */
  readonly authorityTables: readonly SignedStateTable[];
  /** The most objects of one table checked before clearing; past it, the clearing fails rather than judge part. */
  readonly objectsChecked?: number;
}): HoldClearings {
  if (authorityTables.length === 0) throw new RangeError('Clearing checks every authority table first');

  /** The person's membership, read again for this decision: active and an admin, or a refusal. */
  const mustBeAdmin = async (tx: MembershipsTransaction, states: SignedStates, admin: ClearingAdmin): Promise<void> => {
    const membership = await membershipOf(tx, states, admin.orgId, admin.userId);
    if (membership.outcome === 'tampered') throw new ClearingRefused(503, 'INTEGRITY_FAILED');
    if (membership.outcome !== 'active' || membership.role !== 'admin') throw new ClearingRefused(403, 'FORBIDDEN');
  };

  /** The hold's HELD state, the event it was recorded by: or a refusal. */
  const heldEventOf = async (tx: MembershipsTransaction, states: SignedStates, orgId: string): Promise<string> => {
    const hold = await states.holdRecord(tx, orgId);
    if (hold.outcome === 'tampered') throw new ClearingRefused(503, 'INTEGRITY_FAILED');
    if (hold.outcome === 'clear') throw new ClearingRefused(409, 'NOT_ON_HOLD');
    return hold.eventId;
  };

  /**
   * Runs the write in the organisation's transaction, its key claimed first;
   * a refusal is answered, with everything it did rolled back.
   */
  const write = async (
    admin: ClearingAdmin,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: MembershipsTransaction, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const services = { keys, ids, logger: logger.child({ correlationId }) };
    const idempotency = createIdempotentWrites({ keys, logger: services.logger });
    try {
      return await withSignedStates(database, admin.orgId, services, async (tx, states) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        return idempotency.run(tx, idempotent, () => work(tx, states));
      });
    } catch (error) {
      if (error instanceof ClearingRefused)
        return { outcome: 'refused' as const, status: error.status, code: error.code };
      throw error;
    }
  };

  return {
    async ask(admin, idempotent, investigationId, correlationId) {
      const done = await write(admin, idempotent, correlationId, async (tx, states) => {
        await mustBeAdmin(tx, states, admin);
        const holdEventId = await heldEventOf(tx, states, admin.orgId);
        const investigation = await states.holdInvestigation(tx, admin.orgId, investigationId);
        if (investigation.outcome === 'tampered') throw new ClearingRefused(503, 'INTEGRITY_FAILED');
        if (investigation.outcome === 'missing' || investigation.investigation.holdEventId !== holdEventId) {
          throw new ClearingRefused(409, 'NO_INVESTIGATION');
        }
        const challenge = await challenges.open(tx, {
          sessionId: admin.sessionId,
          action: CLEAR_OPERATION,
          changeHash: clearingHash(admin.orgId, holdEventId, investigationId),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new ClearingRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(admin, idempotent, investigationId, stepUpChallengeId, correlationId) {
      const done = await write(admin, idempotent, correlationId, async (tx, states) => {
        const whole = await states.verifyAll(tx, admin.orgId, authorityTables, objectsChecked);
        if (whole.outcome === 'tampered') throw new ClearingRefused(503, 'INTEGRITY_FAILED');
        if (whole.outcome === 'too_many') throw new Error(`more ${whole.subjectType} records than clearing checks`);
        await mustBeAdmin(tx, states, admin);
        const holdEventId = await heldEventOf(tx, states, admin.orgId);
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          {
            sessionId: admin.sessionId,
            action: CLEAR_OPERATION,
            changeHash: clearingHash(admin.orgId, holdEventId, investigationId),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new ClearingRefused(403, 'STEP_UP_FAILED');
        const cleared = await states.clearIntegrityHold(tx, admin.orgId, {
          actor: { type: 'user', id: admin.userId },
          holdEventId,
          investigationId,
          stepUp: stepUpDetails(consumed),
        });
        if (cleared.outcome === 'tampered') throw new ClearingRefused(503, 'INTEGRITY_FAILED');
        if (cleared.outcome !== 'cleared') {
          throw new ClearingRefused(409, cleared.outcome === 'no_investigation' ? 'NO_INVESTIGATION' : 'HOLD_CHANGED');
        }
        return { status: 200, resourceId: cleared.eventId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      // Answered from the hold as it now stands, on a replay too.
      const read = await withSignedStates(
        database,
        admin.orgId,
        { keys, ids, logger: logger.child({ correlationId }) },
        async (tx, states) => {
          await sql`set local statement_timeout = '10s'`.execute(tx);
          return states.holdRecord(tx, admin.orgId);
        },
      );
      if (read.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
      return { outcome: 'cleared', hold: read };
    },
  };
}
