// Rejecting a spend request waiting for approval (PRD §4.2, §7.2; BR-09,
// BR-10; ADR-003 §7; Phase 3 B4a; partner decisions 1, 3 and 6): an admin
// or finance approver, proved with a passkey, with a short reason. DENIED,
// its reservation and order claim released at once (core `rejectRequest`),
// the reason kept in the signed event and shown to the team, never to the
// agent.
//
// - The ask (`spend-requests.reject`): the member read again; the request,
//   still waiting; a challenge bound to the organisation, the request's
//   latest signed event and the reason, so the step-up rejects this request,
//   as it stood when asked, for this reason and no other; answered 202.
// - The confirm (`….confirm`): the same reads, the request for change; the
//   challenge consumed; then the reject, with the step-up's evidence and the
//   reason on its event, in the same transaction.
// - Allowed while the organisation is frozen (decision 3): a reject only
//   gives capacity back, so the organisation isn't read. One no longer
//   waiting (approved, rejected, cancelled or expired) is REQUEST_NOT_WAITING
//   (409); none of the organisation's is NOT_FOUND; one tampered with is
//   INTEGRITY_FAILED.
//
// Lock order (ADR-006 §6): the idempotency key, the session's challenges (0b,
// confirm only), the member's membership (2a), the request (8), the challenge
// consumed, its holdings (11), the chain head last (12).
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import {
  rejectRequest,
  requestOf,
  type SpendRequestRecord,
  type SpendRequestsTables,
} from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { Refused } from './refused.ts';
import {
  createStepUps,
  createUseCaseWork,
  type SessionMember,
  UseCaseRefused,
  type UseCaseTables,
} from './use-case-work.ts';

export const REJECT_OPERATION = 'spend-requests.reject';
export const REJECT_CONFIRM_OPERATION = 'spend-requests.reject.confirm';

/** Who may reject a request (partner decision 1): the admins and the finance approvers. */
export const DECIDING_ROLES = ['admin', 'approver'] as const;

type RejectTables = UseCaseTables & SpendRequestsTables & LimitReservationsTables;

export type RejectAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type Rejected =
  | { readonly outcome: 'rejected'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface SpendRequestRejects {
  /** `reason` as rejectReason keeps it: the route has checked it. */
  ask(
    member: SessionMember,
    idempotent: IdempotentRequest,
    requestId: string,
    reason: string,
    correlationId: string,
  ): Promise<RejectAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    requestId: string,
    confirm: { readonly reason: string; readonly stepUpChallengeId: string },
    correlationId: string,
  ): Promise<Rejected>;
}

/** Refused inside a reject's write, so its transaction ends there. */
class RejectRefused extends UseCaseRefused {}

/**
 * The reject's SHA-256: the organisation, the request's latest event, IDs in
 * lower case, and the reason. That event is the request's own, read from its
 * signed state, so it names the request as it stood when asked (its decision,
 * its input hash): any move since makes the step-up another's.
 */
const rejectHash = (orgId: string, requestEvent: string, reason: string): Buffer =>
  changeHashOf([orgId.toLowerCase(), requestEvent.toLowerCase(), reason]);

/** The request read (`share` or `change`) and verified: refused unless it is the organisation's, still waiting. */
async function waiting(
  tx: DatabaseTransaction<RejectTables>,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
) {
  const read = await requestOf(tx, states, key, lock);
  if (read.outcome === 'missing') throw new RejectRefused(404, 'NOT_FOUND');
  if (read.outcome === 'tampered') throw new RejectRefused(503, 'INTEGRITY_FAILED');
  if (read.request.status !== 'APPROVAL_REQUIRED') throw new RejectRefused(409, 'REQUEST_NOT_WAITING');
  return read;
}

export function createSpendRequestRejects({
  database,
  keys,
  ids,
  clock,
  challenges,
  logger,
}: {
  readonly database: Database<RejectTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): SpendRequestRejects {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: RejectRefused });
  const stepUps = createStepUps({ challenges, Refusal: RejectRefused });

  return {
    async ask(member, idempotent, requestId, reason, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, DECIDING_ROLES);
        const read = await waiting(tx, states, { orgId: member.orgId, id: requestId }, 'share');
        return stepUps.ask(tx, member, {
          action: REJECT_OPERATION,
          changeHash: rejectHash(member.orgId, read.state.eventId, reason),
        });
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, requestId, { reason, stepUpChallengeId }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        await work.memberIn(tx, states, member, DECIDING_ROLES);
        const key = { orgId: member.orgId, id: requestId };
        const read = await waiting(tx, states, key, 'change');
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: REJECT_OPERATION, changeHash: rejectHash(member.orgId, read.state.eventId, reason) },
          { passkeyRequired: true },
        );
        await rejectRequest(
          tx,
          states,
          keys,
          key,
          { userId: member.userId, reason, stepUp: stepUpDetails(consumed) },
          clock.now(),
        );
        return { status: 200, resourceId: requestId };
      });
      if (isUnwritten(done)) return done;
      // The request as it now stands, once rejected or answered for its key.
      return work.answered(member.orgId, correlationId, async (tx, states) => {
        const found = await requestOf(tx, states, { orgId: member.orgId, id: done.result.resourceId });
        if (found.outcome === 'tampered') throw new RejectRefused(503, 'INTEGRITY_FAILED');
        // Requests are never deleted (0039's grants): one rejected is there.
        if (found.outcome !== 'found')
          throw new Error(`A rejected spend request is missing: ${done.result.resourceId}`);
        return { outcome: 'rejected' as const, request: found.request };
      });
    },
  };
}
