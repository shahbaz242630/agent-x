// Approving a spend request waiting for approval (PRD §4.2, §7.2; BR-09,
// BR-10; ADR-003 §7; ADR-006 §6–§11; Phase 3 B4b; partner decisions 1 and 3):
// an admin or finance approver, proved with a passkey. APPROVED, keeping the
// reservation and order claim its decision made (core `approveRequest`),
// only if it would still be decided the same way now.
//
// Each of the ask and the confirm weighs it again, as a decision does
// (`weigh`), in ADR-006's lock order, against everything as it now stands:
// - its own reservation and claim left out (`except`): the engine adds its
//   amount again, and its own claim is no duplicate of it;
// - in the month its capacity is held in (sealed with its decision), not the
//   month it is now: a request decided on the 31st and approved on the 1st
//   is counted where its money already sits;
// - the agent's mandate, the two policies and the supplier must be the
//   versions it was decided against, the key it asked with still live, and
//   the engine must still say ALLOW or REQUIRE_APPROVAL (an approver may
//   approve over the threshold, never past a DENY or REQUIRE_NEW_MANDATE):
//   otherwise REQUEST_CHANGED (409), for the agent to ask again (SEC-LIM-10);
// - one past its 72 hours, that the expiry job hasn't reached yet, is
//   refused (REQUEST_EXPIRED, 409) and then expired at once, its reservation
//   and claim released (SEC-LIM-12), in a transaction of its own.
// A frozen organisation approves nothing (ORG_FROZEN, decision 3). One no
// longer waiting is REQUEST_NOT_WAITING; none of the organisation's is
// NOT_FOUND; anything tampered with, or holdings that don't match its
// decision, INTEGRITY_FAILED.
//
// The step-up is bound to the organisation and the request's latest signed
// event (as a reject's, without a reason): any move since makes it another's.
// Anything else that changes between the ask and the confirm is found by the
// confirm's own weighing.
//
// Lock order (ADR-006 §6): the idempotency key (0), the session's challenges
// (0b, confirm only), the organisation (2), the member's membership (2a), the
// agent (3) and the key it asked with (3a), found by the request's IDs alone
// (an unlocked read); its mandate and policies (4), source (5), supplier (6),
// and the month its capacity is held in (7) (the confirm's locks; the ask
// reads them FOR SHARE and locks no month); the request (8); the chain head
// (12). Its reservation and claim are judged, never locked (approveRequest).
import { agentKeyOf, isLiveKey } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import { lockAgentPeriod } from '@agentx/core/modules/limit-reservations';
import { decide } from '@agentx/core/modules/policies';
import {
  approveRequest,
  decidedAgainst,
  expireRequest,
  heldAsDecidedOf,
  holdsCapacity,
  requestOf,
  type SpendRequestRecord,
  waitedOut,
} from '@agentx/core/modules/spend-requests';
import { type Clock, type IdGenerator, money } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { MandateRefused } from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { agentAlone, type DecisionTables, notFrozen, weigh } from './spend-request-decisions.ts';
import { DECIDING_ROLES } from './spend-request-rejects.ts';
import { createStepUps, createUseCaseWork, type SessionMember } from './use-case-work.ts';

export const APPROVE_OPERATION = 'spend-requests.approve';
export const APPROVE_CONFIRM_OPERATION = 'spend-requests.approve.confirm';

type ApproveTx = DatabaseTransaction<DecisionTables>;

export type ApproveAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type Approved =
  | { readonly outcome: 'approved'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface SpendRequestApprovals {
  ask(
    member: SessionMember,
    idempotent: IdempotentRequest,
    requestId: string,
    correlationId: string,
  ): Promise<ApproveAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    requestId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<Approved>;
}

/** The approval's SHA-256: the organisation and the request's latest event, IDs in lower case (see rejectHash). */
const approveHash = (orgId: string, requestEvent: string): Buffer =>
  changeHashOf([orgId.toLowerCase(), requestEvent.toLowerCase()]);

/**
 * What the request's row names, read before any lock (levels 3–7 come
 * first): each is checked against its signed state once the request is read
 * at its own level, 8.
 */
async function namedBy(tx: ApproveTx, orgId: string, requestId: string) {
  return (
    tx
      // eslint-disable-next-line agentx/authority-tables-through-signed-state -- what it names alone, each checked against its signed state in approvable
      .selectFrom('spend_requests.requests')
      .select([
        'agent_id',
        'agent_key_id',
        'supplier_id',
        'funding_source_id',
        'amount_minor',
        'currency',
        'order_reference',
      ])
      .where('org_id', '=', orgId)
      .where('id', '=', requestId)
      .executeTakeFirst()
  );
}

export function createSpendRequestApprovals({
  database,
  keys,
  ids,
  clock,
  challenges,
  logger,
}: {
  readonly database: Database<DecisionTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): SpendRequestApprovals {
  // The decisions' refusal: the request is weighed through their reads.
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });
  const stepUps = createStepUps({ challenges, Refusal: MandateRefused });

  /**
   * Levels 2–8 in order, the request weighed again: its verified read, if it
   * may be approved now; refused otherwise. The confirm locks (`decides`).
   */
  async function approvable(
    tx: ApproveTx,
    states: SignedStates,
    member: SessionMember,
    requestId: string,
    decides: boolean,
  ) {
    const { orgId } = member;
    // Read before the lock waits below, as a decision's: the instant it is weighed at.
    const now = clock.now();
    await notFrozen(tx, states, orgId);
    await work.memberIn(tx, states, member, DECIDING_ROLES);
    const named = await namedBy(tx, orgId, requestId);
    if (named === undefined) throw new MandateRefused(404, 'NOT_FOUND');
    const agent = await agentAlone(tx, states, { orgId, agentId: named.agent_id });
    const key = await agentKeyOf(tx, states, { orgId, id: named.agent_key_id }, 'share');
    if (key.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    // The month its capacity is held in, as its decision sealed it; none for a request that holds none.
    const held = await heldAsDecidedOf(tx, states, { orgId, id: requestId });
    const asked = {
      amount: money(BigInt(named.amount_minor), named.currency),
      supplierId: named.supplier_id,
      fundingSourceId: named.funding_source_id,
      orderReference: named.order_reference,
    };
    const weighed =
      held === null
        ? null
        : await weigh(tx, states, orgId, agent, asked, {
            now,
            decides,
            except: requestId,
            monthOf: () =>
              decides ? lockAgentPeriod(tx, { agentId: agent.id, month: held.month }) : Promise.resolve(held.month),
          });

    const read = await requestOf(tx, states, { orgId, id: requestId }, decides ? 'change' : 'share');
    if (read.outcome === 'missing') throw new MandateRefused(404, 'NOT_FOUND');
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    const { request } = read;
    if (request.status !== 'APPROVAL_REQUIRED') throw new MandateRefused(409, 'REQUEST_NOT_WAITING');
    // Still waiting, its latest signed event is its decision, which its 72 hours run from (as expireRequest's).
    if (waitedOut(read.state.recordedAt, now)) throw new MandateRefused(409, 'REQUEST_EXPIRED');
    const against = decidedAgainst(read.state);
    // A waiting request holds capacity, sealed with its decision; and its row names what its signed state does.
    if (
      weighed === null ||
      request.agentId !== agent.id ||
      against.agentKeyId !== named.agent_key_id ||
      request.supplierId !== asked.supplierId ||
      request.fundingSourceId !== asked.fundingSourceId ||
      request.amount.minor !== asked.amount.minor ||
      request.amount.currency !== asked.amount.currency ||
      request.orderReference !== asked.orderReference
    ) {
      throw new MandateRefused(503, 'INTEGRITY_FAILED');
    }

    const made = decide(weighed.input);
    const unchanged =
      key.outcome === 'found' &&
      isLiveKey(key.key, now) &&
      weighed.mandate !== null &&
      weighed.mandate.versionId === against.mandateVersionId &&
      made.versions.organizationPolicy === against.organizationPolicyVersionId &&
      made.versions.mandatePolicy === against.mandatePolicyVersionId &&
      weighed.supplier !== null &&
      weighed.supplier.currentVersionId === against.supplierVersionId &&
      holdsCapacity(made.decision);
    if (!unchanged) throw new MandateRefused(409, 'REQUEST_CHANGED');
    return read;
  }

  /**
   * One found past its 72 hours is refused with nothing changed (its
   * transaction rolled back); then expired, in a transaction of its own, as
   * the expiry job would (SEC-LIM-12).
   */
  async function expiredIfDue<Unwritten extends { readonly outcome: 'conflict' | 'busy' } | Refused>(
    answer: Unwritten,
    orgId: string,
    requestId: string,
    correlationId: string,
  ): Promise<Unwritten> {
    if (answer.outcome === 'refused' && answer.code === 'REQUEST_EXPIRED') {
      await work.inOrganisation(orgId, correlationId, (tx, states) =>
        expireRequest(tx, states, keys, { orgId, id: requestId }, clock.now()),
      );
    }
    return answer;
  }

  return {
    async ask(member, idempotent, requestId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const read = await approvable(tx, states, member, requestId, false);
        return stepUps.ask(tx, member, {
          action: APPROVE_OPERATION,
          changeHash: approveHash(member.orgId, read.state.eventId),
        });
      });
      if (isUnwritten(done)) return expiredIfDue(done, member.orgId, requestId, correlationId);
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, requestId, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const read = await approvable(tx, states, member, requestId, true);
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: APPROVE_OPERATION, changeHash: approveHash(member.orgId, read.state.eventId) },
          { passkeyRequired: true },
        );
        const key = { orgId: member.orgId, id: requestId };
        const approved = await approveRequest(tx, states, keys, key, {
          userId: member.userId,
          stepUp: stepUpDetails(consumed),
        });
        // The judging raised the alarm: nothing is approved on holdings changed past the app.
        if (approved === 'mismatch') throw new MandateRefused(503, 'INTEGRITY_FAILED');
        return { status: 200, resourceId: requestId };
      });
      if (isUnwritten(done)) return expiredIfDue(done, member.orgId, requestId, correlationId);
      // The request as it now stands, once approved or answered for its key.
      return work.answered(member.orgId, correlationId, async (tx, states) => {
        const found = await requestOf(tx, states, { orgId: member.orgId, id: done.result.resourceId });
        if (found.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
        // Requests are never deleted (0039's grants): one approved is there.
        if (found.outcome !== 'found')
          throw new Error(`An approved spend request is missing: ${done.result.resourceId}`);
        return { outcome: 'approved' as const, request: found.request };
      });
    },
  };
}
