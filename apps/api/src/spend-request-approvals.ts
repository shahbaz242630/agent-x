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
// - the agent's mandate and the supplier must be the versions it was decided
//   against (a new mandate is new terms, a new supplier version new payee
//   details), the key it asked with not revoked, and the engine, under the
//   policies as they now are, must still say ALLOW or REQUIRE_APPROVAL (an
//   approver may approve over the threshold, never past a DENY or
//   REQUIRE_NEW_MANDATE): otherwise REQUEST_CHANGED (409), for the agent to
//   ask again (SEC-LIM-10). One over the mandate's own limits, sent for
//   approval as its version chose (decision 23), only an admin approves:
//   ADMIN_APPROVAL_ONLY (403) for a finance approver, who may still reject
//   it. Routine changes don't void it: a policy changed
//   since is weighed as it now is, and a key rotated out (expired, not
//   revoked) still stands behind what it asked;
// - re-checked (decisions 15.3, 16, 18; E5a): one whose supplier moved to new
//   details only through changes chosen to pause (E3, pausedFromOf), now
//   verified, isn't approved under the old details: its approver asks with
//   `recheck`, is shown what changed and how the engine weighs it now
//   (RecheckShown, bound into the step-up), and the confirm records it on the
//   approval. Without `recheck` it is RECHECK_REQUIRED (409); `recheck` on
//   one with nothing to re-check is RECHECK_NOT_OFFERED (400);
// - rejected (decision 18; E5b): one the engine now refuses only under rules
//   the team set (a limit or cap lowered, a supplier off a policy: rejectedFor)
//   is shown at the ask as rejected, with each rule and what to do, bound into
//   the step-up; the confirm rejects it (`spend_request.rejected`, the
//   approver's, with a note and the rules as `causes`), its holdings released.
//   A refusal with any stop in it (a suspended agent, mandate or source, an
//   unverified supplier: perhaps a pause the team chose) stays REQUEST_CHANGED;
// - one decided before a stop chosen to cancel (its organisation frozen, its
//   agent, mandate, source or supplier suspended or unverified, decision
//   32a, F1 G1), that the request-voids job hasn't reached yet though what was
//   stopped stands again, is REQUEST_CHANGED: the job voids it;
// - one past its wait (E6), that the expiry job hasn't reached yet, is
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
import { agentKeyOf } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import { lockAgentPeriod } from '@agentx/core/modules/limit-reservations';
import { decide, type Decision } from '@agentx/core/modules/policies';
import {
  approveRequest,
  decidedAgainst,
  expireRequest,
  decisionOf,
  holdsCapacity,
  rejectRequest,
  requestOf,
  type SpendRequestRecord,
  waitedOut,
} from '@agentx/core/modules/spend-requests';
import { type Clock, type IdGenerator, money, type ReasonCode } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { rejectedFor, rejectionNote, type RuleDenial } from './approval-rejections.ts';
import { MandateRefused } from './mandate-reads.ts';
import { overMandateLimit } from './over-limit-choice.ts';
import type { Refused } from './refused.ts';
import { agentAlone, type DecisionTables, notFrozen, weigh } from './spend-request-decisions.ts';
import { DECIDING_ROLES } from './spend-request-rejects.ts';
import { cancelledSinceOf, pausedFromOf } from './suspensions.ts';
import { createStepUps, createUseCaseWork, type SessionMember } from './use-case-work.ts';

export const APPROVE_OPERATION = 'spend-requests.approve';
export const APPROVE_CONFIRM_OPERATION = 'spend-requests.approve.confirm';

type ApproveTx = DatabaseTransaction<DecisionTables>;

/**
 * A re-check as the ask shows it and the approval keeps it (E5a): the
 * supplier's details it was decided under and those it is approved under,
 * and the engine's decision and reasons then and now.
 */
export interface RecheckShown {
  readonly fromSupplierVersionId: string;
  readonly supplierVersionId: string;
  readonly decidedAs: Decision;
  readonly decidedReasons: readonly ReasonCode[];
  readonly decision: Decision;
  readonly reasons: readonly ReasonCode[];
}

/** The words a re-check is confirmed with: the console's confirm shows them, the approval keeps their version. */
export const RECHECK_STATEMENT =
  'The supplier’s details changed after this request was decided, and a second person has verified them. ' +
  'Approving it checks it again under the new details and today’s policies, as shown: its amount, order and ' +
  'the month its money is held in are unchanged.';

/** The version of RECHECK_STATEMENT each re-check names: raised with any change to its words. */
const RECHECK_STATEMENT_VERSION = 1;

/** Past the mandate's own limits only an admin approves, as only an admin sets them (decision 23): ADMIN_APPROVAL_ONLY. */
const adminPastTheLimits = (approver: { readonly role: string }, reasons: readonly ReasonCode[]): void => {
  if (overMandateLimit(reasons) && approver.role !== 'admin') throw new MandateRefused(403, 'ADMIN_APPROVAL_ONLY');
};

/** A re-check as the step-up binds it: what changed, the decision and reasons now, and its words' version. */
const recheckHashParts = (view: RecheckShown | null): readonly string[] =>
  view === null
    ? []
    : [
        'recheck',
        String(RECHECK_STATEMENT_VERSION),
        view.fromSupplierVersionId.toLowerCase(),
        view.supplierVersionId.toLowerCase(),
        view.decision,
        view.reasons.join(','),
      ];

/** A re-check as the approval's event keeps it, beside the step-up's evidence; nothing for none. */
const recheckDetails = (view: RecheckShown | null) =>
  view === null
    ? {}
    : {
        recheckedFromSupplierVersionId: view.fromSupplierVersionId,
        recheckedSupplierVersionId: view.supplierVersionId,
        recheckedDecision: view.decision,
        recheckedReasons: view.reasons.join(' '),
        recheckStatementVersion: RECHECK_STATEMENT_VERSION,
      };

/** What confirming will do, as the ask shows it: re-checked or not, and rejected for its rules or approved. */
interface ApprovalShown {
  readonly recheck: RecheckShown | null;
  /** The rules the engine now refuses it under, so the confirm rejects it (E5b); null when it approves it. */
  readonly rejection: readonly RuleDenial[] | null;
}

export type ApproveAsked =
  | ({ readonly outcome: 'asked'; readonly stepUpChallengeId: string } & ApprovalShown)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type Approved =
  /** Approved; or rejected, the engine now refusing it under rules the team set (E5b). */
  | { readonly outcome: 'approved' | 'rejected'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface SpendRequestApprovals {
  /** `recheck`: the approver asks to re-check one whose supplier's details changed (E5a). */
  ask(
    member: SessionMember,
    idempotent: IdempotentRequest,
    requestId: string,
    recheck: boolean,
    correlationId: string,
  ): Promise<ApproveAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    requestId: string,
    stepUpChallengeId: string,
    recheck: boolean,
    correlationId: string,
  ): Promise<Approved>;
}

/**
 * The approval's SHA-256: the organisation and the request's latest event,
 * IDs in lower case (see rejectHash), any re-check as shown, and any
 * rejection with its rules.
 */
const approveHash = (orgId: string, requestEvent: string, { recheck, rejection }: ApprovalShown): Buffer =>
  changeHashOf([
    orgId.toLowerCase(),
    requestEvent.toLowerCase(),
    ...recheckHashParts(recheck),
    ...(rejection === null ? [] : ['reject', rejection.join(',')]),
  ]);

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

/** Where the supplier's details stand against those a request was decided under. */
type SupplierMove =
  | { readonly move: 'same' }
  /** New details that carried it only through changes chosen to pause (E3): re-checked, never approved as decided. */
  | { readonly move: 'carried'; readonly from: string; readonly to: string }
  /** Moved otherwise, or no supplier: it can't be approved. */
  | { readonly move: 'moved' };

async function supplierMoveOf(
  tx: ApproveTx,
  states: SignedStates,
  orgId: string,
  supplier: { readonly id: string; readonly currentVersionId: string } | null,
  decidedUnder: string | null,
): Promise<SupplierMove> {
  if (supplier === null) return { move: 'moved' };
  if (supplier.currentVersionId === decidedUnder) return { move: 'same' };
  if (decidedUnder === null) return { move: 'moved' };
  const pausedFrom = await pausedFromOf(tx, states, orgId, supplier, () => new MandateRefused(503, 'INTEGRITY_FAILED'));
  return pausedFrom.includes(decidedUnder)
    ? { move: 'carried', from: decidedUnder, to: supplier.currentVersionId }
    : { move: 'moved' };
}

/**
 * The re-check shown for one carried to new details, which must be asked
 * for; none otherwise, where asking for one is refused.
 */
function recheckShown(
  supplier: SupplierMove,
  recheck: boolean,
  request: SpendRequestRecord,
  made: { readonly decision: Decision; readonly reasons: readonly ReasonCode[] },
): RecheckShown | null {
  if (supplier.move !== 'carried') {
    if (recheck) throw new MandateRefused(400, 'RECHECK_NOT_OFFERED');
    return null;
  }
  if (!recheck) throw new MandateRefused(409, 'RECHECK_REQUIRED');
  return {
    fromSupplierVersionId: supplier.from,
    supplierVersionId: supplier.to,
    decidedAs: request.decision,
    decidedReasons: request.reasons,
    decision: made.decision,
    reasons: made.reasons,
  };
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
    recheck: boolean,
  ) {
    const { orgId } = member;
    // Read before the lock waits below, as a decision's: the instant it is weighed at.
    const now = clock.now();
    await notFrozen(tx, states, orgId);
    const approver = await work.memberIn(tx, states, member, DECIDING_ROLES);
    const named = await namedBy(tx, orgId, requestId);
    if (named === undefined) throw new MandateRefused(404, 'NOT_FOUND');
    const agent = await agentAlone(tx, states, { orgId, agentId: named.agent_id });
    const key = await agentKeyOf(tx, states, { orgId, id: named.agent_key_id }, 'share');
    if (key.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    // Its decision as sealed: the month its capacity is held in (none for a request that holds none), and its time.
    const decision = await decisionOf(tx, states, { orgId, id: requestId });
    const held = decision?.held ?? null;
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
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    // Its row was found above, and requests are never deleted (0039's grants).
    if (read.outcome !== 'found') throw new Error(`A spend request found by its row is missing: ${requestId}`);
    const { request } = read;
    if (request.status !== 'APPROVAL_REQUIRED') throw new MandateRefused(409, 'REQUEST_NOT_WAITING');
    // Its wait runs from its decision as sealed, never a later event such as a carry (E4; as expireRequest's).
    // With no decision it holds nothing sealed, so the check below refuses it.
    if (decision !== null && waitedOut(decision, now)) throw new MandateRefused(409, 'REQUEST_EXPIRED');
    if (decision !== null) {
      const ids = {
        organization: orgId,
        agent: request.agentId,
        mandate: request.mandateId,
        source: request.fundingSourceId,
        supplier: request.supplierId,
      };
      const unbelieved = () => new MandateRefused(503, 'INTEGRITY_FAILED');
      const cancelledBy = await cancelledSinceOf(tx, states, orgId, decision.seq, ids, unbelieved);
      if (cancelledBy.size > 0) throw new MandateRefused(409, 'REQUEST_CHANGED');
    }
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
    const supplierNow = await supplierMoveOf(tx, states, orgId, weighed.supplier, against.supplierVersionId);
    const unchanged =
      key.outcome === 'found' &&
      key.key.status !== 'REVOKED' &&
      weighed.mandate !== null &&
      weighed.mandate.versionId === against.mandateVersionId &&
      supplierNow.move !== 'moved';
    const rejection = holdsCapacity(made.decision) ? null : rejectedFor(made.decision, made.reasons);
    if (!unchanged || (rejection === null && !holdsCapacity(made.decision))) {
      throw new MandateRefused(409, 'REQUEST_CHANGED');
    }
    if (rejection === null) adminPastTheLimits(approver, made.reasons);
    const shown: ApprovalShown = { recheck: recheckShown(supplierNow, recheck, request, made), rejection };
    // The policies it is approved under, which may be newer than its decision's: kept with the approval.
    const weighedUnder = {
      organizationPolicyVersionId: made.versions.organizationPolicy,
      mandatePolicyVersionId: made.versions.mandatePolicy,
    };
    return { read, weighedUnder, shown };
  }

  /**
   * One found past its wait is refused with nothing changed (its
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
    async ask(member, idempotent, requestId, recheck, correlationId) {
      let shown: ApprovalShown = { recheck: null, rejection: null };
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const asked = await approvable(tx, states, member, requestId, false, recheck);
        shown = asked.shown;
        return stepUps.ask(tx, member, {
          action: APPROVE_OPERATION,
          changeHash: approveHash(member.orgId, asked.read.state.eventId, asked.shown),
        });
      });
      if (isUnwritten(done)) return expiredIfDue(done, member.orgId, requestId, correlationId);
      // A replayed ask answers from its key's record, which keeps neither a re-check nor a rejection: they are
      // worked out again, as it now stands (as E4c's plan). Changed since the step-up bound them, the confirm refuses.
      if (done.outcome === 'replayed') {
        const again = await work.answered(member.orgId, correlationId, async (tx, states) => ({
          shown: (await approvable(tx, states, member, requestId, false, recheck)).shown,
        }));
        // Refused now (expired, say), as a first ask would be: one past its wait is expired at once.
        if ('outcome' in again) return expiredIfDue(again, member.orgId, requestId, correlationId);
        shown = again.shown;
      }
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId, ...shown };
    },

    async confirm(member, idempotent, requestId, stepUpChallengeId, recheck, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const { read, weighedUnder, shown } = await approvable(tx, states, member, requestId, true, recheck);
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: APPROVE_OPERATION, changeHash: approveHash(member.orgId, read.state.eventId, shown) },
          { passkeyRequired: true },
        );
        const key = { orgId: member.orgId, id: requestId };
        const evidence = { ...stepUpDetails(consumed), ...weighedUnder, ...recheckDetails(shown.recheck) };
        if (shown.rejection !== null) {
          // Decision 18: rejected as the approver's, with what to do, its rules kept whole as `causes`.
          await rejectRequest(
            tx,
            states,
            keys,
            key,
            {
              userId: member.userId,
              reason: rejectionNote(shown.rejection),
              stepUp: { ...evidence, causes: shown.rejection.join(',') },
            },
            clock.now(),
          );
          return { status: 200, resourceId: requestId };
        }
        const approved = await approveRequest(tx, states, keys, key, { userId: member.userId, stepUp: evidence });
        // The judging raised the alarm: nothing is approved on holdings changed past the app.
        if (approved === 'mismatch') throw new MandateRefused(503, 'INTEGRITY_FAILED');
        return { status: 200, resourceId: requestId };
      });
      if (isUnwritten(done)) return expiredIfDue(done, member.orgId, requestId, correlationId);
      // The request as it now stands, once approved or answered for its key.
      return work.answered(member.orgId, correlationId, async (tx, states) => {
        const found = await requestOf(tx, states, { orgId: member.orgId, id: done.result.resourceId });
        if (found.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
        // Requests are never deleted (0039's grants): one approved or rejected is there.
        if (found.outcome !== 'found')
          throw new Error(`An approved spend request is missing: ${done.result.resourceId}`);
        const outcome = found.request.status === 'DENIED' ? ('rejected' as const) : ('approved' as const);
        return { outcome, request: found.request };
      });
    },
  };
}
