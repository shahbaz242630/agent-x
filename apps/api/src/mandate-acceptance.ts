// Accepting a mandate's waiting draft (PRD §3 `MandateEvidence`, §4.1, §7.1;
// BR-05; ADR-003 §8; Phase 2 B3): any admin, proved with a passkey (partner,
// S86), bound to the draft's terms hash, so the admin accepts these very
// terms and nothing else.
//
// - `accept` (`mandates.accept`): the admin names the draft they looked at;
//   everything confirm checks is checked now too, so an ask that can't be
//   confirmed is refused at once; answered 202 with the step-up.
// - `acceptConfirm` (`mandates.accept.confirm`): the same checks again, the
//   step-up consumed, then the draft made the version in force (ACTIVE, for a
//   first) with the step-up's evidence and the terms hash on its event,
//   and every admin and approver told (0036, partner S86), in the same
//   transaction. A version it supersedes settles its pending requests there
//   too, before the move, as the admin chose (decision 15, E4c; no default,
//   and a first acceptance takes none): `cancel` ends them (decision 4;
//   voidPendingOf, C2b), the request-voids job taking any past the batch;
//   `carry` weighs each again under the draft and carries or cancels it
//   (mandate-carry.ts), the plan shown at the ask (decision 17) and bound,
//   with the choice and its words' version, into the step-up.
// - The checks: the agent active (AGENT_NOT_ACTIVE); every mandate of the
//   agent verified (B2's open-mandate query trusts the row's status, S89
//   review); this one neither ended (MANDATE_ENDED) nor suspended
//   (MANDATE_SUSPENDED: resume it first, B4); its draft the one named and
//   waiting (MANDATE_NOT_WAITING) and not past its end
//   (MANDATE_DRAFT_EXPIRED); the source able to fund (SOURCE_NOT_USABLE)
//   and the terms within its consent when strict (MANDATE_PAST_CONSENT), as
//   the bank may have changed it since the draft.
//
// Lock order (ADR-006 §6): the idempotency key, the session's challenges
// (0b, confirm only), the admin's membership (2a), the agent (3), the
// agent's mandates in order of ID (4) and the draft, the source (5), the
// challenge consumed, the mandate's pending requests (8) and their holdings
// (11), the chain head last.
import { agentOf } from '@agentx/core/modules/agents';
import type { SignedStates, VerifiedState } from '@agentx/core/modules/audit';
import { mayFund } from '@agentx/core/modules/funding-sources';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import {
  acceptDraft,
  agentOfMandate,
  consentCheck,
  isEnded,
  type MandateRecord,
  type MandateVersionRecord,
  mandatesOfAgent,
} from '@agentx/core/modules/mandates';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { voidPendingOf } from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  consentOf,
  MandateRefused,
  type MandateTables,
  type MandateTx,
  mandateIn,
  type MandateView,
  sourceIn,
  toldAdminsAndApprovers,
  versionIn,
  viewIn,
  agentBrakeNameOfMandate,
} from './mandate-reads.ts';
import {
  carryOut,
  carryPlan,
  type CarryPlanned,
  planHashOf,
  type SupersedeChoice,
  supersedeChoiceDetails,
  supersedeHashParts,
} from './mandate-carry.ts';
import type { Refused } from './refused.ts';
import type { DecisionTables } from './spend-request-decisions.ts';
import { createStepUps, createUseCaseWork, type SessionMember } from './use-case-work.ts';

/** Accepting a mandate's draft: the ask, then its confirm. */
export const ACCEPT_OPERATION = 'mandates.accept';
export const ACCEPT_CONFIRM_OPERATION = 'mandates.accept.confirm';

/** Who may accept: any admin (partner, S86); maker-checker stays a later option (BRD §5). */
export const ACCEPTING_ROLES = ['admin'] as const;

export type AcceptAsked =
  | {
      readonly outcome: 'asked';
      readonly stepUpChallengeId: string;
      /** A carry's plan: what it will do to each pending request (decision 17); null for any other. */
      readonly carry: readonly CarryPlanned[] | null;
      /** A carry's: how many pending requests past the plan wait for the job, checked the same way (PL-47); 0 for any other. */
      readonly carryLater: number;
    }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type MandateAccepted =
  | ({ readonly outcome: 'accepted' } & MandateView)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface MandateAcceptance {
  accept(
    member: SessionMember,
    idempotent: IdempotentRequest,
    mandateId: string,
    versionId: string,
    pendingRequests: SupersedeChoice | undefined,
    correlationId: string,
  ): Promise<AcceptAsked>;
  acceptConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    mandateId: string,
    stepUpChallengeId: string,
    pendingRequests: SupersedeChoice | undefined,
    correlationId: string,
  ): Promise<MandateAccepted>;
}

/**
 * What a supersede does to the pending requests: the admin's choice, a
 * carry's plan and how many more wait for the job; neither for a first.
 */
interface Settling {
  readonly choice: SupersedeChoice | null;
  readonly plan: readonly CarryPlanned[] | null;
  readonly later: number;
}

/**
 * The acceptance's SHA-256: the organisation, the mandate's latest event and
 * the draft with its terms hash, IDs in lower case; then the choice for the
 * pending requests with its words' version, and a carry's plan. That event is
 * the mandate's own, read from its signed state, so it names the mandate as it
 * stood when asked: any change to it since (a newer draft, a suspension) makes
 * the step-up another change's, and so does another choice, or a plan changed
 * since the admin saw it (decision 17).
 */
const acceptanceHash = (
  orgId: string,
  mandateEvent: string,
  draft: MandateVersionRecord,
  { choice, plan, later }: Settling,
): Buffer =>
  changeHashOf([
    ACCEPT_OPERATION,
    orgId.toLowerCase(),
    mandateEvent.toLowerCase(),
    draft.id,
    draft.termsHash,
    ...supersedeHashParts(choice),
    plan === null ? 'none' : planHashOf(plan),
    // Whether any are left for the job, not how many: one asked meanwhile is weighed the same way, in its turn.
    later > 0 ? 'later' : 'all',
  ]);

/** A mandate as accepting reads it: its signed state, the state a change records from, and its draft. */
interface Acceptable {
  readonly mandate: MandateRecord;
  readonly state: VerifiedState;
  readonly draft: MandateVersionRecord;
}

/**
 * The mandate, of an active agent (AGENT_NOT_ACTIVE), read (`lock`) and
 * verified with every other mandate of that agent, in order of ID: one
 * tampered with refuses it (INTEGRITY_FAILED), though B2's open-mandate query
 * would have missed it (S89 review).
 */
async function ofAnActiveAgent(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandateId: string,
  lock: 'share' | 'change',
) {
  const agentId = await agentOfMandate(tx, orgId, mandateId);
  if (agentId === undefined) throw new MandateRefused(404, 'NOT_FOUND');
  const agent = await agentOf(tx, states, { orgId, id: agentId }, 'share');
  if (agent.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  // The mandate's key on its agent (0035) keeps the agent while the mandate is.
  if (agent.outcome === 'missing') throw new Error(`A mandate's agent is missing: ${mandateId}`);
  if (agent.agent.status !== 'ACTIVE') throw new MandateRefused(409, 'AGENT_NOT_ACTIVE');
  let read: Awaited<ReturnType<typeof mandateIn>> | undefined;
  // One read per mandate the agent has had: few, and only at acceptance. The others are verified, never changed.
  for (const id of await mandatesOfAgent(tx, orgId, agentId)) {
    const each = await mandateIn(tx, states, orgId, id, id === mandateId.toLowerCase() ? lock : 'share');
    if (id === mandateId.toLowerCase()) read = each;
  }
  // Found by its ID just before, its agent fixed for good: anything else is something past the app.
  if (read?.mandate.agentId !== agentId) throw new Error(`A mandate moved from its agent: ${mandateId}`);
  return read;
}

export function createMandateAcceptance({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Database<MandateTables & NotificationsTables & DecisionTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): MandateAcceptance {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });
  const stepUps = createStepUps({ challenges, Refusal: MandateRefused });

  /**
   * Every check acceptance makes, in the lock order: the mandate with its
   * draft, ready to accept. `versionId` is the draft the admin named (the
   * ask), or null for the one waiting (the confirm, whose step-up binds it).
   */
  const acceptable = async (
    tx: MandateTx,
    states: SignedStates,
    orgId: string,
    mandateId: string,
    versionId: string | null,
    lock: 'share' | 'change',
  ): Promise<Acceptable> => {
    const now = clock.now();
    const read = await ofAnActiveAgent(tx, states, orgId, mandateId, lock);
    const { mandate } = read;
    if (isEnded(mandate.status)) throw new MandateRefused(409, 'MANDATE_ENDED');
    if (mandate.status === 'SUSPENDED') throw new MandateRefused(409, 'MANDATE_SUSPENDED');
    const waiting = mandate.pendingVersionId;
    if (waiting === null || (versionId !== null && versionId.toLowerCase() !== waiting)) {
      throw new MandateRefused(409, 'MANDATE_NOT_WAITING');
    }
    const draft = await versionIn(tx, states, orgId, mandate.id, waiting);
    if (draft.endsAt !== null && draft.endsAt <= now) throw new MandateRefused(409, 'MANDATE_DRAFT_EXPIRED');
    const source = await sourceIn(tx, states, orgId, draft.fundingSourceId);
    if (!mayFund(source, now)) throw new MandateRefused(409, 'SOURCE_NOT_USABLE');
    if (consentCheck(draft, consentOf(source)).refused) throw new MandateRefused(409, 'MANDATE_PAST_CONSENT');
    return { mandate, state: read.state, draft };
  };

  /**
   * The choice checked against the mandate (one in force takes one, a first
   * none: PENDING_CHOICE_REQUIRED, PENDING_CHOICE_NOT_OFFERED), and a carry's
   * plan worked out, as the ask (`decides` false) or the confirm reads it.
   */
  const settling = async (
    tx: DatabaseTransaction<DecisionTables>,
    states: SignedStates,
    orgId: string,
    { mandate }: Acceptable,
    choice: SupersedeChoice | undefined,
    decides: boolean,
  ): Promise<Settling> => {
    if (mandate.currentVersionId === null) {
      if (choice !== undefined) throw new MandateRefused(400, 'PENDING_CHOICE_NOT_OFFERED');
      return { choice: null, plan: null, later: 0 };
    }
    if (choice === undefined) throw new MandateRefused(400, 'PENDING_CHOICE_REQUIRED');
    if (choice === 'cancel') return { choice, plan: null, later: 0 };
    const { plan, later } = await carryPlan(tx, states, {
      orgId,
      agentId: mandate.agentId,
      mandateId: mandate.id,
      now: clock.now(),
      decides,
      under: { version: 'draft' },
    });
    return { choice, plan, later };
  };

  return {
    async accept(member, idempotent, mandateId, versionId, pendingRequests, correlationId) {
      let carry: readonly CarryPlanned[] | null = null;
      let carryLater = 0;
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, ACCEPTING_ROLES);
        const read = await acceptable(tx, states, member.orgId, mandateId, versionId, 'share');
        const settled = await settling(tx, states, member.orgId, read, pendingRequests, false);
        carry = settled.plan;
        carryLater = settled.later;
        return stepUps.ask(tx, member, {
          action: ACCEPT_OPERATION,
          changeHash: acceptanceHash(member.orgId, read.state.eventId, read.draft, settled),
        });
      });
      if (isUnwritten(done)) return done;
      // A replayed ask answers from its key's record, which keeps no plan: it is worked out again, as it now
      // stands, so the admin always sees one (decision 17.4). Changed since the step-up bound it, the confirm refuses.
      if (done.outcome === 'replayed' && pendingRequests === 'carry') {
        const again = await work.answered(member.orgId, correlationId, async (tx, states) => {
          const read = await acceptable(tx, states, member.orgId, mandateId, versionId, 'share');
          const { plan, later } = await settling(tx, states, member.orgId, read, pendingRequests, false);
          return { plan, later };
        });
        if ('outcome' in again) return again;
        carry = again.plan;
        carryLater = again.later;
      }
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId, carry, carryLater };
    },

    async acceptConfirm(member, idempotent, mandateId, stepUpChallengeId, pendingRequests, correlationId) {
      const brake = agentBrakeNameOfMandate(member.orgId, mandateId);
      const done = await work.routineBrakeWrite(member, idempotent, correlationId, brake, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const admin = await work.memberIn(tx, states, member, ACCEPTING_ROLES);
        const read = await acceptable(tx, states, member.orgId, mandateId, null, 'change');
        const settled = await settling(tx, states, member.orgId, read, pendingRequests, true);
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          {
            action: ACCEPT_OPERATION,
            changeHash: acceptanceHash(member.orgId, read.state.eventId, read.draft, settled),
          },
          { passkeyRequired: true },
        );
        const evidence = { ...stepUpDetails(consumed), termsHash: read.draft.termsHash };
        const actor = { type: 'user', id: member.userId } as const;
        const now = clock.now();
        if (settled.plan !== null) {
          await carryOut(tx, states, keys, member.orgId, settled.plan, {
            draftId: read.draft.id,
            actor,
            details: evidence,
            now,
          });
        } else if (settled.choice === 'cancel') {
          const braked = { mandateId: read.mandate.id };
          await voidPendingOf(tx, states, keys, member.orgId, braked, 'MANDATE_NOT_IN_FORCE', now);
        }
        await acceptDraft(tx, states, read, {
          orgId: member.orgId,
          versionId: read.draft.id,
          acceptedBy: admin.id,
          acceptedAt: now,
          actor,
          details: {
            ...evidence,
            ...supersedeChoiceDetails(settled.choice),
            ...(settled.plan !== null && {
              carried: settled.plan.filter(({ outcome }) => outcome === 'carry').length,
              cancelled: settled.plan.filter(({ outcome }) => outcome === 'cancel').length,
            }),
            // The rest left on the version replaced for the carry job (PL-47), which reads this event to take them.
            ...(settled.later > 0 && { carryRest: true, carryLater: settled.later }),
          },
        });
        await outbox.add(tx, toldAdminsAndApprovers(member.orgId, 'mandate_accepted', read.mandate.id));
        return { status: 200, resourceId: read.mandate.id };
      });
      if (isUnwritten(done)) return done;
      const view = await work.answered(member.orgId, correlationId, (tx, states) =>
        viewIn(tx, states, member.orgId, done.result.resourceId),
      );
      return 'outcome' in view ? view : { outcome: 'accepted', ...view };
    },
  };
}
