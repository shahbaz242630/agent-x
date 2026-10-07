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
//   transaction.
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
// challenge consumed, the chain head last.
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
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
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
  versionIn,
  viewIn,
} from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork, type SessionMember } from './use-case-work.ts';

/** Accepting a mandate's draft: the ask, then its confirm. */
export const ACCEPT_OPERATION = 'mandates.accept';
export const ACCEPT_CONFIRM_OPERATION = 'mandates.accept.confirm';

/** Who may accept: any admin (partner, S86); maker-checker stays a later option (BRD §5). */
export const ACCEPTING_ROLES = ['admin'] as const;

export type AcceptAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
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
    correlationId: string,
  ): Promise<AcceptAsked>;
  acceptConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    mandateId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<MandateAccepted>;
}

/**
 * The acceptance's SHA-256: the organisation, the mandate's latest event and
 * the draft with its terms hash, IDs in lower case. That event is the
 * mandate's own, read from its signed state, so it names the mandate as it
 * stood when asked: any change to it since (a newer draft, a suspension) makes
 * the step-up another change's.
 */
const acceptanceHash = (orgId: string, mandateEvent: string, draft: MandateVersionRecord): Buffer =>
  changeHashOf([ACCEPT_OPERATION, orgId.toLowerCase(), mandateEvent.toLowerCase(), draft.id, draft.termsHash]);

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
  readonly database: Database<MandateTables & NotificationsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): MandateAcceptance {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

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

  return {
    async accept(member, idempotent, mandateId, versionId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, ACCEPTING_ROLES);
        const { state, draft } = await acceptable(tx, states, member.orgId, mandateId, versionId, 'share');
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: ACCEPT_OPERATION,
          changeHash: acceptanceHash(member.orgId, state.eventId, draft),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new MandateRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async acceptConfirm(member, idempotent, mandateId, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const admin = await work.memberIn(tx, states, member, ACCEPTING_ROLES);
        const read = await acceptable(tx, states, member.orgId, mandateId, null, 'change');
        const consumed = await challenges.consume(
          tx,
          held,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: ACCEPT_OPERATION,
            changeHash: acceptanceHash(member.orgId, read.state.eventId, read.draft),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new MandateRefused(403, 'STEP_UP_FAILED');
        await acceptDraft(tx, states, read, {
          orgId: member.orgId,
          versionId: read.draft.id,
          acceptedBy: admin.id,
          acceptedAt: clock.now(),
          actor: { type: 'user', id: member.userId },
          details: { ...stepUpDetails(consumed), termsHash: read.draft.termsHash },
        });
        await outbox.add(tx, [
          {
            orgId: member.orgId,
            recipientUserId: null,
            kind: 'mandate_accepted',
            membershipId: null,
            role: null,
            aboutId: read.mandate.id,
          },
        ]);
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
