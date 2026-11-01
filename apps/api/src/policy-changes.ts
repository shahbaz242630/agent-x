// Changing a policy, the organisation's own or a mandate's (PRD §5; BR-06;
// SEC-LIM-11; partner decision 5, S91; Phase 2 C3): an admin's, proved with a
// passkey, in force at once (a policy only narrows, so nothing waits for an
// acceptance), and every admin and approver told (0038). Each change is a new
// version; the first makes the policy.
//
// - The ask (`policies.organization.change`, `policies.mandate.change`): the
//   admin read again; every check the confirm makes; a challenge bound to the
//   organisation, the policy, its latest signed event (none for one never
//   set) and the rules' hash, so the step-up makes these very rules on the
//   policy as it stood when asked; answered 202.
// - The confirm (`….confirm`): the same rules sent again with the challenge,
//   the same checks under the policies' lock, the challenge consumed, then the
//   version, with the step-up's evidence on its event, and the notice, in the
//   same transaction.
// - The checks: the day's budget (POLICY_CHANGES_SPENT, 100); the currency
//   one the deployment takes, and a mandate's (POLICY_CURRENCY_REFUSED); every
//   supplier the organisation's (POLICY_SUPPLIER_UNKNOWN); for a mandate's,
//   the mandate open (MANDATE_ENDED) and the rules within its terms, the
//   version in force or else the draft waiting (POLICY_WIDER_THAN_MANDATE).
//   The organisation's is weighed against each mandate by the engine (C2),
//   which takes the strictest.
// - The organisation's monthly cap per agent (decision 15, E2): its admin
//   chooses an amount or none with every change of it, bound into the
//   step-up and kept on the version's event (monthly-cap-choice.ts). A
//   mandate's policy names no choice.
// - `show`, every member: the policy as it stands, or none set.
// - `preview`, an admin's (E5d, decision 19): the requests waiting for
//   approval the rules would reject, and why (policy-waiting.ts), checked as
//   a change is but writing nothing, so the admin sees them before choosing.
//
// Lock order (ADR-006 §6): the idempotency key, the policies' lock (confirm),
// the session's challenges (0b, confirm), the admin's membership (2a), the
// mandate (4) and its version, the policy (4, after the mandates), the
// challenge consumed, the new version, the chain head last.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import {
  currencyAllowed,
  isEnded,
  MOST_POLICY_CHANGES_A_DAY,
  onePolicyChangeAtATime,
  policyChangesSince,
  policyOf,
  type PolicyRules,
  policyRules,
  type PolicyScope,
  type PolicyVersionRecord,
  rulesHash,
  setPolicy,
  widerThanMandate,
} from '@agentx/core/modules/mandates';
import type { Outbox } from '@agentx/core/modules/notifications';
import type { ApprovalWaitHours } from '@agentx/core/modules/spend-requests';
import { suppliersFound } from '@agentx/core/modules/suppliers';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, holdBrake, type IdempotentRequest, isUnwritten, ORGANISATION_BRAKE } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  MandateRefused,
  type MandateTx,
  mandateIn,
  organizationChoicesOf,
  policyRulesIn,
  toldAdminsAndApprovers,
  versionIn,
} from './mandate-reads.ts';
import { waitChoiceDetails } from './approval-wait-choice.ts';
import { capChoiceDetails, type MonthlyCapChoice } from './monthly-cap-choice.ts';
import {
  rejectWaiting,
  type WaitingChoice,
  waitingChosen,
  waitingDetails,
  waitingHashParts,
  type WaitingPlan,
  waitingPlan,
} from './policy-waiting.ts';
import type { Refused } from './refused.ts';
import type { DecisionTables } from './spend-request-decisions.ts';
import { createStepUps, createUseCaseWork, type SessionMember } from './use-case-work.ts';

/** Each kind's operations: the ask, which the step-up challenge names as its action too, and its confirm. */
export const POLICY_OPERATIONS = {
  organization: { ask: 'policies.organization.change', confirm: 'policies.organization.change.confirm' },
  mandate: { ask: 'policies.mandate.change', confirm: 'policies.mandate.change.confirm' },
} as const satisfies Record<PolicyScope, { ask: string; confirm: string }>;

/** Who may change a policy: an admin, with a passkey (decision 5). */
export const CHANGING_ROLES = ['admin'] as const;

/**
 * The confirm's choice checked against its plan: a refusal here (one listed
 * now, none now, or more now) is a plan changed since the ask, whose choice
 * passed it, so it is the step-up's refusal (S118 review, 80): the admin asks
 * again and sees the plan as it is.
 */
function confirmedChoice(plan: WaitingPlan, waiting: WaitingChoice | undefined): WaitingChoice | null {
  try {
    return waitingChosen(plan, waiting);
  } catch (error) {
    if (error instanceof MandateRefused) throw new MandateRefused(403, 'STEP_UP_FAILED');
    throw error;
  }
}

/** No waiting request weighed yet: an ask's plan until its transaction has read one. */
const NONE_WAITING: WaitingPlan = { rejected: [], more: false, leftover: [], weighedTo: null };

/** The mandate a target names, in lower case as its rows hold it; null for the organisation's own. */
const mandateIdOf = (target: PolicyTarget): string | null =>
  target.scope === 'mandate' ? target.mandateId.toLowerCase() : null;

/** Which policy: the organisation's own, or a mandate's. */
export type PolicyTarget =
  { readonly scope: 'organization' } | { readonly scope: 'mandate'; readonly mandateId: string };

/** A policy as the routes show it: what it is a policy of, and its version in force, or none set. */
export interface PolicyView {
  readonly scope: PolicyScope;
  /** The organisation's ID for its own, the mandate's for a mandate's. */
  readonly id: string;
  readonly mandateId: string | null;
  readonly current: PolicyVersionRecord | null;
  /** The organisation's monthly cap as its admin chose it (E2), or null: not chosen, or a mandate's policy. */
  readonly monthlyCapChoice: MonthlyCapChoice | null;
  /** The organisation's approval wait as its admin chose it (E6), or null: not chosen (72 hours), or a mandate's policy. */
  readonly approvalWait: ApprovalWaitHours | null;
}

/** A change's rules, with the organisation's choices (E2's cap, E6's wait): null, and only null, for a mandate's policy. */
interface PolicyAsked {
  readonly rules: PolicyRules;
  readonly capChoice: MonthlyCapChoice | null;
  readonly approvalWait: ApprovalWaitHours | null;
}

export type PolicyChangeAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string; readonly waiting: WaitingPlan }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type PolicyChanged =
  | ({ readonly outcome: 'changed' } & PolicyView)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface PolicyChanges {
  ask(
    member: SessionMember,
    idempotent: IdempotentRequest,
    target: PolicyTarget,
    asked: PolicyAsked,
    waiting: WaitingChoice | undefined,
    correlationId: string,
  ): Promise<PolicyChangeAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    target: PolicyTarget,
    asked: PolicyAsked,
    waiting: WaitingChoice | undefined,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<PolicyChanged>;
  show(
    orgId: string,
    target: PolicyTarget,
    correlationId: string,
  ): Promise<({ readonly outcome: 'found' } & PolicyView) | Refused>;
  preview(
    member: SessionMember,
    target: PolicyTarget,
    asked: PolicyAsked,
    correlationId: string,
  ): Promise<({ readonly outcome: 'previewed' } & WaitingPlan) | Refused>;
}

/** What each kind's change records on the notice (0038). */
const NOTICE = { organization: 'organization_policy_changed', mandate: 'mandate_policy_changed' } as const;

/**
 * The change's SHA-256: the operation, the organisation, the policy, its
 * latest signed event (empty for one never set), the rules' hash and, for the
 * organisation's, the monthly cap choice and the approval wait, each with its
 * words' version, IDs in
 * lower case: any change to the policy since the ask, other rules or another
 * choice, make the step-up another change's.
 */
const changeHash = (
  scope: PolicyScope,
  orgId: string,
  policyId: string,
  existing: { readonly state: { readonly eventId: string } } | null,
  { rules, capChoice, approvalWait }: PolicyAsked,
  waiting: readonly string[],
) =>
  changeHashOf([
    POLICY_OPERATIONS[scope].ask,
    orgId.toLowerCase(),
    policyId.toLowerCase(),
    existing?.state.eventId.toLowerCase() ?? '',
    rulesHash(rules),
    ...(capChoice === null ? [] : Object.values(capChoiceDetails(capChoice)).map(String)),
    ...(approvalWait === null ? [] : Object.values(waitChoiceDetails(approvalWait)).map(String)),
    ...waiting,
  ]);

/**
 * The rules checked again (policyRules), with choices only for the
 * organisation's: the cap's saying what its rules do (an amount with a cap,
 * none without), and a wait always. The routes have checked them; this keeps
 * another caller to them.
 */
function askedOf(target: PolicyTarget, { rules, capChoice, approvalWait }: PolicyAsked): PolicyAsked {
  const expected = target.scope === 'mandate' ? null : rules.monthlyCap === null ? 'none' : 'amount';
  if (capChoice !== expected) throw new RangeError('The monthly cap choice must match the policy’s rules');
  if ((approvalWait === null) !== (target.scope === 'mandate'))
    throw new RangeError('An approval wait is chosen with the organisation’s policy alone, and always');
  return { rules: policyRules(rules), capChoice, approvalWait };
}

export function createPolicyChanges({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Database<DecisionTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): PolicyChanges {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });
  const stepUps = createStepUps({ challenges, Refusal: MandateRefused });

  /** The policy, by its ID, read and verified: null for one never set; INTEGRITY_FAILED for one that can't be believed. */
  const policyIn = async (tx: MandateTx, states: SignedStates, orgId: string, id: string, lock: 'share' | 'change') => {
    const read = await policyOf(tx, states, { orgId, id }, lock);
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    return read.outcome === 'missing' ? null : read;
  };

  /** Which policy the target names, its ID: the mandate read (`share`) and open for a mandate's, with its rules within it. */
  const targeted = async (
    tx: MandateTx,
    states: SignedStates,
    orgId: string,
    target: PolicyTarget,
    rules: PolicyRules,
  ) => {
    if (target.scope === 'organization') {
      if (!(await currencyAllowed(tx, rules.currency))) throw new MandateRefused(409, 'POLICY_CURRENCY_REFUSED');
      return { id: orgId.toLowerCase(), mandateId: null };
    }
    const { mandate } = await mandateIn(tx, states, orgId, target.mandateId, 'share');
    if (isEnded(mandate.status)) throw new MandateRefused(409, 'MANDATE_ENDED');
    // 0035 keeps a version in force or a draft waiting on every mandate.
    const shown = mandate.currentVersionId ?? mandate.pendingVersionId;
    if (shown === null) throw new Error(`A mandate has no version: ${mandate.id}`);
    const terms = await versionIn(tx, states, orgId, mandate.id, shown);
    if (rules.currency !== terms.perOrderLimit.currency) throw new MandateRefused(409, 'POLICY_CURRENCY_REFUSED');
    if (widerThanMandate(rules, terms).length > 0) throw new MandateRefused(409, 'POLICY_WIDER_THAN_MANDATE');
    return { id: mandate.id, mandateId: mandate.id };
  };

  /** Every check a change makes, ask and confirm alike: the policy targeted, and the policy read (`share` or `change`). */
  const changeable = async (
    tx: MandateTx,
    states: SignedStates,
    member: SessionMember,
    target: PolicyTarget,
    rules: PolicyRules,
    lock: 'share' | 'change',
  ) => {
    const admin = await work.memberIn(tx, states, member, CHANGING_ROLES);
    const since = new Date(clock.now().getTime() - DAY_MS);
    if ((await policyChangesSince(tx, member.orgId, since)) >= MOST_POLICY_CHANGES_A_DAY) {
      throw new MandateRefused(409, 'POLICY_CHANGES_SPENT');
    }
    const { id, mandateId } = await targeted(tx, states, member.orgId, target, rules);
    if (rules.supplierIds !== null) {
      const found = await suppliersFound(tx, member.orgId, rules.supplierIds);
      if (found.length !== rules.supplierIds.length) throw new MandateRefused(409, 'POLICY_SUPPLIER_UNKNOWN');
    }
    const existing = await policyIn(tx, states, member.orgId, id, lock);
    return { admin, id, mandateId, existing };
  };

  /**
   * The ask's, a replayed ask's and the preview's reads: every check a change
   * makes, the policy read FOR SHARE, and its waiting requests' plan.
   */
  const weighedIn = async (
    tx: MandateTx,
    states: SignedStates,
    member: SessionMember,
    target: PolicyTarget,
    rules: PolicyRules,
  ) => {
    // Read before any wait below, as a decision's: the instant the requests are weighed at.
    const now = clock.now();
    const read = await changeable(tx, states, member, target, rules, 'share');
    return {
      ...read,
      plan: await waitingPlan(tx, states, { orgId: member.orgId, now, mandateId: read.mandateId, rules }),
    };
  };

  /** The policy as it now stands, or none set. */
  const policyViewIn = async (
    tx: MandateTx,
    states: SignedStates,
    orgId: string,
    target: PolicyTarget,
  ): Promise<PolicyView> => {
    const id =
      target.scope === 'organization'
        ? orgId.toLowerCase()
        : (await mandateIn(tx, states, orgId, target.mandateId, 'share')).mandate.id;
    const current = (await policyRulesIn(tx, states, orgId, id))?.current ?? null;
    const chosen =
      target.scope === 'organization'
        ? await organizationChoicesOf(tx, states, orgId, current)
        : { capChoice: null, approvalWait: null };
    return {
      scope: target.scope,
      id,
      mandateId: target.scope === 'mandate' ? id : null,
      current,
      monthlyCapChoice: chosen.capChoice,
      approvalWait: chosen.approvalWait,
    };
  };

  return {
    async ask(member, idempotent, target, sent, waiting, correlationId) {
      let plan = NONE_WAITING;
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const asked = askedOf(target, sent);
        const read = await weighedIn(tx, states, member, target, asked.rules);
        plan = read.plan;
        const choice = waitingChosen(plan, waiting);
        return stepUps.ask(tx, member, {
          action: POLICY_OPERATIONS[target.scope].ask,
          changeHash: changeHash(
            target.scope,
            member.orgId,
            read.id,
            read.existing,
            asked,
            waitingHashParts(choice, plan),
          ),
        });
      });
      if (isUnwritten(done)) return done;
      // A replayed ask answers from its key's record, which keeps no plan: it is worked out again, as it now
      // stands, so the admin always sees one. Changed since the step-up bound it, the confirm refuses (as E4c's).
      if (done.outcome === 'replayed') {
        const again = await work.answered(member.orgId, correlationId, async (tx, states) =>
          weighedIn(tx, states, member, target, askedOf(target, sent).rules),
        );
        if ('outcome' in again) return again;
        plan = again.plan;
      }
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId, waiting: plan };
    },

    async confirm(member, idempotent, target, sent, waiting, stepUpChallengeId, correlationId) {
      const hold = (tx: MandateTx) => holdBrake(tx, ORGANISATION_BRAKE, member.orgId);
      const done = await work.brakeWrite(member, idempotent, correlationId, hold, async (tx, states) => {
        const asked = askedOf(target, sent);
        const { rules, capChoice, approvalWait } = asked;
        const now = clock.now();
        await onePolicyChangeAtATime(tx, member.orgId);
        const held = await challenges.hold(tx, member.sessionId);
        // 2a, before the agents the plan reads (3); `changeable` reads it again.
        await work.memberIn(tx, states, member, CHANGING_ROLES);
        const read: { changed?: Awaited<ReturnType<typeof changeable>> } = {};
        const scope = { orgId: member.orgId, now, mandateId: mandateIdOf(target), rules };
        const plan = await waitingPlan(tx, states, scope, {
          decides: true,
          locked: async () => {
            read.changed = await changeable(tx, states, member, target, rules, 'change');
          },
        });
        if (read.changed === undefined) throw new Error('A policy change weighed its waiting requests unlocked');
        const { admin, id, mandateId, existing } = read.changed;
        // The ask's choice passed its plan: one this plan refuses means it isn't the plan the step-up bound.
        const choice = confirmedChoice(plan, waiting);
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          {
            action: POLICY_OPERATIONS[target.scope].ask,
            changeHash: changeHash(target.scope, member.orgId, id, existing, asked, waitingHashParts(choice, plan)),
          },
          { passkeyRequired: true },
        );
        const versionId = ids.next();
        if (choice === 'reject') {
          await rejectWaiting(tx, states, keys, plan, {
            orgId: member.orgId,
            userId: member.userId,
            evidence: { ...stepUpDetails(consumed), policyVersionId: versionId },
            now,
          });
        }
        await setPolicy(tx, states, {
          orgId: member.orgId,
          existing,
          scope: target.scope,
          mandateId,
          versionId,
          rules,
          madeBy: admin.id,
          madeAt: now,
          actor: { type: 'user', id: member.userId },
          details: {
            ...stepUpDetails(consumed),
            ...(capChoice === null ? {} : capChoiceDetails(capChoice)),
            ...(approvalWait === null ? {} : waitChoiceDetails(approvalWait)),
            ...waitingDetails(choice, plan),
          },
        });
        await outbox.add(tx, toldAdminsAndApprovers(member.orgId, NOTICE[target.scope], id));
        return { status: 200, resourceId: id };
      });
      if (isUnwritten(done)) return done;
      const view = await work.answered(member.orgId, correlationId, (tx, states) =>
        policyViewIn(tx, states, member.orgId, target),
      );
      return 'outcome' in view ? view : { outcome: 'changed', ...view };
    },

    async show(orgId, target, correlationId) {
      const view = await work.answered(orgId, correlationId, (tx, states) => policyViewIn(tx, states, orgId, target));
      return 'outcome' in view ? view : { outcome: 'found', ...view };
    },

    async preview(member, target, sent, correlationId) {
      const read = await work.answered(member.orgId, correlationId, (tx, states) =>
        weighedIn(tx, states, member, target, askedOf(target, sent).rules),
      );
      return 'outcome' in read ? read : { outcome: 'previewed', ...read.plan };
    },
  };
}
