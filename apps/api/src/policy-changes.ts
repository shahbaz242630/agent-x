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
// - `show`, every member: the policy as it stands, or none set.
//
// Lock order (ADR-006 §6): the idempotency key, the policies' lock (confirm),
// the session's challenges (0b, confirm), the admin's membership (2a), the
// mandate (4) and its version, the policy (4, after the mandates) and its
// version, the challenge consumed, the chain head last.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import {
  currencyAllowed,
  isEnded,
  MOST_POLICY_CHANGES_A_DAY,
  onePolicyChangeAtATime,
  policyChangesSince,
  policyOf,
  type PolicyRecord,
  type PolicyRules,
  policyRules,
  type PolicyScope,
  type PolicyVersionRecord,
  policyVersionOf,
  rulesHash,
  setPolicy,
  widerThanMandate,
} from '@agentx/core/modules/mandates';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { suppliersFound } from '@agentx/core/modules/suppliers';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { MandateRefused, type MandateTables, type MandateTx, mandateIn, versionIn } from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork, type SessionMember } from './use-case-work.ts';

/** Each kind's operations: the ask, which the step-up challenge names as its action too, and its confirm. */
export const POLICY_OPERATIONS = {
  organization: { ask: 'policies.organization.change', confirm: 'policies.organization.change.confirm' },
  mandate: { ask: 'policies.mandate.change', confirm: 'policies.mandate.change.confirm' },
} as const satisfies Record<PolicyScope, { ask: string; confirm: string }>;

/** Who may change a policy: an admin, with a passkey (decision 5). */
export const CHANGING_ROLES = ['admin'] as const;

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
}

export type PolicyChangeAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
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
    rules: PolicyRules,
    correlationId: string,
  ): Promise<PolicyChangeAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    target: PolicyTarget,
    rules: PolicyRules,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<PolicyChanged>;
  show(
    orgId: string,
    target: PolicyTarget,
    correlationId: string,
  ): Promise<({ readonly outcome: 'found' } & PolicyView) | Refused>;
}

/** What each kind's change records on the notice (0038). */
const NOTICE = { organization: 'organization_policy_changed', mandate: 'mandate_policy_changed' } as const;

/**
 * The change's SHA-256: the operation, the organisation, the policy, its
 * latest signed event (empty for one never set) and the rules' hash, IDs in
 * lower case: any change to the policy since the ask, or other rules, make the
 * step-up another change's.
 */
const changeHash = (scope: PolicyScope, orgId: string, policyId: string, event: string | null, rules: PolicyRules) =>
  changeHashOf([
    POLICY_OPERATIONS[scope].ask,
    orgId.toLowerCase(),
    policyId.toLowerCase(),
    event?.toLowerCase() ?? '',
    rulesHash(rules),
  ]);

export function createPolicyChanges({
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
}): PolicyChanges {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  /** The policy, by its ID, read and verified: null for one never set; INTEGRITY_FAILED for one that can't be believed. */
  const policyIn = async (tx: MandateTx, states: SignedStates, orgId: string, id: string, lock: 'share' | 'change') => {
    const read = await policyOf(tx, states, { orgId, id }, lock);
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    return read.outcome === 'missing' ? null : read;
  };

  /** The policy's version in force, read and verified. */
  const currentOf = async (tx: MandateTx, states: SignedStates, orgId: string, policy: PolicyRecord) => {
    const read = await policyVersionOf(tx, states, { orgId, id: policy.currentVersionId }, policy.id);
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    // 0037's `current_is_its_own` holds a policy's version in force to its own.
    if (read.outcome === 'missing') throw new Error(`A policy names a version not its own: ${policy.id}`);
    return read.version;
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

  /** The policy as it now stands, or none set. */
  const viewIn = async (
    tx: MandateTx,
    states: SignedStates,
    orgId: string,
    target: PolicyTarget,
  ): Promise<PolicyView> => {
    let id = orgId.toLowerCase();
    let mandateId: string | null = null;
    if (target.scope === 'mandate') {
      ({ id } = (await mandateIn(tx, states, orgId, target.mandateId, 'share')).mandate);
      mandateId = id;
    }
    const read = await policyIn(tx, states, orgId, id, 'share');
    return {
      scope: target.scope,
      id,
      mandateId,
      current: read === null ? null : await currentOf(tx, states, orgId, read.policy),
    };
  };

  return {
    async ask(member, idempotent, target, asked, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const rules = policyRules(asked);
        const { id, existing } = await changeable(tx, states, member, target, rules, 'share');
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: POLICY_OPERATIONS[target.scope].ask,
          changeHash: changeHash(target.scope, member.orgId, id, existing?.state.eventId ?? null, rules),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new MandateRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, target, asked, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const rules = policyRules(asked);
        await onePolicyChangeAtATime(tx, member.orgId);
        const held = await challenges.hold(tx, member.sessionId);
        const { admin, id, mandateId, existing } = await changeable(tx, states, member, target, rules, 'change');
        const consumed = await challenges.consume(
          tx,
          held,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: POLICY_OPERATIONS[target.scope].ask,
            changeHash: changeHash(target.scope, member.orgId, id, existing?.state.eventId ?? null, rules),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new MandateRefused(403, 'STEP_UP_FAILED');
        await setPolicy(tx, states, {
          orgId: member.orgId,
          existing,
          scope: target.scope,
          mandateId,
          versionId: ids.next(),
          rules,
          madeBy: admin.id,
          madeAt: clock.now(),
          actor: { type: 'user', id: member.userId },
          details: stepUpDetails(consumed),
        });
        await outbox.add(tx, [
          {
            orgId: member.orgId,
            recipientUserId: null,
            kind: NOTICE[target.scope],
            membershipId: null,
            role: null,
            aboutId: id,
          },
        ]);
        return { status: 200, resourceId: id };
      });
      if (isUnwritten(done)) return done;
      const view = await work.answered(member.orgId, correlationId, (tx, states) =>
        viewIn(tx, states, member.orgId, target),
      );
      return 'outcome' in view ? view : { outcome: 'changed', ...view };
    },

    async show(orgId, target, correlationId) {
      const view = await work.answered(orgId, correlationId, (tx, states) => viewIn(tx, states, orgId, target));
      return 'outcome' in view ? view : { outcome: 'found', ...view };
    },
  };
}
