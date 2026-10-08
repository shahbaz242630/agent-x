// The reads the mandates' use cases share (Phase 2 B2–B5): drafting
// (mandate-registry.ts), accepting (mandate-acceptance.ts), moving
// (mandate-moves.ts), expiring (mandate-expiry.ts) and the agent's own
// (agent-mandate.ts) each read a mandate,
// its versions and their source the same way, answer with the mandate as it
// now stands, and tell of it the same way. Policies (policy-changes.ts) are
// read here too, as every mandate shows the monthly cap its agent is held to
// (C3c, partner S92: a lower cap is never quiet).
import type { AgentsTables } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { type FundingSourcesTables, type SourceRecord, sourceOf } from '@agentx/core/modules/funding-sources';
import {
  type ConsentAllows,
  consentCheck,
  type MandateRecord,
  type MandatesTables,
  type MandateVersionRecord,
  mandateOf,
  mandateVersionOf,
  policyOf,
  type PolicyVersionRecord,
  policyVersionOf,
} from '@agentx/core/modules/mandates';
import type { Notice, NoticeKind } from '@agentx/core/modules/notifications';
import type { SuppliersTables } from '@agentx/core/modules/suppliers';
import { monthlyCapOf, type MonthlyCapFrom } from '@agentx/core/modules/policies';
import { compare, type Money, money } from '@agentx/core/shared-kernel';
import type { DatabaseTransaction } from '@agentx/platform/db';

import { UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

export type MandateTables = UseCaseTables & MandatesTables & AgentsTables & FundingSourcesTables & SuppliersTables;
export type MandateTx = DatabaseTransaction<MandateTables>;

/** The mandates' UseCaseRefused: the only refusal their work answers. */
export class MandateRefused extends UseCaseRefused {}

/** A version as the routes show it: its terms, and how they now stand against the bank consent and the agent's monthly cap. */
export interface VersionShown {
  readonly version: MandateVersionRecord;
  readonly consentWarnings: readonly string[];
  /** Where the agent's monthly cap in force holds it below these terms: none when they fit. */
  readonly capWarnings: readonly string[];
}

/** The monthly cap the policies hold the mandate's agent to (decision 5), and where it comes from. */
interface AgentMonthlyCap {
  readonly cap: Money;
  readonly from: MonthlyCapFrom;
}

/** A mandate as the routes show it: its signed state, its version in force, its waiting draft, and its agent's monthly cap. */
export interface MandateView {
  readonly mandate: MandateRecord;
  readonly current: VersionShown | null;
  readonly pending: VersionShown | null;
  readonly agentMonthlyCap: AgentMonthlyCap;
}

/** A notice about a mandate or a policy (0036, 0038): to every admin and approver of the organisation, found as it is sent. */
export const toldAdminsAndApprovers = (orgId: string, kind: NoticeKind, aboutId: string): Notice[] => [
  { orgId, recipientUserId: null, kind, membershipId: null, role: null, aboutId },
];

/** What a source's bank consent allows, as the terms are checked against it. */
export const consentOf = ({ controls: { currency, period, maxPaymentMinor, maxPeriodMinor } }: SourceRecord) =>
  ({
    currency,
    maxPayment: money(maxPaymentMinor, currency),
    maxPeriod: money(maxPeriodMinor, currency),
    limitPeriod: period,
  }) satisfies ConsentAllows;

/** The source, read (`share`) and verified: SOURCE_NOT_USABLE for none of the organisation's. */
export async function sourceIn(tx: MandateTx, states: SignedStates, orgId: string, sourceId: string) {
  const read = await sourceOf(tx, states, { orgId, id: sourceId }, 'share');
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome === 'missing') throw new MandateRefused(409, 'SOURCE_NOT_USABLE');
  return read.source;
}

/** The mandate read (`share` or `change`) and verified: NOT_FOUND, or INTEGRITY_FAILED for one that can't be believed. */
export async function mandateIn(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  id: string,
  lock: 'share' | 'change',
) {
  const read = await mandateOf(tx, states, { orgId, id }, lock);
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome === 'missing') throw new MandateRefused(404, 'NOT_FOUND');
  return read;
}

/** A version of the mandate, read (`share`) and verified: INTEGRITY_FAILED for one that can't be believed. */
export async function versionIn(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandateId: string,
  versionId: string,
): Promise<MandateVersionRecord> {
  const read = await mandateVersionOf(tx, states, { orgId, id: versionId }, mandateId);
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  // 0035's keys hold a mandate's versions to its own.
  if (read.outcome === 'missing') throw new Error(`A mandate names a version not its own: ${mandateId}`);
  return read.version;
}

/** The words of the warning a version in force above its agent's monthly cap carries. */
export const ABOVE_THE_CAP =
  'the monthly limit is above the monthly cap the organisation’s policies hold the agent to (agentMonthlyCap): payments past the cap are refused; raise it in the mandate’s policy if the mandate’s limit is meant';

/** The same, for a draft waiting: a mandate's policy is weighed against the version in force, so the cap is raised once it is accepted. */
export const DRAFT_ABOVE_THE_CAP =
  'the monthly limit is above the monthly cap the organisation’s policies hold the agent to (agentMonthlyCap): once this draft is accepted, payments past the cap are refused until it is raised in the mandate’s policy';

/** A version of the mandate with how it now stands against its source's consent, whatever its setting. */
async function versionShown(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandateId: string,
  versionId: string | null,
) {
  if (versionId === null) return null;
  const version = await versionIn(tx, states, orgId, mandateId, versionId);
  const source = await sourceIn(tx, states, orgId, version.fundingSourceId);
  return { version, consentWarnings: consentCheck(version, consentOf(source)).problems };
}

/** Whether the agent's cap holds the version below its own monthly limit: never compared across currencies (C2 denies those). */
const heldBelow = (
  shown: Omit<VersionShown, 'capWarnings'> | null,
  { cap }: AgentMonthlyCap,
  warning: string,
): VersionShown | null =>
  shown === null
    ? null
    : {
        ...shown,
        capWarnings:
          cap.currency === shown.version.monthlyLimit.currency && compare(shown.version.monthlyLimit, cap) > 0
            ? [warning]
            : [],
      };

/** A policy's rules in force, read (`share`) and verified: null for one never set; INTEGRITY_FAILED for one that can't be believed. */
export async function policyRulesIn(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  policyId: string,
  lock: 'share' | 'change' = 'share',
) {
  const read = await policyOf(tx, states, { orgId, id: policyId }, lock);
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome === 'missing') return null;
  const current = await policyVersionOf(tx, states, { orgId, id: read.policy.currentVersionId }, read.policy.id);
  if (current.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  // 0037's `current_is_its_own` holds a policy's version in force to its own.
  if (current.outcome === 'missing') throw new Error(`A policy names a version not its own: ${read.policy.id}`);
  return { ...read, current: current.version satisfies PolicyVersionRecord };
}

/**
 * The monthly cap the policies hold the mandate's agent to: the mandate's
 * policy's, else the organisation's, else the default. The organisation's is
 * read only when the mandate's own sets none, as it can't change the cap then.
 */
export async function agentCapOf(tx: MandateTx, states: SignedStates, orgId: string, mandateId: string) {
  const own = (await policyRulesIn(tx, states, orgId, mandateId))?.current ?? null;
  const organization = own?.monthlyCap ? null : ((await policyRulesIn(tx, states, orgId, orgId))?.current ?? null);
  return monthlyCapOf(organization, own);
}

/** The mandate as it now stands, with its version in force, its waiting draft, and its agent's monthly cap. */
export async function viewIn(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandateId: string,
): Promise<MandateView> {
  const { mandate } = await mandateIn(tx, states, orgId, mandateId, 'share');
  // The lock order's: the mandate's versions, then the policies (ADR-006 §6: 4).
  const current = await versionShown(tx, states, orgId, mandate.id, mandate.currentVersionId);
  const pending = await versionShown(tx, states, orgId, mandate.id, mandate.pendingVersionId);
  const agentMonthlyCap = await agentCapOf(tx, states, orgId, mandate.id);
  return {
    mandate,
    current: heldBelow(current, agentMonthlyCap, ABOVE_THE_CAP),
    pending: heldBelow(pending, agentMonthlyCap, DRAFT_ABOVE_THE_CAP),
    agentMonthlyCap,
  };
}
