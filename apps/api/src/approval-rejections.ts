// Decision 18 (partner, S117; Phase 3 E5b): a request waiting for approval
// that today's weighing denies because of a rule the team set (a limit or a
// cap lowered, a supplier taken off a policy, the monthly cap not chosen) is
// rejected when its approver confirms, with why and what to do, kept on the
// signed record and shown to the team. Stops are never turned into a
// rejection: a suspended agent, mandate or source and an unverified supplier
// may be pauses the team chose (decision 7), so those stay REQUEST_CHANGED
// and the request waits as it was.
import { type Decision, reasonsShownToAgent } from '@agentx/core/modules/policies';
import { REJECT_REASON_MOST } from '@agentx/core/modules/spend-requests';
import type { ReasonCode } from '@agentx/core/shared-kernel';

/** What the team can change for each rule that now denies it: shown to the approver before they confirm. */
export const WHAT_TO_DO = {
  MANDATE_ORDER_LIMIT: 'Raise the mandate’s per-order limit (accept a new version with a higher one).',
  MANDATE_MONTHLY_LIMIT: 'Raise the mandate’s monthly limit (accept a new version with a higher one).',
  POLICY_ORDER_CAP: 'Raise the per-order cap in the organisation’s or the mandate’s policy settings.',
  POLICY_MONTHLY_CAP: 'Raise the monthly cap in the organisation’s or the mandate’s policy settings.',
  ORG_MONTHLY_CAP_NOT_SET: 'Choose the organisation’s monthly cap in its policy settings.',
  POLICY_SUPPLIER_NOT_ALLOWED: 'Add the supplier to the policy’s allowed suppliers.',
  CURRENCY_NOT_ALLOWED: 'Set the policy’s amounts in the mandate’s currency.',
  DUPLICATE_ORDER_REFERENCE: 'Check the order isn’t already paid; if it isn’t, the agent asks with its own reference.',
} as const satisfies Partial<Record<ReasonCode, string>>;

export type RuleDenial = keyof typeof WHAT_TO_DO;

const isRuleDenial = (code: ReasonCode): code is RuleDenial => Object.hasOwn(WHAT_TO_DO, code);

/**
 * The reasons a weighing that now refuses it would reject it for: those that
 * made the refusal, when every one is a rule the team set; null when any is
 * a stop (or it isn't refused). Unlike the agent's list, a policy's order cap
 * is named beside another refusal: it may have refused as well, and the team
 * changing only the other would see the agent refused again.
 */
export function rejectedFor(decision: Decision, reasons: readonly ReasonCode[]): readonly RuleDenial[] | null {
  if (decision !== 'DENY' && decision !== 'REQUIRE_NEW_MANDATE') return null;
  const orderCap = decision === 'DENY' && reasons.includes('POLICY_ORDER_CAP');
  const made = [
    ...new Set([...reasonsShownToAgent(decision, reasons), ...(orderCap ? ['POLICY_ORDER_CAP' as const] : [])]),
  ];
  return made.length > 0 && made.every(isRuleDenial) ? made.filter(isRuleDenial) : null;
}

/**
 * The note the rejection keeps, within REJECT_REASON_MOST: the rules by code
 * and what to do; past it, without the codes, which its event keeps whole
 * (`causes`).
 */
export function rejectionNote(reasons: readonly ReasonCode[]): string {
  const note = (rules: string) =>
    `Rejected on approval: today’s check denies it under your team’s rules${rules}. Change them in settings, then the agent asks again.`;
  const named = note(` (${reasons.join(', ')})`);
  return named.length <= REJECT_REASON_MOST ? named : note('');
}
