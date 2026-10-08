// A policy's rules (PRD §3 `Policy` / `PolicyRule`, §5.2; BR-06; partner
// decision 5, S91; Phase 2 C3): what an organisation narrows on top of its
// mandates, its own policy for every agent or a mandate's for its one. Checked
// here before anything is written; the database's checks (0037) hold the
// same shapes.
//
// Each rule is optional: a per-order cap with what happens over it (DENY or
// REQUIRE_APPROVAL), a monthly cap per agent, an approval threshold, a
// supplier list. Where set, they nest as a mandate's limits do: threshold ≤
// per-order cap ≤ monthly cap. All in one currency.
//
// A mandate's own policy is never wider than its mandate (SEC-LIM-11): each
// rule at most the mandate's own, its suppliers among the mandate's. The
// organisation's is weighed against each mandate by the engine (C2), which
// takes the strictest, so it needs no such check here.
import { compare, type Money, UUID } from '../../../shared-kernel/index.ts';
import { MOST_ALLOWED_SUPPLIERS } from './mandate.ts';
import type { MandateTerms } from './terms.ts';

/** What a per-order cap does to an order over it. */
export const OVER_CAP = ['DENY', 'REQUIRE_APPROVAL'] as const;
export type OverCap = (typeof OVER_CAP)[number];

/** The two kinds (0037): the organisation's own, and one mandate's. */
export const POLICY_SCOPES = ['organization', 'mandate'] as const;
export type PolicyScope = (typeof POLICY_SCOPES)[number];

/** A policy's rules: each null where it sets none. */
export interface PolicyRules {
  readonly currency: string;
  readonly perOrderCap: { readonly cap: Money; readonly over: OverCap } | null;
  readonly monthlyCap: Money | null;
  readonly approvalThreshold: Money | null;
  /** Lower case, sorted, each once; null for no list (an empty list is refused: it would allow no one). */
  readonly supplierIds: readonly string[] | null;
}

/** The rules can't be a policy's; `problems` say why. */
export class PolicyRulesRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The policy's rules were refused: ${problems.join('; ')}`);
    this.name = 'PolicyRulesRefused';
    this.problems = problems;
  }
}

/** The rules as a version keeps them, the suppliers in lower case, sorted; or `PolicyRulesRefused` naming each problem. */
export function policyRules(rules: PolicyRules): PolicyRules {
  const problems: string[] = [];
  const { perOrderCap, monthlyCap, approvalThreshold } = rules;
  const cap = perOrderCap?.cap ?? null;
  // An ISO 4217 code even with no amount to carry it, so no other text reaches a query.
  if (!/^[A-Z]{3}$/.test(rules.currency)) problems.push('the currency is not an ISO 4217 code');
  const amounts = [cap, monthlyCap, approvalThreshold].filter((m) => m !== null);
  if (amounts.some(({ currency }) => currency !== rules.currency))
    problems.push('the rules are not all in one currency');
  else {
    const above = (a: Money | null, b: Money | null) => a !== null && b !== null && compare(a, b) > 0;
    if (above(approvalThreshold, cap)) problems.push('the approval threshold is above the per-order cap');
    if (above(cap, monthlyCap)) problems.push('the per-order cap is above the monthly cap');
    if (above(approvalThreshold, monthlyCap)) problems.push('the approval threshold is above the monthly cap');
  }
  let supplierIds: string[] | null = null;
  if (rules.supplierIds !== null) {
    supplierIds = [...new Set(rules.supplierIds.map((id) => id.toLowerCase()))].sort();
    if (supplierIds.length === 0 || supplierIds.length > MOST_ALLOWED_SUPPLIERS) {
      problems.push(`a supplier list names 1 to ${String(MOST_ALLOWED_SUPPLIERS)} suppliers`);
    }
    if (supplierIds.length !== rules.supplierIds.length) problems.push('a supplier is named twice');
    if (!supplierIds.every((id) => UUID.test(id))) problems.push('a supplier is not named by its ID');
  }
  if (problems.length > 0) throw new PolicyRulesRefused(problems);
  return { ...rules, supplierIds };
}

/**
 * Where a mandate's own policy goes past the mandate's terms (SEC-LIM-11):
 * each rule above the mandate's own, a supplier it doesn't name, or another
 * currency. None: within it.
 */
export function widerThanMandate(rules: PolicyRules, terms: MandateTerms): string[] {
  if (rules.currency !== terms.perOrderLimit.currency) return ['the policy is not in the mandate’s currency'];
  const above = (rule: Money | null, limit: Money) => rule !== null && compare(rule, limit) > 0;
  const wider: string[] = [];
  if (above(rules.perOrderCap?.cap ?? null, terms.perOrderLimit))
    wider.push('the per-order cap is above the mandate’s');
  if (above(rules.monthlyCap, terms.monthlyLimit)) wider.push('the monthly cap is above the mandate’s');
  if (above(rules.approvalThreshold, terms.approvalThreshold)) {
    wider.push('the approval threshold is above the mandate’s');
  }
  if (rules.supplierIds?.some((id) => !terms.supplierIds.includes(id))) {
    wider.push('a supplier is not one the mandate names');
  }
  return wider;
}
