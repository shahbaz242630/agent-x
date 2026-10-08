// The decision engine (PRD §5.2; BRD BR-06, BR-07; ADR-006 §7; ADR-014 §8;
// partner decision 5, Phase 2 C2): one spend request against the mandate in
// force and the two policies over it, the organisation's and the mandate's.
// Pure and deterministic: everything it weighs is passed in, read by the
// caller under ADR-006's locks; the simulator (C4) calls it the same way.
//
// Deny by default. Every check that fails adds its reason code, and the
// decision is the strictest of them: DENY, then REQUIRE_NEW_MANDATE, then
// REQUIRE_APPROVAL, then ALLOW. So an ended mandate is always DENY, and an
// approval can never allow more than the mandate.
//
// - Over the mandate's own per-order or monthly limit: REQUIRE_NEW_MANDATE.
// - Per-order cap, approval threshold, supplier list: each policy narrows on
//   its own, so the tightest of the three always applies.
// - The monthly cap per agent (decision 5): the mandate's policy's if it sets
//   one, higher or lower, else the organisation's, else AED 20,000. Over it is
//   DENY; the mandate's own monthly limit still binds above it.
// - The month's total is the agent's under every mandate (decision 4), every
//   reservation but a released one (ADR-006 §8).
//
// Free text (the purpose, the order reference's wording) is never weighed:
// the duplicate check comes in as the caller's finding (SEC-AG-14).
import { type Money, money, plus, type ReasonCode, withinLimit } from '../../../shared-kernel/index.ts';

export const DECISIONS = ['DENY', 'REQUIRE_NEW_MANDATE', 'REQUIRE_APPROVAL', 'ALLOW'] as const;
/** Strictest first: a decision's place in DECISIONS is its precedence. */
export type Decision = (typeof DECISIONS)[number];

/** What a policy's per-order cap does to an order over it: refuse it, or send it for approval. */
export type OverCap = 'DENY' | 'REQUIRE_APPROVAL';

/** Every agent's monthly cap when the organisation has set none (partner, S91): AED 20,000. Another currency has no default. */
export const DEFAULT_MONTHLY_CAP: Money = money(2_000_000n, 'AED');

/** The request as the agent made it, its amounts already Money (A1). */
export interface SpendAsked {
  readonly amount: Money;
  readonly supplierId: string;
  readonly fundingSourceId: string;
}

/** The agent's mandate and the terms of its version in force. */
export interface MandateInForce {
  readonly id: string;
  readonly agentId: string;
  readonly status: string;
  readonly versionId: string;
  readonly perOrderLimit: Money;
  readonly monthlyLimit: Money;
  readonly approvalThreshold: Money;
  /** Lower case, as a version keeps them. */
  readonly supplierIds: readonly string[];
  readonly fundingSourceId: string;
  readonly splitCheck: boolean;
  readonly endsAt: Date | null;
}

/** A policy's version in force: each rule null where it sets none. */
export interface PolicyRules {
  readonly versionId: string;
  readonly perOrderCap: { readonly cap: Money; readonly over: OverCap } | null;
  readonly monthlyCap: Money | null;
  readonly approvalThreshold: Money | null;
  /** Lower case, as a version keeps them. */
  readonly supplierIds: readonly string[] | null;
}

/** Everything a decision weighs. */
export interface DecisionInput {
  readonly request: SpendAsked;
  /** When it is decided: the server's clock, never a time the agent sends, as it decides whether the mandate has ended. */
  readonly now: Date;
  readonly agent: { readonly id: string; readonly status: string };
  /** The agent's open mandate, or null for none. */
  readonly mandate: MandateInForce | null;
  /** The supplier's status, or null when it isn't the organisation's. */
  readonly supplierStatus: string | null;
  /** Whether the source may fund now: ACTIVE both here and at the partner, before its consent's expiry. */
  readonly sourceMayFund: boolean;
  readonly organizationPolicy: PolicyRules | null;
  readonly mandatePolicy: PolicyRules | null;
  /** What the agent holds or spent this month (the mandate's zone's), every reservation but a released one. */
  readonly monthSpent: Money;
  /** The same supplier's other open requests in the split window: counted only when the mandate's split check is on. */
  readonly splitOpen: Money;
  /** Whether an open, unknown or paid request already claims this supplier and order reference (D3). */
  readonly duplicateOrder: boolean;
}

/** Where the monthly cap per agent came from. */
export type MonthlyCapFrom = 'mandate-policy' | 'organization-policy' | 'default';

export interface DecisionMade {
  readonly decision: Decision;
  /** Every failing check's code, each once, in the order checked; none for ALLOW. */
  readonly reasons: readonly ReasonCode[];
  /** The exact versions weighed, for the evidence (PRD §5.2). */
  readonly versions: {
    readonly mandate: string | null;
    readonly organizationPolicy: string | null;
    readonly mandatePolicy: string | null;
  };
  readonly monthlyCapFrom: MonthlyCapFrom;
}

/** Which decision each reason makes. */
const DECIDES: Readonly<Partial<Record<ReasonCode, Decision>>> = {
  MANDATE_ORDER_LIMIT: 'REQUIRE_NEW_MANDATE',
  MANDATE_MONTHLY_LIMIT: 'REQUIRE_NEW_MANDATE',
  APPROVAL_THRESHOLD: 'REQUIRE_APPROVAL',
  AGGREGATE_THRESHOLD: 'REQUIRE_APPROVAL',
};

/** The request against the mandate and its policies: the decision, every failing reason and the versions weighed. */
export function decide(input: DecisionInput): DecisionMade {
  const { mandate, organizationPolicy, mandatePolicy } = input;
  const policies = [organizationPolicy, mandatePolicy].filter((p) => p !== null);
  const monthly = monthlyCapOf(organizationPolicy, mandatePolicy);
  const failed: { code: ReasonCode; decision: Decision }[] = [];
  const fail = (code: ReasonCode, decision: Decision = DECIDES[code] ?? 'DENY'): void => {
    failed.push({ code, decision });
  };

  statusChecks(input, fail);
  const inForce = mandate !== null && mandateInForce(input, mandate);
  if (!inForce) fail('MANDATE_NOT_IN_FORCE');
  const supplierId = input.request.supplierId.toLowerCase();
  if (policies.some((p) => p.supplierIds !== null && !p.supplierIds.includes(supplierId))) {
    fail('POLICY_SUPPLIER_NOT_ALLOWED');
  }
  // Amounts are weighed only against a mandate in force, and only when every one is in its currency:
  // two currencies are never compared, and a policy or total in another one denies rather than throws.
  if (inForce) {
    if (!mandate.supplierIds.includes(supplierId)) fail('SUPPLIER_NOT_ALLOWED');
    if (input.request.fundingSourceId.toLowerCase() !== mandate.fundingSourceId) fail('SOURCE_NOT_MANDATED');
    const weighed = [
      input.request.amount,
      input.monthSpent,
      input.splitOpen,
      monthly.cap,
      ...policies.flatMap(amountsOf),
    ];
    if (weighed.every(({ currency }) => currency === mandate.perOrderLimit.currency)) {
      amountChecks(input, mandate, policies, monthly.cap, fail);
    } else fail('CURRENCY_NOT_ALLOWED');
  }

  const decision = DECISIONS.find((d) => failed.some((f) => f.decision === d)) ?? 'ALLOW';
  return {
    decision,
    reasons: [...new Set(failed.map(({ code }) => code))],
    versions: {
      mandate: mandate?.versionId ?? null,
      organizationPolicy: organizationPolicy?.versionId ?? null,
      mandatePolicy: mandatePolicy?.versionId ?? null,
    },
    monthlyCapFrom: monthly.from,
  };
}

type Fail = (code: ReasonCode, decision?: Decision) => void;

/** More than the limit: exactly at it passes. */
const over = (amount: Money, limit: Money): boolean => !withinLimit(amount, limit);

/** Every amount a policy sets. */
const amountsOf = (p: PolicyRules): Money[] =>
  [p.perOrderCap?.cap ?? null, p.monthlyCap, p.approvalThreshold].filter((m) => m !== null);

/**
 * The monthly cap per agent: the mandate's policy's, else the organisation's,
 * else the default (decision 5). Also what a mandate shows its agent held to
 * (C3c, partner S92: never quiet).
 */
export function monthlyCapOf(
  organizationPolicy: Pick<PolicyRules, 'monthlyCap'> | null,
  mandatePolicy: Pick<PolicyRules, 'monthlyCap'> | null,
): { readonly cap: Money; readonly from: MonthlyCapFrom } {
  if (mandatePolicy?.monthlyCap) return { cap: mandatePolicy.monthlyCap, from: 'mandate-policy' };
  if (organizationPolicy?.monthlyCap) return { cap: organizationPolicy.monthlyCap, from: 'organization-policy' };
  return { cap: DEFAULT_MONTHLY_CAP, from: 'default' };
}

/** The agent, supplier, source and order, whatever the mandate. */
function statusChecks(input: DecisionInput, fail: Fail): void {
  if (input.agent.status !== 'ACTIVE') fail('AGENT_SUSPENDED');
  if (input.supplierStatus !== 'VERIFIED') fail('SUPPLIER_NOT_VERIFIED');
  if (!input.sourceMayFund) fail('SOURCE_NOT_USABLE');
  if (input.duplicateOrder) fail('DUPLICATE_ORDER_REFERENCE');
}

/** ACTIVE, this agent's, and before its end. */
function mandateInForce(input: DecisionInput, mandate: MandateInForce): boolean {
  return (
    mandate.status === 'ACTIVE' &&
    mandate.agentId === input.agent.id &&
    (mandate.endsAt === null || input.now.getTime() < mandate.endsAt.getTime())
  );
}

/** The limits, caps and thresholds, all in the mandate's currency. */
function amountChecks(
  input: DecisionInput,
  mandate: MandateInForce,
  policies: readonly PolicyRules[],
  monthlyCap: Money,
  fail: Fail,
): void {
  const { amount } = input.request;
  const monthTotal = plus(input.monthSpent, amount);

  if (over(amount, mandate.perOrderLimit)) fail('MANDATE_ORDER_LIMIT');
  if (over(monthTotal, mandate.monthlyLimit)) fail('MANDATE_MONTHLY_LIMIT');
  for (const { perOrderCap } of policies) {
    if (perOrderCap !== null && over(amount, perOrderCap.cap)) fail('POLICY_ORDER_CAP', perOrderCap.over);
  }
  if (over(monthTotal, monthlyCap)) fail('POLICY_MONTHLY_CAP');

  // Over any of the three thresholds is over the lowest.
  const thresholds = [mandate.approvalThreshold, ...policies.flatMap((p) => p.approvalThreshold ?? [])];
  const overThreshold = (a: Money): boolean => thresholds.some((threshold) => over(a, threshold));
  if (overThreshold(amount)) fail('APPROVAL_THRESHOLD');
  // A split: this order alone is within the threshold, with the supplier's other open ones it isn't (ADR-014 §5).
  else if (mandate.splitCheck && overThreshold(plus(input.splitOpen, amount))) fail('AGGREGATE_THRESHOLD');
}

/**
 * The input as the evidence keeps it: canonical JSON of every fact weighed,
 * for the caller to hash with its key (PRD §5.2's evaluated input hash). No
 * free text, as none is weighed.
 */
export function decisionInputText(input: DecisionInput): string {
  const amount = (m: Money | null): string | null => (m === null ? null : `${String(m.minor)} ${m.currency}`);
  const rules = (p: PolicyRules | null): unknown[] | null =>
    p === null
      ? null
      : [
          p.versionId,
          p.perOrderCap === null ? null : [amount(p.perOrderCap.cap), p.perOrderCap.over],
          amount(p.monthlyCap),
          amount(p.approvalThreshold),
          p.supplierIds,
        ];
  const { request, mandate } = input;
  return JSON.stringify([
    [amount(request.amount), request.supplierId.toLowerCase(), request.fundingSourceId.toLowerCase()],
    input.now.toISOString(),
    [input.agent.id, input.agent.status],
    mandate === null
      ? null
      : [
          mandate.id,
          mandate.agentId,
          mandate.status,
          mandate.versionId,
          amount(mandate.perOrderLimit),
          amount(mandate.monthlyLimit),
          amount(mandate.approvalThreshold),
          mandate.supplierIds,
          mandate.fundingSourceId,
          mandate.splitCheck,
          mandate.endsAt?.toISOString() ?? null,
        ],
    input.supplierStatus,
    input.sourceMayFund,
    rules(input.organizationPolicy),
    rules(input.mandatePolicy),
    amount(input.monthSpent),
    amount(input.splitOpen),
    input.duplicateOrder,
    // So a change of the default changes the text too.
    amount(DEFAULT_MONTHLY_CAP),
  ]);
}
