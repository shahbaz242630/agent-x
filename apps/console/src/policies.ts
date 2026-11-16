// Policies as the console reads and changes them (6D3b; BR-07, BR-08, BR-22):
// the organisation's own policy (GET /v1/policies/organization) and a
// mandate's (GET /v1/mandates/:id/policy), each changed by an admin by asking,
// a passkey and confirming, after a preview of the requests waiting for
// approval the change would reject; and the simulator (POST
// /v1/mandates/:id/policy/simulate), which writes nothing. The shapes and
// rules are the API's (apps/api/src/policies.ts); the roles only decide which
// buttons show, and the API checks again whatever is sent.
//
// Amounts are whole minor units (fils) in the API. A typed amount is read
// exactly, as integers (BigInt), never through floating point: more decimals
// than the currency has, a sign, zero or past 2^53 − 1 are refused in place.
// A rule the admin didn't choose is never sent: every choice starts unpicked,
// and the body is built only once each one is made.
import { useQuery } from '@tanstack/react-query';

import { api, isIntegrityFailed, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import type { Role } from './session.tsx';
import { t } from './text.ts';

/** What a per-order cap does to an order over it (OVER_CAP). */
export const OVER = ['DENY', 'REQUIRE_APPROVAL'] as const;
type Over = (typeof OVER)[number];
/** How long the organisation's requests wait for approval, in hours (APPROVAL_WAITS), as the radios name them. */
export const WAITS = ['24', '48', '72'] as const;
type Wait = (typeof WAITS)[number];
/** What happens to the waiting requests a change would reject (WAITING_CHOICES), in the API's order. */
export const WAITING = ['reject', 'leave'] as const;
export type Waiting = (typeof WAITING)[number];
/** The most suppliers a policy's list may name (MOST_ALLOWED_SUPPLIERS). */
const MOST_SUPPLIERS = 100;

/** A policy's rules as a body sends them and a version shows them: each null where it sets none. */
export interface Rules {
  readonly currency: string;
  readonly perOrderCap: { readonly capMinor: number; readonly over: Over } | null;
  readonly monthlyCapMinor: number | null;
  readonly approvalThresholdMinor: number | null;
  readonly supplierIds: readonly string[] | null;
}

interface PolicyVersion extends Rules {
  readonly id: string;
  readonly version: number;
  /** The membership of the admin who made it. */
  readonly madeBy: string;
  readonly madeAt: string;
}

/** A rule set to an amount, or to none (the organisation's monthly cap choice, MONTHLY_CAP_CHOICES). */
type AmountOrNone = 'amount' | 'none';

export interface Policy {
  readonly scope: 'organization' | 'mandate';
  readonly current: PolicyVersion | null;
  /** The organisation's monthly cap choice; null: not chosen yet (no agent spends), or a mandate's policy. */
  readonly monthlyCapChoice: AmountOrNone | null;
  readonly approvalWaitHours: number | null;
  readonly approvalWaitInForceHours: number | null;
  /** What the console fills in for the organisation's monthly cap, never applied until an admin chooses it. */
  readonly suggestedMonthlyCapMinor: number;
}

/** One rule that would reject a waiting request (decision 18): the API's words, and what to do. */
interface RuleDenial {
  readonly code: string;
  readonly message: string;
  readonly whatToDo: string;
}

export interface WaitingPreview {
  readonly rejected: readonly {
    readonly id: string;
    readonly agentId: string;
    readonly amountMinor: number;
    readonly currency: string;
    readonly reasons: readonly RuleDenial[];
  }[];
  readonly more: boolean;
}

export type Decision = 'DENY' | 'REQUIRE_NEW_MANDATE' | 'REQUIRE_APPROVAL' | 'ALLOW';
export type CapFrom = 'mandate-policy' | 'organization-policy' | 'none' | 'not-set';

export interface Simulation {
  readonly decision: Decision;
  readonly reasons: readonly { readonly code: string; readonly message: string }[];
  readonly mandateId: string | null;
  readonly proposed: { readonly organizationPolicy: boolean; readonly mandatePolicy: boolean };
  readonly monthlyCapFrom: CapFrom;
  readonly month: string | null;
  readonly monthSpentMinor: number;
}

/** A mandate's terms, the bounds its own policy is held within. */
export interface MandateTerms {
  readonly currency: string;
  readonly perOrderLimitMinor: number;
  readonly monthlyLimitMinor: number;
  readonly approvalThresholdMinor: number;
  readonly supplierIds: readonly string[];
  readonly fundingSourceId: string;
}

interface Mandate {
  readonly id: string;
  readonly status: string;
  readonly current: MandateTerms | null;
  readonly pending: MandateTerms | null;
}

/** The organisation policy's currency: AED, the Pilot's only one (the API refuses another, POLICY_CURRENCY_REFUSED). */
export const PILOT_CURRENCY = 'AED';

/** Who may change a policy (CHANGING_ROLES): an admin. */
export const CHANGING: readonly Role[] = ['admin'];
/** Who may use the simulator (SIMULATING_ROLES). */
export const SIMULATING: readonly Role[] = ['admin', 'approver', 'developer'];

/** Which policy: the organisation's own, or one mandate's. */
export type Target = { readonly kind: 'organization' } | { readonly kind: 'mandate'; readonly mandateId: string };

const mandateAt = (id: string): string => `/v1/mandates/${encodeURIComponent(id)}`;

/** A policy's address in the API: its change is at `/change`, its preview at `/change/preview`. */
export const policyAt = (target: Target): string =>
  target.kind === 'organization' ? '/v1/policies/organization' : `${mandateAt(target.mandateId)}/policy`;

export const simulateAt = (mandateId: string): string => `${mandateAt(mandateId)}/policy/simulate`;

/** Whether the address names a policy at all: a mandate's only by a UUID, as any other names none. */
export const isNamed = (target: Target): boolean => target.kind === 'organization' || isUuid(target.mandateId);

export function usePolicy(target: Target, organization: string) {
  return useQuery({
    queryKey: ['policies', organization, target.kind === 'organization' ? 'organization' : target.mandateId],
    enabled: isNamed(target),
    queryFn: () => api.get<Policy>(policyAt(target), { organization }),
  });
}

/** One mandate, for the terms its policy is held within (in force, else the draft waiting). */
export function useMandate(id: string, organization: string) {
  return useQuery({
    queryKey: ['mandates', organization, 'one', id],
    enabled: isUuid(id),
    queryFn: () => api.get<Mandate>(mandateAt(id), { organization }),
    select: (mandate) => ({ status: mandate.status, terms: mandate.current ?? mandate.pending }),
  });
}

interface Statement {
  readonly id: string;
  readonly version: number;
  readonly words: readonly { readonly choice: string; readonly text: string }[];
}

/** The API's words for changes, read afresh each time it is shown (as the shared confirm reads them). */
export function useStatements(enabled: boolean) {
  return useQuery({
    queryKey: ['statements'],
    enabled,
    queryFn: () => api.get<{ readonly statements: readonly Statement[] }>('/v1/statements'),
    staleTime: 0,
    refetchOnMount: 'always',
  });
}

/** One choice's words in a set and the set's version, or none while they aren't read. */
export function wordsOf(
  read: { readonly statements: readonly Statement[] } | undefined,
  id: string,
  choice: string,
): { readonly version: number; readonly text: string } | undefined {
  const statement = read?.statements.find((one) => one.id === id);
  const words = statement?.words.find((one) => one.choice === choice);
  return statement === undefined || words === undefined ? undefined : { version: statement.version, text: words.text };
}

// Digits only, grouped by commas in threes or not at all, then an optional fraction: no sign, no exponent, no spaces.
const AMOUNT_TEXT = /^(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?$/;

/**
 * An amount typed in major units (`2500`, `2,500.50`) as whole minor units,
 * exactly: none for anything else, more decimals than the currency has, zero,
 * or past 2^53 − 1 (the API's AMOUNT).
 */
export function parseAmount(text: string, digits: number): number | null {
  const typed = text.trim();
  if (!AMOUNT_TEXT.test(typed)) return null;
  const [whole = '', fraction = ''] = typed.replaceAll(',', '').split('.');
  if (fraction.length > digits) return null;
  const minor = BigInt(whole) * 10n ** BigInt(digits) + BigInt(fraction.padEnd(digits, '0') || '0');
  if (minor < 1n || minor > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(minor);
}

/** Whole minor units as an amount field shows them for change (`2500.50`), exactly. */
export function amountField(minor: number, digits: number): string {
  const amount = BigInt(minor);
  const scale = 10n ** BigInt(digits);
  const whole = String(amount / scale);
  return digits === 0 ? whole : `${whole}.${String(amount % scale).padStart(digits, '0')}`;
}

/** A policy's rules as an admin chooses them: each choice null until made, the amounts as typed. */
export interface Draft {
  readonly perOrder: 'none' | 'cap' | null;
  readonly perOrderAmount: string;
  readonly over: Over | null;
  readonly monthly: AmountOrNone | null;
  readonly monthlyAmount: string;
  readonly threshold: AmountOrNone | null;
  readonly thresholdAmount: string;
  readonly suppliers: 'any' | 'only' | null;
  readonly supplierIds: readonly string[];
  readonly wait: Wait | null;
}

/**
 * A draft to start changing from: no choice made, the amount fields holding
 * the rules in force (the organisation's monthly cap the suggested amount
 * when it has none), so the admin changes or keeps them, then chooses.
 */
export function draftFrom(current: Rules | null, digits: number, suggestedMonthly?: number): Draft {
  const field = (minor: number | null | undefined) =>
    minor === null || minor === undefined ? '' : amountField(minor, digits);
  return {
    perOrder: null,
    perOrderAmount: field(current?.perOrderCap?.capMinor),
    over: null,
    monthly: null,
    monthlyAmount: field(current?.monthlyCapMinor ?? suggestedMonthly),
    threshold: null,
    thresholdAmount: field(current?.approvalThresholdMinor),
    suppliers: null,
    supplierIds: current?.supplierIds ?? [],
    wait: null,
  };
}

/** What is wrong with a draft, each said in place. */
export type Problem =
  | 'perOrder'
  | 'perOrderAmount'
  | 'over'
  | 'monthly'
  | 'monthlyAmount'
  | 'threshold'
  | 'thresholdAmount'
  | 'suppliers'
  | 'supplierIds'
  | 'wait'
  | 'thresholdAbovePerOrder'
  | 'perOrderAboveMonthly'
  | 'thresholdAboveMonthly'
  | 'perOrderAboveMandate'
  | 'monthlyAboveMandate'
  | 'thresholdAboveMandate'
  | 'supplierOutsideMandate';

/** One amount rule: none, or the amount typed; a choice not made or an amount that can't be is a problem. */
function amountRule(
  choice: string | null,
  typed: string,
  digits: number,
  [unchosen, unreadable]: readonly [Problem, Problem],
  problems: Problem[],
): number | null {
  if (choice === null) problems.push(unchosen);
  if (choice === null || choice === 'none') return null;
  const minor = parseAmount(typed, digits);
  if (minor === null) problems.push(unreadable);
  return minor;
}

const above = (a: number | null, b: number | null): boolean => a !== null && b !== null && a > b;

/** Where the rules go past a mandate's terms (the API's widerThanMandate), said before anything is sent. */
function widerThan(rules: Rules, terms: MandateTerms, problems: Problem[]): void {
  if (above(rules.perOrderCap?.capMinor ?? null, terms.perOrderLimitMinor)) problems.push('perOrderAboveMandate');
  if (above(rules.monthlyCapMinor, terms.monthlyLimitMinor)) problems.push('monthlyAboveMandate');
  if (above(rules.approvalThresholdMinor, terms.approvalThresholdMinor)) problems.push('thresholdAboveMandate');
  const named = new Set(terms.supplierIds.map((id) => id.toLowerCase()));
  if (rules.supplierIds?.some((id) => !named.has(id.toLowerCase())) === true) problems.push('supplierOutsideMandate');
}

/** The supplier rule: any, or the ones ticked (1 to 100). */
function supplierRule(draft: Draft, problems: Problem[]): readonly string[] | null {
  if (draft.suppliers === null) problems.push('suppliers');
  if (draft.suppliers !== 'only') return null;
  if (draft.supplierIds.length === 0 || draft.supplierIds.length > MOST_SUPPLIERS) problems.push('supplierIds');
  return [...draft.supplierIds].sort();
}

/** What a draft is checked with: its currency's code and digits, the wait asked (the organisation's), a mandate's terms. */
export interface Checked {
  readonly currency: string;
  readonly digits: number;
  readonly withWait: boolean;
  readonly within?: MandateTerms | null | undefined;
}

/**
 * The rules a draft makes, checked by the API's own rules (each choice made,
 * each amount readable, threshold ≤ per-order cap ≤ monthly cap, a mandate's
 * within its terms); or every problem, said in place before anything is sent.
 */
export function rulesFrom(
  draft: Draft,
  { currency, digits, withWait, within }: Checked,
): { readonly rules: Rules; readonly wait: number | null } | { readonly problems: readonly Problem[] } {
  const problems: Problem[] = [];
  const cap = amountRule(draft.perOrder, draft.perOrderAmount, digits, ['perOrder', 'perOrderAmount'], problems);
  if (draft.perOrder === 'cap' && draft.over === null) problems.push('over');
  const monthly = amountRule(draft.monthly, draft.monthlyAmount, digits, ['monthly', 'monthlyAmount'], problems);
  const threshold = amountRule(
    draft.threshold,
    draft.thresholdAmount,
    digits,
    ['threshold', 'thresholdAmount'],
    problems,
  );
  const supplierIds = supplierRule(draft, problems);
  if (withWait && draft.wait === null) problems.push('wait');
  if (above(threshold, cap)) problems.push('thresholdAbovePerOrder');
  if (above(cap, monthly)) problems.push('perOrderAboveMonthly');
  if (above(threshold, monthly)) problems.push('thresholdAboveMonthly');
  const rules: Rules = {
    currency,
    perOrderCap: cap === null || draft.over === null ? null : { capMinor: cap, over: draft.over },
    monthlyCapMinor: monthly,
    approvalThresholdMinor: threshold,
    supplierIds,
  };
  if (within !== undefined && within !== null) widerThan(rules, within, problems);
  if (problems.length > 0) return { problems };
  return { rules, wait: withWait && draft.wait !== null ? Number(draft.wait) : null };
}

/** Whether the change would reject any waiting request (or more wait than were weighed): the admin then chooses what happens. */
export const waitingOffered = (preview: WaitingPreview): boolean => preview.rejected.length > 0 || preview.more;

/** What a preview lists, to tell whether the ask's plan is the one the admin read. */
export const waitingSeen = (preview: WaitingPreview): string =>
  JSON.stringify([
    preview.more,
    ...preview.rejected.map(({ id, reasons }) => [id.toLowerCase(), ...reasons.map(({ code }) => code)]),
  ]);

/** The refusals a policy's change or the simulator can meet that the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'POLICY_CURRENCY_REFUSED',
  'POLICY_WIDER_THAN_MANDATE',
  'POLICY_CHANGES_SPENT',
  'POLICY_SUPPLIER_UNKNOWN',
  'MANDATE_ENDED',
  'MANDATE_NOT_IN_FORCE',
  'CURRENCY_NOT_ALLOWED',
  'WAITING_CHOICE_REQUIRED',
  'WAITING_CHOICE_NOT_OFFERED',
  'STEP_UP_NOT_ASKED',
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/** The refusals that mean the waiting requests moved since the preview: checked again before anything else. */
export const WAITING_MOVED: ReadonlySet<string> = new Set(['WAITING_CHOICE_REQUIRED', 'WAITING_CHOICE_NOT_OFFERED']);

/** What a policy's refusal or failure says; a record that failed its integrity check as itself (a 503). */
export function policyRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('policies.integrity');
  return refusalText(error, REFUSALS, 'policies.refused');
}
