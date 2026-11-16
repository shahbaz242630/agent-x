// An organisation's mandates (6D3a, BR-05, BR-06): what the list and one
// mandate's page read (GET /v1/mandates, GET /v1/mandates/:id), the rules a
// draft's terms keep, typed amounts read exactly, and who may press what. The
// shapes and rules are the API's (mandates.ts, the mandates module): the limits
// nest (approval threshold ≤ per-order ≤ monthly), every setting is the
// admin's to choose with none picked for them (Rule Book §1.9), and every
// amount is whole fils. The roles only decide which buttons show; the API
// checks again whatever is pressed.
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

import { api, isIntegrityFailed, isRefusal, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import { knownMinorDigits, minorDigits, pageQuery } from './requests.ts';
import type { Role } from './session.tsx';
import { t } from './text.ts';
import { isVisibleName } from './visible-name.ts';

export type MandateStatus = 'PENDING_ACCEPTANCE' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'EXPIRED';
type ConsentLimits = 'strict' | 'flexible';
type OverLimit = 'refuse' | 'approval';

/** A mandate as the list gives it: the purpose of the version in force, or else the draft's. */
export interface MandateListed {
  readonly id: string;
  readonly agentId: string;
  readonly timeZone: string;
  readonly splitWindowHours: number;
  readonly status: MandateStatus;
  readonly purpose: string;
}

/** One version of a mandate's terms, made once (MandateVersion). */
export interface MandateVersion {
  readonly id: string;
  readonly version: number;
  readonly purpose: string;
  readonly currency: string;
  readonly perOrderLimitMinor: number;
  readonly monthlyLimitMinor: number;
  readonly approvalThresholdMinor: number;
  readonly supplierIds: readonly string[];
  readonly fundingSourceId: string;
  readonly splitCheck: boolean;
  readonly consentLimits: ConsentLimits;
  readonly endsAt: string | null;
  /** `not-chosen`: a version drafted before the choice existed, which refuses. */
  readonly overLimit: OverLimit | 'not-chosen';
  readonly termsHash: string;
  /** The membership of the admin who drafted it. */
  readonly draftedBy: string;
  readonly draftedAt: string;
  readonly consentWarnings: readonly string[];
  readonly capWarnings: readonly string[];
  readonly splitCheckWarning: string | null;
}

export type CapFrom = 'mandate-policy' | 'organization-policy' | 'none' | 'not-set';

/** A mandate with its version in force and the draft waiting (MandateDetails). */
export interface MandateDetails extends Omit<MandateListed, 'purpose'> {
  readonly acceptedBy: string | null;
  readonly acceptedAt: string | null;
  readonly current: MandateVersion | null;
  readonly pending: MandateVersion | null;
  readonly agentMonthlyCap: {
    readonly capMinor: number | null;
    readonly currency: string | null;
    readonly from: CapFrom;
  };
}

/** A bank account a mandate may draw on, as GET /v1/funding-sources gives it: never an account number. */
export interface SourceListed {
  readonly id: string;
  readonly status: 'ACTIVE' | 'SUSPENDED' | 'ENDED';
  readonly availability: 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'UNAVAILABLE';
  readonly holderName: string;
  readonly hint: string;
  readonly controls: {
    readonly currency: string;
    readonly period: 'day' | 'week' | 'month' | 'year';
    readonly maxPaymentMinor: string;
    readonly maxPeriodMinor: string;
  };
}

/**
 * Who may draft, accept, suspend, resume, revoke or choose past the limits
 * (DRAFTING_ROLES, ACCEPTING_ROLES, MOVING_ROLES): an admin, every one. Every
 * member reads them.
 */
export const MANAGING: readonly Role[] = ['admin'];

/** Whether a mandate has ended for good: nothing more can be done with it. */
export const isEnded = (status: MandateStatus): boolean => status === 'REVOKED' || status === 'EXPIRED';

/** A mandate's address in the API. */
export const mandateAt = (id: string): string => `/v1/mandates/${encodeURIComponent(id)}`;

interface Page<T> {
  readonly listed: readonly T[];
  readonly next: string | null;
  readonly unchecked: readonly string[];
}

/** A list in the organisation, a page at a time, its things under `key` in each answer. */
function useList<T>(name: string, path: string, key: string, organization: string) {
  return useInfiniteQuery({
    queryKey: [name, organization, 'list'],
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: Page<T>) => last.next ?? undefined,
    queryFn: async ({ pageParam }): Promise<Page<T>> => {
      const answer = await api.get<Readonly<Record<string, unknown>> & Omit<Page<T>, 'listed'>>(
        `${path}?${pageQuery(pageParam)}`,
        { organization },
      );
      return { listed: answer[key] as readonly T[], next: answer.next, unchecked: answer.unchecked };
    },
  });
}

/** The organisation's mandates, a page at a time. */
export const useMandateList = (organization: string) =>
  useList<MandateListed>('mandates', '/v1/mandates', 'mandates', organization);

/** The organisation's bank accounts, a page at a time, with the limits their bank consent holds. */
export const useSourceList = (organization: string) =>
  useList<SourceListed>('funding-sources', '/v1/funding-sources', 'sources', organization);

/** One mandate with its versions; asked for only by a UUID, as any other address names none (shown as not found). */
export function useMandate(id: string, organization: string) {
  return useQuery({
    queryKey: ['mandates', organization, 'one', id],
    enabled: isUuid(id),
    queryFn: () => api.get<MandateDetails>(mandateAt(id), { organization }),
  });
}

/** The minor digits of the Pilot's one currency, AED (fils): what a form checks by before a bank account is chosen. */
const AED_DIGITS = 2;
/** Whole units as typed: grouped by commas, or not. */
const WHOLE = /^(?:\d{1,3}(?:,\d{3})+|\d+)$/;
const DIGITS = /^\d+$/;

/**
 * An amount typed in the currency's whole units as its minor units, read
 * exactly (never through floating point), by its own minor digits (AED: 2,
 * so `2,500.5` is 250050). None for anything the API wouldn't take: empty, a
 * sign, more decimals than the currency has, below one minor unit or past
 * 2^53 − 1.
 */
export function amountMinor(typed: string, digits = AED_DIGITS): number | undefined {
  const [whole = '', fraction = '', ...more] = typed.trim().split('.');
  const fractioned = typed.includes('.');
  if (!WHOLE.test(whole) || more.length > 0) return undefined;
  if (fractioned && (fraction.length > digits || !DIGITS.test(fraction))) return undefined;
  const scale = 10n ** BigInt(digits);
  const minor =
    BigInt(whole.replaceAll(',', '')) * scale + (fraction === '' ? 0n : BigInt(fraction.padEnd(digits, '0')));
  if (minor < 1n || minor > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  return Number(minor);
}

/** Minor units as a field shows them to change: `2500.00`, never grouped, so it reads back the same. */
export function amountTyped(minor: number, digits = AED_DIGITS): string {
  const scale = 10n ** BigInt(digits);
  const units = BigInt(minor);
  const whole = String(units / scale);
  return digits === 0 ? whole : `${whole}.${String(units % scale).padStart(digits, '0')}`;
}

/**
 * How an amount field says what to type: its currency (the chosen bank
 * account's, AED's until one is chosen), an example in that currency's own
 * digits, and how many decimals it takes.
 */
export function amountWords(
  currency: string | undefined,
): Readonly<Record<'currency' | 'example' | 'decimals', string>> {
  const shown = currency ?? 'AED';
  const digits = minorDigits(shown);
  return {
    currency: shown,
    example: amountTyped(2500 * 10 ** digits, digits),
    decimals:
      digits === 0 ? t('mandates.form.decimals.none') : t('mandates.form.decimals.some', { digits: String(digits) }),
  };
}

/** The most characters a purpose may have (PURPOSE_MOST), the suppliers one names (MOST_ALLOWED_SUPPLIERS). */
export const PURPOSE_MOST = 200;
export const SUPPLIERS_MOST = 100;
/** The split window's bounds in hours (SPLIT_WINDOW_HOURS). */
export const WINDOW_HOURS = { least: 1, most: 744 } as const;

/** A version's terms as the form holds them: amounts as typed, every setting none until chosen. */
export interface TermsTyped {
  readonly purpose: string;
  readonly perOrder: string;
  readonly monthly: string;
  readonly threshold: string;
  readonly supplierIds: readonly string[];
  readonly fundingSourceId: string | null;
  readonly splitCheck: 'on' | 'off' | null;
  readonly consentLimits: ConsentLimits | null;
  readonly ends: 'never' | 'on' | null;
  /** A `datetime-local` field's value, in the browser's own zone. */
  readonly endsAt: string;
}

/** A new mandate as the form holds it: its agent, zone and window as well, fixed for good once drafted. */
export interface DraftTyped extends TermsTyped {
  readonly agentId: string | null;
  readonly timeZone: string;
  readonly splitWindowHours: string;
}

export type TermsProblem =
  | 'currency'
  | 'purpose'
  | 'perOrder'
  | 'monthly'
  | 'threshold'
  | 'thresholdAbove'
  | 'perOrderAbove'
  | 'suppliers'
  | 'source'
  | 'splitCheck'
  | 'consentLimits'
  | 'ends'
  | 'endsAt';
export type DraftProblem = TermsProblem | 'agent' | 'timeZone' | 'splitWindowHours';

/** The end as an instant, or none for a value that names none. */
const endOf = (typed: TermsTyped): number | undefined => {
  const at = new Date(typed.endsAt).getTime();
  return typed.endsAt === '' || Number.isNaN(at) ? undefined : at;
};

/** The limits' problems: each one readable, then nested as the API has them (mandateTerms). */
function limitProblems(typed: TermsTyped, digits: number): TermsProblem[] {
  const perOrder = amountMinor(typed.perOrder, digits);
  const monthly = amountMinor(typed.monthly, digits);
  const threshold = amountMinor(typed.threshold, digits);
  const problems: TermsProblem[] = [];
  if (perOrder === undefined) problems.push('perOrder');
  if (monthly === undefined) problems.push('monthly');
  if (threshold === undefined) problems.push('threshold');
  if (threshold !== undefined && perOrder !== undefined && threshold > perOrder) problems.push('thresholdAbove');
  if (perOrder !== undefined && monthly !== undefined && perOrder > monthly) problems.push('perOrderAbove');
  return problems;
}

/**
 * Each part of a version's terms the API would refuse, checked before anything
 * is sent, the amounts by `currency`'s minor digits (the chosen bank
 * account's; AED's until one is chosen); the API checks again.
 */
export function termsProblems(typed: TermsTyped, now = Date.now(), currency?: string): TermsProblem[] {
  const problems: TermsProblem[] = [];
  const digits = currency === undefined ? AED_DIGITS : knownMinorDigits(currency);
  if (digits === undefined) problems.push('currency');
  if (!isVisibleName(typed.purpose, PURPOSE_MOST)) problems.push('purpose');
  problems.push(...limitProblems(typed, digits ?? AED_DIGITS));
  if (typed.supplierIds.length === 0 || typed.supplierIds.length > SUPPLIERS_MOST) problems.push('suppliers');
  if (typed.fundingSourceId === null) problems.push('source');
  if (typed.splitCheck === null) problems.push('splitCheck');
  if (typed.consentLimits === null) problems.push('consentLimits');
  if (typed.ends === null) problems.push('ends');
  const ends = endOf(typed);
  if (typed.ends === 'on' && (ends === undefined || ends <= now)) problems.push('endsAt');
  return problems;
}

/** Whether the browser knows a zone by this IANA name; the API checks against its own database again. */
function isTimeZone(zone: string): boolean {
  if (zone === '') return false;
  try {
    new Intl.DateTimeFormat('en', { timeZone: zone }).format(0);
    return true;
  } catch {
    return false;
  }
}

/** Each part of a new mandate the API would refuse: its agent, zone and window, then its terms. */
export function draftProblems(typed: DraftTyped, now = Date.now(), currency?: string): DraftProblem[] {
  const problems: DraftProblem[] = [];
  if (typed.agentId === null) problems.push('agent');
  if (!isTimeZone(typed.timeZone)) problems.push('timeZone');
  const hours = /^\d{1,3}$/.test(typed.splitWindowHours) ? Number(typed.splitWindowHours) : 0;
  if (hours < WINDOW_HOURS.least || hours > WINDOW_HOURS.most) problems.push('splitWindowHours');
  return [...problems, ...termsProblems(typed, now, currency)];
}

/** Read only once termsProblems found none: each amount readable, each setting chosen. */
const known = <T>(value: T | null | undefined): T => {
  if (value === null || value === undefined) throw new Error('Checked by termsProblems before it is sent');
  return value;
};

/** The terms as the API takes them, in `currency` (the source's): the over-limit choice and its words added at the confirm. */
export function termsBody(typed: TermsTyped, currency: string) {
  const digits = known(knownMinorDigits(currency));
  return {
    purpose: typed.purpose,
    currency,
    perOrderLimitMinor: known(amountMinor(typed.perOrder, digits)),
    monthlyLimitMinor: known(amountMinor(typed.monthly, digits)),
    approvalThresholdMinor: known(amountMinor(typed.threshold, digits)),
    supplierIds: typed.supplierIds,
    fundingSourceId: known(typed.fundingSourceId),
    splitCheck: typed.splitCheck === 'on',
    consentLimits: known(typed.consentLimits),
    endsAt: typed.ends === 'on' ? new Date(known(endOf(typed))).toISOString() : null,
  };
}

/** A new mandate as the API takes it. */
export const draftBody = (typed: DraftTyped, currency: string) => ({
  agentId: known(typed.agentId),
  timeZone: typed.timeZone,
  splitWindowHours: Number(typed.splitWindowHours),
  ...termsBody(typed, currency),
});

/** An ISO time as a `datetime-local` field holds it, in the browser's zone (minutes, no seconds). */
export function localTyped(iso: string): string {
  const at = new Date(iso);
  const two = (part: number) => String(part).padStart(2, '0');
  return (
    `${String(at.getFullYear())}-${two(at.getMonth() + 1)}-${two(at.getDate())}` +
    `T${two(at.getHours())}:${two(at.getMinutes())}`
  );
}

/**
 * A version's terms to change for a new one: its purpose, limits, suppliers
 * and source as they are, every setting left for the admin to choose again
 * (Rule Book §1.9: the page shows what is in force beside each).
 */
export function termsFrom(version: MandateVersion): TermsTyped {
  const digits = minorDigits(version.currency);
  return {
    purpose: version.purpose,
    perOrder: amountTyped(version.perOrderLimitMinor, digits),
    monthly: amountTyped(version.monthlyLimitMinor, digits),
    threshold: amountTyped(version.approvalThresholdMinor, digits),
    supplierIds: version.supplierIds,
    fundingSourceId: version.fundingSourceId,
    splitCheck: null,
    consentLimits: null,
    ends: null,
    endsAt: version.endsAt === null ? '' : localTyped(version.endsAt),
  };
}

export const NO_TERMS: TermsTyped = {
  purpose: '',
  perOrder: '',
  monthly: '',
  threshold: '',
  supplierIds: [],
  fundingSourceId: null,
  splitCheck: null,
  consentLimits: null,
  ends: null,
  endsAt: '',
};

/** One pending request as an acceptance's carry would settle it (decision 17). */
export interface Carried {
  readonly id: string;
  readonly outcome: 'carry' | 'cancel';
  readonly reasons: readonly { readonly code: string; readonly message: string }[];
}

/** What an acceptance's ask answered: for a carry, what it will do to each pending request, and how many wait their turn. */
export function carryIn(answer: unknown): { readonly plan: readonly Carried[]; readonly later: number } {
  if (typeof answer !== 'object' || answer === null) return { plan: [], later: 0 };
  const plan = 'carry' in answer && Array.isArray(answer.carry) ? (answer.carry as readonly Carried[]) : [];
  const later = 'carryLater' in answer && typeof answer.carryLater === 'number' ? answer.carryLater : 0;
  return { plan, later };
}

/** The refusals a mandate's change can meet that the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'AGENT_NOT_ACTIVE',
  'AGENT_ZONE_KEPT',
  'MANDATE_DRAFTS_SPENT',
  'MANDATE_DRAFT_EXPIRED',
  'MANDATE_ENDED',
  'MANDATE_NOT_ACCEPTED',
  'MANDATE_NOT_ACTIVE',
  'MANDATE_NOT_SUSPENDED',
  'MANDATE_NOT_WAITING',
  'MANDATE_OPEN',
  'MANDATE_PAST_CONSENT',
  'MANDATE_SUSPENDED',
  'PENDING_CHOICE_NOT_OFFERED',
  'PENDING_CHOICE_REQUIRED',
  'PENDING_REQUESTS_CANCELLED',
  'SOURCE_NOT_USABLE',
  'SUPPLIER_UNKNOWN',
  'HISTORY_TOO_LONG',
  'STATEMENT_CHANGED',
  'STEP_UP_NOT_ASKED',
  'IDEMPOTENCY_KEY_BUSY',
  'IDEMPOTENCY_KEY_REUSED',
  'RATE_LIMITED',
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/** What a refusal or failure of a mandate's change says: a record that failed the integrity check as itself (a 503). */
export function mandateRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('mandates.integrity');
  return refusalText(error, REFUSALS, 'mandates.refused');
}

/**
 * The refusals a draft sent again with its held key may meet before the API
 * looks the key up (a gate: the words' version, access, too many tries, the
 * first try still being worked on): they say nothing of the first try.
 */
const GATES = new Set([
  'STATEMENT_CHANGED',
  'FORBIDDEN',
  'RATE_LIMITED',
  'IDEMPOTENCY_KEY_BUSY',
  'AGENT_BUSY',
  'ORGANISATION_BUSY',
  'PLATFORM_BUSY',
]);

/**
 * Whether a draft's answer decides it, so its key need not be kept: no
 * answer, or a 5xx, never does (the draft may have been made). A first send's
 * refusal does, as nothing was written with a fresh key. A held one asked
 * again: a refusal past the gates does, as a draft made by the first try
 * would have been answered as made; a gate or a 401 doesn't.
 */
export function decidesTheDraft(error: unknown, retry: boolean): boolean {
  if (!isRefusal(error)) return false;
  if (!retry) return true;
  return error.status !== 401 && !GATES.has(error.code);
}

/** What a draft's failure says: a deciding refusal as any; otherwise why it is still held for Try again. */
export function draftFailure(error: unknown, retry: boolean): string {
  // A held draft's body is checked (an end passed since the first try) before its key is looked up: the first may stand.
  if (retry && isRefusal(error) && error.code === 'BAD_REQUEST') return t('mandates.held.badRequest');
  if (decidesTheDraft(error, retry) || isIntegrityFailed(error)) return mandateRefusal(error);
  if (!isRefusal(error)) return t('mandates.held.unanswered');
  if (error.code === 'STATEMENT_CHANGED') return t('mandates.held.wordsChanged');
  return t('mandates.held.refused', { said: mandateRefusal(error) });
}
