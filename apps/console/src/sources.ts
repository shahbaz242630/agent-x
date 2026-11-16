// The organisation's bank accounts (6D4a, BR-03, ADR-014 §4): what one
// account's page reads (GET /v1/funding-sources/:id: the account as the bank
// partner described it, never its number or balance), a link started through
// the partner and kept over the trip to the bank, and who may press what. The
// shapes and rules are the API's (funding-sources.ts); the roles only decide
// which buttons show, and the API checks again whatever is pressed.
import { useQuery } from '@tanstack/react-query';

import { api, ApiError, isIntegrityFailed, isRefusal, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import type { Role } from './session.tsx';
import { t } from './text.ts';

/** What happens to an account's pending requests when its bank consent runs out (decision 21): none means cancel. */
type ConsentExpiry = 'cancel' | 'pause';

export interface Source {
  readonly id: string;
  readonly status: 'ACTIVE' | 'SUSPENDED' | 'ENDED';
  readonly availability: 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'UNAVAILABLE';
  /** The partner's own word for the bank's consent, shown as it is. */
  readonly consentStatus: string;
  readonly consentExpiresAt: string;
  readonly holderName: string;
  readonly accountType: 'retail' | 'sme' | 'corporate';
  readonly hint: string;
  readonly controls: {
    readonly currency: string;
    readonly period: 'day' | 'week' | 'month' | 'year';
    /** Minor units as a string of digits: may be past what a number holds exactly. */
    readonly maxPaymentMinor: string;
    readonly maxPeriodMinor: string;
    readonly maxPeriodPayments: number;
  };
  readonly consentExpiry: ConsentExpiry | null;
}

/** A link to the bank, as the API answers it. */
export interface Link {
  readonly id: string;
  readonly status: 'open' | 'linked' | 'rejected' | 'expired' | 'unknown';
  readonly expiresAt: string;
  readonly createdAt: string;
  readonly settledAt: string | null;
  readonly sourceId: string | null;
}

/** Who may link an account (LINKING_ROLES), refresh one (REFRESHING_ROLES) and choose its consent expiry (CONSENT_EXPIRY_ROLES). */
export const LINKING: readonly Role[] = ['admin'];

export const SOURCES_PATH = '/v1/funding-sources';

/** An account's address in the API. */
export const sourceAt = (id: string): string => `${SOURCES_PATH}/${encodeURIComponent(id)}`;

/** One account; asked for only by a UUID, as any other address names none (shown as not found). */
export function useSource(id: string, organization: string) {
  return useQuery({
    queryKey: ['sources', organization, 'one', id],
    enabled: isUuid(id),
    queryFn: () => api.get<Source>(sourceAt(id), { organization }),
  });
}

/** AED's minor digits, and any other currency's as Intl knows them; 2 for a code it doesn't. */
function digitsOf(currency: string): number {
  if (currency === 'AED') return 2;
  try {
    return new Intl.NumberFormat('en', { style: 'currency', currency }).resolvedOptions().maximumFractionDigits ?? 2;
  } catch {
    return 2;
  }
}

/**
 * A limit in minor units as a statement shows it: `AED 50,000.00`. Read from
 * its digits as text and BigInt, never a floating-point number, so no fils is
 * lost however large; anything but digits is shown as given.
 */
export function limitText(minor: string, currency: string): string {
  if (!/^\d+$/.test(minor)) return `${currency} ${minor}`;
  const digits = digitsOf(currency);
  const padded = minor.padStart(digits + 1, '0');
  const whole = new Intl.NumberFormat('en').format(BigInt(padded.slice(0, padded.length - digits)));
  return digits > 0 ? `${currency} ${whole}.${padded.slice(-digits)}` : `${currency} ${whole}`;
}

/** Whether a partner's page may be opened: HTTPS only, as the API itself checks (isPartnerPage). */
export function isBankPage(url: string): boolean {
  return URL.canParse(url) && new URL(url).protocol === 'https:';
}

/** A link started and not yet settled: kept in this tab over the trip to the bank, so a reload still finds it. */
export interface Started {
  readonly link: Link;
  readonly authoriseUrl: string;
}

const KEY = 'agentx.source-link.';
const keyOf = (user: string, organization: string) => `${KEY}${user.toLowerCase()}/${organization}`;

const isStarted = (value: unknown): value is Started =>
  typeof value === 'object' &&
  value !== null &&
  'authoriseUrl' in value &&
  typeof value.authoriseUrl === 'string' &&
  'link' in value &&
  typeof value.link === 'object' &&
  value.link !== null &&
  'id' in value.link &&
  typeof value.link.id === 'string' &&
  isUuid(value.link.id) &&
  'expiresAt' in value.link &&
  typeof value.link.expiresAt === 'string';

/** The link this person started in this organisation and tab, or none (storage cleared or blocked). */
export function startedLink(user: string, organization: string): Started | undefined {
  try {
    const kept: unknown = JSON.parse(sessionStorage.getItem(keyOf(user, organization)) ?? 'null');
    return isStarted(kept) ? kept : undefined;
  } catch {
    return undefined;
  }
}

/** Keeps a started link, or forgets it with null. Storage blocked: it lasts while the page is open. */
export function keepLink(user: string, organization: string, started: Started | null): void {
  try {
    if (started === null) sessionStorage.removeItem(keyOf(user, organization));
    else sessionStorage.setItem(keyOf(user, organization), JSON.stringify(started));
  } catch {
    // Nothing kept: the page's own state still holds it.
  }
}

/** The 4xx answers that leave a write undecided, so its key is kept for Try again: still being worked on, too many tries. */
const UNDECIDED = new Set(['IDEMPOTENCY_KEY_BUSY', 'RATE_LIMITED']);

/** Whether an answer decides a write, so its idempotency key is done with: any but no answer, a 5xx, a 401 or UNDECIDED. */
export const decides = (error: unknown): boolean =>
  isRefusal(error) && error.status !== 401 && !UNDECIDED.has(error.code);

/** The refusals an account's changes can meet that the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'LINK_STARTS_SPENT',
  'IDEMPOTENCY_KEY_REUSED',
  'IDEMPOTENCY_KEY_BUSY',
  'RATE_LIMITED',
  'SOURCE_NOT_USABLE',
  'PENDING_REQUESTS_CANCELLED',
  'STATEMENT_CHANGED',
  'STEP_UP_NOT_ASKED',
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/**
 * What a refusal or failure of an account's change says: a record that failed
 * the integrity check, and the partner not answering, as themselves (each a
 * 503, so not refusals).
 */
export function sourceRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('sources.integrity');
  if (error instanceof ApiError && error.code === 'PARTNER_UNAVAILABLE') return t('sources.partnerUnavailable');
  return refusalText(error, REFUSALS, 'sources.refused');
}
