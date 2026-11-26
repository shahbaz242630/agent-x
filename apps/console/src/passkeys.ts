// Adding a passkey inside Agent X (SA6; the API's passkey-additions.ts). A
// passkey added at the login service directly starts 7 days of developer or
// viewer powers (B6-3d); added here, after signing in again with a passkey the
// person already holds, it doesn't. The way:
// 1. `POST /v1/auth/passkeys/additions` answers the step-up to sign in again
//    for; the browser leaves for it, coming back to PASSKEYS_PATH with
//    `?adding=<id>`. Not `?stepped=`: the shell would offer a kept change to
//    confirm, and there is none (step-up.ts keeps nothing for this).
// 2. Back, the page asks for the add-a-passkey page's address at once, which
//    holds the one-time ticket in its fragment, and shows it as a link to open
//    in a new tab. The address lives in the page's memory alone: never the
//    console's own address, storage, the query cache or a log.
// 3. Meanwhile it checks where the addition got to until it is added or gone.
import { api, ApiError, isSignedOut, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import { t, type TextKey } from './text.ts';

export const PASSKEYS_PATH = '/more/passkeys';
const ADDITIONS = '/v1/auth/passkeys/additions';
/** The query the page comes back with from its step-up: the addition, by its challenge. */
export const ADDING = 'adding';

/** Where an addition got to, as the API says. */
export type AdditionStatus = 'STEPPED_UP' | 'WAITING_FOR_KEY' | 'ADDED' | 'GONE';

/** The refusals said in this page's own words. */
const REFUSALS = new Set([
  'STEP_UP_FAILED',
  'PASSKEY_TICKET_ALREADY_ISSUED',
  'PASSKEY_TICKET_INVALID',
  'PASSKEY_REFUSED',
]);

/** A 404 from any of these routes means the server has adding a passkey switched off. */
const OWN_WORDS: Readonly<Record<string, TextKey>> = { NOT_FOUND: 'passkeys.off' };

export function passkeyRefusal(error: unknown): string {
  if (isSignedOut(error)) return t('passkeys.signedOut');
  return refusalText(error, REFUSALS, 'passkeys.refused', OWN_WORDS);
}

/** Where the browser goes to sign in again with a passkey, coming back to this page with the addition. */
export function stepUpFor(challenge: string): string {
  const returnTo = `${PASSKEYS_PATH}?${new URLSearchParams({ [ADDING]: challenge }).toString()}`;
  return `/v1/auth/step-up?${new URLSearchParams({ challenge, returnTo }).toString()}`;
}

/** Starts an addition: the step-up's challenge to sign in again for. */
export async function beginAddition(): Promise<string> {
  const answered = await api.write<unknown>(ADDITIONS);
  const body = answered.body;
  const challenge =
    typeof body === 'object' && body !== null && 'stepUpChallengeId' in body ? body.stepUpChallengeId : undefined;
  if (answered.status !== 202 || typeof challenge !== 'string' || !isUuid(challenge)) {
    throw new ApiError(answered.status, 'STEP_UP_NOT_ASKED');
  }
  return challenge;
}

/** The add-a-passkey page to open, and when its one-time link runs out. */
export interface PasskeyPage {
  readonly page: string;
  readonly expiresAt: number;
}

/**
 * Asks for the add-a-passkey page's address, once signed in again. Only an
 * https address is taken: it becomes a link, and anything else (a
 * `javascript:` one) is never shown.
 */
export async function pageFor(id: string, idempotencyKey: string): Promise<PasskeyPage> {
  const answer = await api.post<{ readonly page?: unknown; readonly expiresAt?: unknown }>(
    `${ADDITIONS}/${id}/confirm`,
    { idempotencyKey },
  );
  const { page, expiresAt } = answer;
  const ends = typeof expiresAt === 'string' ? Date.parse(expiresAt) : Number.NaN;
  if (typeof page !== 'string' || !isHttps(page) || Number.isNaN(ends)) throw new ApiError(502, 'UNREADABLE');
  return { page, expiresAt: ends };
}

function isHttps(address: string): boolean {
  try {
    return new URL(address).protocol === 'https:';
  } catch {
    return false;
  }
}

const STATUSES: ReadonlySet<string> = new Set(['STEPPED_UP', 'WAITING_FOR_KEY', 'ADDED', 'GONE']);

/** Where the addition got to; an answer the console can't read is a failure, checked again. */
export async function statusOf(id: string): Promise<AdditionStatus> {
  const { status } = await api.get<{ readonly status?: unknown }>(`${ADDITIONS}/${id}`);
  if (typeof status !== 'string' || !STATUSES.has(status)) throw new ApiError(502, 'UNREADABLE');
  return status as AdditionStatus;
}
