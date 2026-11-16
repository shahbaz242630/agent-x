// The shared step-up (6A2, ADR-003 §9). A change that needs a fresh sign-in
// is asked first: the API answers 202 with a challenge for this session. The
// browser signs in again for it (`/v1/auth/step-up`), comes back to the same
// page with `?stepped=<challenge>` (or `?stepUpFailed=<challenge>` when the
// API refused the fresh sign-in), and the person confirms the change there,
// which sends the ask's own body with the challenge to the change's confirm
// address. A change the API makes at once (no step-up asked) is just done.
//
// What to confirm is kept over the round trip in this tab's sessionStorage,
// by challenge: nothing secret (the challenge is good only for this session,
// and only after the fresh sign-in), and gone once confirmed or dismissed. The
// API checks everything again at the confirm whatever the console kept.
import { api, ApiError, isRefusal, isUuid } from './api.ts';
import { goTo } from './navigate.ts';

/** A change asked and waiting for its step-up: where to confirm it and with what. */
export interface PendingChange {
  readonly challenge: string;
  /** What the change is, in the words its screen asked it with: shown again to confirm it. */
  readonly label: string;
  readonly confirmPath: string;
  readonly body: Readonly<Record<string, unknown>>;
  readonly organization?: string | undefined;
  /** The confirm's idempotency key, made once: a retry after no answer replays the first try's answer. */
  readonly idempotencyKey: string;
}

/** What the person asks: the ask's address and body, its confirm's address, and the organisation it acts in. */
export interface Change {
  readonly label: string;
  readonly askPath: string;
  readonly confirmPath: string;
  readonly body: Readonly<Record<string, unknown>>;
  readonly organization?: string | undefined;
}

/** A change asked at `at` and confirmed at its `/confirm`, as every step-up's routes are. */
export const changeAt = (
  at: string,
  label: string,
  body: Readonly<Record<string, unknown>>,
  organization: string,
): Change => ({ label, askPath: at, confirmPath: `${at}/confirm`, body, organization });

/** Storage is blocked here (a private window, a policy): the change can't be carried over the sign-in. */
export class StepUpStorageBlocked extends Error {
  constructor() {
    super('This browser keeps no site storage, which confirming a change after signing in again needs');
    this.name = 'StepUpStorageBlocked';
  }
}

const KEY = 'agentx.step-up.';
/** The query a page comes back with from its step-up. */
export const STEPPED = 'stepped';
/** The query a page comes back with when its step-up failed at the login service's return: the challenge it was for (CO2). */
export const STEP_UP_FAILED = 'stepUpFailed';

const isPending = (value: unknown): value is PendingChange =>
  typeof value === 'object' &&
  value !== null &&
  'challenge' in value &&
  typeof value.challenge === 'string' &&
  'label' in value &&
  typeof value.label === 'string' &&
  'confirmPath' in value &&
  typeof value.confirmPath === 'string' &&
  'idempotencyKey' in value &&
  typeof value.idempotencyKey === 'string' &&
  'body' in value &&
  typeof value.body === 'object' &&
  value.body !== null;

function keep(pending: PendingChange): void {
  try {
    sessionStorage.setItem(KEY + pending.challenge, JSON.stringify(pending));
  } catch {
    throw new StepUpStorageBlocked();
  }
}

/** The change waiting for this challenge's step-up, or none (another tab's, already confirmed, or storage cleared). */
export function pendingFor(challenge: string): PendingChange | undefined {
  try {
    const kept: unknown = JSON.parse(sessionStorage.getItem(KEY + challenge) ?? 'null');
    return isPending(kept) && kept.challenge === challenge ? kept : undefined;
  } catch {
    return undefined;
  }
}

/** Forgets a change: confirmed, or the person chose not to. */
export function forget(challenge: string): void {
  try {
    sessionStorage.removeItem(KEY + challenge);
  } catch {
    // Storage blocked: nothing was kept.
  }
}

/** A page's own query (its filter, `?org=`, CO5): its address's, less a step-up's. */
export function ownQuery(search: string): URLSearchParams {
  const query = new URLSearchParams(search);
  query.delete(STEPPED);
  query.delete(STEP_UP_FAILED);
  return query;
}

/** The most a way back may be, and what it may hold, as the API takes it (RETURN_PATH). */
const RETURN_MOST = 512;
const RETURN_CHARACTERS = /^[\w\-.~/%?=&]*$/;

/**
 * Where the browser goes to sign in again for `challenge`, coming back to
 * `path` to confirm, with the page's own query kept (its filter, `?org=`,
 * CO5) less any earlier step-up's. A way back the API wouldn't take (over 512
 * characters, or holding what RETURN_PATH doesn't) keeps the path alone.
 */
export function stepUpAddress(challenge: string, path: string, search = ''): string {
  const query = ownQuery(search);
  query.set(STEPPED, challenge);
  // URLSearchParams writes a space as `+`, which RETURN_PATH doesn't hold; `%20` says the same.
  const kept = `${path}?${query.toString().replaceAll('+', '%20')}`;
  const returnTo =
    kept.length <= RETURN_MOST && RETURN_CHARACTERS.test(kept)
      ? kept
      : `${path}?${new URLSearchParams({ [STEPPED]: challenge }).toString()}`;
  return `/v1/auth/step-up?${new URLSearchParams({ challenge, returnTo }).toString()}`;
}

/** The challenge a step-up's 202 names; none for any other answer (another 202, such as a download started). */
function challengeIn(status: number, body: unknown): string | undefined {
  if (status !== 202 || typeof body !== 'object' || body === null || !('stepUpChallengeId' in body)) return undefined;
  const { stepUpChallengeId } = body;
  return typeof stepUpChallengeId === 'string' && isUuid(stepUpChallengeId) ? stepUpChallengeId : undefined;
}

/** A change the API asked a step-up for: what its ask answered, and the way on to sign in again for it. */
export interface Asked {
  /** The ask's answer, which may say how the change would come out (an approve that would reject, 6B1). */
  readonly answer: unknown;
  /**
   * Keeps the change and leaves to sign in again, under `label` if what was
   * asked turned out otherwise, its confirm sending `confirmed` too: what the
   * person confirmed once the ask answered (the version of the words shown, CO3).
   */
  readonly stepUp: (label?: string, confirmed?: Readonly<Record<string, unknown>>) => 'stepping';
}

/**
 * Asks for a change and stops there: done at once, its answer; asked for a
 * step-up, the ask's answer, to show before stepping up (`stepUp`).
 */
export async function askFirst(change: Change): Promise<{ readonly done: unknown } | Asked> {
  const { label, askPath, confirmPath, body, organization } = change;
  const answered = await api.write<unknown>(askPath, { organization, body });
  const challenge = challengeIn(answered.status, answered.body);
  if (challenge === undefined) return { done: answered.body };
  return {
    answer: answered.body,
    stepUp: (shown = label, confirmed = {}) => {
      keep({
        challenge,
        label: shown,
        confirmPath,
        body: { ...body, ...confirmed },
        organization,
        idempotencyKey: crypto.randomUUID(),
      });
      goTo(stepUpAddress(challenge, window.location.pathname, window.location.search));
      return 'stepping';
    },
  };
}

/**
 * Asks for a change. Done at once: its answer. Asked for a step-up: the change
 * is kept (its confirm sending `confirmed` too: the version of the words shown,
 * CO3), the browser leaves to sign in again, and this gives back `stepping`.
 */
export async function ask(
  change: Change,
  confirmed?: Readonly<Record<string, unknown>>,
): Promise<{ readonly done: unknown } | 'stepping'> {
  const asked = await askFirst(change);
  return 'done' in asked ? asked : asked.stepUp(undefined, confirmed);
}

/**
 * A change that must be confirmed by passkey: asked and answered with no
 * passkey asked, nothing was made (or what the confirm alone gives, an
 * agent's key, would be lost), so it is refused, never said done.
 */
export async function mustStepUp(asking: Promise<{ readonly done: unknown } | 'stepping'>): Promise<'stepping'> {
  if ((await asking) !== 'stepping') throw new ApiError(200, 'STEP_UP_NOT_ASKED');
  return 'stepping';
}

/**
 * Confirms a change once signed in again: the ask's body with its challenge,
 * giving back the confirm's answer (a new agent key arrives in it, for the
 * caller's memory alone). Forgotten once the API has decided it, either way:
 * a refused challenge is spent or was never good. Kept after a failure on the
 * way (no answer, a 5xx), so the person can try the confirm again.
 */
export async function confirm(pending: PendingChange): Promise<unknown> {
  try {
    const answer = await api.post<unknown>(pending.confirmPath, {
      organization: pending.organization,
      idempotencyKey: pending.idempotencyKey,
      body: { ...pending.body, stepUpChallengeId: pending.challenge },
    });
    forget(pending.challenge);
    return answer;
  } catch (error) {
    if (isRefusal(error)) forget(pending.challenge);
    throw error;
  }
}
