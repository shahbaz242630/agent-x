// The shared step-up (6A2, ADR-003 §9). A change that needs a fresh sign-in
// is asked first: the API answers 202 with a challenge for this session. The
// browser signs in again for it (`/v1/auth/step-up`), comes back to the same
// page with `?stepped=<challenge>`, and the person confirms the change there,
// which sends the ask's own body with the challenge to the change's confirm
// address. A change the API makes at once (no step-up asked) is just done.
//
// What to confirm is kept over the round trip in this tab's sessionStorage,
// by challenge: nothing secret (the challenge is good only for this session,
// and only after the fresh sign-in), and gone once confirmed or dismissed. The
// API checks everything again at the confirm whatever the console kept.
import { api, isRefusal } from './api.ts';
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

/** Where the browser goes to sign in again for `challenge`, coming back to `page` to confirm. */
export function stepUpAddress(challenge: string, page: string): string {
  const returnTo = `${page}?${new URLSearchParams({ [STEPPED]: challenge }).toString()}`;
  return `/v1/auth/step-up?${new URLSearchParams({ challenge, returnTo }).toString()}`;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The challenge a step-up's 202 names; none for any other answer (another 202, such as a download started). */
function challengeIn(status: number, body: unknown): string | undefined {
  if (status !== 202 || typeof body !== 'object' || body === null || !('stepUpChallengeId' in body)) return undefined;
  const { stepUpChallengeId } = body;
  return typeof stepUpChallengeId === 'string' && UUID.test(stepUpChallengeId) ? stepUpChallengeId : undefined;
}

/** A change the API asked a step-up for: what its ask answered, and the way on to sign in again for it. */
export interface Asked {
  /** The ask's answer, which may say how the change would come out (an approve that would reject, 6B1). */
  readonly answer: unknown;
  /** Keeps the change and leaves to sign in again, under `label` if what was asked turned out otherwise. */
  readonly stepUp: (label?: string) => 'stepping';
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
    stepUp: (shown = label) => {
      keep({ challenge, label: shown, confirmPath, body, organization, idempotencyKey: crypto.randomUUID() });
      goTo(stepUpAddress(challenge, window.location.pathname));
      return 'stepping';
    },
  };
}

/**
 * Asks for a change. Done at once: its answer. Asked for a step-up: the change
 * is kept, the browser leaves to sign in again, and this gives back `stepping`.
 */
export async function ask(change: Change): Promise<{ readonly done: unknown } | 'stepping'> {
  const asked = await askFirst(change);
  return 'done' in asked ? asked : asked.stepUp();
}

/**
 * Confirms a change once signed in again: the ask's body with its challenge.
 * Forgotten once the API has decided it, either way: a refused challenge is
 * spent or was never good. Kept after a failure on the way (no answer, a 5xx),
 * so the person can try the confirm again.
 */
export async function confirm(pending: PendingChange): Promise<void> {
  try {
    await api.post<unknown>(pending.confirmPath, {
      organization: pending.organization,
      idempotencyKey: pending.idempotencyKey,
      body: { ...pending.body, stepUpChallengeId: pending.challenge },
    });
    forget(pending.challenge);
  } catch (error) {
    if (isRefusal(error)) forget(pending.challenge);
    throw error;
  }
}
