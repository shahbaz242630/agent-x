// The console session the routes' HTTP tests sign in with (6A1/6B1's clean-up
// batch, S184): one shape where each file had its own copy. A helper, not a
// test: Vitest leaves `*.helper.test.ts` out (vitest.config.ts), and the name
// keeps it with the tests.
import type { LiveSession } from '@agentx/core/modules/identity';

/** A passkey's sign-in, as an admin needs (ADR-012 §7). */
export const PASSKEY = ['pwd', 'user', 'mfa'] as const;
/** A one-time code's sign-in: a second factor, but no passkey. */
export const ONE_TIME_CODE = ['pwd', 'otp', 'mfa'] as const;

const SECOND_MS = 1000;
const MINUTE_MS = 60 * SECOND_MS;

/** The session's moments after its sign-in: made 5 s after, last seen at 10 min, idle-ended at 40 min, ended at 12 h. */
const OPENED_MS = 5 * SECOND_MS;
const LAST_SEEN_MS = 10 * MINUTE_MS;
const IDLE_ENDS_MS = 40 * MINUTE_MS;
const ENDS_MS = 12 * 60 * MINUTE_MS + OPENED_MS;

/** The year a session that should never end in a test's time ends in. */
const FAR_YEAR = 2099;

/**
 * A live session signed in at `signedInAt` (an ISO instant): `amr` a
 * passkey's unless given; its ends that day, or the same day in 2099 when
 * `endless` (a test whose clock moves on, or reads the real time).
 */
export function liveSession(
  signedInAt: string,
  { amr = PASSKEY, endless = false }: { readonly amr?: readonly string[]; readonly endless?: boolean } = {},
): LiveSession {
  const authTime = new Date(signedInAt);
  const after = (ms: number) => new Date(authTime.getTime() + ms);
  const ending = (ms: number) => {
    const at = after(ms);
    if (endless) at.setUTCFullYear(FAR_YEAR);
    return at;
  };
  return {
    sessionId: '0199a0f0-0000-7000-8000-000000000022',
    userId: '0199a0f0-0000-7000-8000-000000000011',
    idpSessionId: 'V1_1',
    authTime,
    amr,
    createdAt: after(OPENED_MS),
    lastSeenAt: after(LAST_SEEN_MS),
    endsAt: ending(ENDS_MS),
    idleEndsAt: ending(IDLE_ENDS_MS),
  };
}
