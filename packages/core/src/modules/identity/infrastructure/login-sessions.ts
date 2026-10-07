// Ending a person's sessions at the login service when they sign out of Agent
// X (Shannon AUTH-VULN-01, S88): our sign-out ends only our own session, and
// the login service's own would stay signed in on a shared computer. Every
// sign-in and step-up asks Zitadel for a fresh login (`prompt=login`), so each
// leaves a session of its own there, and none is ever used again: all of the
// person's are ended, not just the one their sign-in named.
//
// Zitadel's session API (v2), asked with the reset token (idp-factors.ts): its
// Org User Manager role holds `session.read` and `session.delete` on the
// organisation's people (Zitadel v4.17.3 `cmd/defaults.yaml`).
import type { Subject } from '../domain/sign-in.ts';
import { field, ZITADEL_ID } from './zitadel-answer.ts';
import { createZitadelCall, type ZitadelCallOptions } from './zitadel-call.ts';

/** How long one call to the login service may take. */
const CALL_TIMEOUT_MS = 5_000;

/** How long one sign-out may spend ending sessions, so a slow login service can't hold the browser's answer. */
const MOST_TIME_MS = 10_000;

/** The most one answer may hold. */
const MOST_ANSWER_BYTES = 256 * 1024;

/** The most sessions read and ended at one sign-out: far more than one person makes before Zitadel's own expire. */
const MOST_SESSIONS = 100;

export class LoginSessionsUnavailable extends Error {
  override readonly name = 'LoginSessionsUnavailable';
}

export interface LoginSessions {
  /**
   * Ends every session the login service holds for `who`, newest first, and
   * says how many there were; none for a person of another issuer. Throws
   * LoginSessionsUnavailable, and then some may have been ended: past
   * MOST_SESSIONS, the oldest are left, and that throws too.
   */
  endAll(who: Subject): Promise<number>;
}

export function createLoginSessions(
  login: ZitadelCallOptions & {
    /** The time now in milliseconds; a test's moves as it says. */
    readonly now?: (() => number) | undefined;
  },
): LoginSessions {
  const { issuer, now = Date.now } = login;
  const zitadel = createZitadelCall(login, { timeoutMs: CALL_TIMEOUT_MS, mostAnswerBytes: MOST_ANSWER_BYTES });
  const call = (path: string, method: 'POST' | 'DELETE', body: unknown, step: string) =>
    zitadel({ path, method, body }, (how) => new LoginSessionsUnavailable(`${step}: ${how}`));

  /** The IDs of the person's sessions, newest first; Zitadel leaves an empty list out. */
  const sessionsOf = async (subject: string): Promise<string[]> => {
    const step = 'reading the sessions';
    const { status, answer } = await call(
      '/v2/sessions/search',
      'POST',
      {
        query: { limit: MOST_SESSIONS, asc: false },
        sortingColumn: 'SESSION_FIELD_NAME_CREATION_DATE',
        queries: [{ userIdQuery: { id: subject } }],
      },
      step,
    );
    if (status !== 200) throw new LoginSessionsUnavailable(`${step}: it answered ${String(status)}`);
    const sessions = field(answer, 'sessions') ?? [];
    if (!Array.isArray(sessions) || sessions.length > MOST_SESSIONS) {
      throw new LoginSessionsUnavailable(`${step}: the answer holds no list of at most ${String(MOST_SESSIONS)}`);
    }
    return sessions.map((session: unknown) => {
      const id = field(session, 'id');
      if (typeof id !== 'string' || !ZITADEL_ID.test(id)) {
        throw new LoginSessionsUnavailable(`${step}: an ID is not one`);
      }
      return id;
    });
  };

  return {
    async endAll({ issuer: theirs, subject }) {
      // A person of another login service has nothing here, and their ID could name someone else's.
      if (theirs !== issuer) return 0;
      if (!ZITADEL_ID.test(subject)) throw new RangeError("the subject must be the login service's user ID");
      const until = now() + MOST_TIME_MS;
      const ids = await sessionsOf(subject);
      for (const id of ids) {
        if (now() > until) throw new LoginSessionsUnavailable('ending the sessions: out of time');
        // No session token: the role's `session.delete` is what lets us end it.
        const { status } = await call(`/v2/sessions/${id}`, 'DELETE', {}, 'ending a session');
        if (status !== 200 && status !== 404) {
          throw new LoginSessionsUnavailable(`ending a session: it answered ${String(status)}`);
        }
      }
      if (ids.length === MOST_SESSIONS) {
        throw new LoginSessionsUnavailable(`reading the sessions: ${String(MOST_SESSIONS)} or more, any older left`);
      }
      return ids.length;
    },
  };
}
