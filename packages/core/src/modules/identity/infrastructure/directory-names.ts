// People's names and verified addresses, as the login service has them now
// (decision 25): what the audit log shows beside each person's Agent X ID.
// Zitadel's user API (v2) is asked once for up to MOST_A_CALL people
// (`POST /v2/users` with their IDs), with the directory token, which views
// users and changes nothing (B5-3b), as the address book does.
//
// - Only the login service this API signs in with is asked, and only for
//   subjects in its own ID shape; anyone else is left out of the answer.
// - A person the login service no longer has is left out too: the log then
//   names them from the copy Agent X kept (user-contacts.ts).
// - Short in time, as a page waits on it: a login service that is slow, can't
//   be reached, refuses the token or answers otherwise throws
//   DirectoryUnavailable (or LoginTokenRefused), naming the step, never the
//   answer, and the log falls back to the kept copy.
import { invitationEmail } from '../domain/invitation.ts';
import { nameFromParts } from '../domain/person-name.ts';
import { field, ZITADEL_ID } from './zitadel-answer.ts';
import { createZitadelCall, type ZitadelCallOptions } from './zitadel-call.ts';

/** How long one call may take: a page of the log waits on it. */
const CALL_TIMEOUT_MS = 2500;

/** The most people one call asks about. */
export const MOST_A_CALL = 100;

/** The most an answer may hold: a hundred users with their profiles. */
const MOST_ANSWER_BYTES = 512 * 1024;

export class DirectoryUnavailable extends Error {
  override readonly name = 'DirectoryUnavailable';
  constructor(step: string) {
    super(`the login service couldn't give names: ${step}`);
  }
}

/** A person as the login service has them: either may be missing. */
export interface DirectoryEntry {
  readonly name: string | undefined;
  readonly email: string | undefined;
}

export interface DirectoryNames {
  /** The login service this API signs in with: only its subjects are asked about. */
  readonly issuer: string;
  /** Each subject the login service still has, with its name and verified address. */
  entriesOf(subjects: readonly string[]): Promise<ReadonlyMap<string, DirectoryEntry>>;
}

/** One user of the answer, by subject; undefined for anything that isn't one. */
function entryOf(user: unknown): readonly [string, DirectoryEntry] | undefined {
  const subject = field(user, 'userId');
  if (typeof subject !== 'string' || !ZITADEL_ID.test(subject)) return undefined;
  const human = field(user, 'human');
  const profile = field(human, 'profile');
  const email = field(human, 'email');
  return [
    subject,
    {
      name: nameFromParts(field(profile, 'displayName'), field(profile, 'givenName'), field(profile, 'familyName')),
      email: field(email, 'isVerified') === true ? invitationEmail(field(email, 'email')) : undefined,
    },
  ];
}

export function createDirectoryNames(login: ZitadelCallOptions): DirectoryNames {
  const call = createZitadelCall(login, { timeoutMs: CALL_TIMEOUT_MS, mostAnswerBytes: MOST_ANSWER_BYTES });
  const unavailable = (how: string) => new DirectoryUnavailable(how);

  return {
    issuer: login.issuer,
    async entriesOf(subjects) {
      const asked = [...new Set(subjects.filter((subject) => ZITADEL_ID.test(subject)))];
      const entries = new Map<string, DirectoryEntry>();
      for (let start = 0; start < asked.length; start += MOST_A_CALL) {
        const userIds = asked.slice(start, start + MOST_A_CALL);
        const { status, answer } = await call(
          {
            path: '/v2/users',
            method: 'POST',
            body: { query: { limit: userIds.length }, queries: [{ inUserIdsQuery: { userIds } }] },
          },
          unavailable,
        );
        if (status !== 200) throw unavailable(`it answered ${String(status)}`);
        const users = field(answer, 'result') ?? [];
        if (!Array.isArray(users)) throw unavailable('the answer holds no list of users');
        for (const user of users) {
          const entry = entryOf(user);
          // Only the people asked about: an answer naming anyone else adds no one.
          if (entry !== undefined && userIds.includes(entry[0])) entries.set(...entry);
        }
      }
      return entries;
    },
  };
}
