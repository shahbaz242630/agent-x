// The address book (B5-3): a person's email address at send time, from the
// login service, since Agent X keeps none (B5-1b). A notice's recipient is an
// Agent X user; their row gives the issuer and subject they sign in as, and
// the login service (Zitadel's user API, `GET /v2/users/<subject>`) gives the
// address, which is taken only when it says it is verified.
//
// - Read with the login service's token for this alone: a service user of its
//   own, able to view users and nothing else (set up by a person in Zitadel,
//   B5-3b). The token goes only to the issuer's origin, through the same route
//   as sign-in (`routedToIssuer`), and the outbound fetch's allowlist.
// - No address (a user from another issuer, one the login service no longer
//   has, a machine user, or an address not verified) is `undefined`, and the
//   notice to them is given up. A login service that can't be reached, or
//   refuses the token, throws: the notice waits to be tried again.
// - The address is never logged; a failure names the step, never the answer.
import type { AddressBook } from '../../notifications/index.ts';
import type { Subject } from '../domain/sign-in.ts';
import { createZitadelCall, type ZitadelCallOptions } from './zitadel-call.ts';

/** How long one call to the login service may take. */
const CALL_TIMEOUT_MS = 10_000;

/** The most a user's answer may hold. */
const MOST_ANSWER_BYTES = 64 * 1024;

/** A subject as Zitadel makes them: its IDs are digits. */
const SUBJECT = /^[0-9]{1,32}$/;

/** An address as it can be sent to: one @, no spaces or angle brackets, bounded. */
const ADDRESS = /^[^\s@<>"]{1,64}@[^\s@<>"]{1,253}$/;

export class AddressBookUnavailable extends Error {
  override readonly name = 'AddressBookUnavailable';
  constructor(step: string) {
    super(`the login service couldn't give an address: ${step}`);
  }
}

/** The verified address in a Zitadel user answer, in lower case; undefined for none. */
function verifiedAddress(answer: unknown): string | undefined {
  const email = (answer as { user?: { human?: { email?: { email?: unknown; isVerified?: unknown } } } } | null)?.user
    ?.human?.email;
  if (email?.isVerified !== true || typeof email.email !== 'string' || !ADDRESS.test(email.email)) return undefined;
  return email.email.toLowerCase();
}

export function createAddressBook({
  subjectOf,
  ...login
}: ZitadelCallOptions & {
  /** The issuer and subject a user signs in as (`subjectOfUser`); undefined for no such user. */
  readonly subjectOf: (userId: string) => Promise<Subject | undefined>;
}): AddressBook {
  const call = createZitadelCall(login, { timeoutMs: CALL_TIMEOUT_MS, mostAnswerBytes: MOST_ANSWER_BYTES });
  const unavailable = (how: string) => new AddressBookUnavailable(how);

  return {
    async addressOf(userId) {
      const user = await subjectOf(userId);
      // Only the login service this API signs in with is asked; its subjects are its own IDs.
      if (user?.issuer !== login.issuer || !SUBJECT.test(user.subject)) return undefined;
      const { status, answer } = await call({ path: `/v2/users/${user.subject}` }, unavailable);
      if (status === 404) return undefined;
      if (status !== 200) throw unavailable(`it answered ${String(status)}`);
      return verifiedAddress(answer);
    },
  };
}
