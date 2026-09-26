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
import type { OutboundFetch } from '@agentx/platform/outbound';

import type { AddressBook } from '../../notifications/index.ts';
import type { Subject } from '../domain/sign-in.ts';
import { routedToIssuer } from './zitadel-route.ts';

/** How long one call to the login service may take. */
const CALL_TIMEOUT_MS = 10_000;

/** The most a user's answer may hold. */
const MOST_ANSWER_BYTES = 64 * 1024;

/** A subject as Zitadel makes them: its IDs are digits. */
const SUBJECT = /^[0-9]{1,32}$/;

/** A token: visible ASCII, bounded. */
const TOKEN = /^[!-~]{1,4096}$/;

/** An address as it can be sent to: one @, no spaces or angle brackets, bounded. */
const ADDRESS = /^[^\s@<>"]{1,64}@[^\s@<>"]{1,253}$/;

export class AddressBookUnavailable extends Error {
  override readonly name = 'AddressBookUnavailable';
  constructor(step: string) {
    super(`the login service couldn't give an address: ${step}`);
  }
}

/** The body as text, refused past MOST_ANSWER_BYTES however the answer declares its length. */
async function boundedText(response: Response): Promise<string> {
  const reader = (response.body as ReadableStream<Uint8Array> | null)?.getReader();
  if (reader === undefined) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MOST_ANSWER_BYTES) {
      await reader.cancel();
      throw new AddressBookUnavailable(`the answer was larger than ${String(MOST_ANSWER_BYTES)} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
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
  issuer,
  internalOrigin,
  token,
  fetch,
}: {
  /** The issuer and subject a user signs in as (`subjectOfUser`); undefined for no such user. */
  readonly subjectOf: (userId: string) => Promise<Subject | undefined>;
  /** The login service, exactly as its tokens name it. */
  readonly issuer: string;
  /** Where to reach it inside the platform (B2-6); undefined to call the issuer itself. */
  readonly internalOrigin: string | undefined;
  readonly token: string;
  readonly fetch: OutboundFetch;
}): AddressBook {
  if (!URL.canParse(issuer) || new URL(issuer).origin !== issuer) throw new RangeError('the issuer must be an origin');
  if (!TOKEN.test(token)) throw new RangeError('the token must be 1 to 4096 visible ASCII characters');

  return {
    async addressOf(userId) {
      const user = await subjectOf(userId);
      // Only the login service this API signs in with is asked; its subjects are its own IDs.
      if (user?.issuer !== issuer || !SUBJECT.test(user.subject)) return undefined;
      const [url, init] = routedToIssuer(issuer, internalOrigin, `${issuer}/v2/users/${user.subject}`, {
        headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
      });
      let response: Response;
      try {
        response = await fetch(url, { ...init, signal: AbortSignal.timeout(CALL_TIMEOUT_MS) });
      } catch {
        throw new AddressBookUnavailable('the call failed');
      }
      if (response.status === 404) {
        await response.body?.cancel();
        return undefined;
      }
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new AddressBookUnavailable(`it answered ${String(response.status)}`);
      }
      let answer: unknown;
      try {
        answer = JSON.parse(await boundedText(response));
      } catch (error) {
        if (error instanceof AddressBookUnavailable) throw error;
        throw new AddressBookUnavailable('the answer is not JSON');
      }
      return verifiedAddress(answer);
    },
  };
}
