// A call to the login service's own API with its service account's token (B5-3,
// B6-2b, B6-3c): the issuer and the token checked once, each call routed as
// sign-in is (`routedToIssuer`), bounded in time and in the answer's size, and
// the answer parsed only from a 200. The address book, the factor remover,
// the event feed and the sign-out's session ending share it; each throws its
// own error, naming the step, never the answer. A token refused (401, 403) is
// the one failure they share: LoginTokenRefused, which an alert counts by its
// name (partner, S88), so a token that stopped working tells someone.
import type { OutboundFetch } from '@agentx/platform/outbound';

import { boundedText } from './zitadel-answer.ts';
import { routedToIssuer } from './zitadel-route.ts';

/** The login service refused the token (401 or 403): expired, revoked, or its role taken away. */
export class LoginTokenRefused extends Error {
  override readonly name = 'LoginTokenRefused';
}

/** A token: visible ASCII, bounded. */
const TOKEN = /^[!-~]{1,4096}$/;

/** Where the login service is, and how to call it. */
export interface ZitadelCallOptions {
  /** The login service, exactly as its tokens name it. */
  readonly issuer: string;
  /** Where to reach it inside the platform (B2-6); undefined to call the issuer itself. */
  readonly internalOrigin: string | undefined;
  readonly token: string;
  readonly fetch: OutboundFetch;
}

/** One call: its path on the issuer, its method (GET unless said) and its JSON body, if any. */
export interface ZitadelRequest {
  readonly path: string;
  readonly method?: 'GET' | 'POST' | 'DELETE';
  readonly body?: unknown;
}

/** The answer's status, and for a 200 alone, its body parsed; any other's body is dropped. */
export interface ZitadelAnswer {
  readonly status: number;
  readonly answer: unknown;
}

/**
 * A caller with each call's time and answer bounded. A call that fails, or a
 * 200 whose answer is too large or isn't JSON, throws what `unavailable`
 * makes of how; a refused token throws LoginTokenRefused. A bad issuer or
 * token throws RangeError here, at once.
 */
export function createZitadelCall(
  { issuer, internalOrigin, token, fetch }: ZitadelCallOptions,
  { timeoutMs, mostAnswerBytes }: { readonly timeoutMs: number; readonly mostAnswerBytes: number },
): (request: ZitadelRequest, unavailable: (how: string) => Error) => Promise<ZitadelAnswer> {
  if (!URL.canParse(issuer) || new URL(issuer).origin !== issuer) throw new RangeError('the issuer must be an origin');
  if (!TOKEN.test(token)) throw new RangeError('the token must be 1 to 4096 visible ASCII characters');

  return async ({ path, method = 'GET', body }, unavailable) => {
    const [url, init] = routedToIssuer(issuer, internalOrigin, `${issuer}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/json',
        ...(body !== undefined && { 'content-type': 'application/json' }),
      },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    let response: Response;
    try {
      response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch {
      throw unavailable('the call failed');
    }
    if (response.status !== 200) {
      await response.body?.cancel();
      if (response.status === 401 || response.status === 403) {
        throw new LoginTokenRefused(`the login service refused the token: it answered ${String(response.status)}`);
      }
      return { status: response.status, answer: undefined };
    }
    const tooLarge = unavailable(`the answer was larger than ${String(mostAnswerBytes)} bytes`);
    try {
      return {
        status: 200,
        answer: JSON.parse(await boundedText(response, mostAnswerBytes, () => tooLarge)) as unknown,
      };
    } catch (error) {
      // A body broken off part-way reads as one that isn't JSON, as it always has.
      if (error === tooLarge) throw tooLarge;
      throw unavailable('the answer is not JSON');
    }
  };
}
