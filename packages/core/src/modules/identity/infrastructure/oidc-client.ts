// The API as the login service's OpenID Connect client (ADR-003 §5): the
// authorization code flow with PKCE, as a confidential client.
//
// - `start` makes the address a browser is sent to, with a fresh state, nonce
//   and PKCE verifier (S256): the flow, which the caller keeps until the
//   browser comes back (B2-3: a short-lived cookie) and never shows anyone.
// - `finish` takes the browser's code back: the state must match the flow's,
//   the code is traded for tokens with the client's secret and the verifier,
//   and the ID token is checked here, against the issuer's published keys
//   (RS256 only), for its issuer, audience, authorized party, expiry, age,
//   nonce and authentication time. Only who the person is and what the login
//   proved come out.
// - B4-4a: the flow asks for the `email` scope too, and the access token is
//   used once, straight after, at the userinfo endpoint (Zitadel keeps the
//   address out of the ID token unless the app is set to, which staging's
//   isn't). The answer must name the ID token's person; its address comes out
//   only when the login service says it is verified, in lower case, for an
//   invitation to be matched against (B4-4c). An endpoint that fails gives no
//   address and fails nothing. The access and refresh tokens are then
//   dropped.
//
// Every call to the login service goes through the outbound fetch, so only
// the allowlist's origins are reached and no redirect is followed
// (SEC-WEB-05). The discovery document must name the configured issuer
// exactly, and every endpoint it names must be on the issuer's own origin:
// a document that points elsewhere is refused. It is fetched once; the keys
// are fetched again when a token names one not held, at most once a minute
// after a fetch that worked and once in five seconds after one that failed,
// so a flood of forged tokens can't make the API hammer the login service,
// and a failure while it rotates its keys holds sign-ins up only briefly.
//
// Where the issuer's public address can't be reached from inside the
// platform (Azure's apps can't call their own public door, B2-6), every call
// to the issuer's origin goes to an internal origin instead, carrying the
// issuer's host in Zitadel's `x-zitadel-instance-host` and
// `x-zitadel-public-host` headers, as the login pages do: Zitadel then
// answers as the issuer, so the document, the endpoints and the tokens name
// the public address all the same, and are checked against it.
//
// A failure says which step failed, never a token, code or claim's value.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import type { OutboundFetch } from '@agentx/platform/outbound';
import { createLocalJWKSet, errors as joseErrors, type JSONWebKeySet, jwtVerify } from 'jose';

import type { Clock } from '../../../shared-kernel/index.ts';
import { invitationEmail } from '../domain/invitation.ts';
import { checkEvidence, checkSubject, type SignInEvidence, type Subject } from '../domain/sign-in.ts';

export interface OidcClientSettings {
  /** The issuer, exactly as its tokens name it. */
  readonly issuer: string;
  readonly clientId: string;
  /** Sent only to the token endpoint, in the Authorization header (client_secret_basic). */
  readonly clientSecret: string;
  /** Where the login service sends the browser back: registered with it exactly. */
  readonly redirectUri: string;
  /** Where to reach the issuer inside the platform (B2-6); undefined to call the issuer itself. */
  readonly internalOrigin?: string | undefined;
}

/** What `start` hands back to be kept until the browser returns, and never shown. */
export interface LoginFlow {
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
}

export interface SignInStart {
  /** The login service's address, with the flow's state, nonce and PKCE challenge. */
  readonly url: string;
  readonly flow: LoginFlow;
}

export interface VerifiedSignIn {
  readonly subject: Subject;
  readonly evidence: SignInEvidence;
  /** SHA-256 of the ID token, kept as a step-up's evidence (ADR-003 §9); the token itself never is. */
  readonly idTokenHash: Buffer;
  /** The person's email address, in lower case, only when the login service says it is verified. */
  readonly verifiedEmail: string | undefined;
}

/** Why a sign-in failed, for its answer and its security event (B2-5). */
export type SignInFailure =
  /** The browser came back with no flow of ours in time: none started, one used already, or past its ten minutes. */
  | 'flow_missing'
  /** The browser came back with a state that isn't the flow's: another flow's, or a forged one. */
  | 'state_mismatch'
  /** The login service couldn't be reached, or answered in a way that isn't OIDC. */
  | 'provider_unavailable'
  /** The login service refused the code: used already, expired, or not ours. */
  | 'code_rejected'
  /** The ID token failed a check. */
  | 'token_invalid';

export class SignInFailed extends Error {
  override readonly name = 'SignInFailed';
  readonly failure: SignInFailure;
  constructor(failure: SignInFailure, detail: string) {
    super(`sign-in failed (${failure}): ${detail}`);
    this.failure = failure;
  }
}

export interface OidcClient {
  /**
   * A new flow, and the address to send the browser to. `login` makes the
   * person authenticate again, and `nonce` is a step-up challenge's own, which
   * the ID token must then carry (B3). Throws RangeError for a nonce that
   * isn't 32 random bytes in base64url.
   */
  start(options?: { readonly prompt?: 'login'; readonly nonce?: string }): Promise<SignInStart>;
  /** Trades the returned code for a checked ID token. Throws SignInFailed. */
  finish(flow: LoginFlow, returned: { readonly code: string; readonly state: string }): Promise<VerifiedSignIn>;
}

/** The only signature algorithm taken: Zitadel's, and never `none` or a MAC with a public key. */
const ALGORITHMS = ['RS256'];
/** How far the login service's clock may be from ours. */
const CLOCK_TOLERANCE_SECONDS = 60;
/** The oldest an ID token may be when it's checked: it was issued moments before, for this code. */
const MOST_TOKEN_AGE_SECONDS = 300;
/** How long one call to the login service may take. */
const CALL_TIMEOUT_MS = 10_000;
/** The most a login service answer may hold: a discovery document, a key set, a token response. */
const MOST_ANSWER_BYTES = 64 * 1024;
/** How soon after fetching the keys they may be fetched again, for a token naming one not held. */
const KEYS_REFETCH_MS = 60_000;
/** How soon after a failed fetch of the keys it may be tried again: an outage mustn't block sign-ins for a minute. */
const KEYS_RETRY_MS = 5_000;
/** Each random value: 256 bits. */
const RANDOM_BYTES = 32;
/** A nonce as this client makes them, and as a step-up challenge does: 32 random bytes in base64url. */
const NONCE = /^[A-Za-z0-9_-]{43}$/;
/** An access token: visible ASCII, bounded (Zitadel's opaque tokens are about 100 characters, its JWTs about 1,000). */
const ACCESS_TOKEN = /^[!-~]{1,4096}$/;
/** A value the login service hands back through the browser: visible ASCII, bounded. */
const RETURNED = /^[!-~]{1,2048}$/;

interface Discovery {
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly userinfoEndpoint: string;
}

const random = (): string => randomBytes(RANDOM_BYTES).toString('base64url');

/** Equal text, compared in constant time. */
function sameText(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
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
      throw new SignInFailed('provider_unavailable', `an answer was larger than ${MOST_ANSWER_BYTES} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** A JSON object from the answer, or SignInFailed naming what was being read. */
async function jsonObject(response: Response, what: string): Promise<Record<string, unknown>> {
  const text = await boundedText(response);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new SignInFailed('provider_unavailable', `the ${what} is not JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new SignInFailed('provider_unavailable', `the ${what} is not a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

/** Throws unless the settings can make a client at all; the config checks them in full (B2-3). */
function checkSettings({ issuer, clientId, clientSecret, redirectUri, internalOrigin }: OidcClientSettings): void {
  if (!URL.canParse(issuer) || !URL.canParse(redirectUri)) {
    throw new RangeError('the issuer and the redirect address must be absolute URLs');
  }
  if (
    internalOrigin !== undefined &&
    (!URL.canParse(internalOrigin) || new URL(internalOrigin).origin !== internalOrigin)
  ) {
    throw new RangeError('the internal origin must be an origin alone');
  }
  if (!RETURNED.test(clientId) || !RETURNED.test(clientSecret)) {
    throw new RangeError('the client ID and secret must be 1 to 2048 visible ASCII characters');
  }
}

export function createOidcClient({
  settings,
  fetch,
  clock,
}: {
  readonly settings: OidcClientSettings;
  readonly fetch: OutboundFetch;
  readonly clock: Clock;
}): OidcClient {
  checkSettings(settings);
  const { issuer, clientId, clientSecret, redirectUri, internalOrigin } = settings;
  const issuerOrigin = new URL(issuer).origin;

  /**
   * Where a call to the login service goes: the URL itself, or, with an
   * internal origin, the same path and query there, naming the issuer's host
   * to Zitadel. Every call is on the issuer's own origin: the discovery
   * document's, and the endpoints `endpoint` has held to it.
   */
  function routed(url: string, init: RequestInit): [string, RequestInit] {
    if (internalOrigin === undefined) return [url, init];
    const target = new URL(url);
    const headers = new Headers(init.headers);
    const { host } = new URL(issuer);
    headers.set('x-zitadel-instance-host', host);
    headers.set('x-zitadel-public-host', host);
    return [`${internalOrigin}${target.pathname}${target.search}`, { ...init, headers }];
  }

  /** A call to the login service, bounded in time; a network failure is the provider's. */
  async function call(url: string, init: RequestInit = {}): Promise<Response> {
    const [to, sent] = routed(url, init);
    try {
      return await fetch(to, { ...sent, signal: AbortSignal.timeout(CALL_TIMEOUT_MS) });
    } catch (error) {
      if (error instanceof SignInFailed) throw error;
      throw new SignInFailed('provider_unavailable', `a call to ${new URL(to).origin} failed`);
    }
  }

  /** An endpoint the discovery document names: text, an absolute URL, on the issuer's own origin. */
  function endpoint(document: Record<string, unknown>, name: string): string {
    const value = document[name];
    if (typeof value !== 'string' || !URL.canParse(value) || new URL(value).origin !== issuerOrigin) {
      throw new SignInFailed('provider_unavailable', `the discovery document's ${name} is not on the issuer's origin`);
    }
    return value;
  }

  let discovery: Promise<Discovery> | undefined;
  function discover(): Promise<Discovery> {
    discovery ??= (async () => {
      const response = await call(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`, {
        headers: { accept: 'application/json' },
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new SignInFailed('provider_unavailable', `discovery answered ${String(response.status)}`);
      }
      const document = await jsonObject(response, 'discovery document');
      if (document.issuer !== issuer) {
        throw new SignInFailed('provider_unavailable', 'the discovery document names another issuer');
      }
      return {
        authorizationEndpoint: endpoint(document, 'authorization_endpoint'),
        tokenEndpoint: endpoint(document, 'token_endpoint'),
        jwksUri: endpoint(document, 'jwks_uri'),
        userinfoEndpoint: endpoint(document, 'userinfo_endpoint'),
      };
    })();
    // A failed discovery is tried again next time, not held for the life of the process.
    discovery.catch(() => {
      discovery = undefined;
    });
    return discovery;
  }

  let keys: ReturnType<typeof createLocalJWKSet> | undefined;
  /** When the keys may next be fetched, in ms since 1970. */
  let keysFetchableAt = 0;
  /** The fetch of the keys under way, which every sign-in needing them waits on rather than starting its own. */
  let keysFetch: Promise<ReturnType<typeof createLocalJWKSet>> | undefined;
  const mayFetchKeys = (): boolean => clock.now().getTime() >= keysFetchableAt;
  /** The fetch under way, or a new one: never two at once. */
  function fetchKeys(): Promise<ReturnType<typeof createLocalJWKSet>> {
    keysFetch ??= fetchKeysNow().finally(() => {
      keysFetch = undefined;
    });
    return keysFetch;
  }
  async function fetchKeysNow(): Promise<ReturnType<typeof createLocalJWKSet>> {
    const began = clock.now().getTime();
    keysFetchableAt = began + KEYS_RETRY_MS;
    const { jwksUri } = await discover();
    const response = await call(jwksUri, { headers: { accept: 'application/json' } });
    if (!response.ok) {
      await response.body?.cancel();
      throw new SignInFailed('provider_unavailable', `the key set answered ${String(response.status)}`);
    }
    const document = await jsonObject(response, 'key set');
    if (!Array.isArray(document.keys)) throw new SignInFailed('provider_unavailable', 'the key set holds no keys');
    keys = createLocalJWKSet(document as unknown as JSONWebKeySet);
    keysFetchableAt = began + KEYS_REFETCH_MS;
    return keys;
  }

  /** The keys held; or the fetch under way; or a new fetch, if none failed moments ago. */
  function heldKeys(): Promise<ReturnType<typeof createLocalJWKSet>> {
    if (keys !== undefined) return Promise.resolve(keys);
    if (keysFetch === undefined && !mayFetchKeys()) {
      return Promise.reject(
        new SignInFailed('provider_unavailable', 'the key set failed moments ago; not tried again yet'),
      );
    }
    return fetchKeys();
  }

  /** The ID token's claims, checked; a key not held sends for the keys again, at most once a minute. */
  async function verified(idToken: string, nonce: string): Promise<Omit<VerifiedSignIn, 'verifiedEmail'>> {
    const now = clock.now();
    const verify = (set: ReturnType<typeof createLocalJWKSet>) =>
      jwtVerify(idToken, set, {
        issuer,
        audience: clientId,
        algorithms: ALGORITHMS,
        currentDate: now,
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        maxTokenAge: MOST_TOKEN_AGE_SECONDS,
        requiredClaims: ['sub', 'iat', 'exp', 'nonce', 'auth_time', 'amr'],
      });
    let result: Awaited<ReturnType<typeof verify>>;
    try {
      try {
        result = await verify(await heldKeys());
      } catch (error) {
        if (!(error instanceof joseErrors.JWKSNoMatchingKey)) throw error;
        // A key not held: wait on a fetch under way, or start one if the last was long enough ago.
        const fresh = keysFetch !== undefined || mayFetchKeys() ? fetchKeys() : undefined;
        if (fresh === undefined) throw error;
        result = await verify(await fresh);
      }
    } catch (error) {
      if (error instanceof SignInFailed) throw error;
      // jose's own code names the check that failed (ERR_JWT_EXPIRED, ERR_JWS_SIGNATURE_VERIFICATION_FAILED...), never a value.
      const code = error instanceof joseErrors.JOSEError ? error.code : 'unreadable';
      throw new SignInFailed('token_invalid', `the ID token failed its check: ${code}`);
    }

    const { payload } = result;
    const invalid = (why: string): never => {
      throw new SignInFailed('token_invalid', why);
    };
    if (typeof payload.nonce !== 'string' || !sameText(payload.nonce, nonce)) invalid('the nonce is not the flow’s');
    // OIDC Core §3.1.3.7: with more than one audience the authorized party must be named, and it must be us.
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (audiences.length > 1 && payload.azp === undefined)
      invalid('the token has several audiences and no authorized party');
    if (payload.azp !== undefined && payload.azp !== clientId) invalid('the authorized party is another client');
    const authTime = payload.auth_time;
    if (typeof authTime !== 'number' || !Number.isFinite(authTime)) invalid('the authentication time is not a number');
    if ((authTime as number) * 1000 > now.getTime() + CLOCK_TOLERANCE_SECONDS * 1000) {
      invalid('the authentication time is in the future');
    }
    // jose checks only that `sub` is there, not that it is text.
    const { sub } = payload;
    if (typeof sub !== 'string') throw new SignInFailed('token_invalid', 'the subject is not text');
    const { amr, sid } = payload;
    if (sid !== undefined && typeof sid !== 'string') invalid('the login service session is not text');

    const subject: Subject = { issuer, subject: sub };
    const evidence: SignInEvidence = {
      idpSessionId: sid as string | undefined,
      authTime: new Date((authTime as number) * 1000),
      amr: amr as readonly string[],
    };
    try {
      checkSubject(subject);
      checkEvidence(evidence);
    } catch (error) {
      invalid(error instanceof Error ? error.message : 'its claims could not be stored');
    }
    return { subject, evidence, idTokenHash: createHash('sha256').update(idToken, 'ascii').digest() };
  }

  /**
   * The person's verified address, from the userinfo endpoint with the
   * access token: the answer must name the same person; an address comes out
   * only with `email_verified` true, and only as one address (the invitation's
   * own rule), in lower case. An endpoint that can't be reached, or answers
   * with anything but a JSON object, gives no address and fails nothing: a
   * sign-in stands on its ID token, and only accepting an invitation needs an
   * address (B4-4b review). An answer about another person fails the sign-in.
   */
  async function verifiedEmailOf(accessToken: string, subject: string): Promise<string | undefined> {
    let info: Record<string, unknown>;
    try {
      const { userinfoEndpoint } = await discover();
      const response = await call(userinfoEndpoint, {
        headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) {
        await response.body?.cancel();
        return undefined;
      }
      info = await jsonObject(response, 'userinfo answer');
    } catch (error) {
      if (error instanceof SignInFailed && error.failure === 'provider_unavailable') return undefined;
      throw error;
    }
    if (info.sub !== subject) throw new SignInFailed('token_invalid', 'the userinfo answer names another person');
    if (info.email_verified !== true) return undefined;
    return invitationEmail(info.email);
  }

  return {
    async start(options = {}) {
      if (options.nonce !== undefined && (typeof options.nonce !== 'string' || !NONCE.test(options.nonce))) {
        throw new RangeError('a nonce is 32 random bytes in base64url');
      }
      const { authorizationEndpoint } = await discover();
      const flow: LoginFlow = { state: random(), nonce: options.nonce ?? random(), verifier: random() };
      const url = new URL(authorizationEndpoint);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('scope', 'openid email');
      url.searchParams.set('state', flow.state);
      url.searchParams.set('nonce', flow.nonce);
      url.searchParams.set('code_challenge', createHash('sha256').update(flow.verifier).digest('base64url'));
      url.searchParams.set('code_challenge_method', 'S256');
      if (options.prompt !== undefined) url.searchParams.set('prompt', options.prompt);
      return { url: url.toString(), flow };
    },

    async finish(flow, { code, state }) {
      if (typeof state !== 'string' || !RETURNED.test(state) || !sameText(state, flow.state)) {
        throw new SignInFailed('state_mismatch', 'the state returned is not the flow’s');
      }
      if (typeof code !== 'string' || !RETURNED.test(code)) {
        throw new SignInFailed('code_rejected', 'the code returned is not 1 to 2048 visible ASCII characters');
      }
      const { tokenEndpoint } = await discover();
      // RFC 6749 §2.3.1: each part form-encoded before the pair is base64'd.
      const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString(
        'base64',
      );
      const response = await call(tokenEndpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          authorization: `Basic ${basic}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          code_verifier: flow.verifier,
        }).toString(),
      });
      if (response.status >= 400 && response.status < 500) {
        await response.body?.cancel();
        throw new SignInFailed('code_rejected', `the token endpoint answered ${String(response.status)}`);
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new SignInFailed('provider_unavailable', `the token endpoint answered ${String(response.status)}`);
      }
      const tokens = await jsonObject(response, 'token response');
      if (typeof tokens.id_token !== 'string') {
        throw new SignInFailed('provider_unavailable', 'the token response holds no ID token');
      }
      if (typeof tokens.access_token !== 'string' || !ACCESS_TOKEN.test(tokens.access_token)) {
        throw new SignInFailed('provider_unavailable', 'the token response holds no access token');
      }
      // The ID token first: nothing is asked of the userinfo endpoint for a sign-in that doesn't stand.
      const signedIn = await verified(tokens.id_token, flow.nonce);
      const verifiedEmail = await verifiedEmailOf(tokens.access_token, signedIn.subject.subject);
      return { ...signedIn, verifiedEmail };
    },
  };
}
