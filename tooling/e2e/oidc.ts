// A minimal OpenID Connect relying party for the login tests: the
// authorization code flow with PKCE (ADR-003 §5), a callback listener, the
// code exchange, and an ID token check against the issuer's keys. Only what
// the tests need to prove the login service's behaviour; the product's own
// client comes in Phase 1.
import { createHash, createPublicKey, type JsonWebKey, randomBytes, verify } from 'node:crypto';
import { createServer, type Server } from 'node:http';

interface Discovery {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
}

const discoveries = new Map<string, Promise<Discovery>>();

/** The issuer's published endpoints, fetched once per issuer. */
function discover(issuer: string): Promise<Discovery> {
  let pending = discoveries.get(issuer);
  if (pending === undefined) {
    pending = fetch(`${issuer}/.well-known/openid-configuration`).then(async (response) => {
      if (!response.ok) throw new Error(`discovery failed: ${String(response.status)}`);
      return (await response.json()) as Discovery;
    });
    discoveries.set(issuer, pending);
  }
  return pending;
}

const base64url = (bytes: Buffer): string => bytes.toString('base64url');

export interface AuthorizationRequest {
  readonly url: string;
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
}

export interface AuthorizationOptions {
  /** `login` forces a fresh authentication however recent the last one was. */
  readonly prompt?: 'login';
  /** The most seconds since the user authenticated that the issuer may accept; 0 forces a fresh one. */
  readonly maxAge?: number;
}

/** The URL a browser is sent to, with fresh state, nonce and PKCE verifier. */
export async function authorizationRequest(
  issuer: string,
  clientId: string,
  redirectUri: string,
  options: AuthorizationOptions = {},
): Promise<AuthorizationRequest> {
  const { authorization_endpoint } = await discover(issuer);
  const state = base64url(randomBytes(16));
  const nonce = base64url(randomBytes(16));
  const verifier = base64url(randomBytes(32));
  const url = new URL(authorization_endpoint);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', base64url(createHash('sha256').update(verifier).digest()));
  url.searchParams.set('code_challenge_method', 'S256');
  if (options.prompt !== undefined) url.searchParams.set('prompt', options.prompt);
  if (options.maxAge !== undefined) url.searchParams.set('max_age', String(options.maxAge));
  return { url: url.toString(), state, nonce, verifier };
}

export interface CallbackListener {
  readonly redirectUri: string;
  /**
   * The next callback's query (code and state, or an error), or nothing if
   * none arrives within the wait. A wait that ends leaves nothing behind, so
   * a later callback goes to a later caller.
   */
  next(timeoutMs: number): Promise<URLSearchParams | undefined>;
  close(): Promise<void>;
}

/** Listens for the issuer's redirect on the loopback address, one callback at a time. */
export function listenForCallback(port: number): Promise<CallbackListener> {
  type Waiter = (query: URLSearchParams) => void;
  const waiting: Waiter[] = [];
  const arrived: URLSearchParams[] = [];
  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', `http://127.0.0.1:${String(port)}`);
    if (url.pathname !== '/callback') {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/plain' }).end('Signed in. You can close this tab.');
    const waiter = waiting.shift();
    if (waiter === undefined) arrived.push(url.searchParams);
    else waiter(url.searchParams);
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      resolve({
        redirectUri: `http://127.0.0.1:${String(port)}/callback`,
        next: (timeoutMs) => {
          const ready = arrived.shift();
          if (ready !== undefined) return Promise.resolve(ready);
          return new Promise((done) => {
            const waiter: Waiter = (query) => {
              clearTimeout(timer);
              done(query);
            };
            const timer = setTimeout(() => {
              waiting.splice(waiting.indexOf(waiter), 1);
              done(undefined);
            }, timeoutMs);
            waiting.push(waiter);
          });
        },
        close: () =>
          new Promise((done) => {
            server.close(() => {
              done();
            });
          }),
      });
    });
  });
}

export interface Tokens {
  readonly id_token: string;
  readonly access_token: string;
}

/** Trades the code for tokens, proving the PKCE verifier. */
export async function exchangeCode(
  issuer: string,
  clientId: string,
  redirectUri: string,
  code: string,
  verifier: string,
): Promise<Tokens> {
  const { token_endpoint } = await discover(issuer);
  const response = await fetch(token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      redirect_uri: redirectUri,
      code,
      code_verifier: verifier,
    }),
  });
  if (!response.ok) throw new Error(`token exchange failed: ${String(response.status)} ${await response.text()}`);
  return (await response.json()) as Tokens;
}

export interface IdTokenClaims {
  readonly iss: string;
  readonly aud: string | readonly string[];
  readonly sub: string;
  readonly exp: number;
  readonly iat: number;
  readonly nonce?: string;
  /** When the user authenticated, in seconds since 1970 (ADR-003 §9 relies on it). */
  readonly auth_time?: number;
  /** How the user authenticated: `pwd`, `mfa`, `otp`, `user` and so on (ADR-003 §9 relies on it). */
  readonly amr?: readonly string[];
  /** The issuer's session, which a forced re-login may or may not keep. */
  readonly sid?: string;
  readonly preferred_username?: string;
}

/** A published key: Node's JWK shape, which names the key (`kid`) and its type (`kty`). */
type Jwk = JsonWebKey & { readonly kid?: string };

const decodeSegment = (segment: string): unknown => JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));

/**
 * Checks the ID token as the product will (ADR-003 §5): an RS256 signature
 * from the issuer's published keys, then issuer, audience, expiry and nonce.
 */
export async function verifyIdToken(
  issuer: string,
  clientId: string,
  idToken: string,
  expectedNonce: string,
  nowMs = Date.now(),
): Promise<IdTokenClaims> {
  const [headerSegment, payloadSegment, signatureSegment, ...rest] = idToken.split('.');
  if (
    headerSegment === undefined ||
    payloadSegment === undefined ||
    signatureSegment === undefined ||
    rest.length > 0
  ) {
    throw new Error('the ID token is not a compact JWS');
  }
  const header = decodeSegment(headerSegment) as { alg?: string; kid?: string };
  if (header.alg !== 'RS256') throw new Error(`unexpected ID token algorithm: ${String(header.alg)}`);
  if (typeof header.kid !== 'string' || header.kid === '') throw new Error('the ID token names no key');

  const { jwks_uri } = await discover(issuer);
  const { keys } = (await (await fetch(jwks_uri)).json()) as { keys: Jwk[] };
  const jwk = keys.find((candidate) => candidate.kid === header.kid && candidate.kty === 'RSA');
  if (jwk === undefined) throw new Error('the ID token names a key the issuer does not publish');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const signed = Buffer.from(`${headerSegment}.${payloadSegment}`, 'ascii');
  if (!verify('RSA-SHA256', signed, key, Buffer.from(signatureSegment, 'base64url'))) {
    throw new Error('the ID token signature does not verify');
  }

  const claims = decodeSegment(payloadSegment) as IdTokenClaims & { azp?: string };
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  if (claims.iss !== issuer) throw new Error(`unexpected issuer: ${claims.iss}`);
  if (!audiences.includes(clientId)) throw new Error('the ID token is not for this client');
  // With several audiences, OpenID Connect Core §3.1.3.7 wants the authorized party named, and it must be us.
  if (audiences.length > 1 && claims.azp !== clientId) throw new Error('the ID token was authorized for another party');
  if (claims.exp * 1000 <= nowMs) throw new Error('the ID token has expired');
  // A minute of clock skew, as the product will allow.
  if (claims.iat * 1000 > nowMs + 60_000) throw new Error('the ID token was issued in the future');
  if (claims.nonce !== expectedNonce) throw new Error('the ID token nonce does not match');
  return claims;
}
