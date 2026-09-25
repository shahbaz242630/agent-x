// B2-2: the OIDC client against a stand-in login service: its own RSA keys, a
// discovery document, a key set and a token endpoint, all behind a fetch that
// records every call.
import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto';

import { FixedClock } from '@agentx/testing';
import { exportJWK, type JWTPayload, SignJWT } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';

import { createOidcClient, type LoginFlow, type OidcClient, SignInFailed, type SignInFailure } from './oidc-client.ts';

const ISSUER = 'https://auth.example.test';
const CLIENT = '338719472394810051@agentx';
const PASS = 'stand-in-client-pass';
const REDIRECT = 'https://app.example.test/v1/auth/callback';
const NOW = new Date('2026-09-24T09:00:00Z');
const NOW_S = NOW.getTime() / 1000;
const CODE = 'a-code-from-the-login-service';
const ACCESS = 'an-access-token-from-the-login-service';
const SUBJECT = '338719472394810051';

interface Signer {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}
const signer = (kid: string): Signer => ({ kid, ...generateKeyPairSync('rsa', { modulusLength: 2048 }) });
const FIRST = signer('key-1');
const SECOND = signer('key-2');

interface Call {
  readonly url: string;
  readonly init: RequestInit;
}

/** The stand-in login service. Each field can be changed by a test before it signs in. */
class LoginService {
  calls: Call[] = [];
  published: Signer[] = [FIRST];
  discovery: Record<string, unknown> = {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/v2/authorize`,
    token_endpoint: `${ISSUER}/oauth/v2/token`,
    jwks_uri: `${ISSUER}/oauth/v2/keys`,
    userinfo_endpoint: `${ISSUER}/oidc/v1/userinfo`,
  };
  /** What the userinfo endpoint answers, for the access token only. */
  userinfo: Record<string, unknown> = { sub: SUBJECT, email: 'Sara.Khan@Example.test', email_verified: true };
  userinfoStatus = 200;
  discoveryStatus = 200;
  tokenStatus = 200;
  tokenBody: (nonce: string) => Promise<string> = async (nonce) =>
    JSON.stringify({ access_token: ACCESS, token_type: 'Bearer', id_token: await this.idToken({ nonce }) });
  failNetwork = false;
  keysStatus = 200;
  /** When set, the key set answers only once it settles: sign-ins can be made to meet at the fetch. */
  keysGate: Promise<void> | undefined;
  /** When set, the key set's answer in place of the published keys. */
  keysDocument: unknown;

  /** A signed ID token: the usual claims, changed by `claims`, from `key` with `alg`. */
  async idToken(
    claims: JWTPayload,
    { key = FIRST, alg = 'RS256', drop = [] }: { key?: Signer; alg?: string; drop?: string[] } = {},
  ): Promise<string> {
    const full: JWTPayload = {
      iss: ISSUER,
      aud: CLIENT,
      sub: '338719472394810051',
      iat: NOW_S - 5,
      exp: NOW_S + 3600,
      auth_time: NOW_S - 20,
      amr: ['pwd', 'otp', 'mfa'],
      sid: 'V1_338719472394810051',
      ...claims,
    };
    const payload: JWTPayload = Object.fromEntries(Object.entries(full).filter(([name]) => !drop.includes(name)));
    return new SignJWT(payload).setProtectedHeader({ alg, kid: key.kid }).sign(key.privateKey);
  }

  readonly fetch = async (url: string | URL, init: RequestInit = {}): Promise<Response> => {
    const target = String(url);
    this.calls.push({ url: target, init });
    if (this.failNetwork) throw new TypeError('fetch failed');
    if (target === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json(this.discovery, { status: this.discoveryStatus });
    }
    if (target === `${ISSUER}/oauth/v2/keys`) {
      if (this.keysGate !== undefined) await this.keysGate;
      if (this.keysStatus !== 200) return new Response('unavailable', { status: this.keysStatus });
      if (this.keysDocument !== undefined) return Response.json(this.keysDocument);
      const keys = await Promise.all(
        this.published.map(async ({ kid, publicKey }) => ({
          ...(await exportJWK(publicKey)),
          kid,
          alg: 'RS256',
          use: 'sig',
        })),
      );
      return Response.json({ keys });
    }
    if (target === `${ISSUER}/oauth/v2/token`) {
      const verifier = new URLSearchParams(init.body as string).get('code_verifier') ?? '';
      return new Response(await this.tokenBody(this.flows.get(verifier) ?? ''), {
        status: this.tokenStatus,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (target === `${ISSUER}/oidc/v1/userinfo`) {
      if (new Headers(init.headers).get('authorization') !== `Bearer ${ACCESS}`) {
        return new Response('unauthorized', { status: 401 });
      }
      if (this.userinfoStatus !== 200) return new Response('unavailable', { status: this.userinfoStatus });
      return Response.json(this.userinfo);
    }
    return new Response('not found', { status: 404 });
  };

  /** Each flow's nonce by its PKCE verifier, so each token carries its own flow's nonce, as the real service's would. */
  readonly flows = new Map<string, string>();

  /** A flow the service will answer for, as if `start` had sent the browser to it. */
  expect(flow: LoginFlow): void {
    this.flows.set(flow.verifier, flow.nonce);
  }

  callsTo(path: string): Call[] {
    return this.calls.filter((call) => call.url === `${ISSUER}${path}`);
  }
}

let service: LoginService;
let clock: FixedClock;
let client: OidcClient;

beforeEach(() => {
  service = new LoginService();
  clock = new FixedClock(NOW);
  client = createOidcClient({
    settings: { issuer: ISSUER, clientId: CLIENT, clientSecret: PASS, redirectUri: REDIRECT },
    fetch: service.fetch,
    clock,
  });
});

/** Starts a flow and finishes it with the service's current behaviour. */
async function signIn(returned: Partial<{ code: string; state: string }> = {}, flowChange: Partial<LoginFlow> = {}) {
  const { flow } = await client.start();
  service.expect(flow);
  return client.finish({ ...flow, ...flowChange }, { code: CODE, state: flow.state, ...returned });
}

/** Expects the sign-in to fail with this failure, its message naming no code or token. */
async function expectFailure(attempt: Promise<unknown>, failure: SignInFailure, message?: RegExp): Promise<void> {
  const error: unknown = await attempt.then(
    () => undefined,
    (thrown: unknown) => thrown,
  );
  expect(error).toBeInstanceOf(SignInFailed);
  expect((error as SignInFailed).failure).toBe(failure);
  if (message !== undefined) expect((error as SignInFailed).message).toMatch(message);
  expect((error as SignInFailed).message).not.toContain(CODE);
  expect((error as SignInFailed).message).not.toContain('eyJ');
}

describe('starting a sign-in', () => {
  it('sends the browser to the authorization endpoint with a PKCE challenge, state and nonce', async () => {
    const { url, flow } = await client.start();
    const sent = new URL(url);

    expect(`${sent.origin}${sent.pathname}`).toBe(`${ISSUER}/oauth/v2/authorize`);
    expect(Object.fromEntries(sent.searchParams)).toEqual({
      response_type: 'code',
      client_id: CLIENT,
      redirect_uri: REDIRECT,
      scope: 'openid email profile',
      state: flow.state,
      nonce: flow.nonce,
      code_challenge: createHash('sha256').update(flow.verifier).digest('base64url'),
      code_challenge_method: 'S256',
    });
    for (const value of [flow.state, flow.nonce, flow.verifier]) expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url).not.toContain(flow.verifier);
  });

  it('makes a fresh flow every time, and asks for a fresh login when told to', async () => {
    const first = await client.start();
    const second = await client.start({ prompt: 'login' });

    for (const part of ['state', 'nonce', 'verifier'] as const) expect(second.flow[part]).not.toBe(first.flow[part]);
    expect(new URL(first.url).searchParams.has('prompt')).toBe(false);
    expect(new URL(second.url).searchParams.get('prompt')).toBe('login');
  });

  it("B3 carries a step-up challenge's own nonce, which the ID token must then hold", async () => {
    const nonce = 'c'.repeat(43);
    const { url, flow } = await client.start({ prompt: 'login', nonce });

    expect(flow.nonce).toBe(nonce);
    expect(new URL(url).searchParams.get('nonce')).toBe(nonce);
    service.expect(flow);
    await expect(client.finish(flow, { code: CODE, state: flow.state })).resolves.toBeDefined();
  });

  it.each(['', 'short', 'c'.repeat(44), `${'c'.repeat(42)}=`, `${'c'.repeat(42)}+`])(
    'refuses a nonce that is not 32 random bytes in base64url: %j',
    async (nonce) => {
      await expect(client.start({ nonce })).rejects.toThrow(RangeError);
      expect(service.calls).toEqual([]);
    },
  );

  it('reads the discovery document once', async () => {
    await client.start();
    await client.start();

    expect(service.callsTo('/.well-known/openid-configuration')).toHaveLength(1);
  });

  it.each([
    ['names another issuer', { issuer: 'https://other.example.test' }, /another issuer/],
    ['names the issuer with a trailing slash', { issuer: `${ISSUER}/` }, /another issuer/],
    ['puts the token endpoint elsewhere', { token_endpoint: 'https://evil.example.test/token' }, /token_endpoint/],
    ['puts the keys on plain http', { jwks_uri: 'http://auth.example.test/oauth/v2/keys' }, /jwks_uri/],
    ['leaves out the authorization endpoint', { authorization_endpoint: undefined }, /authorization_endpoint/],
    ['names an endpoint that is not a URL', { authorization_endpoint: 'authorize' }, /authorization_endpoint/],
  ])('refuses a discovery document that %s', async (_, change, message) => {
    service.discovery = { ...service.discovery, ...change };

    await expectFailure(client.start(), 'provider_unavailable', message);
  });

  it('tries discovery again after it failed, rather than holding the failure', async () => {
    service.discoveryStatus = 503;
    await expectFailure(client.start(), 'provider_unavailable', /discovery answered 503/);

    service.discoveryStatus = 200;
    await expect(client.start()).resolves.toBeDefined();
    expect(service.callsTo('/.well-known/openid-configuration')).toHaveLength(2);
  });

  it('calls only through the fetch it was given, each call bounded in time', async () => {
    await signIn();

    expect(service.calls.map((call) => new URL(call.url).origin)).toEqual([ISSUER, ISSUER, ISSUER, ISSUER]);
    for (const call of service.calls) expect(call.init.signal).toBeInstanceOf(AbortSignal);
  });
});

describe('finishing a sign-in', () => {
  it('trades the code with the client’s secret and verifier, and gives who signed in and what they proved', async () => {
    const { flow } = await client.start();
    service.expect(flow);

    const signedIn = await client.finish(flow, { code: CODE, state: flow.state });

    expect(signedIn).toEqual({
      subject: { issuer: ISSUER, subject: '338719472394810051' },
      evidence: {
        idpSessionId: 'V1_338719472394810051',
        authTime: new Date((NOW_S - 20) * 1000),
        amr: ['pwd', 'otp', 'mfa'],
      },
      idTokenHash: expect.any(Buffer) as Buffer,
      verifiedEmail: 'sara.khan@example.test',
    });
    const [exchange] = service.callsTo('/oauth/v2/token');
    const headers = new Headers(exchange?.init.headers);
    expect(exchange?.init.method).toBe('POST');
    expect(headers.get('authorization')).toBe(
      `Basic ${Buffer.from(`${encodeURIComponent(CLIENT)}:${PASS}`).toString('base64')}`,
    );
    expect(headers.get('content-type')).toBe('application/x-www-form-urlencoded');
    expect(Object.fromEntries(new URLSearchParams(exchange?.init.body as string))).toEqual({
      grant_type: 'authorization_code',
      code: CODE,
      redirect_uri: REDIRECT,
      code_verifier: flow.verifier,
    });
  });

  it("gives the ID token's SHA-256 as evidence, never the token", async () => {
    let issued = '';
    service.tokenBody = async (nonce) => {
      issued = await service.idToken({ nonce });
      return JSON.stringify({ access_token: ACCESS, id_token: issued });
    };
    const signedIn = await signIn();

    expect(signedIn.idTokenHash).toEqual(createHash('sha256').update(issued, 'ascii').digest());
    expect(JSON.stringify(signedIn)).not.toContain(issued);
  });

  it('takes a token without the login service session', async () => {
    service.tokenBody = async (nonce) =>
      JSON.stringify({ access_token: ACCESS, id_token: await service.idToken({ nonce }, { drop: ['sid'] }) });

    await expect(signIn()).resolves.toMatchObject({ evidence: { idpSessionId: undefined } });
  });

  describe('the state', () => {
    it.each([
      ['another flow’s', 'A'.repeat(43)],
      ['a shorter one', 'A'],
      ['an empty one', ''],
      ['one with a space', 'A A'],
    ])('refuses %s before any call', async (_, state) => {
      await expectFailure(signIn({ state }), 'state_mismatch');

      expect(service.callsTo('/oauth/v2/token')).toEqual([]);
    });

    it('refuses none at all', async () => {
      await expectFailure(signIn({ state: undefined as unknown as string }), 'state_mismatch');
    });
  });

  it.each([
    ['empty', ''],
    ['with a line break', 'code\nmore'],
    ['too long', 'c'.repeat(2049)],
  ])('refuses a code that is %s before any call', async (_, code) => {
    await expectFailure(signIn({ code }), 'code_rejected');

    expect(service.callsTo('/oauth/v2/token')).toEqual([]);
  });

  describe('the token endpoint', () => {
    it('says the code was refused when it answers 400', async () => {
      service.tokenStatus = 400;
      service.tokenBody = () => Promise.resolve(JSON.stringify({ error: 'invalid_grant' }));

      await expectFailure(signIn(), 'code_rejected', /answered 400/);
    });

    it('says the login service is unavailable when it answers 500, or can’t be reached', async () => {
      service.tokenStatus = 502;
      await expectFailure(signIn(), 'provider_unavailable', /answered 502/);

      service.tokenStatus = 200;
      const { flow } = await client.start();
      service.failNetwork = true;
      await expectFailure(client.finish(flow, { code: CODE, state: flow.state }), 'provider_unavailable', /a call to/);
    });

    it.each([
      ['no JSON', () => Promise.resolve('<html>'), /not JSON/],
      ['a JSON list', () => Promise.resolve('[]'), /not a JSON object/],
      ['no ID token', () => Promise.resolve(JSON.stringify({ access_token: 'only' })), /no ID token/],
      [
        'too much',
        () => Promise.resolve(JSON.stringify({ access_token: ACCESS, id_token: 'x'.repeat(70_000) })),
        /larger than 65536 bytes/,
      ],
    ])('refuses an answer with %s', async (_, body, message) => {
      service.tokenBody = body;

      await expectFailure(signIn(), 'provider_unavailable', message);
    });
  });

  describe('the ID token', () => {
    const withToken = (make: (nonce: string) => Promise<string>) => {
      service.tokenBody = async (nonce) => JSON.stringify({ access_token: ACCESS, id_token: await make(nonce) });
    };

    it.each<[string, (nonce: string) => Promise<string>, RegExp]>([
      [
        'signed by a key the issuer never published',
        (nonce) => service.idToken({ nonce }, { key: SECOND }),
        /ERR_JWKS_NO_MATCHING_KEY/,
      ],
      [
        'signed by another key under a published key’s ID',
        (nonce) => service.idToken({ nonce }, { key: { ...SECOND, kid: FIRST.kid } }),
        /ERR_JWS_SIGNATURE_VERIFICATION_FAILED/,
      ],
      ['signed with PS256', (nonce) => service.idToken({ nonce }, { alg: 'PS256' }), /ERR_JOSE_ALG_NOT_ALLOWED/],
      [
        'from another issuer',
        (nonce) => service.idToken({ nonce, iss: 'https://other.example.test' }),
        /ERR_JWT_CLAIM_VALIDATION_FAILED/,
      ],
      [
        'for another client',
        (nonce) => service.idToken({ nonce, aud: 'another-client' }),
        /ERR_JWT_CLAIM_VALIDATION_FAILED/,
      ],
      ['expired', (nonce) => service.idToken({ nonce, exp: NOW_S - 61 }), /ERR_JWT_EXPIRED/],
      ['issued too long ago', (nonce) => service.idToken({ nonce, iat: NOW_S - 400 }), /ERR_JWT_EXPIRED/],
      [
        'issued in the future',
        (nonce) => service.idToken({ nonce, iat: NOW_S + 120 }),
        /ERR_JWT_CLAIM_VALIDATION_FAILED/,
      ],
      [
        'without a nonce',
        (nonce) => service.idToken({ nonce }, { drop: ['nonce'] }),
        /ERR_JWT_CLAIM_VALIDATION_FAILED/,
      ],
      [
        'without an authentication time',
        (nonce) => service.idToken({ nonce }, { drop: ['auth_time'] }),
        /ERR_JWT_CLAIM_VALIDATION_FAILED/,
      ],
      [
        'without authentication methods',
        (nonce) => service.idToken({ nonce }, { drop: ['amr'] }),
        /ERR_JWT_CLAIM_VALIDATION_FAILED/,
      ],
      [
        'without a subject',
        (nonce) => service.idToken({ nonce }, { drop: ['sub'] }),
        /ERR_JWT_CLAIM_VALIDATION_FAILED/,
      ],
      ['with another flow’s nonce', () => service.idToken({ nonce: 'A'.repeat(43) }), /the nonce/],
      [
        'for us and another client, naming no authorized party',
        (nonce) => service.idToken({ nonce, aud: [CLIENT, 'another-client'] }),
        /several audiences/,
      ],
      [
        'authorized for another client',
        (nonce) => service.idToken({ nonce, azp: 'another-client' }),
        /authorized party/,
      ],
      [
        'with an authentication time as text',
        (nonce) => service.idToken({ nonce, auth_time: 'yesterday' }),
        /not a number/,
      ],
      ['authenticated in the future', (nonce) => service.idToken({ nonce, auth_time: NOW_S + 120 }), /in the future/],
      [
        'with a login service session that isn’t text',
        (nonce) => service.idToken({ nonce, sid: 7 }),
        /session is not text/,
      ],
      ['with no authentication methods', (nonce) => service.idToken({ nonce, amr: [] }), /authentication methods/],
      [
        'with a subject that isn’t text',
        (nonce) => service.idToken({ nonce, sub: 7 as unknown as string }),
        /subject is not text/,
      ],
      ['with a subject too long to keep', (nonce) => service.idToken({ nonce, sub: '1'.repeat(256) }), /the subject/],
    ])('is refused when %s', async (_, make, message) => {
      withToken(make);

      await expectFailure(signIn(), 'token_invalid', message);
    });

    it('is refused unsigned', async () => {
      withToken(async (nonce) => {
        const signed = await service.idToken({ nonce });
        const payload = signed.split('.')[1] ?? '';
        const none = Buffer.from(JSON.stringify({ alg: 'none', kid: FIRST.kid })).toString('base64url');
        return `${none}.${payload}.`;
      });

      await expectFailure(signIn(), 'token_invalid');
    });

    it('is taken for us and another client when we are the authorized party', async () => {
      withToken((nonce) => service.idToken({ nonce, aud: [CLIENT, 'another-client'], azp: CLIENT }));

      await expect(signIn()).resolves.toBeDefined();
    });

    it('is taken within the clocks’ minute of difference', async () => {
      withToken((nonce) => service.idToken({ nonce, exp: NOW_S - 59, auth_time: NOW_S + 59 }));

      await expect(signIn()).resolves.toBeDefined();
    });
  });

  describe('the keys', () => {
    it('are fetched once, and again when the login service signs with a new one', async () => {
      await signIn();
      await signIn();
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(1);

      clock.advanceBy(60_000);
      service.published = [FIRST, SECOND];
      service.tokenBody = async (nonce) =>
        JSON.stringify({ access_token: ACCESS, id_token: await service.idToken({ nonce }, { key: SECOND }) });
      await expect(signIn()).resolves.toBeDefined();
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(2);
    });

    it('are tried again five seconds after a fetch that failed, and not sooner', async () => {
      await signIn();
      clock.advanceBy(60_000);
      service.published = [FIRST, SECOND];
      service.keysStatus = 503;
      service.tokenBody = async (nonce) =>
        JSON.stringify({ access_token: ACCESS, id_token: await service.idToken({ nonce }, { key: SECOND }) });
      await expectFailure(signIn(), 'provider_unavailable', /key set answered 503/);

      service.keysStatus = 200;
      clock.advanceBy(4_999);
      await expectFailure(signIn(), 'token_invalid', /ERR_JWKS_NO_MATCHING_KEY/);
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(2);

      clock.advanceBy(1);
      await expect(signIn()).resolves.toBeDefined();
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(3);
    });

    it('are not sent for again within five seconds when none are held yet and the fetch failed', async () => {
      service.keysStatus = 503;
      await expectFailure(signIn(), 'provider_unavailable', /key set answered 503/);
      await expectFailure(signIn(), 'provider_unavailable', /not tried again yet/);
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(1);

      service.keysStatus = 200;
      clock.advanceBy(5_000);
      await expect(signIn()).resolves.toBeDefined();
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(2);
    });

    /**
     * Starts `count` sign-ins and finishes them together, the key set held
     * unanswered until every one has traded its code and come to the keys.
     */
    async function finishTogether(count: number) {
      const flows = await Promise.all(Array.from({ length: count }, () => client.start()));
      let release = (): void => undefined;
      service.keysGate = new Promise((done) => {
        release = done;
      });
      const traded = service.callsTo('/oauth/v2/token').length + count;
      const settled = Promise.allSettled(
        flows.map(({ flow }) => {
          service.expect(flow);
          return client.finish(flow, { code: CODE, state: flow.state });
        }),
      );
      while (service.callsTo('/oauth/v2/token').length < traded) await new Promise((done) => setImmediate(done));
      // Each has its token by now; this lets every one read it and ask for the keys.
      await new Promise((done) => setTimeout(done, 200));
      release();
      service.keysGate = undefined;
      return (await settled).map((result) => result.status);
    }

    it('are sent for once, and waited on by all, when several sign-ins arrive before any are held', async () => {
      expect(await finishTogether(3)).toEqual(['fulfilled', 'fulfilled', 'fulfilled']);
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(1);
    });

    it('are sent for once, and waited on by all, when several sign-ins name a key not held', async () => {
      await signIn();
      clock.advanceBy(60_000);
      service.published = [FIRST, SECOND];
      service.tokenBody = async (nonce) =>
        JSON.stringify({ access_token: ACCESS, id_token: await service.idToken({ nonce }, { key: SECOND }) });

      expect(await finishTogether(3)).toEqual(['fulfilled', 'fulfilled', 'fulfilled']);
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(2);
    });

    it('are refused when the key set holds no list of keys', async () => {
      service.keysDocument = { keys: 'none' };

      await expectFailure(signIn(), 'provider_unavailable', /holds no keys/);
    });

    it('are fetched again at most once a minute, however many tokens name a key not held', async () => {
      await signIn();
      service.tokenBody = async (nonce) =>
        JSON.stringify({ access_token: ACCESS, id_token: await service.idToken({ nonce }, { key: SECOND }) });

      for (let attempt = 0; attempt < 3; attempt += 1) {
        await expectFailure(signIn(), 'token_invalid', /ERR_JWKS_NO_MATCHING_KEY/);
      }
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(1);

      // Five seconds is a failed fetch's wait; one that worked waits the minute.
      clock.advanceBy(5_000);
      await expectFailure(signIn(), 'token_invalid', /ERR_JWKS_NO_MATCHING_KEY/);
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(1);

      clock.advanceBy(55_000);
      await expectFailure(signIn(), 'token_invalid');
      expect(service.callsTo('/oauth/v2/keys')).toHaveLength(2);
    });
  });
});

describe('B2-6 reaching the login service inside the platform', () => {
  const INTERNAL = 'https://zitadel.internal.example.test';
  /** What reached the internal origin, which answers as the issuer only when told the issuer's host. */
  let reached: Call[];

  beforeEach(() => {
    reached = [];
    client = createOidcClient({
      settings: {
        issuer: ISSUER,
        clientId: CLIENT,
        clientSecret: PASS,
        redirectUri: REDIRECT,
        internalOrigin: INTERNAL,
      },
      fetch: (url, init = {}) => {
        const target = new URL(String(url));
        reached.push({ url: target.href, init });
        const headers = new Headers(init.headers);
        if (
          target.origin !== INTERNAL ||
          headers.get('x-zitadel-instance-host') !== 'auth.example.test' ||
          headers.get('x-zitadel-public-host') !== 'auth.example.test'
        ) {
          return Promise.resolve(new Response('not this instance', { status: 404 }));
        }
        return service.fetch(`${ISSUER}${target.pathname}${target.search}`, init);
      },
      clock,
    });
  });

  it("signs in with every call made there, naming the issuer's host, and none to the issuer's public address", async () => {
    const signedIn = await signIn();

    expect(signedIn.subject).toEqual({ issuer: ISSUER, subject: '338719472394810051' });
    expect(reached.map((call) => new URL(call.url).pathname)).toEqual([
      '/.well-known/openid-configuration',
      '/oauth/v2/token',
      '/oauth/v2/keys',
      '/oidc/v1/userinfo',
    ]);
    expect(reached.every((call) => call.url.startsWith(`${INTERNAL}/`))).toBe(true);
  });

  it("keeps the token call's own headers and body beside Zitadel's", async () => {
    await signIn();

    const token = reached.find((call) => call.url === `${INTERNAL}/oauth/v2/token`);
    const headers = new Headers(token?.init.headers);
    expect(headers.get('authorization')).toMatch(/^Basic /);
    expect(new URLSearchParams(token?.init.body as string).get('code')).toBe(CODE);
  });

  it("keeps an endpoint's query on the way there", async () => {
    service.discovery = { ...service.discovery, jwks_uri: `${ISSUER}/oauth/v2/keys?format=jwks` };

    await signIn().catch(() => undefined);

    expect(reached.map((call) => call.url)).toContain(`${INTERNAL}/oauth/v2/keys?format=jwks`);
  });

  it("still refuses a document whose endpoints aren't on the issuer's own origin, the internal one included", async () => {
    service.discovery = { ...service.discovery, token_endpoint: `${INTERNAL}/oauth/v2/token` };

    await expectFailure(signIn(), 'provider_unavailable', /token_endpoint is not on the issuer's origin/);
  });

  it('names the internal origin when a call there fails', async () => {
    service.failNetwork = true;

    await expectFailure(
      client.start(),
      'provider_unavailable',
      /a call to https:\/\/zitadel\.internal\.example\.test failed/,
    );
  });
});

describe('the settings', () => {
  it.each([
    ['an issuer that is not a URL', { issuer: 'auth.example.test' }],
    ['a redirect address that is not a URL', { redirectUri: '/v1/auth/callback' }],
    ['an empty client ID', { clientId: '' }],
    ['a client secret with a space', { clientSecret: 'two words' }],
    ['an internal origin that is not a URL', { internalOrigin: 'zitadel:8080' }],
    ['an internal origin with a path', { internalOrigin: 'https://zitadel.internal.example.test/oauth' }],
  ])('are refused with %s', (_, change) => {
    expect(() =>
      createOidcClient({
        settings: { issuer: ISSUER, clientId: CLIENT, clientSecret: PASS, redirectUri: REDIRECT, ...change },
        fetch: service.fetch,
        clock,
      }),
    ).toThrow(RangeError);
  });
});

describe('B4-4a the verified email address, from the userinfo endpoint', () => {
  it('asks with the access token, once the ID token stands, and gives the address in lower case', async () => {
    const signedIn = await signIn();

    expect(signedIn.verifiedEmail).toBe('sara.khan@example.test');
    const [asked] = service.callsTo('/oidc/v1/userinfo');
    expect(new Headers(asked?.init.headers).get('authorization')).toBe(`Bearer ${ACCESS}`);
    expect(JSON.stringify(signedIn)).not.toContain(ACCESS);
  });

  it.each<[string, Record<string, unknown>]>([
    ['not verified', { sub: SUBJECT, email: 'sara@example.test', email_verified: false }],
    ['verified as text, not true', { sub: SUBJECT, email: 'sara@example.test', email_verified: 'true' }],
    ['no word on verification', { sub: SUBJECT, email: 'sara@example.test' }],
    ['no address', { sub: SUBJECT, email_verified: true }],
    ['an address that isn’t one', { sub: SUBJECT, email: 'sara at example', email_verified: true }],
  ])('gives no address when it is %s, and the sign-in still stands', async (_what, userinfo) => {
    service.userinfo = userinfo;

    await expect(signIn()).resolves.toMatchObject({ subject: { subject: SUBJECT }, verifiedEmail: undefined });
  });

  it('refuses an answer about another person', async () => {
    service.userinfo = { sub: 'someone-else', email: 'mallory@example.test', email_verified: true };

    await expectFailure(signIn(), 'token_invalid', /another person/);
  });

  it('never asks when the ID token fails its check', async () => {
    service.tokenBody = async (nonce) =>
      JSON.stringify({ access_token: ACCESS, id_token: await service.idToken({ nonce: `${nonce}x` }) });

    await expectFailure(signIn(), 'token_invalid');
    expect(service.callsTo('/oidc/v1/userinfo')).toEqual([]);
  });

  it.each([401, 500, 503])(
    'fails as the login service unavailable when the endpoint answers %i (B4-6c: nothing stands unchecked)',
    async (status) => {
      service.userinfoStatus = status;

      await expectFailure(signIn(), 'provider_unavailable', new RegExp(`userinfo endpoint answered ${String(status)}`));
    },
  );

  it('fails as the login service unavailable when the endpoint can’t be reached, answers an error in JSON, or answers what isn’t a JSON object', async () => {
    const fetch = service.fetch;
    for (const answer of [
      // An error answer in JSON, as OAuth's bearer errors are, is still an error: never read as a person.
      () => Promise.resolve(Response.json({ error: 'invalid_token' }, { status: 401 })),
      () => Promise.reject(new TypeError('fetch failed')),
      () => Promise.resolve(new Response('not json', { status: 200 })),
      () => Promise.resolve(Response.json(['a list'])),
    ]) {
      client = createOidcClient({
        settings: { issuer: ISSUER, clientId: CLIENT, clientSecret: PASS, redirectUri: REDIRECT },
        fetch: (url, init = {}) => (String(url) === `${ISSUER}/oidc/v1/userinfo` ? answer() : fetch(url, init)),
        clock,
      });

      await expectFailure(signIn(), 'provider_unavailable');
    }
  });

  it.each<[string, unknown]>([
    ['none', undefined],
    ['not text', 42],
    ['empty', ''],
    ['with a space', 'an access token'],
    ['longer than 4,096 characters', 'a'.repeat(4097)],
  ])('fails as the login service unavailable when the access token is %s', async (_what, accessToken) => {
    service.tokenBody = async (nonce) =>
      JSON.stringify({ access_token: accessToken, id_token: await service.idToken({ nonce }) });

    await expectFailure(signIn(), 'provider_unavailable', /access token/);
    expect(service.callsTo('/oidc/v1/userinfo')).toEqual([]);
  });

  it('takes an access token of 4,096 characters', async () => {
    const long = 'a'.repeat(4096);
    service.tokenBody = async (nonce) =>
      JSON.stringify({ access_token: long, id_token: await service.idToken({ nonce }) });
    const fetch = service.fetch;
    client = createOidcClient({
      settings: { issuer: ISSUER, clientId: CLIENT, clientSecret: PASS, redirectUri: REDIRECT },
      fetch: (url, init = {}) =>
        String(url) === `${ISSUER}/oidc/v1/userinfo`
          ? Promise.resolve(Response.json(service.userinfo))
          : fetch(url, init),
      clock,
    });

    await expect(signIn()).resolves.toMatchObject({ verifiedEmail: 'sara.khan@example.test' });
  });

  it('refuses a discovery document whose userinfo endpoint is on another origin', async () => {
    service.discovery = { ...service.discovery, userinfo_endpoint: 'https://elsewhere.example.test/userinfo' };

    await expectFailure(signIn(), 'provider_unavailable', /userinfo_endpoint/);
  });
});

describe('B4-6c the login service’s break-glass admin never signs in', () => {
  const admin = { sub: SUBJECT, email: 'sara.khan@example.test', email_verified: true };

  it.each(['admin@agent-x.auth.example.test', 'admin'])(
    'fails when the userinfo answer names the login %s, whatever its address',
    async (loginName) => {
      service.userinfo = { ...admin, preferred_username: loginName };

      await expectFailure(signIn(), 'break_glass', /break-glass/);
    },
  );

  it('fails when it names the break-glass login with no verified address at all', async () => {
    service.userinfo = { sub: SUBJECT, preferred_username: 'admin@agent-x.auth.example.test' };

    await expectFailure(signIn(), 'break_glass');
  });

  it.each([500, 503])(
    'lets no sign-in through unchecked when the endpoint answers %i: it fails, to be tried again (review)',
    async (status) => {
      service.userinfo = { ...admin, preferred_username: 'admin@agent-x.auth.example.test' };
      service.userinfoStatus = status;

      await expectFailure(signIn(), 'provider_unavailable');
    },
  );

  it('never says the login name when it fails', async () => {
    service.userinfo = { ...admin, preferred_username: 'Admin@Agent-X.auth.example.test' };

    const failed = await signIn().catch((error: unknown) => error);

    expect(failed).toBeInstanceOf(SignInFailed);
    expect((failed as Error).message).not.toMatch(/agent-x|sara/i);
  });

  it.each([
    ['another person in the same organisation', 'shahbaz@agent-x.auth.example.test'],
    ['an admin of another organisation', 'admin@acme.auth.example.test'],
    ['no login name', undefined],
  ])('lets %s sign in, with their verified address', async (_what, loginName) => {
    service.userinfo = { ...admin, ...(loginName !== undefined && { preferred_username: loginName }) };

    await expect(signIn()).resolves.toMatchObject({ verifiedEmail: 'sara.khan@example.test' });
  });
});
