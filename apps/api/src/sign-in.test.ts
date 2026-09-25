// B2-3a-2: the sign-in routes over HTTP, with a stand-in sign-in (the real
// one: the identity module's sign-in-flow.db.test.ts). B2-4b: a signed-in
// request, found by its session cookie, and the person's own session.
import {
  type CallbackInput,
  type LiveSession,
  type SignIn,
  SignInFailed,
  StepUpFailed,
} from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { SESSION_CHALLENGE } from './access.ts';
import { errorBody } from './errors.ts';
import type { SecurityEventNote } from './security-recorder.ts';
import { buildServer } from './server.ts';
import { cookieValue, FLOW_COOKIE, SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const LOGIN_URL = 'https://auth.agentx.example/oauth/v2/authorize?state=s';
const FLOW_ID = 'F'.repeat(43);
const SESSION_ID = 'S'.repeat(43);
const NEW_SESSION = 'N'.repeat(43);
const USER_ID = '0199a0f0-0000-7000-8000-000000000011';
const RECORD_ID = '0199a0f0-0000-7000-8000-000000000022';
const SESSION_SECONDS = 43_200;

/** A live session, as the sign-in finds it for a request. */
const LIVE: LiveSession = {
  sessionId: RECORD_ID,
  userId: USER_ID,
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: ['pwd', 'otp', 'mfa'],
  createdAt: new Date('2026-09-24T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-24T09:10:00.000Z'),
  endsAt: new Date('2026-09-24T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-24T09:40:00.000Z'),
};

/** The stand-in: what each route asked of it, and what it answers. */
class StandIn implements SignIn {
  begun: (string | undefined)[] = [];
  completed: CallbackInput[] = [];
  signedOut: (string | undefined)[] = [];
  failWith: Error | undefined;
  beginFailsWith: Error | undefined;
  /** The live sessions, by cookie, and every cookie a request was looked up by. */
  live = new Map<string, LiveSession>();
  looked: string[] = [];
  lookupFails: Error | undefined;

  begin(returnTo?: string) {
    this.begun.push(returnTo);
    if (this.beginFailsWith !== undefined) return Promise.reject(this.beginFailsWith);
    return Promise.resolve({ url: LOGIN_URL, flowId: FLOW_ID });
  }

  /** Each step-up begun: the session, the challenge and the return path. */
  steppedUp: [string, string, string | undefined][] = [];
  /** When set, the step-up that `complete` finishes: its challenge. */
  completesStepUp: string | undefined;

  beginStepUp(sessionId: string, challengeId: string, returnTo?: string) {
    this.steppedUp.push([sessionId, challengeId, returnTo]);
    if (this.beginFailsWith !== undefined) return Promise.reject(this.beginFailsWith);
    return Promise.resolve({ url: `${LOGIN_URL}&prompt=login`, flowId: FLOW_ID });
  }

  complete(input: CallbackInput) {
    this.completed.push(input);
    if (this.failWith !== undefined) return Promise.reject(this.failWith);
    return Promise.resolve({
      userId: USER_ID,
      sessionId: RECORD_ID,
      cookie: NEW_SESSION,
      returnTo: '/agents',
      stepUpChallengeId: this.completesStepUp,
    });
  }

  signOut(cookie: string | undefined) {
    this.signedOut.push(cookie);
    return Promise.resolve(cookie !== undefined);
  }

  signedIn(cookie: string) {
    this.looked.push(cookie);
    if (this.lookupFails !== undefined) return Promise.reject(this.lookupFails);
    return Promise.resolve(this.live.get(cookie));
  }
}

const servers: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function server(signIn: SignIn | undefined, limits: { perAddress?: number; perUser?: number } = {}) {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: limits.perAddress ?? 100,
      rateLimitPerUserPerMinute: limits.perUser ?? 100,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: capture,
  });
  const noted: SecurityEventNote[] = [];
  const app = await buildServer({
    config,
    logger,
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: signIn === undefined ? undefined : { service: signIn, sessionSeconds: SESSION_SECONDS },
    securityEvents: { note: (event) => noted.push(event) },
  });
  servers.push(app);
  return { app, capture, noted };
}

const setCookies = (header: string | string[] | number | undefined): string[] =>
  header === undefined ? [] : Array.isArray(header) ? header : [String(header)];

const callback = (query: string, cookie?: string) => ({
  method: 'GET' as const,
  url: `/v1/auth/callback${query}`,
  headers: cookie === undefined ? {} : { cookie },
});

describe('starting a sign-in', () => {
  it('sends the browser to the login service with a short-lived Lax flow cookie', async () => {
    const standIn = new StandIn();
    const { app } = await server(standIn);

    const response = await app.inject('/v1/auth/sign-in?returnTo=%2Fagents%3Ftab%3Dkeys');

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(LOGIN_URL);
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${FLOW_COOKIE}=${FLOW_ID}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`,
    ]);
    expect(standIn.begun).toEqual(['/agents?tab=keys']);
  });

  it('sends the browser home afterwards when it names nowhere', async () => {
    const standIn = new StandIn();
    const { app } = await server(standIn);

    expect((await app.inject('/v1/auth/sign-in')).statusCode).toBe(302);
    expect(standIn.begun).toEqual([undefined]);
  });

  it.each(['//evil.example', 'https://evil.example/', '/\\evil.example', `/${'a'.repeat(512)}`])(
    'refuses a return path that leaves our origin, %s, starting nothing (SEC-WEB-04)',
    async (returnTo) => {
      const standIn = new StandIn();
      const { app } = await server(standIn);

      const response = await app.inject(`/v1/auth/sign-in?returnTo=${encodeURIComponent(returnTo)}`);

      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ error: { code: 'BAD_REQUEST' } });
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(standIn.begun).toEqual([]);
    },
  );
});

describe('coming back from the login service', () => {
  it('opens a session: a fresh Strict session cookie, the flow cookie cleared, and on to the path asked for', async () => {
    const standIn = new StandIn();
    const { app, capture } = await server(standIn);

    const response = await app.inject(
      callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
    );

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/agents');
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${SESSION_COOKIE}=${NEW_SESSION}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${String(SESSION_SECONDS)}`,
      `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    expect(standIn.completed).toEqual([
      { flowId: FLOW_ID, code: 'a-code', state: 'a-state', previousCookie: SESSION_ID },
    ]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.signed_in', userId: USER_ID }));
    expect(capture.text).not.toContain(NEW_SESSION);
    expect(capture.text).not.toContain(FLOW_ID);
  });

  it('passes on no flow and no session when the browser brings none', async () => {
    const standIn = new StandIn();
    const { app } = await server(standIn);

    await app.inject(callback('?code=a-code&state=a-state'));

    expect(standIn.completed).toEqual([
      { flowId: undefined, code: 'a-code', state: 'a-state', previousCookie: undefined },
    ]);
  });

  it.each([
    ['the login service said no', '?error=access_denied&state=a-state', 'provider_refused'],
    [
      'the login service said no, with a code all the same',
      '?error=access_denied&code=a-code&state=a-state',
      'provider_refused',
    ],
    ['no code', '?state=a-state', 'callback_incomplete'],
    ['no state', '?code=a-code', 'callback_incomplete'],
  ])('refuses as SIGN_IN_FAILED when %s, asking nothing of the sign-in', async (_, query, failure) => {
    const standIn = new StandIn();
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject({
      ...callback(query, `${FLOW_COOKIE}=${FLOW_ID}`),
      remoteAddress: '203.0.113.9',
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(errorBody('SIGN_IN_FAILED', response.headers['x-correlation-id'] as string));
    expect(standIn.completed).toEqual([]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.sign_in_failed', failure }));
    expect(noted).toEqual([{ kind: 'sign_in_failed', reason: failure, ip: '203.0.113.9' }]);
  });

  it('refuses as SIGN_IN_FAILED when the sign-in fails, setting no cookie, and logs which step failed', async () => {
    const standIn = new StandIn();
    standIn.failWith = new SignInFailed('token_invalid', 'the ID token failed its check: ERR_JWT_EXPIRED');
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject({
      ...callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`),
      remoteAddress: '2001:db8:1:2::7',
    });
    expect(noted).toEqual([{ kind: 'sign_in_failed', reason: 'token_invalid', ip: '2001:db8:1:2::7' }]);

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: { code: 'SIGN_IN_FAILED' } });
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.sign_in_failed', failure: 'token_invalid' }),
    );
  });

  it('fails on our side, not as a refused sign-in, when something else goes wrong', async () => {
    const standIn = new StandIn();
    standIn.failWith = new Error('the database is away');
    const { app, noted } = await server(standIn);

    const response = await app.inject(callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`));

    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR' } });
    // Our failure, not the caller's: no security event.
    expect(noted).toEqual([]);
  });

  it('notes no security event for a sign-in that works', async () => {
    const { app, noted } = await server(new StandIn());

    const response = await app.inject(callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`));

    expect(response.statusCode).toBe(302);
    expect(noted).toEqual([]);
  });
});

describe('S47 a login service that cannot be reached, such as one still waking from zero', () => {
  const unreachable = () =>
    new SignInFailed('provider_unavailable', 'a call to https://zitadel.internal.example failed');

  it.each([
    [
      'starting a sign-in',
      (standIn: StandIn) => {
        standIn.beginFailsWith = unreachable();
      },
      { url: '/v1/auth/sign-in' },
    ],
    [
      'coming back from it',
      (standIn: StandIn) => {
        standIn.failWith = unreachable();
      },
      callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`),
    ],
  ])(
    'answers %s with SIGN_IN_UNAVAILABLE, 503 and Retry-After, sets no cookie, and notes no security event',
    async (_what, fail, request) => {
      const standIn = new StandIn();
      fail(standIn);
      const { app, capture, noted } = await server(standIn);

      const response = await app.inject(request);

      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual(errorBody('SIGN_IN_UNAVAILABLE', response.headers['x-correlation-id'] as string));
      expect(response.headers['retry-after']).toBe('15');
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(noted).toEqual([]);
      expect(capture.lines()).toContainEqual(
        expect.objectContaining({ event: 'auth.sign_in_unavailable', level: 'warn' }),
      );
    },
  );

  it('still fails on our side, not as unavailable, for any other failure at the start', async () => {
    const standIn = new StandIn();
    standIn.beginFailsWith = new Error('the database is away');
    const { app } = await server(standIn);

    const response = await app.inject('/v1/auth/sign-in');

    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR' } });
  });

  it('refuses a sign-in the login service refused as SIGN_IN_FAILED, as before, not as unavailable', async () => {
    const standIn = new StandIn();
    standIn.failWith = new SignInFailed('code_rejected', 'the login service refused the code');
    const { app } = await server(standIn);

    const response = await app.inject(callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`));

    expect(response.statusCode).toBe(401);
    expect(response.headers['retry-after']).toBeUndefined();
  });
});

describe('signing out', () => {
  it('ends the session the browser holds and clears its cookie', async () => {
    const standIn = new StandIn();
    const { app, capture } = await server(standIn);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/auth/sign-out',
      headers: { origin: PUBLIC_ORIGIN, cookie: `${SESSION_COOKIE}=${SESSION_ID}` },
    });

    expect(response.statusCode).toBe(204);
    expect(response.body).toBe('');
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`,
    ]);
    expect(standIn.signedOut).toEqual([SESSION_ID]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.signed_out' }));
  });

  it('answers the same with no session to end', async () => {
    const standIn = new StandIn();
    const { app } = await server(standIn);

    const response = await app.inject({ method: 'POST', url: '/v1/auth/sign-out', headers: { origin: PUBLIC_ORIGIN } });

    expect(response.statusCode).toBe(204);
    expect(standIn.signedOut).toEqual([undefined]);
  });

  it('refuses a sign-out from another site, ending nothing (SEC-WEB-01)', async () => {
    const standIn = new StandIn();
    const { app } = await server(standIn);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/auth/sign-out',
      headers: { origin: 'https://evil.example', cookie: `${SESSION_COOKIE}=${SESSION_ID}` },
    });

    expect(response.statusCode).toBe(403);
    expect(standIn.signedOut).toEqual([]);
  });
});

describe('a HEAD of either GET', () => {
  it.each(['/v1/auth/sign-in', '/v1/auth/callback?code=a-code&state=a-state'])(
    'does nothing at %s, and answers NOT_FOUND',
    async (url) => {
      const standIn = new StandIn();
      const { app } = await server(standIn);

      const response = await app.inject({ method: 'HEAD', url, headers: { cookie: `${FLOW_COOKIE}=${FLOW_ID}` } });

      expect(response.statusCode).toBe(404);
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(standIn.begun).toEqual([]);
      expect(standIn.completed).toEqual([]);
    },
  );
});

describe('with sign-in off', () => {
  it.each([
    { method: 'GET' as const, url: '/v1/auth/sign-in' },
    { method: 'GET' as const, url: '/v1/auth/callback?code=a&state=b' },
    { method: 'POST' as const, url: '/v1/auth/sign-out', headers: { origin: PUBLIC_ORIGIN } },
  ])('answers $method $url as NOT_FOUND, as a feature that is off does', async (request) => {
    const { app } = await server(undefined);

    const response = await app.inject(request);

    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
  });
});

describe("B2-4b a signed-in request, and the person's own session", () => {
  const asking = (cookie?: string, method: 'GET' | 'HEAD' = 'GET') => ({
    method,
    url: '/v1/auth/session',
    headers: cookie === undefined ? {} : { cookie: `theme=dark; ${SESSION_COOKIE}=${cookie}` },
  });

  it('answers a live session with its own details, found by the session cookie alone', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app } = await server(standIn);

    const response = await app.inject(asking(SESSION_ID));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      userId: USER_ID,
      authenticatedAt: '2026-09-24T09:00:00.000Z',
      methods: ['pwd', 'otp', 'mfa'],
      idleExpiresAt: '2026-09-24T09:40:00.000Z',
      expiresAt: '2026-09-24T21:00:05.000Z',
    });
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(standIn.looked).toEqual([SESSION_ID]);
  });

  it('answers a HEAD of it the same way, with no body', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app } = await server(standIn);

    const response = await app.inject(asking(SESSION_ID, 'HEAD'));

    expect(response.statusCode).toBe(200);
    expect(response.body).toBe('');
  });

  it.each([
    ['no session cookie', undefined, []],
    ['a cookie we could never have set, asking nothing', 'short', []],
    ['a cookie with no live session behind it', NEW_SESSION, [NEW_SESSION]],
  ])('refuses %s as UNAUTHENTICATED, with the challenge that says how to sign in', async (_, cookie, looked) => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app } = await server(standIn);

    const response = await app.inject(asking(cookie));

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(errorBody('UNAUTHENTICATED', response.headers['x-correlation-id'] as string));
    expect(response.headers['www-authenticate']).toBe(SESSION_CHALLENGE);
    expect(standIn.looked).toEqual(looked);
  });

  it('refuses a signed-in person on a route for roles only as FORBIDDEN, with no membership lookup, never running it', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app } = await server(standIn);
    const reached: string[] = [];
    app.get(
      '/test/members',
      { config: { access: ['admin'] }, schema: { response: { 200: z.object({ ok: z.literal(true) }) } } },
      () => {
        reached.push('members');
        return { ok: true as const };
      },
    );

    const response = await app.inject({
      url: '/test/members',
      headers: {
        cookie: `${SESSION_COOKIE}=${SESSION_ID}`,
        'agentx-organization': '0199a0f0-0000-7000-8000-00000000abcd',
      },
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('FORBIDDEN', response.headers['x-correlation-id'] as string));
    expect(reached).toEqual([]);
  });

  it('asks nothing for a public route, whatever cookie it carries', async () => {
    const standIn = new StandIn();
    const { app } = await server(standIn);

    const response = await app.inject({ url: '/health', headers: { cookie: `${SESSION_COOKIE}=${SESSION_ID}` } });

    expect(response.statusCode).toBe(200);
    expect(standIn.looked).toEqual([]);
  });

  it('fails on our side, never letting the request through, when the session cannot be looked up', async () => {
    const standIn = new StandIn();
    standIn.lookupFails = new Error('the database is away');
    const { app } = await server(standIn);
    // A route that would answer whoever reached it: only the hook stands in the way.
    const reached: string[] = [];
    app.get(
      '/test/mine',
      { config: { access: ['person'] }, schema: { response: { 200: z.object({ ok: z.literal(true) }) } } },
      () => {
        reached.push('mine');
        return { ok: true as const };
      },
    );

    const response = await app.inject({ url: '/test/mine', headers: { cookie: `${SESSION_COOKIE}=${SESSION_ID}` } });

    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR' } });
    expect(reached).toEqual([]);
  });

  it('with sign-in off, refuses it as UNAUTHENTICATED: no one can be signed in', async () => {
    const { app } = await server(undefined);

    const response = await app.inject(asking(SESSION_ID));

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe(SESSION_CHALLENGE);
  });
});

describe("SEC-AV-07 B2-5c each signed-in person's own rate limit, beside their address's", () => {
  const OTHER_SESSION = 'O'.repeat(43);
  const OTHER_USER = '0199a0f0-0000-7000-8000-000000000033';
  const fromAddress = (cookie: string, remoteAddress: string) => ({
    url: '/v1/auth/session',
    headers: { cookie: `${SESSION_COOKIE}=${cookie}` },
    remoteAddress,
  });
  /** Two people signed in, with a limit of 10 each and 100 for each address. */
  async function twoPeople() {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    standIn.live.set(OTHER_SESSION, { ...LIVE, sessionId: '0199a0f0-0000-7000-8000-000000000044', userId: OTHER_USER });
    return { standIn, ...(await server(standIn, { perAddress: 100, perUser: 10 })) };
  }

  it('refuses a person past their own limit, however many addresses their requests come from', async () => {
    const { app } = await twoPeople();
    const statuses = [];
    for (let i = 0; i < 10; i += 1) {
      statuses.push((await app.inject(fromAddress(SESSION_ID, `198.51.100.${String(i)}`))).statusCode);
    }
    const refused = await app.inject(fromAddress(SESSION_ID, '198.51.100.99'));

    expect(statuses).toEqual(Array.from({ length: 10 }, () => 200));
    expect(refused.statusCode).toBe(429);
    expect(refused.json()).toEqual(errorBody('RATE_LIMITED', refused.headers['x-correlation-id'] as string));
    expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
  });

  it("says the person's limit on the refusal, and the address's on every answer before it", async () => {
    const { app } = await twoPeople();
    const first = await app.inject(fromAddress(SESSION_ID, '198.51.100.1'));
    for (let i = 0; i < 9; i += 1) await app.inject(fromAddress(SESSION_ID, '198.51.100.1'));
    const refused = await app.inject(fromAddress(SESSION_ID, '198.51.100.1'));

    expect(first.headers).toMatchObject({ 'x-ratelimit-limit': '100', 'x-ratelimit-remaining': '99' });
    expect(first.headers).not.toHaveProperty('retry-after');
    expect(refused.headers).toMatchObject({ 'x-ratelimit-limit': '10', 'x-ratelimit-remaining': '0' });
  });

  it('counts each person on their own', async () => {
    const { app } = await twoPeople();
    for (let i = 0; i < 11; i += 1) await app.inject(fromAddress(SESSION_ID, '198.51.100.1'));

    expect((await app.inject(fromAddress(OTHER_SESSION, '198.51.100.2'))).statusCode).toBe(200);
  });

  it('notes each refusal as a security event, with the person and the address, and nothing before it', async () => {
    const { app, noted } = await twoPeople();
    for (let i = 0; i < 10; i += 1) await app.inject(fromAddress(SESSION_ID, '198.51.100.1'));
    expect(noted).toEqual([]);

    await app.inject(fromAddress(SESSION_ID, '203.0.113.9'));

    expect(noted).toEqual([{ kind: 'rate_limited', reason: 'per_user', ip: '203.0.113.9', userId: USER_ID }]);
  });

  it('counts no one who is not signed in, whose requests are refused as they were', async () => {
    const { app, noted } = await twoPeople();
    for (let i = 0; i < 20; i += 1) {
      expect((await app.inject({ url: '/v1/auth/session', remoteAddress: '198.51.100.1' })).statusCode).toBe(401);
    }

    expect((await app.inject(fromAddress(SESSION_ID, '198.51.100.1'))).statusCode).toBe(200);
    expect(noted).toEqual([]);
  });

  it('counts no request to a public route, which no one is signed in for', async () => {
    const { app, noted } = await twoPeople();
    const statuses = [];
    for (let i = 0; i < 20; i += 1) {
      statuses.push((await app.inject({ url: '/health', remoteAddress: `198.51.100.${String(i)}` })).statusCode);
    }

    expect(statuses).toEqual(Array.from({ length: 20 }, () => 200));
    expect(noted).toEqual([]);
  });

  it("leaves the address's own limit first: a refused address asks nothing of the session store", async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app, noted } = await server(standIn, { perAddress: 10, perUser: 100 });
    for (let i = 0; i < 11; i += 1) await app.inject(fromAddress(SESSION_ID, '198.51.100.1'));

    expect(standIn.looked).toHaveLength(10);
    expect(noted).toEqual([{ kind: 'rate_limited', reason: 'per_address', ip: '198.51.100.1' }]);
  });
});

describe('B3-3a stepping up: signing in again to confirm a change', () => {
  const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c1';
  /** A request to start a step-up, with the session cookie given, or none for null. */
  const starting = (query: string, cookie: string | null = SESSION_ID, method: 'GET' | 'HEAD' = 'GET') => ({
    method,
    url: `/v1/auth/step-up${query}`,
    headers: cookie === null ? {} : { cookie: `${SESSION_COOKIE}=${cookie}` },
  });

  it("starts one for the person's own session: a flow cookie, and off to sign in again", async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app } = await server(standIn);

    const response = await app.inject(starting(`?challenge=${CHALLENGE}&returnTo=/members/confirm`));

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`${LOGIN_URL}&prompt=login`);
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${FLOW_COOKIE}=${FLOW_ID}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`,
    ]);
    expect(standIn.steppedUp).toEqual([[LIVE.sessionId, CHALLENGE, '/members/confirm']]);
  });

  it('asks who is calling first: no session is UNAUTHENTICATED, and starts nothing', async () => {
    const standIn = new StandIn();
    const { app } = await server(standIn);

    const response = await app.inject(starting(`?challenge=${CHALLENGE}`, null));

    expect(response.statusCode).toBe(401);
    expect(standIn.steppedUp).toEqual([]);
  });

  it.each([
    ['no challenge', ''],
    ['a challenge that is not a UUID', '?challenge=nope'],
    ['a return path to another site', `?challenge=${CHALLENGE}&returnTo=//evil.example`],
  ])('refuses %s as BAD_REQUEST, starting nothing', async (_what, query) => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app } = await server(standIn);

    const response = await app.inject(starting(query));

    expect(response.statusCode).toBe(400);
    expect(standIn.steppedUp).toEqual([]);
  });

  it("refuses a challenge that isn't the session's, or isn't pending, as STEP_UP_FAILED, noting it with the person", async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    standIn.beginFailsWith = new StepUpFailed('challenge_missing', 'test');
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject(starting(`?challenge=${CHALLENGE}`));

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('STEP_UP_FAILED', response.headers['x-correlation-id'] as string));
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(noted).toEqual([
      { kind: 'sign_in_failed', reason: 'step_up_challenge_missing', ip: '127.0.0.1', userId: USER_ID },
    ]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.step_up_failed', failure: 'challenge_missing', userId: USER_ID }),
    );
  });

  it('answers a login service that cannot be reached as SIGN_IN_UNAVAILABLE, noting nothing', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    standIn.beginFailsWith = new SignInFailed('provider_unavailable', 'test');
    const { app, noted } = await server(standIn);

    const response = await app.inject(starting(`?challenge=${CHALLENGE}`));

    expect(response.statusCode).toBe(503);
    expect(response.headers['retry-after']).toBe('15');
    expect(noted).toEqual([]);
  });

  it('fails on our side for anything else that goes wrong', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    standIn.beginFailsWith = new Error('the database went away');
    const { app } = await server(standIn);

    expect((await app.inject(starting(`?challenge=${CHALLENGE}`))).statusCode).toBe(500);
  });

  it('does nothing for a HEAD of it', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const { app } = await server(standIn);

    expect((await app.inject(starting(`?challenge=${CHALLENGE}`, SESSION_ID, 'HEAD'))).statusCode).toBe(404);
    expect(standIn.steppedUp).toEqual([]);
  });

  it("comes back with the session's new cookie ID, the flow cookie cleared, and on to confirm the change", async () => {
    const standIn = new StandIn();
    standIn.completesStepUp = CHALLENGE;
    const { app, capture } = await server(standIn);

    const response = await app.inject(
      callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
    );

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/agents');
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${SESSION_COOKIE}=${NEW_SESSION}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${String(SESSION_SECONDS)}`,
      `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.stepped_up', userId: USER_ID }));
    expect(capture.lines().some((line) => line.event === 'auth.signed_in')).toBe(false);
  });

  it.each([
    ['another person signed in', 'other_person', USER_ID],
    ['an old authentication', 'stale_authentication', USER_ID],
    ['no second factor', 'no_second_factor', USER_ID],
    ['no live session', 'session_missing', undefined],
  ] as const)(
    'refuses a step-up back with %s as STEP_UP_FAILED, leaving the cookies',
    async (_what, failure, userId) => {
      const standIn = new StandIn();
      standIn.failWith = new StepUpFailed(failure, 'test', userId);
      const { app, noted } = await server(standIn);

      const response = await app.inject(
        callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
      );

      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual(errorBody('STEP_UP_FAILED', response.headers['x-correlation-id'] as string));
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(noted).toEqual([
        {
          kind: 'sign_in_failed',
          reason: `step_up_${failure}`,
          ip: '127.0.0.1',
          ...(userId !== undefined && { userId }),
        },
      ]);
    },
  );
});

describe('reading our cookies', () => {
  it('finds ours among others', () => {
    expect(cookieValue(`theme=dark; ${FLOW_COOKIE}=${FLOW_ID};other=1`, FLOW_COOKIE)).toBe(FLOW_ID);
  });

  it.each([
    ['no header', undefined],
    ['no such cookie', 'theme=dark'],
    ['a value we never set', `${FLOW_COOKIE}=short`],
    ['a value with more after it', `${FLOW_COOKIE}=${FLOW_ID}x`],
    ['the cookie twice', `${FLOW_COOKIE}=${FLOW_ID}; ${FLOW_COOKIE}=${'G'.repeat(43)}`],
    ['a name that only starts like ours', `${FLOW_COOKIE}x=${FLOW_ID}`],
    ['a name that runs into a value', `${FLOW_COOKIE}x${FLOW_ID}`],
  ])('finds none with %s', (_, header) => {
    expect(cookieValue(header, FLOW_COOKIE)).toBeUndefined();
  });
});
