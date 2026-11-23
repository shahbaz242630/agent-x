// B2-3a-2: the sign-in routes over HTTP, with a stand-in sign-in (the real
// one: the identity module's sign-in-flow.db.test.ts). B2-4b: a signed-in
// request, found by its session cookie, and the person's own session.
import {
  type CallbackInput,
  type LiveSession,
  type LoginSessions,
  LoginSessionsUnavailable,
  MOST_OPEN_SIGN_INS,
  MOST_OPEN_SIGN_INS_A_NETWORK,
  MOST_SESSIONS_A_DAY,
  MOST_STEP_UPS_A_DAY,
  SessionsSpent,
  type SignIn,
  SignInBusy,
  SignInFailed,
  StepUpFailed,
  type Subject,
} from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { FixedClock, LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

// Its first server built before the tests, so none is timed cold (route-server.helper.test.ts).
import './route-server.helper.test.ts';
import { type FindMembership, ORGANIZATION_HEADER, SESSION_CHALLENGE } from './access.ts';
import { errorBody } from './errors.ts';
import { liveSession, ONE_TIME_CODE } from './live-session.helper.test.ts';
import { personCapWarning } from './oauth-authorizing.ts';
import type { SecurityEventNote } from './security-recorder.ts';
import { clientSite } from './rate-limit.ts';
import { PLATFORM_GROWTH_BRAKE } from './platform-growth-brake.ts';
import { buildServer } from './server.ts';
import { cookieValue, FLOW_COOKIE, SESSION_COOKIE, SIGN_IN_STARTS } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const LOGIN_URL = 'https://auth.agentx.example/oauth/v2/authorize?state=s';
const FLOW_ID = 'F'.repeat(43);
const SESSION_ID = 'S'.repeat(43);
const NEW_SESSION = 'N'.repeat(43);
const USER_ID = '0199a0f0-0000-7000-8000-000000000011';
const OTHER_USER = '0199a0f0-0000-7000-8000-000000000012';
const RECORD_ID = '0199a0f0-0000-7000-8000-000000000022';
const SESSION_SECONDS = 43_200;
const SUBJECT = { issuer: 'https://auth.agentx.example', subject: '312000000000000042' };

/** A live session, as the sign-in finds it for a request. */
const LIVE = liveSession('2026-09-24T09:00:00.000Z', { amr: ONE_TIME_CODE });

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

  /** The network each sign-in was begun from (S206 V8). */
  networks: string[] = [];
  /** Whether each sign-in begun had its network's oldest give way to it (S208). */
  gaveWay = false;

  begin(returnTo: string | undefined, network: string) {
    this.begun.push(returnTo);
    this.networks.push(network);
    if (this.beginFailsWith !== undefined) return Promise.reject(this.beginFailsWith);
    return Promise.resolve({ url: LOGIN_URL, flowId: FLOW_ID, gaveWay: this.gaveWay });
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

  /** When set, the step-up a refused callback's flow was for: as the sign-in, it answers StepUpFailed with it. */
  refusedStepUp: { returnTo: string; challengeId: string } | undefined;

  complete(input: CallbackInput) {
    this.completed.push(input);
    if ('refused' in input) {
      const detail = 'sent back without a sign-in';
      return Promise.reject(
        this.refusedStepUp === undefined
          ? new SignInFailed(input.refused, detail)
          : new StepUpFailed(input.refused, detail, undefined, this.refusedStepUp),
      );
    }
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
    return Promise.resolve(cookie === undefined ? undefined : SUBJECT);
  }

  signedIn(cookie: string) {
    this.looked.push(cookie);
    if (this.lookupFails !== undefined) return Promise.reject(this.lookupFails);
    return Promise.resolve(this.live.get(cookie));
  }

  holderOf(cookie: string) {
    return Promise.resolve(this.live.get(cookie)?.userId);
  }
}

const servers: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function server(
  signIn: SignIn | undefined,
  options: {
    perAddress?: number;
    perUser?: number;
    loginSessions?: LoginSessions;
    findMembership?: FindMembership;
    growthBrake?: { engaged(): Promise<boolean> };
  } = {},
) {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: options.perAddress ?? 100,
      rateLimitPerUserPerMinute: options.perUser ?? 100,
      rateLimitPerAgentPerMinute: options.perUser ?? 100,
      rateLimitPerOrganisationPerMinute: 100_000,
      webCopies: 1,
      mcpOauth: false,
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
    signIn:
      signIn === undefined
        ? undefined
        : {
            service: signIn,
            sessionSeconds: SESSION_SECONDS,
            loginSessions: options.loginSessions,
            growthBrake: options.growthBrake,
          },
    securityEvents: { note: (event) => noted.push(event) },
    findMembership: options.findMembership,
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
  ])('refuses a sign-in as SIGN_IN_FAILED when %s, its flow taken, no cookie set', async (_, query, failure) => {
    const standIn = new StandIn();
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject({
      ...callback(query, `${FLOW_COOKIE}=${FLOW_ID}`),
      remoteAddress: '203.0.113.9',
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(errorBody('SIGN_IN_FAILED', response.headers['x-correlation-id'] as string));
    expect(response.headers['set-cookie']).toBeUndefined();
    // Only the flow is asked for, with why: no code or state is ever passed on.
    expect(standIn.completed).toEqual([{ flowId: FLOW_ID, previousCookie: undefined, refused: failure }]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.sign_in_failed', failure }));
    expect(noted).toEqual([{ kind: 'sign_in_failed', reason: failure, ip: '203.0.113.9' }]);
  });

  it('E6-P1 sends a way back that finds no flow waiting home, saying it came back late, not a bare error', async () => {
    const standIn = new StandIn();
    standIn.failWith = new SignInFailed('flow_missing', 'no flow of ours is waiting for this browser');
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject({
      ...callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
      remoteAddress: '203.0.113.9',
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/?signInLate=1');
    // The flow cookie cleared, the session's left alone: a signed-in person stays signed in.
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.sign_in_failed', failure: 'flow_missing', level: 'warn' }),
    );
    expect(noted).toEqual([{ kind: 'sign_in_failed', reason: 'flow_missing', ip: '203.0.113.9' }]);
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

  it('B4-6c refuses the login service’s break-glass admin as SIGN_IN_FAILED, with no cookie, noted as break_glass', async () => {
    const standIn = new StandIn();
    standIn.failWith = new SignInFailed('break_glass', "the login is the login service's break-glass admin");
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject({
      ...callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`),
      remoteAddress: '203.0.113.9',
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: { code: 'SIGN_IN_FAILED' } });
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(noted).toEqual([{ kind: 'sign_in_failed', reason: 'break_glass', ip: '203.0.113.9' }]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.sign_in_failed', failure: 'break_glass' }),
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

  it.each([
    ['203.0.113.7', '203.0.113.7'],
    ['2001:db8:1:2:3:4:5:6', clientSite('2001:db8:1::')],
  ])(
    'SEC-HA-14 S206 V8 begins a sign-in from %s as from its network, as the OAuth flows count one',
    async (address, network) => {
      const standIn = new StandIn();
      const { app } = await server(standIn);

      expect((await app.inject({ url: '/v1/auth/sign-in', remoteAddress: address })).statusCode).toBe(302);
      expect(standIn.networks).toEqual([network]);
    },
  );

  it.each([['every network’s', 'full', 'auth.sign_ins_capped', MOST_OPEN_SIGN_INS]] as const)(
    'SEC-HA-14 S206 V8 answers a sign-in past %s cap SIGN_IN_UNAVAILABLE, 503 and Retry-After, its warning once a minute',
    async (_what, cap, event, most) => {
      const standIn = new StandIn();
      standIn.beginFailsWith = new SignInBusy(cap);
      const { app, capture, noted } = await server(standIn);

      for (let sent = 0; sent < 3; sent += 1) {
        const response = await app.inject('/v1/auth/sign-in');
        expect(response.statusCode).toBe(503);
        expect(response.json()).toEqual(
          errorBody('SIGN_IN_UNAVAILABLE', response.headers['x-correlation-id'] as string),
        );
        expect(response.headers['retry-after']).toBe('15');
        expect(response.headers['set-cookie']).toBeUndefined();
      }
      expect(noted).toEqual([]);
      // A flood is a line a minute, never one a request: the first refusal said at once, the rest counted for later.
      expect(capture.lines().filter((line) => line.event === event)).toEqual([
        expect.objectContaining({ level: 'warn', most, refused: 1 }),
      ]);
      expect(capture.lines().map((line) => line.event)).not.toContain('auth.sign_in_unavailable');
    },
  );

  it('SEC-HA-14 S208 starts a sign-in past its network’s share as any other, its oldest giving way, warned once a minute', async () => {
    const standIn = new StandIn();
    standIn.gaveWay = true;
    const { app, capture, noted } = await server(standIn);

    for (let sent = 0; sent < 3; sent += 1) {
      const response = await app.inject({ url: '/v1/auth/sign-in', remoteAddress: '203.0.113.7' });
      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toBe(LOGIN_URL);
      expect(setCookies(response.headers['set-cookie'])).toEqual([
        `${FLOW_COOKIE}=${FLOW_ID}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`,
      ]);
    }
    expect(noted).toEqual([]);
    // One caller filling its network's share never refuses the next: a line a minute says the oldest gave way.
    expect(capture.lines().filter((line) => line.event === 'auth.sign_ins_gave_way')).toEqual([
      expect.objectContaining({ level: 'warn', most: MOST_OPEN_SIGN_INS_A_NETWORK, started: 1 }),
    ]);
    expect(capture.lines().map((line) => line.event)).not.toContain('auth.sign_ins_capped');
  });

  describe('SEC-HA-14 TR-17 sign-ins started, held to their own limit per network, as their open flows are counted', () => {
    const start = (remoteAddress: string) => ({ url: '/v1/auth/sign-in', remoteAddress });

    it.each([
      // Each IPv4 address on its own: the next one along is another.
      ['an IPv4 address', () => '203.0.113.7', '203.0.113.7', '203.0.113.8'],
      // One /48 counts as one network, as its open flows are counted: starts from many /64s in it are one count.
      [
        'an IPv6 /48',
        (n: number) => `2001:db8:1:${n.toString(16)}::1`,
        '2001:db8:1:ffff:ffff:ffff:ffff:ffff',
        '2001:db8:2::1',
      ],
    ])(
      'refuses %s past them RATE_LIMITED, 429 with Retry-After, beginning nothing; another address goes on',
      async (_what, address, sameOne, another) => {
        const standIn = new StandIn();
        const { app, noted } = await server(standIn);

        for (let n = 1; n <= SIGN_IN_STARTS.most; n += 1) {
          expect((await app.inject(start(address(n)))).statusCode).toBe(302);
        }
        const refused = await app.inject(start(sameOne));

        expect(refused.statusCode).toBe(429);
        expect(refused.json()).toEqual(errorBody('RATE_LIMITED', refused.headers['x-correlation-id'] as string));
        expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
        expect(refused.headers).toMatchObject({ 'x-ratelimit-limit': String(SIGN_IN_STARTS.most) });
        expect(refused.headers['set-cookie']).toBeUndefined();
        expect(standIn.begun).toHaveLength(SIGN_IN_STARTS.most);
        expect(noted).toEqual([]);
        expect((await app.inject(start(another))).statusCode).toBe(302);
        expect(standIn.begun).toHaveLength(SIGN_IN_STARTS.most + 1);
      },
    );

    it('leaves the address’s other routes alone: its callbacks still come back', async () => {
      const standIn = new StandIn();
      const { app } = await server(standIn);
      for (let n = 0; n <= SIGN_IN_STARTS.most; n += 1) await app.inject(start('203.0.113.7'));

      const back = await app.inject({
        ...callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`),
        remoteAddress: '203.0.113.7',
      });

      expect(back.statusCode).toBe(302);
      expect(back.headers.location).toBe('/agents');
    });
  });

  it('warns of no network giving way when none did', async () => {
    const standIn = new StandIn();
    const { app, capture } = await server(standIn);

    expect((await app.inject('/v1/auth/sign-in')).statusCode).toBe(302);
    expect(capture.lines().map((line) => line.event)).not.toContain('auth.sign_ins_gave_way');
  });

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

    // B7: 200 with the empty object its document promises, as JSON, never a bare 204.
    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(response.json()).toEqual({});
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`,
    ]);
    expect(standIn.signedOut).toEqual([SESSION_ID]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.signed_out' }));
  });

  it('answers the same with no session to end', async () => {
    const standIn = new StandIn();
    const { app, capture } = await server(standIn);

    const response = await app.inject({ method: 'POST', url: '/v1/auth/sign-out', headers: { origin: PUBLIC_ORIGIN } });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({});
    expect(standIn.signedOut).toEqual([undefined]);
    // Nothing ended, so nothing said ended.
    expect(capture.lines().some((line) => line.event === 'auth.signed_out')).toBe(false);
  });

  /** A stand-in for the login service's sessions: each person asked, and its answer. */
  const loginSessions = (answer: () => Promise<number>) => {
    const asked: Subject[] = [];
    return {
      asked,
      endAll: (who: Subject) => {
        asked.push(who);
        return answer();
      },
    };
  };
  const signOut = { method: 'POST' as const, url: '/v1/auth/sign-out' };
  const withSession = { origin: PUBLIC_ORIGIN, cookie: `${SESSION_COOKIE}=${SESSION_ID}` };

  it("ends the person's sessions at the login service too (Shannon AUTH-VULN-01)", async () => {
    const ending = loginSessions(() => Promise.resolve(3));
    const { app, capture } = await server(new StandIn(), { loginSessions: ending });

    const response = await app.inject({ ...signOut, headers: withSession });

    expect(response.statusCode).toBe(200);
    expect(ending.asked).toEqual([SUBJECT]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.login_service_signed_out', ended: 3 }),
    );
  });

  it('stands though the login service fails: our session ended, the cookie cleared, the failure logged', async () => {
    const ending = loginSessions(() =>
      Promise.reject(new LoginSessionsUnavailable('reading the sessions: it answered 500')),
    );
    const { app, capture } = await server(new StandIn(), { loginSessions: ending });

    const response = await app.inject({ ...signOut, headers: withSession });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({});
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`,
    ]);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({
        event: 'auth.login_service_sign_out_failed',
        level: 'error',
        err: expect.objectContaining({
          type: 'LoginSessionsUnavailable',
          message: 'reading the sessions: it answered 500',
        }) as unknown,
      }),
    );
  });

  it('asks the login service nothing with no session to end', async () => {
    const ending = loginSessions(() => Promise.resolve(0));
    const { app } = await server(new StandIn(), { loginSessions: ending });

    await app.inject({ ...signOut, headers: { origin: PUBLIC_ORIGIN } });

    expect(ending.asked).toEqual([]);
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

    expect(noted).toEqual([
      { kind: 'rate_limited', reason: 'per_user', ip: '203.0.113.9', userId: USER_ID, orgId: null },
    ]);
  });

  describe("ties a refusal to an organisation only once the person's membership there is found active (CO7b)", () => {
    const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
    const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000abce';
    /** An admin's route, naming an organisation: the person is an active member of ORG alone, a deactivated one of OTHER_ORG. */
    async function member() {
      const standIn = new StandIn();
      standIn.live.set(SESSION_ID, LIVE);
      return server(standIn, {
        perAddress: 100,
        perUser: 2,
        findMembership: (orgId) =>
          Promise.resolve(
            orgId.toLowerCase() === ORG
              ? { outcome: 'active', id: '0199a0f0-0000-7000-8000-0000000000c1', role: 'admin' }
              : orgId.toLowerCase() === OTHER_ORG
                ? { outcome: 'deactivated', id: '0199a0f0-0000-7000-8000-0000000000c2' }
                : { outcome: 'none' },
          ),
      });
    }
    const asking = (orgId: string, url = '/v1/access-log') => ({
      url,
      headers: { cookie: `${SESSION_COOKIE}=${SESSION_ID}`, [ORGANIZATION_HEADER]: orgId.toUpperCase() },
      remoteAddress: '203.0.113.9',
    });

    it.each([
      ['an organisation they are an active member of, by its ID in lower case', ORG, ORG],
      ['an organisation they are not active in: none', OTHER_ORG, null],
      ['an organisation they are not in at all: none', '0199a0f0-0000-7000-8000-00000000abcf', null],
    ])('on %s', async (_what, orgId, tied) => {
      const { app, noted } = await member();
      for (let i = 0; i < 2; i += 1) await app.inject(asking(orgId));
      const refused = await app.inject(asking(orgId));

      expect(refused.statusCode).toBe(429);
      expect(noted).toEqual([
        { kind: 'rate_limited', reason: 'per_user', ip: '203.0.113.9', userId: USER_ID, orgId: tied },
      ]);
    });

    it("on a person's own route, though the request names an organisation: none", async () => {
      const { app, noted } = await member();
      for (let i = 0; i < 3; i += 1) await app.inject(asking(ORG, '/v1/auth/session'));

      expect(noted).toEqual([
        { kind: 'rate_limited', reason: 'per_user', ip: '203.0.113.9', userId: USER_ID, orgId: null },
      ]);
    });
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
      `${FLOW_COOKIE}=${FLOW_ID}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=900`,
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

  it('E6-P4 sends a step-up whose challenge ran out before it began back to its page, saying the time ran out', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    standIn.beginFailsWith = new StepUpFailed('challenge_expired', 'test');
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject(starting(`?challenge=${CHALLENGE}&returnTo=/members/confirm`));
    const home = await app.inject(starting(`?challenge=${CHALLENGE}`));

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`/members/confirm?stepUpFailed=${CHALLENGE}&stepUpWhy=expired`);
    expect(home.headers.location).toBe(`/?stepUpFailed=${CHALLENGE}&stepUpWhy=expired`);
    expect(noted).toContainEqual({
      kind: 'sign_in_failed',
      reason: 'step_up_challenge_expired',
      ip: '127.0.0.1',
      userId: USER_ID,
    });
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.step_up_failed', failure: 'challenge_expired', userId: USER_ID }),
    );
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

  it('notes a failed step-up tied to no organisation, though the request names one the person is active in (CO7b)', async () => {
    const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    standIn.beginFailsWith = new StepUpFailed('challenge_missing', 'test');
    const { app, noted } = await server(standIn, {
      findMembership: () =>
        Promise.resolve({ outcome: 'active', id: '0199a0f0-0000-7000-8000-0000000000c1', role: 'admin' }),
    });
    const request = starting(`?challenge=${CHALLENGE}`);

    const response = await app.inject({ ...request, headers: { ...request.headers, [ORGANIZATION_HEADER]: ORG } });

    expect(response.statusCode).toBe(403);
    expect(noted).toEqual([
      { kind: 'sign_in_failed', reason: 'step_up_challenge_missing', ip: '127.0.0.1', userId: USER_ID },
    ]);
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
    'refuses a step-up back with %s, sending the browser back to its page to say so (CO2), the session cookie left',
    async (_what, failure, userId) => {
      const standIn = new StandIn();
      // The page's own query stays (CO5); `?stepped=`, which would offer the change to confirm, is dropped.
      const back = { returnTo: `/approvals/abc?org=o-1&stepped=${CHALLENGE}`, challengeId: CHALLENGE };
      standIn.failWith = new StepUpFailed(failure, 'test', userId, back);
      const { app, noted, capture } = await server(standIn);

      const response = await app.inject(
        callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
      );

      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toBe(`/approvals/abc?org=o-1&stepUpFailed=${CHALLENGE}`);
      expect(setCookies(response.headers['set-cookie'])).toEqual([
        `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
      ]);
      expect(capture.lines()).toContainEqual(
        expect.objectContaining({
          event: 'auth.step_up_failed',
          failure,
          correlationId: expect.any(String) as unknown,
        }),
      );
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

  it.each([
    ['cancelled or refused at the login service', '?error=access_denied&state=a-state', 'provider_refused'],
    ['back with no code', '?state=a-state', 'callback_incomplete'],
  ] as const)(
    'sends a step-up %s back to its page to say so (CO2), the flow cookie cleared, the session left',
    async (_what, query, failure) => {
      const standIn = new StandIn();
      // A way back with no query at all (made by hand: the console's always holds `?stepped=`) gets the challenge alone.
      standIn.refusedStepUp = { returnTo: '/approvals/abc', challengeId: CHALLENGE };
      const { app, noted, capture } = await server(standIn);

      const response = await app.inject({
        ...callback(query, `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
        remoteAddress: '203.0.113.9',
      });

      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toBe(`/approvals/abc?stepUpFailed=${CHALLENGE}`);
      expect(setCookies(response.headers['set-cookie'])).toEqual([
        `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
      ]);
      expect(standIn.completed).toEqual([{ flowId: FLOW_ID, previousCookie: SESSION_ID, refused: failure }]);
      expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.step_up_failed', failure }));
      expect(noted).toEqual([{ kind: 'sign_in_failed', reason: `step_up_${failure}`, ip: '203.0.113.9' }]);
    },
  );

  it('SEC-HA-04 TR-18 sends a step-up back whose flow was not started for its challenge (its nonce not the challenge’s) to its page, failed', async () => {
    const standIn = new StandIn();
    const back = { returnTo: `/approvals/abc?stepped=${CHALLENGE}`, challengeId: CHALLENGE };
    standIn.failWith = new StepUpFailed(
      'challenge_missing',
      'the flow was not started for this challenge',
      USER_ID,
      back,
    );
    const { app, noted, capture } = await server(standIn);

    const response = await app.inject(
      callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
    );

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`/approvals/abc?stepUpFailed=${CHALLENGE}`);
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    expect(capture.lines().some((line) => line.event === 'auth.stepped_up')).toBe(false);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.step_up_failed', failure: 'challenge_missing', userId: USER_ID }),
    );
    expect(noted).toEqual([
      { kind: 'sign_in_failed', reason: 'step_up_challenge_missing', ip: '127.0.0.1', userId: USER_ID },
    ]);
  });

  it('E6-P2 sends a step-up whose ten minutes ran out back to its page, failed and saying so, logged as expired', async () => {
    const standIn = new StandIn();
    standIn.failWith = new StepUpFailed('challenge_expired', 'test', USER_ID, {
      returnTo: `/approvals/abc?stepped=${CHALLENGE}&stepUpWhy=spent`,
      challengeId: CHALLENGE,
    });
    const { app, noted, capture } = await server(standIn);

    const response = await app.inject(
      callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
    );

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`/approvals/abc?stepUpFailed=${CHALLENGE}&stepUpWhy=expired`);
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'auth.step_up_failed', failure: 'challenge_expired', userId: USER_ID }),
    );
    expect(noted).toEqual([
      { kind: 'sign_in_failed', reason: 'step_up_challenge_expired', ip: '127.0.0.1', userId: USER_ID },
    ]);
  });

  it('answers a step-up failure that names no page to go back to as STEP_UP_FAILED, leaving the cookies', async () => {
    const standIn = new StandIn();
    standIn.failWith = new StepUpFailed('challenge_missing', 'test', USER_ID);
    const { app } = await server(standIn);

    const response = await app.inject(
      callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`),
    );

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('STEP_UP_FAILED', response.headers['x-correlation-id'] as string));
    expect(response.headers['set-cookie']).toBeUndefined();
  });
});

describe("SEC-LIM-13 S210 TR-7 a person's day's sessions and step-ups", () => {
  const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c2';
  const coming = () =>
    callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`);

  it('refuses a sign-in past the day’s sessions as RATE_LIMITED, 429 with Retry-After, the flow cookie cleared, warned once a minute; sign-out still works', async () => {
    const standIn = new StandIn();
    standIn.failWith = new SessionsSpent(USER_ID);
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject(coming());

    expect(response.statusCode).toBe(429);
    expect(response.json()).toEqual(errorBody('RATE_LIMITED', response.headers['x-correlation-id'] as string));
    expect(response.headers['retry-after']).toBe('3600');
    // No new session cookie: the one the browser holds is left as it is.
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    await app.inject(coming());
    // Said once a minute a person, naming them by Agent X's own ID: another person's refusal is a line of its own.
    standIn.failWith = new SessionsSpent(OTHER_USER);
    await app.inject(coming());
    expect(capture.lines().filter((line) => line.event === 'auth.person_sessions_spent')).toEqual([
      expect.objectContaining({ level: 'warn', most: MOST_SESSIONS_A_DAY, userId: USER_ID, refused: 1 }),
      expect.objectContaining({ level: 'warn', most: MOST_SESSIONS_A_DAY, userId: OTHER_USER, refused: 1 }),
    ]);
    // Nothing about the sign-in was wrong: no failed sign-in noted or logged.
    expect(noted).toEqual([]);
    expect(capture.lines().map((line) => line.event)).not.toContain('auth.sign_in_failed');
    // A sign-out is never refused.
    const out = await app.inject({
      method: 'POST',
      url: '/v1/auth/sign-out',
      headers: { cookie: `${SESSION_COOKIE}=${SESSION_ID}`, origin: PUBLIC_ORIGIN },
    });
    expect(out.statusCode).toBe(200);
    expect(standIn.signedOut).toEqual([SESSION_ID]);
  });

  it('refuses a step-up past the day’s step-ups at its start as STEP_UPS_SPENT, 429 with Retry-After, warned once a minute, no security event', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    standIn.beginFailsWith = new StepUpFailed('step_ups_spent', 'test', USER_ID);
    const { app, capture, noted } = await server(standIn);
    const starting = {
      url: `/v1/auth/step-up?challenge=${CHALLENGE}`,
      headers: { cookie: `${SESSION_COOKIE}=${SESSION_ID}` },
    };

    const response = await app.inject(starting);

    expect(response.statusCode).toBe(429);
    expect(response.json()).toEqual(errorBody('STEP_UPS_SPENT', response.headers['x-correlation-id'] as string));
    expect(response.headers['retry-after']).toBe('3600');
    expect(response.headers['set-cookie']).toBeUndefined();
    await app.inject(starting);
    expect(capture.lines().filter((line) => line.event === 'auth.person_step_ups_spent')).toEqual([
      expect.objectContaining({ level: 'warn', most: MOST_STEP_UPS_A_DAY, userId: USER_ID, refused: 1 }),
    ]);
    expect(capture.lines().map((line) => line.event)).not.toContain('auth.step_up_failed');
    expect(noted).toEqual([]);
  });

  it('sends a step-up refused past the day’s step-ups as it comes back to its page, failed and saying why', async () => {
    const standIn = new StandIn();
    standIn.failWith = new StepUpFailed('step_ups_spent', 'test', USER_ID, {
      returnTo: `/members/confirm?stepped=${CHALLENGE}&stepUpWhy=other`,
      challengeId: CHALLENGE,
    });
    const { app, capture, noted } = await server(standIn);

    const response = await app.inject(coming());

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`/members/confirm?stepUpFailed=${CHALLENGE}&stepUpWhy=spent`);
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    expect(capture.lines().filter((line) => line.event === 'auth.person_step_ups_spent')).toHaveLength(1);
    expect(noted).toEqual([]);
  });

  it('says each person’s refusals once a minute with how many, never losing a count to another’s line', () => {
    const capture = new LogCapture();
    const clock = new FixedClock(new Date('2026-12-01T09:00:00Z'));
    const logger = createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
      destination: capture,
    });
    const refused = personCapWarning(logger, clock, 'auth.person_sessions_spent', { most: 2 });
    const said = () => capture.lines().map(({ userId, refused: count }) => ({ userId, refused: count }));
    refused(USER_ID);
    refused(USER_ID);
    refused(USER_ID);
    clock.advanceBy(60_000);
    // Another's line, a minute on, forgets no one with refusals still unsaid.
    refused(OTHER_USER);
    expect(said()).toEqual([
      { userId: USER_ID, refused: 1 },
      { userId: OTHER_USER, refused: 1 },
    ]);
    refused(USER_ID);
    expect(said().at(-1)).toEqual({ userId: USER_ID, refused: 3 });
    // Quiet for a minute with nothing unsaid, a person is forgotten: their next refusal starts a count of its own.
    clock.advanceBy(60_000);
    refused(OTHER_USER);
    refused(USER_ID);
    expect(said().slice(-2)).toEqual([
      { userId: OTHER_USER, refused: 1 },
      { userId: USER_ID, refused: 1 },
    ]);
  });
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

describe('SEC-LIM-13 S210 R2-4 the platform chain’s growth brake', () => {
  const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c3';
  /** A brake the test turns on and off, counting how often it was asked. */
  const brakeOf = () => {
    const brake = {
      on: true,
      asked: 0,
      engaged: () => {
        brake.asked += 1;
        return Promise.resolve(brake.on);
      },
    };
    return brake;
  };
  const signingIn = { url: '/v1/auth/sign-in' };
  const coming = () =>
    callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}; ${SESSION_COOKIE}=${SESSION_ID}`);
  const steppingUp = {
    url: `/v1/auth/step-up?challenge=${CHALLENGE}`,
    headers: { cookie: `${SESSION_COOKIE}=${SESSION_ID}` },
  };
  const braked = (response: Awaited<ReturnType<FastifyInstance['inject']>>) => {
    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual(errorBody('SIGN_IN_UNAVAILABLE', response.headers['x-correlation-id'] as string));
    expect(response.headers['retry-after']).toBe('60');
    expect(setCookies(response.headers['set-cookie'])).toEqual([
      `${FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
  };

  it('refuses a sign-in and a step-up started while on, 503 with Retry-After, warned once a minute; a flow begun before completes, and a sign-out still works', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const brake = brakeOf();
    const { app, capture, noted } = await server(standIn, { growthBrake: brake });

    braked(await app.inject(signingIn));
    braked(await app.inject(steppingUp));

    // Nothing started: no flow begun, no step-up begun.
    expect(standIn.begun).toEqual([]);
    expect(standIn.steppedUp).toEqual([]);
    // A flow begun before the brake, back from the login service, completes: no one lands on an error there.
    const asking = brake.asked;
    const back = await app.inject(coming());
    expect(back.statusCode).toBe(302);
    expect(standIn.completed).toHaveLength(1);
    expect(brake.asked).toBe(asking);
    // Said once for the minute, with the brake's place; nothing about the sign-ins was wrong.
    expect(capture.lines().filter((line) => line.event === 'auth.platform_chain_braked')).toEqual([
      expect.objectContaining({ level: 'warn', most: PLATFORM_GROWTH_BRAKE, refused: 1 }),
    ]);
    expect(noted).toEqual([]);
    // A sign-out is never refused, nor asks the brake.
    const asked = brake.asked;
    const out = await app.inject({
      method: 'POST',
      url: '/v1/auth/sign-out',
      headers: { cookie: `${SESSION_COOKIE}=${SESSION_ID}`, origin: PUBLIC_ORIGIN },
    });
    expect(out.statusCode).toBe(200);
    expect(standIn.signedOut).toEqual([SESSION_ID]);
    expect(brake.asked).toBe(asked);
  });

  it('lets every one through as before once it is off', async () => {
    const standIn = new StandIn();
    standIn.live.set(SESSION_ID, LIVE);
    const brake = brakeOf();
    brake.on = false;
    const { app, capture } = await server(standIn, { growthBrake: brake });

    expect((await app.inject(signingIn)).statusCode).toBe(302);
    expect((await app.inject(coming())).statusCode).toBe(302);
    expect((await app.inject(steppingUp)).statusCode).toBe(302);
    expect(standIn.begun).toHaveLength(1);
    expect(standIn.completed).toHaveLength(1);
    expect(standIn.steppedUp).toHaveLength(1);
    expect(brake.asked).toBe(2);
    expect(capture.lines().map((line) => line.event)).not.toContain('auth.platform_chain_braked');
  });
});
