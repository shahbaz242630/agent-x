// B2-3a-2: the sign-in routes over HTTP, with a stand-in sign-in (the real
// one: the identity module's sign-in-flow.db.test.ts).
import { type CallbackInput, type SignIn, SignInFailed } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { errorBody } from './errors.ts';
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

/** The stand-in: what each route asked of it, and what it answers. */
class StandIn implements SignIn {
  begun: (string | undefined)[] = [];
  completed: CallbackInput[] = [];
  signedOut: (string | undefined)[] = [];
  failWith: Error | undefined;

  begin(returnTo?: string) {
    this.begun.push(returnTo);
    return Promise.resolve({ url: LOGIN_URL, flowId: FLOW_ID });
  }

  complete(input: CallbackInput) {
    this.completed.push(input);
    if (this.failWith !== undefined) return Promise.reject(this.failWith);
    return Promise.resolve({ userId: USER_ID, sessionId: RECORD_ID, cookie: NEW_SESSION, returnTo: '/agents' });
  }

  signOut(cookie: string | undefined) {
    this.signedOut.push(cookie);
    return Promise.resolve(cookie !== undefined);
  }
}

const servers: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function server(signIn: SignIn | undefined) {
  const config = {
    http: { host: '127.0.0.1', port: 0, publicOrigin: PUBLIC_ORIGIN, trustedProxies: [], rateLimitPerMinute: 100 },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: capture,
  });
  const app = await buildServer({
    config,
    logger,
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: signIn === undefined ? undefined : { service: signIn, sessionSeconds: SESSION_SECONDS },
  });
  servers.push(app);
  return { app, capture };
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
    const { app, capture } = await server(standIn);

    const response = await app.inject(callback(query, `${FLOW_COOKIE}=${FLOW_ID}`));

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual(errorBody('SIGN_IN_FAILED', response.headers['x-correlation-id'] as string));
    expect(standIn.completed).toEqual([]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'auth.sign_in_failed', failure }));
  });

  it('refuses as SIGN_IN_FAILED when the sign-in fails, setting no cookie, and logs which step failed', async () => {
    const standIn = new StandIn();
    standIn.failWith = new SignInFailed('token_invalid', 'the ID token failed its check: ERR_JWT_EXPIRED');
    const { app, capture } = await server(standIn);

    const response = await app.inject(callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`));

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
    const { app } = await server(standIn);

    const response = await app.inject(callback('?code=a-code&state=a-state', `${FLOW_COOKIE}=${FLOW_ID}`));

    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR' } });
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
