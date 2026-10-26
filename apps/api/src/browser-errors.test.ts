// 6A2, ADR-013: POST /v1/client-errors writes a console error to our own log
// with its plain words, for anyone on our origin: an error naming the person
// when signed in, a warning when not (partner, S150: no forged alert); refuses
// what isn't one (a foreign origin, a page with a query, an unknown field, a
// body over its cap); and cleans what it writes.
import type { LiveSession, SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { ANONYMOUS_BROWSER_ERROR, BROWSER_ERROR } from './browser-errors.ts';
import { closeServers, COOKIE, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

afterEach(closeServers);

const REPORT = {
  kind: 'error',
  message: "Cannot read properties of undefined (reading 'id')",
  page: '/approvals',
  stack: 'TypeError: …\n    at Approvals (/assets/index-3f2a.js:1:2345)',
  build: 'ade7f27d',
};

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: ['pwd', 'otp', 'mfa'],
  createdAt: new Date('2026-09-24T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-24T09:10:00.000Z'),
  endsAt: new Date('2026-09-24T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-24T09:40:00.000Z'),
};

/** A sign-in whose session lookup fails: the database down, say. */
const UNREADABLE_SESSIONS: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(undefined),
  signedIn: () => Promise.reject(new Error('not in these tests')),
  holderOf: () => Promise.reject(new Error('the database is down')),
};

async function withCapture(options: { readonly sessions?: SignIn } = {}) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
    destination: capture,
  });
  const app = await routeServer({
    live: LIVE,
    logger,
    ...(options.sessions !== undefined && { signIn: { service: options.sessions, sessionSeconds: 43_200 } }),
  });
  const sent = capture.lines.bind(capture);
  return {
    app,
    logged: () => sent().filter((line) => line.event === BROWSER_ERROR || line.event === ANONYMOUS_BROWSER_ERROR),
  };
}

const post = (body: unknown, origin: string = PUBLIC_ORIGIN, cookie?: string) => ({
  method: 'POST' as const,
  url: '/v1/client-errors',
  headers: { origin, 'content-type': 'application/json', ...(cookie !== undefined && { cookie }) },
  payload: JSON.stringify(body),
});
const signedIn = `${SESSION_COOKIE}=${COOKIE}`;

describe('POST /v1/client-errors', () => {
  it('logs a report as a warning with its plain words, with no one signed in', async () => {
    const { app, logged } = await withCapture();

    const response = await app.inject(post(REPORT));

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({});
    expect(logged()).toEqual([
      expect.objectContaining({
        level: 'warn',
        event: ANONYMOUS_BROWSER_ERROR,
        correlationId: expect.any(String) as unknown,
        says: expect.stringContaining('The console failed') as unknown,
        ...REPORT,
      }),
    ]);
  });

  it('logs a signed-in person’s report as an error naming them, which the error alert counts', async () => {
    const { app, logged } = await withCapture();

    const response = await app.inject(post(REPORT, PUBLIC_ORIGIN, signedIn));

    expect(response.statusCode).toBe(202);
    expect(logged()).toEqual([
      expect.objectContaining({
        level: 'error',
        event: BROWSER_ERROR,
        actor: LIVE.userId,
        says: expect.any(String) as unknown,
        ...REPORT,
      }),
    ]);
  });

  it.each([
    ['a cookie naming no live session', `${SESSION_COOKIE}=${'X'.repeat(43)}`, {}],
    ['a session that can’t be read just now', signedIn, { sessions: UNREADABLE_SESSIONS }],
  ])('logs a report with %s as no one’s warning, taken all the same', async (_what, cookie, options) => {
    const { app, logged } = await withCapture(options);

    const response = await app.inject(post(REPORT, PUBLIC_ORIGIN, cookie));

    expect(response.statusCode).toBe(202);
    expect(logged()).toEqual([expect.objectContaining({ level: 'warn', event: ANONYMOUS_BROWSER_ERROR, ...REPORT })]);
    expect(logged()[0]).not.toHaveProperty('actor');
  });

  it('cleans what it writes: an email in the message is not kept', async () => {
    const { app, logged } = await withCapture();

    await app.inject(post({ kind: 'rejection', message: 'no account for amira@example.com', page: '/' }));

    expect(logged()).toEqual([expect.objectContaining({ message: 'no account for [email]' })]);
  });

  it.each([
    ['a page with a query', { ...REPORT, page: '/approvals?token=abc' }],
    ['a page that is an API address', { ...REPORT, page: '/v1/statements' }],
    ['an unknown kind', { ...REPORT, kind: 'warning' }],
    ['an empty message', { ...REPORT, message: '' }],
    ['a message over 500 characters', { ...REPORT, message: 'x'.repeat(501) }],
    ['a field of its own', { ...REPORT, user: 'amira' }],
  ])('refuses %s, writing nothing', async (_what, body) => {
    const { app, logged } = await withCapture();

    const response = await app.inject(post(body));

    expect(response.statusCode).toBe(400);
    expect(logged()).toEqual([]);
  });

  it('refuses a body over its cap, writing nothing', async () => {
    const { app, logged } = await withCapture();

    const response = await app.inject(post({ ...REPORT, stack: 'x'.repeat(9000) }));

    expect(response.statusCode).toBe(413);
    expect(logged()).toEqual([]);
  });

  it('refuses a report from another origin (SEC-WEB-01), writing nothing', async () => {
    const { app, logged } = await withCapture();

    const response = await app.inject(post(REPORT, 'https://elsewhere.example'));

    expect(response.statusCode).toBe(403);
    expect(logged()).toEqual([]);
  });
});
