// 6A2, ADR-013: POST /v1/client-errors writes a console error to our own log
// with its plain words, for anyone on our origin: an error naming the person
// when signed in, a warning when not (partner, S150: no forged alert); refuses
// what isn't one (a foreign origin, a page with a query, an unknown field, a
// body over its cap); and cleans what it writes.
import type { SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { ANONYMOUS_BROWSER_ERROR, BROWSER_ERROR } from './browser-errors.ts';
import { liveSession, ONE_TIME_CODE } from './live-session.helper.test.ts';
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

const LIVE = liveSession('2026-09-24T09:00:00.000Z', { amr: ONE_TIME_CODE });

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

// S206 V8 (ADR-013, SEC-AV-09): anyone may send a report, so a flood of them is the cheapest way to try to fill the
// log's budget and hide something else. One address is held to its own rate limit; many addresses together fill only
// the anonymous report's own per-minute cap, counted exactly once the minute is over, and every other event still
// gets out: a signed-in person's report, the rate limit's own refusal line.
describe('POST /v1/client-errors under a flood of anonymous reports', () => {
  const PER_ADDRESS = 20;
  const CAP = 10;
  const MINUTE = 60_000;

  async function flooded() {
    const capture = new LogCapture();
    // The log's own clock, held still, so the whole flood is one of its minutes until the test moves it on.
    let now = Date.parse('2026-11-20T09:00:05.000Z');
    const config = {
      http: {
        host: '127.0.0.1',
        port: 0,
        publicOrigin: PUBLIC_ORIGIN,
        trustedProxies: [],
        rateLimitPerMinute: PER_ADDRESS,
        rateLimitPerUserPerMinute: 1000,
        rateLimitPerAgentPerMinute: 1000,
        rateLimitPerOrganisationPerMinute: 1000,
        webCopies: 1,
        mcpOauth: false,
      },
      log: { level: 'info' as const, eventCapPerMinute: CAP },
    };
    const logger = createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...config },
      destination: capture,
      now: () => now,
    });
    const app = await routeServer({ live: LIVE, logger, config });
    return {
      app,
      linesOf: (event: string) => capture.lines().filter((line) => line.event === event),
      nextMinute: () => {
        now += MINUTE;
      },
    };
  }

  const from = (address: string, cookie?: string) => ({
    ...post(REPORT, PUBLIC_ORIGIN, cookie),
    remoteAddress: address,
  });

  it('holds one address to its rate limit, and many to the anonymous report’s own cap, which hides no other event', async () => {
    const { app, linesOf, nextMinute } = await flooded();

    const oneAddress = [];
    for (let sent = 0; sent < PER_ADDRESS + 5; sent += 1) {
      oneAddress.push((await app.inject(from('203.0.113.7'))).statusCode);
    }
    expect(oneAddress).toEqual([...Array<number>(PER_ADDRESS).fill(202), ...Array<number>(5).fill(429)]);

    // Then as many again, each from an address of its own, every one under its limit: each answered as any other.
    const manyAddresses = await Promise.all(
      Array.from({ length: PER_ADDRESS }, (_, at) => app.inject(from(`198.51.100.${String(at + 1)}`))),
    );
    expect(manyAddresses.map(({ statusCode }) => statusCode)).toEqual(Array<number>(PER_ADDRESS).fill(202));

    // A signed-in person's report, from an address the flood never used, still gets out, as does the refusal's line.
    expect((await app.inject(from('192.0.2.44', signedIn))).statusCode).toBe(202);
    expect(linesOf(ANONYMOUS_BROWSER_ERROR)).toHaveLength(CAP);
    expect(linesOf(BROWSER_ERROR)).toEqual([expect.objectContaining({ level: 'error', actor: LIVE.userId })]);
    expect(linesOf('http.request_rate_limited').length).toBeGreaterThan(0);

    // Once the minute is over, what was held back is said with its exact count: the flood is seen, never silent.
    nextMinute();
    await app.inject(from('192.0.2.45'));
    expect(linesOf('log.suppressed')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ suppressedEvent: ANONYMOUS_BROWSER_ERROR, suppressedCount: 2 * PER_ADDRESS - CAP }),
      ]),
    );
    expect(linesOf('log.suppressed').map(({ suppressedEvent }) => suppressedEvent)).not.toContain(BROWSER_ERROR);
  });
});
