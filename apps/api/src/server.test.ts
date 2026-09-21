import type { Config } from '@agentx/platform/config';
import { createLogger, type Logger } from '@agentx/platform/observability';
import { findLeaks, LogCapture, SENSITIVE_SAMPLES as SAMPLES, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { CORRELATION_HEADER } from './correlation.ts';
import { errorBody } from './errors.ts';
import { FRAMEWORK_EVENT } from './framework-logger.ts';
import { CHECK_FAILED, type HealthCheck } from './health.ts';
import { REQUEST_COMPLETED, REQUEST_FAILED, REQUEST_RATE_LIMITED } from './request-log.ts';
import { SECURITY_HEADERS } from './security-headers.ts';
import { buildServer } from './server.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
/** A marker value that must never come out. Plain words, so secret scanners ignore it. */
const PLANTED = 'planted value that must not appear';
/** The first IDs SequentialIds hands out, for requests that bring no usable correlation ID. */
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const SECOND_ID = '00000000-0000-7000-8000-000000000002';
/**
 * Test routes are open to anyone, read at most 1 KiB and answer `{ ok: true }`
 * (or a string, sent as it is): none of that is what these tests are about.
 */
const OPEN = {
  config: { access: ['public'] },
  bodyLimit: 1024,
  schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
} as const;

const HTTP: Config['http'] = {
  host: '127.0.0.1',
  port: 0,
  publicOrigin: PUBLIC_ORIGIN,
  trustedProxies: [],
  rateLimitPerMinute: 100,
};
const LOG: Config['log'] = { level: 'debug', eventCapPerMinute: 10_000 };

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface SetupOptions {
  readonly http?: Partial<Config['http']>;
  readonly log?: Partial<Config['log']>;
  readonly healthChecks?: readonly HealthCheck[];
  /** Wraps the logger the server gets, to make part of it fail. */
  readonly wrapLogger?: (logger: Logger) => Logger;
}

/** A server with a few routes that exist only in these tests, to reach the paths real routes will take. */
async function setup(options: SetupOptions = {}) {
  const capture = new LogCapture();
  const config = { http: { ...HTTP, ...options.http }, log: { ...LOG, ...options.log } };
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: capture,
    // A fixed clock, so the log's per-minute caps never reset in the middle of a test.
    now: () => Date.UTC(2026, 8, 14, 10, 0, 0),
  });
  const app = await buildServer({
    config,
    logger: options.wrapLogger?.(logger) ?? logger,
    ids: new SequentialIds(),
    healthChecks: options.healthChecks ?? [],
  });
  const reached: string[] = [];
  app.post('/test/write', OPEN, () => {
    reached.push('write');
    return { ok: true };
  });
  app.post('/test/body', { ...OPEN, schema: { response: { 200: z.object({ received: z.string() }) } } }, (request) => {
    reached.push('body');
    return { received: typeof request.body };
  });
  app.get('/test/fail', OPEN, () => {
    throw new Error(`database said: password rejected for ${SAMPLES.email}`);
  });
  // A route bug a later route could have: it replies twice.
  app.get('/test/items/:ref', OPEN, (_request, reply) => {
    void reply.send({ ok: true });
    void reply.send({ ok: true });
  });
  // A route with its own, lower limit, as Phase 1's per-agent limits will have.
  app.get('/test/limited', { ...OPEN, config: { ...OPEN.config, rateLimit: { max: 2, timeWindow: 60_000 } } }, () => ({
    ok: true,
  }));
  app.get('/test/ip', { ...OPEN, schema: { response: { 200: z.object({ ip: z.string() }) } } }, (request) => ({
    ip: request.ip,
  }));
  // A route that puts caller input in a header, which Node refuses when it holds a control character.
  app.get('/test/header', OPEN, (request, reply) => {
    void reply.header('x-note', (request.query as { note?: string }).note);
    return { ok: true };
  });
  servers.push(app);
  await app.ready();
  return { app, reached, capture, lines: () => capture.lines() };
}

const events = (lines: readonly Record<string, unknown>[], event: string) =>
  lines.filter((line) => line.event === event);

/** Written out here, not taken from SECURITY_HEADERS, so a header dropped from that list fails the tests. */
const EXPECTED_HEADERS = {
  'content-security-policy':
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

function expectSecurityHeaders(response: LightMyRequestResponse): void {
  expect(response.headers).toMatchObject(EXPECTED_HEADERS);
  expect(response.headers[CORRELATION_HEADER]).toMatch(/^[0-9a-f-]{36}$/);
}

describe('SEC-WEB-02 every response carries the security headers', () => {
  it.each([
    ['a health check', { method: 'GET', url: '/health' }, 200],
    ['an unknown address', { method: 'GET', url: '/nothing-here' }, 404],
    ['a refused write', { method: 'POST', url: '/test/write' }, 403],
    ['a failure on our side', { method: 'GET', url: '/test/fail' }, 500],
    [
      'a malformed body',
      {
        method: 'POST',
        url: '/test/body',
        headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
        payload: '{',
      },
      400,
    ],
    ['a malformed address', { method: 'GET', url: '/%zz' }, 400],
  ] as const)('on %s', async (_what, request, status) => {
    const { app } = await setup();
    const response = await app.inject(request);
    expect(response.statusCode).toBe(status);
    expectSecurityHeaders(response);
  });

  it('on a rate-limited request', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10 } });
    for (let i = 0; i < 10; i += 1) await app.inject('/health');
    const response = await app.inject('/health');
    expect(response.statusCode).toBe(429);
    expectSecurityHeaders(response);
  });

  it('keeps the header list and this test in step, so a header added to one is added to the other', () => {
    expect(SECURITY_HEADERS).toEqual(EXPECTED_HEADERS);
  });
});

describe('SEC-WEB-01 a request that can change something must come from our own origin', () => {
  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const)('refuses %s with no Origin', async (method) => {
    const { app, reached } = await setup();
    const response = await app.inject({ method, url: '/test/write' });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('ORIGIN_REFUSED', FIRST_ID));
    expect(reached).toEqual([]);
  });

  it.each([
    ['another site', 'https://evil.example'],
    ['an opaque origin', 'null'],
    ['plain http', 'http://app.agentx.example'],
    ['another port', 'https://app.agentx.example:8443'],
    ['a subdomain', 'https://x.app.agentx.example'],
    ['a trailing slash', 'https://app.agentx.example/'],
    ['capital letters', 'https://APP.agentx.example'],
    ['two origins in one header', `${PUBLIC_ORIGIN}, https://evil.example`],
  ])('refuses %s', async (_what, origin) => {
    const { app, reached } = await setup();
    const response = await app.inject({ method: 'POST', url: '/test/write', headers: { origin } });
    expect(response.statusCode).toBe(403);
    expect(reached).toEqual([]);
  });

  it('accepts a write from our own origin', async () => {
    const { app, reached } = await setup();
    const response = await app.inject({ method: 'POST', url: '/test/write', headers: { origin: PUBLIC_ORIGIN } });
    expect(response.statusCode).toBe(200);
    expect(reached).toEqual(['write']);
  });

  it.each(['GET', 'HEAD'] as const)('lets %s through without an Origin, as it only reads', async (method) => {
    const { app } = await setup();
    expect((await app.inject({ method, url: '/health' })).statusCode).toBe(200);
  });

  it('refuses before reading the body', async () => {
    const { app, reached } = await setup();
    const response = await app.inject({
      method: 'POST',
      url: '/test/body',
      headers: { origin: 'https://evil.example', 'content-type': 'application/json' },
      payload: '{ not json',
    });
    expect(response.statusCode).toBe(403);
    expect(reached).toEqual([]);
  });

  it('refuses a write to an address that does not exist, before saying so', async () => {
    const { app } = await setup();
    expect((await app.inject({ method: 'POST', url: '/nothing-here' })).statusCode).toBe(403);
    expect(
      (await app.inject({ method: 'POST', url: '/nothing-here', headers: { origin: PUBLIC_ORIGIN } })).statusCode,
    ).toBe(404);
  });
});

describe('SEC-DATA-04 errors show no internals', () => {
  it('answers a failure on our side with a plain 500, and logs the detail instead', async () => {
    const { app, lines } = await setup();
    const response = await app.inject('/test/fail');
    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(response.body).not.toContain('database');
    expect(events(lines(), REQUEST_FAILED)).toEqual([
      expect.objectContaining({
        level: 'error',
        correlationId: FIRST_ID,
        err: expect.objectContaining({
          type: 'Error',
          message: expect.stringContaining('[email]') as unknown,
        }) as unknown,
      }),
    ]);
  });

  it("still answers plainly when a route set a header Node refuses (Fastify's fallback would show the error)", async () => {
    const { app, lines } = await setup();
    const note = `before${String.fromCharCode(1)}after`;
    const response = await app.inject({ url: '/test/header', query: { note } });
    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(response.headers).toMatchObject(EXPECTED_HEADERS);
    expect(response.headers).not.toHaveProperty('x-note');
    expect(events(lines(), REQUEST_FAILED)).toEqual([
      expect.objectContaining({ err: expect.objectContaining({ code: 'ERR_INVALID_CHAR' }) as unknown }),
    ]);
  });

  it('still answers plainly when logging the failure throws', async () => {
    const failingErrors = (logger: Logger): Logger => ({
      ...logger,
      child: (bindings) => ({
        ...logger.child(bindings),
        error: () => {
          throw new Error('log write failed');
        },
      }),
    });
    const { app } = await setup({ wrapLogger: failingErrors });
    const response = await app.inject('/test/fail');
    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
  });

  it('answers an unknown address with a plain 404 that does not repeat it', async () => {
    const { app } = await setup();
    const response = await app.inject(`/v1/agents/${SAMPLES.agentKey}?token=${encodeURIComponent(PLANTED)}`);
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual(errorBody('NOT_FOUND', FIRST_ID));
  });

  it('answers a method the address does not have with the same 404, as for a feature that is off', async () => {
    const { app } = await setup();
    const response = await app.inject({ method: 'DELETE', url: '/health', headers: { origin: PUBLIC_ORIGIN } });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual(errorBody('NOT_FOUND', FIRST_ID));
  });

  it('answers a malformed address with a plain 400 that does not repeat it, and logs the request', async () => {
    const { app, lines } = await setup();
    const response = await app.inject('/%zz-malformed');
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('BAD_REQUEST', FIRST_ID));
    expect(events(lines(), REQUEST_COMPLETED)).toEqual([
      expect.objectContaining({ method: 'GET', route: null, status: 400, correlationId: FIRST_ID }),
    ]);
  });

  it.each([
    ['a malformed JSON body', 'application/json', '{"amount": ', 400, 'BAD_REQUEST'],
    ['a body that tries to set a prototype', 'application/json', '{"__proto__": {"admin": true}}', 400, 'BAD_REQUEST'],
    ['an empty JSON body', 'application/json', '', 400, 'BAD_REQUEST'],
    ['a body type the address does not take', 'application/xml', '<a/>', 415, 'UNSUPPORTED_MEDIA_TYPE'],
    [
      'a body over the size limit',
      'application/json',
      JSON.stringify({ note: 'x'.repeat(70_000) }),
      413,
      'PAYLOAD_TOO_LARGE',
    ],
  ] as const)('answers %s with only its reason code', async (_what, contentType, payload, status, code) => {
    const { app, reached } = await setup();
    const response = await app.inject({
      method: 'POST',
      url: '/test/body',
      headers: { origin: PUBLIC_ORIGIN, 'content-type': contentType },
      payload,
    });
    expect(response.statusCode).toBe(status);
    expect(response.json()).toEqual(errorBody(code, FIRST_ID));
    expect(reached).toEqual([]);
  });

  it('reads a well-formed body (the test route itself works)', async () => {
    const { app } = await setup();
    const response = await app.inject({
      method: 'POST',
      url: '/test/body',
      headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
      payload: '{"amount": 1}',
    });
    expect(response.json()).toEqual({ received: 'object' });
  });
});

describe('logging standard §2: the correlation ID', () => {
  it("keeps the caller's UUID, in lower case, in the response and in every line", async () => {
    const { app, lines } = await setup();
    const response = await app.inject({
      url: '/nothing-here',
      headers: { [CORRELATION_HEADER]: '0199A1B2-C3D4-7E5F-8A6B-7C8D9E0F1A2B' },
    });
    const id = '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b';
    expect(response.headers[CORRELATION_HEADER]).toBe(id);
    expect(response.json()).toEqual(errorBody('NOT_FOUND', id));
    expect(lines().filter((line) => line.event === REQUEST_COMPLETED)).toEqual([
      expect.objectContaining({ correlationId: id }),
    ]);
  });

  it.each([
    ['no ID', undefined],
    ['text that is not a UUID', 'my-request-1'],
    ['an attempt to add fields to a log line', `${FIRST_ID}", "orgId": "org-b`],
    ['a UUID with extra text', `${SECOND_ID}x`],
  ])('makes a new one when the caller sends %s', async (_what, value) => {
    const { app } = await setup();
    const headers = value === undefined ? {} : { [CORRELATION_HEADER]: value };
    const response = await app.inject({ url: '/health', headers });
    expect(response.headers[CORRELATION_HEADER]).toBe(FIRST_ID);
  });

  it('gives each request its own', async () => {
    const { app } = await setup();
    const first = await app.inject('/health');
    const second = await app.inject('/health');
    expect([first.headers[CORRELATION_HEADER], second.headers[CORRELATION_HEADER]]).toEqual([FIRST_ID, SECOND_ID]);
  });
});

describe('ADR-011 §4 each client address has a rate limit', () => {
  it('refuses the request after the limit with RATE_LIMITED and says when to retry', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10 } });
    const allowed = [];
    for (let i = 0; i < 10; i += 1) allowed.push((await app.inject('/health')).statusCode);
    const refused = await app.inject('/health');
    expect(allowed).toEqual(Array.from({ length: 10 }, () => 200));
    expect(refused.statusCode).toBe(429);
    expect(refused.json()).toEqual(errorBody('RATE_LIMITED', '00000000-0000-7000-8000-00000000000b'));
    expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('counts 404s and refused writes too, so a flood of them is limited', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10 } });
    for (let i = 0; i < 5; i += 1) await app.inject('/nothing-here');
    for (let i = 0; i < 5; i += 1) await app.inject({ method: 'POST', url: '/test/write' });
    expect(
      (await app.inject({ method: 'POST', url: '/test/write', headers: { origin: PUBLIC_ORIGIN } })).statusCode,
    ).toBe(429);
  });

  it('counts each address on its own', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10 } });
    for (let i = 0; i < 11; i += 1) await app.inject({ url: '/health', remoteAddress: '192.0.2.10' });
    expect((await app.inject({ url: '/health', remoteAddress: '192.0.2.10' })).statusCode).toBe(429);
    expect((await app.inject({ url: '/health', remoteAddress: '192.0.2.11' })).statusCode).toBe(200);
  });

  it('counts malformed addresses too, which fail before any hook runs', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10 } });
    const statuses = [];
    for (let i = 0; i < 11; i += 1) statuses.push((await app.inject('/%zz')).statusCode);
    expect(statuses).toEqual([...Array.from({ length: 10 }, () => 400), 429]);
    const refused = await app.inject('/health');
    expect(refused.statusCode).toBe(429);
    expect(refused.headers['retry-after']).toBeDefined();
  });

  it('counts a malformed address behind a trusted proxy under its real client, not the proxy', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10, trustedProxies: ['10.0.0.1'] } });
    const statuses = [];
    for (let i = 0; i < 11; i += 1) {
      const headers = { 'x-forwarded-for': `198.51.100.${i}` };
      statuses.push((await app.inject({ url: '/%zz', remoteAddress: '10.0.0.1', headers })).statusCode);
    }
    expect(statuses).toEqual(Array.from({ length: 11 }, () => 400));
    expect((await app.inject({ url: '/health', remoteAddress: '10.0.0.1' })).statusCode).toBe(200);
  });

  it("leaves a route's own, lower limit working (the plugin's hook would have switched it off)", async () => {
    const { app } = await setup();
    const statuses = [];
    for (let i = 0; i < 3; i += 1) statuses.push((await app.inject('/test/limited')).statusCode);
    expect(statuses).toEqual([200, 200, 429]);
    expect((await app.inject('/health')).statusCode).toBe(200);
  });

  it('sets the limit headers on each counted response', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10 } });
    const response = await app.inject('/health');
    expect(response.headers).toMatchObject({
      'x-ratelimit-limit': '10',
      'x-ratelimit-remaining': '9',
      'x-ratelimit-reset': '60',
    });
    expect(response.headers).not.toHaveProperty('retry-after');
  });
});

describe("SEC-AV-09 one client's flood can't crowd out other clients' request lines", () => {
  it('writes rate-limited requests under their own event, capped on their own', async () => {
    const { app, lines } = await setup({ http: { rateLimitPerMinute: 10 }, log: { eventCapPerMinute: 20 } });
    for (let i = 0; i < 40; i += 1) await app.inject({ url: '/health', remoteAddress: '192.0.2.10' });
    const other = await app.inject({ url: '/health', remoteAddress: '198.51.100.7' });
    const otherId = other.headers[CORRELATION_HEADER];
    expect(events(lines(), REQUEST_COMPLETED)).toHaveLength(11);
    expect(events(lines(), REQUEST_COMPLETED).at(-1)).toMatchObject({ correlationId: otherId, status: 200 });
    expect(events(lines(), REQUEST_RATE_LIMITED)).toHaveLength(20);
    expect(events(lines(), REQUEST_RATE_LIMITED)[0]).toMatchObject({ route: '/health', status: 429 });
  });
});

describe('SEC-AV-07 a forged X-Forwarded-For does not dodge the rate limit', () => {
  /** Sends `count` requests and returns the status of one more. */
  async function afterRequests(
    app: FastifyInstance,
    count: number,
    request: (i: number) => { remoteAddress: string; headers?: Record<string, string> },
  ) {
    for (let i = 0; i < count; i += 1) await app.inject({ url: '/health', ...request(i) });
    return (await app.inject({ url: '/health', ...request(count) })).statusCode;
  }

  it('ignores the header when no proxy is trusted', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10 } });
    const status = await afterRequests(app, 10, (i) => ({
      remoteAddress: '192.0.2.10',
      headers: { 'x-forwarded-for': `198.51.100.${i}` },
    }));
    expect(status).toBe(429);
  });

  it('ignores the header from an address that is not a trusted proxy', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10, trustedProxies: ['10.0.0.1'] } });
    const status = await afterRequests(app, 10, (i) => ({
      remoteAddress: '192.0.2.10',
      headers: { 'x-forwarded-for': `198.51.100.${i}` },
    }));
    expect(status).toBe(429);
  });

  it("believes a trusted proxy's last entry, so each real client has its own limit", async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10, trustedProxies: ['10.0.0.0/24'] } });
    const status = await afterRequests(app, 10, (i) => ({
      remoteAddress: '10.0.0.1',
      headers: { 'x-forwarded-for': `198.51.100.${i}` },
    }));
    expect(status).toBe(200);
  });

  it('ignores the entries a client wrote before the one the trusted proxy added', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10, trustedProxies: ['10.0.0.1'] } });
    const status = await afterRequests(app, 10, (i) => ({
      remoteAddress: '10.0.0.1',
      headers: { 'x-forwarded-for': `198.51.100.${i}, 203.0.113.9` },
    }));
    expect(status).toBe(429);
  });

  it('gives routes the same client address: request.ip believes only a trusted proxy', async () => {
    const { app } = await setup({ http: { trustedProxies: ['10.0.0.1'] } });
    const headers = { 'x-forwarded-for': '198.51.100.7' };
    const viaProxy = await app.inject({ url: '/test/ip', remoteAddress: '10.0.0.1', headers });
    const direct = await app.inject({ url: '/test/ip', remoteAddress: '192.0.2.10', headers });
    expect([viaProxy.json(), direct.json()]).toEqual([{ ip: '198.51.100.7' }, { ip: '192.0.2.10' }]);
  });

  it('counts a client by its address alone when the proxy adds a port that changes with each connection', async () => {
    const { app } = await setup({ http: { rateLimitPerMinute: 10, trustedProxies: ['10.0.0.1'] } });
    const status = await afterRequests(app, 10, (i) => ({
      remoteAddress: '10.0.0.1',
      headers: { 'x-forwarded-for': `203.0.113.9:${40_000 + i}` },
    }));
    expect(status).toBe(429);
  });
});

describe('ADR-011 §7 one line per request: route pattern, status and duration only', () => {
  it('writes the method, the route pattern, the status, the duration and the correlation ID', async () => {
    const { app, lines } = await setup();
    await app.inject('/health');
    await app.inject('/nothing-here');
    expect(events(lines(), REQUEST_COMPLETED)).toEqual([
      expect.objectContaining({ level: 'info', method: 'GET', route: '/health', status: 200, correlationId: FIRST_ID }),
      expect.objectContaining({ level: 'info', method: 'GET', route: null, status: 404, correlationId: SECOND_ID }),
    ]);
    const [line] = events(lines(), REQUEST_COMPLETED);
    expect(Object.keys(line ?? {}).sort()).toEqual(
      [
        'correlationId',
        'durationMs',
        'env',
        'event',
        'level',
        'method',
        'release',
        'route',
        'service',
        'status',
        'time',
      ].sort(),
    );
    expect(line?.durationMs).toEqual(expect.any(Number));
  });

  it("writes no other line for an ordinary request (Fastify's own request lines are replaced)", async () => {
    const { app, lines } = await setup();
    await app.inject('/health');
    expect(lines().map((line) => line.event)).toEqual([REQUEST_COMPLETED]);
  });

  it('SEC-DATA-01 FX-LOGSCAN: never logs the address as sent, the query, the headers, the body or the client IP', async () => {
    const { app, capture } = await setup({ http: { trustedProxies: ['10.0.0.1'] } });
    const samples = Object.values(SAMPLES);
    // A marker nothing gets encoded in, under an ordinary name, so a logged query would show it as written.
    const query = `?ref=plantedqueryvalue&a='plantedafterquote&note=${encodeURIComponent(samples.join(' '))}`;
    const headers = {
      origin: PUBLIC_ORIGIN,
      authorization: SAMPLES.bearer,
      cookie: `session=${PLANTED}`,
      'x-forwarded-for': `${SAMPLES.ipv4}, ${SAMPLES.ipv6}`,
      'user-agent': `agent ${SAMPLES.email}`,
      referer: SAMPLES.oauthCallback,
      'content-type': 'application/json',
    };
    const payload = JSON.stringify({ iban: SAMPLES.uaeIban, card: SAMPLES.card, note: PLANTED });
    await app.inject({ method: 'POST', url: `/test/body${query}`, headers, payload, remoteAddress: '10.0.0.1' });
    await app.inject({
      method: 'POST',
      url: `/v1/suppliers/${SAMPLES.uaeIban}${query}`,
      headers,
      payload,
      remoteAddress: '10.0.0.1',
    });
    await app.inject({ url: `/test/fail${query}`, headers, remoteAddress: '10.0.0.1' });
    await app.inject({ url: SAMPLES.relativeCallback, headers, remoteAddress: '10.0.0.1' });

    await app.inject({ url: `/test/items/${SAMPLES.uaeIban}${query}`, headers, remoteAddress: '10.0.0.1' });

    expect(capture.lines().length).toBeGreaterThan(4);
    const markers = [PLANTED, 'plantedqueryvalue', 'plantedafterquote', 'session=', '/v1/suppliers', 'oauth/callback'];
    expect(findLeaks(capture.text, [...markers, '10.0.0.1'])).toEqual([]);
  });
});

describe('ADR-013 the health check says only ok or unavailable', () => {
  const passing: HealthCheck = { name: 'passing_check', check: () => Promise.resolve(true) };

  it('answers ok when every check passes (and when there are none)', async () => {
    for (const healthChecks of [[], [passing]]) {
      const { app } = await setup({ healthChecks });
      const response = await app.inject('/health');
      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
      expect(response.json()).toEqual({ status: 'ok' });
    }
  });

  it.each([
    ['returns false', () => Promise.resolve(false), false],
    ['rejects', () => Promise.reject(new Error(`timed out reaching ${SAMPLES.ipv4}`)), true],
    [
      'throws before returning a promise',
      () => {
        throw new Error('not ready');
      },
      true,
    ],
  ] as const)('answers unavailable when a check %s, and logs which one', async (_what, check, hasError) => {
    const { app, lines } = await setup({ healthChecks: [passing, { name: 'worker_heartbeat', check }] });
    const response = await app.inject('/health');
    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({ status: 'unavailable' });
    expect(response.body).not.toContain('worker_heartbeat');
    const failures = events(lines(), CHECK_FAILED);
    expect(failures).toEqual([
      expect.objectContaining({ level: 'warn', check: 'worker_heartbeat', correlationId: FIRST_ID }),
    ]);
    expect('err' in (failures[0] ?? {})).toBe(hasError);
    expect(findLeaks(JSON.stringify(failures))).toEqual([]);
  });

  it('answers a HEAD request with the status and no body', async () => {
    const { app } = await setup();
    const response = await app.inject({ method: 'HEAD', url: '/health' });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBe('');
  });
});

describe("ADR-013 Fastify's own lines go through the adapter", () => {
  it('logs a reply sent twice as one framework line: its code, but not the address as sent', async () => {
    const { app, lines } = await setup();
    await app.inject("/test/items/customer-ref-private?a='note=plantedafterquote");
    const framework = events(lines(), FRAMEWORK_EVENT);
    expect(framework).toEqual([
      expect.objectContaining({
        level: 'warn',
        correlationId: FIRST_ID,
        err: expect.objectContaining({
          type: 'FastifyError',
          code: 'FST_ERR_REP_ALREADY_SENT',
          message: 'FST_ERR_REP_ALREADY_SENT',
        }) as unknown,
      }),
    ]);
    expect(findLeaks(JSON.stringify(framework), ['customer-ref-private', 'plantedafterquote'])).toEqual([]);
  });
});
