import type { LiveSession, SignIn } from '@agentx/core/modules/identity';
import type { IdempotentRequest, IdempotentWrite } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { errorBody } from './errors.ts';
import { answerRefusedWrite, BUSY_RETRY_SECONDS, canonicalJson, idempotentRequest } from './idempotent-writes.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-0000000000aa';
const ITEM = '0199a0f0-0000-7000-8000-0000000000bb';

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

/** A sign-in that knows one session and does nothing else these tests need. */
const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/**
 * A server with one idempotent write, `items.rename` at PUT /v1/items/:id,
 * whose store answers as the test says and records what it was asked.
 */
async function withWrite(answer: (asked: IdempotentRequest) => IdempotentWrite) {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 1000,
      rateLimitPerUserPerMinute: 1000,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: new LogCapture(),
  });
  const app = await buildServer({
    config,
    logger,
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: { service: SIGN_IN, sessionSeconds: 43_200 },
  });
  servers.push(app);
  const asked: IdempotentRequest[] = [];
  app.put(
    '/v1/items/:id',
    {
      config: { access: ['person'], operation: 'items.rename' },
      bodyLimit: 1024,
      schema: {
        params: z.object({ id: z.uuid() }),
        querystring: z.object({ notify: z.enum(['yes', 'no']).optional(), tag: z.string().optional() }),
        body: z.object({ label: z.string(), details: z.object({ colour: z.string(), size: z.number() }).optional() }),
        response: { '2xx': z.object({ id: z.uuid() }) },
      },
    },
    (request, reply) => {
      const idempotent = idempotentRequest(request, ORG);
      asked.push(idempotent);
      const outcome = answer(idempotent);
      const refused = answerRefusedWrite(outcome, request, reply);
      if (refused !== undefined) return refused;
      if (outcome.outcome === 'conflict' || outcome.outcome === 'busy') throw new Error('unreachable');
      return reply.code(outcome.result.status).send({ id: outcome.result.resourceId });
    },
  );
  await app.ready();
  return { app, asked };
}

const DONE: IdempotentWrite = { outcome: 'done', result: { status: 200, resourceId: ITEM } };

/** The signed-in person's rename, with the key, query and body given. */
const rename = (body: unknown, { key = 'k-1', query = '' }: { key?: string; query?: string } = {}): InjectOptions => ({
  method: 'PUT',
  url: `/v1/items/${ITEM}${query}`,
  headers: {
    origin: PUBLIC_ORIGIN,
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    'idempotency-key': key,
    'content-type': 'application/json',
  },
  payload: typeof body === 'string' ? body : JSON.stringify(body),
});

describe('SEC-DP-07 the request the store is asked about', () => {
  it("names the person, the route's operation, the key and the organisation the route found", async () => {
    const { app, asked } = await withWrite(() => DONE);
    const response = await app.inject(rename({ label: 'new' }, { key: 'retry-me' }));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ id: ITEM });
    expect(asked).toEqual([
      {
        orgId: ORG,
        client: { kind: 'user', id: LIVE.userId },
        operation: 'items.rename',
        key: 'retry-me',
        payload: `{"body":{"label":"new"},"params":{"id":"${ITEM}"},"query":{}}`,
      },
    ]);
  });

  it('asks the same about the same request, whatever the order of its fields and parameters, and its spacing', async () => {
    const { app, asked } = await withWrite(() => DONE);
    await app.inject(rename({ label: 'new', details: { size: 2, colour: 'red' } }, { query: '?notify=yes&tag=t' }));
    await app.inject(
      rename('{ "details" : { "colour":"red","size":2.0 }, "label":"new" }', { query: '?tag=t&notify=yes' }),
    );
    expect(asked).toHaveLength(2);
    expect(asked[0]?.payload).toBe(asked[1]?.payload);
  });

  it('asks differently about a different body, query or address, and drops fields the schema does not name', async () => {
    const { app, asked } = await withWrite(() => DONE);
    await app.inject(rename({ label: 'new' }));
    await app.inject(rename({ label: 'new', unnamed: 'dropped' }));
    await app.inject(rename({ label: 'other' }));
    await app.inject(rename({ label: 'new' }, { query: '?notify=no' }));
    const [first, unnamed, ...different] = asked.map((request) => request.payload);
    expect(unnamed).toBe(first);
    expect(new Set([first, ...different]).size).toBe(3);
  });

  it('refuses a body holding text that is not well-formed as BAD_REQUEST, asking the store nothing', async () => {
    const { app, asked } = await withWrite(() => DONE);
    const response = await app.inject(rename('{"label":"\\ud800"}'));
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('BAD_REQUEST', FIRST_ID));
    expect(asked).toEqual([]);
  });
});

describe('what a write route can never hand the store', () => {
  /** A request as a route would see it, with parts changed. */
  const requestLike = (changes: {
    operation?: string | undefined;
    key?: string | undefined;
    person?: LiveSession | null;
  }) =>
    ({
      routeOptions: { config: { operation: 'operation' in changes ? changes.operation : 'items.rename' } },
      headers: 'key' in changes ? { 'idempotency-key': changes.key } : { 'idempotency-key': 'k-1' },
      person: 'person' in changes ? changes.person : LIVE,
      params: undefined,
      query: undefined,
      body: undefined,
    }) as unknown as Parameters<typeof idempotentRequest>[0];

  it.each<[string, Parameters<typeof requestLike>[0], string]>([
    ['a route that names no operation', { operation: undefined }, 'names no operation'],
    ['a request without its key', { key: undefined }, 'without a well-formed key'],
    ['a request with a malformed key', { key: 'two words' }, 'without a well-formed key'],
    ['a request without a signed-in person', { person: null }, 'without a signed-in person'],
  ])('fails on our side for %s', (_what, changes, message) => {
    expect(() => idempotentRequest(requestLike(changes), ORG)).toThrow(message);
  });

  it('takes a request with no params, query or body as empty ones', () => {
    expect(idempotentRequest(requestLike({}), ORG).payload).toBe('{"body":null,"params":{},"query":{}}');
  });
});

describe('SEC-DP-07/08/09 answering what the store says', () => {
  it("answers a replay with the first write's status and resource, as the route re-reads it", async () => {
    const { app } = await withWrite(() => ({ outcome: 'replayed', result: { status: 201, resourceId: ITEM } }));
    const response = await app.inject(rename({ label: 'new' }));
    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ id: ITEM });
  });

  it('answers a key used for another request with 409 IDEMPOTENCY_KEY_REUSED', async () => {
    const { app } = await withWrite(() => ({ outcome: 'conflict' }));
    const response = await app.inject(rename({ label: 'new' }));
    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual(errorBody('IDEMPOTENCY_KEY_REUSED', FIRST_ID));
    expect(response.headers['retry-after']).toBeUndefined();
  });

  it('answers a key still being done with 409 IDEMPOTENCY_KEY_BUSY and when to send it again', async () => {
    const { app } = await withWrite(() => ({ outcome: 'busy' }));
    const response = await app.inject(rename({ label: 'new' }));
    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual(errorBody('IDEMPOTENCY_KEY_BUSY', FIRST_ID));
    expect(response.headers['retry-after']).toBe(String(BUSY_RETRY_SECONDS));
    expect(BUSY_RETRY_SECONDS).toBeGreaterThanOrEqual(5);
  });

  it('leaves a write done, or replayed, for the route to answer', () => {
    const request = { id: FIRST_ID } as Parameters<typeof answerRefusedWrite>[1];
    const reply = {} as Parameters<typeof answerRefusedWrite>[2];
    expect(answerRefusedWrite(DONE, request, reply)).toBeUndefined();
    expect(answerRefusedWrite({ outcome: 'replayed', result: DONE.result }, request, reply)).toBeUndefined();
  });
});

describe('the canonical JSON of a request', () => {
  it.each<[string, unknown, string]>([
    ['null', null, 'null'],
    ['true and false', [true, false], '[true,false]'],
    ['numbers as JSON writes them', [1, 1.5, -0, 1e21, 0.1], '[1,1.5,0,1e+21,0.1]'],
    ['text, escaped as JSON writes it', 'a"b\\c\u0001é😀', JSON.stringify('a"b\\c\u0001é😀')],
    [
      'keys sorted at every depth',
      { b: { d: 1, c: 2 }, a: [{ z: 1, y: 2 }] },
      '{"a":[{"y":2,"z":1}],"b":{"c":2,"d":1}}',
    ],
    ['keys sorted by code unit', { é: 1, z: 2, Z: 3, 10: 4, 9: 5 }, '{"10":4,"9":5,"Z":3,"z":2,"é":1}'],
    ['a list in its own order', [3, 1, 2], '[3,1,2]'],
    ['an object with no prototype', Object.assign(Object.create(null) as object, { a: 1 }), '{"a":1}'],
    [
      'an object whose prototype is empty with none behind it, as Fastify makes params and query',
      Object.assign(Object.create(Object.create(null) as object) as object, { a: 1 }),
      '{"a":1}',
    ],
    [
      'a key named __proto__, as JSON.parse makes one',
      JSON.parse('{"__proto__":1,"a":2}') as unknown,
      '{"__proto__":1,"a":2}',
    ],
    ['empty object and list', { a: {}, b: [] }, '{"a":{},"b":[]}'],
  ])('writes %s', (_what, value, text) => {
    expect(canonicalJson(value)).toBe(text);
  });

  it.each<[string, unknown]>([
    ['not a number', Number.NaN],
    ['infinity', Number.POSITIVE_INFINITY],
    ['undefined', undefined],
    ['a date', new Date(0)],
    ['a big integer', 1n],
    ['a function', () => 1],
    ['a map', new Map()],
    [
      'an instance of a class of our own',
      new (class Point {
        x = 1;
      })(),
    ],
    ['an object whose prototype holds a field', Object.create(Object.assign(Object.create(null) as object, { a: 1 }))],
    ['an object whose prototype is a plain object', Object.create({})],
    ['undefined inside an object', { a: undefined }],
  ])('refuses %s as a failure on our side', (_what, value) => {
    expect(() => canonicalJson(value)).toThrow(TypeError);
  });

  it("refuses a lone surrogate in text or a key as the client's, a 400", () => {
    for (const value of ['\ud800', { '\udc00': 1 }, ['ok', { a: 'x\ud83d' }]]) {
      expect(() => canonicalJson(value)).toThrow(expect.objectContaining({ statusCode: 400 }) as Error);
    }
  });
});
