import { Readable } from 'node:stream';

import { type IdGenerator, isReasonCode, REASON_CODES } from '@agentx/core/shared-kernel';
import { createLogger } from '@agentx/platform/observability';
import { findLeaks, LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, FastifyReply, FastifySchema, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { ContractBroken, NOT_FOUND_CHECKS, routeTableProblems, withoutUnusedSchemas } from './contract.ts';
import { ERROR_BODY, errorBody } from './errors.ts';
import { REQUEST_FAILED } from './request-log.ts';
import { buildServer } from './server.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
/** A marker value that must never come out. Plain words, so secret scanners ignore it. */
const PLANTED = 'planted value that must not appear';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const ITEM_ID = '0190f4c2-1e5b-7c3d-8a9b-0c1d2e3f4a5b';
/**
 * Test routes are open to anyone, read at most 1 KiB and answer `{ ok: true }`
 * (or a string, sent as it is): none of that is what these tests are about.
 */
const OPEN = {
  config: { access: ['public'] },
  bodyLimit: 1024,
  schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
} as const;

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** The real server, not yet ready, so a test can add routes of its own first. */
async function server(ids: IdGenerator = new SequentialIds()) {
  const capture = new LogCapture();
  const config = {
    http: { host: '127.0.0.1', port: 0, publicOrigin: PUBLIC_ORIGIN, trustedProxies: [], rateLimitPerMinute: 100 },
    log: { level: 'debug' as const, eventCapPerMinute: 10_000 },
  };
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: capture,
  });
  const app = await buildServer({ config, logger, ids, healthChecks: [] });
  servers.push(app);
  return { app, capture };
}

/** The parts of the document these tests read, checked as they are read. */
const DOCUMENT = z.object({
  paths: z.record(z.string(), z.record(z.string(), z.object({ responses: z.record(z.string(), z.unknown()) }))),
  components: z.object({ schemas: z.record(z.string(), z.unknown()) }),
});
const REASON_CODES_DOCUMENTED = z.object({
  properties: z.object({
    error: z.object({
      properties: z.object({
        code: z.object({ anyOf: z.array(z.object({ const: z.string(), description: z.string() })) }),
      }),
    }),
  }),
});

const documentOf = (app: FastifyInstance) => DOCUMENT.parse(app.swagger());

/** Every operation in the document, as "METHOD /path". */
function operations(app: FastifyInstance): string[] {
  return Object.entries(documentOf(app).paths).flatMap(([path, item]) =>
    Object.keys(item).map((method) => `${method.toUpperCase()} ${path}`),
  );
}

describe('SEC-WEB-06 the router serves exactly what the OpenAPI document holds', () => {
  it('keeps the document in the repository, so every change to the API is a reviewed diff', async () => {
    const { app } = await server();
    await app.ready();
    // Run `corepack pnpm vitest run -u apps/api/src/contract.test.ts` to write it after a deliberate change.
    await expect(`${JSON.stringify(app.swagger(), null, 2)}\n`).toMatchFileSnapshot('../openapi.json');
  });

  it("documents every route the server serves, and the HEAD Fastify adds to each GET, whatever the route's shape", async () => {
    const { app } = await server();
    app.get('/test/items/:ref', OPEN, () => 'ok');
    app.route({ method: ['POST', 'PUT'], url: '/test/both', ...OPEN, handler: () => 'ok' });
    await app.register(
      (child, _options, done) => {
        child.delete('/things/:id', OPEN, () => 'ok');
        done();
      },
      { prefix: '/test/nested' },
    );
    await app.ready();
    expect(operations(app).sort()).toEqual([
      'DELETE /test/nested/things/{id}',
      'GET /health',
      'GET /test/items/{ref}',
      'GET /v1/auth/callback',
      'GET /v1/auth/sign-in',
      'HEAD /health',
      'HEAD /test/items/{ref}',
      'HEAD /v1/auth/callback',
      'HEAD /v1/auth/sign-in',
      'POST /test/both',
      'POST /v1/auth/sign-out',
      'PUT /test/both',
    ]);
  });

  it.each([
    ['marked hidden', { hide: true }],
    ["tagged with the document's hidden tag", { tags: ['X-HIDDEN'] }],
  ])('refuses to start with a route %s, naming it and its HEAD', async (_how, schema) => {
    const { app } = await server();
    app.get('/test/debug', { ...OPEN, schema: { ...OPEN.schema, ...schema } }, () => 'ok');
    const ready = app.ready();
    await expect(ready).rejects.toThrow(ContractBroken);
    await expect(ready).rejects.toMatchObject({
      problems: ['GET /test/debug is served but not documented', 'HEAD /test/debug is served but not documented'],
    });
  });

  it("documents a route under the provider's own skip list rather than leaving it out", async () => {
    const { app } = await server();
    app.get('/documentation/json', OPEN, () => 'ok');
    await app.ready();
    expect(operations(app)).toContain('GET /documentation/json');
  });

  it.each<[string, RouteShorthandOptions, string]>([
    ['a body schema that is not zod', { schema: { body: { type: 'object' } } }, 'its body schema is not a zod schema'],
    ['a query schema that is not zod', { schema: { querystring: { type: 'object' } } }, 'its querystring schema'],
    ['a response schema that is not zod', { schema: { response: { 200: { type: 'object' } } } }, 'its 200 response'],
    [
      'a response of one content type that is not zod',
      { schema: { response: { 200: { content: { 'application/json': { schema: { type: 'object' } } } } } } },
      'its 200 response',
    ],
    [
      'a content type that holds no schema',
      { schema: { response: { 200: { content: { 'application/json': {} } } } } },
      'its 200 response',
    ],
    ['content that is not a list of types', { schema: { response: { 200: { content: 'text' } } } }, 'its 200 response'],
    ['content that is empty', { schema: { response: { 200: { content: null } } } }, 'its 200 response'],
    ['its own 4xx error body', { schema: { response: { '4xx': ERROR_BODY } } }, 'it sets its own 4xx response'],
    ['its own 5XX error body', { schema: { response: { '5XX': ERROR_BODY } } }, 'it sets its own 5XX response'],
    ['its own default body', { schema: { response: { default: ERROR_BODY } } }, 'it sets its own default response'],
    [
      'its own shape for an error status',
      { schema: { response: { 400: z.object({ detail: z.string() }) } } },
      'its 400 answer is not the one error body',
    ],
    [
      'its own shape for a failure',
      { schema: { response: { 500: z.object({ detail: z.string() }) } } },
      'its 500 answer is not the one error body',
    ],
    [
      'its own shape for one content type of an error status',
      {
        schema: {
          response: { 409: { content: { 'application/json': { schema: z.object({ detail: z.string() }) } } } },
        },
      },
      'its 409 answer is not the one error body',
    ],
    [
      'the one error body for one content type of an error status, but not for another',
      {
        schema: {
          response: {
            409: {
              content: {
                'application/json': { schema: ERROR_BODY },
                'application/problem+json': { schema: z.object({ detail: z.string() }) },
              },
            },
          },
        },
      },
      'its 409 answer is not the one error body',
    ],
    ['empty constraints, which say nothing but hide nothing either', { constraints: {} }, 'it is served only for some'],
    ['validation errors handed to it rather than refused', { attachValidation: true }, 'it sets attachValidation'],
    ['a validator of its own', { validatorCompiler: () => () => true }, 'it sets validatorCompiler'],
    [
      'a serializer of its own',
      { serializerCompiler: () => (data) => JSON.stringify(data) },
      'it sets serializerCompiler',
    ],
    [
      'an error handler of its own',
      {
        errorHandler: (_error, _request, reply) => {
          void reply.send('detail');
        },
      },
      'it sets errorHandler',
    ],
    ['a twin served only for one host', { constraints: { host: 'debug.example' } }, 'it is served only for some hosts'],
    [
      'its own way of being documented',
      { config: { swaggerTransform: () => ({ schema: {}, url: '/elsewhere' }) } },
      'it changes how the document shows it',
    ],
  ])('refuses a route with %s as it is added', async (_what, options, problem) => {
    const { app } = await server();
    expect(() => app.post('/test/route', options, () => 'ok')).toThrow(ContractBroken);
    expect(() => app.post('/test/route', options, () => 'ok')).toThrow(`POST /test/route: ${problem}`);
  });

  it('documents a success answer with the description its schema was registered with', async () => {
    const { app } = await server();
    const item = z.object({ id: z.uuid() }).register(API_SCHEMAS, { description: 'The item.' });
    app.get('/test/item', { ...OPEN, schema: { response: { 200: item } } }, () => ({ id: ITEM_ID, note: PLANTED }));
    await app.ready();
    expect(documentOf(app).paths['/test/item']?.get?.responses['200']).toMatchObject({ description: 'The item.' });
    expect((await app.inject('/test/item')).json()).toEqual({ id: ITEM_ID });
  });

  it('lets a route name an error status with the one error body, to say when it is sent', async () => {
    const { app } = await server();
    const conflict = {
      description: 'Another request holds the key.',
      content: { 'application/json': { schema: ERROR_BODY } },
    };
    const response = { 200: z.object({ id: z.uuid() }), 409: conflict, 422: ERROR_BODY };
    app.post('/test/claim', { ...OPEN, schema: { response } }, () => ({ id: ITEM_ID }));
    await app.ready();
    expect(documentOf(app).paths['/test/claim']?.post?.responses['409']).toMatchObject({
      description: 'Another request holds the key.',
    });
  });

  it('refuses to start with a twin of a route, served by a stricter address pattern', async () => {
    const { app } = await server();
    app.get('/test/a/:id', OPEN, () => 'ok');
    app.get('/test/a/:id(^[0-9]+$)', OPEN, () => 'twin');
    await expect(app.ready()).rejects.toMatchObject({
      problems: [
        'GET /test/a/{id} is served by more than one route',
        'HEAD /test/a/{id} is served by more than one route',
      ],
    });
  });

  it("refuses a route at its prefix's root, which Fastify would also serve with a slash, unseen", async () => {
    const { app } = await server();
    // An async plugin: Fastify hands what it throws to ready(). A callback plugin's throw escapes
    // Fastify altogether, and the API's crash handler stops it instead.
    // eslint-disable-next-line @typescript-eslint/require-await -- an async plugin is what this case is about
    const plugin = async (child: FastifyInstance): Promise<void> => {
      child.get('/', OPEN, () => 'ok');
    };
    void app.register(plugin, { prefix: '/test/p' });
    await expect(app.ready()).rejects.toThrow("GET /test/p: it sits at its prefix's root");
  });

  it("serves and documents a route at its prefix's root in the one form it chose", async () => {
    const { app } = await server();
    await app.register(
      (child, _options, done) => {
        child.get('/', { prefixTrailingSlash: 'no-slash', ...OPEN }, () => 'ok');
        done();
      },
      { prefix: '/test/p' },
    );
    await app.ready();
    expect(operations(app)).toContain('GET /test/p');
    expect((await app.inject('/test/p/')).statusCode).toBe(404);
  });

  it('refuses to start with a schema the document could only show as "anything"', async () => {
    const { app } = await server();
    const schema = { ...OPEN.schema, body: z.object({ at: z.date() }) };
    app.post('/test/when', { ...OPEN, schema }, () => 'ok');
    await expect(app.ready()).rejects.toThrow(/Date cannot be represented in JSON Schema/);
  });

  it('names a documented route the server does not serve, and a method OpenAPI has no place for', () => {
    const document = { paths: { '/health': { get: {} }, '/gone': { post: {} } } };
    expect(routeTableProblems(['GET /health', 'PROPFIND /health'], document)).toEqual([
      'PROPFIND /health is served but not documented',
      'POST /gone is documented but not served',
    ]);
    expect(routeTableProblems(['GET /health', 'POST /gone'], document)).toEqual([]);
    expect(routeTableProblems([], { paths: { '/nothing': undefined } })).toEqual([]);
    expect(routeTableProblems(['GET /health'], {})).toEqual(['GET /health is served but not documented']);
    expect(routeTableProblems(['GET /health', 'GET /health'], document)).toEqual([
      'POST /gone is documented but not served',
      'GET /health is served by more than one route',
    ]);
  });
});

describe('SEC-WEB-06 every route is checked again once every plugin has had its say', () => {
  const item = (child: FastifyInstance): void => {
    child.get('/item', OPEN, () => 'ok');
  };

  it.each<[string, (child: FastifyInstance) => void, string]>([
    [
      'writes through a serializer of its own, set after its route was added',
      (child) => {
        item(child);
        // eslint-disable-next-line no-restricted-properties -- proves the check at start catches what lint bans
        child.setSerializerCompiler(() => (data) => JSON.stringify(data));
      },
      'its plugin checks or writes through compilers other than zod',
    ],
    [
      'checks through a validator of its own, set after its route was added',
      (child) => {
        item(child);
        // eslint-disable-next-line no-restricted-properties -- proves the check at start catches what lint bans
        child.setValidatorCompiler(() => () => true);
      },
      'its plugin checks or writes through compilers other than zod',
    ],
    [
      'changes its routes with an onRoute hook of its own, which runs after the contract check',
      (child) => {
        child.addHook('onRoute', (route) => {
          route.attachValidation = true;
        });
        item(child);
      },
      'it sets attachValidation',
    ],
  ])('refuses to start with a plugin that %s', async (_what, plugin, problem) => {
    const { app } = await server();
    await app.register(
      (child, _options, done) => {
        plugin(child);
        done();
      },
      { prefix: '/test/plugin' },
    );
    await expect(app.ready()).rejects.toThrow(`GET /test/plugin/item: ${problem}`);
  });
});

describe('SEC-DATA-04 every error answer is written as it is, never through a route schema or hook', () => {
  // A correlation ID the error body's schema would refuse, so an answer written through it would fail.
  const odd: IdGenerator = { next: () => 'not-a-uuid' };

  it.each([
    ['a refused body', 'POST', '/test/item', { origin: PUBLIC_ORIGIN }, { quantity: 'many' }, 400, 'BAD_REQUEST'],
    ['a refused origin', 'POST', '/test/item', {}, { quantity: 1 }, 403, 'ORIGIN_REFUSED'],
    ['a failure on our side', 'GET', '/test/item', {}, undefined, 500, 'INTERNAL_ERROR'],
    ['an unknown address', 'GET', '/test/nothing', {}, undefined, 404, 'NOT_FOUND'],
  ] as const)('answers %s', async (_what, method, url, headers, payload, status, code) => {
    const { app } = await server(odd);
    const schema = { body: z.object({ quantity: z.int() }), response: { 200: z.object({ quantity: z.int() }) } };
    // A hook that would add to any object answer: an error answer is already a string, so it never runs.
    const preSerialization = (
      _request: unknown,
      _reply: unknown,
      payload: unknown,
      done: (e: null, p: unknown) => void,
    ) => {
      done(null, { ...(payload as object), note: PLANTED });
    };
    app.post('/test/item', { ...OPEN, schema, preSerialization }, () => ({ quantity: 1 }));
    app.get('/test/item', { ...OPEN, schema: { response: schema.response }, preSerialization }, () => {
      throw new Error('failed on our side');
    });
    await app.ready();
    const response = await app.inject({ method, url, headers, ...(payload && { payload }) });
    expect(response.statusCode).toBe(status);
    expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(response.json()).toEqual(errorBody(code, 'not-a-uuid'));
  });
});

describe('SEC-WEB-06 each route declares what it answers, and the most it reads', () => {
  it.each<[string, RouteShorthandOptions, string]>([
    [
      'no answer for success',
      { ...OPEN, schema: { response: { 404: ERROR_BODY } } },
      'it declares no answer for success',
    ],
    [
      'a success answer that is a string',
      { ...OPEN, schema: { response: { 200: z.string() } } },
      'its 200 answer is not an object with named fields',
    ],
    [
      'a success answer that is a list',
      { ...OPEN, schema: { response: { 200: z.array(z.object({ id: z.uuid() })) } } },
      'its 200 answer is not an object with named fields',
    ],
    [
      'a success answer that could be anything',
      { ...OPEN, schema: { response: { 201: z.unknown() } } },
      'its 201 answer is not an object with named fields',
    ],
    [
      'a body but no limit of its own for it',
      { config: OPEN.config, schema: OPEN.schema },
      'it takes a body but sets no limit of its own for it',
    ],
    [
      "a body limit over the server's own",
      { ...OPEN, bodyLimit: 64 * 1024 + 1 },
      'it takes a body but sets no limit of its own for it',
    ],
    [
      'a body limit of its own in its document',
      { ...OPEN, schema: { ...OPEN.schema, 'x-body-limit': 10 } as FastifySchema },
      'the body limit its document shows is not its own (x-body-limit)',
    ],
  ])('refuses a write with %s as it is added', async (_what, options, problem) => {
    const { app } = await server();
    expect(() => app.post('/test/route', options, () => 'ok')).toThrow(`POST /test/route: ${problem}`);
  });

  it.each([0, 1.5])(
    'refuses to start when a later hook sets a body limit of %s, which Fastify checks only as a route is added',
    async (limit) => {
      const { app } = await server();
      await app.register(
        (child, _options, done) => {
          child.addHook('onRoute', (route) => {
            route.bodyLimit = limit;
          });
          child.post('/item', OPEN, () => 'ok');
          done();
        },
        { prefix: '/test/plugin' },
      );
      await expect(app.ready()).rejects.toThrow('POST /test/plugin/item: it takes a body but sets no limit of its own');
    },
  );

  it('asks a body limit of a delete, and of a route that reads and writes at one address', async () => {
    const { app } = await server();
    const noLimit = { config: OPEN.config, schema: OPEN.schema };
    expect(() => app.delete('/test/one', noLimit, () => 'ok')).toThrow('DELETE /test/one: it takes a body');
    const both = { method: ['GET', 'POST'] as const, url: '/test/two', ...noLimit, handler: () => 'ok' };
    expect(() => app.route({ ...both, method: [...both.method] })).toThrow('GET,POST /test/two: it takes a body');
  });

  it('takes a route whose only success answer is a redirect', async () => {
    const { app } = await server();
    app.get('/test/moved', { config: OPEN.config, schema: { response: { 302: z.object({}) } } }, (_request, reply) =>
      reply.code(302).header('location', '/health').send({}),
    );
    await app.ready();
    expect((await app.inject('/test/moved')).statusCode).toBe(302);
  });

  it('takes a read with no body limit, a range of success answers, and a body limit of the most allowed', async () => {
    const { app } = await server();
    const read = { config: OPEN.config, schema: { response: { '2xx': z.object({ ok: z.literal(true) }) } } };
    app.get('/test/read', read, () => ({ ok: true }));
    const create = { ...OPEN, bodyLimit: 64 * 1024, schema: { response: { 201: z.object({ id: z.uuid() }) } } };
    app.post('/test/create', create, (_request, reply) => reply.code(201).send({ id: ITEM_ID }));
    await app.ready();
    const paths = app.swagger().paths as Record<string, Record<string, Record<string, unknown>>>;
    expect(paths['/test/create']?.post?.['x-body-limit']).toBe(64 * 1024);
    expect(paths['/test/read']?.get).not.toHaveProperty('x-body-limit');
  });

  it("refuses a body over the route's own limit, though under the server's", async () => {
    const { app } = await server();
    app.post('/test/small', { ...OPEN, bodyLimit: 16 }, () => ({ ok: true }));
    await app.ready();
    const response = await app.inject({
      method: 'POST',
      url: '/test/small',
      headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
      payload: JSON.stringify({ note: 'longer than sixteen bytes' }),
    });
    expect(response.statusCode).toBe(413);
    expect(response.json()).toEqual(errorBody('PAYLOAD_TOO_LARGE', FIRST_ID));
  });

  // The serializer runs zod, so the zod schema is what is checked: the document can show a part
  // tighter than zod sends it, as each of the last five here would be.
  it.each<[string, z.ZodType, string]>([
    ['open to fields it does not name', z.looseObject({ id: z.uuid() }), "answer (open to fields it doesn't name)"],
    ['a field that could be anything', z.object({ id: z.uuid(), extra: z.unknown() }), 'answer.extra (unknown)'],
    ['a field of any kind', z.object({ id: z.uuid(), extra: z.any() }), 'answer.extra (any)'],
    ['a list of anything, deeper down', z.object({ items: z.array(z.unknown()) }), 'answer.items[] (unknown)'],
    [
      'a nested object open to more fields',
      z.object({ owner: z.object({ id: z.uuid() }).catchall(z.string()) }),
      "answer.owner (open to fields it doesn't name)",
    ],
    ['a tuple whose rest could be anything', z.object({ row: z.tuple([z.string()], z.unknown()) }), 'answer.row[rest]'],
    [
      'a map keyed by any text',
      z.object({ byName: z.record(z.string(), z.string()) }),
      'answer.byName (a map whose keys',
    ],
    ['a date', z.object({ at: z.date() }), 'answer.at (date)'],
    ['a default', z.object({ note: z.string().default('x') }), 'answer.note (default)'],
    [
      'a union with a member that could be anything, which the document leaves out',
      z.object({ extra: z.union([z.unknown(), z.object({ id: z.uuid() })]) }),
      'answer.extra (unknown)',
    ],
    ['a codec, whose sent side the document never shows', z.object({ flag: z.stringbool() }), 'answer.flag (pipe)'],
    ['a transform', z.object({ name: z.string().transform((name) => name) }), 'answer.name (pipe)'],
    [
      'an intersection with a map, which the document shows closed',
      z.object({ row: z.object({ id: z.uuid() }).and(z.record(z.string(), z.string())) }),
      'answer.row (intersection)',
    ],
    [
      'a lazy part that turns out open',
      z.object({ later: z.lazy(() => z.looseObject({ id: z.uuid() })) }),
      "answer.later (open to fields it doesn't name)",
    ],
    [
      'a loose map, which the document shows as a map of described values',
      z.object({ tags: z.looseRecord(z.enum(['a']), z.string()) }),
      'answer.tags (a map whose keys',
    ],
  ])('refuses a success answer %s, as it is added', async (_what, answer, where) => {
    const { app } = await server();
    const options = { ...OPEN, schema: { response: { 200: answer } } };
    expect(() => app.get('/test/loose', options, () => ({ id: ITEM_ID }))).toThrow(
      `GET /test/loose: its 200 answer lets through what it doesn't name: ${where}`,
    );
  });

  it('sends an answer under a range written in capitals, which Fastify reads as the range', async () => {
    const { app } = await server();
    const options = { ...OPEN, schema: { response: { '2XX': z.object({ id: z.uuid() }) } } };
    app.get('/test/capital', options, (_request, reply) => reply.code(201).send({ id: ITEM_ID, secret: PLANTED }));
    await app.ready();
    const answer = await app.inject('/test/capital');
    expect(answer.statusCode).toBe(201);
    expect(answer.json()).toEqual({ id: ITEM_ID });
  });

  it('asks no body limit of a TRACE route, whose requests Fastify reads no body for', async () => {
    const { app } = await server();
    app.route({ method: 'TRACE', url: '/test/trace', config: OPEN.config, schema: OPEN.schema, handler: () => 'ok' });
    await app.ready();
    expect(operations(app)).toContain('TRACE /test/trace');
  });

  it('refuses a loose answer under a range written in capitals, which Fastify reads as the range', async () => {
    const { app } = await server();
    const options = { ...OPEN, schema: { response: { '2XX': z.looseObject({ id: z.uuid() }) } } };
    expect(() => app.get('/test/loose', options, () => ({ id: ITEM_ID }))).toThrow(
      "GET /test/loose: its 2XX answer lets through what it doesn't name",
    );
  });

  it('refuses a success answer declared per content type, since Fastify would miss another type', async () => {
    const { app } = await server();
    const item = z.object({ id: z.uuid() });
    const options = { ...OPEN, schema: { response: { 200: { content: { 'application/json': { schema: item } } } } } };
    expect(() => app.get('/test/item', options, () => 'ok')).toThrow(
      'GET /test/item: its 200 answer is not an object with named fields, declared as its schema itself',
    );
  });

  it('refuses an error status whose content names no type', async () => {
    const { app } = await server();
    const options = { ...OPEN, schema: { response: { ...OPEN.schema.response, 409: { content: {} } } } };
    expect(() => app.get('/test/item', options, () => 'ok')).toThrow(
      'GET /test/item: its 409 response names no content type',
    );
  });

  it('takes answers that name all they carry at every depth: lists, tuples, fixed-key maps, optional, nullable, read-only, lazy and union parts', async () => {
    const { app } = await server();
    const node: z.ZodType<{ name: string; children: unknown[] }> = z.object({
      name: z.string(),
      children: z.lazy(() => z.array(node)),
    });
    const answer = z.object({
      items: z.array(z.object({ id: z.uuid() })),
      counts: z.record(z.enum(['open', 'paid']), z.int()),
      only: z.record(z.literal('total'), z.int()),
      owner: z.object({ name: z.string() }).nullable(),
      nickname: z.string().optional(),
      pair: z.tuple([z.string(), z.int()]),
      fixed: z.readonly(z.object({ code: z.literal('A') })),
      kind: z.discriminatedUnion('type', [z.object({ type: z.literal('a') }), z.object({ type: z.literal('b') })]),
      tree: node,
      ref: z.templateLiteral(['agent-', z.int()]),
      state: z.enum(['on', 'off']),
      ready: z.boolean(),
      strictly: z.strictObject({ id: z.uuid() }),
    });
    app.get('/test/tight', { ...OPEN, schema: { response: { 200: answer } } }, () => ({
      items: [],
      counts: { open: 1, paid: 2 },
      only: { total: 3 },
      owner: null,
      pair: ['a', 1],
      fixed: { code: 'A' },
      kind: { type: 'a' },
      tree: { name: 'root', children: [] },
      ref: 'agent-1',
      state: 'on',
      ready: true,
      strictly: { id: ITEM_ID },
    }));
    await app.ready();
    expect((await app.inject('/test/tight')).statusCode).toBe(200);
  });
});

describe('SEC-WEB-06 an object answer goes out only through the schema declared for its status', () => {
  it.each([
    ['a status it declares no answer for', { 201: z.object({ id: z.uuid() }) }, (reply: FastifyReply) => reply],
    [
      'a status the range of its answer does not cover',
      { 200: z.object({ id: z.uuid() }) },
      (reply: FastifyReply) => reply.code(203),
    ],
    [
      'a JSON-like content type Fastify still serializes, but not as the JSON declared',
      { 200: z.object({ id: z.uuid() }) },
      (reply: FastifyReply) => reply.type('application/problem+json'),
    ],
    [
      'an error status in a content type the error answers are not declared for',
      { 200: z.object({ id: z.uuid() }) },
      (reply: FastifyReply) => {
        reply.statusCode = 409;
        return reply.type('application/problem+json');
      },
    ],
  ])('answers an object sent with %s as a failure on our side, showing none of it', async (_what, response, set) => {
    const { app, capture } = await server();
    app.get('/test/row', { ...OPEN, schema: { response } }, (_request, reply) =>
      set(reply).send({ id: ITEM_ID, secret: PLANTED }),
    );
    await app.ready();
    const answer = await app.inject('/test/row');
    expect(answer.statusCode).toBe(500);
    expect(answer.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(capture.lines().filter((line) => line.event === REQUEST_FAILED)).toEqual([
      expect.objectContaining({ err: expect.objectContaining({ type: 'AnswerUndeclared' }) as unknown }),
    ]);
    expect(findLeaks(capture.text, [PLANTED])).toEqual([]);
  });

  it("sends an object under a range it declares, and an error body under the contract's own ranges", async () => {
    const { app } = await server();
    app.post(
      '/test/claim',
      { ...OPEN, schema: { response: { '2xx': z.object({ id: z.uuid() }) } } },
      (_request, reply) => reply.code(201).send({ id: ITEM_ID, secret: PLANTED }),
    );
    const conflict = { ...OPEN, schema: { response: { ...OPEN.schema.response, 409: ERROR_BODY } } };
    app.get('/test/conflict', conflict, (_request, reply) => reply.code(409).send(errorBody('ORG_FROZEN', FIRST_ID)));
    await app.ready();
    const claim = await app.inject({ method: 'POST', url: '/test/claim', headers: { origin: PUBLIC_ORIGIN } });
    expect(claim.statusCode).toBe(201);
    expect(claim.json()).toEqual({ id: ITEM_ID });
    expect((await app.inject('/test/conflict')).statusCode).toBe(409);
  });
});

describe("SEC-WEB-06 a route's own answers above 500 are held to the same rules", () => {
  it.each<[string, Record<number, z.ZodType>, string]>([
    ['a 503 open to fields it does not name', { 503: z.looseObject({ id: z.uuid() }) }, 'its 503 answer lets through'],
    ['a 503 that could be anything', { 503: z.unknown() }, 'its 503 answer is not an object with named fields'],
    ['a 501 map keyed by any text', { 501: z.record(z.string(), z.string()) }, 'its 501 answer is not an object'],
  ])('refuses %s, as it is added', async (_what, extra, problem) => {
    const { app } = await server();
    const options = { ...OPEN, schema: { response: { ...OPEN.schema.response, ...extra } } };
    expect(() => app.get('/test/route', options, () => 'ok')).toThrow(`GET /test/route: ${problem}`);
  });

  it('refuses to start when a later hook adds an open answer of its own to a route', async () => {
    const { app } = await server();
    await app.register(
      (child, _options, done) => {
        child.addHook('onRoute', (route) => {
          const responses = route.schema?.response as Record<string, unknown>;
          responses['503'] = z.looseObject({});
        });
        child.get('/item', OPEN, () => 'ok');
        done();
      },
      { prefix: '/test/plugin' },
    );
    await expect(app.ready()).rejects.toThrow(
      "GET /test/plugin/item: its 503 answer lets through what it doesn't name",
    );
  });
});

describe("SEC-WEB-06 the contract's check of an answer runs after every other hook that could change it", () => {
  it("answers as a failure an object whose status the route's own hook changed before it was written", async () => {
    const { app, capture } = await server();
    const preSerialization = (
      _request: unknown,
      reply: FastifyReply,
      payload: unknown,
      done: (e: null, p: unknown) => void,
    ) => {
      reply.code(201);
      done(null, payload);
    };
    app.get('/test/row', { ...OPEN, preSerialization }, () => ({ ok: true, secret: PLANTED }));
    await app.ready();
    const answer = await app.inject('/test/row');
    expect(answer.statusCode).toBe(500);
    expect(findLeaks(answer.body + capture.text, [PLANTED])).toEqual([]);
  });

  it("answers as a failure an object whose status a plugin's own hook changed before it was written", async () => {
    const { app, capture } = await server();
    await app.register(
      (child, _options, done) => {
        child.addHook('preSerialization', (_request, reply, payload, next) => {
          void reply.code(201);
          next(null, payload);
        });
        child.get('/row', OPEN, () => ({ ok: true, secret: PLANTED }));
        done();
      },
      { prefix: '/test/plugin' },
    );
    await app.ready();
    const answer = await app.inject('/test/plugin/row');
    expect(answer.statusCode).toBe(500);
    expect(findLeaks(answer.body + capture.text, [PLANTED])).toEqual([]);
  });

  it('answers as a failure an object sent on the not-found path, which is no route', async () => {
    const { app, capture } = await server();
    app.addHook('onRequest', (request, reply, done) => {
      if (request.url === '/test/unknown') {
        void reply.send({ ok: true, secret: PLANTED });
        return;
      }
      done();
    });
    await app.ready();
    const answer = await app.inject('/test/unknown');
    expect(answer.statusCode).toBe(500);
    expect(findLeaks(answer.body + capture.text, [PLANTED])).toEqual([]);
  });

  it("refuses to start when a later hook puts a preSerialization hook after the contract's", async () => {
    const { app } = await server();
    await app.register(
      (child, _options, done) => {
        child.addHook('onRoute', (route) => {
          route.preSerialization = [...(route.preSerialization as unknown[]), () => undefined] as never;
        });
        child.get('/item', OPEN, () => 'ok');
        done();
      },
      { prefix: '/test/plugin' },
    );
    await expect(app.ready()).rejects.toThrow(
      "GET /test/plugin/item: a preSerialization hook runs after the contract's check of its answers",
    );
  });

  it("answers as a failure an object a serializer of the reply's own would write whole", async () => {
    const { app, capture } = await server();
    app.get('/test/row', OPEN, (_request, reply) =>
      // eslint-disable-next-line no-restricted-properties -- proves the check catches what lint bans
      reply.serializer((payload) => JSON.stringify(payload)).send({ ok: true, secret: PLANTED }),
    );
    await app.ready();
    const answer = await app.inject('/test/row');
    expect(answer.statusCode).toBe(500);
    expect(findLeaks(answer.body + capture.text, [PLANTED])).toEqual([]);
  });

  it('walks the inner schema zod caches for a lazy part, calling its getter once, as zod does', async () => {
    const { app } = await server();
    const getter = vi.fn(() => z.object({ id: z.uuid() }));
    const answer = z.object({ inner: z.lazy(getter) });
    app.get('/test/lazy', { ...OPEN, schema: { response: { 200: answer } } }, () => ({
      inner: { id: ITEM_ID, secret: PLANTED },
    }));
    await app.ready();
    expect((await app.inject('/test/lazy')).json()).toEqual({ inner: { id: ITEM_ID } });
    expect(getter).toHaveBeenCalledTimes(1);
  });
});

describe('SEC-WEB-06 what the contract wrote into a route must still be there once every plugin has had its say', () => {
  it('refuses to start when a later hook rebuilds a route schema, dropping its access, limit and error answers', async () => {
    const { app } = await server();
    await app.register(
      (child, _options, done) => {
        child.addHook('onRoute', (route) => {
          route.schema = { response: { 200: z.object({ ok: z.literal(true) }) } };
        });
        child.post('/item', OPEN, () => 'ok');
        done();
      },
      { prefix: '/test/plugin' },
    );
    const ready = app.ready();
    await expect(ready).rejects.toThrow("POST /test/plugin/item: its error answers are not the contract's");
    await expect(ready).rejects.toThrow('POST /test/plugin/item: the body limit its document shows is not its own');
    await expect(ready).rejects.toThrow('POST /test/plugin/item: the access its document shows is not its own');
  });
});

describe('SEC-WEB-06 an answer leaves only as the contract wrote it', () => {
  it.each<[string, () => unknown]>([
    ['a string', () => `row ${PLANTED}`],
    ['bytes', () => Buffer.from(`row ${PLANTED}`)],
    ['a stream', () => Readable.from([`row ${PLANTED}`])],
  ])('answers %s a route sent itself as a failure on our side, showing none of it', async (_what, body) => {
    const { app, capture } = await server();
    app.get('/test/raw', OPEN, (_request, reply) => reply.send(body()));
    await app.ready();
    const answer = await app.inject('/test/raw');
    expect(answer.statusCode).toBe(500);
    expect(answer.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(capture.lines().filter((line) => line.event === REQUEST_FAILED)).toEqual([
      expect.objectContaining({ err: expect.objectContaining({ type: 'AnswerUnwritten' }) as unknown }),
    ]);
    expect(findLeaks(answer.body + capture.text, [PLANTED])).toEqual([]);
  });

  it.each<[string, (reply: FastifyReply) => FastifyReply]>([
    ['with no body', (reply) => reply.send()],
    ['as empty text', (reply) => reply.send('')],
  ])('lets an answer go empty, %s, at a status its route declares', async (_what, send) => {
    const { app } = await server();
    app.get('/test/empty', OPEN, (_request, reply) => send(reply));
    await app.ready();
    const answer = await app.inject('/test/empty');
    expect(answer.statusCode).toBe(200);
    expect(answer.body).toBe('');
  });

  it('answers as a failure an empty answer at a status its route does not declare', async () => {
    const { app } = await server();
    app.get('/test/teapot', OPEN, (_request, reply) => {
      reply.statusCode = 418;
      return reply.send();
    });
    await app.ready();
    const answer = await app.inject('/test/teapot');
    expect(answer.statusCode).toBe(500);
    expect(answer.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
  });

  it('refuses an onSend hook on the server or a plugin, which could rewrite an answer after the check', async () => {
    const { app } = await server();
    const hook = (_request: unknown, _reply: unknown, payload: unknown, done: (e: null, p: unknown) => void) => {
      done(null, payload);
    };
    // eslint-disable-next-line no-restricted-syntax -- proves the server refuses what lint bans
    expect(() => app.addHook('onSend', hook)).toThrow(
      'an onSend hook on the server or a plugin could rewrite an answer',
    );
    // eslint-disable-next-line @typescript-eslint/require-await -- an async plugin, so its throw fails ready()
    const plugin = async (child: FastifyInstance): Promise<void> => {
      // eslint-disable-next-line no-restricted-syntax -- proves the server refuses what lint bans
      child.addHook('onSend', hook);
    };
    void app.register(plugin, { prefix: '/test/plugin' });
    await expect(app.ready()).rejects.toThrow('an onSend hook on the server or a plugin could rewrite an answer');
  });

  it("refuses a plugin's own not-found handler without the contract's checks", async () => {
    const { app } = await server();
    // eslint-disable-next-line @typescript-eslint/require-await -- an async plugin, so its throw fails ready()
    const plugin = async (child: FastifyInstance): Promise<void> => {
      // eslint-disable-next-line no-restricted-properties -- proves the server refuses what lint bans
      child.setNotFoundHandler((_request, reply) => reply.send({ leak: PLANTED }));
    };
    void app.register(plugin, { prefix: '/test/plugin' });
    await expect(app.ready()).rejects.toThrow("a not-found handler must carry the contract's checks");
  });

  it('holds the not-found checks fixed, and a handler that carries them to a handler of its own', async () => {
    expect(Object.isFrozen(NOT_FOUND_CHECKS)).toBe(true);
    expect(Object.values(NOT_FOUND_CHECKS).every((hooks) => Object.isFrozen(hooks))).toBe(true);
    const { app } = await server();
    // eslint-disable-next-line @typescript-eslint/require-await -- an async plugin, so its throw fails ready()
    const plugin = async (child: FastifyInstance): Promise<void> => {
      // eslint-disable-next-line no-restricted-properties -- proves the server refuses what lint bans
      const setNotFound = child.setNotFoundHandler.bind(child) as unknown as (opts: object) => void;
      setNotFound(NOT_FOUND_CHECKS);
    };
    void app.register(plugin, { prefix: '/test/plugin' });
    await expect(app.ready()).rejects.toThrow("a not-found handler must carry the contract's checks");
  });

  it("answers as a failure an object a serializer of the reply's own writes, though it says JSON", async () => {
    const { app, capture } = await server();
    app.get('/test/row', OPEN, (_request, reply) => {
      void reply.type('application/json');
      // eslint-disable-next-line no-restricted-properties -- proves the check catches what lint bans
      return reply.serializer((payload) => JSON.stringify(payload)).send({ ok: true, secret: PLANTED });
    });
    await app.ready();
    const answer = await app.inject('/test/row');
    expect(answer.statusCode).toBe(500);
    expect(answer.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(findLeaks(answer.body + capture.text, [PLANTED])).toEqual([]);
  });

  it('closes a stream it refuses, so the stream holds nothing open', async () => {
    const { app } = await server();
    const stream = Readable.from(['row']);
    app.get('/test/stream', OPEN, (_request, reply) => reply.send(stream));
    await app.ready();
    expect((await app.inject('/test/stream')).statusCode).toBe(500);
    expect(stream.destroyed).toBe(true);
  });

  it('lets the HEAD of a GET go, which Fastify empties after it is written', async () => {
    const { app } = await server();
    app.get('/test/row', OPEN, () => ({ ok: true }));
    await app.ready();
    const answer = await app.inject({ method: 'HEAD', url: '/test/row' });
    expect(answer.statusCode).toBe(200);
    expect(answer.body).toBe('');
  });

  it('answers as a failure a string sent on the not-found path, which is no route', async () => {
    const { app, capture } = await server();
    app.addHook('onRequest', (request, reply, done) => {
      if (request.url === '/test/unknown') {
        void reply.send(`row ${PLANTED}`);
        return;
      }
      done();
    });
    await app.ready();
    const answer = await app.inject('/test/unknown');
    expect(answer.statusCode).toBe(500);
    expect(findLeaks(answer.body + capture.text, [PLANTED])).toEqual([]);
  });

  it("refuses Fastify's own name for its HEAD hook on a route that isn't HEAD alone", async () => {
    const { app } = await server();
    function headRouteOnSendHandler(
      _request: unknown,
      _reply: unknown,
      payload: unknown,
      done: (e: null, p: unknown) => void,
    ) {
      done(null, payload);
    }
    const route = { url: '/test/both', ...OPEN, onSend: headRouteOnSendHandler, handler: () => ({ ok: true }) };
    expect(() => app.route({ ...route, method: ['GET', 'HEAD'] })).toThrow(
      'GET,HEAD /test/both: it rewrites its answers after they are written (onSend)',
    );
    expect(() =>
      app.route({ ...route, method: 'HEAD', onSend: [headRouteOnSendHandler, headRouteOnSendHandler] }),
    ).toThrow('HEAD /test/both: it rewrites its answers after they are written (onSend)');
  });

  it("answers as a failure a HEAD route's own hook that borrows Fastify's name to rewrite its answer", async () => {
    const { app } = await server();
    function headRouteOnSendHandler(
      _request: unknown,
      _reply: unknown,
      _payload: unknown,
      done: (e: null, p: unknown) => void,
    ) {
      done(null, `row ${PLANTED}`);
    }
    app.route({
      method: 'HEAD',
      url: '/test/head',
      ...OPEN,
      onSend: headRouteOnSendHandler,
      handler: () => ({ ok: true }),
    });
    await app.ready();
    expect((await app.inject({ method: 'HEAD', url: '/test/head' })).statusCode).toBe(500);
  });

  it('refuses a route with an onSend hook of its own, which could rewrite an answer after it was written', async () => {
    const { app } = await server();
    const onSend = (_request: unknown, _reply: unknown, payload: unknown, done: (e: null, p: unknown) => void) => {
      done(null, payload);
    };
    expect(() => app.get('/test/route', { ...OPEN, onSend }, () => ({ ok: true }))).toThrow(
      'GET /test/route: it rewrites its answers after they are written (onSend)',
    );
  });

  it("refuses to start when a later hook puts an onSend hook after the contract's", async () => {
    const { app } = await server();
    await app.register(
      (child, _options, done) => {
        child.addHook('onRoute', (route) => {
          route.onSend = [...(route.onSend as unknown[]), () => undefined] as never;
        });
        child.get('/item', OPEN, () => ({ ok: true }));
        done();
      },
      { prefix: '/test/plugin' },
    );
    const ready = app.ready();
    await expect(ready).rejects.toThrow(
      "GET /test/plugin/item: an onSend hook runs after the contract's check of what leaves",
    );
    await expect(ready).rejects.toThrow(
      'GET /test/plugin/item: it rewrites its answers after they are written (onSend)',
    );
  });
});

describe('the document names only the schemas it uses', () => {
  const schema = (ref: string) => ({ content: { 'application/json': { schema: { $ref: ref } } } });

  it('keeps each named schema a route refers to, directly or through another, and drops the rest', () => {
    const document = {
      paths: { '/a': { get: { responses: { 200: schema('#/components/schemas/Outer') } } } },
      components: {
        schemas: {
          Outer: { properties: { inner: { $ref: '#/components/schemas/Inner' } } },
          Inner: { type: 'string' },
          OuterInput: { properties: { inner: { $ref: '#/components/schemas/InnerInput' } } },
          InnerInput: { type: 'string' },
        },
      },
    };
    expect(Object.keys(withoutUnusedSchemas(document).components.schemas)).toEqual(['Outer', 'Inner']);
  });

  it('follows only real references: not a "$ref" named as a property or held as a value', () => {
    const document = {
      paths: {
        '/a': {
          get: {
            properties: { $ref: { type: 'string' } },
            enum: ['#/components/schemas/Named'],
            other: { $ref: 'https://example.com/schemas/Named' },
            // As long as the prefix it should have, so a check on length alone would take it.
            header: { $ref: '#/components/headers/Named' },
          },
        },
      },
      components: { schemas: { Named: { type: 'string' } } },
    };
    expect(withoutUnusedSchemas(document).components.schemas).toEqual({});
  });

  it('leaves a document with no named schemas as it is', () => {
    expect(withoutUnusedSchemas({ paths: { '/a': { get: {} } } }).components).toEqual({ schemas: {} });
  });

  it('survives a named schema that refers to itself', () => {
    const document = {
      paths: { '/a': { get: schema('#/components/schemas/Tree') } },
      components: { schemas: { Tree: { properties: { child: { $ref: '#/components/schemas/Tree' } } } } },
    };
    expect(Object.keys(withoutUnusedSchemas(document).components.schemas)).toEqual(['Tree']);
  });
});

describe('SEC-DATA-04, ADR-011 §8 the document names the one error body and every reason code', () => {
  it('gives every operation a 4XX and a 5XX answer in the one error body', async () => {
    const { app } = await server();
    app.post('/test/write', OPEN, () => 'ok');
    await app.ready();
    const document = documentOf(app);
    const answers = Object.values(document.paths).flatMap((item) =>
      Object.values(item).map((operation) => [operation.responses['4XX'], operation.responses['5XX']]),
    );
    // The test's route, /health and the three sign-in routes, with each GET's HEAD.
    expect(answers.length).toBe(8);
    for (const answer of answers.flat()) {
      expect(answer).toMatchObject({
        content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
      });
    }
    expect(Object.keys(document.components.schemas)).toEqual(['Error']);
  });

  it('documents every registered reason code with its public description, and nothing else', async () => {
    const { app } = await server();
    await app.ready();
    const error = REASON_CODES_DOCUMENTED.parse(documentOf(app).components.schemas.Error);
    const documented = error.properties.error.properties.code.anyOf.map((code) => [code.const, code.description]);
    expect(Object.fromEntries(documented)).toEqual(REASON_CODES);
  });

  it('takes the body of every registered code, and refuses a code that is not registered', () => {
    for (const code of Object.keys(REASON_CODES).filter(isReasonCode)) {
      expect(ERROR_BODY.safeParse(errorBody(code, FIRST_ID)).success).toBe(true);
    }
    const unregistered = { error: { code: 'NOT_A_CODE', message: 'x', correlationId: FIRST_ID } };
    expect(ERROR_BODY.safeParse(unregistered).success).toBe(false);
  });
});

describe('every route checks and answers through its own zod schemas', () => {
  async function withRoute() {
    const { app, capture } = await server();
    const reached: unknown[] = [];
    app.post(
      '/test/items/:id',
      {
        ...OPEN,
        schema: {
          params: z.object({ id: z.uuid() }),
          querystring: z.object({ mode: z.enum(['quick', 'full']).optional() }),
          body: z.strictObject({ quantity: z.int().positive() }),
          response: { 200: z.object({ id: z.uuid(), quantity: z.int() }) },
        },
      },
      (request) => {
        reached.push(request.body);
        const { quantity } = request.body as { quantity: number };
        // More than the answer declares: only what its schema names may leave.
        return { id: ITEM_ID, quantity, note: PLANTED };
      },
    );
    app.get('/test/broken', { ...OPEN, schema: { response: { 200: z.object({ quantity: z.int() }) } } }, () => ({
      quantity: PLANTED,
    }));
    await app.ready();
    const post = (url: string, payload: unknown) =>
      app.inject({ method: 'POST', url, headers: { origin: PUBLIC_ORIGIN }, payload: payload as object });
    return { app, capture, reached, post };
  }

  it('answers a valid request with only the fields its answer declares', async () => {
    const { post, reached } = await withRoute();
    const response = await post(`/test/items/${ITEM_ID}`, { quantity: 3 });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ id: ITEM_ID, quantity: 3 });
    expect(reached).toEqual([{ quantity: 3 }]);
  });

  it.each([
    ['a body field of the wrong type', `/test/items/${ITEM_ID}`, { quantity: PLANTED }],
    ['a body field it does not take', `/test/items/${ITEM_ID}`, { quantity: 1, note: PLANTED }],
    ['a missing body', `/test/items/${ITEM_ID}`, undefined],
    ['an address parameter of the wrong form', `/test/items/${encodeURIComponent(PLANTED)}`, { quantity: 1 }],
    ['a query value it does not take', `/test/items/${ITEM_ID}?mode=${encodeURIComponent(PLANTED)}`, { quantity: 1 }],
  ])('refuses %s as BAD_REQUEST, repeating nothing, before the route runs', async (_what, url, payload) => {
    const { post, reached, capture } = await withRoute();
    const response = await post(url, payload);
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('BAD_REQUEST', FIRST_ID));
    expect(reached).toEqual([]);
    expect(findLeaks(capture.text, [PLANTED])).toEqual([]);
  });

  it('answers an answer that breaks its own schema as a failure on our side, showing none of it', async () => {
    const { app, capture } = await withRoute();
    const response = await app.inject('/test/broken');
    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(capture.lines().filter((line) => line.event === REQUEST_FAILED)).toEqual([
      expect.objectContaining({ err: expect.objectContaining({ code: 'FST_ERR_RESPONSE_SERIALIZATION' }) as unknown }),
    ]);
    expect(findLeaks(capture.text, [PLANTED])).toEqual([]);
  });
});
