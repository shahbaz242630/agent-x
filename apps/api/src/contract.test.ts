import { type IdGenerator, isReasonCode, REASON_CODES } from '@agentx/core/shared-kernel';
import { createLogger } from '@agentx/platform/observability';
import { findLeaks, LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { ContractBroken, routeTableProblems, withoutUnusedSchemas } from './contract.ts';
import { ERROR_BODY, errorBody } from './errors.ts';
import { REQUEST_FAILED } from './request-log.ts';
import { buildServer } from './server.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
/** A marker value that must never come out. Plain words, so secret scanners ignore it. */
const PLANTED = 'planted value that must not appear';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const ITEM_ID = '0190f4c2-1e5b-7c3d-8a9b-0c1d2e3f4a5b';

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
    app.get('/test/items/:ref', () => 'ok');
    app.route({ method: ['POST', 'PUT'], url: '/test/both', handler: () => 'ok' });
    await app.register(
      (child, _options, done) => {
        child.delete('/things/:id', () => 'ok');
        done();
      },
      { prefix: '/test/nested' },
    );
    await app.ready();
    expect(operations(app).sort()).toEqual([
      'DELETE /test/nested/things/{id}',
      'GET /health',
      'GET /test/items/{ref}',
      'HEAD /health',
      'HEAD /test/items/{ref}',
      'POST /test/both',
      'PUT /test/both',
    ]);
  });

  it.each([
    ['marked hidden', { hide: true }],
    ["tagged with the document's hidden tag", { tags: ['X-HIDDEN'] }],
  ])('refuses to start with a route %s, naming it and its HEAD', async (_how, schema) => {
    const { app } = await server();
    app.get('/test/debug', { schema }, () => 'ok');
    const ready = app.ready();
    await expect(ready).rejects.toThrow(ContractBroken);
    await expect(ready).rejects.toMatchObject({
      problems: ['GET /test/debug is served but not documented', 'HEAD /test/debug is served but not documented'],
    });
  });

  it("documents a route under the provider's own skip list rather than leaving it out", async () => {
    const { app } = await server();
    app.get('/documentation/json', () => 'ok');
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

  it('takes an answer declared for each content type in zod, and documents it with its description', async () => {
    const { app } = await server();
    const item = z.object({ id: z.uuid() });
    const response = { 200: { description: 'The item.', content: { 'application/json': { schema: item } } } };
    app.get('/test/item', { schema: { response } }, () => ({ id: ITEM_ID, note: PLANTED }));
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
    app.post('/test/claim', { schema: { response } }, () => ({ id: ITEM_ID }));
    await app.ready();
    expect(documentOf(app).paths['/test/claim']?.post?.responses['409']).toMatchObject({
      description: 'Another request holds the key.',
    });
  });

  it('refuses to start with a twin of a route, served by a stricter address pattern', async () => {
    const { app } = await server();
    app.get('/test/a/:id', () => 'ok');
    app.get('/test/a/:id(^[0-9]+$)', () => 'twin');
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
      child.get('/', () => 'ok');
    };
    void app.register(plugin, { prefix: '/test/p' });
    await expect(app.ready()).rejects.toThrow("GET /test/p: it sits at its prefix's root");
  });

  it("serves and documents a route at its prefix's root in the one form it chose", async () => {
    const { app } = await server();
    await app.register(
      (child, _options, done) => {
        child.get('/', { prefixTrailingSlash: 'no-slash' }, () => 'ok');
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
    app.get('/test/when', { schema: { response: { 200: z.object({ at: z.date() }) } } }, () => ({ at: new Date() }));
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
    child.get('/item', () => 'ok');
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

describe('SEC-DATA-04 every error answer is written as it is, never through a route schema', () => {
  // A correlation ID the error body's schema would refuse, so an answer written through it would fail.
  const odd: IdGenerator = { next: () => 'not-a-uuid' };

  it.each([
    ['a refused body', 'POST', { origin: PUBLIC_ORIGIN }, { quantity: 'many' }, 400, 'BAD_REQUEST'],
    ['a refused origin', 'POST', {}, { quantity: 1 }, 403, 'ORIGIN_REFUSED'],
    ['a failure on our side', 'GET', {}, undefined, 500, 'INTERNAL_ERROR'],
  ] as const)('answers %s', async (_what, method, headers, payload, status, code) => {
    const { app } = await server(odd);
    const schema = { body: z.object({ quantity: z.int() }), response: { 200: z.object({ quantity: z.int() }) } };
    app.post('/test/item', { schema }, () => ({ quantity: 1 }));
    app.get('/test/item', { schema: { response: schema.response } }, () => {
      throw new Error('failed on our side');
    });
    await app.ready();
    const response = await app.inject({ method, url: '/test/item', headers, ...(payload && { payload }) });
    expect(response.statusCode).toBe(status);
    expect(response.json()).toEqual(errorBody(code, 'not-a-uuid'));
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
    app.post('/test/write', () => 'ok');
    await app.ready();
    const document = documentOf(app);
    const answers = Object.values(document.paths).flatMap((item) =>
      Object.values(item).map((operation) => [operation.responses['4XX'], operation.responses['5XX']]),
    );
    expect(answers.length).toBe(3);
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
    app.get('/test/broken', { schema: { response: { 200: z.object({ quantity: z.int() }) } } }, () => ({
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
