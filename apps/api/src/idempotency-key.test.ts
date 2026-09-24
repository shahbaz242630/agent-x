import type { LiveSession, SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { ContractBroken } from './contract.ts';
import { errorBody } from './errors.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const COOKIE = 'S'.repeat(43);

/** A live session, as the sign-in finds it for the one cookie it knows. */
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
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function server() {
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
  return app;
}

/** A signed-in person's own write, named `profile.update`; its answer isn't what these tests are about. */
const WRITE = {
  config: { access: ['person'], operation: 'profile.update' },
  bodyLimit: 1024,
  schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
} as const satisfies RouteShorthandOptions;

/** A server with the write, recording each time it runs. */
async function withWrite(options: RouteShorthandOptions = WRITE) {
  const app = await server();
  const reached: unknown[] = [];
  app.post('/v1/profile', options, (request) => {
    reached.push(request.headers);
    return { ok: true };
  });
  app.post('/v1/open', { ...WRITE, config: { access: ['public'] } }, () => ({ ok: true }));
  app.get('/v1/profile', { ...WRITE, config: { access: ['person'] } }, () => ({ ok: true }));
  await app.ready();
  return { app, reached };
}

/** The signed-in person's write from our own origin, with the key given (none when undefined). */
const signedInWrite = (key?: string, extra: Partial<InjectOptions> = {}): InjectOptions => ({
  method: 'POST',
  url: '/v1/profile',
  headers: {
    origin: PUBLIC_ORIGIN,
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    ...(key !== undefined && { 'idempotency-key': key }),
  },
  ...extra,
});

describe('SEC-DP-07 a write carries its idempotency key', () => {
  it.each([
    ['a UUID', '0199a0f0-0000-7000-8000-000000000099'],
    ['one character', 'k'],
    ['255 characters', 'k'.repeat(255)],
    ['every visible ASCII character', '!"#$%&\'()*+,-./09:;<=>?@AZ[\\]^_`az{|}~'],
  ])('lets a write through with %s as its key', async (_what, key) => {
    const { app, reached } = await withWrite();
    const response = await app.inject(signedInWrite(key));
    expect(response.statusCode).toBe(200);
    expect(reached).toHaveLength(1);
  });

  it.each<[string, string | undefined]>([
    ['no key', undefined],
    ['an empty key', ''],
    ['256 characters', 'k'.repeat(256)],
    ['a space inside', 'two words'],
    ['a character past ASCII', 'clé'],
    // Node joins a header sent twice into one value with a comma and a space.
    ['the header sent twice, as Node joins it', 'first, second'],
  ])('refuses a write with %s as IDEMPOTENCY_KEY_INVALID, before the route runs', async (_what, key) => {
    const { app, reached } = await withWrite();
    const response = await app.inject(signedInWrite(key));
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('IDEMPOTENCY_KEY_INVALID', FIRST_ID));
    expect(reached).toEqual([]);
  });

  it('refuses before the body is read, so a body over the limit is still IDEMPOTENCY_KEY_INVALID', async () => {
    const { app } = await withWrite();
    const response = await app.inject(
      signedInWrite(undefined, {
        headers: {
          origin: PUBLIC_ORIGIN,
          cookie: `${SESSION_COOKIE}=${COOKIE}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ note: 'x'.repeat(70_000) }),
      }),
    );
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('IDEMPOTENCY_KEY_INVALID', FIRST_ID));
  });

  it('asks who is calling first: no session and no key is UNAUTHENTICATED', async () => {
    const { app } = await withWrite();
    const response = await app.inject({ method: 'POST', url: '/v1/profile', headers: { origin: PUBLIC_ORIGIN } });
    expect(response.statusCode).toBe(401);
  });

  it('asks no key of a read or a public write', async () => {
    const { app } = await withWrite();
    const read = await app.inject({
      method: 'GET',
      url: '/v1/profile',
      headers: { cookie: `${SESSION_COOKIE}=${COOKIE}` },
    });
    expect(read.statusCode).toBe(200);
    const open = await app.inject({ method: 'POST', url: '/v1/open', headers: { origin: PUBLIC_ORIGIN } });
    expect(open.statusCode).toBe(200);
  });

  it('keeps every header the route was sent, besides those its own headers schema names', async () => {
    const { app, reached } = await withWrite({
      ...WRITE,
      schema: { ...WRITE.schema, headers: z.object({ 'x-agentx-test': z.literal('yes') }) },
    });
    const refused = await app.inject(signedInWrite('k-1'));
    expect(refused.statusCode).toBe(400);
    expect(refused.json()).toEqual(errorBody('BAD_REQUEST', FIRST_ID));
    const response = await app.inject(
      signedInWrite('k-1', {
        headers: {
          origin: PUBLIC_ORIGIN,
          cookie: `${SESSION_COOKIE}=${COOKIE}`,
          'idempotency-key': 'k-1',
          'x-agentx-test': 'yes',
        },
      }),
    );
    expect(response.statusCode).toBe(200);
    expect(reached).toEqual([
      expect.objectContaining({ 'idempotency-key': 'k-1', 'x-agentx-test': 'yes', origin: PUBLIC_ORIGIN }),
    ]);
  });
});

/** The header parameters of the document's POST /v1/profile. */
const OPERATION = z.object({
  parameters: z.array(
    z.object({
      in: z.string(),
      name: z.string(),
      required: z.boolean().optional(),
      description: z.string().optional(),
      schema: z.unknown(),
    }),
  ),
});

describe('SEC-DP-07 the document shows the key each write requires', () => {
  it('shows it as a required header of the write, with its form, and on no read', async () => {
    const { app } = await withWrite();
    const paths = app.swagger().paths ?? {};
    const write = OPERATION.parse(paths['/v1/profile']?.post);
    expect(write.parameters).toEqual([
      {
        in: 'header',
        name: 'idempotency-key',
        required: true,
        description: expect.stringContaining('safe to retry') as unknown,
        schema: { type: 'string', pattern: '^[!-~]{1,255}$' },
      },
    ]);
    expect(paths['/v1/profile']?.get).not.toHaveProperty('parameters');
    expect(paths['/v1/open']?.post).not.toHaveProperty('parameters');
  });

  it("refuses a write whose own headers schema isn't an object, which couldn't carry the key", async () => {
    const app = await server();
    const options = { ...WRITE, schema: { ...WRITE.schema, headers: z.string() } };
    expect(() => app.post('/v1/profile', options, () => ({ ok: true }))).toThrow(ContractBroken);
    expect(() => app.post('/v1/profile', options, () => ({ ok: true }))).toThrow(
      'POST /v1/profile: it names an operation, but its headers schema is not an object',
    );
  });

  it.each([
    ['drops its headers', () => undefined],
    ['swaps the key for a looser one', () => z.object({ 'idempotency-key': z.string() }).loose()],
    ['keeps its own headers without the key', () => z.object({ 'x-agentx-test': z.string() })],
  ])("refuses to start when a later hook %s, so the document wouldn't show the key", async (_what, headers) => {
    const app = await server();
    await app.register((child, _options, done) => {
      child.addHook('onRoute', (route) => {
        route.schema = { ...route.schema, headers: headers() };
      });
      child.post('/v1/profile', WRITE, () => ({ ok: true }));
      done();
    });
    await expect(app.ready()).rejects.toThrow(
      "POST /v1/profile: its document doesn't show the idempotency key it requires (headers)",
    );
  });
});
