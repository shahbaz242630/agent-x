// B4-2a: a route naming roles answers a person acting in the organisation the
// request names, in a role the route names, as their verified membership
// there says (access.ts). The membership's own reading and verifying is the
// identity module's (memberships.db.test.ts); here, what the hook does with
// each answer. B3+-1: an admin's and an approver's powers need a session
// signed in with a passkey.
import type { LiveSession, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { type FindMembership, type Member, ORGANIZATION_HEADER } from './access.ts';
import { errorBody } from './errors.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const COOKIE = 'S'.repeat(43);
/** A session of the same person signed in with an authenticator app, not a passkey. */
const APP_COOKIE = 'A'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const MEMBERSHIP = '0199a0f0-0000-7000-8000-000000000033';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-09-24T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-24T09:10:00.000Z'),
  endsAt: new Date('2026-09-24T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-24T09:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) =>
    Promise.resolve(
      cookie === COOKIE ? LIVE : cookie === APP_COOKIE ? { ...LIVE, amr: ['pwd', 'otp', 'mfa'] } : undefined,
    ),
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** What the lookup was asked, and what it answered. */
interface Lookup {
  readonly asked: [orgId: string, userId: string, correlationId: string][];
}

/** A server whose lookup answers `check` for the one organisation, and none for any other. */
async function withRoutes(check: MembershipCheck | Error | undefined, options: { signIn?: boolean } = {}) {
  const lookup: Lookup = { asked: [] };
  const findMembership: FindMembership | undefined =
    check === undefined
      ? undefined
      : (orgId, userId, correlationId) => {
          lookup.asked.push([orgId, userId, correlationId]);
          if (check instanceof Error) return Promise.reject(check);
          return Promise.resolve(orgId.toLowerCase() === ORG ? check : { outcome: 'none' });
        };
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
  const capture = new LogCapture();
  const app = await buildServer({
    config,
    logger: createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...config },
      destination: capture,
    }),
    ids: new SequentialIds(),
    healthChecks: [],
    ...((options.signIn ?? true) && { signIn: { service: SIGN_IN, sessionSeconds: 43_200 } }),
    findMembership,
  });
  servers.push(app);
  const reached: { member: Member | null; person: LiveSession | null }[] = [];
  const answer: RouteShorthandOptions = {
    bodyLimit: 1024,
    schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
  };
  app.get('/v1/test-members', { ...answer, config: { access: ['admin', 'viewer'] } }, (request) => {
    reached.push({ member: request.member, person: request.person });
    return { ok: true };
  });
  app.post(
    '/v1/test-members',
    { ...answer, config: { access: ['admin'], operation: 'test-members.invite' } },
    (request) => {
      reached.push({ member: request.member, person: request.person });
      return { ok: true };
    },
  );
  app.get('/v1/test-own', { ...answer, config: { access: ['person'] } }, (request) => {
    reached.push({ member: request.member, person: request.person });
    return { ok: true };
  });
  app.get('/v1/test-approvals', { ...answer, config: { access: ['approver'] } }, (request) => {
    reached.push({ member: request.member, person: request.person });
    return { ok: true };
  });
  app.get('/v1/test-builds', { ...answer, config: { access: ['admin', 'developer'] } }, (request) => {
    reached.push({ member: request.member, person: request.person });
    return { ok: true };
  });
  app.get(
    '/v1/test-reads',
    { ...answer, config: { access: ['admin', 'approver', 'developer', 'viewer'] } },
    (request) => {
      reached.push({ member: request.member, person: request.person });
      return { ok: true };
    },
  );
  app.get('/v1/test-agents', { ...answer, config: { access: ['agent'] } }, () => ({ ok: true }));
  app.get('/v1/test-shared', { ...answer, config: { access: ['admin', 'agent'] } }, (request) => {
    reached.push({ member: request.member, person: request.person });
    return { ok: true };
  });
  await app.ready();
  return { app, reached, lookup, capture };
}

const signedIn = (extra: Partial<InjectOptions> & { org?: string | null } = {}): InjectOptions => {
  const { org = ORG, headers, ...rest } = extra;
  return {
    method: 'GET',
    url: '/v1/test-members',
    headers: {
      cookie: `${SESSION_COOKIE}=${COOKIE}`,
      ...(org !== null && { [ORGANIZATION_HEADER]: org }),
      ...headers,
    },
    ...rest,
  };
};

const ACTIVE = (role: 'admin' | 'approver' | 'developer' | 'viewer'): MembershipCheck => ({
  outcome: 'active',
  id: MEMBERSHIP,
  role,
});

describe('BR-04 a route naming roles answers a member of the organisation the request names, in one of them', () => {
  it.each(['admin', 'viewer'] as const)(
    'lets an active %s through, with their membership on the request, as the lookup read it',
    async (role) => {
      const { app, reached, lookup } = await withRoutes(ACTIVE(role));

      const response = await app.inject(signedIn());

      expect(response.statusCode).toBe(200);
      expect(reached).toEqual([{ member: { orgId: ORG, membershipId: MEMBERSHIP, role }, person: LIVE }]);
      expect(lookup.asked).toEqual([[ORG, LIVE.userId, FIRST_ID]]);
    },
  );

  it('keeps the organisation in lower case, however the header wrote it', async () => {
    const { app, reached, lookup } = await withRoutes(ACTIVE('admin'));

    const response = await app.inject(signedIn({ org: ORG.toUpperCase() }));

    expect(response.statusCode).toBe(200);
    expect(reached[0]?.member?.orgId).toBe(ORG);
    expect(lookup.asked[0]?.[0]).toBe(ORG.toUpperCase());
  });

  it.each<[string, MembershipCheck, 'GET' | 'POST']>([
    ['a role the route does not name', ACTIVE('approver'), 'GET'],
    ['another role, on a write only admins make', ACTIVE('viewer'), 'POST'],
    ['a deactivated membership', { outcome: 'deactivated', id: MEMBERSHIP }, 'GET'],
    ['no membership there', { outcome: 'none' }, 'GET'],
    ['a membership tampered with', { outcome: 'tampered', sign: 'seal' }, 'GET'],
  ])('refuses %s as FORBIDDEN, before the route runs', async (_, check, method) => {
    const { app, reached } = await withRoutes(check);

    const response = await app.inject(
      signedIn({
        method,
        headers: { origin: PUBLIC_ORIGIN, 'idempotency-key': 'k-1' },
      }),
    );

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('FORBIDDEN', FIRST_ID));
    expect(reached).toEqual([]);
  });

  it('refuses an organisation the person isn’t in exactly as one that doesn’t exist: FORBIDDEN, never NOT_FOUND', async () => {
    const { app, reached } = await withRoutes(ACTIVE('admin'));

    const response = await app.inject(signedIn({ org: '0199a0f0-0000-7000-8000-00000000ffff' }));

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('FORBIDDEN', FIRST_ID));
    expect(reached).toEqual([]);
  });

  it.each([
    ['no header', null],
    ['an empty one', ''],
    ['one that is not an ID', 'acme'],
    ['an ID with something after it', `${ORG} `],
    ['two IDs', `${ORG},${ORG}`],
  ] as const)('refuses %s as ORGANIZATION_INVALID, without asking who the person is there', async (_, org) => {
    const { app, reached, lookup } = await withRoutes(ACTIVE('admin'));

    const response = await app.inject(signedIn({ org }));

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(errorBody('ORGANIZATION_INVALID', FIRST_ID));
    expect(reached).toEqual([]);
    expect(lookup.asked).toEqual([]);
  });

  it('asks who is signed in first: no session is UNAUTHENTICATED, header or not', async () => {
    const { app, lookup } = await withRoutes(ACTIVE('admin'));

    for (const org of [ORG, null]) {
      const response = await app.inject({
        method: 'GET',
        url: '/v1/test-members',
        headers: { ...(org !== null && { [ORGANIZATION_HEADER]: org }) },
      });
      expect(response.statusCode).toBe(401);
    }
    expect(lookup.asked).toEqual([]);
  });

  it('refuses every role with no lookup at all, as no one holds one', async () => {
    const { app, reached } = await withRoutes(undefined);

    const response = await app.inject(signedIn());

    expect(response.statusCode).toBe(403);
    expect(reached).toEqual([]);
  });

  it('fails as INTERNAL_ERROR when the lookup fails, never letting the request through', async () => {
    const { app, reached, capture } = await withRoutes(new Error('the database is away'));

    const response = await app.inject(signedIn());

    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(reached).toEqual([]);
    expect(capture.lines()).toContainEqual(expect.objectContaining({ level: 'error', correlationId: FIRST_ID }));
  });

  it("answers a person's own route without the header or a lookup, and puts no membership on it", async () => {
    const { app, reached, lookup } = await withRoutes(ACTIVE('admin'));

    const response = await app.inject(signedIn({ url: '/v1/test-own', org: null }));

    expect(response.statusCode).toBe(200);
    expect(reached).toEqual([{ member: null, person: LIVE }]);
    expect(lookup.asked).toEqual([]);
  });

  it('lets an admin through on a route that names agents beside roles, and refuses another role there', async () => {
    const admin = await withRoutes(ACTIVE('admin'));
    const viewer = await withRoutes(ACTIVE('viewer'));

    expect((await admin.app.inject(signedIn({ url: '/v1/test-shared' }))).statusCode).toBe(200);
    expect(admin.reached).toEqual([{ member: { orgId: ORG, membershipId: MEMBERSHIP, role: 'admin' }, person: LIVE }]);
    expect((await viewer.app.inject(signedIn({ url: '/v1/test-shared' }))).statusCode).toBe(403);
  });

  it.each([
    ['admin', 'POST', '/v1/test-members'],
    ['admin', 'GET', '/v1/test-shared'],
    ['approver', 'GET', '/v1/test-approvals'],
  ] as const)(
    'SEC-HA-12 refuses an active %s signed in with an app code, not a passkey, on %s %s as PASSKEY_REQUIRED',
    async (role, method, url) => {
      const { app, reached } = await withRoutes(ACTIVE(role));
      const withApp = { cookie: `${SESSION_COOKIE}=${APP_COOKIE}`, origin: PUBLIC_ORIGIN, 'idempotency-key': 'k-1' };

      const response = await app.inject(signedIn({ method, url, headers: withApp }));

      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual(errorBody('PASSKEY_REQUIRED', FIRST_ID));
      expect(reached).toEqual([]);
      expect(
        (await app.inject(signedIn({ method, url, headers: { ...withApp, cookie: `${SESSION_COOKIE}=${COOKIE}` } })))
          .statusCode,
      ).toBe(200);
    },
  );

  it.each([
    ['admin', '/v1/test-members'],
    ['admin', '/v1/test-builds'],
    ['approver', '/v1/test-reads'],
  ] as const)(
    'SEC-HA-12 keeps what a developer or a viewer may do for an active %s with an app code: %s',
    async (role, url) => {
      const { app, reached } = await withRoutes(ACTIVE(role));

      const response = await app.inject(signedIn({ url, headers: { cookie: `${SESSION_COOKIE}=${APP_COOKIE}` } }));

      expect(response.statusCode).toBe(200);
      expect(reached).toMatchObject([{ member: { role } }]);
    },
  );

  it.each(['developer', 'viewer'] as const)(
    'lets an active %s with an app code through where their role is named, and refuses them elsewhere as FORBIDDEN, not for a passkey',
    async (role) => {
      const { app } = await withRoutes(ACTIVE(role));
      const headers = { cookie: `${SESSION_COOKIE}=${APP_COOKIE}` };

      expect(
        (await app.inject(signedIn({ url: role === 'viewer' ? '/v1/test-members' : '/v1/test-builds', headers })))
          .statusCode,
      ).toBe(200);
      const refused = await app.inject(signedIn({ url: '/v1/test-approvals', headers }));
      expect(refused.json()).toEqual(
        errorBody('FORBIDDEN', refused.json<{ error: { correlationId: string } }>().error.correlationId),
      );
    },
  );

  it("refuses a person on an agent's route as FORBIDDEN, whatever organisation they name", async () => {
    const { app, lookup } = await withRoutes(ACTIVE('admin'));

    const response = await app.inject(signedIn({ url: '/v1/test-agents' }));

    expect(response.statusCode).toBe(403);
    expect(lookup.asked).toEqual([]);
  });

  it('shows the header as required on each operation of a route naming roles, and on no other', async () => {
    const { app } = await withRoutes(ACTIVE('admin'));
    const paths = app.swagger().paths ?? {};
    const headerOf = (path: string, method: 'get' | 'post' | 'head') =>
      (paths[path]?.[method]?.parameters ?? []).find(
        (parameter) => 'name' in parameter && parameter.name === ORGANIZATION_HEADER,
      );

    for (const method of ['get', 'head', 'post'] as const) {
      expect(headerOf('/v1/test-members', method)).toMatchObject({ in: 'header', required: true });
    }
    expect(headerOf('/v1/test-shared', 'get')).toMatchObject({ in: 'header', required: true });
    expect(headerOf('/v1/test-own', 'get')).toBeUndefined();
    expect(headerOf('/v1/test-agents', 'get')).toBeUndefined();
  });
});

describe("the contract holds a route naming roles to the organisation's header", () => {
  const ROLE_ROUTE = {
    bodyLimit: 1024,
    config: { access: ['admin'] },
    schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
  } as const satisfies RouteShorthandOptions;

  /** A server with no routes of these tests' own yet, not ready. */
  async function bareServer() {
    const app = await buildServer({
      config: {
        http: {
          host: '127.0.0.1',
          port: 0,
          publicOrigin: PUBLIC_ORIGIN,
          trustedProxies: [],
          rateLimitPerMinute: 1000,
          rateLimitPerUserPerMinute: 1000,
        },
        log: { level: 'info', eventCapPerMinute: 10_000 },
      },
      logger: createLogger({
        service: 'api',
        config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
        destination: new LogCapture(),
      }),
      ids: new SequentialIds(),
      healthChecks: [],
    });
    servers.push(app);
    return app;
  }

  it("refuses a route whose own headers schema isn't an object, which couldn't carry the header", async () => {
    const app = await bareServer();
    const options = { ...ROLE_ROUTE, schema: { ...ROLE_ROUTE.schema, headers: z.string() } };

    expect(() => app.get('/v1/test-roles', options, () => ({ ok: true }))).toThrow(
      "GET /v1/test-roles: it names roles, but its headers schema is not an object to carry the organisation's header",
    );
  });

  it.each([
    ['drops its headers', () => undefined],
    ['swaps the header for a looser one', () => z.object({ [ORGANIZATION_HEADER]: z.string() })],
    ['keeps its own headers without it', () => z.object({ 'x-agentx-test': z.string() })],
  ])("refuses to start when a later hook %s, so the document wouldn't show it", async (_what, headers) => {
    const app = await bareServer();
    await app.register((child, _options, done) => {
      child.addHook('onRoute', (route) => {
        route.schema = { ...route.schema, headers: headers() };
      });
      child.get('/v1/test-roles', ROLE_ROUTE, () => ({ ok: true }));
      done();
    });

    await expect(app.ready()).rejects.toThrow(
      "GET /v1/test-roles: its document doesn't show the organisation's header it requires (headers)",
    );
  });
});
