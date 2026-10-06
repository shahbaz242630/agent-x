// C2-1 (ADR-011 §1, SEC-AG-01, SEC-AG-02, SEC-WEB-01): an agent's request,
// sent with its key as a bearer token, through the access hook, the Origin
// rule and the contract, with the key check stood in for (its own tests,
// key-check.db.test.ts, hold what it accepts).
import type { AcceptedKey, KeyChecked } from '@agentx/core/modules/agents';
import type { LiveSession, SignIn } from '@agentx/core/modules/identity';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, FastifySchema, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  AGENT_CHALLENGE,
  agentOf,
  agentScopeProblems,
  bearerToken,
  type CheckAgentKey,
  SESSION_CHALLENGE,
} from './access.ts';
import { errorBody } from './errors.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';
const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const COOKIE = 'C'.repeat(43);

const ACCEPTED: AcceptedKey = {
  orgId: '0199a0f0-0000-7000-8000-00000000abcd',
  agentId: '0199a0f0-0000-7000-8000-0000000000a1',
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes: ['requests:read', 'suppliers:read'],
  expiresAt: new Date('2026-12-28T09:00:00.000Z'),
};

const SESSION: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000201',
  userId: '0199a0f0-0000-7000-8000-000000000101',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-09-24T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-09-24T09:00:05.000Z'),
  lastSeenAt: new Date('2026-09-24T09:10:00.000Z'),
  endsAt: new Date('2026-09-24T21:00:05.000Z'),
  idleEndsAt: new Date('2026-09-24T09:40:00.000Z'),
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** What the stand-ins were asked: the key texts checked, and the cookies looked up. */
interface Asked {
  readonly keys: { readonly text: string; readonly correlationId: string }[];
  readonly cookies: string[];
  readonly reached: { readonly route: string; readonly agent: AcceptedKey | null; readonly person: unknown }[];
}

/** A key check that accepts KEY alone, as ACCEPTED, unless told what to answer. */
const acceptingKey =
  (asked: Asked, answer?: () => Promise<KeyChecked>): CheckAgentKey =>
  (text, correlationId) => {
    asked.keys.push({ text, correlationId });
    if (answer !== undefined) return answer();
    return Promise.resolve(text === KEY ? { outcome: 'accepted', key: ACCEPTED } : { outcome: 'refused' });
  };

/** A route's options, its access and scopes typed loosely so a test can hand over wrong ones. */
const withAccess = (access: unknown, agentScopes?: unknown): RouteShorthandOptions => ({
  config: { access, ...(agentScopes !== undefined && { agentScopes }) } as NonNullable<RouteShorthandOptions['config']>,
  bodyLimit: 1024,
  schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
});

async function server(
  { checkKey, noCheck = false }: { checkKey?: (asked: Asked) => CheckAgentKey; noCheck?: boolean } = {},
  routes?: (app: FastifyInstance, asked: Asked) => void,
) {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 100,
      rateLimitPerUserPerMinute: 100,
      rateLimitPerAgentPerMinute: 100,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: new LogCapture(),
  });
  const asked: Asked = { keys: [], cookies: [], reached: [] };
  const signIn: SignIn = {
    begin: () => Promise.reject(new Error('not here')),
    beginStepUp: () => Promise.reject(new Error('not here')),
    complete: () => Promise.reject(new Error('not here')),
    signOut: () => Promise.resolve(undefined),
    signedIn: (cookie) => {
      asked.cookies.push(cookie);
      return Promise.resolve(cookie === COOKIE ? SESSION : undefined);
    },
  };
  const app = await buildServer({
    config,
    logger,
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: { service: signIn, sessionSeconds: 43_200 },
    checkAgentKey: noCheck ? undefined : (checkKey ?? ((a) => acceptingKey(a)))(asked),
  });
  servers.push(app);
  const reach =
    (route: string) =>
    ({ agent, person }: { agent: AcceptedKey | null; person: unknown }) => {
      asked.reached.push({ route, agent, person });
      return { ok: true as const };
    };
  if (routes === undefined) {
    app.get('/test/agent', withAccess(['agent'], []), (request) => reach('agent read')(request));
    app.get('/test/suppliers', withAccess(['agent'], ['suppliers:read']), (request) => reach('suppliers')(request));
    app.get('/test/writes', withAccess(['agent'], ['requests:write']), (request) => reach('writes')(request));
    const write = withAccess(['agent'], []);
    app.post('/test/agent', { ...write, config: { ...write.config, operation: 'test.agent-write' } }, (request) =>
      reach('agent write')(request),
    );
    app.get('/test/mine', withAccess(['person']), (request) => reach('mine')(request));
    const personWrite = withAccess(['person']);
    app.post(
      '/test/mine',
      { ...personWrite, config: { ...personWrite.config, operation: 'test.person-write' } },
      (request) => reach('person write')(request),
    );
  } else {
    routes(app, asked);
  }
  await app.ready();
  return { app, asked };
}

const bearer = (text = KEY) => ({ authorization: `Bearer ${text}` });

describe('C2-1 the contract: every route naming agents says which scopes their keys need', () => {
  it.each<[string, unknown, unknown]>([
    ['agents with no scope needed', ['agent'], []],
    ['agents with scopes', ['agent'], ['suppliers:read', 'requests:read']],
    ['a route not naming agents, with none', ['admin'], undefined],
  ])('takes %s', (_what, access, scopes) => {
    expect(agentScopeProblems(access, scopes)).toEqual([]);
  });

  it.each<[string, unknown, unknown, string]>([
    ['agents without scopes', ['agent'], undefined, 'not the scopes their keys need'],
    ['agents with scopes not a list', ['agent'], 'requests:read', 'not the scopes their keys need'],
    ['a scope there is not', ['agent'], ['requests:delete'], "name one there isn't"],
    ['a scope in the wrong case', ['agent'], ['Requests:read'], "name one there isn't"],
    ['a scope twice', ['agent'], ['requests:read', 'requests:read'], 'name one twice'],
    ['scopes on a route not naming agents', ['admin'], [], 'names scopes for agents, but not agents'],
    ['scopes with no access at all', undefined, ['requests:read'], 'names scopes for agents, but not agents'],
  ])('refuses %s', (_what, access, scopes, problem) => {
    expect(agentScopeProblems(access, scopes).join('; ')).toContain(problem);
  });

  it('refuses a list of scopes with a hole in it, which every() alone would skip', () => {
    const sparse: unknown[] = [];
    sparse[1] = 'requests:read';
    expect(agentScopeProblems(['agent'], sparse)).toEqual([expect.stringContaining("name one there isn't")]);
  });

  it('refuses, as it is added, a route naming agents without their scopes', async () => {
    await expect(
      server({}, (app) => {
        app.get('/test/route', withAccess(['agent']), () => ({ ok: true }));
      }),
    ).rejects.toThrow('GET /test/route: it names agents, but not the scopes their keys need');
  });

  it('refuses a route that writes its own scopes into the document', async () => {
    const schema: FastifySchema & Record<string, unknown> = { 'x-agent-scopes': [] };
    await expect(
      server({}, (app) => {
        app.get('/test/route', { ...withAccess(['agent'], ['requests:write']), schema }, () => ({ ok: true }));
      }),
    ).rejects.toThrow('the agent scopes its document shows are not its own');
  });

  it('shows each agent route’s scopes in the document, held to those it was added with', async () => {
    const scopes = ['suppliers:read'];
    const { app, asked } = await server({}, (app, asked) => {
      app.get('/test/suppliers', withAccess(['agent'], scopes), () => {
        asked.reached.push({ route: 'suppliers', agent: null, person: null });
        return { ok: true };
      });
    });
    scopes.splice(0, 1, 'requests:write');
    const documented = app.swagger().paths?.['/test/suppliers']?.get as Record<string, unknown> | undefined;
    expect(documented?.['x-agent-scopes']).toEqual(['suppliers:read']);
    expect(Object.isFrozen(documented?.['x-agent-scopes'])).toBe(true);
    expect((await app.inject({ url: '/test/suppliers', headers: bearer() })).statusCode).toBe(200);
    expect(asked.reached).toHaveLength(1);
  });
});

describe('C2-1 SEC-AG-01 an agent is let in by its key alone', () => {
  it('lets a key the check accepts through, as its agent, with the text it sent and the request’s ID', async () => {
    const { app, asked } = await server();
    const response = await app.inject({ url: '/test/agent', headers: bearer() });
    expect(response.statusCode).toBe(200);
    expect(asked.keys).toEqual([{ text: KEY, correlationId: FIRST_ID }]);
    expect(asked.reached).toEqual([{ route: 'agent read', agent: ACCEPTED, person: null }]);
  });

  it('takes the scheme’s name in any case, and more than one space before the key (RFC 6750 §2.1)', async () => {
    const { app, asked } = await server();
    expect((await app.inject({ url: '/test/agent', headers: { authorization: `bearer ${KEY}` } })).statusCode).toBe(
      200,
    );
    expect((await app.inject({ url: '/test/agent', headers: { authorization: `BEARER  ${KEY}` } })).statusCode).toBe(
      200,
    );
    expect(asked.keys.map(({ text }) => text)).toEqual([KEY, KEY]);
  });

  it.each([
    [
      'a key the check refuses',
      `Bearer axk_${'c'.repeat(32)}_${'d'.repeat(43)}`,
      `axk_${'c'.repeat(32)}_${'d'.repeat(43)}`,
    ],
    ['another scheme', `Basic ${KEY}`, ''],
    ['the scheme with no key', 'Bearer', ''],
    ['a key with more after it', `Bearer ${KEY} ${KEY}`, ''],
    ['an empty header', '', ''],
  ])('refuses %s as UNAUTHENTICATED, invalid_token, saying nothing of why', async (_what, authorization, text) => {
    const { app, asked } = await server();
    const response = await app.inject({ url: '/test/agent', headers: { authorization } });
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe(`${AGENT_CHALLENGE}, error="invalid_token"`);
    expect(response.json()).toEqual(errorBody('UNAUTHENTICATED', FIRST_ID));
    expect(asked.keys.map((key) => key.text)).toEqual([text]);
    expect(asked.reached).toEqual([]);
  });

  it('refuses every key when the API has no key check, never letting one through unchecked', async () => {
    const { app, asked } = await server({ noCheck: true });
    const response = await app.inject({ url: '/test/agent', headers: bearer() });
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe(`${AGENT_CHALLENGE}, error="invalid_token"`);
    expect(asked.reached).toEqual([]);
  });

  it('answers a check that fails as our failure (500), never letting the request through', async () => {
    const { app, asked } = await server({
      checkKey: (a) => acceptingKey(a, () => Promise.reject(new Error('the database is away'))),
    });
    const response = await app.inject({ url: '/test/agent', headers: bearer() });
    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual(errorBody('INTERNAL_ERROR', FIRST_ID));
    expect(asked.reached).toEqual([]);
  });

  it('answers a check that fails with something not an Error as our failure too', async () => {
    const { app, asked } = await server({
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- what a careless library might do
      checkKey: (a) => acceptingKey(a, () => Promise.reject('away')),
    });
    expect((await app.inject({ url: '/test/agent', headers: bearer() })).statusCode).toBe(500);
    expect(asked.reached).toEqual([]);
  });

  it('refuses a key without every scope the route needs as INSUFFICIENT_SCOPE, naming them', async () => {
    const { app, asked } = await server();
    const response = await app.inject({ url: '/test/writes', headers: bearer() });
    expect(response.statusCode).toBe(403);
    expect(response.headers['www-authenticate']).toBe(
      `${AGENT_CHALLENGE}, error="insufficient_scope", scope="requests:write"`,
    );
    expect(response.json()).toEqual(errorBody('INSUFFICIENT_SCOPE', FIRST_ID));
    expect(asked.reached).toEqual([]);
  });

  it('lets a key with the scopes a route needs through', async () => {
    const { app, asked } = await server();
    expect((await app.inject({ url: '/test/suppliers', headers: bearer() })).statusCode).toBe(200);
    expect(asked.reached).toEqual([{ route: 'suppliers', agent: ACCEPTED, person: null }]);
  });

  it('refuses no one on a route naming agents with UNAUTHENTICATED, the challenge saying to send a key', async () => {
    const { app } = await server();
    const response = await app.inject({ url: '/test/agent' });
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe(AGENT_CHALLENGE);
    expect(response.json()).toEqual(errorBody('UNAUTHENTICATED', FIRST_ID));
  });

  it('still gives no one the Cookie challenge on a route naming people', async () => {
    const { app } = await server();
    const response = await app.inject({ url: '/test/mine' });
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe(SESSION_CHALLENGE);
  });
});

describe('C2-1 a request carrying a key is an agent’s, never a person’s', () => {
  it('refuses a key on a route not naming agents as FORBIDDEN, checking no key and reading no session', async () => {
    const { app, asked } = await server();
    const response = await app.inject({
      url: '/test/mine',
      headers: { ...bearer(), cookie: `${SESSION_COOKIE}=${COOKIE}` },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('FORBIDDEN', FIRST_ID));
    expect(asked.keys).toEqual([]);
    expect(asked.cookies).toEqual([]);
    expect(asked.reached).toEqual([]);
  });

  it('refuses a refused key with a live session beside it: the session never stands in for the key', async () => {
    const { app, asked } = await server();
    const response = await app.inject({
      url: '/test/suppliers',
      headers: { authorization: 'Bearer nonsense', cookie: `${SESSION_COOKIE}=${COOKIE}` },
    });
    expect(response.statusCode).toBe(401);
    expect(asked.cookies).toEqual([]);
    expect(asked.reached).toEqual([]);
  });

  it('judges a key with a live session beside it as the agent alone', async () => {
    const { app, asked } = await server();
    const response = await app.inject({
      url: '/test/agent',
      headers: { ...bearer(), cookie: `${SESSION_COOKIE}=${COOKIE}` },
    });
    expect(response.statusCode).toBe(200);
    expect(asked.cookies).toEqual([]);
    expect(asked.reached).toEqual([{ route: 'agent read', agent: ACCEPTED, person: null }]);
  });

  it('refuses a signed-in person on a route naming agents alone as FORBIDDEN', async () => {
    const { app, asked } = await server();
    const response = await app.inject({ url: '/test/agent', headers: { cookie: `${SESSION_COOKIE}=${COOKIE}` } });
    expect(response.statusCode).toBe(403);
    expect(asked.reached).toEqual([]);
  });
});

describe('C2-1 SEC-WEB-01 the Origin rule’s agent case', () => {
  it('lets an agent’s write through without an Origin, or with another site’s', async () => {
    const { app, asked } = await server();
    for (const headers of [{}, { origin: 'https://evil.example' }]) {
      const response = await app.inject({
        method: 'POST',
        url: '/test/agent',
        headers: { ...bearer(), 'idempotency-key': '0199a0f0-0000-7000-8000-00000000c001', ...headers },
      });
      expect(response.statusCode).toBe(200);
    }
    expect(asked.reached.map(({ route }) => route)).toEqual(['agent write', 'agent write']);
  });

  it('still refuses a write from another site without a key on a route naming agents', async () => {
    const { app, asked } = await server();
    const response = await app.inject({
      method: 'POST',
      url: '/test/agent',
      headers: { origin: 'https://evil.example' },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('ORIGIN_REFUSED', FIRST_ID));
    expect(asked.keys).toEqual([]);
  });

  it('still refuses a write from another site to a route not naming agents, whatever header it carries', async () => {
    const { app, asked } = await server();
    const response = await app.inject({
      method: 'POST',
      url: '/test/mine',
      headers: { ...bearer(), cookie: `${SESSION_COOKIE}=${COOKIE}`, origin: 'https://evil.example' },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(errorBody('ORIGIN_REFUSED', FIRST_ID));
    expect(asked.reached).toEqual([]);
  });
});

describe('C2-1 agentOf', () => {
  it('gives the agent the access hook accepted, and fails loudly on a route it never let one through to', () => {
    expect(agentOf({ agent: ACCEPTED })).toBe(ACCEPTED);
    expect(() => agentOf({ agent: null })).toThrow("an agent's route ran without an agent");
  });
});

describe('C2-1 bearerToken', () => {
  it.each([
    [`Bearer ${KEY}`, KEY],
    [`bEaReR ${KEY}`, KEY],
    [`Bearer   ${KEY}`, KEY],
    [`Bearer ${KEY} `, ''],
    [` Bearer ${KEY}`, ''],
    [`Bearer\t${KEY}`, ''],
    [`Bearer${KEY}`, ''],
    [`Token ${KEY}`, ''],
    ['', ''],
  ])('reads %j as %j', (header, token) => {
    expect(bearerToken(header)).toBe(token);
  });
});

describe('C2-1 GET /v1/agent: the agent a key is', () => {
  it('answers the agent, its organisation, the key, its scopes and its expiry, from the key check alone', async () => {
    const { app, asked } = await server({}, () => undefined);
    const response = await app.inject({ url: '/v1/agent', headers: bearer() });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      agentId: ACCEPTED.agentId,
      organizationId: ACCEPTED.orgId,
      keyId: ACCEPTED.keyId,
      scopes: ['requests:read', 'suppliers:read'],
      keyExpiresAt: '2026-12-28T09:00:00.000Z',
    });
    expect(asked.keys).toHaveLength(1);
  });

  it('refuses anyone else', async () => {
    const { app } = await server({}, () => undefined);
    expect((await app.inject({ url: '/v1/agent' })).statusCode).toBe(401);
    expect(
      (await app.inject({ url: '/v1/agent', headers: { cookie: `${SESSION_COOKIE}=${COOKIE}` } })).statusCode,
    ).toBe(403);
  });
});
