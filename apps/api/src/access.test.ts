import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, FastifySchema, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { accessProblems, type Principal } from './access.ts';
import { ContractBroken } from './contract.ts';
import { errorBody } from './errors.ts';
import { buildServer } from './server.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const FIRST_ID = '00000000-0000-7000-8000-000000000001';

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function server() {
  const config = {
    http: { host: '127.0.0.1', port: 0, publicOrigin: PUBLIC_ORIGIN, trustedProxies: [], rateLimitPerMinute: 100 },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', ...config },
    destination: new LogCapture(),
  });
  const app = await buildServer({ config, logger, ids: new SequentialIds(), healthChecks: [] });
  servers.push(app);
  return app;
}

/** A route's options with a given access, typed loosely so a test can hand over a wrong one. */
const withAccess = (access: unknown): RouteShorthandOptions => ({
  config: { access } as NonNullable<RouteShorthandOptions['config']>,
});

describe('BR-04 every route names who may call it', () => {
  it.each<[string, readonly Principal[], string]>([
    ['one role', ['admin'], '/v1/members'],
    ['several roles and agents', ['admin', 'approver', 'developer', 'viewer', 'agent'], '/v1/spend-requests'],
    ['a parameter past the first segment', ['admin'], '/v1/members/:id'],
    ['the public alone', ['public'], '/health'],
    ['operators alone, under /operator/', ['operator'], '/operator/hand-off/pause'],
  ])('takes %s', (_what, access, url) => {
    expect(accessProblems(access, url)).toEqual([]);
  });

  it.each<[string, unknown, string, string]>([
    ['no access at all', undefined, '/v1/members', 'it names no one who may call it'],
    ['an empty list', [], '/v1/members', 'it names no one who may call it'],
    ['a single name rather than a list', 'admin', '/v1/members', 'it names no one who may call it'],
    ['someone unknown', ['admin', 'owner'], '/v1/members', 'its access names someone unknown'],
    ['a name in the wrong case', ['Admin'], '/v1/members', 'its access names someone unknown'],
    ['someone twice', ['admin', 'admin'], '/v1/members', 'its access names someone twice'],
    ['the public beside others', ['public', 'viewer'], '/v1/members', 'the public beside others'],
    ['operators beside customers (SEC-OPS-01)', ['operator', 'admin'], '/operator/tools', 'operators beside others'],
    ['operators on a tenant address', ['operator'], '/v1/organization/unfreeze', 'operators outside /operator/'],
    [
      'operators behind a parameter, which would answer a tenant address too',
      ['operator'],
      '/:api/organization/unfreeze',
      'operators outside /operator/',
    ],
    ['operators behind a wildcard', ['operator'], '/v1*', 'operators outside /operator/'],
    ['operators at the prefix without its slash', ['operator'], '/operator', 'operators outside /operator/'],
    ['customers under the operator prefix', ['admin'], '/operator/tools', 'which only operators may call'],
    ['the public under the operator prefix', ['public'], '/operator/status', 'which only operators may call'],
    ['the public on a root wildcard, which would answer operator addresses', ['public'], '/*', 'parameter or wildcard'],
    ['customers behind a root parameter', ['admin'], '/:x/pause', 'parameter or wildcard'],
    ['customers behind a root pattern', ['admin'], '/(^[0-9]+$)/pause', 'parameter or wildcard'],
  ])('refuses %s', (_what, access, url, problem) => {
    expect(accessProblems(access, url).join('; ')).toContain(problem);
  });

  it('refuses a list with a hole in it, which every() alone would skip', () => {
    const sparse: unknown[] = [];
    sparse[1] = 'admin';
    expect(accessProblems(sparse, '/v1/members')).toEqual([expect.stringContaining('names someone unknown')]);
  });

  it('refuses, as it is added, a route that names no one', async () => {
    const app = await server();
    expect(() => app.get('/test/route', () => 'ok')).toThrow(ContractBroken);
    expect(() => app.get('/test/route', () => 'ok')).toThrow('GET /test/route: it names no one who may call it');
  });

  it('refuses, as it is added, a route whose access names someone unknown', async () => {
    const app = await server();
    expect(() => app.get('/test/route', withAccess(['owner']), () => 'ok')).toThrow('names someone unknown');
  });

  it('refuses a route that writes its own access into the document', async () => {
    const app = await server();
    const schema: FastifySchema & Record<string, unknown> = { 'x-access': ['public'] };
    const options = { ...withAccess(['admin']), schema };
    expect(() => app.get('/test/route', options, () => 'ok')).toThrow('the access its document shows is not its own');
  });

  it("refuses to start when a plugin's own hook swaps a route's access after the document was written", async () => {
    const app = await server();
    await app.register(
      (child, _options, done) => {
        child.addHook('onRoute', (route) => {
          route.config = { ...route.config, access: ['public'] };
        });
        child.get('/item', withAccess(['admin']), () => 'ok');
        done();
      },
      { prefix: '/test/plugin' },
    );
    await expect(app.ready()).rejects.toThrow('GET /test/plugin/item: the access its document shows is not its own');
  });

  it('holds a route to the list it was added with: changing that list, or the document, later changes nothing', async () => {
    const app = await server();
    const readers: Principal[] = ['admin'];
    app.get('/test/report', withAccess(readers), () => 'report');
    await app.ready();
    readers.splice(0, 1, 'public');
    const documented = app.swagger().paths?.['/test/report']?.get as Record<string, unknown> | undefined;
    expect(Object.isFrozen(documented?.['x-access'])).toBe(true);
    expect(documented?.['x-access']).toEqual(['admin']);
    expect((await app.inject('/test/report')).statusCode).toBe(401);
  });

  it('shows who may call each operation in the document, the HEAD of a GET included', async () => {
    const app = await server();
    app.get('/test/members', withAccess(['admin', 'viewer']), () => 'ok');
    await app.ready();
    const item = app.swagger().paths?.['/test/members'];
    expect(item).toMatchObject({ get: { 'x-access': ['admin', 'viewer'] }, head: { 'x-access': ['admin', 'viewer'] } });
  });
});

describe('BR-04 a route answers only a caller it names, denying by default', () => {
  async function withRoutes() {
    const app = await server();
    const reached: string[] = [];
    app.get('/test/members', withAccess(['admin', 'viewer']), () => {
      reached.push('members');
      return 'ok';
    });
    app.post('/test/members', withAccess(['admin']), () => {
      reached.push('invite');
      return 'ok';
    });
    app.get('/test/open', withAccess(['public']), () => 'open');
    await app.ready();
    return { app, reached };
  }

  it.each([
    ['a read', { method: 'GET', url: '/test/members' }],
    ['the HEAD of a read', { method: 'HEAD', url: '/test/members' }],
    ['a write from our own origin', { method: 'POST', url: '/test/members', headers: { origin: PUBLIC_ORIGIN } }],
  ] as const)('refuses %s from no one it names as UNAUTHENTICATED, before the route runs', async (_what, request) => {
    const { app, reached } = await withRoutes();
    const response = await app.inject(request);
    expect(response.statusCode).toBe(401);
    expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
    if (request.method !== 'HEAD') expect(response.json()).toEqual(errorBody('UNAUTHENTICATED', FIRST_ID));
    expect(reached).toEqual([]);
  });

  it('refuses before the body is read, so a body over any limit is still UNAUTHENTICATED', async () => {
    const { app } = await withRoutes();
    const response = await app.inject({
      method: 'POST',
      url: '/test/members',
      headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
      payload: JSON.stringify({ note: 'x'.repeat(70_000) }),
    });
    expect(response.statusCode).toBe(401);
  });

  it('refuses a write from another origin first, as the Origin rule always has (SEC-WEB-01)', async () => {
    const { app } = await withRoutes();
    const response = await app.inject({
      method: 'POST',
      url: '/test/members',
      headers: { origin: 'https://evil.example' },
    });
    expect(response.statusCode).toBe(403);
  });

  it('refuses a route in a prefixed plugin, before a hook of the route itself runs', async () => {
    const app = await server();
    const reached: string[] = [];
    await app.register(
      (child, _options, done) => {
        child.get(
          '/members',
          {
            ...withAccess(['admin']),
            onRequest: (_request, _reply, next) => {
              reached.push('route hook');
              next();
            },
          },
          () => {
            reached.push('route');
            return 'ok';
          },
        );
        done();
      },
      { prefix: '/test/plugin' },
    );
    await app.ready();
    expect((await app.inject('/test/plugin/members')).statusCode).toBe(401);
    expect(reached).toEqual([]);
  });

  it('answers a public route, and the health check, to anyone', async () => {
    const { app } = await withRoutes();
    expect((await app.inject('/test/open')).body).toBe('open');
    expect((await app.inject('/health')).json()).toEqual({ status: 'ok' });
  });

  it('answers an unknown address with the plain 404, not a refusal that would tell it apart', async () => {
    const { app } = await withRoutes();
    const response = await app.inject('/test/nothing-here');
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual(errorBody('NOT_FOUND', FIRST_ID));
  });
});
