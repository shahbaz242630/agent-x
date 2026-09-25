import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, RouteOptions, RouteShorthandOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { ContractBroken } from './contract.ts';
import { buildServer } from './server.ts';
import { isWriteRoute, operationProblems, sharedOperations } from './write-operations.ts';

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function server() {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: 'https://app.agentx.example',
      trustedProxies: [],
      rateLimitPerMinute: 100,
      rateLimitPerUserPerMinute: 100,
    },
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

/**
 * A route's options for an admin's write, with the operation given, typed
 * loosely so a test can hand over a wrong one. Its body limit and answer aren't
 * what these tests are about.
 */
const write = (operation: unknown, access: unknown = ['admin']): RouteShorthandOptions => ({
  config: { access, operation } as NonNullable<RouteShorthandOptions['config']>,
  bodyLimit: 1024,
  schema: { response: { 200: z.object({ ok: z.literal(true) }) } },
});

/** The document's operations, each with the operationId it shows, if any. */
const PATHS = z.record(z.string(), z.record(z.string(), z.object({ operationId: z.string().optional() })));

/** The operationId of each operation in the document, as "METHOD /path". */
function operationIds(app: FastifyInstance): Record<string, string | undefined> {
  return Object.fromEntries(
    Object.entries(PATHS.parse(app.swagger().paths)).flatMap(([path, item]) =>
      Object.entries(item).map(([method, operation]) => [`${method.toUpperCase()} ${path}`, operation.operationId]),
    ),
  );
}

describe('SEC-DP-07 each write names what it does, so its idempotency keys are its own', () => {
  it.each([
    ['POST', true],
    ['PUT', true],
    ['PATCH', true],
    ['DELETE', true],
    ['GET', false],
    ['HEAD', false],
    ['OPTIONS', false],
    ['TRACE', false],
  ])('counts %s as a write: %s', (method, writes) => {
    expect(isWriteRoute([method])).toBe(writes);
  });

  it('counts a route that reads and writes as a write', () => {
    expect(isWriteRoute(['GET', 'POST'])).toBe(true);
  });

  it.each([
    ['one word', 'members'],
    ['words joined by a dot', 'members.invite'],
    ['words joined by a dash, with digits', 'spend-requests.create2'],
    ['64 characters', `a${'b'.repeat(63)}`],
  ])('takes a write naming %s', (_what, operation) => {
    expect(operationProblems(operation, ['POST'], ['admin'])).toEqual([]);
  });

  it.each([
    ['nothing', undefined, 'it writes but names no operation (config.operation)'],
    ['capitals', 'Members.invite', 'its operation is not lower-case words'],
    ['a space', 'members invite', 'its operation is not lower-case words'],
    ['a leading digit', '1members', 'its operation is not lower-case words'],
    ['a trailing dot', 'members.', 'its operation is not lower-case words'],
    ['two dots together', 'members..invite', 'its operation is not lower-case words'],
    ['an underscore', 'members_invite', 'its operation is not lower-case words'],
    ['65 characters', `a${'b'.repeat(64)}`, 'its operation is not lower-case words'],
    ['empty text', '', 'its operation is not lower-case words'],
    ['something other than text', 7, 'its operation is not lower-case words'],
  ])('refuses a write naming %s', (_what, operation, problem) => {
    const problems = operationProblems(operation, ['POST'], ['admin']);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain(problem);
  });

  it('asks an operation of a write any signed-in caller may make, operators included', () => {
    for (const access of [['person'], ['admin', 'agent'], ['operator'], ['public', 'admin']]) {
      expect(operationProblems(undefined, ['DELETE'], access)).toEqual([
        'it writes but names no operation (config.operation)',
      ]);
    }
  });

  it('refuses an operation on a public write, which has no caller to keep its keys apart', () => {
    expect(operationProblems(undefined, ['POST'], ['public'])).toEqual([]);
    expect(operationProblems('auth.sign-out', ['POST'], ['public'])).toEqual([
      'it names an operation, but a public write takes no idempotency key',
    ]);
  });

  it('refuses an operation on a read, which takes no key', () => {
    expect(operationProblems(undefined, ['GET'], ['admin'])).toEqual([]);
    expect(operationProblems('members.list', ['GET', 'HEAD'], ['admin'])).toEqual([
      'it names an operation, but a read takes no idempotency key',
    ]);
  });

  it('names each operation more than one route names, once', () => {
    expect(sharedOperations(['a', undefined, 'b', 'a', undefined, 'a', 'c'])).toEqual(['a']);
    expect(sharedOperations(['a', 'b', undefined, undefined])).toEqual([]);
  });
});

describe('SEC-DP-07 the contract holds every write route to its operation', () => {
  it('writes the operation into the document as the operationId of its one operation, and none for the rest', async () => {
    const app = await server();
    app.post('/v1/team', write('team.invite'), () => ({ ok: true }));
    app.delete('/v1/team/:id', write('team.remove'), () => ({ ok: true }));
    app.get('/v1/team', write(undefined), () => ({ ok: true }));
    await app.ready();
    const ids = operationIds(app);
    expect(ids['POST /v1/team']).toBe('team.invite');
    expect(ids['DELETE /v1/team/{id}']).toBe('team.remove');
    expect(ids['GET /v1/team']).toBeUndefined();
    expect(ids['HEAD /v1/team']).toBeUndefined();
    // Nor the members list, a read.
    expect(ids['GET /v1/members']).toBeUndefined();
    // The one public write, sign-out, names none.
    expect(ids['POST /v1/auth/sign-out']).toBeUndefined();
  });

  it.each<[string, RouteShorthandOptions, string]>([
    ['no operation', write(undefined), 'it writes but names no operation (config.operation)'],
    ['a malformed operation', write('Members'), 'its operation is not lower-case words'],
    [
      'an operation on a public write',
      write('auth.x', ['public']),
      'it names an operation, but a public write takes no idempotency key',
    ],
    [
      'an operationId of its own in its document',
      { ...write('test.invite'), schema: { ...write('x').schema, operationId: 'other' } },
      'the operation its document shows is not its own (operationId)',
    ],
    [
      'an operationId in its document but no operation',
      { ...write(undefined, ['public']), schema: { ...write('x').schema, operationId: 'other' } },
      'the operation its document shows is not its own (operationId)',
    ],
  ])('refuses a write with %s as it is added', async (_what, options, problem) => {
    const app = await server();
    expect(() => app.post('/v1/test', options, () => ({ ok: true }))).toThrow(ContractBroken);
    expect(() => app.post('/v1/test', options, () => ({ ok: true }))).toThrow(`POST /v1/test: ${problem}`);
  });

  it('refuses a read naming an operation as it is added', async () => {
    const app = await server();
    expect(() => app.get('/v1/test', write('members.list'), () => ({ ok: true }))).toThrow(
      'GET /v1/test: it names an operation, but a read takes no idempotency key',
    );
  });

  it.each([
    ['a read and a write', ['GET', 'POST']],
    ['two writes', ['POST', 'PUT']],
  ])('refuses one operation for a route of %s, which the document would show twice', async (_what, method) => {
    const app = await server();
    const route = { method, url: '/v1/test', ...write('test.invite'), handler: () => ({ ok: true }) };
    expect(() => app.route(route as RouteOptions)).toThrow(
      `${method.join(',')} /v1/test: it names an operation but serves more than one method`,
    );
  });

  it("refuses a second route naming another's operation as it is added, whatever its address", async () => {
    const app = await server();
    app.post('/v1/members', write('test.invite'), () => ({ ok: true }));
    expect(() => app.put('/v1/invitations', write('test.invite'), () => ({ ok: true }))).toThrow(
      "PUT /v1/invitations: its operation is another route's too",
    );
  });

  it("refuses to start when a later hook gives a route another's operation", async () => {
    const app = await server();
    app.post('/v1/members', write('test.invite'), () => ({ ok: true }));
    await app.register((child, _options, done) => {
      child.addHook('onRoute', (route) => {
        route.config = { ...route.config, operation: 'test.invite' };
      });
      child.post('/v1/invitations', write('invitations.send'), () => ({ ok: true }));
      done();
    });
    const ready = app.ready();
    await expect(ready).rejects.toThrow(ContractBroken);
    await expect(ready).rejects.toThrow('the operation test.invite is named by more than one route');
  });

  it("refuses to start when a later hook changes a route's operation, parting it from its document", async () => {
    const app = await server();
    await app.register((child, _options, done) => {
      child.addHook('onRoute', (route) => {
        route.config = { ...route.config, operation: 'members.other' };
      });
      child.post('/v1/members', write('test.invite'), () => ({ ok: true }));
      done();
    });
    await expect(app.ready()).rejects.toThrow(
      'POST /v1/members: the operation its document shows is not its own (operationId)',
    );
  });

  it("refuses to start when a later hook rebuilds a write route's schema, dropping its operationId", async () => {
    const app = await server();
    await app.register((child, _options, done) => {
      child.addHook('onRoute', (route) => {
        route.schema = { response: { 200: z.object({ ok: z.literal(true) }) } };
      });
      child.post('/v1/members', write('test.invite'), () => ({ ok: true }));
      done();
    });
    await expect(app.ready()).rejects.toThrow(
      'POST /v1/members: the operation its document shows is not its own (operationId)',
    );
  });

  it("refuses to start when a later hook takes a write route's operation away", async () => {
    const app = await server();
    await app.register((child, _options, done) => {
      child.addHook('onRoute', (route) => {
        const { operation: _taken, ...rest } = route.config ?? {};
        route.config = rest;
      });
      child.post('/v1/members', write('test.invite'), () => ({ ok: true }));
      done();
    });
    await expect(app.ready()).rejects.toThrow('POST /v1/members: it writes but names no operation');
  });
});
