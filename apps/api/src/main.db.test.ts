// The API process against a real Postgres (Rule Book §6): the pool opens as the
// app's role, the role check refuses the migration role, a wrong login is
// reported without the login, and a stop closes every connection.
import { EventEmitter } from 'node:events';

import { type AuditTables, createAuditTrail } from '@agentx/core/modules/audit';
import { type DirectoryTables, registerOrganization } from '@agentx/core/modules/directory';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, withTenant } from '@agentx/platform/db';
import { loadKeys, PURPOSES } from '@agentx/platform/keys';
import { createLogger, type Output } from '@agentx/platform/observability';
import {
  createTestDatabase,
  findLeaks,
  LogCapture,
  type TestDatabase,
  type TestRole,
  writeTestKeys,
} from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { type ApiProcess, runApi } from './main.ts';

const server = inject('postgres');
const keys = writeTestKeys(PURPOSES);
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
  keys.remove();
});

class FakeProcess extends EventEmitter implements ApiProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  readonly exits: number[] = [];
  exitCode: number | string | null | undefined = undefined;

  exit(code: number): void {
    this.exits.push(code);
  }
}

/** The environment of an API run against this test database, as one of its roles. */
function envFor(role: TestRole, overrides: Record<string, string> = {}): Record<string, string> {
  const connection = database.connection(role);
  return {
    AGENTX_ENV: 'test',
    AGENTX_HTTP_PORT: '0',
    AGENTX_DB_HOST: connection.host,
    AGENTX_DB_PORT: String(connection.port),
    AGENTX_DB_NAME: connection.database,
    AGENTX_DB_USER: connection.user,
    AGENTX_DB_PASSWORD: connection.password,
    AGENTX_DB_TLS: 'disable',
    AGENTX_KEYS_DIR: keys.directory,
    ...overrides,
  };
}

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((api) => api.close()));
});

async function start(env: Record<string, string>) {
  const host = new FakeProcess();
  const capture = new LogCapture();
  const api = await runApi(host, { env, destination: capture });
  if (api !== undefined) servers.push(api);
  return {
    host,
    api,
    capture,
    /** The process's own events, without the framework's lines. */
    events: () =>
      capture
        .lines()
        .map((line) => String(line.event))
        .filter((event) => event.startsWith('api.')),
  };
}

/** Stops a started API as the platform would, with SIGTERM, and waits for it to exit. */
async function stop(run: { readonly host: FakeProcess }): Promise<void> {
  run.host.emit('SIGTERM', 'SIGTERM');
  await vi.waitFor(() => {
    expect(run.host.exits).toEqual([0]);
  });
}

/** The connections named agentx-api open to this test database: who holds them, and what they are doing. */
async function apiConnections(): Promise<{ usename: string; state: string | null }[]> {
  return database
    .as('admin')
    .query<{ usename: string; state: string | null }>(
      'select usename::text, state from pg_catalog.pg_stat_activity where datname = $1 and application_name = $2',
      [database.name, 'agentx-api'],
    );
}

/** Postgres removes a backend a moment after its client disconnects. */
async function expectNoApiConnections(): Promise<void> {
  await vi.waitFor(
    async () => {
      expect(await apiConnections()).toEqual([]);
    },
    { timeout: 5000 },
  );
}

describe(`APP-02 the API and its database (Postgres ${server.version})`, () => {
  it('starts as the app role, answers, and closes every connection when it stops', async () => {
    const { host, api, events } = await start(envFor('app'));
    expect(api).toBeDefined();
    expect(events()).toEqual(['api.starting', 'api.database_connected', 'api.start_recorded', 'api.listening']);
    expect((await api?.inject('/health'))?.json()).toEqual({ status: 'ok' });
    // The role check opened at least one connection, named for Postgres's own views, as the app role.
    expect(await apiConnections()).toEqual(
      expect.arrayContaining([expect.objectContaining({ usename: database.connection('app').user })]),
    );

    host.emit('SIGTERM', 'SIGTERM');
    await vi.waitFor(() => {
      expect(host.exits).toEqual([0]);
    });
    expect(events().slice(-2)).toEqual(['api.stopping', 'api.stopped']);
    await expectNoApiConnections();
  });

  it('refuses to run as the migration role, which owns the tables and could switch the walls off', async () => {
    const { host, api, capture, events } = await start(envFor('owner'));
    expect(api).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(events()).toEqual(['api.starting', 'api.start_refused']);
    expect(capture.lines().at(-1)?.problems).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^it owns the database$/),
        expect.stringMatching(/^it owns objects/),
      ]),
    );
    await expectNoApiConnections();
  });

  it('refuses to run as the backup role, which bypasses row-level security', async () => {
    const { api, capture } = await start(envFor('backup'));
    expect(api).toBeUndefined();
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({ event: 'api.start_refused', problems: ['it has BYPASSRLS'] }),
    );
  });

  it('reports a wrong login as the database being unavailable, without the login, and exits with a failure', async () => {
    const wrong = 'not the login for these tests';
    const { host, api, capture, events } = await start(envFor('app', { AGENTX_DB_PASSWORD: wrong }));
    expect(api).toBeUndefined();
    expect(host.exitCode).toBe(1);
    expect(events()).toEqual(['api.starting', 'api.database_unavailable']);
    expect(findLeaks(capture.text, [wrong, database.connection('app').password])).toEqual([]);
  });

  it('SEC-OPS-05 writes each start to the platform audit chain, with the hash it logged, in order', async () => {
    await database.as('admin').query('truncate platform_controls.audit_events, platform_controls.audit_head');
    const first = await start(envFor('app'));
    await stop(first);
    const second = await start(envFor('app', { AGENTX_RELEASE: 'r-second' }));
    await stop(second);
    const logged = [first, second].map(
      ({ capture }) => capture.lines().find((line) => line.event === 'api.starting')?.configHash,
    );
    const rows = await database
      .as('admin')
      .query<{ seq: string; actor_id: string; action: string; details: string }>(
        'select seq, actor_id, action, details from platform_controls.audit_events order by seq',
      );

    expect(rows).toEqual([
      {
        seq: '1',
        actor_id: 'api',
        action: 'platform.started',
        details: JSON.stringify({ configHash: logged[0], release: 'local' }),
      },
      {
        seq: '2',
        actor_id: 'api',
        action: 'platform.started',
        details: JSON.stringify({ configHash: logged[1], release: 'r-second' }),
      },
    ]);
    expect(first.capture.lines().find((line) => line.event === 'api.start_recorded')?.seq).toBe('1');

    // The chain checks out with the keys the API loaded.
    const reader = createDatabase<PlatformControlsTables>(
      database.connection('app'),
      createLogger({
        service: 'test',
        config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
        destination: new LogCapture(),
      }),
    );
    try {
      const chain = createPlatformChain({ keys: loadKeys({ directory: keys.directory, current: {} }), ids: uuidV7Ids });
      expect(await reader.transaction().execute((tx) => chain.verify(tx, undefined))).toMatchObject({
        ok: true,
        seq: 2n,
      });
    } finally {
      await reader.destroy();
    }
  });

  it('anchors the platform chain once it listens, where the start it recorded is the head (ADR-012 §2)', async () => {
    await database.as('admin').query('truncate platform_controls.audit_events, platform_controls.audit_head');
    const run = await start(envFor('app'));
    await vi.waitFor(() => {
      expect(run.capture.lines().find((line) => line.event === 'audit.anchored')).toEqual(
        expect.objectContaining({ level: 'info', chain: 'platform', seq: '1' }),
      );
    });
    await stop(run);
  });

  it("anchors each organisation's chain from the directory's list, and raises the alarm for one tampered with (B1d-2)", async () => {
    const [kept, broken] = ['0199a0f0-0000-7000-8000-00000000b1d1', '0199a0f0-0000-7000-8000-00000000b1d2'];
    const writer = createDatabase<DirectoryTables & AuditTables>(
      { ...database.connection('app'), tls: 'disable', maxConnections: 2 },
      createLogger({
        service: 'test',
        config: { environment: 'test', release: 'r-1', log: { level: 'error', eventCapPerMinute: 1000 } },
        destination: new LogCapture(),
      }),
    );
    const trail = createAuditTrail({ keys: loadKeys({ directory: keys.directory, current: {} }), ids: uuidV7Ids });
    try {
      for (const orgId of [kept, broken]) {
        await withTenant(writer, orgId, async (tx) => {
          await registerOrganization(tx, orgId);
          await trail.record(tx, orgId, {
            actor: { type: 'system', id: 'test' },
            action: 'probe.made',
            subject: { type: 'probe', id: orgId, version: 1 },
            details: {},
          });
        });
      }
    } finally {
      await writer.destroy();
    }
    await database.as('admin').query('update audit.heads set seq = seq + 5 where org_id = $1', [broken]);

    const run = await start(envFor('app'));
    await vi.waitFor(() => {
      expect(run.capture.lines().find((line) => line.event === 'audit.anchor_check_done')).toBeDefined();
    });
    const lines = run.capture.lines();
    expect(lines.find((line) => line.event === 'audit.anchored' && line.orgId === kept)).toEqual(
      expect.objectContaining({ level: 'info', chain: 'organisation', seq: '1' }),
    );
    expect(lines.find((line) => line.event === 'audit.integrity_failed' && line.orgId === broken)).toEqual(
      expect.objectContaining({ level: 'error', chain: 'organisation', check: 'anchor', reason: 'head' }),
    );
    await stop(run);
  });

  it('refuses to start when the platform chain has been tampered with, and closes its connections', async () => {
    // A start of its own to give the chain a head, then stopped, so every connection left is the next one's.
    await stop(await start(envFor('app')));
    await database.as('admin').query('update platform_controls.audit_head set seq = seq + 5');
    try {
      const { host, api, events, capture } = await start(envFor('app'));

      expect(api).toBeUndefined();
      expect(host.exitCode).toBe(1);
      expect(events()).toEqual(['api.starting', 'api.database_connected', 'api.start_not_recorded']);
      expect(capture.lines().find((line) => line.event === 'audit.integrity_failed')).toEqual(
        expect.objectContaining({ level: 'error', chain: 'platform', check: 'start' }),
      );
      await expectNoApiConnections();
    } finally {
      await database.as('admin').query('truncate platform_controls.audit_events, platform_controls.audit_head');
    }
  });

  it('reports a database that is not there as unavailable, with the address redacted', async () => {
    const { api, capture, events } = await start(envFor('app', { AGENTX_DB_PORT: '1' }));
    expect(api).toBeUndefined();
    expect(events()).toEqual(['api.starting', 'api.database_unavailable']);
    expect(findLeaks(capture.text, ['127.0.0.1'])).toEqual([]);
  });
});
