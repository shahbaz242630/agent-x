// The API process against a real Postgres (Rule Book §6): the pool opens as the
// app's role, the role check refuses the migration role, a wrong login is
// reported without the login, and a stop closes every connection.
import { EventEmitter } from 'node:events';

import { PURPOSES } from '@agentx/platform/keys';
import type { Output } from '@agentx/platform/observability';
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
    expect(events()).toEqual(['api.starting', 'api.database_connected', 'api.listening']);
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

  it('reports a database that is not there as unavailable, with the address redacted', async () => {
    const { api, capture, events } = await start(envFor('app', { AGENTX_DB_PORT: '1' }));
    expect(api).toBeUndefined();
    expect(events()).toEqual(['api.starting', 'api.database_unavailable']);
    expect(findLeaks(capture.text, ['127.0.0.1'])).toEqual([]);
  });
});
