import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createTenantProbe } from './tenant-probe.ts';
import { createTestDatabase, type TestDatabase } from './test-database.ts';

const server = inject('postgres');
let first: TestDatabase;
let second: TestDatabase;

beforeAll(async () => {
  [first, second] = await Promise.all([
    createTestDatabase(server, { schema: 'migrated' }),
    createTestDatabase(server, { schema: 'empty' }),
  ]);
});

afterAll(async () => {
  await Promise.all([first.drop(), second.drop()]);
});

describe(`createTestDatabase (Postgres ${server.version})`, () => {
  it('gives each test file a database of its own', async () => {
    expect(first.name).not.toBe(second.name);
    await createTenantProbe(first);
    const [row] = await second
      .as('admin')
      .query<{ found: boolean }>("select pg_catalog.to_regclass('probe.items') is not null as found");
    expect(row?.found).toBe(false);
  });

  it('copies the migrated template, or starts empty', async () => {
    const applied = async (database: TestDatabase): Promise<boolean> => {
      const [row] = await database
        .as('admin')
        .query<{ found: boolean }>("select pg_catalog.to_regclass('migrations.applied') is not null as found");
      return row?.found ?? false;
    };
    expect(await applied(first)).toBe(true);
    expect(await applied(second)).toBe(false);
  });

  it('connects each role as itself, with bound parameters', async () => {
    for (const role of ['admin', 'owner', 'app', 'backup'] as const) {
      const [row] = await first
        .as(role)
        .query<{ login: string; echoed: string }>('select session_user::text as login, $1::text as echoed', [
          "it's plain text",
        ]);
      expect(row).toEqual({
        login: first.connection(role).user,
        echoed: "it's plain text",
      });
    }
  });

  it('describes each role’s connection for @agentx/platform/db, with TLS off for the local server', () => {
    expect(first.connection('app')).toEqual({
      host: server.host,
      port: server.port,
      database: first.name,
      user: 'agentx_app',
      password: server.roles.app.password,
      tls: 'disable',
    });
  });

  it('opens a connection of its own, so a transaction stays on one connection', async () => {
    const client = await first.connect('app');
    try {
      const [row] = await client.query<{ pid: number }>('select pg_catalog.pg_backend_pid() as pid');
      expect(row?.pid).toBe(client.pid);
      await client.query('begin');
      const transaction = 'select pg_catalog.pg_current_xact_id()::text as id';
      const [before] = await client.query<{ id: string }>(transaction);
      const [after] = await client.query<{ id: string }>(transaction);
      expect(after?.id).toBe(before?.id);
      await client.query('rollback');
    } finally {
      await client.end();
    }
    // Ending it again is harmless.
    await client.end();
  });

  it('closes the connections a test left open when the database is dropped', async () => {
    const extra = await createTestDatabase(server, { schema: 'empty' });
    const left = await extra.connect('app');
    await extra.drop();
    // pg's message for a connection closed from our side, not one the server cut.
    await expect(left.query('select 1')).rejects.toThrow('Client was closed and is not queryable');
  });

  it('turns a connection the server ends into a failed query, not a crash', async () => {
    const client = await first.connect('app');
    try {
      await first.as('admin').query('select pg_catalog.pg_terminate_backend($1, 5000)', [client.pid]);
      // Give the idle connection time to hear it was ended, as it would between two queries.
      await new Promise((resolve) => setTimeout(resolve, 200));
      await expect(client.query('select 1')).rejects.toThrow(
        'Client has encountered a connection error and is not queryable',
      );
    } finally {
      await client.end();
    }
  });

  it('deletes the database on drop, even with a session still open', async () => {
    const extra = await createTestDatabase(server, { schema: 'empty' });
    // A session the harness doesn't know about, like a pool a test forgot to close.
    const straggler = new pg.Client({ ...extra.connection('app'), ssl: false });
    const straggling: unknown[] = [];
    straggler.on('error', (error: unknown) => straggling.push(error));
    await straggler.connect();
    await straggler.query('select 1');
    await extra.drop();
    // The server ended the straggling session, which is what WITH (FORCE) does.
    await expect(straggler.query('select 1')).rejects.toThrow();
    await straggler.end();
    const [row] = await first
      .as('admin')
      .query<{ found: boolean }>('select exists (select 1 from pg_catalog.pg_database where datname = $1) as found', [
        extra.name,
      ]);
    expect(row?.found).toBe(false);
  });
});
