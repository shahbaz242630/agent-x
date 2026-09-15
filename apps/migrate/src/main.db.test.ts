// The migration job against a real Postgres (Rule Book §6): the repository's
// migrations applied to an empty database as the migration role, a second run
// that applies nothing, and the ways it fails without leaving half a change.
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Output } from '@agentx/platform/observability';
import { createTestDatabase, findLeaks, LogCapture, type TestDatabase } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { type MigrateProcess, runMigrate } from './main.ts';

const server = inject('postgres');
const REPOSITORY_MIGRATIONS = fileURLToPath(new URL('../../../db/migrations', import.meta.url));

class FakeProcess implements MigrateProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  exitCode: number | string | null | undefined = undefined;
}

/** The job's environment for a database, as its migration role. */
function envFor(database: TestDatabase, overrides: Record<string, string> = {}): Record<string, string> {
  const connection = database.connection('owner');
  return {
    AGENTX_ENV: 'test',
    AGENTX_DB_HOST: connection.host,
    AGENTX_DB_PORT: String(connection.port),
    AGENTX_DB_NAME: connection.database,
    AGENTX_DB_MIGRATION_USER: connection.user,
    AGENTX_DB_MIGRATION_PASSWORD: connection.password,
    AGENTX_DB_TLS: 'disable',
    ...overrides,
  };
}

async function run(env: Record<string, string>, directory?: string) {
  const host = new FakeProcess();
  const capture = new LogCapture();
  const code = await runMigrate(host, { env, destination: capture, directory });
  return { code, host, capture, events: () => capture.lines().map((line) => line.event) };
}

/** A folder of migration files for one test. */
function folderWith(files: Record<string, string>): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentx-migrate-'));
  for (const [name, sql] of Object.entries(files)) writeFileSync(path.join(dir, name), sql);
  folders.push(dir);
  return dir;
}
const folders: string[] = [];

const databases: TestDatabase[] = [];
async function emptyDatabase(): Promise<TestDatabase> {
  const database = await createTestDatabase(server, { schema: 'empty' });
  databases.push(database);
  return database;
}

afterAll(async () => {
  await Promise.all(databases.map((database) => database.drop()));
  for (const dir of folders) rmSync(dir, { recursive: true, force: true });
});

describe(`the migration job (Postgres ${server.version})`, () => {
  let database: TestDatabase;

  beforeAll(async () => {
    database = await emptyDatabase();
  });

  it('applies every migration in the repository to an empty database, in order, and exits 0', async () => {
    const files = readdirSync(REPOSITORY_MIGRATIONS).sort();
    expect(files.length).toBeGreaterThanOrEqual(1);

    const { code, host, capture, events } = await run(envFor(database));
    expect(code).toBe(0);
    expect(host.exitCode).toBe(0);
    expect(events()).toEqual([
      'migrate.starting',
      ...files.map(() => 'db.migration.applied'),
      'db.migrations.done',
      'migrate.done',
    ]);
    expect(capture.lines()[0]).toEqual(
      expect.objectContaining({ service: 'migrate', event: 'migrate.starting', role: 'agentx_owner' }),
    );
    expect(capture.lines().at(-1)).toEqual(expect.objectContaining({ event: 'migrate.done', applied: files }));

    const ledger = await database
      .as('owner')
      .query<{ name: string }>('select name from migrations.applied order by name');
    expect(ledger.map((row) => row.name)).toEqual(files);
  });

  it('applies nothing the second time, and still exits 0: the database is current', async () => {
    const { code, capture } = await run(envFor(database));
    expect(code).toBe(0);
    expect(capture.lines().at(-1)).toEqual(expect.objectContaining({ event: 'migrate.done', applied: [] }));
  });

  it('reports a wrong login without the login, and exits 1', async () => {
    const wrong = 'not the login for these tests';
    const { code, capture, events } = await run(envFor(database, { AGENTX_DB_MIGRATION_PASSWORD: wrong }));
    expect(code).toBe(1);
    expect(events()).toEqual(['migrate.starting', 'migrate.failed']);
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({ level: 'error', event: 'migrate.failed', err: expect.any(Object) as unknown }),
    );
    expect(findLeaks(capture.text, [wrong, database.connection('owner').password])).toEqual([]);
  });

  it('refuses a broken set of files before touching the database, naming each problem, and exits 1', async () => {
    const fresh = await emptyDatabase();
    const folder = folderWith({ '0001_bad.sql': 'begin;\ncreate table example (id int);\ncommit;\n' });
    const { code, capture } = await run(envFor(fresh), folder);
    expect(code).toBe(1);
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({
        event: 'migrate.failed',
        problems: [expect.stringMatching(/^0001_bad\.sql has BEGIN, COMMIT: /)],
      }),
    );
    const schemas = await fresh.as('admin').query("select 1 from pg_catalog.pg_namespace where nspname = 'migrations'");
    expect(schemas).toEqual([]);
  });

  it('reports a migration that fails, rolled back, naming the file, and exits 1', async () => {
    const fresh = await emptyDatabase();
    const folder = folderWith({ '0001_breaks.sql': 'create table example (id int);\nselect 1/0;\n' });
    const { code, capture } = await run(envFor(fresh), folder);
    expect(code).toBe(1);
    expect(capture.lines().at(-1)).toEqual(
      expect.objectContaining({
        event: 'migrate.failed',
        migration: '0001_breaks.sql',
        err: expect.objectContaining({ type: 'MigrationFailed' }) as unknown,
      }),
    );
    const tables = await fresh
      .as('admin')
      .query("select 1 from information_schema.tables where table_name = 'example'");
    expect(tables).toEqual([]);
  });
});
