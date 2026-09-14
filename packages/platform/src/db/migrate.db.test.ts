import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createTestDatabase, LogCapture, type TestDatabase } from '@agentx/testing';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { MigrationFailed, MigrationRefused, runMigrations } from './migrate.ts';
import { TenantContextError } from './tenant.ts';

const REPO_MIGRATIONS = fileURLToPath(new URL('../../../../db/migrations', import.meta.url));
const ORG_A = '0199a000-0000-7000-8000-00000000000a';

const server = inject('postgres');
let database: TestDatabase;
let folder: string;
let capture: LogCapture;

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'empty' });
  folder = await mkdtemp(path.join(tmpdir(), 'agentx-migrations-'));
  capture = new LogCapture();
});

afterEach(async () => {
  await database.drop();
  await rm(folder, { recursive: true, force: true });
});

const write = (name: string, text: string): Promise<void> => writeFile(path.join(folder, name), text, 'utf8');

const run = (directory = folder): Promise<string[]> =>
  runMigrations({
    connection: database.connection('owner'),
    directory,
    logger: createLogger({
      service: 'migrate',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: capture,
    }),
  });

const ledger = (): Promise<{ name: string; checksum: string }[]> =>
  database.as('owner').query('select name, checksum from migrations.applied order by name');

const tables = async (): Promise<string[]> => {
  const rows = await database
    .as('owner')
    .query<{ name: string }>(
      "select table_name as name from information_schema.tables where table_schema = 'demo' order by 1",
    );
  return rows.map((row) => row.name);
};

describe(`runMigrations (Postgres ${server.version})`, () => {
  it('applies each file once, in order, records it in the ledger, and logs it', async () => {
    await write('0001_first.sql', 'create schema demo;\ncreate table demo.one (id int);\n');
    await write('0002_second.sql', 'create table demo.two (id int);\n');

    expect(await run()).toEqual(['0001_first.sql', '0002_second.sql']);
    expect(await tables()).toEqual(['one', 'two']);
    expect((await ledger()).map((row) => row.name)).toEqual(['0001_first.sql', '0002_second.sql']);
    expect(capture.lines().map((line) => line.event)).toEqual([
      'db.migration.applied',
      'db.migration.applied',
      'db.migrations.done',
    ]);
    expect(capture.lines()[2]).toMatchObject({ applied: 2, total: 2 });
  });

  it('applies nothing the second time, and only new files later', async () => {
    await write('0001_first.sql', 'create schema demo;');
    expect(await run()).toEqual(['0001_first.sql']);
    expect(await run()).toEqual([]);
    await write('0002_second.sql', 'create table demo.two (id int);');
    expect(await run()).toEqual(['0002_second.sql']);
  });

  it('refuses to run when an applied file was changed afterwards', async () => {
    await write('0001_first.sql', 'create schema demo;');
    await run();
    await write('0001_first.sql', 'create schema demo; create table demo.sneaked (id int);');
    await write('0002_second.sql', 'create table demo.two (id int);');

    await expect(run()).rejects.toThrow(new MigrationRefused(['0001_first.sql was changed after it was applied']));
    expect(await tables()).toEqual([]);
  });

  it('refuses to run when the database has a migration this build lacks', async () => {
    await write('0001_first.sql', 'create schema demo;');
    await write('0002_newer.sql', 'create table demo.newer (id int);');
    await run();
    const older = await mkdtemp(path.join(tmpdir(), 'agentx-migrations-'));
    try {
      await writeFile(path.join(older, '0001_first.sql'), 'create schema demo;', 'utf8');
      await expect(run(older)).rejects.toThrow(
        new MigrationRefused(['the database has 0002_newer.sql applied where this build has no file']),
      );
      await writeFile(path.join(older, '0002_other.sql'), 'create table demo.other (id int);', 'utf8');
      await expect(run(older)).rejects.toThrow(
        new MigrationRefused(['the database has 0002_newer.sql applied where this build has 0002_other.sql']),
      );
    } finally {
      await rm(older, { recursive: true, force: true });
    }
  });

  it('rolls a failing file back completely, keeps the files before it, and names it', async () => {
    await write('0001_first.sql', 'create schema demo;');
    await write('0002_broken.sql', 'create table demo.half (id int);\nselect no_such_column from demo.half;\n');
    await write('0003_never.sql', 'create table demo.never (id int);');

    const error = await run().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(MigrationFailed);
    expect((error as MigrationFailed).migration).toBe('0002_broken.sql');
    expect(String((error as MigrationFailed).cause)).toMatch(/no_such_column/);
    expect(await tables()).toEqual([]);
    expect((await ledger()).map((row) => row.name)).toEqual(['0001_first.sql']);
  });

  it('stops at a file that ends its own transaction', async () => {
    await write('0001_first.sql', 'create schema demo;\ncommit;\ncreate table demo.after_commit (id int);\n');

    const error = await run().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(MigrationFailed);
    expect(String((error as MigrationFailed).cause)).toMatch(/ended its own transaction/);
    expect(await ledger()).toEqual([]);
  });

  it('lets only one run work at a time, so two deploys at once apply each file once', async () => {
    await write('0001_first.sql', 'create schema demo;');
    await write('0002_second.sql', 'create table demo.two (id int);');
    await write('0003_third.sql', 'create table demo.three (id int); select pg_catalog.pg_sleep(0.2);');

    const [first, second] = await Promise.all([run(), run()]);
    expect([...first, ...second].sort()).toEqual(['0001_first.sql', '0002_second.sql', '0003_third.sql']);
    expect(await ledger()).toHaveLength(3);
  });

  it('refuses a connection that already carries a tenant', async () => {
    await write('0001_first.sql', 'create schema demo;');
    // eslint-disable-next-line agentx/no-string-built-sql -- Test setup: the database name is generated, and ALTER can't take it as a parameter.
    await database
      .as('admin')
      .query(`alter role agentx_owner in database ${database.name} set app.org_id = '${ORG_A}'`);
    try {
      await expect(run()).rejects.toThrow(TenantContextError);
    } finally {
      // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
      await database.as('admin').query(`alter role agentx_owner in database ${database.name} reset all`);
    }
  });

  it('survives losing its connection mid-migration: logs it, and reports the failure', async () => {
    await write('0001_first.sql', 'select pg_catalog.pg_terminate_backend(pg_catalog.pg_backend_pid());');

    await expect(run()).rejects.toThrow(MigrationFailed);
    const events = capture.lines().map((line) => line.event);
    expect(events).toContain('db.migration.rollback_failed');
    expect(events).toContain('db.migration.connection_lost');
  });

  it('applies the repository’s own migrations', async () => {
    expect(await run(REPO_MIGRATIONS)).toEqual(['0001_baseline.sql']);
    expect(await run(REPO_MIGRATIONS)).toEqual([]);
  });
});
