import { copyFile, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import {
  createTestDatabase,
  LogCapture,
  type TestClient,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import pg from 'pg';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { builtMigrationNames, readLedgerMarks } from './ledger-marks.ts';
import { PINNED_SEARCH_PATH_VALUE } from './search-path.ts';
import {
  applyMigration,
  isLockTimeout,
  LOCK_TIMEOUT_MS,
  LOCK_TRIES,
  MigrationFailed,
  MigrationNotAtomic,
  MigrationRefused,
  NO_TRANSACTION,
  runMigrations,
} from './migrate.ts';
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

  it('refuses a file that would end its own transaction, before running anything', async () => {
    await write('0001_first.sql', 'create schema demo;');
    await write('0002_second.sql', 'create table demo.one (id int);\ncommit;\ncreate table demo.two (id int);\n');

    await expect(run()).rejects.toThrow(MigrationRefused);
    const [row] = await database
      .as('owner')
      .query<{ found: boolean }>("select pg_catalog.to_regnamespace('demo') is not null as found");
    expect(row?.found).toBe(false);
  });

  it('backs that up: a file that ends the transaction anyway is reported as needing repair, with no ledger row', async () => {
    await run(); // an empty folder: just creates the ledger
    const client = new pg.Client({ ...database.connection('owner'), ssl: false });
    await client.connect();
    try {
      const sqlText = 'create schema demo;\ncommit;\ncreate table demo.after_commit (id int);\n';
      const error = await applyMigration(
        client,
        { name: '0001_first.sql', sql: sqlText, checksum: 'not checked here' },
        createLogger({
          service: 'migrate',
          config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
          destination: capture,
        }),
        LOCK_TIMEOUT_MS,
      ).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(MigrationNotAtomic);
      expect(String(error)).toMatch(/Repair the database by hand/);
    } finally {
      await client.end();
    }
    expect(await tables()).toEqual(['after_commit']);
    expect(await ledger()).toEqual([]);
  });

  it('resets the session after each file, so a SET in one file cannot change the next', async () => {
    await write('0001_first.sql', 'create schema demo;\nset search_path = demo;\ncreate table one (id int);\n');
    // The second file checks the path itself before creating anything: the
    // reset puts back what the startup packet pinned (PINNED_SEARCH_PATH), so
    // a leak from the first file shows as the raised error rather than as a
    // table in the wrong schema.
    await write(
      '0002_second.sql',
      `do $$ begin if pg_catalog.current_setting('search_path') <> '${PINNED_SEARCH_PATH_VALUE}'` +
        " then raise exception 'the search_path of the file before leaked'; end if; end $$;\n" +
        'create table demo.two (id int);\n',
    );
    await run();
    const rows = await database
      .as('owner')
      .query<{ schema: string; name: string }>(
        "select table_schema as schema, table_name as name from information_schema.tables where table_name in ('one', 'two') order by 2",
      );
    expect(rows).toEqual([
      { schema: 'demo', name: 'one' },
      { schema: 'demo', name: 'two' },
    ]);
  });

  it('pins the search_path inside a migration, so an unqualified object is refused rather than landing in public', async () => {
    await write('0001_first.sql', 'create table stray (id int);\n');
    await expect(run()).rejects.toThrow(MigrationFailed);
    expect(await tables()).toEqual([]);
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

  describe('a file that needs a table another transaction holds', () => {
    // A short wait and pause stand in for the job's 2 s and 5 s.
    const runWaiting = (pauseMs: number): Promise<string[]> =>
      runMigrations({
        connection: database.connection('owner'),
        directory: folder,
        logger: createLogger({
          service: 'migrate',
          config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
          destination: capture,
        }),
        lockWait: { timeoutMs: 200, pauseMs },
      });
    const lockWaits = () => capture.lines().filter((line) => line.event === 'db.migration.lock_wait_ran_out');

    async function untilLogged(lines: () => unknown[], count: number): Promise<void> {
      while (lines().length < count) await sleep(10);
    }

    /** A transaction that has read demo.one and stays open, as a request part-way would. */
    async function holdTable(): Promise<TestClient> {
      const holder = await database.connect('owner');
      await holder.query('begin');
      await holder.query('select * from demo.one');
      return holder;
    }

    beforeEach(async () => {
      await write('0001_first.sql', 'create schema demo;\ncreate table demo.one (id int);\n');
      await run();
      // ALTER TABLE takes the table to itself (ACCESS EXCLUSIVE), as 0047's DROP TRIGGER did.
      await write('0002_second.sql', 'alter table demo.one add column note text;\n');
    });

    it('gives up rather than waiting forever, tries LOCK_TRIES times, and leaves the file unapplied', async () => {
      const holder = await holdTable();
      try {
        const error = await runWaiting(10).catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(MigrationFailed);
        expect(isLockTimeout(error)).toBe(true);
        // A line for each try but the last, which fails the run.
        expect(lockWaits().map((line) => [line.migration, line.try])).toEqual(
          Array.from({ length: LOCK_TRIES - 1 }, (_, index) => ['0002_second.sql', index + 1]),
        );
        // The job's own limits (partner, S117): the app's queries queue at most 2 s behind a file.
        expect([LOCK_TIMEOUT_MS, LOCK_TRIES]).toEqual([2000, 5]);
        // The holder never noticed: its transaction still reads the table.
        await holder.query('select * from demo.one');
      } finally {
        await holder.end();
      }
      expect((await ledger()).map((row) => row.name)).toEqual(['0001_first.sql']);
      expect(await runWaiting(10)).toEqual(['0002_second.sql']);
    });

    it('applies the file on a later try once the table is free', async () => {
      const holder = await holdTable();
      const started = performance.now();
      const running = runWaiting(2000);
      try {
        await waitUntilQueued(database.as('admin'), 1);
        // The first try's wait runs out; the holder lets go during the pause.
        await within(5000, untilLogged(lockWaits, 1), 'the first lock wait to run out');
      } finally {
        await holder.end();
      }
      expect(await running).toEqual(['0002_second.sql']);
      expect(lockWaits()).toHaveLength(1);
      // The retry came after the pause, not straight away.
      expect(performance.now() - started).toBeGreaterThanOrEqual(2000);
    });
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
    const files = (await readdir(REPO_MIGRATIONS)).filter((name) => name.endsWith('.sql')).sort();

    expect(files[0]).toBe('0001_baseline.sql');
    expect(await run(REPO_MIGRATIONS)).toEqual(files);
    expect(await run(REPO_MIGRATIONS)).toEqual([]);
    // What an image says it was built with: these same files, by default.
    expect(await builtMigrationNames()).toEqual(files);
  });

  describe("the ledger's marks, which the app role reads in place of the ledger (schema-check.ts)", () => {
    const marks = async () => {
      const app = createDatabase({ ...database.connection('app'), tls: 'disable', maxConnections: 1 }, testLog());
      try {
        return await readLedgerMarks(app);
      } finally {
        await app.destroy();
      }
    };
    const testLog = () =>
      createLogger({
        service: 'test',
        config: { environment: 'test', release: 'r-1', log: { level: 'error', eventCapPerMinute: 100 } },
        destination: { write: () => undefined },
      });

    it('are none before there is a ledger', async () => {
      expect(await marks()).toBeUndefined();
    });

    it('show a ledger never counted as such', async () => {
      await database
        .as('owner')
        .query('create schema migrations; create table migrations.applied (name text primary key, checksum text)');
      expect(await marks()).toEqual({ rows: -1, liveRows: 0, countedMsAgo: undefined });
    });

    /** When the ledger was last counted by hand, as the database stamped it. */
    const stamped = async () => {
      const [row] = await database
        .as('owner')
        .query<{ at: Date | null }>(
          "select last_analyze as at from pg_catalog.pg_stat_all_tables where schemaname = 'migrations' and relname = 'applied'",
        );
      return row?.at ?? undefined;
    };

    it('count the rows, now and as counted, and stamp when, on every run, so a rerun recounts', async () => {
      await write('0001_first.sql', 'create schema demo;');
      await write('0002_second.sql', 'create table demo.two (id int);');
      await run();
      expect(await marks()).toEqual({ rows: 2, liveRows: 2, countedMsAgo: expect.any(Number) as unknown });
      const first = await stamped();

      await run();
      expect(await marks()).toEqual(expect.objectContaining({ rows: 2, liveRows: 2 }));
      expect((await stamped())?.getTime()).toBeGreaterThan(first?.getTime() ?? Infinity);
    });

    it('a count that cannot be made only warns: the files are in, and the run succeeds', async () => {
      await write('0001_first.sql', 'create schema demo;');
      await run();
      const before = await stamped();
      // ANALYZE's own lock, held: the count's bounded wait runs out.
      const holder = await database.connect('owner');
      await holder.query('begin');
      await holder.query('lock table migrations.applied in share update exclusive mode');
      try {
        await write('0002_second.sql', 'create table demo.two (id int);');
        const applied = await runMigrations({
          connection: database.connection('owner'),
          directory: folder,
          logger: createLogger({
            service: 'migrate',
            config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
            destination: capture,
          }),
          lockWait: { timeoutMs: 100, pauseMs: 10 },
        });
        expect(applied).toEqual(['0002_second.sql']);
      } finally {
        await holder.end();
      }
      expect(capture.lines().filter((line) => line.level === 'warn')).toEqual([
        expect.objectContaining({ event: 'db.migration.ledger_not_counted' }),
      ]);
      expect(await stamped()).toEqual(before);
      expect(await tables()).toEqual(['two']);
    });
  });

  describe('a file run outside a transaction, building concurrently (4D2e D8)', () => {
    const runWaiting = (timeoutMs: number): Promise<string[]> =>
      runMigrations({
        connection: database.connection('owner'),
        directory: folder,
        logger: createLogger({
          service: 'migrate',
          config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
          destination: capture,
        }),
        lockWait: { timeoutMs, pauseMs: 10 },
      });
    const owner = () => database.as('owner');
    const indexValid = async (name: string) =>
      (
        await owner().query<{ valid: boolean }>(
          `select i.indisvalid as valid from pg_catalog.pg_index i
             join pg_catalog.pg_class c on c.oid = i.indexrelid where c.relname = $1`,
          [name],
        )
      ).map(({ valid }) => valid);
    const logged = (event: string) => capture.lines().filter((line) => line.event === event);

    beforeEach(async () => {
      await write(
        '0001_first.sql',
        'create schema demo;\ncreate table demo.one (id int);\ninsert into demo.one values (1), (2);\n',
      );
      await run();
    });

    it('lets writes go on while it builds: it waits only for transactions already open, and holds back none', async () => {
      // A writer part-way: the build waits for it to end, as Postgres's concurrent build does.
      const holder = await database.connect('owner');
      await holder.query('begin');
      await holder.query('insert into demo.one values (3)');
      await write(
        '0002_index.sql',
        `${NO_TRANSACTION}\ncreate index concurrently if not exists one_id on demo.one (id);\n`,
      );
      const running = runWaiting(10_000);
      try {
        await waitUntilQueued(database.as('admin'), 1);
        // A write while the build waits: through at once, where a build in a transaction would hold it to its end.
        await within(5000, owner().query('insert into demo.one values (4)'), 'a write during the build');
      } finally {
        await holder.query('commit');
        await holder.end();
      }
      expect(await running).toEqual(['0002_index.sql']);
      expect(await indexValid('one_id')).toEqual([true]);
      expect((await ledger()).map(({ name }) => name)).toEqual(['0001_first.sql', '0002_index.sql']);
    });

    it('a build that failed leaves its index not valid and no ledger row; the next run drops it and builds it again', async () => {
      await owner().query('insert into demo.one values (7), (7)');
      await write(
        '0002_index.sql',
        `${NO_TRANSACTION}\ncreate unique index concurrently if not exists one_id on demo.one (id);\n`,
      );
      const error = await runWaiting(2000).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(MigrationFailed);
      expect(await indexValid('one_id')).toEqual([false]);
      expect((await ledger()).map(({ name }) => name)).toEqual(['0001_first.sql']);

      await owner().query('delete from demo.one where id = 7');
      expect(await runWaiting(2000)).toEqual(['0002_index.sql']);
      expect(await indexValid('one_id')).toEqual([true]);
      expect(logged('db.migration.invalid_index_dropped')).toEqual([
        expect.objectContaining({ migration: '0002_index.sql', index: 'demo.one_id' }),
      ]);
    });

    it('waits for an open transaction no longer than the lock limit, tries again, then builds once it ends', async () => {
      const holder = await database.connect('owner');
      await holder.query('begin');
      await holder.query('insert into demo.one values (3)');
      await write(
        '0002_index.sql',
        `${NO_TRANSACTION}\ncreate index concurrently if not exists one_id on demo.one (id);\n`,
      );
      try {
        const error = await runWaiting(200).catch((caught: unknown) => caught);
        expect(isLockTimeout(error)).toBe(true);
        expect(logged('db.migration.lock_wait_ran_out')).toHaveLength(LOCK_TRIES - 1);
      } finally {
        await holder.query('commit');
        await holder.end();
      }
      expect((await ledger()).map(({ name }) => name)).toEqual(['0001_first.sql']);
      expect(await runWaiting(2000)).toEqual(['0002_index.sql']);
      expect(await indexValid('one_id')).toEqual([true]);
    });

    it('drops concurrently too, and a run again does nothing more', async () => {
      await owner().query('create index old_id on demo.one (id)');
      await write('0002_index.sql', `${NO_TRANSACTION}\ndrop index concurrently if exists demo.old_id;\n`);
      expect(await runWaiting(2000)).toEqual(['0002_index.sql']);
      expect(await indexValid('old_id')).toEqual([]);
      expect(await runWaiting(2000)).toEqual([]);
    });
  });

  describe('a file aborted to break a deadlock (4D2e D8)', () => {
    it('is tried again, its first try rolled back whole, and said', async () => {
      await write(
        '0001_first.sql',
        'create schema demo;\ncreate table demo.one (id int);\ncreate table demo.two (id int);\n',
      );
      await run();
      await write(
        '0002_second.sql',
        'lock table demo.one in access exclusive mode;\nlock table demo.two in access exclusive mode;\nalter table demo.one add column note text;\n',
      );
      // Holds demo.two, then reaches for demo.one, which the file holds while it waits for demo.two: a deadlock. Its
      // own check waits 10 s, the file's the server's 1 s, so the file is the one aborted.
      const holder = await database.connect('admin');
      await holder.query("set deadlock_timeout = '10s'");
      await holder.query('begin');
      await holder.query('select * from demo.two');
      const running = runMigrations({
        connection: database.connection('owner'),
        directory: folder,
        logger: createLogger({
          service: 'migrate',
          config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
          destination: capture,
        }),
        lockWait: { timeoutMs: 8000, pauseMs: 10 },
      });
      try {
        await waitUntilQueued(database.as('admin'), 1);
        await within(8000, holder.query('select * from demo.one'), 'the holder reaching for demo.one');
      } finally {
        await holder.query('commit');
        await holder.end();
      }
      expect(await running).toEqual(['0002_second.sql']);
      expect(capture.lines().filter((line) => line.event === 'db.migration.deadlocked')).toEqual([
        expect.objectContaining({ migration: '0002_second.sql', try: 1 }),
      ]);
    });
  });

  describe('0073 against a request transaction committing as it runs (4D2e D8)', () => {
    it('waits for it, and both go through: its locks are taken in the order commits take them', async () => {
      for (const name of (await readdir(REPO_MIGRATIONS)).filter((file) => file < '0073')) {
        await copyFile(path.join(REPO_MIGRATIONS, name), path.join(folder, name));
      }
      await run();
      await copyFile(path.join(REPO_MIGRATIONS, '0073_expiry_marks.sql'), path.join(folder, '0073_expiry_marks.sql'));
      await database.as('admin').query('insert into directory.orgs (org_id) values ($1)', [ORG_A]);
      // As a request's transaction part-way: it has the requests' table, and marks its work at its commit (0072).
      const writer = await database.connect('admin');
      await writer.query("set deadlock_timeout = '10s'");
      await writer.query('begin');
      await writer.query('select 1 from spend_requests.requests limit 1');
      const running = runMigrations({
        connection: database.connection('owner'),
        directory: folder,
        logger: createLogger({
          service: 'migrate',
          config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
          destination: capture,
        }),
        lockWait: { timeoutMs: 8000, pauseMs: 10 },
      });
      try {
        await waitUntilQueued(database.as('admin'), 1);
        // Its mark, as 0072's deferred trigger writes it at commit: org_work is not yet the file's, so it goes through.
        await within(
          5000,
          writer.query(
            `insert into directory.org_work (org_id, job, due_at) values ($1, 'hand_off', pg_catalog.now())`,
            [ORG_A],
          ),
          'the commit marking its work',
        );
        await writer.query('commit');
      } finally {
        await writer.end();
      }
      expect(await running).toEqual(['0073_expiry_marks.sql']);
      expect(capture.lines().filter((line) => line.event === 'db.migration.deadlocked')).toEqual([]);
    });
  });
});
