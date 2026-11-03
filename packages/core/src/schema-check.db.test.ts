// A release's new table against the check on the schedule, on a real Postgres (4D2e D0): both sides. An image that
// doesn't know a table warns once and then raises the alarm; a known table's drift never waits; a start refuses.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createTestDatabase, LogCapture, type TestDatabase, testLogger, type TestSession } from '@agentx/testing';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';

import {
  checkSchemaOnSchedule,
  createFullServerWatch,
  createReleaseDriftWatch,
  RELEASE_START_WAIT_MS,
  schemaSoundAtStart,
} from './schema-check.ts';
import type { Clock } from './shared-kernel/index.ts';

const server = inject('postgres');
const NEW_TABLE = 'create table platform_controls.planted (name text primary key)';

let database: TestDatabase;
let app: Database;
let owner: TestSession;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase({ ...database.connection('app'), tls: 'disable', maxConnections: 2 }, testLogger());
  owner = database.as('owner');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

afterEach(async () => {
  await owner.query('drop table if exists platform_controls.planted');
});

/** A start at the clock's time: whether it may go on, and its warn and error lines. */
async function startAt(clock: Clock) {
  const capture = new LogCapture();
  const sound = await schemaSoundAtStart({ database: app, appRole: 'agentx_app', logger: testLogger(capture), clock });
  const said = capture.lines().filter((line) => line.level === 'warn' || line.level === 'error');
  return { sound, said, events: said.map((line) => `${String(line.level)} ${String(line.event)}`) };
}

const at = (time: Date, msLater: number): Clock => ({ now: () => new Date(time.getTime() + msLater) });

/** One process's checks on the schedule: each run's lines by level and event. */
function aProcess() {
  const capture = new LogCapture();
  const watch = createFullServerWatch(60_000, () => 0);
  const releaseDrift = createReleaseDriftWatch();
  const logger = testLogger(capture);
  return {
    capture,
    run: () => checkSchemaOnSchedule({ database: app, appRole: 'agentx_app', logger }, watch, releaseDrift),
    said: () =>
      capture
        .lines()
        .filter((line) => line.level === 'warn' || line.level === 'error')
        .map((line) => `${String(line.level)} ${String(line.event)}`),
  };
}

describe(`a table this image's migrations did not build (Postgres ${server.version})`, () => {
  it('warns at its first sighting in a process and raises the alarm at every later one', async () => {
    await owner.query(NEW_TABLE);
    await owner.query('grant select, update on platform_controls.planted to agentx_app');
    const process = aProcess();

    await process.run();
    expect(process.said()).toEqual(['warn db.schema_release_drift_seen']);

    await process.run();
    await process.run();
    expect(process.said()).toEqual([
      'warn db.schema_release_drift_seen',
      'error audit.integrity_failed',
      'error audit.integrity_failed',
    ]);
    expect(process.capture.lines().at(-1)).toEqual(
      expect.objectContaining({
        check: 'schema',
        when: 'running',
        problems: expect.arrayContaining(['agentx_app may UPDATE on platform_controls.planted']) as unknown,
      }),
    );
  });

  it('gone and back is still the alarm: a sighting is never forgotten', async () => {
    const process = aProcess();
    await owner.query(NEW_TABLE);
    await process.run();
    await owner.query('drop table platform_controls.planted');
    await process.run();
    await owner.query(NEW_TABLE);
    await process.run();
    expect(process.said()).toEqual(['warn db.schema_release_drift_seen', 'error audit.integrity_failed']);
  });

  it("a known table's drift in the first run beside it is the alarm at once, naming only that", async () => {
    await owner.query(NEW_TABLE);
    await owner.query('alter table audit.events no force row level security');
    const process = aProcess();
    try {
      await process.run();
      expect(process.said()).toEqual(['warn db.schema_release_drift_seen', 'error audit.integrity_failed']);
      expect(process.capture.lines().at(-1)?.problems).toEqual([
        'audit.events does not have row-level security forced',
      ]);
    } finally {
      await owner.query('alter table audit.events force row level security');
    }
  });

  it('a known table alone, first sighting, is the alarm at once', async () => {
    await owner.query('alter table audit.events no force row level security');
    const process = aProcess();
    try {
      await process.run();
      expect(process.said()).toEqual(['error audit.integrity_failed']);
    } finally {
      await owner.query('alter table audit.events force row level security');
    }
  });

  it('a start refuses it, as it refuses any drift: the alarm, and no going on', async () => {
    await owner.query(NEW_TABLE);
    const capture = new LogCapture();
    const sound = await schemaSoundAtStart({
      database: app,
      appRole: 'agentx_app',
      logger: testLogger(capture),
      // No newer migration in this database's ledger, so the time it reads changes nothing.
      clock: { now: () => new Date(0) },
    });
    expect(sound).toBe(false);
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'audit.integrity_failed', check: 'schema', when: 'start' }),
    ]);
  });
});

describe(`a start during a release: an older image meets the newer one's migration (Postgres ${server.version})`, () => {
  const COMING = '9999_coming.sql';

  /** What the migration job does: a ledger row this image has no file for, then the count. Returns its stamp. */
  async function migratedNewer(): Promise<Date> {
    await owner.query("insert into migrations.applied (name, checksum) values ($1, 'not a real file')", [COMING]);
    await owner.query('analyze migrations.applied');
    const [row] = await owner.query<{ at: Date }>(
      "select last_analyze as at from pg_catalog.pg_stat_all_tables where schemaname = 'migrations' and relname = 'applied'",
    );
    if (row === undefined) throw new Error('the ledger has no statistics row');
    return row.at;
  }

  afterEach(async () => {
    await owner.query('delete from migrations.applied where name = $1', [COMING]);
    await owner.query('analyze migrations.applied');
  });

  it('refuses the start with a warning and no alarm, just after the migration', async () => {
    await owner.query(NEW_TABLE);
    const counted = await migratedNewer();

    const { sound, said, events } = await startAt(at(counted, 60_000));
    expect(sound).toBe(false);
    expect(events).toEqual(['warn db.schema_start_waits_release']);
    expect(said[0]).toEqual(
      expect.objectContaining({
        problems: expect.arrayContaining([
          'platform_controls.planted does not have row-level security enabled',
        ]) as unknown,
        ledgerMigrations: expect.any(Number) as unknown,
        countedMsAgo: 60_000,
      }),
    );
    const { ledgerMigrations, builtMigrations } = said[0] as { ledgerMigrations: number; builtMigrations: number };
    expect(ledgerMigrations).toBe(builtMigrations + 1);
  });

  it('still waits a moment before the window ends, and is the alarm as it ends', async () => {
    await owner.query(NEW_TABLE);
    const counted = await migratedNewer();

    expect((await startAt(at(counted, RELEASE_START_WAIT_MS - 1))).events).toEqual([
      'warn db.schema_start_waits_release',
    ]);
    const late = await startAt(at(counted, RELEASE_START_WAIT_MS));
    expect(late.sound).toBe(false);
    expect(late.events).toEqual(['error audit.integrity_failed']);
    expect(late.said[0]).toEqual(expect.objectContaining({ check: 'schema', when: 'start' }));
  });

  it("is the alarm at once when a known table's drift is beside it, however fresh the migration", async () => {
    await owner.query(NEW_TABLE);
    await owner.query('alter table audit.events no force row level security');
    try {
      const counted = await migratedNewer();
      const { sound, said, events } = await startAt(at(counted, 0));
      expect(sound).toBe(false);
      expect(events).toEqual(['error audit.integrity_failed']);
      expect(said[0]?.problems).toEqual(
        expect.arrayContaining([
          'audit.events does not have row-level security forced',
          'platform_controls.planted does not have row-level security enabled',
        ]),
      );
    } finally {
      await owner.query('alter table audit.events force row level security');
    }
  });

  it('is the alarm when the ledger, freshly counted, holds no migration newer than this image', async () => {
    await owner.query(NEW_TABLE);
    await owner.query('analyze migrations.applied');
    const [row] = await owner.query<{ at: Date }>(
      "select last_analyze as at from pg_catalog.pg_stat_all_tables where schemaname = 'migrations' and relname = 'applied'",
    );
    const { sound, events } = await startAt(at(row?.at ?? new Date(0), 0));
    expect(sound).toBe(false);
    expect(events).toEqual(['error audit.integrity_failed']);
  });

  it("is the alarm when the ledger's marks can't be read", async () => {
    await owner.query(NEW_TABLE);
    const counted = await migratedNewer();
    const admin = database.as('admin');
    await admin.query('revoke select on pg_catalog.pg_stat_all_tables from public');
    try {
      const { sound, events } = await startAt(at(counted, 0));
      expect(sound).toBe(false);
      expect(events).toEqual(['error audit.integrity_failed']);
    } finally {
      await admin.query('grant select on pg_catalog.pg_stat_all_tables to public');
    }
  });
});
