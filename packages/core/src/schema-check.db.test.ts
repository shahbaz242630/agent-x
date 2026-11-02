// A release's new table against the check on the schedule, on a real Postgres (4D2e D0): both sides. An image that
// doesn't know a table warns once and then raises the alarm; a known table's drift never waits; a start refuses.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createTestDatabase, LogCapture, type TestDatabase, testLogger, type TestSession } from '@agentx/testing';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';

import {
  checkSchemaOnSchedule,
  createFullServerWatch,
  createReleaseDriftWatch,
  schemaSoundAtStart,
} from './schema-check.ts';

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
    });
    expect(sound).toBe(false);
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'audit.integrity_failed', check: 'schema', when: 'start' }),
    ]);
  });
});
