// S206 (faster detection, R-15): the security events' five-minute tally, on
// the real migrated schema as the app role, the database's owner deleting
// rows as the admin role. A row of yesterday or today deleted, from the
// global table or an organisation's, is the alarm at the next run, and its
// day's lower count is logged at once; a day that only grew is logged again
// at most hourly; a log the database refuses says so and keeps its counts. And
// hourly, every retained day counted: a sealed day's row deleted is the alarm
// at the next hourly count, a day leaving the retention is none.
import { v7Floor } from '@agentx/core/modules/activity';
import { createSecurityEvents, type SecurityEvent } from '@agentx/core/modules/security-events';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { keys } from './mandate-world.helper.test.ts';
import type { SecuritySealTables } from './security-seal.ts';
import { createSecurityTally } from './security-tally.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SecuritySealTables>;
let capture: LogCapture;
let clock: FixedClock;
let org: string;
const ids = new SequentialIds(0x5206_7a11_0000);
const HOUR_MS = 60 * 60_000;
const TODAY = '2027-01-21';
const YESTERDAY = '2027-01-20';

let made = 0;
/** IDs made at the clock's time, as the API's are made as it writes. */
const idsAt = (at: Clock): IdGenerator => ({
  next: () => {
    made += 1;
    return `${v7Floor(at.now().getTime()).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
  },
});

/** A failed sign-in counted in the minute before `at`, the organisation's when `orgId` is named. */
const failed = (at: string, change: Partial<SecurityEvent> = {}): SecurityEvent => ({
  kind: 'sign_in_failed',
  reason: 'state_mismatch',
  ip: '203.0.113.7',
  userId: undefined,
  windowStart: new Date(Date.parse(at) - 60_000),
  count: 2,
  ...change,
});

/** The events written by the app at `at`, each with its MAC. */
const written = (at: string, events: readonly SecurityEvent[]) => {
  const then = new FixedClock(new Date(at));
  return createSecurityEvents({ ids: idsAt(then), clock: then, keys, retentionDays: 30 }).record(app, events);
};

const tally = (list = () => Promise.resolve([org])) =>
  createSecurityTally({ list, database: app, clock, logger: testLogger(capture), retentionDays: 30, page: 2 });

const owner = () => database.as('admin');

/** The tally lines logged since the test began: each its log ('' for the global table), day and rows. */
const lines = () =>
  capture
    .lines()
    .filter((line) => line.event === 'security_seal.tally')
    .map(({ orgId, day, rows }) => [orgId ?? '', day, rows]);

const alarms = () =>
  capture
    .lines()
    .filter((line) => line.event === 'audit.integrity_failed' && line.check === 'security_event')
    .map(({ orgId, reason, day }) => [orgId ?? '', reason, day]);

/** The organisation's first row of today, as the owner sees it. */
const firstToday = async () => {
  const rows = await owner().query<{ id: string }>(
    'select id from security.org_events where org_id = $1 and id >= $2::uuid order by id limit 1',
    [org, v7Floor(Date.parse(`${TODAY}T00:00:00Z`))],
  );
  return rows[0]?.id;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SecuritySealTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  clock = new FixedClock(new Date(`${TODAY}T12:00:00.000Z`));
  org = ids.next();
  await owner().query('insert into directory.orgs (org_id) values ($1)', [org]);
  await owner().query('delete from security.events');
  await written(`${YESTERDAY}T09:00:00.000Z`, [
    failed(`${YESTERDAY}T09:00:00.000Z`),
    failed(`${YESTERDAY}T09:00:00.000Z`, { ip: '203.0.113.8' }),
  ]);
  await written(`${TODAY}T09:00:00.000Z`, [
    failed(`${TODAY}T09:00:00.000Z`, { kind: 'rate_limited', reason: 'per_user', orgId: org }),
    failed(`${TODAY}T09:00:00.000Z`, { kind: 'rate_limited', reason: 'per_user', orgId: org, ip: '203.0.113.9' }),
  ]);
});

describe('SEC-DB-18 the security events’ five-minute tally (S206, R-15)', () => {
  it('logs each day once as first counted, then nothing while it stands, and no alarm', async () => {
    const run = tally();
    await run.run();
    expect(lines()).toEqual([
      ['', YESTERDAY, 2],
      [org, TODAY, 2],
    ]);
    clock.advanceBy(5 * 60_000);
    await run.run();
    expect(lines()).toHaveLength(2);
    expect(alarms()).toEqual([]);
  });

  it('an organisation’s row deleted today: the alarm at the next run, and its lower count logged at once', async () => {
    const run = tally();
    await run.run();
    await owner().query('delete from security.org_events where id = $1', [await firstToday()]);
    clock.advanceBy(5 * 60_000);
    await run.run();
    expect(alarms()).toEqual([[org, 'count_fell', TODAY]]);
    expect(lines().at(-1)).toEqual([org, TODAY, 1]);
  });

  it('every global row of yesterday deleted: the alarm, the day logged as none, and then forgotten', async () => {
    const run = tally();
    await run.run();
    await owner().query('delete from security.events');
    clock.advanceBy(5 * 60_000);
    await run.run();
    expect(alarms()).toEqual([['', 'count_fell', YESTERDAY]]);
    expect(lines().at(-1)).toEqual(['', YESTERDAY, 0]);
    clock.advanceBy(5 * 60_000);
    await run.run();
    expect(alarms()).toHaveLength(1);
  });

  it('a day that grew is logged again only an hour after its last line, and a fall below what grew is the alarm', async () => {
    const run = tally();
    await run.run();
    await written(`${TODAY}T12:00:00.000Z`, [failed(`${TODAY}T12:00:00.000Z`, { orgId: org, reason: 'per_ip' })]);
    clock.advanceBy(5 * 60_000);
    await run.run();
    expect(lines()).toHaveLength(2);
    // Fallen back to the two it last logged: still a fall from the three it read.
    await owner().query('delete from security.org_events where id = $1', [await firstToday()]);
    clock.advanceBy(5 * 60_000);
    await run.run();
    expect(alarms()).toEqual([[org, 'count_fell', TODAY]]);
    expect(lines().at(-1)).toEqual([org, TODAY, 2]);

    await written(`${TODAY}T12:10:00.000Z`, [failed(`${TODAY}T12:10:00.000Z`, { orgId: org, reason: 'per_ip' })]);
    clock.advanceBy(HOUR_MS - 1);
    await run.run();
    expect(lines()).toHaveLength(3);
    clock.advanceBy(1);
    await run.run();
    expect(lines().at(-1)).toEqual([org, TODAY, 3]);
  });

  it('counts yesterday and today alone: a day before is no one’s to tally, and the next day starts afresh', async () => {
    const run = tally();
    await run.run();
    clock.advanceBy(DAY_MS);
    await run.run();
    // Yesterday's global rows are now the day before: not counted, and no alarm for their going.
    expect(lines()).toEqual([
      ['', YESTERDAY, 2],
      [org, TODAY, 2],
    ]);
    expect(alarms()).toEqual([]);
  });

  it('a log the database refuses says so, keeps its counts, and raises no alarm; a list that fails, the run’s line', async () => {
    const run = tally(() => Promise.resolve([org, 'not-an-organisation', org.toUpperCase()]));
    await run.run();
    await owner().query('revoke select on security.org_events, security.events from agentx_app');
    try {
      clock.advanceBy(5 * 60_000);
      await run.run();
    } finally {
      await owner().query('grant select on security.org_events, security.events to agentx_app');
    }
    expect(capture.lines().filter(({ event }) => event === 'security_tally.missed')).toEqual([
      expect.objectContaining({ level: 'warn' }),
      expect.objectContaining({ level: 'warn', orgId: org }),
    ]);
    clock.advanceBy(5 * 60_000);
    await run.run();
    expect(alarms()).toEqual([]);
    expect(lines()).toHaveLength(2);

    await tally(() => Promise.reject(new Error('the directory is away'))).run();
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'security_tally.run_failed' }));
  });

  it('every retained day counted hourly: an older day’s row deleted is the alarm at the next hourly count, not before', async () => {
    const OLDER = '2027-01-12';
    await written(`${OLDER}T09:00:00.000Z`, [
      failed(`${OLDER}T09:00:00.000Z`, { orgId: org }),
      failed(`${OLDER}T09:00:00.000Z`, { orgId: org, ip: '203.0.113.9' }),
    ]);
    const run = tally();
    await run.run();
    const rows = await owner().query<{ id: string }>(
      'select id from security.org_events where org_id = $1 and id < $2::uuid order by id limit 1',
      [org, v7Floor(Date.parse(`${YESTERDAY}T00:00:00Z`))],
    );
    await owner().query('delete from security.org_events where id = $1', [rows[0]?.id]);
    clock.advanceBy(HOUR_MS - 1);
    await run.run();
    expect(alarms()).toEqual([]);
    clock.advanceBy(1);
    await run.run();
    expect(alarms()).toEqual([[org, 'count_fell', OLDER]]);
    // No line for an older day: the alarm alone.
    expect(lines().filter(([, day]) => day === OLDER)).toEqual([]);
    // Yesterday's fall is the five-minute tally's alarm alone, not the hourly count's too.
    await owner().query('delete from security.events');
    clock.advanceBy(HOUR_MS);
    await run.run();
    expect(alarms()).toEqual([
      [org, 'count_fell', OLDER],
      ['', 'count_fell', YESTERDAY],
    ]);
  });

  it('a day leaving the retention, the sweep’s to take, is no alarm', async () => {
    await written('2026-12-24T09:00:00.000Z', [failed('2026-12-24T09:00:00.000Z', { orgId: org })]);
    const run = tally();
    await run.run();
    clock.advanceBy(DAY_MS);
    await owner().query('delete from security.org_events where org_id = $1 and id < $2::uuid', [
      org,
      v7Floor(Date.parse('2026-12-25T00:00:00Z')),
    ]);
    await run.run();
    expect(alarms()).toEqual([]);
  });
});
