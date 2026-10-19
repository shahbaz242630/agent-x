// Phase 3 L6: the daily seal job on the real migrated schema, as the app
// role: each closed day of an organisation's activity log sealed on its
// audit chain from its first row's day, quiet days too, today and the grace
// after midnight left; nothing sealed twice, by a second run or by a server
// that sealed the day meanwhile (its lock forced, ADR-006 §6, 11b); a day
// that moved while it was digested left for the next run; at most 31 days a
// run.
import { ACTIVITY_SEALED, type ActivityTables, digestOfDay, v7Floor } from '@agentx/core/modules/activity';
import { createAuditTrail } from '@agentx/core/modules/audit';
import { createDatabase, type Database, holdTransactionLock, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createActivitySealCheck } from './activity-seal-check.ts';
import { ACTIVITY_SEAL_LOCK, createActivitySeal } from './activity-seal.ts';
import { keys, mandateWorld, type MandateWorldTables, type World } from './mandate-world.helper.test.ts';

type Tables = MandateWorldTables & ActivityTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0xa16b_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000a16b0';

let clock: FixedClock;
let capture: LogCapture;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'activity-seal' });
const { world } = shared;

let made = 0;
/** A UUIDv7 of the instant `at`, as a row written then has. */
const idAt = (at: string) => {
  made += 1;
  return `${v7Floor(Date.parse(at)).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
};

/** The SHA-256 of the empty text: a quiet day's digest. */
const NOTHING = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** A request of the world's admin written at `written`. */
const written = (w: World, at: string) =>
  withTenant(app, w.org, (tx) =>
    tx
      .insertInto('access.requests')
      .values({
        org_id: w.org,
        id: idAt(at),
        recorded_at: new Date(at),
        actor_type: 'user',
        actor_id: w.admin.userId,
        method: 'GET',
        route: '/v1/members',
        path_ids: [],
        status: 200,
        reason: null,
        correlation_id: CORRELATION,
        duration_ms: 3,
        ip: null,
        country: null,
        city: null,
        time_zone: null,
        time_zone_from: null,
      })
      .execute(),
  );

const sealFor = (w: World) =>
  createActivitySeal({
    list: () => Promise.resolve([w.org]),
    database: app,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
    batch: 2,
  });

/** The organisation's seals, oldest first, each its details. */
const sealsOf = (w: World): Promise<Record<string, unknown>[]> =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        .selectFrom('audit.events')
        .select(['actor_type', 'actor_id', 'details'])
        .where('action', '=', ACTIVITY_SEALED)
        .orderBy('seq')
        .execute()
    ).map((row) => ({
      actor: `${row.actor_type}:${row.actor_id}`,
      ...(JSON.parse(row.details) as Record<string, unknown>),
    })),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-21T00:14:00.000Z'));
  capture = new LogCapture();
});

describe('L6 the daily seal (decision 26, ADR-011 §7)', () => {
  it('seals each closed day from the first row’s, quiet days too, today and the grace after midnight left; once', async () => {
    const w = await world();
    await written(w, '2026-10-17T09:00:00.000Z');
    await written(w, '2026-10-19T09:00:00.000Z');
    await written(w, '2026-10-19T10:00:00.000Z');
    await written(w, '2026-10-20T23:00:00.000Z');

    await sealFor(w).run();
    const seals = await sealsOf(w);

    // The 20th closed 14 minutes ago: inside the grace, so not yet.
    expect(seals.map((seal) => [seal.day, seal.requests])).toEqual([
      ['2026-10-17', 1],
      ['2026-10-18', 0],
      ['2026-10-19', 2],
    ]);
    const digest = await digestOfDay((work) => withTenant(app, w.org, work), w.org, '2026-10-19', 100);
    expect(seals[2]).toEqual({
      actor: 'system:api',
      day: '2026-10-19',
      requests: 2,
      digest: digest.digest,
      idFrom: digest.idFrom,
      idTo: digest.idTo,
      form: 1,
      correlationId: expect.stringMatching(/^[0-9a-f-]{36}$/) as unknown,
    });
    expect(seals[1]).toMatchObject({ idFrom: null, idTo: null, digest: NOTHING });

    clock.advanceBy(60_000);
    await sealFor(w).run();
    await sealFor(w).run();
    expect((await sealsOf(w)).map((seal) => seal.day)).toEqual([
      '2026-10-17',
      '2026-10-18',
      '2026-10-19',
      '2026-10-20',
    ]);
  });

  it('reads only seals as seals: another event about the activity log after them seals nothing again', async () => {
    const w = await world();
    await written(w, '2026-10-19T09:00:00.000Z');
    await sealFor(w).run();
    // A download of the log, recorded about it after its seal.
    await withTenant(app, w.org, (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: { type: 'user', id: w.admin.userId },
        action: 'access_log.exported',
        subject: { type: 'access_log', id: w.org, version: 1 },
        details: { format: 'csv' },
      }),
    );

    await sealFor(w).run();

    expect((await sealsOf(w)).map((seal) => seal.day)).toEqual(['2026-10-19']);
  });

  it('seals nothing for an organisation with no rows', async () => {
    const w = await world();

    await sealFor(w).run();

    expect(await sealsOf(w)).toEqual([]);
  });

  it('seals at most 31 days a run, catching up over the next', async () => {
    const w = await world();
    await written(w, '2026-08-01T09:00:00.000Z');

    await sealFor(w).run();
    expect(await sealsOf(w)).toHaveLength(31);
    await sealFor(w).run();
    await sealFor(w).run();

    const days = (await sealsOf(w)).map((seal) => seal.day);
    expect(days[0]).toBe('2026-08-01');
    // The 20th is still inside its grace.
    expect(days.at(-1)).toBe('2026-10-19');
    expect(new Set(days).size).toBe(days.length);
  });

  it('FX-RACE a day sealed by another server meanwhile: the run waits on the seal lock, then seals it no second time', async () => {
    const w = await world();
    await written(w, '2026-10-20T09:00:00.000Z');
    clock.advanceBy(60_000);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // Another server's seal of the 20th, its lock taken and its event recorded, held open before it commits.
    const other = withTenant(app, w.org, async (tx) => {
      await holdTransactionLock(tx, ACTIVITY_SEAL_LOCK, w.org);
      await createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: { type: 'system', id: 'api' },
        action: ACTIVITY_SEALED,
        subject: { type: 'access_log', id: w.org, version: 1 },
        details: { day: '2026-10-20', requests: 1, digest: 'x', idFrom: null, idTo: null, form: 1 },
      });
      holding(undefined);
      await gate;
    });
    await held;
    const run = within(20_000, sealFor(w).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    await other;
    await run;
    expect((await sealsOf(w)).map((seal) => seal.day)).toEqual(['2026-10-20']);
  });

  it('FX-RACE a day that moved while it was digested: left unsealed, and the run stops there, no day skipped', async () => {
    const w = await world();
    await written(w, '2026-10-19T09:00:00.000Z');
    // The 20th is closed too: a run that went on past the 19th would seal it, and never the 19th.
    clock.advanceBy(60_000);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The seal lock held while a row lands in the closed day (a server's clock far behind, or tampering).
    const other = withTenant(app, w.org, async (tx) => {
      await holdTransactionLock(tx, ACTIVITY_SEAL_LOCK, w.org);
      holding(undefined);
      await gate;
    });
    await held;
    const run = within(20_000, sealFor(w).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    await written(w, '2026-10-19T10:00:00.000Z');
    open(undefined);

    await other;
    await run;
    expect(await sealsOf(w)).toEqual([]);
    expect(capture.lines().filter((line) => line.event === 'access_log_seal.moved')).toEqual([
      expect.objectContaining({ level: 'warn', day: '2026-10-19', digested: 1, counted: 2 }),
    ]);
    await sealFor(w).run();
    expect((await sealsOf(w)).map((seal) => [seal.day, seal.requests])).toEqual([
      ['2026-10-19', 2],
      ['2026-10-20', 0],
    ]);
  });

  it('FX-RACE a row replaced in the day while it was digested, the count the same: its last ID shows it moved', async () => {
    const w = await world();
    await written(w, '2026-10-20T09:00:00.000Z');
    clock.advanceBy(60_000);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const other = withTenant(app, w.org, async (tx) => {
      await holdTransactionLock(tx, ACTIVITY_SEAL_LOCK, w.org);
      holding(undefined);
      await gate;
    });
    await held;
    const run = within(20_000, sealFor(w).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    // Past the app: its one row deleted and another written later the same day.
    await database.as('admin').query('delete from access.requests where org_id = $1', [w.org]);
    await written(w, '2026-10-20T10:00:00.000Z');
    open(undefined);

    await other;
    await run;
    expect(await sealsOf(w)).toEqual([]);
    expect(capture.lines().filter((line) => line.event === 'access_log_seal.moved')).toEqual([
      expect.objectContaining({ day: '2026-10-20', digested: 1, counted: 1 }),
    ]);
  });

  it('seals nothing once stopped, and logs an organisation that fails, going on to the next', async () => {
    const w = await world();
    await written(w, '2026-10-19T09:00:00.000Z');
    const stopping = new AbortController();
    stopping.abort();
    await sealFor(w).run(stopping.signal);
    expect(await sealsOf(w)).toEqual([]);

    const both = createActivitySeal({
      list: () => Promise.resolve(['not-an-organisation', w.org]),
      database: app,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    });
    await both.run();

    expect(capture.lines().filter((line) => line.event === 'access_log_seal.failed')).toEqual([
      expect.objectContaining({ level: 'error', reason: 'error' }),
    ]);
    expect((await sealsOf(w)).map((seal) => seal.day)).toEqual(['2026-10-19']);
  });

  it('seals nothing past a newest seal tampered with: the alarm raised and the organisation held', async () => {
    const w = await world();
    await written(w, '2026-10-18T09:00:00.000Z');
    await sealFor(w).run();
    // The newest seal, the 19th's, rewritten past the app: its MAC no longer holds.
    await database
      .as('admin')
      .query(
        "update audit.events set details = replace(details, '2026-10-19', '2026-10-29') where action = $1 and org_id = $2 and details like '%2026-10-19%'",
        [ACTIVITY_SEALED, w.org],
      );
    clock.advanceBy(86_400_000);

    await sealFor(w).run();

    expect(await sealsOf(w)).toHaveLength(2);
    expect(capture.lines().map((line) => line.event)).toEqual(
      expect.arrayContaining(['audit.integrity_failed', 'audit.integrity_hold_set']),
    );
  });

  it('logs a run whose list fails', async () => {
    const w = await world();
    const seal = createActivitySeal({
      list: () => Promise.reject(new Error('the directory is down')),
      database: app,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    });

    await seal.run();

    expect(w.org).toBeDefined();
    expect(capture.lines().filter((line) => line.event === 'access_log_seal.run_failed')).toEqual([
      expect.objectContaining({ level: 'error' }),
    ]);
  });
});

describe('L6c the seals checked (decision 26, ADR-012 §2)', () => {
  const checkFor = (w: World, sealsARun = 7) =>
    createActivitySealCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      sealsARun,
      batch: 2,
    });
  const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');
  const held = () => capture.lines().some((line) => line.event === 'audit.integrity_hold_set');

  /** Three days sealed, the 17th to the 19th, two rows on the 18th: the world and their rows' IDs. */
  const sealed = async () => {
    const w = await world();
    await written(w, '2026-10-17T09:00:00.000Z');
    await written(w, '2026-10-18T09:00:00.000Z');
    await written(w, '2026-10-18T10:00:00.000Z');
    await sealFor(w).run();
    capture = new LogCapture();
    return w;
  };
  const admin = () => database.as('admin');

  it('finds every seal holding, a few a run, back to the oldest and from the newest again', async () => {
    const w = await sealed();
    const check = checkFor(w, 2);

    for (let run = 0; run < 4; run += 1) await check.run();

    expect(alarms()).toEqual([]);
    expect(held()).toBe(false);
  });

  it('holds the organisation for a row of a sealed day changed past the app', async () => {
    const w = await sealed();
    await admin().query(
      "update access.requests set status = 403 where org_id = $1 and recorded_at = '2026-10-18T09:00:00Z'",
      [w.org],
    );

    await checkFor(w).run();

    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', reason: 'holding', subjectType: 'access_log', objectId: w.org }),
    ]);
    expect(held()).toBe(true);
    expect(capture.lines().filter((line) => line.event === 'access_log_seal_check.broken')).toEqual([
      expect.objectContaining({ day: '2026-10-18', why: 'digest' }),
    ]);
  });

  it('holds it for a row deleted from a sealed day, and for one slipped into a sealed day', async () => {
    const deleted = await sealed();
    await admin().query("delete from access.requests where org_id = $1 and recorded_at = '2026-10-17T09:00:00Z'", [
      deleted.org,
    ]);
    await checkFor(deleted).run();
    expect(alarms()).toHaveLength(1);

    const slipped = await sealed();
    capture = new LogCapture();
    await written(slipped, '2026-10-19T08:00:00.000Z');
    await checkFor(slipped).run();
    expect(alarms()).toEqual([expect.objectContaining({ objectId: slipped.org })]);
  });

  it('finds a seal holding with its rows’ IP addresses and places blanked, as a lawful erasure may', async () => {
    const w = await sealed();
    await admin().query('update access.requests set ip = null, country = null, city = null where org_id = $1', [w.org]);

    await checkFor(w).run();

    expect(alarms()).toEqual([]);
  });

  it('holds it for a seal missing between two others', async () => {
    const w = await sealed();
    await admin().query("delete from audit.events where org_id = $1 and action = $2 and details like '%2026-10-18%'", [
      w.org,
      ACTIVITY_SEALED,
    ]);

    await checkFor(w).run();

    expect(capture.lines().filter((line) => line.event === 'access_log_seal_check.broken')).toEqual([
      expect.objectContaining({ day: '2026-10-17', why: 'gap' }),
    ]);
    expect(held()).toBe(true);
  });

  it('holds it for a seal rewritten past the app: its own seal can’t be believed', async () => {
    const w = await sealed();
    await admin().query(
      'update audit.events set details = replace(details, \'"requests":2\', \'"requests":1\') where org_id = $1 and action = $2',
      [w.org, ACTIVITY_SEALED],
    );

    await checkFor(w).run();

    expect(alarms()).toEqual([expect.objectContaining({ reason: 'log' })]);
    expect(held()).toBe(true);
  });

  it('logs an organisation it can’t check, going on, and a run whose list fails', async () => {
    const w = await sealed();
    const both = createActivitySealCheck({
      list: () => Promise.resolve(['not-an-organisation', w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });
    await both.run();
    expect(capture.lines().filter((line) => line.event === 'access_log_seal_check.failed')).toHaveLength(1);
    expect(alarms()).toEqual([]);

    const none = createActivitySealCheck({
      list: () => Promise.reject(new Error('the directory is down')),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });
    await none.run();
    expect(capture.lines().filter((line) => line.event === 'access_log_seal_check.run_failed')).toHaveLength(1);
  });

  it('checks nothing once stopped', async () => {
    const w = await sealed();
    await admin().query('update access.requests set status = 500 where org_id = $1', [w.org]);
    const stopping = new AbortController();
    stopping.abort();

    await checkFor(w).run(stopping.signal);

    expect(alarms()).toEqual([]);
  });
});
