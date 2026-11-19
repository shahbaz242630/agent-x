// S206 V6 (Threat-Model R-15): the security events' daily seals, recorded
// and checked, on the real migrated schema as the app role, the database's
// owner tampering as the admin role on the plain rows. The global table is
// one for the whole database, so each test has a database of its own.
//
// Normal writes seal clean, the global table's days on the platform chain and
// an organisation's on its own, each closed day holding rows once. The owner
// deleting or editing a sealed failed sign-in, or slipping a row into a day
// between two seals, raises the alarm at the next run; a row planted with no
// MAC (or edited) before its day is sealed raises it when the day is sealed,
// once; a seal past the retention is not checked. And a flood of writers
// from many addresses never queues: not behind another's open write, nor
// behind the seal's lock, which the seal itself does queue behind.
import { v7Floor } from '@agentx/core/modules/activity';
import {
  createSecurityEvents,
  recordMacBoundary,
  SECURITY_EVENTS_SEALED,
  type SecurityEvent,
} from '@agentx/core/modules/security-events';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
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
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { keys, mandateWorld, type MandateWorldTables, type World } from './mandate-world.helper.test.ts';
import { createSecuritySeal, SECURITY_SEAL_LOCK, type SecuritySealTables } from './security-seal.ts';

type Tables = MandateWorldTables & SecuritySealTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;
let capture: LogCapture;
let clock: FixedClock;

const ids = new SequentialIds(0x5e6_0000_0000);
const RETENTION = 30;

let made = 0;
/** A UUIDv7 of the instant `ms`, as a row written then has. */
const idAt = (ms: number) => {
  made += 1;
  return `${v7Floor(ms).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
};

/** IDs made at the clock's time, as the API's are made as it writes. */
const idsAt = (at: Clock): IdGenerator => ({ next: () => idAt(at.now().getTime()) });

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'security-seal' });

/** A failed sign-in counted in the minute before `at`. */
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
  return createSecurityEvents({ ids: idsAt(then), clock: then, keys, retentionDays: RETENTION }).record(app, events);
};

const sealer = (list = () => Promise.resolve(listed), done?: (orgId: string) => void) =>
  createSecuritySeal({
    list,
    ...(done === undefined ? {} : { done }),
    database: app,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
    retentionDays: RETENTION,
    batch: 2,
    pick: () => 1n,
  });
let listed: string[] = [];

/** The global table's seals, oldest first: each its day and count. */
const globalSeals = async () =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select('details')
      .where('action', '=', SECURITY_EVENTS_SEALED)
      .orderBy('seq')
      .execute()
  ).map((row) => {
    const { day, requests } = JSON.parse(row.details) as Record<string, unknown>;
    return [day, requests];
  });

/** The organisation's seals, oldest first: each its day and count. */
const orgSeals = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        .selectFrom('audit.events')
        .select('details')
        .where('action', '=', SECURITY_EVENTS_SEALED)
        .orderBy('seq')
        .execute()
    ).map((row) => {
      const { day, requests } = JSON.parse(row.details) as Record<string, unknown>;
      return [day, requests];
    }),
  );

const alarms = () =>
  capture
    .lines()
    .filter((line) => line.event === 'audit.integrity_failed' && line.check === 'security_event')
    .map(({ chain, reason, day, orgId, rowId }) => ({ chain, reason, day, orgId, rowId }));

const owner = () => database.as('admin');

/** The global rows of `day`, by ID, as the owner sees them. */
const rowsOf = async (day: string) =>
  owner().query<{ id: string }>('select id from security.events where id >= $1::uuid and id < $2::uuid order by id', [
    v7Floor(Date.parse(`${day}T00:00:00Z`)),
    v7Floor(Date.parse(`${day}T00:00:00Z`) + DAY_MS),
  ]);

/** A row the owner writes itself: no MAC, its ID made at `at`. */
const planted = async (at: string) => {
  const id = idAt(Date.parse(at));
  await owner().query(
    `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at)
     values ($1, 'sign_in_failed', 'state_mismatch', '198.51.100.9', null, $2, 1, $2)`,
    [id, new Date(at)],
  );
  return id;
};

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  capture = new LogCapture();
  clock = new FixedClock(new Date('2027-01-21T00:20:00.000Z'));
  listed = [];
});

afterEach(async () => {
  await app.destroy();
  await database.drop();
});

describe('the security events’ daily seals (S206 V6, R-15)', () => {
  it('seals each closed day holding rows once, the global table’s and an organisation’s, with no alarm', async () => {
    const w = await shared.world();
    listed = [w.org];
    await written('2027-01-17T09:00:00.000Z', [
      failed('2027-01-17T09:00:00.000Z'),
      failed('2027-01-17T09:00:00.000Z', { ip: '2001:DB8::7' }),
    ]);
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z', { ip: undefined })]);
    // Today's: not closed yet.
    await written('2027-01-21T00:10:00.000Z', [failed('2027-01-21T00:10:00.000Z')]);
    await written('2027-01-18T09:00:00.000Z', [
      failed('2027-01-18T09:00:00.000Z', {
        kind: 'rate_limited',
        reason: 'per_user',
        userId: w.admin.userId,
        orgId: w.org,
      }),
      failed('2027-01-18T09:00:00.000Z', { kind: 'rate_limited', reason: 'per_agent', agentId: w.agent, orgId: w.org }),
    ]);

    await sealer().run();
    await sealer().run();

    expect(await globalSeals()).toEqual([
      ['2027-01-17', 2],
      ['2027-01-19', 1],
    ]);
    expect(await orgSeals(w)).toEqual([['2027-01-18', 2]]);
    expect(alarms()).toEqual([]);

    // The next day, once past its grace: today's day sealed too, the checks still clean.
    clock.advanceBy(DAY_MS);
    await sealer().run();
    expect((await globalSeals()).map(([day]) => day)).toEqual(['2027-01-17', '2027-01-19', '2027-01-21']);
    expect(alarms()).toEqual([]);
  });

  it('the owner deleting a sealed failed sign-in: the alarm at the next run', async () => {
    await written('2027-01-19T09:00:00.000Z', [
      failed('2027-01-19T09:00:00.000Z'),
      failed('2027-01-19T09:00:00.000Z', { ip: '203.0.113.8' }),
    ]);
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    await sealer().run();
    const [first] = await rowsOf('2027-01-19');

    await owner().query('delete from security.events where id = $1', [first?.id]);
    await sealer().run();

    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'digest', day: '2027-01-19', orgId: undefined, rowId: undefined },
    ]);
  });

  it('the owner editing a sealed one (its count put back to one): the alarm at the next run', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z', { count: 40 })]);
    await sealer().run();

    await owner().query('update security.events set count = 1');
    await sealer().run();

    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'digest', day: '2027-01-20', orgId: undefined, rowId: undefined },
    ]);
  });

  it('the owner rewriting only a sealed row’s MAC: the alarm at the next run', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    await sealer().run();

    await owner().query("update security.events set mac = pg_catalog.decode(pg_catalog.repeat('ab', 32), 'hex')");
    await sealer().run();

    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'digest', day: '2027-01-20', orgId: undefined, rowId: undefined },
    ]);
  });

  it('a row planted with no MAC before its day is sealed: the alarm as the day is sealed, once', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    const id = await planted('2027-01-20T10:00:00.000Z');

    await sealer().run();
    await sealer().run();

    // Sealed as it stands, so the seal's own check holds and the alarm isn't raised again each run.
    expect(await globalSeals()).toEqual([['2027-01-20', 2]]);
    expect(alarms()).toEqual([{ chain: 'platform', reason: 'mac', day: '2027-01-20', orgId: undefined, rowId: id }]);
  });

  it('a row edited before its day is sealed fails its MAC as the day is sealed', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z', { count: 40 })]);
    const [row] = await rowsOf('2027-01-20');
    await owner().query('update security.events set count = 1');

    await sealer().run();

    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'mac', day: '2027-01-20', orgId: undefined, rowId: row?.id },
    ]);
  });

  it('a row slipped into a day between two seals, which no seal holds: the alarm', async () => {
    await written('2027-01-15T09:00:00.000Z', [failed('2027-01-15T09:00:00.000Z')]);
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await sealer().run();

    await planted('2027-01-17T09:00:00.000Z');
    await sealer().run();

    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'unsealed_day', day: '2027-01-16', orgId: undefined, rowId: undefined },
    ]);
  });

  /** A row the owner writes itself, its ID made at `idAt` but saying it was written at `writtenAt`. */
  const misdated = async (idTime: string, writtenAt: string) => {
    const id = idAt(Date.parse(idTime));
    await owner().query(
      `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at)
       values ($1, 'sign_in_failed', 'state_mismatch', null, null, $2, 1, $2)`,
      [id, new Date(writtenAt)],
    );
    return id;
  };

  it('a row whose ID is far from when it says it was written is left out of its day, alarmed once; sealing goes on', async () => {
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    const id = await misdated('2027-01-19T10:00:00.000Z', '2027-01-17T09:00:00.000Z');

    await sealer().run();
    await sealer().run();

    // Both days sealed, the 19th without the misdated row; its alarm raised as the 19th was sealed, not again.
    expect(await globalSeals()).toEqual([
      ['2027-01-19', 1],
      ['2027-01-20', 1],
    ]);
    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'misdated', day: '2027-01-19', orgId: undefined, rowId: id },
    ]);
  });

  it('a sealed row edited into a misdated one, to drop it from its day: the alarm at the next check', async () => {
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await sealer().run();

    await owner().query(
      "update security.events set created_at = created_at - interval '3 days', window_start = window_start - interval '3 days'",
    );
    await sealer().run();

    expect(alarms().map(({ reason }) => reason)).toEqual(['digest']);
  });

  it.each([
    ['made two months back', '2026-11-21T09:00:00.000Z'],
    ['made in 2100', '2100-01-01T00:00:00.000Z'],
  ])('a row the seal can never reach, its ID %s while it says it was written now: the alarm', async (_when, idTime) => {
    const id = await misdated(idTime, '2027-01-20T23:00:00.000Z');

    await sealer().run();

    expect(alarms()).toEqual([{ chain: 'platform', reason: 'out_of_range', day: null, orgId: undefined, rowId: id }]);
  });

  it('logs each day not yet sealed (its rows and last ID) and each day sealed, for the alert off the database', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z'), failed('2027-01-20T09:00:00.000Z')]);
    await written('2027-01-21T00:10:00.000Z', [failed('2027-01-21T00:10:00.000Z')]);
    clock = new FixedClock(new Date('2027-01-21T00:12:00.000Z'));
    await sealer().run();
    clock = new FixedClock(new Date('2027-01-21T00:20:00.000Z'));
    await sealer().run();

    const lines = capture
      .lines()
      .filter(({ event }) => event === 'security_seal.tally' || event === 'security_events.sealed')
      .map(({ event, day, rows, requests }) => [event, day, rows ?? requests]);
    expect(lines).toEqual([
      // The 20th still in its grace at 00:12: both days tallied, nothing sealed.
      ['security_seal.tally', '2027-01-20', 2],
      ['security_seal.tally', '2027-01-21', 1],
      ['security_events.sealed', '2027-01-20', 2],
      ['security_seal.tally', '2027-01-21', 1],
    ]);
  });

  it('an organisation with no rows and no seals is finished at once, nothing read of its chain', async () => {
    const w = await shared.world();
    const done: string[] = [];

    await sealer(
      () => Promise.resolve([w.org]),
      (orgId) => done.push(orgId),
    ).run();

    expect(done).toEqual([w.org]);
    expect(await orgSeals(w)).toEqual([]);
    expect(alarms()).toEqual([]);
  });

  it('a row with no MAC from before the boundary is believed; one after it is not; the first boundary stands', async () => {
    const first = await recordMacBoundary(app, {
      keys,
      ids,
      clock: new FixedClock(new Date('2027-01-19T12:00:00.000Z')),
    });
    const again = await recordMacBoundary(app, { keys, ids, clock });
    expect([first, again]).toEqual([Date.parse('2027-01-19T13:00:00.000Z'), Date.parse('2027-01-19T13:00:00.000Z')]);
    const before = await planted('2027-01-19T12:30:00.000Z');
    const after = await planted('2027-01-19T13:30:00.000Z');

    await sealer().run();

    expect(alarms()).toEqual([{ chain: 'platform', reason: 'mac', day: '2027-01-19', orgId: undefined, rowId: after }]);
    expect(before).not.toBe(after);
  });

  it('a seal of the global table rewritten on the platform chain: the alarm, and nothing sealed past it', async () => {
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await sealer().run();
    await owner().query(
      "update platform_controls.audit_events set details = replace(details, '2027-01-19', '2027-01-29') where action = $1",
      [SECURITY_EVENTS_SEALED],
    );
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);

    await sealer().run();

    expect(await globalSeals()).toEqual([['2027-01-29', 1]]);
    expect(alarms().map(({ reason }) => reason)).toEqual(['unsealed', 'unsealed']);
  });

  it("an organisation's sealed rows deleted by the owner: the alarm, naming it", async () => {
    const w = await shared.world();
    listed = [w.org];
    await written('2027-01-19T09:00:00.000Z', [
      failed('2027-01-19T09:00:00.000Z', {
        kind: 'rate_limited',
        reason: 'per_user',
        userId: w.admin.userId,
        orgId: w.org,
      }),
    ]);
    await sealer().run();

    await owner().query('delete from security.org_events where org_id = $1', [w.org]);
    await sealer().run();

    expect(alarms()).toEqual([
      { chain: 'organisation', reason: 'digest', day: '2027-01-19', orgId: w.org, rowId: undefined },
    ]);
  });

  it('checks no seal past the retention: rows swept from under it raise nothing', async () => {
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    await sealer().run();

    clock.advanceBy((RETENTION - 1) * DAY_MS);
    await createSecurityEvents({ ids, clock, keys, retentionDays: RETENTION }).sweep(app, 1);
    await sealer().run();

    expect(await rowsOf('2027-01-19')).toEqual([]);
    expect(alarms()).toEqual([]);
  });

  it('never throws: an organisation that fails is logged and the next sealed, a list that fails logged, a stopped run stops', async () => {
    const w = await shared.world();
    await written('2027-01-19T09:00:00.000Z', [
      failed('2027-01-19T09:00:00.000Z', {
        kind: 'rate_limited',
        reason: 'per_user',
        userId: w.admin.userId,
        orgId: w.org,
      }),
    ]);
    const stopped = new AbortController();
    stopped.abort();
    await sealer(() => Promise.resolve([w.org])).run(stopped.signal);
    expect(await orgSeals(w)).toEqual([]);

    const done: string[] = [];
    await sealer(
      () => Promise.resolve(['acme', w.org]),
      (orgId) => done.push(orgId),
    ).run();
    await sealer(() => Promise.reject(new Error('the list is down'))).run();

    expect(await orgSeals(w)).toEqual([['2027-01-19', 1]]);
    expect(done).toEqual([w.org]);
    expect(
      capture
        .lines()
        .filter(({ level }) => level === 'error')
        .map(({ event }) => event),
    ).toEqual(['security_event_seal.failed', 'security_event_seal.run_failed']);
  });

  it('a flood of writers from many addresses never queues: not behind an open write, nor the seal’s lock', async () => {
    const w = await shared.world();
    listed = [w.org];
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    // A write part way, the seal's lock held, as a seal part way through recording holds it.
    const { promise: held, resolve: heldNow } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = app.transaction().execute(async (tx) => {
      await holdTransactionLock(tx, SECURITY_SEAL_LOCK);
      await tx
        .insertInto('security.events')
        .values({
          id: idAt(clock.now().getTime()),
          kind: 'sign_in_failed',
          reason: 'state_mismatch',
          ip: '203.0.113.7',
          user_id: null,
          window_start: new Date(clock.now().getTime() - 60_000),
          count: 1,
          created_at: clock.now(),
          mac: null,
          mac_key_version: null,
        })
        .execute();
      heldNow(undefined);
      await gate;
    });
    await held;
    try {
      const now = clock.now().toISOString();
      // Many addresses, the held row's own among them, and an organisation's: none waits on another.
      await within(
        20_000,
        Promise.all([
          ...Array.from({ length: 20 }, (_, n) => written(now, [failed(now, { ip: `203.0.113.${String(n)}` })])),
          written(now, [
            failed(now, { kind: 'rate_limited', reason: 'per_user', userId: w.admin.userId, orgId: w.org }),
          ]),
        ]),
        'the writers',
      );
      // The seal does take the lock: it queues behind it (the control that a queue would show).
      const sealing = sealer().run();
      await waitUntilQueued(owner(), 1);
      open(undefined);
      await holder;
      await sealing;
    } finally {
      open(undefined);
      await holder;
    }
    expect(await globalSeals()).toEqual([['2027-01-20', 1]]);
  });
});
