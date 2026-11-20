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
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import {
  createSecurityEvents,
  orgSecurityEventsPage,
  ROW_MACS_FROM,
  SEALING_STARTED,
  sealLegacyRows,
  SECURITY_EVENTS_SEALED,
  securityDigestOfDay,
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

import { createLegacySealJob } from './legacy-seal-job.ts';
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
  // The owner's own first step: 0105's rule that every row written carries a MAC dropped, to plant rows without one.
  await owner().query(`
    alter table security.events drop constraint event_mac_required;
    alter table security.org_events drop constraint org_event_mac_required`);
});

afterEach(async () => {
  await app.destroy();
  await database.drop();
});

describe('SEC-DB-18 the security events’ daily seals (S206 V6, R-15)', () => {
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

    const [row] = await rowsOf('2027-01-20');
    await owner().query('update security.events set count = 1');
    await sealer().run();

    // Its MAC no longer holds, and its day's digest has moved.
    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'mac', day: '2027-01-20', orgId: undefined, rowId: row?.id },
      { chain: 'platform', reason: 'digest', day: '2027-01-20', orgId: undefined, rowId: undefined },
    ]);
  });

  it('the owner rewriting only a sealed row’s MAC: the alarm at the next run', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    await sealer().run();

    await owner().query("update security.events set mac = pg_catalog.decode(pg_catalog.repeat('ab', 32), 'hex')");
    await sealer().run();

    expect(alarms().map(({ reason }) => reason)).toEqual(['mac', 'digest']);
  });

  /** Each alarm for `id` on the 20th, as one run after another raises it. */
  const onThe20th = (reason: string, id: string | undefined, runs: number) =>
    Array.from({ length: runs }, () => ({ chain: 'platform', reason, day: '2027-01-20', orgId: undefined, rowId: id }));

  it('a row planted with no MAC before its day is sealed: the alarm as the day is sealed, and at each check', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    const id = await planted('2027-01-20T10:00:00.000Z');

    await sealer().run();
    await sealer().run();

    // Sealed as it stands, so later days go on being sealed; the row is met again at each run's check.
    expect(await globalSeals()).toEqual([['2027-01-20', 2]]);
    expect(alarms()).toEqual(onThe20th('mac', id, 3));
  });

  it('a row edited before its day is sealed fails its MAC as the day is sealed', async () => {
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z', { count: 40 })]);
    const [row] = await rowsOf('2027-01-20');
    await owner().query('update security.events set count = 1');

    await sealer().run();

    expect(alarms()).toEqual(onThe20th('mac', row?.id, 2));
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

  it('a row whose ID is far from when it says it was written is left out of its day, alarmed; sealing goes on', async () => {
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await written('2027-01-20T09:00:00.000Z', [failed('2027-01-20T09:00:00.000Z')]);
    const id = await misdated('2027-01-19T10:00:00.000Z', '2027-01-17T09:00:00.000Z');

    await sealer().run();
    await sealer().run();

    // Both days sealed, the 19th without the misdated row; its alarm raised as the 19th was sealed and at each check.
    expect(await globalSeals()).toEqual([
      ['2027-01-19', 1],
      ['2027-01-20', 1],
    ]);
    expect(alarms()).toEqual(
      Array.from({ length: 3 }, () => ({
        chain: 'platform',
        reason: 'misdated',
        day: '2027-01-19',
        orgId: undefined,
        rowId: id,
      })),
    );
  });

  it('a sealed row edited into a misdated one, to drop it from its day: the alarm at the next check', async () => {
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await sealer().run();

    await owner().query(
      "update security.events set created_at = created_at - interval '3 days', window_start = window_start - interval '3 days'",
    );
    await sealer().run();

    expect(alarms().map(({ reason }) => reason)).toEqual(['misdated', 'digest']);
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

  it('a misdated row planted into a day sealed already: the alarm at the check, though the digest still holds', async () => {
    await written('2027-01-19T09:00:00.000Z', [failed('2027-01-19T09:00:00.000Z')]);
    await sealer().run();
    expect(alarms()).toEqual([]);

    const id = await misdated('2027-01-19T10:00:00.000Z', '2027-01-16T09:00:00.000Z');
    await sealer().run();

    expect(alarms()).toEqual([
      { chain: 'platform', reason: 'misdated', day: '2027-01-19', orgId: undefined, rowId: id },
    ]);
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

// The staging start of 20 Nov 2026: the day seal ran before the pass giving
// the rows from before 0105 their MACs (legacy-seal.ts), sealing their days
// as they stood, a 'mac' alarm raised for each; once the pass gave the MACs,
// every such seal failed its digest at each check. Nothing was tampered with.
// Each order is forced here, step by step.
describe('the day seal and the pass giving the rows from before 0105 their MACs, in either order (S206 V6)', () => {
  /** Before the pass's cutoff, as staging was: its scope from 28 days back (the retention less two), 2026-10-23T08:00. */
  const NOW = '2026-11-20T08:00:00.000Z';

  /** A row as the release before 0105 wrote it: no MAC, marked `before_macs`, its ID made at `at`; an organisation's if named. */
  const fromBefore = async (at: string, orgId?: string) => {
    const id = idAt(Date.parse(at));
    await (orgId === undefined
      ? owner().query(
          `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, before_macs)
           values ($1, 'sign_in_failed', 'state_mismatch', '203.0.113.7', null, $2, 1, $2, true)`,
          [id, new Date(at)],
        )
      : owner().query(
          `insert into security.org_events (org_id, id, kind, reason, ip, user_id, agent_id, window_start, count,
             created_at, before_macs)
           values ($1, $2, 'rate_limited', 'per_user', null, null, null, $3, 1, $3, true)`,
          [orgId, id, new Date(at)],
        ));
    return id;
  };

  /** The platform chain's head, as the anchor check would have anchored it. */
  const headNow = async () => {
    const [head] = await owner().query<{ seq: string; hash: Buffer; mac_key_version: number }>(
      'select seq, hash, mac_key_version from platform_controls.audit_head',
    );
    return head === undefined
      ? undefined
      : { seq: BigInt(head.seq), hash: head.hash, macKeyVersion: head.mac_key_version };
  };

  /** The pass, as the jobs' copy runs it, the chain held to its head. */
  const legacyPass = () =>
    sealLegacyRows(app, {
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      orgs: () => Promise.resolve(listed),
      retentionDays: RETENTION,
      anchor: headNow,
      anchorNow: () => Promise.resolve(),
    });

  /** An event of the API's on the platform chain, as a start records it: a chain under way, for its head to be anchored. */
  const platformStarted = () =>
    app.transaction().execute((tx) =>
      createPlatformChain({ keys, ids }).record(tx, {
        actor: { type: 'system', id: 'api' },
        action: 'platform.started',
        details: {},
      }),
    );

  /** A seal whose check reads every seal of each log, not a few from a point at random. */
  const checkingAll = () =>
    createSecuritySeal({
      list: () => Promise.resolve(listed),
      database: app,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      retentionDays: RETENTION,
      batch: 2,
      pick: (below) => below + 1n,
    });

  /** The global day as digested now. */
  const digestNow = (day: string) =>
    securityDigestOfDay((work) => app.transaction().execute(work), keys, 'global', day, {
      batch: 2,
      legacy: { excusedBefore: null },
    });

  /** A global seal recorded as the first release recorded it: form 1, with the digest given. */
  const formOneSeal = async (day: string, digest: string) => {
    const { requests, idFrom, idTo } = await digestNow(day);
    await app.transaction().execute((tx) =>
      createPlatformChain({ keys, ids }).record(tx, {
        actor: { type: 'system', id: 'api' },
        action: SECURITY_EVENTS_SEALED,
        details: { day, requests, digest, idFrom, idTo, form: 1 },
      }),
    );
  };

  const forms = async () =>
    (
      await app
        .selectFrom('platform_controls.audit_events')
        .select('details')
        .where('action', '=', SECURITY_EVENTS_SEALED)
        .orderBy('seq')
        .execute()
    ).map((row) => (JSON.parse(row.details) as Record<string, unknown>).form);

  const withoutMac = async () =>
    (await owner().query<{ id: string }>('select id from security.events where mac is null order by id')).map(
      ({ id }) => id,
    );

  /** Each alarm once, however many times a check met it. */
  const alarmsOnce = (): unknown[] =>
    [...new Set(alarms().map((alarm) => JSON.stringify(alarm)))].map((line): unknown => JSON.parse(line));

  beforeEach(() => {
    clock = new FixedClock(new Date(NOW));
  });

  it('the day seal first: days sealed with no alarm; the pass after; every seal still holds, nothing alarmed', async () => {
    const w = await shared.world();
    listed = [w.org];
    // Before the pass's scope, on the first day still checked: left to the sweep, never given a MAC.
    const leftToSweep = await fromBefore('2026-10-23T03:00:00.000Z');
    await fromBefore('2026-11-18T09:00:00.000Z');
    await fromBefore('2026-11-18T10:00:00.000Z');
    await fromBefore('2026-11-19T09:00:00.000Z');
    await fromBefore('2026-11-18T09:00:00.000Z', w.org);

    await checkingAll().run();
    expect(await globalSeals()).toEqual([
      ['2026-10-23', 1],
      ['2026-11-18', 2],
      ['2026-11-19', 1],
    ]);
    expect(await orgSeals(w)).toEqual([['2026-11-18', 1]]);
    expect(alarms()).toEqual([]);

    expect(await legacyPass()).toBe('sealed');
    expect(await withoutMac()).toEqual([leftToSweep]);

    clock.advanceBy(30 * 60_000);
    await checkingAll().run();
    expect(alarms()).toEqual([]);
    expect(await forms()).toEqual([2, 2, 2]);
  });

  it('staging’s own: form 1 seals made before the pass hold after it, though their old reading no longer would', async () => {
    await fromBefore('2026-11-18T09:00:00.000Z');
    await fromBefore('2026-11-18T10:00:00.000Z');
    await fromBefore('2026-11-19T09:00:00.000Z');
    // Each day sealed as the first release sealed it: every row's MAC as it stood, none yet.
    const sealedAs = (await digestNow('2026-11-18')).formOne;
    await formOneSeal('2026-11-18', sealedAs);
    await formOneSeal('2026-11-19', (await digestNow('2026-11-19')).formOne);

    expect(await legacyPass()).toBe('sealed');
    // What staging's check read: the rows' new MACs in each line, so the seal no longer held ('digest').
    expect((await digestNow('2026-11-18')).formOne).not.toBe(sealedAs);

    await checkingAll().run();
    expect(alarms()).toEqual([]);
    expect(await globalSeals()).toEqual([
      ['2026-11-18', 2],
      ['2026-11-19', 1],
    ]);
  });

  it('a form 1 seal made after the pass, the MACs in its lines, holds too; one matching neither reading is the alarm', async () => {
    await fromBefore('2026-11-18T09:00:00.000Z');
    await fromBefore('2026-11-19T09:00:00.000Z');
    await platformStarted();
    expect(await legacyPass()).toBe('sealed');
    await formOneSeal('2026-11-18', 'f'.repeat(64));
    await formOneSeal('2026-11-19', (await digestNow('2026-11-19')).formOne);

    await checkingAll().run();
    expect(alarmsOnce()).toEqual([{ chain: 'platform', reason: 'digest', day: '2026-11-18' }]);
  });

  it('once the pass has ended, a MAC nulled by the owner is the alarm, and a day of such rows is sealed, never waited on', async () => {
    const row = await fromBefore('2026-11-18T09:00:00.000Z');
    await checkingAll().run();
    expect(await legacyPass()).toBe('sealed');

    await owner().query('update security.events set mac = null, mac_key_version = null where id = $1', [row]);
    // A new day of rows planted so: the owner's try at holding the seal up.
    const planted = await fromBefore('2026-11-20T09:00:00.000Z');
    clock.advanceBy(DAY_MS);
    await checkingAll().run();

    expect(alarmsOnce()).toEqual([
      { chain: 'platform', reason: 'mac', day: '2026-11-20', rowId: planted },
      { chain: 'platform', reason: 'mac', day: '2026-11-18', rowId: row },
    ]);
    expect((await globalSeals()).map(([day]) => day)).toEqual(['2026-11-18', '2026-11-20']);
  });

  it('a record of the pass edited by the owner: the alarm, and no row excused, the one left to the sweep alarmed too', async () => {
    const leftToSweep = await fromBefore('2026-10-23T03:00:00.000Z');
    await fromBefore('2026-11-18T09:00:00.000Z');
    await checkingAll().run();
    expect(await legacyPass()).toBe('sealed');

    await owner().query(`update platform_controls.audit_events set details = '{}' where action = $1`, [
      SEALING_STARTED,
    ]);
    await checkingAll().run();

    expect(alarmsOnce()).toEqual([
      { chain: 'platform', reason: 'unsealed', day: null },
      { chain: 'platform', reason: 'mac', day: '2026-10-23', rowId: leftToSweep },
    ]);
  });

  it('before the pass has ended, only a marked row with no MAC is excused: one unmarked with none, or a marked one whose MAC fails, is the alarm', async () => {
    await fromBefore('2026-11-18T08:00:00.000Z');
    const unmarked = await planted('2026-11-18T09:00:00.000Z');
    const edited = idAt(Date.parse('2026-11-19T09:00:00.000Z'));
    await owner().query(
      `insert into security.events (id, kind, reason, ip, user_id, window_start, count, created_at, before_macs, mac,
         mac_key_version)
       values ($1, 'sign_in_failed', 'state_mismatch', null, null, $2, 1, $2, true, $3, 1)`,
      [edited, new Date('2026-11-19T09:00:00.000Z'), Buffer.alloc(32, 9)],
    );
    await checkingAll().run();

    expect(alarmsOnce()).toEqual([
      { chain: 'platform', reason: 'mac', day: '2026-11-18', rowId: unmarked },
      { chain: 'platform', reason: 'mac', day: '2026-11-19', rowId: edited },
    ]);
  });

  it('the pass held up by the owner taking its lock: a row he marks and strips after the pass began is still the alarm, the old ones excused', async () => {
    await fromBefore('2026-11-18T09:00:00.000Z');
    // A pass begun at NOW and stopped part way, as a stop leaves it.
    await app.transaction().execute((tx) =>
      createPlatformChain({ keys, ids }).record(tx, {
        actor: { type: 'system', id: 'api' },
        action: SEALING_STARTED,
        details: { since: '2026-10-23T08:00:00.000Z', until: NOW, days: '{}' },
      }),
    );
    await written('2026-11-20T09:00:00.000Z', [failed('2026-11-20T09:00:00.000Z')]);
    const [genuine] = await rowsOf('2026-11-20');
    // A session of the owner's own holds the sealer's lock, so every pass after is 'busy'.
    const holder = await database.connect('admin');
    await holder.query(
      "select pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended('security-events-legacy-sealer', 0))",
    );
    try {
      expect(await legacyPass()).toBe('busy');
      await owner().query(
        'update security.events set before_macs = true, mac = null, mac_key_version = null, count = 99 where id = $1',
        [genuine?.id],
      );
      clock.advanceBy(DAY_MS);
      await checkingAll().run();
      expect(await legacyPass()).toBe('busy');
    } finally {
      await holder.end();
    }

    expect(alarmsOnce()).toEqual([{ chain: 'platform', reason: 'mac', day: '2026-11-20', rowId: genuine?.id }]);
    expect((await globalSeals()).map(([day]) => day)).toEqual(['2026-11-18', '2026-11-20']);
  });

  it('the owner taking the pass’s lock before it ever ran: a row he strips after the first start is the alarm, and once he lets go the pass never gives it a MAC', async () => {
    const old = await fromBefore('2026-11-18T09:00:00.000Z');
    // The first start on this release, as boot records it: its time.
    await app.transaction().execute((tx) =>
      createPlatformChain({ keys, ids }).record(tx, {
        actor: { type: 'system', id: 'api' },
        action: 'platform.started',
        details: { release: 'r', [ROW_MACS_FROM]: NOW },
      }),
    );
    const holder = await database.connect('admin');
    await holder.query(
      "select pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended('security-events-legacy-sealer', 0))",
    );
    let genuine: string | undefined;
    try {
      expect(await legacyPass()).toBe('busy');
      await written('2026-11-20T09:00:00.000Z', [failed('2026-11-20T09:00:00.000Z')]);
      genuine = (await rowsOf('2026-11-20'))[0]?.id;
      await owner().query(
        'update security.events set before_macs = true, mac = null, mac_key_version = null, count = 99 where id = $1',
        [genuine],
      );
      clock.advanceBy(DAY_MS);
      await checkingAll().run();
    } finally {
      await holder.end();
    }
    expect(alarmsOnce()).toEqual([{ chain: 'platform', reason: 'mac', day: '2026-11-20', rowId: genuine }]);

    expect(await legacyPass()).toBe('sealed');
    expect(await withoutMac()).toEqual([genuine]);
    expect((await withoutMac()).includes(old)).toBe(false);
  });

  it('the admins’ page once the pass has ended: a row it left to the sweep left off quietly, an organisation’s MAC nulled by the owner the alarm', async () => {
    const w = await shared.world();
    listed = [w.org];
    await fromBefore('2026-10-23T03:00:00.000Z', w.org);
    const stripped = await fromBefore('2026-11-18T09:00:00.000Z', w.org);
    await checkingAll().run();
    await platformStarted();
    expect(await legacyPass()).toBe('sealed');
    await owner().query('update security.org_events set mac = null, mac_key_version = null where id = $1', [stripped]);

    const page = await withTenant(app, w.org, (tx) =>
      orgSecurityEventsPage(
        tx,
        w.org,
        { from: new Date('2026-10-01T00:00:00.000Z'), to: new Date('2026-12-01T00:00:00.000Z'), limit: 10 },
        { keys, logger: testLogger(capture), clock },
      ),
    );

    expect(page.rows).toEqual([]);
    expect(alarmsOnce()).toEqual([{ chain: 'organisation', reason: 'mac', day: null, orgId: w.org, rowId: stripped }]);
  });

  it('past the pass’s cutoff with no end recorded, a row with no MAC is the alarm as its day is sealed, and at its check', async () => {
    clock = new FixedClock(new Date('2026-12-08T08:00:00.000Z'));
    const row = await fromBefore('2026-12-05T09:00:00.000Z');
    await sealer().run();

    const alarm = { chain: 'platform', reason: 'mac', day: '2026-12-05', orgId: undefined, rowId: row };
    expect(alarms()).toEqual([alarm, alarm]);
    expect(await globalSeals()).toEqual([['2026-12-05', 1]]);
  });

  it('with no anchor store (a machine of our own) the pass never runs, and a new database’s days still seal clean', async () => {
    await written('2026-11-18T09:00:00.000Z', [failed('2026-11-18T09:00:00.000Z')]);
    await createLegacySealJob({
      database: app,
      anchors: undefined,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      retentionDays: RETENTION,
    }).run();

    await checkingAll().run();
    expect(capture.lines().find((line) => line.event === 'security.legacy_seal_done')?.outcome).toBe('no_anchor_store');
    expect(await globalSeals()).toEqual([['2026-11-18', 1]]);
    expect(alarms()).toEqual([]);
  });
});
