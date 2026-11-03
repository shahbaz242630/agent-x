// The jobs following their marks (4D2e D7), on the real tables as the app role: the
// hand-off, its sweep and the payment checks visit only the organisations marked,
// and settle each after a run, holding a mark row only for one statement and its
// commit. Every race is forced with a held transaction, never left to chance. The
// marks themselves and the hourly look are org-work.db.test.ts's.
import { markOrgWork } from '@agentx/core/modules/directory';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import type { FakeRail } from '@agentx/core/modules/providers';
import { createDatabase, type Database, noStatementTimes, timingStatements } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it, onTestFinished } from 'vitest';

import { createHandoff, handOffDue, handoffDatabaseGate, handOffSweepDue, HEARTBEAT_STALE_MS } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, type World } from './mandate-world.helper.test.ts';
import { createOrgWorkRediscovery, markedOrganisations, withOrgWork } from './org-work.ts';
import { createPaymentChecks, paymentCheckDue } from './payment-checks.ts';
import { createRailHealth } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xd7a0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xd7b0_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'org_work_switch',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, statusOf } = shared;
const { ready } = handoffWorld({ app: () => app, clock: () => clock, ids, registry: () => registry, shared });

const admin = () => database.as('admin');
const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const WEEK_MS = 7 * 24 * 3_600_000;

async function marksOf(w: World): Promise<Record<string, { due_at: Date; marks: string }>> {
  const rows = await admin().query<{ job: string; due_at: Date; marks: string }>(
    'select job, due_at, marks from directory.org_work where org_id = $1',
    [w.org],
  );
  return Object.fromEntries(rows.map(({ job, ...rest }) => [job, rest]));
}

/** The server's time now: the marks' times are its clock's. */
const serverNow = async () =>
  (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0]?.now.getTime() ?? 0;

const pauseMoved = (paused: boolean) =>
  app
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused, reason: 'TEST-D7', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );

const marked = (job: 'hand_off' | 'hand_off_sweep', most?: number) =>
  markedOrganisations({
    job,
    nextDue: job === 'hand_off' ? handOffDue : handOffSweepDue,
    database: app,
    logger: testLogger(capture),
    ...(most === undefined ? {} : { most }),
  });

/** The hand-off as job-list.ts makes it: its organisations from the marks, settled after each run. */
function switchedHandoff(
  w: World,
  { rail = w.rail, db = app }: { rail?: FakeRail; db?: Database<HandoffWorldTables> } = {},
) {
  const handOffs = marked('hand_off');
  const sweeps = marked('hand_off_sweep');
  const job = withOrgWork(
    [handOffs, sweeps],
    createHandoff({
      list: handOffs.list,
      sweepList: sweeps.list,
      database: db,
      outbox: createOutbox({ ids, clock }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
    }),
  );
  return { job, handOffs, sweeps };
}

/** The payment checks as job-list.ts makes them. */
function switchedChecks(w: World, rail: FakeRail = w.rail) {
  const base = { job: 'payment_check', nextDue: paymentCheckDue, database: app, logger: testLogger(capture) } as const;
  const checks = markedOrganisations(base);
  const watches = markedOrganisations({ ...base, due: 'any' });
  const job = withOrgWork(
    [checks, watches],
    createPaymentChecks({
      list: checks.list,
      watchList: watches.list,
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
    }),
  );
  return { job, checks, watches };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  // Born paused (ADR-014 §4): resumed for these tests, as the operator would.
  await pauseMoved(false);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  const logger = testLogger(capture);
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  // The marks are read across organisations: each test starts with none, so it sees its own alone.
  await admin().query('delete from directory.org_work');
});

describe('the hand-off follows its marks', () => {
  it('visits only an organisation marked: one whose mark was lost waits for the hourly look', async () => {
    const one = await ready();
    const first = await ask(one.acting, one.w, { amount: ALLOWED() });
    const two = await ready();
    const second = await ask(two.acting, two.w, { amount: ALLOWED() });
    await admin().query('delete from directory.org_work where org_id = $1', [two.w.org]);
    const { job } = switchedHandoff(one.w);

    await job.run();
    expect(await statusOf(one.w, first.id)).toBe('HANDED_OFF');
    expect(await statusOf(two.w, second.id)).toBe('APPROVED');

    await createOrgWorkRediscovery({
      list: () => Promise.resolve([two.w.org]),
      database: app,
      logger: testLogger(capture),
    }).run();
    await job.run();
    expect(await statusOf(two.w, second.id)).toBe('HANDED_OFF');
  });

  it("settles each after a run: Tx A's own mark stands one visit more, then the mark with nothing left goes", async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    const listed = (await marksOf(w)).hand_off?.marks;
    const { job } = switchedHandoff(w);

    await job.run();
    // Tx A marks it as it makes the request ready, after the run listed it: that mark stands, so it is visited again.
    const after = await marksOf(w);
    expect(BigInt(after.hand_off?.marks ?? '0')).toBeGreaterThan(BigInt(listed ?? '0'));
    await job.run();
    const settled = await marksOf(w);
    expect(Object.keys(settled).toSorted()).toEqual(['hand_off_sweep', 'payment_check']);
  });

  it('a request still waiting keeps its mark, due now, behind those due longer', async () => {
    const { w, acting } = await ready();
    // Waiting for its supplier's payee, a reason the run knows: it stays APPROVED.
    const waiting = await ask(acting, w, { amount: ALLOWED(), supplierId: w.suppliers[1] ?? '' });
    const before = (await marksOf(w)).hand_off;
    const started = await serverNow();

    await switchedHandoff(w).job.run();

    expect(await statusOf(w, waiting.id)).toBe('APPROVED');
    const after = (await marksOf(w)).hand_off;
    expect(after?.marks).toBe(before?.marks);
    expect(after?.due_at.getTime()).toBeGreaterThanOrEqual(started);
    expect(after?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
  });

  it('takes at most as many as it may, due longest first', async () => {
    const one = await ready();
    await ask(one.acting, one.w, { amount: ALLOWED(), supplierId: one.w.suppliers[1] ?? '' });
    const two = await ready();
    await ask(two.acting, two.w, { amount: ALLOWED(), supplierId: two.w.suppliers[1] ?? '' });
    const handOffs = marked('hand_off', 1);
    expect(await handOffs.list()).toEqual([one.w.org]);
    await handOffs.settle();
    // Settled due now, it goes behind the one due since before.
    expect(await handOffs.list()).toEqual([two.w.org]);
  });

  it('a run stopped settles nothing: its marks are read again, as they stood', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(), supplierId: w.suppliers[1] ?? '' });
    const before = await marksOf(w);
    const { job } = switchedHandoff(w);
    const stop = new AbortController();
    stop.abort();

    await job.run(stop.signal);

    expect(await marksOf(w)).toEqual(before);
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    await job.run();
    expect((await marksOf(w)).hand_off?.due_at.getTime()).toBeGreaterThan(before.hand_off?.due_at.getTime() ?? 0);
  });

  it('held by the pause, reads no marks and settles none', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const before = await marksOf(w);
    const handOffs = marked('hand_off');
    let read = 0;
    const job = withOrgWork(
      [handOffs],
      createHandoff({
        list: () => {
          read += 1;
          return handOffs.list();
        },
        sweepList: () => Promise.resolve([]),
        database: app,
        outbox: createOutbox({ ids, clock }),
        rail: w.rail,
        keys,
        ids,
        clock,
        logger: testLogger(capture),
        health: createRailHealth({ clock, logger: testLogger(capture) }),
        databaseGate: handoffDatabaseGate(6),
      }),
    );
    await pauseMoved(true);
    try {
      await job.run();
    } finally {
      await pauseMoved(false);
    }
    expect(read).toBe(0);
    expect(await marksOf(w)).toEqual(before);
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    // Held on a pause read whole, the run is alive: it beats.
    expect(job.beating()).toBe(true);
  });

  it("a pause it can't read beats nothing, unless it sweeps: one failing every time reads as stopped", async () => {
    const { w } = await ready();
    let unreadable = false;
    const failing = new Proxy(app, {
      get(target, name, receiver) {
        if (name === 'transaction' && unreadable) {
          unreadable = false;
          return () => {
            throw new Error('the pause is unreadable');
          };
        }
        const value: unknown = Reflect.get(target, name, receiver);
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    const { job } = switchedHandoff(w, { db: failing });
    await job.run();
    // Within the sweep's minute: the next run doesn't sweep, so it reads nothing.
    clock.advanceBy(30_000);
    unreadable = true;
    await job.run();
    expect(lines('handoff.pause_unread')).toHaveLength(1);
    clock.advanceBy(HEARTBEAT_STALE_MS - 29_000);
    expect(job.beating()).toBe(false);
  });

  it("a sweep list it can't read is said, and the sweep waits for the next run", async () => {
    const { w } = await ready();
    let swept = 0;
    const job = createHandoff({
      list: () => Promise.resolve([w.org]),
      sweepList: () => {
        swept += 1;
        return swept === 1 ? Promise.reject(new Error('no marks')) : Promise.resolve([w.org]);
      },
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: w.rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
    });
    await job.run();
    expect(lines('handoff.run_failed')).toHaveLength(1);
    // Not swept, so the next run sweeps, though within the minute.
    await job.run();
    expect(swept).toBe(2);
  });
});

describe('a mark row held only for a moment, and never lost', () => {
  it("an agent's decision during a visit commits at once: the job holds no mark while it works", async () => {
    const { w, acting } = await ready();
    // Small enough that both are approved within the mandate's limits.
    const first = await ask(acting, w, { amount: SMALL() });
    let during: Awaited<ReturnType<typeof ask>> | undefined;
    const rail: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        // A decision carries a 5 s lock_timeout: had the job held the hand-off's mark, its commit would fail.
        during ??= await ask(acting, w, { amount: SMALL(5n) });
        return w.rail.submitApprovedIntent(intent);
      },
    };
    const { job } = switchedHandoff(w, { rail });

    await job.run();
    expect(await statusOf(w, first.id)).toBe('HANDED_OFF');
    expect(during?.status).toBe('APPROVED');
    // Its mark stands, whichever run takes it.
    await job.run();
    expect(await statusOf(w, during?.id ?? '')).toBe('HANDED_OFF');
  });

  it('the settle reads what is due holding nothing: a mark made meanwhile is made at once, and stands', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    const handOffs = marked('hand_off');
    expect(await handOffs.list()).toEqual([w.org]);
    // The requests held, so the settle's read of what is due waits.
    const holder = await database.connect('owner');
    await holder.query('begin');
    await holder.query('lock table spend_requests.requests in access exclusive mode');
    const settling = handOffs.settle();
    let held = true;
    onTestFinished(async () => {
      if (held) await holder.query('commit');
      await settling;
      await holder.end();
    });
    await waitUntilQueued(admin(), 1);
    const listed = (await marksOf(w)).hand_off?.marks ?? '0';
    // The same row a commit's trigger takes, taken while the settle waits: had the settle held it, this would wait too.
    await markOrgWork(app, w.org, 'hand_off', clock.now());
    const made = (await marksOf(w)).hand_off;
    expect(BigInt(made?.marks ?? '0')).toBe(BigInt(listed) + 1n);
    held = false;
    await holder.query('commit');
    await settling;
    expect((await marksOf(w)).hand_off).toEqual(made);
  });

  it('a settle behind a commit marking the row waits for it, then leaves the mark that commit made', async () => {
    const { w } = await ready();
    // A mark with nothing due: settled alone, it would go.
    await markOrgWork(app, w.org, 'hand_off', clock.now());
    const handOffs = marked('hand_off');
    expect(await handOffs.list()).toEqual([w.org]);
    // A committing writer's position: it has moved marks and not ended.
    const writer = await database.connect('admin');
    try {
      await writer.query('begin');
      await writer.query(`update directory.org_work set marks = marks + 1 where org_id = $1 and job = 'hand_off'`, [
        w.org,
      ]);
      const settling = handOffs.settle();
      await waitUntilQueued(admin(), 1);
      await writer.query('commit');
      await settling;
    } finally {
      await writer.end();
    }
    expect(Object.keys(await marksOf(w))).toEqual(['hand_off']);
    // Settled again with that mark read, it goes.
    await handOffs.list();
    await handOffs.settle();
    expect(await marksOf(w)).toEqual({});
  });

  it('listed twice before settling, the first read is the one compared: a mark between them stands', async () => {
    const { w } = await ready();
    await markOrgWork(app, w.org, 'hand_off', clock.now());
    const handOffs = marked('hand_off');
    await handOffs.list();
    await markOrgWork(app, w.org, 'hand_off', clock.now());
    const made = (await marksOf(w)).hand_off;
    expect(await handOffs.list()).toEqual([w.org]);
    await handOffs.settle();
    expect((await marksOf(w)).hand_off).toEqual(made);
  });

  it('a settle that fails is said, and leaves the mark for another visit', async () => {
    const { w } = await ready();
    await markOrgWork(app, w.org, 'hand_off', clock.now());
    const before = await marksOf(w);
    const failing = markedOrganisations({
      job: 'hand_off',
      nextDue: () => ({ execute: () => Promise.reject(new Error('no read')) }),
      database: app,
      logger: testLogger(capture),
    });
    await failing.list();
    await failing.settle();
    expect(lines('org_work.settle_failed')).toEqual([expect.objectContaining({ orgId: w.org, job: 'hand_off' })]);
    expect(await marksOf(w)).toEqual(before);
  });

  it('a settle takes one transaction an organisation, on four trips, the row its last statement', async () => {
    const { w } = await ready();
    await markOrgWork(app, w.org, 'hand_off', clock.now());
    const handOffs = marked('hand_off');
    await handOffs.list();
    const times = noStatementTimes();
    await timingStatements(times, () => handOffs.settle());
    // Its start with the organisation set, the read of what is due, the row, the commit.
    expect(times.trips).toBe(4);
    expect(await marksOf(w)).toEqual({});
  });
});

describe('the payment checks follow theirs', () => {
  it('a payment under way keeps its mark due; settled, it is watched a week, by the laps alone', async () => {
    const { w, acting } = await ready();
    // `.01`: the fake declines it with its proof, so the hand-off's Tx B settles it FAILED.
    await ask(acting, w, { amount: ALLOWED(1n) });
    await switchedHandoff(w).job.run();
    // The fils choose it stays under way.
    const other = await ready();
    await ask(other.acting, other.w, { amount: SMALL() });
    await switchedHandoff(other.w).job.run();
    const looked: string[] = [];
    const rail: FakeRail = {
      ...w.rail,
      getExecution: (ref) => {
        looked.push(ref.organizationId);
        return w.rail.getExecution(ref);
      },
    };
    const { job, checks, watches } = switchedChecks(w, rail);

    const started = await serverNow();
    // The first run after a start begins the laps: the watch's takes the paid and failed ones too.
    await job.run();
    expect(looked).toContain(w.org);

    const watched = (await marksOf(w)).payment_check?.due_at.getTime() ?? 0;
    expect(watched).toBeGreaterThanOrEqual(started + WEEK_MS);
    expect(watched).toBeLessThanOrEqual((await serverNow()) + WEEK_MS);
    const underWay = (await marksOf(other.w)).payment_check?.due_at.getTime() ?? 0;
    expect(underWay).toBeLessThanOrEqual(await serverNow());
    expect(await checks.list()).toEqual([other.w.org]);
    expect((await watches.list()).toSorted()).toEqual([w.org, other.w.org].toSorted());
  });

  it("a watch list it can't read is said, and the regular checks go on", async () => {
    const { w } = await ready();
    let regular = 0;
    const job = createPaymentChecks({
      list: () => {
        regular += 1;
        return Promise.resolve([w.org]);
      },
      watchList: () => Promise.reject(new Error('no marks')),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: w.rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
    });
    await job.run();
    expect(regular).toBe(1);
    expect(lines('payment_check.run_failed')).toHaveLength(1);
  });
});
