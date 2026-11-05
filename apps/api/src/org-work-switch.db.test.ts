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

import {
  createHandoff,
  handOffDue,
  RUN_BUDGET_MS,
  handoffDatabaseGate,
  handOffSweepDue,
  HEARTBEAT_STALE_MS,
  settleReadsGate,
} from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type World } from './mandate-world.helper.test.ts';
import { createOrgWorkRediscovery, markedOrganisations, WAITING_AS_A_WHOLE_MS, withOrgWork } from './org-work.ts';
import { createPaymentChecks, paymentCheckDue } from './payment-checks.ts';
import { createRailHealth, type RailHealth } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;
/** The operator's own role (PL-57), the one that moves the hand-off pause. */
let operator: Database<HandoffWorldTables>;

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

/** The organisation's marks of the hand-off's and the checks' jobs: those 0073 adds for the expiries are their tests'. */
async function marksOf(w: World): Promise<Record<string, { due_at: Date; marks: string }>> {
  const rows = await admin().query<{ job: string; due_at: Date; marks: string }>(
    `select job, due_at, marks from directory.org_work
      where org_id = $1 and job in ('hand_off', 'hand_off_sweep', 'payment_check')`,
    [w.org],
  );
  return Object.fromEntries(rows.map(({ job, ...rest }) => [job, rest]));
}

/** The server's time now: the marks' times are its clock's. */
const serverNow = async () =>
  (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0]?.now.getTime() ?? 0;

const pauseMoved = (paused: boolean) =>
  operator
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
    clock,
    ...(most === undefined ? {} : { most }),
  });

/** The hand-off as job-list.ts makes it: its organisations from the marks, settled after each run. */
function switchedHandoff(
  w: World,
  {
    rail = w.rail,
    db = app,
    runBudgetMs,
    health = createRailHealth({ clock, logger: testLogger(capture) }),
  }: {
    rail?: FakeRail;
    db?: Database<HandoffWorldTables>;
    runBudgetMs?: number;
    health?: RailHealth;
  } = {},
) {
  const handOffs = marked('hand_off');
  const sweeps = marked('hand_off_sweep');
  const job = withOrgWork(
    [handOffs, sweeps],
    createHandoff({
      list: handOffs.list,
      sweepList: sweeps.list,
      unfinished: handOffs.unfinished,
      waitsAsAWhole: handOffs.waitsAsAWhole,
      ...(runBudgetMs === undefined ? {} : { runBudgetMs }),
      database: db,
      outbox: createOutbox({ ids, clock }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health,
      databaseGate: handoffDatabaseGate(6),
    }),
  );
  return { job, handOffs, sweeps };
}

/** The payment checks as job-list.ts makes them, `most` of their marks a run. */
function switchedChecks({
  rail,
  most,
  runBudgetMs,
}: {
  readonly rail: FakeRail;
  readonly most?: number;
  readonly runBudgetMs?: number;
}) {
  const checks = markedOrganisations({
    job: 'payment_check',
    nextDue: paymentCheckDue,
    database: app,
    logger: testLogger(capture),
    clock,
    ...(most === undefined ? {} : { most }),
  });
  const job = withOrgWork(
    [checks],
    createPaymentChecks({
      list: checks.list,
      unfinished: checks.unfinished,
      nextTurn: (orgId, at) => {
        checks.dueBy(orgId, at);
      },
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture), laneUnknowns: 1_000 }),
      databaseGate: handoffDatabaseGate(6),
      ...(runBudgetMs === undefined ? {} : { runBudgetMs }),
    }),
  );
  return { job, checks };
}

/** A rail whose lookups find nothing, each noted with its organisation and the test clock's minute. */
function noting(
  w: World,
  { answers = () => false }: { readonly answers?: (instructionId: string) => boolean } = {},
): { rail: FakeRail; asked: { orgId: string; instructionId: string; minute: number }[] } {
  const asked: { orgId: string; instructionId: string; minute: number }[] = [];
  const startedAt = clock.now().getTime();
  return {
    asked,
    rail: {
      ...w.rail,
      getExecution: (ref) => {
        asked.push({
          orgId: ref.organizationId,
          instructionId: ref.instructionId,
          minute: Math.round((clock.now().getTime() - startedAt) / 60_000),
        });
        // Those `answers` picks, the world's own fake answers, so they move as the bank moves them.
        return answers(ref.instructionId) ? w.rail.getExecution(ref) : Promise.resolve({ kind: 'not_found' });
      },
    },
  };
}

/** The minutes one payment was asked about, in order, once each. */
const minutesOf = (asked: readonly { instructionId: string; minute: number }[], instructionId: string) => [
  ...new Set(asked.filter((each) => each.instructionId === instructionId).map(({ minute }) => minute)),
];

/** The gaps between the minutes a payment was asked about. */
const gapsOf = (minutes: readonly number[]) => minutes.slice(1).map((minute, at) => minute - (minutes[at] ?? 0));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  operator = createDatabase<HandoffWorldTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  // Born paused (ADR-014 §4): resumed for these tests, as the operator would.
  await pauseMoved(false);
});

afterAll(async () => {
  await app.destroy();
  await operator.destroy();
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

  it("a run its budget cut before the organisation's turn leaves it due now, by the job's word, not its rows", async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const before = (await marksOf(w)).hand_off;

    await switchedHandoff(w, { runBudgetMs: 0 }).job.run();

    expect(await statusOf(w, request.id)).toBe('APPROVED');
    // The job's clock, behind Postgres's: its rows, read, would have said Postgres's now.
    expect((await marksOf(w)).hand_off).toEqual({ marks: before?.marks, due_at: clock.now() });
    await switchedHandoff(w).job.run();
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });

  it('one stopped at the gate as the budget ran out is due now too', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const before = (await marksOf(w)).hand_off;
    const real = createRailHealth({ clock, logger: testLogger(capture) });
    // The budget (a millisecond, so the job's clock stays behind Postgres's) spent while it waited for the gate.
    const health: RailHealth = {
      ...real,
      enter: (orgId) => {
        clock.advanceBy(1);
        return real.enter(orgId);
      },
    };

    await switchedHandoff(w, { health, runBudgetMs: 1 }).job.run();

    expect(await statusOf(w, request.id)).toBe('APPROVED');
    // Its rows, read, would have said Postgres's now, later.
    expect(clock.now().getTime()).toBeLessThan(await serverNow());
    expect((await marksOf(w)).hand_off).toEqual({ marks: before?.marks, due_at: clock.now() });
  });

  it('a frozen organisation is visited once a minute, not every run, and lifted, is handed off within it', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const mandateId = await shared.mandateIdOf(w);
    await shared.moved(w, mandateId, 'organization', 'pause');
    const { job } = switchedHandoff(w);
    const visited = () => lines('handoff.waiting').length + lines('handoff.handed_off').length;
    const dueAt = async () => (await marksOf(w)).hand_off?.due_at.getTime();

    await job.run();
    expect(lines('handoff.waiting')).toEqual([expect.objectContaining({ requestId: request.id, why: 'organization' })]);
    const waitsUntil = clock.now().getTime() + WAITING_AS_A_WHOLE_MS;
    expect(await dueAt()).toBe(waitsUntil);
    // Within its minute: not listed, so not visited, and its mark stays where it was.
    clock.advanceBy(WAITING_AS_A_WHOLE_MS / 2);
    capture = new LogCapture();
    const quiet = switchedHandoff(w);
    await quiet.job.run();
    expect(await dueAt()).toBe(waitsUntil);
    expect(visited()).toBe(0);
    // Its minute passed: visited again (a new job says its waiting afresh), and waits another.
    clock.advanceBy(WAITING_AS_A_WHOLE_MS / 2);
    await quiet.job.run();
    expect(visited()).toBe(1);
    expect(await dueAt()).toBe(clock.now().getTime() + WAITING_AS_A_WHOLE_MS);

    await shared.moved(w, mandateId, 'organization', 'resume');
    clock.advanceBy(WAITING_AS_A_WHOLE_MS);
    await quiet.job.run();
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });

  it("one held by the bank breaker waits its minute too, as a reason its whole organisation's", async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const real = createRailHealth({ clock, logger: testLogger(capture) });
    const health: RailHealth = { ...real, enter: () => ({ hold: 'lane', outage: 0 }) };

    await switchedHandoff(w, { health }).job.run();

    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect((await marksOf(w)).hand_off?.due_at.getTime()).toBe(clock.now().getTime() + WAITING_AS_A_WHOLE_MS);
  });

  it('held as a whole and stopped at the gate in one turn: it waits its minute, its rows unable to move', async () => {
    const { w, acting } = await ready();
    const requests = [await ask(acting, w, { amount: SMALL() }), await ask(acting, w, { amount: SMALL(5n) })];
    const real = createRailHealth({ clock, logger: testLogger(capture) });
    let entered = 0;
    // Both taken at once in its lane: the first held, and the budget spent as it is; the second finds it spent.
    const health: RailHealth = {
      ...real,
      enter: (orgId) => {
        entered += 1;
        if (entered > 1) return real.enter(orgId);
        clock.advanceBy(RUN_BUDGET_MS);
        return { hold: 'lane', outage: 0 };
      },
    };

    await switchedHandoff(w, { health }).job.run();

    expect(entered).toBe(2);
    for (const { id } of requests) expect(await statusOf(w, id)).toBe('APPROVED');
    expect((await marksOf(w)).hand_off?.due_at.getTime()).toBe(clock.now().getTime() + WAITING_AS_A_WHOLE_MS);
  });

  it('one frozen beside another in the same run: only the frozen one waits its minute', async () => {
    const frozen = await ready();
    await ask(frozen.acting, frozen.w, { amount: ALLOWED() });
    const mandateId = await shared.mandateIdOf(frozen.w);
    await shared.moved(frozen.w, mandateId, 'organization', 'pause');
    const other = await ready();
    // Waiting for its supplier's payee: a reason of its own request's.
    await ask(other.acting, other.w, { amount: ALLOWED(), supplierId: other.w.suppliers[1] ?? '' });

    await switchedHandoff(frozen.w).job.run();

    const waitsUntil = clock.now().getTime() + WAITING_AS_A_WHOLE_MS;
    expect((await marksOf(frozen.w)).hand_off?.due_at.getTime()).toBe(waitsUntil);
    expect((await marksOf(other.w)).hand_off?.due_at.getTime()).toBeLessThan(waitsUntil);
  });

  it('a whole organisation lifted: a run after that ends its turn on its own request settles by its rows again', async () => {
    const { w, acting } = await ready();
    // Waiting for its supplier's payee, a reason of its own, once the freeze is lifted.
    await ask(acting, w, { amount: ALLOWED(), supplierId: w.suppliers[1] ?? '' });
    const mandateId = await shared.mandateIdOf(w);
    await shared.moved(w, mandateId, 'organization', 'pause');
    const { job } = switchedHandoff(w);
    await job.run();
    await shared.moved(w, mandateId, 'organization', 'resume');
    clock.advanceBy(WAITING_AS_A_WHOLE_MS);

    await job.run();

    expect(lines('handoff.waiting').map(({ why }) => why)).toEqual(['organization', 'payee']);
    // Due now by its rows (Postgres's clock), not another minute on.
    expect((await marksOf(w)).hand_off?.due_at.getTime()).toBeLessThan(clock.now().getTime() + WAITING_AS_A_WHOLE_MS);
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

  it('a settle never waits on a commit marking the row: it skips it, and the mark that commit made stands', async () => {
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
      // Returns while the writer still holds the row: had it waited, it could not.
      await handOffs.settle();
      await writer.query('commit');
    } finally {
      await writer.end();
    }
    expect(Object.keys(await marksOf(w))).toEqual(['hand_off']);
    // Settled again with that mark read, it goes.
    await handOffs.list();
    await handOffs.settle();
    expect(await marksOf(w)).toEqual({});
  });

  it('one the run left unfinished, a commit marking it during the settle: skipped, and that mark stands', async () => {
    const { w } = await ready();
    const earlier = new Date(clock.now().getTime() - 60_000);
    await markOrgWork(app, w.org, 'hand_off', earlier);
    const handOffs = marked('hand_off');
    expect(await handOffs.list()).toEqual([w.org]);
    const listed = (await marksOf(w)).hand_off?.marks ?? '0';
    handOffs.unfinished(w.org);
    const writer = await database.connect('admin');
    try {
      await writer.query('begin');
      await writer.query(`update directory.org_work set marks = marks + 1 where org_id = $1 and job = 'hand_off'`, [
        w.org,
      ]);
      // Returns while the writer still holds the row: had it waited, it could not.
      await handOffs.settle();
      await writer.query('commit');
    } finally {
      await writer.end();
    }
    // Not moved to now: the writer's mark stands as it made it.
    expect((await marksOf(w)).hand_off).toEqual({ marks: String(BigInt(listed) + 1n), due_at: earlier });
  });

  it('those left unfinished settle due now, behind those due before them: one cut every run keeps no other out', async () => {
    const orgs: string[] = [];
    for (let n = 0; n < 3; n += 1) orgs.push((await ready()).w.org);
    await admin().query('delete from directory.org_work');
    // None has rows due: only the job's word keeps the two it didn't finish marked.
    for (const [at, orgId] of orgs.entries()) {
      await markOrgWork(app, orgId, 'hand_off', new Date(clock.now().getTime() - (orgs.length - at) * 1000));
    }
    const [first, second, third] = orgs;
    const handOffs = marked('hand_off', 2);
    expect(await handOffs.list()).toEqual([first, second]);
    handOffs.unfinished(first ?? '');
    handOffs.unfinished(second ?? '');
    await handOffs.settle();

    const next = await handOffs.list();
    expect(next[0]).toBe(third);
    expect(next).toHaveLength(2);
    await handOffs.settle();
    // Read by their rows this time, the two settled go; the one left behind is listed again.
    expect(await handOffs.list()).toEqual([first, second].filter((orgId) => !next.includes(orgId ?? '')));
  });

  it.each([
    [15, 3],
    [6, 1],
  ])(
    "every job's settling shares one gate: with a pool of %i, the hand-off's 2 and %i read beside them, a third",
    async (poolMax, most) => {
      const orgs: string[] = [];
      for (let n = 0; n < 3; n += 1) {
        const { w, acting } = await ready();
        await ask(acting, w, { amount: ALLOWED() });
        await markOrgWork(app, w.org, 'payment_check', clock.now());
        orgs.push(w.org);
      }
      const reads = settleReadsGate(poolMax);
      const base = { database: app, logger: testLogger(capture), clock, reads };
      const handOffs = markedOrganisations({ ...base, job: 'hand_off', nextDue: handOffDue });
      const checks = markedOrganisations({ ...base, job: 'payment_check', nextDue: paymentCheckDue });
      expect((await handOffs.list()).toSorted()).toEqual(orgs.toSorted());
      expect((await checks.list()).toSorted()).toEqual(orgs.toSorted());
      // The rows both read held: each read waits there, so those under way at once are all seen waiting.
      const holder = await database.connect('owner');
      await holder.query('begin');
      await holder.query('lock table spend_requests.requests, transactions.transactions in access exclusive mode');
      const settling = Promise.all([handOffs.settle(), checks.settle()]);
      let held = true;
      onTestFinished(async () => {
        if (held) await holder.query('commit');
        await settling;
        await holder.end();
      });
      expect(await waitUntilQueued(admin(), most)).toHaveLength(most);
      // No more than that: the other reads, of both jobs, wait their turn outside the database.
      const [{ waiting } = { waiting: 0 }] = await admin().query<{ waiting: number }>(
        // This test's database alone: other test files wait on locks in their own databases on the same server.
        `select pg_catalog.count(distinct l.pid)::integer as waiting from pg_catalog.pg_locks l
           join pg_catalog.pg_stat_activity a on a.pid = l.pid
          where not l.granted and a.datname = pg_catalog.current_database()`,
      );
      expect(waiting).toBe(most);
      held = false;
      await holder.query('commit');
      await settling;
      // Each still has its approved request: moved to now, none lost on the way.
      expect(await admin().query(`select 1 from directory.org_work where job = 'hand_off'`)).toHaveLength(3);
    },
  );

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

  it("a settle reads each organisation's next due in a transaction of its own, then writes the page in one", async () => {
    const trips = async (count: number) => {
      const orgs: string[] = [];
      for (let n = 0; n < count; n += 1) orgs.push((await ready()).w.org);
      await admin().query('delete from directory.org_work');
      for (const orgId of orgs) await markOrgWork(app, orgId, 'hand_off', clock.now());
      const handOffs = marked('hand_off');
      await handOffs.list();
      const times = noStatementTimes();
      await timingStatements(times, () => handOffs.settle());
      expect(await admin().query('select 1 from directory.org_work')).toEqual([]);
      return times.trips;
    };
    const one = await trips(1);
    // Each read: its start with the organisation set, the read, the commit; the write: its start, the statement, the commit.
    expect(one).toBe(6);
    expect(await trips(3)).toBe(one + 2 * 3);
  });
});

describe('the payment checks follow theirs', () => {
  it('a payment under way keeps its mark due now; one settled is watched, due in 30 minutes, not listed before', async () => {
    const { w, acting } = await ready();
    // `.01`: the fake declines it with its proof, so the hand-off's Tx B settles it FAILED.
    await ask(acting, w, { amount: ALLOWED(1n) });
    await switchedHandoff(w).job.run();
    // The fils choose it stays under way.
    const other = await ready();
    await ask(other.acting, other.w, { amount: SMALL() });
    await switchedHandoff(other.w).job.run();
    const { rail, asked } = noting(w);
    const { job, checks } = switchedChecks({ rail });

    // Each one's turns are due at once after a start: the failed one's watch among them.
    await job.run();
    expect(asked.map(({ orgId }) => orgId)).toContain(w.org);

    expect((await marksOf(w)).payment_check?.due_at.getTime()).toBe(clock.now().getTime() + 30 * 60_000);
    expect((await marksOf(other.w)).payment_check?.due_at.getTime()).toBe(clock.now().getTime());
    expect(await checks.list()).toEqual([other.w.org]);
    clock.advanceBy(30 * 60_000);
    expect((await checks.list()).toSorted()).toEqual([w.org, other.w.org].toSorted());
  });

  it('an organisation whose turn a run cut short is due now, whatever its rows say, and the next run takes it', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: SMALL() });
    await switchedHandoff(w).job.run();
    const before = await marksOf(w);
    const { rail, asked } = noting(w);
    // Past its first 15 minutes, its rows say its next turn is 5 minutes on.
    clock.advanceBy(16 * 60_000);

    await switchedChecks({ rail, runBudgetMs: 0 }).job.run();
    expect(asked).toEqual([]);
    expect((await marksOf(w)).payment_check).toEqual({
      marks: before.payment_check?.marks,
      due_at: clock.now(),
    });

    await switchedChecks({ rail }).job.run();
    expect(asked.map(({ orgId }) => orgId)).toContain(w.org);
  });

  it("two a run of many: every organisation's older, UNKNOWN and watched payments are checked every 30 minutes or so", async () => {
    // Three kept under way, two gone UNKNOWN, one failed (watched alone): all older than a day by the runs.
    const slow: World[] = [];
    for (let n = 0; n < 3; n += 1) {
      const { w, acting } = await ready();
      await ask(acting, w, { amount: SMALL() });
      slow.push(w);
    }
    for (let n = 0; n < 2; n += 1) {
      const { w, acting } = await ready();
      // The fake's .02: made at the partner, its answer lost.
      await ask(acting, w, { amount: AED(5_002n) });
      slow.push(w);
    }
    const failed = await ready();
    await ask(failed.acting, failed.w, { amount: ALLOWED(1n) });
    slow.push(failed.w);
    for (const w of slow) await switchedHandoff(w).job.run();
    clock.advanceBy(2 * 24 * 3_600_000);
    // Then more than the cap with payments under 15 minutes old, due every run.
    const busy: World[] = [];
    for (let n = 0; n < 3; n += 1) {
      const { w, acting } = await ready();
      await ask(acting, w, { amount: SMALL() });
      await switchedHandoff(w).job.run();
      busy.push(w);
    }
    const [first] = slow;
    if (first === undefined) throw new Error('no world');
    const { rail, asked } = noting(first);
    const { job } = switchedChecks({ rail, most: 2 });

    // 75 runs, a minute apart.
    for (let run = 0; run < 75; run += 1) {
      await job.run();
      clock.advanceBy(60_000);
    }

    const minutesOf = (w: World) => [
      ...new Set(asked.filter(({ orgId }) => orgId === w.org).map(({ minute }) => minute)),
    ];
    for (const w of slow) {
      const minutes = minutesOf(w);
      // The first soon, however many are due ahead of it; then each again 30 minutes on, within a few runs.
      expect(minutes[0]).toBeLessThanOrEqual(10);
      expect(minutes.length).toBeGreaterThanOrEqual(2);
      for (let at = 1; at < minutes.length; at += 1) {
        expect((minutes[at] ?? 0) - (minutes[at - 1] ?? 0)).toBeGreaterThanOrEqual(30);
        expect((minutes[at] ?? 0) - (minutes[at - 1] ?? 0)).toBeLessThanOrEqual(36);
      }
    }
    // The busy ones, under 15 minutes old, were asked run after run while they were.
    for (const w of busy) expect(minutesOf(w).length).toBeGreaterThanOrEqual(10);
  });

  describe('a mark never passes a turn already counted', () => {
    /** `n` runs of the job, a minute apart. */
    const minutes = async (job: { run(): Promise<void> }, n: number) => {
      for (let run = 0; run < n; run += 1) {
        await job.run();
        clock.advanceBy(60_000);
      }
    };

    it('an old payment asked every 30 minutes though a fresh one came and was paid between', async () => {
      const { w, acting } = await ready();
      // The fils choose it stays under way: older than a day by the runs.
      await ask(acting, w, { amount: SMALL() });
      await switchedHandoff(w).job.run();
      clock.advanceBy(2 * 24 * 3_600_000);
      // The bank answers for all but the first it is asked about: that old one stays under way.
      const startedAt = clock.now().getTime();
      const kept: { id?: string } = {};
      const { rail, asked } = noting(w, { answers: (instructionId) => (kept.id ??= instructionId) !== instructionId });
      const { job } = switchedChecks({ rail });

      await minutes(job, 10);
      const old = kept.id;
      if (old === undefined) throw new Error('not asked');
      // At minute 10 a fresh one, marked as it is handed off, then paid by the bank's word within a few runs.
      await ask(acting, w, { amount: ALLOWED() });
      await switchedHandoff(w).job.run();
      await minutes(job, 10);
      // Paid, and a day's turn since that read none: the mark waits for the old one's turn at 30, not the day's at 20.
      expect((await marksOf(w)).payment_check?.due_at.getTime()).toBe(startedAt + 30 * 60_000);
      await minutes(job, 40);

      const times = minutesOf(asked, old);
      expect(times[0]).toBe(0);
      expect(times.length).toBeGreaterThanOrEqual(2);
      for (const gap of gapsOf(times)) expect(gap).toBe(30);
    });

    it("a payment past its first 15 minutes keeps its day's turns 5 minutes apart", async () => {
      const { w, acting } = await ready();
      await ask(acting, w, { amount: SMALL() });
      await switchedHandoff(w).job.run();
      // Its first check two minutes on, so its day's turns fall off the 15 minutes' edge.
      clock.advanceBy(2 * 60_000);
      const { rail, asked } = noting(w);
      const { job } = switchedChecks({ rail });

      await minutes(job, 40);

      const [first] = asked;
      if (first === undefined) throw new Error('not asked');
      const times = minutesOf(asked, first.instructionId);
      // Every run while under 15 minutes old (to minute 13), its day's turns at 0, 5, 10: the next is 15, not 13's + 5.
      const after = times.filter((minute) => minute >= 14);
      expect(after[0]).toBe(15);
      expect(after.length).toBeGreaterThanOrEqual(4);
      for (const gap of gapsOf(after)) expect(gap).toBe(5);
    });

    it("with Postgres's clock minutes ahead of this process's, no turn slips a period", async () => {
      const { w, acting } = await ready();
      await ask(acting, w, { amount: SMALL() });
      await switchedHandoff(w).job.run();
      clock.advanceBy(2 * 60_000);
      const { rail, asked } = noting(w);
      const { job } = switchedChecks({ rail });
      // Postgres three minutes ahead, as the list reads a mark: each time a settle writes, its time is read back three
      // minutes sooner, so the list finds it that much early, run after run (this process's clock is the test's).
      let written: number | undefined;
      const aheadOfUs = async () => {
        const due = (await marksOf(w)).payment_check?.due_at.getTime();
        if (due === undefined || due === written) return;
        written = due - 3 * 60_000;
        await admin().query(
          `update directory.org_work set due_at = due_at - interval '3 minutes' where org_id = $1 and job = 'payment_check'`,
          [w.org],
        );
      };

      for (let run = 0; run < 40; run += 1) {
        await job.run();
        await aheadOfUs();
        clock.advanceBy(60_000);
      }

      const [first] = asked;
      if (first === undefined) throw new Error('not asked');
      // Past its first 15 minutes (minute 13), its day's turns at 15, 20, 25...: each listed early, never taken late.
      const after = minutesOf(asked, first.instructionId).filter((minute) => minute >= 14);
      expect(after[0]).toBe(15);
      expect(after.length).toBeGreaterThanOrEqual(4);
      for (const gap of gapsOf(after)) expect(gap).toBe(5);
    });

    it('a slower kind that read nothing still holds the mark to its turn: a payment paid beside an old UNKNOWN', async () => {
      const { w, acting } = await ready();
      // The fake's .02: made at the partner, its answer lost; older than a day by the runs.
      await ask(acting, w, { amount: AED(5_002n) });
      await switchedHandoff(w).job.run();
      clock.advanceBy(2 * 24 * 3_600_000);
      // The bank answers for all but the UNKNOWN; its first answer stops the first run, so the watch's turn is cut.
      const kept: { id?: string } = {};
      const stop = new AbortController();
      const noted = noting(w, { answers: (instructionId) => (kept.id ??= instructionId) !== instructionId });
      const rail: FakeRail = {
        ...noted.rail,
        getExecution: async (ref) => {
          const answer = await noted.rail.getExecution(ref);
          if (ref.instructionId === kept.id) stop.abort();
          return answer;
        },
      };
      const { job } = switchedChecks({ rail });

      await job.run(stop.signal);
      clock.advanceBy(60_000);
      // Minute 1: the watch's turn taken whole, reading nothing; its next at 31, the UNKNOWNs' at 30.
      await minutes(job, 4);
      // Minute 5: a fresh one, handed off, then paid within a few runs: watched from then on.
      await ask(acting, w, { amount: ALLOWED() });
      await switchedHandoff(w).job.run();
      await minutes(job, 35);

      const unknown = kept.id;
      if (unknown === undefined) throw new Error('not asked');
      expect(minutesOf(noted.asked, unknown)).toEqual([0, 30]);
      const paid = noted.asked.find(({ instructionId }) => instructionId !== unknown)?.instructionId ?? '';
      // Its watch's turn at 31, at most a run late: not pushed to 60 by the UNKNOWNs' settles.
      expect(minutesOf(noted.asked, paid).find((minute) => minute >= 15)).toBeLessThanOrEqual(32);
    });
  });
});
