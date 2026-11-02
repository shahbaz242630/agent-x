// 4D2e Stage F: the hand-off held for the bank, on the real migrated schema as
// the app role. A lane's 3 unknowns in a row hold its organisation, then one at
// a time; 5 unknowns from 3 organisations hold everyone, until a status lookup
// answers; a real payment is never the probe; each organisation told once, in
// its signed audit log.
import { createAuditTrail } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import { createMemoryAnchorStore, signAnchor } from '@agentx/platform/audit-chain';
import { type FakeRail, type PaymentExecution, RailUnavailable } from '@agentx/core/modules/providers';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import fc from 'fast-check';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, HEARTBEAT_STALE_MS, QUEUE_STALE_MS } from './handoff.ts';
import { handoffWorld, type HandoffWorldTables } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { createRailHealth, type RailHealth, watchedRail } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xf2a0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xf2b0_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let health: RailHealth;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'handoff-lanes',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, statusOf } = shared;
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

/** AED 50: many to one supplier still under the approval threshold, its split check included. */
const TINY = AED(5_000n);

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

type Submit = FakeRail['submitApprovedIntent'];

const noAnswer: Submit = (_intent) => Promise.reject(new RailUnavailable());

/**
 * One partner for all the worlds, each organisation's intent reaching its own
 * world's fake (where its consent is), each submission noted by organisation;
 * `answering` answers instead of the fake where it says so.
 */
function railOver(worlds: readonly World[], answering?: (real: Submit) => Submit) {
  const [first] = worlds;
  if (first === undefined) throw new Error('no world');
  const sent: string[] = [];
  const real: Submit = (intent) =>
    (worlds.find((w) => w.org === intent.organizationId) ?? first).rail.submitApprovedIntent(intent);
  const answer = answering === undefined ? real : answering(real);
  const rail: FakeRail = {
    ...first.rail,
    submitApprovedIntent: (intent) => {
      sent.push(intent.organizationId);
      return answer(intent);
    },
  };
  return { rail, sent };
}

type HandoffOptions = Parameters<typeof createHandoff>[0];

/** The job over the worlds' organisations, paying through `rail`, on this test's breaker. */
const handoffOver = (worlds: readonly World[], rail: FakeRail, options: Partial<HandoffOptions> = {}) =>
  createHandoff({
    list: () => Promise.resolve(worlds.map(({ org }) => org)),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail,
    health,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
    poolMax: 6,
    // One at a time unless a test says otherwise, so what it counts falls the same each run.
    limits: { total: 1, perOrganisation: 1 },
    ...options,
  });

/** A world with `count` small requests waiting, approved. */
async function worldWith(count: number) {
  const { w, acting } = await ready();
  const requests: string[] = [];
  for (let at = 0; at < count; at += 1) {
    const request = await ask(acting, w, { amount: TINY });
    expect(request.status).toBe('APPROVED');
    requests.push(request.id);
  }
  return { w, acting, requests };
}

/** The organisation's signed notes that its payments wait for the bank. */
const heldNotesOf = (w: World) =>
  withTenant(app, w.org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['actor_type', 'subject_type', 'details'])
      .where('action', '=', 'handoff.held_for_bank')
      .orderBy('seq')
      .execute(),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  // Born paused (ADR-014 §4): resumed for these tests.
  await app
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: false, reason: 'TEST-F', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  const logger = testLogger(capture);
  health = createRailHealth({ clock, logger });
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
});

/** Unknowns counted for these organisations, as a bank gone quiet leaves them. */
const unknownsFrom = (orgs: readonly string[]) => {
  for (const org of orgs) {
    const entry = health.enter(org);
    if ('settle' in entry) entry.settle('unknown');
  }
};

/** Answers a status lookup for the organisation, as the bank check would. */
const lookedFor = (w: World, rail: FakeRail) =>
  watchedRail(rail, health).getExecution({ organizationId: w.org, instructionId: ids.next() });

/** The app's database, `opened` called at each transaction it opens: a run's trips counted, or stopped at one. */
const databaseWatched = (opened: () => void): Database<HandoffWorldTables> =>
  new Proxy(app, {
    get(target, name, receiver) {
      const value: unknown = Reflect.get(target, name, receiver);
      if (typeof value !== 'function') return value;
      if (name !== 'transaction') return (value as (...args: unknown[]) => unknown).bind(target);
      return () => {
        opened();
        return (value as () => unknown).call(target);
      };
    },
  });

describe('turns: fair, kept between runs (fair-lanes.ts)', () => {
  it('gives each organisation one request a pass, whichever has most', async () => {
    const big = await worldWith(3);
    const small = await worldWith(1);
    const { rail, sent } = railOver([big.w, small.w]);

    await handoffOver([big.w, small.w], rail).run();

    expect(sent).toEqual([big.w.org, small.w.org, big.w.org, big.w.org]);
  });

  it('a long run of waiting requests keeps no younger one out', async () => {
    const { w, acting } = await ready();
    // Older, to the supplier with no payee yet: each waits. Each run is stopped as its first request's Tx A opens.
    const older = [];
    for (let at = 0; at < 3; at += 1) {
      older.push(await ask(acting, w, { amount: TINY, supplierId: w.suppliers[1] ?? '' }));
    }
    const younger = await ask(acting, w, { amount: TINY });
    let stopping = new AbortController();
    let opened = 0;
    const job = handoffOver([w], railOver([w]).rail, {
      database: databaseWatched(() => {
        opened += 1;
        // A run's transactions: the pause (1), the page (2), the first request's Tx A (3).
        if (opened === 3) stopping.abort();
      }),
    });
    const stoppedRun = async () => {
      stopping = new AbortController();
      opened = 0;
      await job.run(stopping.signal);
    };

    await stoppedRun();
    await stoppedRun();
    await stoppedRun();
    // Each run took the next: none read twice, though no run reached the end.
    expect(lines('handoff.waiting').map(({ requestId }) => requestId)).toEqual(older.map(({ id }) => id));
    expect(await statusOf(w, younger.id)).toBe('APPROVED');

    await stoppedRun();
    expect(await statusOf(w, younger.id)).toBe('HANDED_OFF');
  });

  it('wraps to the start after its end: one left waiting is tried again, not said again', async () => {
    const { w, acting } = await ready();
    const stuck = await ask(acting, w, { amount: TINY, supplierId: w.suppliers[1] ?? '' });
    const job = handoffOver([w], railOver([w]).rail);

    await job.run();
    await job.run();

    expect(lines('handoff.waiting')).toEqual([expect.objectContaining({ requestId: stuck.id })]);
    expect(await statusOf(w, stuck.id)).toBe('APPROVED');
  });

  it('never counts the rest as left standing while a pass is cut short; once it is whole, it does', async () => {
    const { w } = await worldWith(3);
    // Every Tx A fails, so they stand for no reason the run knows; the first run is stopped at its first.
    let stopping: AbortController | undefined = new AbortController();
    let opened = 0;
    const failing = new Proxy(app, {
      get(target, name, receiver) {
        const value: unknown = Reflect.get(target, name, receiver);
        if (typeof value !== 'function') return value;
        if (name !== 'transaction') return (value as (...args: unknown[]) => unknown).bind(target);
        return () => {
          opened += 1;
          // The pause (1), the page (2); then a Tx A, which fails.
          if (opened === 3) {
            stopping?.abort();
            throw new Error('the database is away');
          }
          return (value as () => unknown).call(target);
        };
      },
    });
    const job = handoffOver([w], railOver([w], () => noAnswer).rail, { database: failing });
    clock.advanceBy(QUEUE_STALE_MS + 60_000);

    await job.run(stopping.signal);
    expect(lines('handoff.failed')).toHaveLength(1);
    expect(lines('handoff.queue_stale')).toEqual([]);

    // On from where it stopped, to its end: the one that failed is now left standing, and said.
    stopping = undefined;
    opened = 100;
    await job.run();
    expect(lines('handoff.queue_stale')).toEqual([expect.objectContaining({ requests: 1 })]);
  });

  it('counts nothing left standing for an organisation with no rows: a trip saved', async () => {
    const { w } = await ready();
    let opened = 0;
    const job = handoffOver([w], railOver([w]).rail, {
      database: databaseWatched(() => {
        opened += 1;
      }),
    });
    // Its sweep done on the first; on the second, the pause (1) and the page (2), and no count.
    await job.run();
    opened = 0;
    await job.run();

    expect(opened).toBe(2);
  });

  it('a frozen organisation stops its turn and raises no stale alert', async () => {
    const { w, requests } = await worldWith(3);
    const mandateId = await shared.mandateIdOf(w);
    await shared.moved(w, mandateId, 'organization', 'pause');
    let opened = 0;
    const { rail, sent } = railOver([w]);
    const job = handoffOver([w], rail, {
      database: databaseWatched(() => {
        opened += 1;
      }),
    });

    await job.run();
    // Past the queue's age, its sweep already done: the pause (1), the page (2), the first request's Tx A (3), and no more.
    clock.advanceBy(QUEUE_STALE_MS + 60_000);
    await job.run();
    opened = 0;
    await job.run();
    expect(opened).toBe(3);

    expect(sent).toEqual([]);
    expect(lines('handoff.queue_stale')).toEqual([]);
    // Said once, for the one request it reached; the rest not walked for the same answer.
    expect(lines('handoff.waiting')).toEqual([
      expect.objectContaining({ requestId: requests[0] ?? '', why: 'organization' }),
    ]);

    await shared.moved(w, mandateId, 'organization', 'resume');
    await job.run();
    for (const id of requests) expect(await statusOf(w, id)).toBe('HANDED_OFF');
  });
});

/** The rail hanging every call until told: each given back to the test to answer, by the fake, or not at all. */
function railHanging(worlds: readonly World[]) {
  const calls: { intent: Parameters<Submit>[0]; answer: () => void; lose: () => void }[] = [];
  const { rail, sent } = railOver(worlds, (real) => (intent) => {
    const { promise, resolve, reject } = Promise.withResolvers<Awaited<ReturnType<Submit>>>();
    calls.push({
      intent,
      answer: () => {
        void real(intent).then(resolve, reject);
      },
      lose: () => {
        reject(new RailUnavailable());
      },
    });
    return promise;
  });
  return { rail, sent, calls };
}

/** The organisation's chain head held for update by another connection: its signed writes all queue there. */
async function headHeld(w: World) {
  const holder = await database.connect('owner');
  await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
  await holder.query('begin');
  await holder.query('select org_id from audit.heads where org_id = $1 for update', [w.org]);
  return async () => {
    await holder.query('commit');
    await holder.end();
  };
}

const handedOffNoFailure = () => {
  expect(lines('handoff.failed')).toEqual([]);
  expect(lines('handoff.answer_unrecorded')).toEqual([]);
};

const AT_ONCE = { total: 6, perOrganisation: 6 };

/** Asks the bank, as the bank check would, for each organisation: each lookup begun now. */
const lookupsFor = (orgs: readonly string[]) => {
  for (const org of orgs) health.lookupBegun(org)();
};

/** A request's row held for change by another connection, until let go: its Tx A queues there, in the gate. */
async function rowHeld(w: World, id: string) {
  const holder = await database.connect('owner');
  await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
  await holder.query('begin');
  await holder.query('select id from spend_requests.requests where id = $1 for no key update', [id]);
  return async () => {
    await holder.query('commit');
    await holder.end();
  };
}

/** How many of this database's backends wait on a lock now. */
const lockWaits = async () => {
  const rows = await database
    .as('admin')
    .query<{ count: string }>(
      "select count(*) as count from pg_stat_activity where wait_event_type = 'Lock' and datname = current_database()",
    );
  return Number(rows[0]?.count);
};

const settleTicks = () => new Promise((resolve) => setTimeout(resolve, 200));

describe('at concurrency: bank slot, database gate, Tx A, the call, Tx B', () => {
  it('two Tx As in one organisation make one instruction each', async () => {
    const { w, requests } = await worldWith(2);
    const { rail, sent } = railOver([w]);
    const release = await headHeld(w);
    // Two copies, as a deploy overlaps them, each with its own gate: within one, the gate lets one in at a time.
    const copies = [handoffOver([w], rail, { limits: AT_ONCE }), handoffOver([w], rail, { limits: AT_ONCE })];
    const runs = within(20_000, Promise.all(copies.map((job) => job.run())), 'the runs');
    await waitUntilQueued(database.as('admin'), 2);
    await release();
    await runs;

    expect(sent).toHaveLength(2);
    const made = await Promise.all(requests.map((id) => paymentOf(w, id)));
    for (const payment of made) expect(payment).toMatchObject({ transactions: 1 });
    expect(new Set(made.map(({ instruction }) => (instruction as { id: string }).id)).size).toBe(2);
    handedOffNoFailure();
  });

  it('no bank call before Tx A commits', async () => {
    const { w, requests } = await worldWith(2);
    const seen: unknown[] = [];
    const { rail, sent } = railOver([w], (real) => async (intent) => {
      // By another connection: only what is committed can be read.
      const payments = await Promise.all(requests.map((id) => paymentOf(w, id)));
      seen.push(payments.find(({ instruction }) => (instruction as { id?: string }).id === intent.instructionId));
      return real(intent);
    });
    const release = await headHeld(w);
    const run = within(20_000, handoffOver([w], rail, { limits: AT_ONCE }).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    // At the head, uncommitted: nothing has gone to the bank.
    expect(sent).toEqual([]);
    await release();
    await run;

    expect(seen).toEqual([
      expect.objectContaining({ transaction: expect.objectContaining({ status: 'SUBMISSION_PENDING' }) as unknown }),
      expect.objectContaining({ transaction: expect.objectContaining({ status: 'SUBMISSION_PENDING' }) as unknown }),
    ]);
  });

  it('a chain behind its anchor is never sent at concurrency', async () => {
    const { w, requests } = await worldWith(3);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      const head = await owner.saveHead();
      // Grown honestly, anchored there as the anchor check would, then wound back behind it.
      await withTenant(app, w.org, (tx) =>
        createAuditTrail({ keys, ids }).record(tx, w.org, {
          actor: OPERATOR,
          action: 'invitation.drafted',
          subject: { type: 'invitation', id: ids.next(), version: 1 },
          details: {},
        }),
      );
      const grown = await owner.saveHead();
      const anchors = createMemoryAnchorStore();
      const chainOf = { kind: 'organisation', orgId: w.org } as const;
      anchors.keep(signAnchor(keys, chainOf, { seq: BigInt(grown.seq), hash: grown.hash }, clock.now()));
      await owner.windBack(head);
      const { rail, sent } = railOver([w]);

      await handoffOver([w], rail, {
        limits: AT_ONCE,
        anchoring: { anchors, anchorFirst: () => Promise.resolve() },
      }).run();

      expect(sent).toEqual([]);
      for (const id of requests) {
        expect(await statusOf(w, id)).toBe('APPROVED');
        expect(await paymentOf(w, id)).toEqual({ instruction: 'missing' });
      }
      expect(await shared.signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
    } finally {
      await owner.end();
    }
  });

  it('an UNKNOWN is never resent at concurrency', async () => {
    const { w, acting } = await ready();
    const requests: string[] = [];
    // The fake's .02: made at the partner, its answer lost.
    for (let at = 0; at < 3; at += 1) requests.push((await ask(acting, w, { amount: AED(5_002n) })).id);
    const instructions: string[] = [];
    const { rail } = railOver([w], (real) => (intent) => {
      instructions.push(intent.instructionId);
      return real(intent);
    });
    const job = handoffOver([w], rail, { limits: AT_ONCE });

    await job.run();
    clock.advanceBy(10 * 60_000 + 1);
    await job.run();
    lookupsFor([w.org]);
    await job.run();

    expect(instructions).toHaveLength(3);
    expect(new Set(instructions).size).toBe(3);
    for (const id of requests) {
      expect(await paymentOf(w, id)).toMatchObject({ transactions: 1, transaction: { status: 'UNKNOWN' } });
    }
  });

  it('Tx A and Tx B of one organisation don’t deadlock', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w, { amount: TINY });
    const hanging = railHanging([w]);
    const job = handoffOver([w], hanging.rail, { limits: AT_ONCE });
    // The first's Tx A committed, its call under way.
    const firstRun = job.run();
    await expect.poll(() => hanging.calls.length).toBe(1);
    const second = await ask(acting, w, { amount: TINY });
    const release = await headHeld(w);
    // The second's Tx A (holding its authority and its request), and the first's Tx B (holding its transaction and
    // holdings), both at the head, whichever gets it first: a second copy's Tx A, as one copy's gate lets one in.
    const secondRun = handoffOver([w], railOver([w]).rail, { limits: AT_ONCE }).run();
    await waitUntilQueued(database.as('admin'), 1);
    hanging.calls[0]?.answer();
    await waitUntilQueued(database.as('admin'), 2);
    await release();
    await within(20_000, Promise.all([firstRun, secondRun]), 'both runs');

    for (const { id } of [first, second]) {
      expect(await statusOf(w, id)).toBe('HANDED_OFF');
      expect(await paymentOf(w, id)).toMatchObject({ transactions: 1, transaction: { status: 'PROCESSING' } });
    }
    handedOffNoFailure();
  });

  it('a stop mid-call leaves SUBMISSION_PENDING and the check settles it', async () => {
    const { w, requests } = await worldWith(5);
    const hanging = railHanging([w]);
    const stopping = new AbortController();
    const job = handoffOver([w], hanging.rail, {
      limits: { total: 4, perOrganisation: 4 },
      stopWaitMs: 100,
    });
    const run = job.run(stopping.signal);
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(4);

    // Made at the bank, all four, their answers lost with the process.
    for (const call of hanging.calls) await w.rail.submitApprovedIntent(call.intent);
    stopping.abort();
    // A stop never waits out a hung bank: it ends clean, well inside the API's deadline.
    await within(5_000, run, 'the stop');
    const under = requests.slice(0, 4);
    for (const id of under) {
      expect(await paymentOf(w, id)).toMatchObject({ transaction: { status: 'SUBMISSION_PENDING' } });
    }
    expect(await statusOf(w, requests[4] ?? '')).toBe('APPROVED');

    // Their answers, come too late: nothing written, nothing said, the pool closing as it would be.
    for (const call of hanging.calls) call.lose();
    await settleTicks();
    expect(lines('handoff.answer_unrecorded')).toEqual([]);
    expect(capture.lines().filter((line) => line.level === 'error')).toEqual([]);
    for (const id of under) {
      expect(await paymentOf(w, id)).toMatchObject({ transaction: { status: 'SUBMISSION_PENDING' } });
    }

    // The check, past the answer's time, finds each at the bank by our reference: nothing sent again.
    clock.advanceBy(60_001);
    await createPaymentChecks({
      list: () => Promise.resolve([w.org]),
      database: app,
      rail: w.rail,
      outbox: createOutbox({ ids, clock }),
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    }).run();
    for (const id of under) {
      expect(await paymentOf(w, id)).toMatchObject({ transactions: 1, transaction: { status: 'PROCESSING' } });
    }
    expect(hanging.sent).toHaveLength(4);
  });

  it('a stop that isn’t held up waits for the calls under way, and records them', async () => {
    const { w, requests } = await worldWith(2);
    const hanging = railHanging([w]);
    const stopping = new AbortController();
    const run = handoffOver([w], hanging.rail, { limits: AT_ONCE }).run(stopping.signal);
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(2);

    stopping.abort();
    for (const call of hanging.calls) call.answer();
    await run;

    for (const id of requests) {
      expect(await paymentOf(w, id)).toMatchObject({ transaction: { status: 'PROCESSING' } });
    }
  });

  it('a hung bank starts no new Tx A', async () => {
    const worlds = [await worldWith(4), await worldWith(4), await worldWith(4)];
    const allWorlds = worlds.map(({ w }) => w);
    const hanging = railHanging(allWorlds);
    const job = handoffOver(allWorlds, hanging.rail, { limits: { total: 5, perOrganisation: 2 } });
    const total = 12;

    const run = job.run();
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(5);
    // Every slot held by a call that doesn't answer: no sixth, so no more instructions, however long.
    await settleTicks();
    expect(hanging.calls).toHaveLength(5);
    const madeNow = async () => {
      const payments = await Promise.all(worlds.flatMap(({ w, requests }) => requests.map((id) => paymentOf(w, id))));
      return payments.filter(({ instruction }) => instruction !== 'missing').length;
    };
    expect(await madeNow()).toBe(5);

    // Timeouts spread across the gaps between Tx As, oldest first, each slot free before the next: new Tx As may
    // start until the trip, none after it.
    let lost = 0;
    while (lines('handoff.bank_held').length === 0) {
      hanging.calls[lost]?.lose();
      lost += 1;
      await settleTicks();
    }
    await settleTicks();
    const sentByTheTrip = hanging.calls.length;
    const madeByTheTrip = await madeNow();
    expect(sentByTheTrip).toBeLessThan(total);
    expect(madeByTheTrip).toBe(sentByTheTrip);

    for (const call of hanging.calls.slice(lost)) call.lose();
    await run;
    await settleTicks();
    await job.run();
    expect(hanging.calls).toHaveLength(sentByTheTrip);
    expect(await madeNow()).toBe(madeByTheTrip);
  });

  it('half-open at concurrency: 3 at once, an acceptance reopening it for the rest', async () => {
    const worlds = [await worldWith(2), await worldWith(2), await worldWith(2)];
    const allWorlds = worlds.map(({ w }) => w);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    lookupsFor(['anyone']);
    const hanging = railHanging(allWorlds);

    const run = handoffOver(allWorlds, hanging.rail, { limits: { total: 6, perOrganisation: 2 } }).run();
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(3);
    await settleTicks();
    expect(hanging.calls).toHaveLength(3);

    // Its turn ended by the hold, each organisation waits for the next run: this one's three answered.
    for (const call of hanging.calls) call.answer();
    await run;
    expect(lines('handoff.bank_back')).toHaveLength(1);
  });

  it('half-open at concurrency: one unknown trips it again, and no more go', async () => {
    const worlds = [await worldWith(2), await worldWith(2), await worldWith(2)];
    const allWorlds = worlds.map(({ w }) => w);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    lookupsFor(['anyone']);
    const hanging = railHanging(allWorlds);
    const job = handoffOver(allWorlds, hanging.rail, { limits: { total: 6, perOrganisation: 2 } });

    const run = job.run();
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(3);
    hanging.calls[0]?.lose();
    await settleTicks();
    expect(health.heldFor(allWorlds[0]?.org ?? '')).toBe('bank');
    expect(lines('handoff.bank_held_again')).toHaveLength(1);
    expect(hanging.calls).toHaveLength(3);
    for (const call of hanging.calls.slice(1)) call.answer();
    await run;
    await job.run();
    expect(hanging.calls).toHaveLength(3);
  });

  it('holds 24 at once in all, and 4 in an organisation, by its own limits', async () => {
    const worlds = [];
    for (let at = 0; at < 7; at += 1) worlds.push(await worldWith(at === 0 ? 5 : 4));
    const allWorlds = worlds.map(({ w }) => w);
    const hanging = railHanging(allWorlds);
    const job = createHandoff({
      list: () => Promise.resolve(allWorlds.map(({ org }) => org)),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: hanging.rail,
      health,
      poolMax: 6,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    });

    const run = job.run();
    await expect.poll(() => hanging.calls.length, { timeout: 60_000 }).toBe(24);
    await settleTicks();
    expect(hanging.calls).toHaveLength(24);
    const byOrganisation = new Map<string, number>();
    for (const org of hanging.sent) byOrganisation.set(org, (byOrganisation.get(org) ?? 0) + 1);
    expect(Math.max(...byOrganisation.values())).toBe(4);

    for (const call of hanging.calls) call.answer();
    await expect.poll(() => hanging.calls.length, { timeout: 60_000 }).toBe(29);
    for (const call of hanging.calls.slice(24)) call.answer();
    await run;
  }, 180_000);

  it('takes at most 2 transactions at once: the rest wait at the gate, holding no connection', async () => {
    const worlds = [await worldWith(1), await worldWith(1), await worldWith(1), await worldWith(1)];
    const allWorlds = worlds.map(({ w }) => w);
    const { rail, sent } = railOver(allWorlds);
    const releases = await Promise.all(allWorlds.map((w) => headHeld(w)));
    const run = within(30_000, handoffOver(allWorlds, rail, { limits: AT_ONCE }).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 2);
    await settleTicks();

    expect(await lockWaits()).toBe(2);

    for (const release of releases) await release();
    await run;
    expect(sent).toHaveLength(4);
  });

  it('one organisation stuck at its own lock keeps no other from the gate', async () => {
    const stuck = await worldWith(2);
    const other = await worldWith(2);
    const { rail, sent } = railOver([stuck.w, other.w]);
    const release = await headHeld(stuck.w);
    const run = within(30_000, handoffOver([stuck.w, other.w], rail, { limits: AT_ONCE }).run(), 'the run');

    // Its two Tx As, the second behind the first in the gate; the other's Tx As and Tx Bs go through past them.
    await expect
      .poll(async () => (await paymentOf(other.w, other.requests[1] ?? '')).transaction, { timeout: 20_000 })
      .toMatchObject({ status: 'PROCESSING' });
    expect(await lockWaits()).toBe(1);
    expect(sent.filter((org) => org === stuck.w.org)).toEqual([]);

    await release();
    await run;
    expect(sent).toHaveLength(4);
    handedOffNoFailure();
  });

  it('puts Tx B ahead of a new Tx A', async () => {
    const worlds = [];
    for (let at = 0; at < 6; at += 1) worlds.push(await worldWith(1));
    const [first, second, third, fourth, fifth, sixth] = worlds;
    if (!first || !second || !third || !fourth || !fifth || !sixth) throw new Error('no worlds');
    // The third's and fourth's rows held: their Tx As fill the gate, waiting. The fifth's and sixth's held too, and queued
    // behind them. Each gets to its Tx A in the order listed, the first two already at the bank.
    const held = await Promise.all(
      [third, fourth, fifth, sixth].map(({ w, requests }) => rowHeld(w, requests[0] ?? '')),
    );
    const allWorlds = worlds.map(({ w }) => w);
    const hanging = railHanging(allWorlds);
    const run = handoffOver(allWorlds, hanging.rail, { limits: { total: 6, perOrganisation: 1 } }).run();
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(2);
    await waitUntilQueued(database.as('admin'), 2);
    await settleTicks();

    // The first two's answers come, after the fifth and sixth at the gate. Their Tx Bs join the queue.
    hanging.calls[0]?.answer();
    hanging.calls[1]?.answer();
    await settleTicks();
    await held[0]?.();
    await held[1]?.();

    // Ahead: both answers recorded, the fifth and sixth then filling the gate at their own held rows. Behind, those
    // two would fill it first, and the answers would never get in while they are held.
    for (const { w, requests } of [first, second]) {
      await expect
        .poll(async () => (await paymentOf(w, requests[0] ?? '')).transaction, { timeout: 10_000 })
        .toMatchObject({ status: 'PROCESSING' });
    }

    await held[2]?.();
    await held[3]?.();
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(6);
    for (const call of hanging.calls.slice(2)) call.answer();
    await run;
    handedOffNoFailure();
  }, 60_000);

  it('starts no new work past its budget, at real concurrency; the next run goes on', async () => {
    const { w } = await worldWith(6);
    let spent = false;
    const { rail, sent } = railOver([w], (real) => (intent) => {
      if (!spent) clock.advanceBy(1_000);
      spent = true;
      return real(intent);
    });
    const job = handoffOver([w], rail, { limits: { total: 3, perOrganisation: 3 }, runBudgetMs: 1_000 });

    await job.run();
    const firstRun = sent.length;
    expect(firstRun).toBeGreaterThan(0);
    expect(firstRun).toBeLessThan(6);

    await job.run();
    expect(sent).toHaveLength(6);
    expect(new Set(sent).size).toBe(1);
  });

  it('begins no Tx A past its budget while waiting at the gate (L4)', async () => {
    const { w, requests } = await worldWith(3);
    const { rail, sent } = railOver([w]);
    const job = handoffOver([w], rail, { limits: AT_ONCE, runBudgetMs: 1_000 });
    const release = await headHeld(w);
    const run = job.run();
    await waitUntilQueued(database.as('admin'), 1);
    clock.advanceBy(1_000);
    await release();
    await run;
    // The one under way finishes; the rest, at the gate, never began.
    expect(sent).toHaveLength(1);
    expect(await statusOf(w, requests[1] ?? '')).toBe('APPROVED');

    await job.run();
    expect(sent).toHaveLength(3);
  });

  it('starts nothing once stopped while waiting at the gate, and takes up where it left off', async () => {
    const { w, requests } = await worldWith(3);
    const stopping = new AbortController();
    const { rail, sent } = railOver([w]);
    const job = handoffOver([w], rail, { limits: AT_ONCE });
    const release = await headHeld(w);
    const run = job.run(stopping.signal);
    await waitUntilQueued(database.as('admin'), 1);
    stopping.abort();
    await release();
    await run;
    // The one at the head finishes; those at the gate never began.
    expect(sent).toHaveLength(1);
    expect(await statusOf(w, requests[1] ?? '')).toBe('APPROVED');

    await job.run();
    expect(sent).toHaveLength(3);
  });

  it('tells an organisation once, though several of its requests reach the hold at once', async () => {
    const { w } = await worldWith(4);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    const { rail, sent } = railOver([w]);

    await handoffOver([w], rail, { limits: AT_ONCE }).run();

    expect(sent).toEqual([]);
    expect(await heldNotesOf(w)).toHaveLength(1);
  });

  it('ends its turn at the hold: the requests behind the first aren’t walked for the same answer', async () => {
    const { w, requests } = await worldWith(3);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    const { rail } = railOver([w]);

    await handoffOver([w], rail).run();

    expect(lines('handoff.waiting')).toEqual([
      expect.objectContaining({ requestId: requests[0] ?? '', why: 'hold_bank' }),
    ]);
  });

  it('half-open, a request that never reached the bank gives its place back', async () => {
    const { w, acting } = await ready();
    // Three older, to the supplier with no payee yet: each reaches Tx A, and waits. Then one that goes.
    for (let at = 0; at < 3; at += 1) await ask(acting, w, { amount: TINY, supplierId: w.suppliers[1] ?? '' });
    const younger = await ask(acting, w, { amount: TINY });
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    lookupsFor(['anyone']);
    const { rail, sent } = railOver([w]);

    await handoffOver([w], rail).run();

    expect(sent).toHaveLength(1);
    expect(await statusOf(w, younger.id)).toBe('HANDED_OFF');
  });

  it('takes a lane’s own note to speak for the platform’s hold that follows: one note, not two', async () => {
    const { w } = await worldWith(4);
    const { rail } = railOver([w], () => noAnswer);
    const job = handoffOver([w], rail);
    await job.run();
    expect(await heldNotesOf(w)).toHaveLength(1);

    unknownsFrom(['p', 'p', 'q', 'q', 'r']);
    expect(health.heldFor(w.org)).toBe('bank');
    await job.run();

    expect(await heldNotesOf(w)).toHaveLength(1);
  });

  it('counts a rejection with its proof as neutral: it breaks no row', async () => {
    const { w } = await worldWith(4);
    // Two unknown, one rejected with its proof, one unknown: three in a row, the rejection not breaking it.
    let sentSoFar = 0;
    const { rail } = railOver([w], (real) => async (intent) => {
      sentSoFar += 1;
      if (sentSoFar !== 3) return noAnswer(intent);
      const answer = await real(intent);
      return answer.kind === 'accepted'
        ? { ...answer, execution: { ...answer.execution, providerStatus: 'Rejected' as const, noDebitProven: true } }
        : answer;
    });

    await handoffOver([w], rail).run();

    expect(sentSoFar).toBe(4);
    expect(health.heldFor(w.org)).toBe('lane');
  });

  it('goes one at a time past a lane’s hold, until the bank accepts one', async () => {
    const { w } = await worldWith(3);
    unknownsFrom([w.org, w.org, w.org]);
    clock.advanceBy(5 * 60_000);
    lookupsFor([w.org]);
    const hanging = railHanging([w]);
    const job = handoffOver([w], hanging.rail, { limits: AT_ONCE });
    const run = job.run();

    await expect.poll(() => hanging.calls.length).toBe(1);
    await settleTicks();
    expect(hanging.calls).toHaveLength(1);

    // Accepted: clear of it, and the rest go side by side.
    hanging.calls[0]?.answer();
    await expect.poll(() => hanging.calls.length, { timeout: 20_000 }).toBe(3);
    hanging.calls[1]?.answer();
    hanging.calls[2]?.answer();
    await run;
    expect(health.oneAtATime(w.org)).toBe(false);
  });

  describe('first anchors', () => {
    const unanchoredWorlds = async (count: number) => {
      const worlds = [];
      for (let at = 0; at < count; at += 1) worlds.push((await worldWith(1)).w);
      return worlds;
    };

    it('makes them 2 at a time, holding no bank slot: an organisation with one goes meanwhile', async () => {
      const unanchored = await unanchoredWorlds(3);
      const anchored = await worldWith(1);
      const anchors = createMemoryAnchorStore();
      const owner = await tamperAsOwner(database, SPEND_REQUESTS, anchored.w.org);
      try {
        const head = await owner.saveHead();
        const chainOf = { kind: 'organisation', orgId: anchored.w.org } as const;
        anchors.keep(signAnchor(keys, chainOf, { seq: BigInt(head.seq), hash: head.hash }, clock.now()));
      } finally {
        await owner.end();
      }
      const release: (() => void)[] = [];
      const anchorFirst = () => new Promise<void>((resolve) => release.push(resolve));
      const allWorlds = [...unanchored, anchored.w];
      const { rail, sent } = railOver(allWorlds);

      const run = handoffOver(allWorlds, rail, {
        limits: { total: 2, perOrganisation: 2 },
        anchoring: { anchors, anchorFirst },
      }).run();
      await expect.poll(() => sent).toEqual([anchored.w.org]);
      expect(release).toHaveLength(2);

      release.shift()?.();
      await expect.poll(() => release.length).toBe(2);
      for (const next of [...release]) next();
      await run;
      // None was made: each waits, uncompared never, and nothing was sent for it.
      expect(sent).toEqual([anchored.w.org]);
      expect(lines('handoff.waiting').map(({ why }) => why)).toEqual([
        'anchor_pending',
        'anchor_pending',
        'anchor_pending',
      ]);
    });

    it('begins none once stopped, though queued for the gate', async () => {
      const worlds = await unanchoredWorlds(3);
      const stopping = new AbortController();
      const release: (() => void)[] = [];
      let begun = 0;
      const anchorFirst = () => {
        begun += 1;
        return new Promise<void>((resolve) => release.push(resolve));
      };
      const { rail } = railOver(worlds);

      const run = handoffOver(worlds, rail, {
        limits: AT_ONCE,
        anchoring: { anchors: createMemoryAnchorStore(), anchorFirst },
      }).run(stopping.signal);
      await expect.poll(() => begun, { timeout: 20_000 }).toBe(2);

      stopping.abort();
      for (const next of release) next();
      await within(5_000, run, 'the run');
      expect(begun).toBe(2);
    });

    it('begins none past the run’s budget, though queued for the gate', async () => {
      const worlds = await unanchoredWorlds(3);
      const release: (() => void)[] = [];
      let begun = 0;
      const anchorFirst = () => {
        begun += 1;
        return new Promise<void>((resolve) => release.push(resolve));
      };
      const { rail } = railOver(worlds);

      const run = handoffOver(worlds, rail, {
        limits: AT_ONCE,
        runBudgetMs: 1_000,
        anchoring: { anchors: createMemoryAnchorStore(), anchorFirst },
      }).run();
      await expect.poll(() => begun, { timeout: 20_000 }).toBe(2);

      clock.advanceBy(1_000);
      for (const next of release) next();
      await run;
      expect(begun).toBe(2);
    });

    it('beats for each, so /health doesn’t read a long run of them as stopped', async () => {
      const worlds = await unanchoredWorlds(4);
      const beats: boolean[] = [];
      const job = handoffOver(worlds, railOver(worlds).rail, {
        limits: AT_ONCE,
        runBudgetMs: 24 * 60 * 60_000,
        anchoring: {
          anchors: createMemoryAnchorStore(),
          anchorFirst: () => {
            beats.push(job.beating());
            clock.advanceBy(HEARTBEAT_STALE_MS - 1);
            return Promise.resolve();
          },
        },
      });

      await job.run();

      expect(beats).toEqual([true, true, true, true]);
    });
  });

  it('refuses to start with a gate over a third of the pool', () => {
    const job = (poolMax: number) => () =>
      createHandoff({
        list: () => Promise.resolve([]),
        database: app,
        outbox: createOutbox({ ids, clock }),
        rail: {} as FakeRail,
        health,
        keys,
        ids,
        clock,
        logger: testLogger(capture),
        poolMax,
      });

    expect(job(5)).toThrow(RangeError);
    expect(job(6)).not.toThrow();
  });
});

describe('the model at concurrency: random batches, each sent once', () => {
  const OUTCOMES = [
    { fils: 0n, status: 'PROCESSING' },
    { fils: 1n, status: 'FAILED' },
    { fils: 2n, status: 'UNKNOWN' },
    { fils: 3n, status: 'UNKNOWN' },
    { fils: 4n, status: 'PROCESSING' },
  ] as const;
  /** Pinned, so a failure replays; said, so it can be read from the log. */
  const SEED = 20_261_102;

  it('makes one instruction and one transaction each, however they interleave, whatever the bank answers', async () => {
    // eslint-disable-next-line no-restricted-properties -- a test's note for whoever replays it, holding nothing of anyone's
    process.stdout.write(`the model's seed: ${String(SEED)}\n`);
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.constantFrom(...OUTCOMES), { minLength: 2, maxLength: 8 }),
        fc.integer({ min: 2, max: 6 }),
        async (batch, limit) => {
          capture = new LogCapture();
          const { w, acting } = await ready();
          const asked = [];
          for (const outcome of batch) {
            asked.push({ outcome, request: await ask(acting, w, { amount: AED(5_000n + outcome.fils) }) });
          }
          const instructions: string[] = [];
          const { rail } = railOver([w], (real) => (intent) => {
            instructions.push(intent.instructionId);
            return real(intent);
          });
          const job = handoffOver([w], rail, {
            limits: { total: limit, perOrganisation: limit },
            health: createRailHealth({ clock, logger: testLogger(capture), laneUnknowns: 1_000 }),
          });

          await job.run();
          await job.run();

          expect(new Set(instructions).size).toBe(batch.length);
          expect(instructions).toHaveLength(batch.length);
          for (const { outcome, request } of asked) {
            expect(await paymentOf(w, request.id)).toMatchObject({
              transactions: 1,
              transaction: { status: outcome.status },
            });
          }
          handedOffNoFailure();
        },
      ),
      { numRuns: 4, seed: SEED, endOnFailure: true },
    );
  }, 180_000);
});

describe('a lane held: 3 unknowns in a row from one organisation', () => {
  it('sends no more; a hung organisation sends nothing past its hold; a lookup lets one; an acceptance clears it', async () => {
    const { w, requests } = await worldWith(5);
    let bankAway = true;
    const { rail, sent } = railOver([w], (real) => (intent) => (bankAway ? noAnswer(intent) : real(intent)));
    const job = handoffOver([w], rail);

    await job.run();
    expect(sent).toHaveLength(3);
    expect(await statusOf(w, requests[3] ?? '')).toBe('APPROVED');
    expect(lines('handoff.lane_held')).toHaveLength(1);

    // Still held: nothing sent, however many runs. Past its hold, no lookup having answered: still nothing.
    await job.run();
    clock.advanceBy(60 * 60_000);
    await job.run();
    expect(sent).toHaveLength(3);

    // A lookup answers: one goes, unanswered, and holds it again, for longer.
    await lookedFor(w, rail);
    await job.run();
    expect(sent).toHaveLength(4);
    expect(lines('handoff.lane_held').map(({ holdMinutes }) => holdMinutes)).toEqual([5, 10]);

    // Past it again, the bank back: the last goes, and it is clear.
    bankAway = false;
    clock.advanceBy(10 * 60_000);
    await lookedFor(w, rail);
    await job.run();
    expect(sent).toHaveLength(5);
    expect(await statusOf(w, requests[4] ?? '')).toBe('HANDED_OFF');
    expect(health.heldFor(w.org)).toBeUndefined();
    expect(health.oneAtATime(w.org)).toBe(false);
  });

  it('holds no other organisation', async () => {
    const held = await worldWith(4);
    const other = await worldWith(1);
    const { rail, sent } = railOver(
      [held.w, other.w],
      (real) => (intent) => (intent.organizationId === held.w.org ? noAnswer(intent) : real(intent)),
    );

    await handoffOver([held.w, other.w], rail).run();

    expect(sent.filter((org) => org === held.w.org)).toHaveLength(3);
    expect(await statusOf(other.w, other.requests[0] ?? '')).toBe('HANDED_OFF');
  });

  it('never counts as left standing the requests a held organisation leaves behind', async () => {
    const { w } = await worldWith(5);
    const { rail } = railOver([w], () => noAnswer);
    const job = handoffOver([w], rail);

    await job.run();
    clock.advanceBy(QUEUE_STALE_MS + 60_000);
    await job.run();

    expect(lines('handoff.queue_stale')).toEqual([]);
    expect(lines('handoff.queue_unread')).toEqual([]);
  });

  it('says a hold outlasting the queue’s age, an error, once a payment really waits on it; a blip nothing', async () => {
    const { w } = await worldWith(4);
    const { rail } = railOver([w], () => noAnswer);
    const job = handoffOver([w], rail);

    await job.run();
    clock.advanceBy(QUEUE_STALE_MS - 1);
    await job.run();
    expect(lines('handoff.hold_lasting')).toEqual([]);

    clock.advanceBy(1);
    await job.run();
    expect(lines('handoff.hold_lasting')).toEqual([expect.objectContaining({ level: 'error', hold: 'lane' })]);
  });
});

describe('an answer that is no acceptance (H3)', () => {
  const fourAnsweredAs = async (change: (execution: PaymentExecution) => PaymentExecution) => {
    const { w } = await worldWith(4);
    const { rail, sent } = railOver([w], (real) => async (intent) => {
      const answer = await real(intent);
      return answer.kind === 'accepted' ? { ...answer, execution: change(answer.execution) } : answer;
    });
    await handoffOver([w], rail).run();
    return { w, sent };
  };

  it.each([
    ['about another payment', (execution: PaymentExecution) => ({ ...execution, instructionId: 'another' })],
    ['for another amount', (execution: PaymentExecution) => ({ ...execution, amountMinor: 1n })],
    ['in another currency', (execution: PaymentExecution) => ({ ...execution, currency: 'USD' })],
    ['of another organisation', (execution: PaymentExecution) => ({ ...execution, organizationId: 'another' })],
    [
      'Rejected with no proof the money stayed',
      (execution: PaymentExecution) => ({ ...execution, providerStatus: 'Rejected' as const, noDebitProven: false }),
    ],
  ])('counts an accepted answer %s as an unknown: 3 hold the lane', async (_name, change) => {
    const { w, sent } = await fourAnsweredAs(change);

    expect(sent).toHaveLength(3);
    expect(health.heldFor(w.org)).toBe('lane');
  });

  it('counts a rejection with its proof, and a refusal, as neither: no unknown, nothing cleared', async () => {
    const proven = await fourAnsweredAs((execution) => ({
      ...execution,
      providerStatus: 'Rejected' as const,
      noDebitProven: true,
    }));
    expect(proven.sent).toHaveLength(4);
    expect(lines('handoff.lane_held')).toEqual([]);

    // Two unknowns, then a refusal (.01), then one more: three in a row, the refusal not breaking it.
    const { w, acting } = await ready();
    for (const fils of [2n, 2n, 1n, 2n, 0n]) await ask(acting, w, { amount: AED(5_000n + fils) });
    const { rail, sent } = railOver([w]);
    await handoffOver([w], rail).run();
    expect(sent).toHaveLength(4);
    expect(health.heldFor(w.org)).toBe('lane');
  });
});

describe('the bank held: 5 unknowns from at least 3 organisations in 60 s', () => {
  /** Three worlds, `each` requests approved in each. */
  const threeWorlds = async (each: number) => {
    const worlds = [await worldWith(each), await worldWith(each), await worldWith(each)];
    return { worlds: worlds.map(({ w }) => w), requests: worlds.flatMap(({ requests }) => requests) };
  };

  it('sends nothing while held, however long, until a lookup answers', async () => {
    const { worlds } = await threeWorlds(3);
    let bankAway = true;
    const { rail, sent } = railOver(worlds, (real) => (intent) => (bankAway ? noAnswer(intent) : real(intent)));
    const job = handoffOver(worlds, rail);

    await job.run();
    expect(lines('handoff.bank_held')).toEqual([expect.objectContaining({ level: 'error' })]);
    const sentByTheHold = sent.length;
    const unsent = worlds.length * 3 - sentByTheHold;
    expect(unsent).toBeGreaterThan(0);

    // The bank is back, but nothing has asked it: a day of runs sends nothing to find out, time never reopens it.
    bankAway = false;
    for (const hours of [1, 24]) {
      clock.advanceBy(hours * 60 * 60_000);
      await job.run();
    }
    expect(sent).toHaveLength(sentByTheHold);
    expect(health.heldFor(worlds[0]?.org ?? '')).toBe('bank');

    // A lookup answers, "not found" at that, for each: half-open, a real acceptance reopens it, and what waited goes.
    for (const w of worlds) expect((await lookedFor(w, rail)).kind).toBe('not_found');
    expect(lines('handoff.bank_half_open')).toHaveLength(1);
    await job.run();
    expect(lines('handoff.bank_step').length).toBeGreaterThan(0);
    expect(sent).toHaveLength(worlds.length * 3);
  });

  it('half-open, one unknown trips it again: nothing more sent, no new error, no second note', async () => {
    const { worlds } = await threeWorlds(4);
    const { rail, sent } = railOver(worlds, () => noAnswer);
    const job = handoffOver(worlds, rail);

    await job.run();
    const sentByTheHold = sent.length;
    for (const w of worlds) await lookedFor(w, rail);
    clock.advanceBy(60 * 60_000);
    for (const w of worlds) await lookedFor(w, rail);
    await job.run();

    // The third organisation's lane still clear of its own row: one goes, unanswered, tripping it again.
    expect(sent).toHaveLength(sentByTheHold + 1);
    expect(lines('handoff.bank_held')).toHaveLength(1);
    expect(lines('handoff.bank_held_again')).toHaveLength(1);
    await job.run();
    expect(sent).toHaveLength(sentByTheHold + 1);
    for (const w of worlds) expect(await heldNotesOf(w)).toHaveLength(1);
  });

  it('tells each organisation with payments waiting once, signed, in its audit log, however many runs', async () => {
    const { worlds } = await threeWorlds(4);
    const { rail } = railOver(worlds, () => noAnswer);
    const job = handoffOver(worlds, rail);

    await job.run();
    await job.run();
    await job.run();

    for (const w of worlds) {
      expect(await heldNotesOf(w)).toEqual([
        expect.objectContaining({ actor_type: 'system', subject_type: 'handoff_hold' }),
      ]);
    }
  });

  it('tells it again in a later hold, once one of its own payments was accepted between', async () => {
    const { w } = await worldWith(8);
    // Three unanswered, one accepted, three unanswered: two outages, one still waiting to be held.
    let sentSoFar = 0;
    const { rail } = railOver([w], (real) => (intent) => {
      sentSoFar += 1;
      return sentSoFar === 4 ? real(intent) : noAnswer(intent);
    });
    const job = handoffOver([w], rail);

    await job.run();
    await job.run();
    expect(await heldNotesOf(w)).toHaveLength(1);

    clock.advanceBy(5 * 60_000);
    await lookedFor(w, rail);
    await job.run();
    await job.run();
    expect(sentSoFar).toBe(7);
    expect(await heldNotesOf(w)).toHaveLength(2);
  });

  it('tells it again for a new platform outage, though none of its own was accepted between', async () => {
    const { w, requests } = await worldWith(3);
    const job = handoffOver([w], railOver([w]).rail);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    await job.run();
    expect(await heldNotesOf(w)).toHaveLength(1);

    // Others' acceptances reopen it, all the way; 15 healthy minutes on, a fresh trip is a new outage.
    health.lookupBegun('p')();
    for (const calls of [3, 6, 12, 24]) {
      const places = Array.from({ length: calls }, (_, at) => health.enter(`others-${String(calls)}-${String(at)}`));
      for (const place of places) if ('settle' in place) place.settle('accepted');
    }
    clock.advanceBy(15 * 60_000);
    unknownsFrom(['q', 'r', 's', 't', 'u']);
    await job.run();

    expect(await heldNotesOf(w)).toHaveLength(2);
    expect(await statusOf(w, requests[0] ?? '')).toBe('APPROVED');
  });

  it('tells it of a lane hold of its own, though told of the bank in this same outage', async () => {
    const { w } = await worldWith(1);
    const job = handoffOver([w], railOver([w]).rail);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    await job.run();
    expect(await heldNotesOf(w)).toHaveLength(1);

    // Half-open, its own three unanswered: a hold of its lane, though the outage is the same.
    health.lookupBegun('anyone')();
    const own = [health.enter(w.org), health.enter(w.org), health.enter(w.org)];
    for (const place of own) if ('settle' in place) place.settle('unknown');
    clock.advanceBy(60 * 60_000);
    health.lookupBegun('anyone')();
    await job.run();

    const notes = await heldNotesOf(w);
    expect(notes).toHaveLength(2);
    expect(notes.map(({ details }) => JSON.parse(details) as unknown)).toEqual([
      expect.objectContaining({ hold: 'bank' }),
      expect.objectContaining({ hold: 'lane' }),
    ]);
  });

  it('counts an answer too malformed to read as unknown, its place given back, nothing sent again', async () => {
    const { w, requests } = await worldWith(1);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    health.lookupBegun('anyone')();
    const { rail, sent } = railOver(
      [w],
      () => () => Promise.resolve({ kind: 'accepted', execution: null } as unknown as Awaited<ReturnType<Submit>>),
    );

    await handoffOver([w], rail).run();

    expect(sent).toHaveLength(1);
    // Unknown in half-open: back to held, no place left stuck.
    expect(lines('handoff.bank_held_again')).toHaveLength(1);
    expect(lines('handoff.answer_unrecorded')).toHaveLength(1);
    expect(await paymentOf(w, requests[0] ?? '')).toMatchObject({ transaction: { status: 'SUBMISSION_PENDING' } });
  });

  it('says the note it couldn’t write, the payment held all the same, and writes it next run', async () => {
    const { w, requests } = await worldWith(1);
    unknownsFrom(['x', 'x', 'y', 'y', 'z']);
    expect(health.heldFor(w.org)).toBe('bank');
    // A run's transactions: the pause (1), the page (2), the note (3), which fails the first time alone.
    let opened = 0;
    const failing = new Proxy(app, {
      get(target, name, receiver) {
        const value: unknown = Reflect.get(target, name, receiver);
        if (typeof value !== 'function') return value;
        if (name !== 'transaction') return (value as (...args: unknown[]) => unknown).bind(target);
        return () => {
          opened += 1;
          if (opened === 3) throw new Error('the database is away');
          return (value as () => unknown).call(target);
        };
      },
    });
    const { rail, sent } = railOver([w]);
    const job = handoffOver([w], rail, { database: failing });

    await job.run();
    expect(lines('handoff.held_unrecorded')).toHaveLength(1);
    expect(await heldNotesOf(w)).toEqual([]);
    expect(await statusOf(w, requests[0] ?? '')).toBe('APPROVED');
    expect(sent).toEqual([]);

    await job.run();
    expect(await heldNotesOf(w)).toHaveLength(1);
    expect(sent).toEqual([]);
  });
});
