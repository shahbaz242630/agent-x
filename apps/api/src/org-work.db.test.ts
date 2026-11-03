// The marks (0072, 4D2e D6) on the real tables, as the app role, through the real
// hand-off: where each mark comes from, that it fires inside COMMIT after every lock
// the signed writes take, on no trip of its own, and the hourly look holding them to
// what the rows say. How a deferred trigger behaves in itself is
// packages/core/src/modules/directory/infrastructure/org-work.db.test.ts's.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import type { FakeRail } from '@agentx/core/modules/providers';
import { markOrgWork } from '@agentx/core/modules/directory';
import { SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import { noteTransactionFacts } from '@agentx/core/modules/transactions';
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
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, type World } from './mandate-world.helper.test.ts';
import { createOrgWorkRediscovery } from './org-work.ts';
import { createRailHealth } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xd6a0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xd6b0_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'org_work',
  registry: () => registry,
  decisions: () => decisions,
});
const { quiet, ask, statusOf } = shared;
const { ready } = handoffWorld({ app: () => app, clock: () => clock, ids, registry: () => registry, shared });

const admin = () => database.as('admin');

const handoffOf = (w: World, rail: FakeRail = w.rail) =>
  createHandoff({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
    health: createRailHealth({ clock, logger: testLogger(capture) }),
    databaseGate: handoffDatabaseGate(6),
  });

const rediscoveryOf = (...orgs: readonly string[]) =>
  createOrgWorkRediscovery({ list: () => Promise.resolve(orgs), database: app, logger: testLogger(capture) });

async function marksOf(w: World): Promise<Record<string, { due_at: Date; marks: string }>> {
  const rows = await admin().query<{ job: string; due_at: Date; marks: string }>(
    'select job, due_at, marks from directory.org_work where org_id = $1',
    [w.org],
  );
  return Object.fromEntries(rows.map(({ job, ...rest }) => [job, rest]));
}

/** The server's time now: the marks' times are its clock's, which may run a few ms off this process's. */
const serverNow = async () =>
  (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0]?.now.getTime() ?? 0;

const jobsMarked = async (w: World) => Object.keys(await marksOf(w)).toSorted();
const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const JOBS = ['hand_off', 'hand_off_sweep', 'payment_check'];

/** The request's transaction's ID and status, read past its signed state. */
async function transactionOfRequest(requestId: string) {
  const [row] = await admin().query<{ id: string; status: string; created_at: Date }>(
    `select t.id, t.status, t.created_at from transactions.transactions t
     join instructions.instructions i on i.org_id = t.org_id and i.id = t.instruction_id
     where i.spend_request_id = $1`,
    [requestId],
  );
  if (row === undefined) throw new Error('no transaction');
  return row;
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  // Born paused (ADR-014 §4): resumed for these tests, as the operator would.
  await app
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: false, reason: 'TEST-D6', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
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

describe('where each mark comes from', () => {
  it('a request approved marks the hand-off, and one waiting for approval marks nothing', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    expect(waiting.status).toBe('APPROVAL_REQUIRED');
    expect(await jobsMarked(w)).toEqual([]);

    const started = (await admin().query<{ now: Date }>('select pg_catalog.now() as now'))[0]?.now.getTime() ?? 0;
    const approved = await ask(acting, w, { amount: ALLOWED(), supplierId: w.suppliers[1] ?? '' });
    expect(approved.status).toBe('APPROVED');
    const marks = await marksOf(w);
    expect(Object.keys(marks)).toEqual(['hand_off']);
    // Due at once, from its transaction's start.
    expect(marks.hand_off?.due_at.getTime()).toBeGreaterThanOrEqual(started);
    expect(marks.hand_off?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
  });

  it("a request's hand-off marks its sweep and its checks, the sweep's ten minutes on, as UNKNOWN_AFTER_MS", async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    const marks = await marksOf(w);
    expect(Object.keys(marks).toSorted()).toEqual(JOBS);
    const { created_at: created } = await transactionOfRequest(request.id);
    // The trigger's wait from its transaction's start, the job's from the row's time: within that transaction.
    const apart = (marks.hand_off_sweep?.due_at.getTime() ?? 0) - (created.getTime() + 10 * 60_000);
    expect(Math.abs(apart)).toBeLessThan(30_000);
  });

  it('a payment UNKNOWN still marks its checks, not its sweep: a write on it marks the checks alone', async () => {
    const { w, acting } = await ready();
    // `.02`: the answer lost, so the hand-off's Tx B leaves it UNKNOWN.
    const request = await ask(acting, w, { amount: ALLOWED(2n) });
    await handoffOf(w).run();
    const { id, status } = await transactionOfRequest(request.id);
    expect(status).toBe('UNKNOWN');
    await admin().query('delete from directory.org_work where org_id = $1', [w.org]);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      noteTransactionFacts(
        tx,
        states,
        { orgId: w.org, id },
        { providerStatus: 'NotedForTheTest', paymentInstructionRef: null, rejectCode: null, providerChangedAt: null },
        { actor: { type: 'system', id: 'api' }, details: {} },
      ),
    );
    expect((await transactionOfRequest(request.id)).status).toBe('UNKNOWN');
    expect(await jobsMarked(w)).toEqual(['payment_check']);
  });

  it('a payment finished makes no mark of its own: nothing but what is due is marked', async () => {
    const { w, acting } = await ready();
    // `.01`: the fake declines it, with its proof, so the hand-off's Tx B settles it FAILED.
    const request = await ask(acting, w, { amount: ALLOWED(1n) });
    // Read between the two transactions: the partner has answered, and Tx B can't start until this returns.
    let beforeTxB: Awaited<ReturnType<typeof marksOf>> = {};
    let statusBeforeTxB = '';
    await handoffOf(w, {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        const answer = await w.rail.submitApprovedIntent(intent);
        beforeTxB = await marksOf(w);
        statusBeforeTxB = (await transactionOfRequest(request.id)).status;
        return answer;
      },
    }).run();
    expect(statusBeforeTxB).toBe('SUBMISSION_PENDING');
    expect((await transactionOfRequest(request.id)).status).toBe('FAILED');
    // Tx B made no mark and brought none forward: the same jobs, the same due times. Its counts moved by its note of
    // the bank's refusal alone, written while the payment was still under way (a note is 2 row writes, each marking,
    // as every write on a payment under way does); its move to FAILED marked nothing.
    expect(Object.keys(beforeTxB).toSorted()).toEqual(JOBS);
    const before = await marksOf(w);
    const moved = (job: string) => BigInt(before[job]?.marks ?? '0') - BigInt(beforeTxB[job]?.marks ?? '0');
    expect(JOBS.map((job) => [job, before[job]?.due_at, moved(job)])).toEqual([
      ['hand_off', beforeTxB.hand_off?.due_at, 0n],
      ['hand_off_sweep', beforeTxB.hand_off_sweep?.due_at, 2n],
      ['payment_check', beforeTxB.payment_check?.due_at, 2n],
    ]);
    await rediscoveryOf(w.org).run();
    expect(await jobsMarked(w)).toEqual([]);
    expect(Object.keys(before).toSorted()).toEqual(JOBS);
  });
});

describe('a mark in COMMIT, against the signed writes', () => {
  it('fires inside COMMIT with every lock of Tx A held, and the hand-off goes on once it can', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const holder = await database.connect('admin');
    try {
      await holder.query('begin');
      await holder.query(`select 1 from directory.org_work where org_id = $1 and job = 'hand_off' for update`, [w.org]);
      const running = handoffOf(w).run();
      const [blocked] = await waitUntilQueued(admin(), 1);
      // It is the commit that waits, the read-back before it in the same text.
      const [activity] = await admin().query<{ query: string }>(
        'select query from pg_catalog.pg_stat_activity where pid = $1',
        [blocked],
      );
      expect(activity?.query).toMatch(/; commit$/u);
      // And it holds the chain's head and the request: the last of ADR-006's locks, and the row before it.
      await expect(
        admin().query('select 1 from audit.heads where org_id = $1 for no key update nowait', [w.org]),
      ).rejects.toMatchObject({ code: '55P03' });
      await expect(
        admin().query('select 1 from spend_requests.requests where id = $1 for no key update nowait', [request.id]),
      ).rejects.toMatchObject({ code: '55P03' });
      await holder.query('commit');
      await running;
      expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    } finally {
      await holder.end();
    }
  });

  it('adds no trip: a hand-off takes the same trips with the triggers and without', async () => {
    const trips = async () => {
      const { w, acting } = await ready();
      await ask(acting, w, { amount: ALLOWED() });
      const times = noStatementTimes();
      await timingStatements(times, () => handoffOf(w).run());
      return times.trips;
    };
    const withThem = await trips();
    const owner = database.as('owner');
    await owner.query('alter table spend_requests.requests disable trigger marks_hand_off');
    await owner.query('alter table transactions.transactions disable trigger marks_hand_off_sweep');
    await owner.query('alter table transactions.transactions disable trigger marks_payment_check');
    try {
      expect(await trips()).toBe(withThem);
    } finally {
      await owner.query('alter table spend_requests.requests enable trigger marks_hand_off');
      await owner.query('alter table transactions.transactions enable trigger marks_hand_off_sweep');
      await owner.query('alter table transactions.transactions enable trigger marks_payment_check');
    }
  });

  it('two signed writes marking two jobs in opposite order: the second waits at the head, and both keep', async () => {
    const { w, acting } = await ready();
    // The fils choose it stays under way, so each transaction can still be noted.
    const first = await ask(acting, w, { amount: SMALL() });
    const second = await ask(acting, w, { amount: SMALL(5n) });
    await handoffOf(w).run();
    const third = await ask(acting, w, { amount: SMALL(6n) });
    const fourth = await ask(acting, w, { amount: SMALL(7n) });
    const [one, two] = [await transactionOfRequest(first.id), await transactionOfRequest(second.id)];
    const before = await marksOf(w);
    const facts = {
      providerStatus: 'NotedForTheTest',
      paymentInstructionRef: null,
      rejectCode: null,
      providerChangedAt: null,
    };
    const change = { actor: { type: 'system', id: 'api' }, details: {} } as const;
    const made = (key: { readonly orgId: string; readonly id: string }) => ({
      actor: change.actor,
      action: 'spend_request.made_ready',
      details: {},
      key,
    });
    let letGo = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      letGo = resolve;
    });
    let sayNoted = (): void => undefined;
    const noted = new Promise<void>((resolve) => {
      sayNoted = resolve;
    });

    // Payment check, then hand-off.
    const paymentFirst = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await noteTransactionFacts(tx, states, { orgId: w.org, id: one.id }, facts, change);
      sayNoted();
      await held;
      const key = { orgId: w.org, id: third.id };
      const { actor, action, details } = made(key);
      await states.changeStatus(tx, SPEND_REQUESTS, key, 'make_ready', { actor, action, details });
    });
    // Hand-off, then payment check: it reaches the head behind the one above.
    await Promise.race([noted, paymentFirst]);
    const handOffFirst = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const key = { orgId: w.org, id: fourth.id };
      const { actor, action, details } = made(key);
      await states.changeStatus(tx, SPEND_REQUESTS, key, 'make_ready', { actor, action, details });
      await noteTransactionFacts(tx, states, { orgId: w.org, id: two.id }, facts, change);
    });
    await waitUntilQueued(admin(), 1);
    letGo();
    await Promise.all([paymentFirst, handOffFirst]);
    const after = await marksOf(w);
    // At least one a write: a signed write is several row updates (measured: 2 for a note, 3 for a move), each queuing one.
    expect(BigInt(after.hand_off?.marks ?? '0') - BigInt(before.hand_off?.marks ?? '0')).toBeGreaterThanOrEqual(2n);
    expect(
      BigInt(after.payment_check?.marks ?? '0') - BigInt(before.payment_check?.marks ?? '0'),
    ).toBeGreaterThanOrEqual(2n);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });
});

describe('the hourly look', () => {
  it('with marks and rows agreeing writes nothing, on one trip of reads between its start and commit', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    const before = await marksOf(w);
    const times = noStatementTimes();
    await timingStatements(times, () => rediscoveryOf(w.org).run());
    expect(times.trips).toBe(3);
    expect(await marksOf(w)).toEqual(before);
    expect(lines('org_work.unmarked')).toEqual([]);
    expect(lines('org_work.rediscovered')).toEqual([
      expect.objectContaining({ organisations: 1, unmarked: 0, late: 0, cleared: 0, failed: 0 }),
    ]);
  });

  it('a mark lost is written and said, once; the next look finds nothing', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await admin().query('delete from directory.org_work where org_id = $1', [w.org]);

    await rediscoveryOf(w.org).run();

    expect(await jobsMarked(w)).toEqual(['hand_off']);
    expect(lines('org_work.unmarked')).toEqual([
      expect.objectContaining({ orgId: w.org, job: 'hand_off', late: false }),
    ]);
    expect(lines('org_work.rediscovered')).toEqual([expect.objectContaining({ unmarked: 1 })]);

    capture = new LogCapture();
    await rediscoveryOf(w.org).run();
    expect(lines('org_work.unmarked')).toEqual([]);
  });

  it("the sweep's mark lost is written for when the row's wait ends, its checks' for now", async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    // Looks while the partner is being called: Tx A committed, its transaction still waiting for the answer.
    const rail: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        await admin().query('delete from directory.org_work where org_id = $1', [w.org]);
        await rediscoveryOf(w.org).run();
        return w.rail.submitApprovedIntent(intent);
      },
    };
    let seen: Awaited<ReturnType<typeof marksOf>> = {};
    let created = new Date(0);
    await handoffOf(w, {
      ...rail,
      submitApprovedIntent: async (intent) => {
        const answer = await rail.submitApprovedIntent(intent);
        seen = await marksOf(w);
        created = (await transactionOfRequest(request.id)).created_at;
        return answer;
      },
    }).run();

    expect(seen.hand_off_sweep?.due_at).toEqual(new Date(created.getTime() + 10 * 60_000));
    expect(seen.payment_check?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
    expect(lines('org_work.unmarked').map(({ job }) => job as string)).toEqual(['hand_off_sweep', 'payment_check']);
  });

  describe('a commit landing between its reads, forced', () => {
    // The look reads the marks, then the requests, then the transactions, then the marks again: each its own statement
    // on one trip. A session holding the requests' table stops it after its first read of the marks, until let go.
    async function lookHeldAfterTheFirstRead(w: World) {
      const holder = await database.connect('owner');
      await holder.query('begin');
      await holder.query('lock table spend_requests.requests in access exclusive mode');
      const looking = rediscoveryOf(w.org).run();
      await waitUntilQueued(admin(), 1);
      return {
        letGo: async () => {
          await holder.query('commit');
          await looking;
          await holder.end();
        },
      };
    }

    it('a payment written meanwhile is read due with its mark in the later read: no miss is said', async () => {
      const { w, acting } = await ready();
      // The fils choose it stays under way, so it can still be noted.
      const request = await ask(acting, w, { amount: SMALL() });
      await handoffOf(w).run();
      const { id } = await transactionOfRequest(request.id);
      await admin().query('delete from directory.org_work where org_id = $1', [w.org]);
      const look = await lookHeldAfterTheFirstRead(w);
      // Its row and mark commit together, after the look read no mark and before it reads what is due.
      await withSignedStates(app, w.org, quiet(), (tx, states) =>
        noteTransactionFacts(
          tx,
          states,
          { orgId: w.org, id },
          { providerStatus: 'NotedForTheTest', paymentInstructionRef: null, rejectCode: null, providerChangedAt: null },
          { actor: { type: 'system', id: 'api' }, details: {} },
        ),
      );
      const marked = await marksOf(w);
      expect(Object.keys(marked)).toContain('payment_check');
      await look.letGo();
      // The earlier read had none; the later one has it, so the look reads no miss, and writes nothing.
      expect(lines('org_work.unmarked')).toEqual([]);
      expect(lines('org_work.rediscovered')).toEqual([
        expect.objectContaining({ organisations: 1, unmarked: 0, late: 0, cleared: 0, failed: 0 }),
      ]);
      expect(await marksOf(w)).toEqual(marked);
    });

    it('a mark made meanwhile on work the look read as done is not cleared; the next look clears it', async () => {
      const { w } = await ready();
      await admin().query(`insert into directory.org_work (org_id, job, due_at) values ($1, 'payment_check', now())`, [
        w.org,
      ]);
      const look = await lookHeldAfterTheFirstRead(w);
      // After the look read the mark, and before its reads find nothing due: the mark moves.
      await markOrgWork(app, w.org, 'payment_check', clock.now());
      const marked = await marksOf(w);
      await look.letGo();
      expect(await marksOf(w)).toEqual(marked);
      expect(lines('org_work.rediscovered')).toEqual([expect.objectContaining({ cleared: 0, failed: 0 })]);

      await rediscoveryOf(w.org).run();
      expect(await jobsMarked(w)).toEqual([]);
      expect(lines('org_work.rediscovered').at(-1)).toEqual(expect.objectContaining({ cleared: 1 }));
    });
  });

  it('a mark saying too late is brought forward and said; one a moment off is left', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await admin().query(`update directory.org_work set due_at = now() + interval '50 seconds' where org_id = $1`, [
      w.org,
    ]);
    const near = await marksOf(w);
    await rediscoveryOf(w.org).run();
    expect(await marksOf(w)).toEqual(near);
    expect(lines('org_work.unmarked')).toEqual([]);

    await admin().query(`update directory.org_work set due_at = 'tomorrow' where org_id = $1`, [w.org]);
    await rediscoveryOf(w.org).run();
    expect((await marksOf(w)).hand_off?.due_at.getTime()).toBeLessThanOrEqual(await serverNow());
    expect(lines('org_work.unmarked')).toEqual([expect.objectContaining({ job: 'hand_off', late: true })]);
    expect(lines('org_work.rediscovered').at(-1)).toEqual(expect.objectContaining({ late: 1 }));
  });

  it('a mark with nothing due goes, without a word: finished work, or one forged', async () => {
    const { w } = await ready();
    await admin().query(`insert into directory.org_work (org_id, job, due_at) values ($1, 'payment_check', now())`, [
      w.org,
    ]);
    await rediscoveryOf(w.org).run();
    expect(await jobsMarked(w)).toEqual([]);
    expect(lines('org_work.unmarked')).toEqual([]);
    expect(lines('org_work.rediscovered')).toEqual([expect.objectContaining({ cleared: 1 })]);
  });

  it('an organisation it cannot read is said, and the rest are still looked at', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await admin().query('delete from directory.org_work where org_id = $1', [w.org]);
    await rediscoveryOf('not-a-uuid', w.org).run();
    expect(await jobsMarked(w)).toEqual(['hand_off']);
    expect(lines('org_work.rediscovery_failed')).toEqual([expect.objectContaining({ orgId: 'not-a-uuid' })]);
    expect(lines('org_work.rediscovered')).toEqual([expect.objectContaining({ organisations: 2, failed: 1 })]);
  });

  it('a list it cannot read is said, and that run ends', async () => {
    const job = createOrgWorkRediscovery({
      list: () => Promise.reject(new Error('no list')),
      database: app,
      logger: testLogger(capture),
    });
    await job.run();
    expect(lines('org_work.rediscovery_failed')).toHaveLength(1);
    expect(lines('org_work.rediscovered')).toEqual([]);
  });

  it('stops between organisations when told, saying nothing of a run it did not finish', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await admin().query('delete from directory.org_work where org_id = $1', [w.org]);
    const stop = new AbortController();
    stop.abort();
    await rediscoveryOf(w.org).run(stop.signal);
    expect(await jobsMarked(w)).toEqual([]);
    expect(lines('org_work.rediscovered')).toEqual([]);
  });
});
