// 4D2e Stage F: the hand-off held for the bank, on the real migrated schema as
// the app role. A lane's 3 unknowns in a row hold its organisation, then one at
// a time; 5 unknowns from 3 organisations hold everyone, until a status lookup
// answers; a real payment is never the probe; each organisation told once, in
// its signed audit log.
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { type FakeRail, RailUnavailable } from '@agentx/core/modules/providers';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, QUEUE_STALE_MS } from './handoff.ts';
import { handoffWorld, type HandoffWorldTables } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type World } from './mandate-world.helper.test.ts';
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
const { ready } = handoffWorld({
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

describe('a lane held: 3 unknowns in a row from one organisation', () => {
  it('sends no more, then after 5 minutes one, held again by its unknown; an answer clears it', async () => {
    const { w, requests } = await worldWith(5);
    let bankAway = true;
    const { rail, sent } = railOver([w], (real) => (intent) => (bankAway ? noAnswer(intent) : real(intent)));
    const job = handoffOver([w], rail);

    await job.run();
    expect(sent).toHaveLength(3);
    expect(await statusOf(w, requests[3] ?? '')).toBe('APPROVED');
    expect(lines('handoff.lane_held')).toHaveLength(1);

    // Still held: nothing sent, however many runs.
    await job.run();
    expect(sent).toHaveLength(3);

    // Past its hold: one, unanswered, holds it again.
    clock.advanceBy(5 * 60_000);
    await job.run();
    expect(sent).toHaveLength(4);
    expect(lines('handoff.lane_held')).toHaveLength(2);

    // Past it again, the bank back: the last goes, and it is clear.
    bankAway = false;
    clock.advanceBy(5 * 60_000);
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
    // Past the queue's age and the lane's hold: one more sent, unanswered, held again.
    clock.advanceBy(QUEUE_STALE_MS + 60_000);
    await job.run();

    expect(lines('handoff.queue_stale')).toEqual([]);
    expect(lines('handoff.queue_unread')).toEqual([]);
  });
});

describe('the bank held: 5 unknowns from at least 3 organisations in 60 s', () => {
  /** Three worlds, `each` requests approved in each. */
  const threeWorlds = async (each: number) => {
    const worlds = [await worldWith(each), await worldWith(each), await worldWith(each)];
    return { worlds: worlds.map(({ w }) => w), requests: worlds.flatMap(({ requests }) => requests) };
  };

  it('a payment is never the probe', async () => {
    const { worlds } = await threeWorlds(3);
    let bankAway = true;
    const { rail, sent } = railOver(worlds, (real) => (intent) => (bankAway ? noAnswer(intent) : real(intent)));
    const job = handoffOver(worlds, rail);

    await job.run();
    expect(lines('handoff.bank_held')).toHaveLength(1);
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

    // A lookup answers, "not found" at that: open, said, and what waited goes.
    const lookup = await watchedRail(rail, health).getExecution({
      organizationId: worlds[0]?.org ?? '',
      instructionId: ids.next(),
    });
    expect(lookup.kind).toBe('not_found');
    expect(lines('handoff.bank_back')).toHaveLength(1);
    await job.run();
    expect(sent).toHaveLength(worlds.length * 3);
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

  it('tells it again in a later outage, once one of its payments was answered between', async () => {
    const { w } = await worldWith(8);
    // Three unanswered, one answered, three unanswered: two outages, one still waiting to be held.
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
    await job.run();
    await job.run();
    expect(sentSoFar).toBe(7);
    expect(await heldNotesOf(w)).toHaveLength(2);
  });

  it('says the note it couldn’t write, the payment held all the same, and writes it next run', async () => {
    const { w, requests } = await worldWith(1);
    for (const org of ['x', 'x', 'y', 'y', 'z']) health.unknown(org);
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
