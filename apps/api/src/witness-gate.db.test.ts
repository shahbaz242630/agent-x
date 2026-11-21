// TR-1 PR-1d (S209): Tx A held to the path frontier and the gate after its commit, on two copies over one database and
// one witness store. W (a web copy) writes and witnesses; J (the jobs copy) hands off, its own witness log read before
// Tx A. Section 1.8 of the plan: (3) the gate after a forced order, (4) a forced lock order, (6) the pause hidden for a
// moment, (9) the witness store unreadable, (12) a rebase sets witnesses aside, (13) a walk past its reach. Each with
// its positive control: an honest J pays.
import { AGENTS } from '@agentx/core/modules/agents';
import {
  type ChainFrontier,
  checkStatesWith,
  createAuditTrail,
  createChainFrontier,
  witnessWith,
} from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import {
  type AnchorStore,
  CHAIN_START,
  type Chain,
  createDigestLog,
  createMemoryAnchorStore,
  createWitnessLog,
  type DigestLog,
  signAnchor,
  type WitnessLog,
} from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  type FakeWriteOnceStore,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createRailHealth } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;
let operator: Database<HandoffWorldTables>;

const ids = new SequentialIds(0x7b2e_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x7b2f_0000_0000) });
const PLATFORM: Chain = { kind: 'platform' };

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'witness-gate',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, statusOf, signed } = shared;
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The operator pauses or resumes every hand-off, as its command does. */
const pauseAll = (paused: boolean) =>
  operator
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused, reason: 'TEST-TR1D', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  operator = createDatabase<HandoffWorldTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  // Born paused (ADR-014 §4): resumed, as the operator would once the hand-off is live.
  await pauseAll(false);
});

afterAll(async () => {
  await app.destroy();
  await operator.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  const logger = testLogger(capture);
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock, keys }),
    keys,
    ids,
    clock,
    logger,
  });
});

afterEach(() => {
  checkStatesWith(undefined);
  witnessWith(undefined);
});

/** A copy's witness log over the store every copy shares. */
const witnessOver = (store: FakeWriteOnceStore): WitnessLog =>
  createWitnessLog({
    store: store.store,
    keys,
    logger: testLogger(capture),
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: 60_000,
    mostBytes: 1024 * 1024,
  });

/** Rebases the copies' logs have read (chain-rebase --after-restore), by chain name, and when. */
type Rebases = Map<string, Date>;
const rebasedIn =
  (rebases: Rebases) =>
  (each: Chain, at: Date): boolean => {
    const when = rebases.get(each.kind === 'platform' ? 'platform' : each.orgId.toLowerCase());
    return when !== undefined && when.getTime() > at.getTime();
  };

/** The jobs copy J: both chains walked and anchored at their heads, its digest, witness log and frontier. */
interface JobsCopy {
  readonly digest: DigestLog;
  readonly anchors: AnchorStore;
  readonly witness: WitnessLog;
  readonly frontier: ChainFrontier;
}

async function jobsCopy(
  w: World,
  store: FakeWriteOnceStore,
  rebases: Rebases = new Map(),
  { readsHeld = true }: { readonly readsHeld?: boolean } = {},
): Promise<JobsCopy> {
  const witness = witnessOver(store);
  const rebasedAfter = rebasedIn(rebases);
  const digest = createDigestLog({
    store: createFakeWriteOnceStore().store,
    keys,
    logger: testLogger(capture),
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: 60_000,
    mostBytes: 64 * 1024 * 1024,
    // Its reads held to the heads witnessed too (PR-1c); left out, only Tx A's own walk holds to them.
    ...(readsHeld ? { witnessed: (each: Chain, most?: number) => witness.pending(each, most) } : {}),
    anchors: { rebasedAfter, holds: () => true },
  });
  await digest.read();
  const anchors = createMemoryAnchorStore();
  const orgChain = { kind: 'organisation', orgId: w.org } as const;
  const walked = await createAuditTrail({ keys, ids }).checkFromAnchor(app, w.org, CHAIN_START);
  if (!walked.ok) throw new Error('the organisation’s chain should check out');
  digest.record(orgChain, walked.signed ?? new Map(), clock.now(), { from: 0n, to: walked });
  anchors.keep(signAnchor(keys, orgChain, walked, clock.now()));
  const platform = await chain.checkFromAnchor(app, CHAIN_START);
  if (!platform.ok) throw new Error('the platform chain should check out');
  digest.record(PLATFORM, new Map(), clock.now(), { from: 0n, to: platform });
  anchors.keep(signAnchor(keys, PLATFORM, platform, clock.now()));
  witness.useAnchors({ rebasedAfter, latest: (each) => anchors.latest(each) });
  const frontier = createChainFrontier({
    anchors: { latest: (each) => anchors.latest(each), rebasedAfter },
    now: () => clock.now(),
  });
  return { digest, anchors, witness, frontier };
}

/** J's hand-off run, every call to the partner counted; its witness log as given, or wrapped by a test. */
async function handOffOnJ(
  w: World,
  j: JobsCopy,
  {
    witness = j.witness,
    mostWalked,
    listed = () => Promise.resolve(),
  }: {
    readonly witness?: WitnessLog;
    readonly mostWalked?: number;
    /** Done as the run lists its organisations: after its first read of the pause, before any Tx A. */
    readonly listed?: () => Promise<void>;
  } = {},
): Promise<number> {
  let submitted = 0;
  const rail = {
    ...w.rail,
    submitApprovedIntent: (intent: Parameters<typeof w.rail.submitApprovedIntent>[0]) => {
      submitted += 1;
      return w.rail.submitApprovedIntent(intent);
    },
  };
  checkStatesWith(j.digest);
  witnessWith(j.witness);
  try {
    await createHandoff({
      anchoring: { anchors: j.anchors, anchorFirst: () => Promise.resolve(), digest: j.digest },
      witnessing: { witness, frontier: j.frontier, ...(mostWalked === undefined ? {} : { mostWalked }) },
      list: async () => {
        await listed();
        return [w.org];
      },
      database: app,
      outbox: createOutbox({ ids, clock, keys }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
    }).run();
  } finally {
    checkStatesWith(undefined);
    witnessWith(undefined);
  }
  return submitted;
}

/** The owner's own statements inside the organisation, the connection ended after. */
async function asOwner(w: World, run: (owner: Awaited<ReturnType<typeof tamperAsOwner>>) => Promise<void>) {
  const owner = await tamperAsOwner(database, AGENTS, w.org);
  try {
    await run(owner);
  } finally {
    await owner.end();
  }
}

/** W suspends the agent, its head witnessed before the answer. */
async function suspendOnW(w: World, store: FakeWriteOnceStore): Promise<void> {
  witnessWith(witnessOver(store));
  try {
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: { reason: 'test' },
      }),
    );
  } finally {
    witnessWith(undefined);
  }
}

/**
 * `work` as another process would do it while J's run waits on a lock: neither J's digest nor its witness log, which
 * this process holds for J alone, sees it (each is the process's own: checkStatesWith, witnessWith). J's set back after.
 */
async function asW(j: JobsCopy, work: () => Promise<void>): Promise<void> {
  checkStatesWith(undefined);
  try {
    await work();
  } finally {
    checkStatesWith(j.digest);
    witnessWith(j.witness);
  }
}

/** What the owner keeps to cut a stop off: the agent's row and the head as they are now. */
async function savedForCut(w: World) {
  let cut: () => Promise<void> = () => Promise.resolve();
  await asOwner(w, async (owner) => {
    const row = await owner.saveRow(w.agent);
    const head = await owner.saveHead();
    cut = () =>
      asOwner(w, async (again) => {
        await again.windBack(head);
        await again.withoutStatusGuard(() => again.restoreRow(row));
      });
  });
  return cut;
}

/** A witness log whose refresh first does what a test says: something landing between Tx A's commit and the gate. */
const beforeGateRead = (witness: WitnessLog, first: () => Promise<void>): WitnessLog => ({
  ...witness,
  async refreshWhole() {
    await first();
    return witness.refreshWhole();
  },
});

/** The payment's state: the partner called or not, the request, its transaction, and the gate's line. */
async function outcome(w: World, requestId: string, submitted: number) {
  const payment = await paymentOf(w, requestId);
  const transaction = 'transaction' in payment ? payment.transaction : undefined;
  return {
    submitted,
    request: await statusOf(w, requestId),
    transaction: typeof transaction === 'object' ? transaction.status : transaction,
    held: lines('handoff.held_before_sending').map(({ reason }) => reason),
  };
}

const heldNow = async (w: World) => (await signed(w, (tx, states) => states.holdRecord(tx, w.org))).outcome;

describe('TR-1 PR-1d the positive control: an honest jobs copy held to the frontier and the gate', () => {
  it('pays once: Tx A walks from the frontier, the gate witnesses its head and finds every head on the path', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    // Asked after J's anchor: Tx A walks its events from the frontier.
    const request = await ask(acting, w, { amount: ALLOWED() });
    await j.witness.refresh();
    const submitted = await handOffOnJ(w, j);
    expect(await outcome(w, request.id, submitted)).toMatchObject({ submitted: 1, request: 'HANDED_OFF', held: [] });
    // H_A went out before the call: J's own file in the store, its head among those witnessed.
    expect(store.files.size).toBe(1);
    expect(j.witness.pending({ kind: 'organisation', orgId: w.org }).length).toBeGreaterThan(0);
    expect(j.frontier.startOf({ kind: 'organisation', orgId: w.org })?.from.seq).toBeGreaterThan(
      j.anchors.latest({ kind: 'organisation', orgId: w.org })?.seq ?? 0n,
    );
    expect(lines('audit.integrity_failed')).toEqual([]);
  });
});

describe('TR-1 (3): the gate after a forced order', () => {
  it('J reads the store, W stops the agent and the owner cuts it off, J’s Tx A commits: the gate sends nothing, the organisation held', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const cut = await savedForCut(w);
    await suspendOnW(w, store);
    await cut();
    const submitted = await handOffOnJ(w, j);
    expect(await outcome(w, request.id, submitted)).toEqual({
      submitted: 0,
      request: 'HANDED_OFF',
      transaction: 'SUBMISSION_PENDING',
      held: ['cut_back'],
    });
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ chain: 'organisation', check: 'witness', reason: 'cut_back' }),
    );
    expect(await heldNow(w)).toBe('held');
  });

  it('the positive control: an honest write landing after Tx A (a later write, linked) lets the payment go', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const witness = beforeGateRead(j.witness, () => suspendOnW(w, store));
    const submitted = await handOffOnJ(w, j, { witness });
    expect(await outcome(w, request.id, submitted)).toMatchObject({ submitted: 1, request: 'HANDED_OFF', held: [] });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });
});

describe('TR-1 (4): a forced lock order', () => {
  /** J's run queued on the pause row the owner holds; `meanwhile` done; the row let go; the run's calls. */
  async function queuedBehindThePause(w: World, j: JobsCopy, meanwhile: () => Promise<void>): Promise<number> {
    const holder = await database.connect('owner');
    try {
      // Taken once the run has read the pause and listed its organisations: the one waiting is Tx A's level 1 lock.
      const running = handOffOnJ(w, j, {
        listed: async () => {
          await holder.query('begin');
          await holder.query('select paused from platform_controls.handoff_pause for update');
        },
      });
      await waitUntilQueued(database.as('owner'), 1);
      await meanwhile();
      await holder.query('commit');
      return await running;
    } finally {
      await holder.end();
    }
  }

  it('Tx A queued at the pause, W stops the agent and the owner cuts it off, then the row let go: the gate refuses', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const cut = await savedForCut(w);
    const submitted = await queuedBehindThePause(w, j, async () => {
      await asW(j, () => suspendOnW(w, store));
      await cut();
    });
    expect(await outcome(w, request.id, submitted)).toMatchObject({
      submitted: 0,
      transaction: 'SUBMISSION_PENDING',
      held: ['cut_back'],
    });
    expect(await heldNow(w)).toBe('held');
  });

  it('the positive control: no cut, and Tx A, let go, finds the agent suspended and waits', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const submitted = await queuedBehindThePause(w, j, () => asW(j, () => suspendOnW(w, store)));
    // Read after the lock let it go: the suspension, chosen to cancel, denies it (decision 3), no call.
    expect(await outcome(w, request.id, submitted)).toMatchObject({ submitted: 0, request: 'DENIED', held: [] });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });
});

describe('TR-1 (9): the witness store unreadable', () => {
  it('a view older than 30 s waits (witness_pending), nothing committed; read again, it goes', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    clock.advanceBy(31_000);
    store.instead.list = () => Promise.reject(new Error('store away'));
    expect(await j.witness.refreshWhole()).toBe(false);
    expect(await handOffOnJ(w, j)).toBe(0);
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toContainEqual(expect.objectContaining({ why: 'witness_pending' }));
    delete store.instead.list;
    await j.witness.refresh();
    expect(await handOffOnJ(w, j)).toBe(1);
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });

  it('a read that fails after Tx A’s commit: the gate sends nothing (witness_unread)', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const witness = beforeGateRead(j.witness, () => {
      store.instead.list = () => Promise.reject(new Error('store away'));
      return Promise.resolve();
    });
    const submitted = await handOffOnJ(w, j, { witness });
    expect(await outcome(w, request.id, submitted)).toMatchObject({
      submitted: 0,
      transaction: 'SUBMISSION_PENDING',
      held: ['witness_unread'],
    });
  });
});

describe('TR-1 (12): a rebase after a restore sets the witnesses and the frontier aside', () => {
  it('the stop W witnessed, cut off by a restore: held without the rebase; with it recorded, the payment goes', async () => {
    const control = createFakeWriteOnceStore();
    const first = await ready();
    const unrebased = await ask(first.acting, first.w, { amount: ALLOWED() });
    const plain = await jobsCopy(first.w, control);
    const cutFirst = await savedForCut(first.w);
    await suspendOnW(first.w, control);
    await cutFirst();
    await plain.witness.refresh();
    expect(await handOffOnJ(first.w, plain)).toBe(0);
    expect(await statusOf(first.w, unrebased.id)).toBe('APPROVED');
    expect(lines('audit.integrity_failed')).toContainEqual(expect.objectContaining({ check: 'witness' }));
    capture = new LogCapture();

    const store = createFakeWriteOnceStore();
    const rebases: Rebases = new Map();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store, rebases);
    const cut = await savedForCut(w);
    await suspendOnW(w, store);
    await cut();
    // The operator's rebase after the restore, dated after every head witnessed before it.
    clock.advanceBy(1_000);
    rebases.set(w.org.toLowerCase(), clock.now());
    clock.advanceBy(1_000);
    // The anchor check's walk after it: the digest and the anchor taken again from the chain as restored.
    const orgChain = { kind: 'organisation', orgId: w.org } as const;
    const rewalked = await createAuditTrail({ keys, ids }).checkFromAnchor(app, w.org, CHAIN_START);
    if (!rewalked.ok) throw new Error('the restored chain should check out');
    j.digest.record(orgChain, rewalked.signed ?? new Map(), clock.now(), { from: 0n, to: rewalked });
    j.anchors.keep(signAnchor(keys, orgChain, rewalked, clock.now()));
    await j.witness.refresh();
    expect(j.witness.pending({ kind: 'organisation', orgId: w.org })).toEqual([]);
    expect(await handOffOnJ(w, j)).toBe(1);
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });
});

describe('TR-1 F.3 Tx A’s own walk, and a frontier with no anchor', () => {
  it('a stop witnessed before Tx A, cut off, its reads not held to it: Tx A’s walk finds it (hold_tampered), nothing committed', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store, new Map(), { readsHeld: false });
    const cut = await savedForCut(w);
    await suspendOnW(w, store);
    await cut();
    await j.witness.refresh();
    expect(await handOffOnJ(w, j)).toBe(0);
    expect(await outcome(w, request.id, 0)).toMatchObject({ request: 'APPROVED', transaction: undefined, held: [] });
    expect(lines('handoff.waiting')).toContainEqual(expect.objectContaining({ why: 'hold_tampered' }));
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ chain: 'organisation', check: 'witness', reason: 'cut_back' }),
    );
    expect(await heldNow(w)).toBe('held');
  });

  it('a frontier that knows no anchor of a chain waits (anchor_pending), the platform’s or the organisation’s', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    const request = await ask(acting, w, { amount: ALLOWED() });
    await j.witness.refresh();
    for (const known of [
      () => undefined,
      (each: Chain) => (each.kind === 'platform' ? j.anchors.latest(each) : undefined),
    ]) {
      const frontier = createChainFrontier({
        anchors: { latest: known, rebasedAfter: () => false },
        now: () => clock.now(),
      });
      expect(await handOffOnJ(w, { ...j, frontier })).toBe(0);
    }
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting').map(({ why }) => why)).toEqual(['anchor_pending', 'anchor_pending']);
  });

  it('refuses at start a witness log with no anchors to walk from', () => {
    expect(() =>
      createHandoff({
        witnessing: {
          witness: witnessOver(createFakeWriteOnceStore()),
          frontier: createChainFrontier({
            anchors: { latest: () => undefined, rebasedAfter: () => false },
            now: () => clock.now(),
          }),
        },
        list: () => Promise.resolve([]),
        database: app,
        outbox: createOutbox({ ids, clock, keys }),
        rail: {} as never,
        keys,
        ids,
        clock,
        logger: testLogger(capture),
        health: createRailHealth({ clock, logger: testLogger(capture) }),
        databaseGate: handoffDatabaseGate(6),
      }),
    ).toThrow(RangeError);
  });
});

describe('TR-1 (13): a walk past its reach', () => {
  it('more events past the frontier than a walk may take waits (chain_unverified); within it, it goes', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    const request = await ask(acting, w, { amount: ALLOWED() });
    await j.witness.refresh();
    expect(await handOffOnJ(w, j, { mostWalked: 1 })).toBe(0);
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toContainEqual(expect.objectContaining({ why: 'chain_unverified' }));
    expect(lines('audit.integrity_failed')).toEqual([]);
    expect(await handOffOnJ(w, j)).toBe(1);
  });
});

describe('TR-1 (6): the pause hidden for a moment', () => {
  /** The platform rows past `seq`, the head and the pause row, as the owner saves them to put back. */
  async function ownerSaves(seq: string) {
    const owner = await database.connect('owner');
    try {
      const saved = async (statement: string, values: unknown[] = []) =>
        // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written just below.
        (await owner.query<{ row: string }>(statement, values)).map(({ row }) => row);
      return {
        events: await saved(
          'select pg_catalog.to_jsonb(e)::text as row from platform_controls.audit_events e where e.seq > $1',
          [seq],
        ),
        signatures: await saved(
          'select pg_catalog.to_jsonb(s)::text as row from platform_controls.operator_signatures s where s.seq > $1',
          [seq],
        ),
        head: await saved('select pg_catalog.to_jsonb(h)::text as row from platform_controls.audit_head h'),
        pause: await saved('select pg_catalog.to_jsonb(p)::text as row from platform_controls.handoff_pause p'),
      };
    } finally {
      await owner.end();
    }
  }

  /** The owner's statements, as the owner may run them. */
  async function owner(statements: readonly (readonly [string, readonly unknown[]])[]) {
    const connection = await database.connect('owner');
    try {
      // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
      for (const [statement, values] of statements) await connection.query(statement, [...values]);
    } finally {
      await connection.end();
    }
  }

  /** The platform head row's place, as stored. */
  const platformHead = async () =>
    (await database.as('owner').query<{ seq: string }>('select seq::text from platform_controls.audit_head'))[0]?.seq ??
    '0';

  /**
   * The operator pauses (witnessed by W); the owner cuts the pause off with the platform chain's end and points the row
   * back at the resume. What puts it back.
   */
  async function pauseHidden(store: FakeWriteOnceStore) {
    const before = await platformHead();
    const shown = await ownerSaves(before);
    const w = witnessOver(store);
    witnessWith(w);
    try {
      await pauseAll(true);
      await w.settled([PLATFORM]);
    } finally {
      witnessWith(undefined);
    }
    const paused = await ownerSaves(before);
    const [head] = shown.head;
    const [pause] = shown.pause;
    await owner([
      ['delete from platform_controls.operator_signatures where seq > $1', [before]],
      ['delete from platform_controls.audit_events where seq > $1', [before]],
      [
        'update platform_controls.audit_head h set seq = r.seq, hash = r.hash, mac = r.mac, mac_key_version = r.mac_key_version from pg_catalog.jsonb_populate_record(null::platform_controls.audit_head, $1::jsonb) r',
        [head],
      ],
      [
        'update platform_controls.handoff_pause p set paused = r.paused, event_seq = r.event_seq, event_id = r.event_id from pg_catalog.jsonb_populate_record(null::platform_controls.handoff_pause, $1::jsonb) r',
        [pause],
      ],
    ]);
    return () =>
      owner([
        ...paused.events.map(
          (row) =>
            [
              'insert into platform_controls.audit_events select * from pg_catalog.jsonb_populate_record(null::platform_controls.audit_events, $1::jsonb)',
              [row],
            ] as const,
        ),
        ...paused.signatures.map(
          (row) =>
            [
              'insert into platform_controls.operator_signatures select * from pg_catalog.jsonb_populate_record(null::platform_controls.operator_signatures, $1::jsonb)',
              [row],
            ] as const,
        ),
        [
          'update platform_controls.audit_head h set seq = r.seq, hash = r.hash, mac = r.mac, mac_key_version = r.mac_key_version from pg_catalog.jsonb_populate_record(null::platform_controls.audit_head, $1::jsonb) r',
          [paused.head[0]],
        ],
        [
          'update platform_controls.handoff_pause p set paused = r.paused, event_seq = r.event_seq, event_id = r.event_id from pg_catalog.jsonb_populate_record(null::platform_controls.handoff_pause, $1::jsonb) r',
          [paused.pause[0]],
        ],
      ]);
  }

  it('hidden through Tx A: the gate finds the platform chain cut below the pause witnessed, and sends nothing', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const putBack = await pauseHidden(store);
    try {
      const submitted = await handOffOnJ(w, j);
      expect(await outcome(w, request.id, submitted)).toMatchObject({
        submitted: 0,
        transaction: 'SUBMISSION_PENDING',
        held: ['platform_cut_back'],
      });
      // The platform's cut holds no organisation.
      expect(await heldNow(w)).toBe('clear');
    } finally {
      await putBack();
      await pauseAll(false);
    }
  });

  it('put back once Tx A committed: the gate walks from P to the pause, a pause after all, and sends nothing', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const putBack = await pauseHidden(store);
    try {
      const witness = beforeGateRead(j.witness, putBack);
      const submitted = await handOffOnJ(w, j, { witness });
      expect(await outcome(w, request.id, submitted)).toMatchObject({ submitted: 0, held: ['paused'] });
    } finally {
      await pauseAll(false);
    }
  });

  it('the positive control: a sign-in’s platform event after Tx A, linked and no pause, lets the payment go', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const witness = beforeGateRead(j.witness, async () => {
      const onW = witnessOver(store);
      witnessWith(onW);
      try {
        await createPlatformChain({ keys, ids }).recordAlone(app, {
          actor: { type: 'system', id: 'api' },
          action: 'platform.started',
          details: { configHash: 'a'.repeat(64), release: 'r-test' },
        });
        await onW.settled([PLATFORM]);
      } finally {
        witnessWith(j.witness);
      }
    });
    const submitted = await handOffOnJ(w, j, { witness });
    expect(await outcome(w, request.id, submitted)).toMatchObject({ submitted: 1, request: 'HANDED_OFF', held: [] });
  });
});
