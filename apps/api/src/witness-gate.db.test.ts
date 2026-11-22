// TR-1 PR-1d (S209): Tx A held to the path frontier and the gate after its commit, on two copies over one database and
// one witness store. W (a web copy) writes and witnesses; J (the jobs copy) hands off, its own witness log read before
// Tx A. Section 1.8 of the plan: (3) the gate after a forced order, (4) a forced lock order, (6) the pause hidden for a
// moment, (9) the witness store unreadable, (12) a rebase sets witnesses aside, (13) a walk past its reach. Each with
// its positive control: an honest J pays.
import { AGENTS } from '@agentx/core/modules/agents';
import {
  type AuditDetails,
  type AuditTransaction,
  type ChainFrontier,
  checkStatesWith,
  createAuditTrail,
  createChainFrontier,
  historyNamedOf,
  type SignedStates,
  type VerifiedState,
  witnessWith,
} from '@agentx/core/modules/audit';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { MANDATES } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  cancelRequest,
  decisionsOf,
  ORDER_SLOTS,
  type Pausable,
  SPEND_REQUESTS,
} from '@agentx/core/modules/spend-requests';
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
import { createDatabase, type Database, type SignedStateTable } from '@agentx/platform/db';
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

import { CONSENT_EXPIRY_CHOSEN, consentExpiryOf } from './consent-expiry-choice.ts';
import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables } from './handoff-world.helper.test.ts';
import { carriesRest } from './mandate-carry-rest.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createRailHealth } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';
import { authorityOf } from './request-voids.ts';
import { createStateNames } from './state-names.ts';
import { cancelledSinceOf, type HeldBy, PAUSABLE_TABLES, pausedOf } from './suspensions.ts';

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

/** Each object `ids` names with its verified state, read `share` in the test's own transaction; undefined for one tampered. */
async function stopsHeldOf(
  tx: AuditTransaction,
  states: SignedStates,
  orgId: string,
  ids: Readonly<Record<Pausable, string | null>>,
): Promise<readonly HeldBy[] | undefined> {
  const held: HeldBy[] = [];
  for (const which of Object.keys(PAUSABLE_TABLES) as Pausable[]) {
    const id = ids[which];
    if (id === null) continue;
    const state = await states.verifiedState(tx, PAUSABLE_TABLES[which], { orgId, id }, 'share');
    if (state.outcome !== 'verified') return undefined;
    held.push({ table: PAUSABLE_TABLES[which], id, state });
  }
  return held;
}

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
  {
    readsHeld = true,
    writes,
    digestBytes = 64 * 1024 * 1024,
  }: {
    readonly readsHeld?: boolean;
    /** Whether its digest writes (it leads the jobs, TR-1 A); always, unless given. */
    readonly writes?: () => boolean;
    /** What its digest may hold: past it a chain gives way for memory (AT13e). */
    readonly digestBytes?: number;
  } = {},
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
    mostBytes: digestBytes,
    ...(writes === undefined ? {} : { writes }),
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
    // As job-list.ts wires it (TR-3): what each Tx A's walk read of the signed objects kept in the digest.
    facts: {
      keep: (each, signed, began) => {
        digest.record(each, signed, began);
      },
      kept: (each) => digest.factsKept(each),
    },
  });
  return { digest, anchors, witness, frontier };
}

/** J's hand-off run, every call to the partner counted; its witness log as given, or wrapped by a test. */
async function handOffOnJ(
  w: World,
  j: JobsCopy,
  options: {
    readonly witness?: WitnessLog;
    readonly mostWalked?: number;
    /** Done as the run lists its organisations: after its first read of the pause, before any Tx A. */
    readonly listed?: () => Promise<void>;
  } = {},
): Promise<number> {
  const handOff = handOffMadeOnJ(w, j, options);
  return handOff.run();
}

/** J's hand-off made once, to run as often as a test asks (one process's, its memory kept): each run's partner calls. */
function handOffMadeOnJ(
  w: World,
  j: JobsCopy,
  {
    witness = j.witness,
    mostWalked,
    listed = () => Promise.resolve(),
  }: {
    readonly witness?: WitnessLog;
    readonly mostWalked?: number;
    readonly listed?: () => Promise<void>;
  } = {},
): { run(): Promise<number> } {
  const calls = { submitted: 0 };
  const rail = {
    ...w.rail,
    submitApprovedIntent: (intent: Parameters<typeof w.rail.submitApprovedIntent>[0]) => {
      calls.submitted += 1;
      return w.rail.submitApprovedIntent(intent);
    },
  };
  const made = createHandoff({
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
  });
  return {
    async run() {
      calls.submitted = 0;
      checkStatesWith(j.digest);
      witnessWith(j.witness);
      try {
        await made.run();
      } finally {
        checkStatesWith(undefined);
        witnessWith(undefined);
      }
      return calls.submitted;
    },
  };
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

describe('SEC-DB-20 TR-1 PR-1d the positive control: an honest jobs copy held to the frontier and the gate', () => {
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

describe('SEC-DB-20 TR-1 (3): the gate after a forced order', () => {
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

describe('SEC-DB-20 TR-1 (4): a forced lock order', () => {
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

describe('SEC-DB-20 TR-1 (9): the witness store unreadable', () => {
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

describe('SEC-DB-20 TR-1 (12): a rebase after a restore sets the witnesses and the frontier aside', () => {
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

describe('SEC-DB-20 TR-1 F.3 Tx A’s own walk, and a frontier with no anchor', () => {
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

describe('SEC-DB-20 TR-1 review: the platform frontier, witness writes failing, a restart', () => {
  it('82: each Tx A raises the platform frontier to the head it walked to, so the next walks only what came since', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    const anchored = j.anchors.latest(PLATFORM)?.seq ?? 0n;
    // Platform events past the anchor (starts, as copies write them): the first Tx A walks them.
    for (const _ of [1, 2, 3]) {
      await createPlatformChain({ keys, ids }).recordAlone(app, {
        actor: { type: 'system', id: 'api' },
        action: 'platform.started',
        details: { configHash: 'a'.repeat(64), release: 'r-test' },
      });
    }
    const request = await ask(acting, w, { amount: ALLOWED() });
    await j.witness.refresh();
    expect(await handOffOnJ(w, j)).toBe(1);
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    expect(j.frontier.startOf(PLATFORM)?.from.seq).toBe(anchored + 3n);
  });

  it('80: witness writes failing while reads work: nothing commits, nothing left SUBMISSION_PENDING; writes back, it pays', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    // The store refuses this copy's writes (its flush of a head it holds fails), and still lists and gives files.
    store.instead.put = () => Promise.reject(new Error('writes refused'));
    const platform = await chain.checkFromAnchor(app, CHAIN_START);
    if (!platform.ok) throw new Error('the platform chain should check out');
    j.witness.soon(PLATFORM, platform);
    await j.witness.flush();
    expect(await j.witness.refreshWhole()).toBe(true);
    expect(await handOffOnJ(w, j)).toBe(0);
    expect(await outcome(w, request.id, 0)).toMatchObject({ request: 'APPROVED', transaction: undefined, held: [] });
    expect(lines('handoff.waiting')).toContainEqual(expect.objectContaining({ why: 'witness_pending' }));
    delete store.instead.put;
    await j.witness.flush();
    expect(await handOffOnJ(w, j)).toBe(1);
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });

  it('the platform log past its memory waits (witness_pending), as the organisation’s does', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const j = await jobsCopy(w, store);
    await j.witness.refresh();
    const beyond: WitnessLog = { ...j.witness, beyondMemory: (each) => each.kind === 'platform' };
    expect(await handOffOnJ(w, { ...j, witness: beyond }, { witness: beyond })).toBe(0);
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toContainEqual(expect.objectContaining({ why: 'witness_pending' }));
  });

  /**
   * Plan 1.1 #4: a request paid, J restarted (nothing of its memory left), and the owner cuts Tx A's events off, puts the
   * request back APPROVED with its old MAC and deletes its instruction and transaction. What the restarted J's run does.
   */
  async function paidThenCutAfterRestart(sharedStore: boolean) {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const first = await jobsCopy(w, store);
    await first.witness.refresh();
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    let saved: { row: Awaited<ReturnType<typeof owner.saveRow>>; head: Awaited<ReturnType<typeof owner.saveHead>> };
    try {
      saved = { row: await owner.saveRow(request.id), head: await owner.saveHead() };
    } finally {
      await owner.end();
    }
    expect(await handOffOnJ(w, first)).toBe(1);
    const cutting = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await cutting.query('delete from transactions.transactions where org_id = $1', [w.org]);
      await cutting.query('delete from instructions.instructions where org_id = $1', [w.org]);
      await cutting.windBack(saved.head);
      await cutting.withoutStatusGuard(() => cutting.restoreRow(saved.row));
    } finally {
      await cutting.end();
    }
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    capture = new LogCapture();
    // Restarted: a new digest, anchors, frontier and witness log, the store read again (or, the control, a store of
    // its own that never saw the first run's head).
    const restarted = await jobsCopy(w, sharedStore ? store : createFakeWriteOnceStore());
    await restarted.witness.refresh();
    return { w, request, submitted: await handOffOnJ(w, restarted) };
  }

  it('1.1 #4: paid, restarted, cut and the request put back: the head the first Tx A witnessed refuses a second call', async () => {
    const { w, submitted } = await paidThenCutAfterRestart(true);
    expect(submitted).toBe(0);
    // Found by the reads held to that head (PR-1c) before Tx A's own walk: the alarm, and the organisation held.
    expect(lines('audit.integrity_failed').length).toBeGreaterThan(0);
    expect(await heldNow(w)).toBe('held');
  });

  it('the positive control: a restarted copy that never read the first head pays a second time (the attack)', async () => {
    const { submitted } = await paidThenCutAfterRestart(false);
    expect(submitted).toBe(1);
  });
});

describe('SEC-DB-20 TR-3 a stop rewritten in place below the frontier, its hash kept', () => {
  /**
   * Two requests; W cancels the second, its head witnessed; J's Tx A for the first walks past the cancel, raising F
   * beyond it. Then, `rewrite` given, the owner moves the cancel's event to another subject (its stored hash left as it
   * was, so every one-row check still reads true) and puts the request's row back as approved. J's next run.
   */
  async function cancelledThenRewritten(
    rewrite: boolean,
    { leaseLost = false, digestBytes }: { readonly leaseLost?: boolean; readonly digestBytes?: number } = {},
  ) {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const leads = { now: true };
    const j = await jobsCopy(w, store, new Map(), {
      writes: () => leads.now,
      ...(digestBytes === undefined ? {} : { digestBytes }),
    });
    const paid = await ask(acting, w, { amount: ALLOWED() });
    const stopped = await ask(acting, w, { amount: ALLOWED() });
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    let saved: Awaited<ReturnType<typeof owner.saveRow>>;
    try {
      saved = await owner.saveRow(stopped.id);
    } finally {
      await owner.end();
    }
    witnessWith(witnessOver(store));
    try {
      await signed(w, (tx, states) =>
        states.changeStatus(tx, SPEND_REQUESTS, { orgId: w.org, id: stopped.id }, 'cancel', {
          actor: OPERATOR,
          action: 'spend_request.cancelled',
          details: {},
        }),
      );
    } finally {
      witnessWith(undefined);
    }
    // More of the organisation's writes after the stop, so the walk raises F past it, not to it (the event at F itself
    // is read whole by every walk from F).
    const noted = ids.next();
    await signed(w, (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: OPERATOR,
        action: 'handoff.held_for_bank',
        subject: { type: 'handoff_hold', id: noted, version: 1 },
        details: { hold: 'lane' },
      }),
    );
    await j.witness.refresh();
    // The lease lost through the paying Tx A: its digest takes nothing that walk read.
    leads.now = !leaseLost;
    expect(await handOffOnJ(w, j)).toBe(1);
    leads.now = true;
    expect(await statusOf(w, paid.id)).toBe('HANDED_OFF');
    expect(await statusOf(w, stopped.id)).toBe('CANCELLED');
    const orgChain = { kind: 'organisation', orgId: w.org } as const;
    if (!leaseLost && digestBytes === undefined) {
      // Kept in the digest from Tx A's walk: the cancel, a signed state; never an event carrying no state seal.
      expect(j.digest.latest(orgChain, SPEND_REQUESTS.subject, stopped.id)).toBeDefined();
      expect(j.digest.latest(orgChain, 'handoff_hold', noted)).toBeUndefined();
    } else {
      // Not kept (the lease lost, or the chain given way for memory): so no stretch either; F at the anchor still.
      expect(j.digest.latest(orgChain, SPEND_REQUESTS.subject, stopped.id)).toBeUndefined();
      expect(j.frontier.startOf(orgChain)?.from.seq).toBe(j.anchors.latest(orgChain)?.seq);
      // Given way, really: the digest says it keeps none of the chain's facts.
      if (digestBytes !== undefined) expect(j.digest.factsKept(orgChain)).toBeUndefined();
    }
    if (rewrite) {
      const cutting = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
      try {
        await cutting.query('begin');
        await cutting.query('alter table audit.events disable trigger user');
        await cutting.query(
          "update audit.events set subject_id = '0199a0f0-0000-7000-8000-00000000dead' where org_id = $1 and subject_id = $2 and action = 'spend_request.cancelled'",
          [w.org, stopped.id],
        );
        await cutting.query('alter table audit.events enable trigger user');
        await cutting.query('commit');
        await cutting.withoutStatusGuard(() => cutting.restoreRow(saved));
      } finally {
        await cutting.end();
      }
    }
    capture = new LogCapture();
    return { w, stopped, submitted: await handOffOnJ(w, j) };
  }

  it('the stop rewritten in place and the request put back approved: never paid, the alarm', async () => {
    const { w, stopped, submitted } = await cancelledThenRewritten(true);
    expect(submitted).toBe(0);
    expect(await outcome(w, stopped.id, submitted)).toMatchObject({ transaction: undefined });
    expect(lines('audit.integrity_failed').length).toBeGreaterThan(0);
  });

  /** The organisation's slot rows as the owner saves them, and the chain's newest place now. */
  async function slotsAsTheyAre(w: World) {
    const owner = await tamperAsOwner(database, ORDER_SLOTS, w.org);
    try {
      const rows = await owner.query<{ id: string }>('select id from spend_requests.order_slots where org_id = $1', [
        w.org,
      ]);
      const saved = await Promise.all(rows.map(({ id }) => owner.saveRow(id)));
      const [top] = await owner.query<{ seq: string }>(
        'select max(seq)::text as seq from audit.events where org_id = $1',
        [w.org],
      );
      return { saved, before: top?.seq ?? '0' };
    } finally {
      await owner.end();
    }
  }

  /**
   * The order-slot variant: an order asked, ended (its slots let go), asked again and paid, a write after it. The paid
   * Tx A walks past the slots' `order_slot.held`, raising F beyond. Then, `rewrite` given, the owner moves those events to
   * another subject (hashes kept), puts the slots back as no one's and releases the claim. The order asked a third time.
   */
  async function orderRewritten(rewrite: boolean) {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    const earlier = await ask(acting, w, { amount: ALLOWED(), orderReference: 'ORD-77' });
    await signed(w, (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: earlier.id },
        { kind: 'user', userId: '0199a0f0-0000-7000-8000-0000000000aa' },
        clock.now(),
      ),
    );
    const { saved, before } = await slotsAsTheyAre(w);
    const paid = await ask(acting, w, { amount: ALLOWED(), orderReference: 'ORD-77' });
    await signed(w, (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: OPERATOR,
        action: 'handoff.held_for_bank',
        subject: { type: 'handoff_hold', id: ids.next(), version: 1 },
        details: { hold: 'lane' },
      }),
    );
    await j.witness.refresh();
    expect(await handOffOnJ(w, j)).toBe(1);
    expect(await statusOf(w, paid.id)).toBe('HANDED_OFF');
    if (rewrite) {
      const cutting = await tamperAsOwner(database, ORDER_SLOTS, w.org);
      try {
        await cutting.query('begin');
        await cutting.query('alter table audit.events disable trigger user');
        await cutting.query('alter table spend_requests.order_claims disable trigger user');
        await cutting.query('alter table spend_requests.order_slots disable trigger user');
        await cutting.query(
          "update audit.events set subject_id = gen_random_uuid() where org_id = $1 and action = 'order_slot.held' and seq > $2",
          [w.org, before],
        );
        await cutting.query('update spend_requests.order_claims set released_at = claimed_at where request_id = $1', [
          paid.id,
        ]);
        await cutting.query('alter table spend_requests.order_slots enable trigger user');
        await cutting.query('alter table spend_requests.order_claims enable trigger user');
        await cutting.query('alter table audit.events enable trigger user');
        await cutting.query('commit');
        for (const row of saved) await cutting.restoreRow(row);
      } finally {
        await cutting.end();
      }
    }
    // The order asked a third time, on this process, its reads held to J's digest (its alarm in the decisions' log).
    const before3 = lines('audit.integrity_failed').length;
    checkStatesWith(j.digest);
    try {
      const answer = await ask(acting, w, { amount: ALLOWED(), orderReference: 'ORD-77' }).then(
        (request) => request.decision,
        (error: unknown) => (error instanceof Error ? error.message : 'refused'),
      );
      return { answer, alarms: lines('audit.integrity_failed').length - before3 };
    } finally {
      checkStatesWith(undefined);
    }
  }

  it('the order-slot variant: its slots rewritten in place and put back as no one’s, the order asked again is refused', async () => {
    const { answer, alarms } = await orderRewritten(true);
    expect(answer).toMatch(/INTEGRITY_FAILED/);
    expect(alarms).toBeGreaterThan(0);
  });

  it('the order-slot variant’s positive control: not rewritten, the order asked again is an honest duplicate', async () => {
    expect(await orderRewritten(false)).toEqual({ answer: 'DENY', alarms: 0 });
  });

  it.each([
    ['the lease lost through the paying Tx A (its digest writing nothing)', { leaseLost: true }],
    ['the chain given way for memory (its facts dropped)', { digestBytes: 2_000 }],
  ])(
    'no residual: %s, F keeps no stretch, and the rewrite is caught by the next walk from the anchor',
    async (_what, how) => {
      const { w, stopped, submitted } = await cancelledThenRewritten(true, how);
      expect(submitted).toBe(0);
      expect(await outcome(w, stopped.id, submitted)).toMatchObject({ transaction: undefined });
      expect(lines('audit.integrity_failed').length).toBeGreaterThan(0);
    },
  );

  /**
   * A stop above F hidden for one Tx A alone: A paid (F raised), then W suspends the agent (above F, no digest fact yet).
   * The owner hides the suspension and puts the agent's row back as active, holding the chain's head row: J's Tx A for B
   * reads the agent as active, then waits on the head; with `restore`, the owner puts the suspension back before letting
   * go, so the walk reads the true chain (the agent isn't read again after the head's lock; the request is).
   */
  async function stopAboveFHiddenForOneTxA(restore: boolean) {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    const paid = await ask(acting, w, { amount: ALLOWED() });
    await j.witness.refresh();
    expect(await handOffOnJ(w, j)).toBe(1);
    expect(await statusOf(w, paid.id)).toBe('HANDED_OFF');
    // Asked after F rose past A: its decision, and the cancel to come, above F.
    const stopped = await ask(acting, w, { amount: ALLOWED() });
    const owner = await tamperAsOwner(database, AGENTS, w.org);
    try {
      const saved = await owner.saveRow(w.agent);
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
      await j.witness.refresh();
      await owner.query('alter table audit.events disable trigger user');
      await owner.query(
        "update audit.events set subject_id = '0199a0f0-0000-7000-8000-00000000beef' where org_id = $1 and subject_id = $2 and action = 'agent.suspended'",
        [w.org, w.agent],
      );
      await owner.withoutStatusGuard(() => owner.restoreRow(saved));
      const holder = await database.connect('owner');
      try {
        // Inside the organisation, as the owner's tampering is (the tables' walls hold the owner too).
        await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
        await holder.query('begin');
        const locked = await holder.query('select seq from audit.heads where org_id = $1 for update', [w.org]);
        expect(locked).toHaveLength(1);
        capture = new LogCapture();
        const running = handOffOnJ(w, j);
        await waitUntilQueued(database.as('owner'), 1);
        if (restore) {
          await holder.query(
            "update audit.events set subject_id = $2 where org_id = $1 and subject_id = '0199a0f0-0000-7000-8000-00000000beef'",
            [w.org, w.agent],
          );
        }
        await holder.query('commit');
        return { w, stopped, submitted: await running };
      } finally {
        await holder.end();
      }
    } finally {
      await owner.query('alter table audit.events enable trigger user');
      await owner.end();
    }
  }

  /**
   * A cancel in a history hidden for one Tx A alone: A paid (F raised); B approved; then W suspends the agent choosing
   * to cancel (E1) and reactivates it (E2), both above F. The owner moves E1 aside, holding the chain's head row: J's Tx
   * A for B reads the agent as active (E2, the walk's newest too) and no cancel since B's decision; with `restore`, the
   * owner puts E1 back before letting go, so the walk reads it: a cancel B's history read asked for and didn't get.
   */
  async function cancelHiddenFromHistory(restore: boolean) {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    await ask(acting, w, { amount: ALLOWED() });
    await j.witness.refresh();
    expect(await handOffOnJ(w, j)).toBe(1);
    const stopped = await ask(acting, w, { amount: ALLOWED() });
    witnessWith(witnessOver(store));
    try {
      for (const [event, action] of [
        ['suspend', 'agent.suspended'],
        ['reactivate', 'agent.reactivated'],
      ] as const) {
        await signed(w, (tx, states) =>
          states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, event, {
            actor: OPERATOR,
            action,
            details: event === 'suspend' ? { pendingRequests: 'cancel' } : {},
          }),
        );
      }
    } finally {
      witnessWith(undefined);
    }
    await j.witness.refresh();
    const owner = await tamperAsOwner(database, AGENTS, w.org);
    try {
      await owner.query('alter table audit.events disable trigger user');
      await owner.query(
        "update audit.events set subject_id = '0199a0f0-0000-7000-8000-00000000cafe' where org_id = $1 and subject_id = $2 and action = 'agent.suspended'",
        [w.org, w.agent],
      );
      const holder = await database.connect('owner');
      try {
        await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
        await holder.query('begin');
        await holder.query('select seq from audit.heads where org_id = $1 for update', [w.org]);
        capture = new LogCapture();
        const running = handOffOnJ(w, j);
        await waitUntilQueued(database.as('owner'), 1);
        if (restore) {
          await holder.query(
            "update audit.events set subject_id = $2 where org_id = $1 and subject_id = '0199a0f0-0000-7000-8000-00000000cafe'",
            [w.org, w.agent],
          );
        }
        await holder.query('commit');
        return { w, stopped, submitted: await running };
      } finally {
        await holder.end();
      }
    } finally {
      await owner.query('alter table audit.events enable trigger user');
      await owner.end();
    }
  }

  /**
   * An older stop hidden below F for good (the digest keeps each object's newest place alone, residual 75): B asked;
   * W suspends the agent choosing to cancel (E1) and reactivates it (E2), B left approved, as one past the brake's
   * batch is; A asked and paid, its walk raising F past both (B kept out of that run's list by its row's status, put
   * back after). Then, `hide` given, the owner moves E1 to another subject, its hash kept: B's history read finds no
   * cancel since its decision, the agent's newest event is still E2, and the walk from F never reaches E1.
   */
  async function olderStopHiddenBelowF(hide: boolean) {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const j = await jobsCopy(w, store);
    const stopped = await ask(acting, w, { amount: ALLOWED() });
    for (const [event, action] of [
      ['suspend', 'agent.suspended'],
      ['reactivate', 'agent.reactivated'],
    ] as const) {
      await signed(w, (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, event, {
          actor: OPERATOR,
          action,
          details: event === 'suspend' ? { pendingRequests: 'cancel' } : {},
        }),
      );
    }
    const paid = await ask(acting, w, { amount: ALLOWED() });
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      const saved = await owner.saveRow(stopped.id);
      await owner.withoutStatusGuard(() =>
        owner.query("update spend_requests.requests set status = 'CANCELLED' where org_id = $1 and id = $2", [
          w.org,
          stopped.id,
        ]),
      );
      await j.witness.refresh();
      expect(await handOffOnJ(w, j)).toBe(1);
      expect(await statusOf(w, paid.id)).toBe('HANDED_OFF');
      await owner.withoutStatusGuard(() => owner.restoreRow(saved));
      if (hide) {
        await owner.query('alter table audit.events disable trigger user');
        await owner.query(
          "update audit.events set subject_id = '0199a0f0-0000-7000-8000-00000000c0de' where org_id = $1 and subject_id = $2 and action = 'agent.suspended'",
          [w.org, w.agent],
        );
        await owner.query('alter table audit.events enable trigger user');
      }
    } finally {
      await owner.end();
    }
    expect(await statusOf(w, stopped.id)).toBe('APPROVED');
    capture = new LogCapture();
    return { w, stopped, submitted: await handOffOnJ(w, j) };
  }

  it('75: an older cancel hidden below F for good, the agent reactivated since: never paid, the alarm', async () => {
    const { w, stopped, submitted } = await olderStopHiddenBelowF(true);
    expect(submitted).toBe(0);
    expect(await outcome(w, stopped.id, submitted)).toMatchObject({ transaction: undefined });
    expect(lines('audit.integrity_failed').length).toBeGreaterThan(0);
  });

  it('75’s positive control: not hidden, the cancel is read and the request never paid, nothing alarmed', async () => {
    const { submitted } = await olderStopHiddenBelowF(false);
    expect(submitted).toBe(0);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('a stop hidden for every Tx A in a row: each waits, and the fifth in a row is the error (someone at it)', async () => {
    const store = createFakeWriteOnceStore();
    const { w, acting } = await ready();
    const leads = { now: true };
    const j = await jobsCopy(w, store, new Map(), { writes: () => leads.now });
    await ask(acting, w, { amount: ALLOWED() });
    await j.witness.refresh();
    expect(await handOffOnJ(w, j)).toBe(1);
    const stopped = await ask(acting, w, { amount: ALLOWED() });
    const owner = await tamperAsOwner(database, AGENTS, w.org);
    try {
      // The agent's row as it was, active, before the suspension.
      const saved = await owner.saveRow(w.agent);
      await signed(w, (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
          actor: OPERATOR,
          action: 'agent.suspended',
          details: { pendingRequests: 'pause' },
        }),
      );
      // This copy no longer keeping facts (its lease gone mid-run each time): each run's reads stand on the rows alone.
      leads.now = false;
      capture = new LogCapture();
      // One process's hand-off, run again and again: its count of reads moved in a row kept between runs.
      const handOff = handOffMadeOnJ(w, j);
      await owner.query('alter table audit.events disable trigger user');
      for (let run = 0; run < 5; run += 1) {
        await owner.query(
          "update audit.events set subject_id = '0199a0f0-0000-7000-8000-00000000f00d' where org_id = $1 and subject_id = $2 and action = 'agent.suspended'",
          [w.org, w.agent],
        );
        await owner.withoutStatusGuard(() => owner.restoreRow(saved));
        const holder = await database.connect('owner');
        try {
          await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
          await holder.query('begin');
          await holder.query('select seq from audit.heads where org_id = $1 for update', [w.org]);
          const running = handOff.run();
          await waitUntilQueued(database.as('owner'), 1);
          await holder.query(
            "update audit.events set subject_id = $2 where org_id = $1 and subject_id = '0199a0f0-0000-7000-8000-00000000f00d'",
            [w.org, w.agent],
          );
          await holder.query('commit');
          expect(await running).toBe(0);
        } finally {
          await holder.end();
        }
      }
    } finally {
      await owner.query('alter table audit.events enable trigger user');
      await owner.end();
    }
    expect(await statusOf(w, stopped.id)).toBe('APPROVED');
    expect(lines('handoff.read_moved')).toHaveLength(5);
    expect(lines('handoff.read_moved_repeatedly')).toEqual([expect.objectContaining({ level: 'error', times: 5 })]);
  });

  it('80: a cancel hidden from Tx A’s history read and put back before its walk: never paid', async () => {
    const { w, stopped, submitted } = await cancelHiddenFromHistory(true);
    expect(submitted).toBe(0);
    expect(await outcome(w, stopped.id, submitted)).toMatchObject({ transaction: undefined });
    // Caught before the walk since residual 75: the agent's state (E2) names E1, and the read didn't get it.
    expect(lines('audit.integrity_failed').length).toBeGreaterThan(0);
  });

  it('80: a stop above F hidden while Tx A reads and put back before its walk: never paid', async () => {
    const { w, stopped, submitted } = await stopAboveFHiddenForOneTxA(true);
    expect(submitted).toBe(0);
    expect(await outcome(w, stopped.id, submitted)).toMatchObject({ transaction: undefined });
    expect(lines('handoff.waiting')).toContainEqual(expect.objectContaining({ why: 'read_moved' }));
  });

  it('the positive control: left hidden, the read and the walk agree and nothing stops the payment here', async () => {
    const { submitted } = await stopAboveFHiddenForOneTxA(false);
    // The rewrite left in place: its event's MAC no longer holds, so the walk itself refuses (not this check's).
    expect(submitted).toBe(0);
    expect(lines('handoff.waiting')).not.toContainEqual(expect.objectContaining({ why: 'read_moved' }));
  });

  it('the positive control: not rewritten, the cancelled request is never handed off, and nothing is alarmed', async () => {
    const { w, stopped, submitted } = await cancelledThenRewritten(false);
    expect(submitted).toBe(0);
    expect(await statusOf(w, stopped.id)).toBe('CANCELLED');
    expect(lines('audit.integrity_failed')).toEqual([]);
  });
});

describe('SEC-DB-20 TR-3 residual 75: each history read a request rests on held to what its object’s state names', () => {
  const HIDE = 'hide-me';

  /**
   * On one object of `table`: each of `made` recorded in turn as a signed state event (the one whose details carry
   * HIDE marked), then one more (so the marked one is no longer the newest); with `hide`, the owner moves the marked
   * event to another subject, its hash kept. Then `read` twice in the organisation's transaction: held to the object's
   * verified state, and from the log alone (the read as it was before). Each answer, or its refusal; and whether the
   * organisation is held after.
   */
  async function olderEventHidden<T>(
    table: SignedStateTable,
    idOf: (w: World, acting: Awaited<ReturnType<typeof ready>>['acting']) => Promise<string>,
    made: readonly (readonly [string, AuditDetails])[],
    hide: boolean,
    read: (tx: AuditTransaction, states: SignedStates, orgId: string, id: string, state?: VerifiedState) => Promise<T>,
  ) {
    const { w, acting } = await ready();
    const id = await idOf(w, acting);
    for (const [action, details] of [...made, ['test.noted', {}] as const]) {
      await signed(w, async (tx, states) => {
        const state = await states.verifiedState(tx, table, { orgId: w.org, id }, 'change');
        if (state.outcome !== 'verified') throw new Error('the object should verify');
        await states.record(tx, table, { orgId: w.org, id }, state, {}, { actor: OPERATOR, action, details });
      });
    }
    if (hide) {
      await asOwner(w, async (owner) => {
        await owner.query('alter table audit.events disable trigger user');
        await owner.query(
          'update audit.events set subject_id = gen_random_uuid() where org_id = $1 and subject_id = $2 and strpos(details, $3) > 0',
          [w.org, id, HIDE],
        );
        await owner.query('alter table audit.events enable trigger user');
      });
    }
    const answer = (held: boolean) =>
      signed(w, async (tx, states) => {
        const state = await states.verifiedState(tx, table, { orgId: w.org, id }, 'share');
        if (state.outcome !== 'verified') throw new Error('the object should verify');
        return read(tx, states, w.org, id, held ? state : undefined);
      }).then(
        (value) => ({ value }),
        (error: unknown) => ({ refused: error instanceof Error ? error.message : String(error) }),
      );
    const unheld = await answer(false);
    const held = await answer(true);
    const hold = await signed(w, (tx, states) => states.integrityHold(tx, w.org, 'none'));
    return { held, unheld, onHold: hold.outcome === 'held' };
  }

  const theAgent = (w: World) => Promise.resolve(w.agent);
  const theSource = (w: World) => Promise.resolve(w.source);
  const theMandate = async (w: World) => {
    let id = '';
    await asOwner(w, async (owner) => {
      const [row] = await owner.query<{ id: string }>('select id from mandates.mandates where org_id = $1', [w.org]);
      id = row?.id ?? '';
    });
    return id;
  };

  const pausedRead = (tx: AuditTransaction, states: SignedStates, orgId: string, id: string, state?: VerifiedState) =>
    pausedOf(tx, states, orgId, [['agent', id, 'SUSPENDED', state]]).then((paused) => paused.has('agent'));
  const suspendedTwice = [
    ['agent.suspended', { pendingRequests: 'pause' }],
    ['agent.suspended', { pendingRequests: 'cancel', testMark: HIDE }],
  ] as const;

  it('pausedOf: a cancel over a pause hidden, the pause read as in force from the log alone; held, refused, the alarm', async () => {
    const { held, unheld, onHold } = await olderEventHidden(AGENTS, theAgent, suspendedTwice, true, pausedRead);
    expect(unheld).toEqual({ value: true });
    expect('refused' in held && held.refused).toMatch(/can't be believed/);
    expect(onHold).toBe(true);
  });

  it('pausedOf’s positive control: nothing hidden, the cancel in force, held or not, and no hold', async () => {
    const { held, unheld, onHold } = await olderEventHidden(AGENTS, theAgent, suspendedTwice, false, pausedRead);
    expect([held, unheld, onHold]).toEqual([{ value: false }, { value: false }, false]);
  });

  const expiryRead = (tx: AuditTransaction, states: SignedStates, orgId: string, id: string, state?: VerifiedState) =>
    consentExpiryOf(tx, states, orgId, id, state);
  const chosenTwice = [
    [CONSENT_EXPIRY_CHOSEN, { pendingRequests: 'pause' }],
    [CONSENT_EXPIRY_CHOSEN, { pendingRequests: 'cancel', testMark: HIDE }],
  ] as const;

  it('consentExpiryOf: the newest choice (cancel) hidden, an older hold read from the log alone; held, refused', async () => {
    const { held, unheld, onHold } = await olderEventHidden(SOURCES, theSource, chosenTwice, true, expiryRead);
    expect(unheld).toEqual({ value: 'pause' });
    expect('refused' in held && held.refused).toMatch(/can't be believed/);
    expect(onHold).toBe(true);
  });

  it('consentExpiryOf’s positive control: nothing hidden, the cancel read, held or not', async () => {
    const { held, unheld, onHold } = await olderEventHidden(SOURCES, theSource, chosenTwice, false, expiryRead);
    expect([held, unheld, onHold]).toEqual([{ value: 'cancel' }, { value: 'cancel' }, false]);
  });

  const carryRead = (tx: AuditTransaction, states: SignedStates, orgId: string, id: string, state?: VerifiedState) =>
    carriesRest(tx, states, orgId, { id, currentVersionId: null }, state);
  const acceptedTwice = [
    ['mandate.accepted', { carryRest: true }],
    ['mandate.accepted', { carryRest: false, testMark: HIDE }],
  ] as const;

  it('carriesRest: the newest acceptance hidden, an older one carrying the rest read from the log alone; held, refused', async () => {
    const { held, unheld, onHold } = await olderEventHidden(MANDATES, theMandate, acceptedTwice, true, carryRead);
    expect(unheld).toEqual({ value: true });
    expect('refused' in held && held.refused).toMatch(/can't be believed/);
    expect(onHold).toBe(true);
  });

  it('carriesRest’s positive control: nothing hidden, the newest acceptance read, held or not', async () => {
    const { held, unheld, onHold } = await olderEventHidden(MANDATES, theMandate, acceptedTwice, false, carryRead);
    expect([held, unheld, onHold]).toEqual([{ value: false }, { value: false }, false]);
  });

  const aRequest = async (w: World, acting: Awaited<ReturnType<typeof ready>>['acting']) =>
    (await ask(acting, w, { amount: ALLOWED() })).id;
  const keptRead = (tx: AuditTransaction, states: SignedStates, orgId: string, id: string, state?: VerifiedState) =>
    // None answered for a history that can't be believed (decisionsOf): `unread`, never "not kept".
    decisionsOf(tx, states, orgId, [id], state && new Map([[id, state]])).then(
      (read) => read.get(id)?.capacityKept ?? 'unread',
    );
  const endedKept = [
    ['spend_request.cancelled', { capacityKept: true, keptAmountMinor: '1', testMark: HIDE }],
  ] as const;

  it('decisionsRead: an ending that kept its capacity hidden, none kept from the log alone; held, tampered', async () => {
    const { held, unheld, onHold } = await olderEventHidden(SPEND_REQUESTS, aRequest, endedKept, true, keptRead);
    expect(unheld).toEqual({ value: false });
    expect(held).toEqual({ value: 'unread' });
    expect(onHold).toBe(true);
  });

  /** A table as an image from before the names had it: tracking nothing. */
  const untracked = <Table extends SignedStateTable>(table: Table): Table =>
    Object.fromEntries(Object.entries(table).filter(([column]) => column !== 'tracks')) as Table;

  /**
   * An organisation recorded before the names (state-names.ts): its own state and its agent's recorded again with the
   * names left off (each table's tracks dropped, as an image from before them wrote), the agent suspended choosing to
   * cancel (E1) and reactivated (E2) the same way. Then, with `named`, the job names them, its chain checked whole.
   */
  async function legacyOrganisation(named: boolean, walked?: (w: World) => Promise<void>) {
    const { w, acting } = await ready();
    const LEGACY_ORG = untracked(ORGANIZATIONS);
    const LEGACY_AGENTS = untracked(AGENTS);
    await signed(w, async (tx, states) => {
      const own = await states.verifiedState(tx, LEGACY_ORG, { orgId: w.org, id: w.org }, 'change');
      if (own.outcome !== 'verified') throw new Error('the organisation should verify');
      await states.record(
        tx,
        LEGACY_ORG,
        { orgId: w.org, id: w.org },
        own,
        {},
        { actor: OPERATOR, action: 'test.noted', details: {} },
      );
    });
    for (const [event, action] of [
      ['suspend', 'agent.suspended'],
      ['reactivate', 'agent.reactivated'],
    ] as const) {
      await signed(w, (tx, states) =>
        states.changeStatus(tx, LEGACY_AGENTS, { orgId: w.org, id: w.agent }, event, {
          actor: OPERATOR,
          action,
          details: event === 'suspend' ? { pendingRequests: 'cancel' } : {},
        }),
      );
    }
    capture = new LogCapture();
    const job = createStateNames({
      ...(walked === undefined ? {} : { walked: () => walked(w) }),
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });
    if (named) await job.run();
    return { w, acting, job };
  }

  /** The agent's cancel since `decidedSeq` read held to its state and the organisation's: the cancels found, or the refusal. */
  const cancelsHeld = (w: World, decidedSeq: bigint) =>
    signed(w, async (tx, states) => {
      const held = await stopsHeldOf(tx, states, w.org, {
        organization: w.org,
        agent: w.agent,
        mandate: null,
        source: null,
        supplier: null,
      });
      return cancelledSinceOf(
        tx,
        states,
        w.org,
        decidedSeq,
        { organization: w.org, agent: w.agent, mandate: null, source: null, supplier: null },
        undefined,
        held,
      );
    }).then(
      (cancelled) => ({ value: [...cancelled] }),
      (error: unknown) => ({ refused: error instanceof Error ? error.message : String(error) }),
    );

  const hideTheCancel = (w: World) =>
    asOwner(w, async (owner) => {
      await owner.query('alter table audit.events disable trigger user');
      await owner.query(
        "update audit.events set subject_id = gen_random_uuid() where org_id = $1 and subject_id = $2 and action = 'agent.suspended'",
        [w.org, w.agent],
      );
      await owner.query('alter table audit.events enable trigger user');
    });

  it('state names: a legacy organisation named once its chain checks out whole; then its older cancel can’t be hidden', async () => {
    const { w, job } = await legacyOrganisation(true);
    // Its agent and its own state: each named once, from its whole history.
    expect(lines('state_names.named')).toEqual([expect.objectContaining({ named: 2 })]);
    // Named again (the same job, its log the same): nothing more, the organisation reaching its start, no second line.
    await job.run();
    expect(lines('state_names.named')).toHaveLength(1);
    await hideTheCancel(w);
    expect(await cancelsHeld(w, 0n)).toEqual({ refused: expect.stringMatching(/can't be believed/) as string });
  });

  it('state names’ positive control: not named, the legacy cancel hidden is read as none (read as before)', async () => {
    const { w } = await legacyOrganisation(false);
    await hideTheCancel(w);
    expect(await cancelsHeld(w, 0n)).toEqual({ value: [] });
  });

  it('state names: a chain that doesn’t check out whole names nothing, and says so', async () => {
    const { w, job } = await legacyOrganisation(false);
    await hideTheCancel(w);
    await job.run();
    expect(lines('state_names.chain_unverified')).toEqual([expect.objectContaining({ level: 'warn' })]);
    expect(lines('state_names.named')).toEqual([]);
  });

  /** Whether the organisation's and its agent's states carry names where they must (authorityOf's check), and the hold. */
  const namesHeld = async (w: World) => {
    const held = await signed(w, async (tx, states) => {
      const on = await stopsHeldOf(tx, states, w.org, {
        organization: w.org,
        agent: w.agent,
        mandate: null,
        source: null,
        supplier: null,
      });
      return on !== undefined && states.historyHeld(w.org, [], { on, actions: [], after: undefined });
    });
    const hold = await signed(w, (tx, states) => states.integrityHold(tx, w.org, 'none'));
    return { held, onHold: hold.outcome === 'held' };
  };

  /** A pending request's authority read as the voids job and Tx A read it: its refusal, or none. */
  const authorityRefusal = (w: World, requestId: string) =>
    signed(w, (tx, states) => authorityOf(tx, states, { orgId: w.org, id: requestId }, clock.now())).then(
      () => undefined,
      (error: unknown) => (error instanceof Error ? error.message : String(error)),
    );

  /** The agent's state recorded again with no names, as the app's older code records it (a copy draining, a rollback). */
  const recordedByOlderCode = (w: World) =>
    signed(w, async (tx, states) => {
      const LEGACY_AGENTS = untracked(AGENTS);
      const agent = await states.verifiedState(tx, LEGACY_AGENTS, { orgId: w.org, id: w.agent }, 'change');
      if (agent.outcome !== 'verified') throw new Error('the agent should verify');
      await states.record(
        tx,
        LEGACY_AGENTS,
        { orgId: w.org, id: w.agent },
        agent,
        {},
        { actor: OPERATOR, action: 'test.noted', details: {} },
      );
    });

  it('80: once named, a state with no names written after it (the app’s older code) holds nothing, read as before', async () => {
    const { w, acting } = await legacyOrganisation(true);
    const pending = await ask(acting, w, { amount: ALLOWED() });
    await recordedByOlderCode(w);
    expect(await authorityRefusal(w, pending.id)).toBeUndefined();
    expect(await namesHeld(w)).toEqual({ held: true, onHold: false });
  });

  it('the cut-over: a state with no names from before its organisation was named (one the naming missed) is the gap', async () => {
    const { w, acting } = await legacyOrganisation(false);
    const pending = await ask(acting, w, { amount: ALLOWED() });
    // The organisation's own state named whole, its agent missed (as a naming that skipped it would leave it).
    await signed(w, async (tx, states) => {
      const own = await states.verifiedState(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'change');
      if (own.outcome !== 'verified') throw new Error('the organisation should verify');
      await states.renamed(
        tx,
        ORGANIZATIONS,
        { orgId: w.org, id: w.org },
        own,
        { from: 0n, last: new Map() },
        {
          actor: OPERATOR,
          action: historyNamedOf(ORGANIZATIONS.subject),
          details: {},
        },
      );
    });
    expect(await authorityRefusal(w, pending.id)).toMatch(/carries no names where it must/);
    expect(await namesHeld(w)).toEqual({ held: false, onHold: true });
  });

  it('3: an event moved between the walk and the naming is named all the same, from what the walk read', async () => {
    // Moved to a type no table lists (one moved to another agent's ID would be an object of its own, not believed).
    const movedAside = (w: World) =>
      asOwner(w, async (owner) => {
        await owner.query('alter table audit.events disable trigger user');
        await owner.query(
          "update audit.events set subject_type = 'moved_aside' where org_id = $1 and subject_id = $2 and action = 'agent.suspended'",
          [w.org, w.agent],
        );
        await owner.query('alter table audit.events enable trigger user');
      });
    const { w } = await legacyOrganisation(true, movedAside);
    expect(lines('state_names.failed')).toEqual([]);
    expect(lines('state_names.named')).toEqual([expect.objectContaining({ named: 2, left: 0 })]);
    expect(await cancelsHeld(w, 0n)).toEqual({ refused: expect.stringMatching(/can't be believed/) as string });
  });

  it('3: an object recorded again after the walk is left for the next run, and its organisation not named yet', async () => {
    let once = false;
    const { job } = await legacyOrganisation(true, async (at) => {
      if (once) return;
      once = true;
      await recordedByOlderCode(at);
    });
    expect(lines('state_names.named')).toEqual([expect.objectContaining({ named: 0, left: 1 })]);
    await job.run();
    expect(lines('state_names.named')).toEqual([
      expect.objectContaining({ left: 1 }),
      expect.objectContaining({ named: 2, left: 0 }),
    ]);
  });

  it('state names: an object that can’t be believed is the organisation’s failure, logged, nothing claimed named', async () => {
    const { w, job } = await legacyOrganisation(false);
    await asOwner(w, async (owner) => {
      await owner.withoutStatusGuard(() =>
        owner.query("update agents.agents set status = 'SUSPENDED' where org_id = $1 and id = $2", [w.org, w.agent]),
      );
    });
    await job.run();
    expect(lines('state_names.failed')).toEqual([expect.objectContaining({ level: 'error', orgId: w.org })]);
    expect(lines('state_names.named')).toEqual([]);
  });

  it('state names: a list that can’t be read is the run’s failure; an aborted run starts nothing', async () => {
    capture = new LogCapture();
    const failing = createStateNames({
      list: () => Promise.reject(new Error('directory down')),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });
    await failing.run();
    expect(lines('state_names.run_failed')).toEqual([expect.objectContaining({ level: 'error' })]);
    const { w, job } = await legacyOrganisation(false);
    await job.run(AbortSignal.abort());
    expect(lines('state_names.named')).toEqual([]);
    expect(await namesHeld(w)).toEqual({ held: true, onHold: false });
  });

  it('the cut-over’s positive control: not named, a legacy state with no names is read as before', async () => {
    const { w } = await legacyOrganisation(false);
    expect(await namesHeld(w)).toEqual({ held: true, onHold: false });
  });

  it('decisionsRead’s positive control: nothing hidden, the capacity kept, held or not', async () => {
    const { held, unheld, onHold } = await olderEventHidden(SPEND_REQUESTS, aRequest, endedKept, false, keptRead);
    expect([held, unheld, onHold]).toEqual([{ value: true }, { value: true }, false]);
  });
});

describe('SEC-DB-20 TR-1 (13): a walk past its reach', () => {
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

describe('SEC-DB-20 TR-1 (6): the pause hidden for a moment', () => {
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
