// TR-1 (S209): a stop written on one copy, the chain cut back below it, read by another. Two copies over one database
// and one witness store: W (a web copy) suspends the agent, its head witnessed before the answer; the owner, holding no
// app key, cuts the chain's end off (the suspension's events gone, an earlier sealed head put back, the agent's row as
// it was). J (the jobs copy) never read the suspension: its own digest holds only the chain's anchor, which the cut
// keeps. Before TR-1 its Tx A paid (the positive control); held to the heads W witnessed, Tx A, the anchor check's probe
// and its walk each find the cut. Section 1.8 of the plan: tests (1), (7) and (10); (5)'s walk; (8) and (14) live in
// month-totals.db.test.ts.
import { AGENTS } from '@agentx/core/modules/agents';
import {
  checkStatesWith,
  createAuditTrail,
  holdOrganisation,
  withSignedStates,
  witnessWith,
  WriteCutBack,
} from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import {
  type AnchorStore,
  CHAIN_START,
  createDigestLog,
  createMemoryAnchorStore,
  createWitnessLog,
  type DigestLog,
  signAnchor,
  type WitnessLog,
  WitnessUnconfirmed,
} from '@agentx/platform/audit-chain';
import { createDatabase, createIdempotentWrites, type Database } from '@agentx/platform/db';
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  type FakeWriteOnceStore,
  FixedClock,
  LogCapture,
  type SavedHead,
  type SavedRow,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createAnchorCheck } from './anchor-check.ts';
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

const ids = new SequentialIds(0x7b1e_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x7b1f_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'witness-cut',
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

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  operator = createDatabase<HandoffWorldTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  // Born paused (ADR-014 §4): resumed, as the operator would once the hand-off is live.
  await operator
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: false, reason: 'TEST-TR1C', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );
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
const witnessOver = (store: FakeWriteOnceStore, waitMs?: number): WitnessLog =>
  createWitnessLog({
    store: store.store,
    keys,
    logger: testLogger(capture),
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: 60_000,
    mostBytes: 1024 * 1024,
    ...(waitMs === undefined ? {} : { waitMs }),
  });

/** The owner's own statements, inside the organisation, the connection ended after. */
async function asOwner(w: World, run: (owner: Awaited<ReturnType<typeof tamperAsOwner>>) => Promise<void>) {
  const owner = await tamperAsOwner(database, AGENTS, w.org);
  try {
    await run(owner);
  } finally {
    await owner.end();
  }
}

/**
 * The jobs copy J as it stands after its anchor check's walk of the chain: its digest covering the chain to its head,
 * anchored there; held to the heads the store witnessed where `witness` is given (TR-1), else as before TR-1.
 */
async function jobsCopy(
  w: World,
  witness: WitnessLog | undefined,
): Promise<{ digest: DigestLog; anchors: AnchorStore }> {
  const digest = createDigestLog({
    store: createFakeWriteOnceStore().store,
    keys,
    logger: testLogger(capture),
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: 60_000,
    mostBytes: 64 * 1024 * 1024,
    ...(witness === undefined ? {} : { witnessed: (orgChain) => witness.pending(orgChain) }),
  });
  const orgChain = { kind: 'organisation', orgId: w.org } as const;
  const walked = await createAuditTrail({ keys, ids }).checkFromAnchor(app, w.org, CHAIN_START);
  if (!walked.ok || walked.signed === undefined) throw new Error('The chain should have checked out');
  await digest.read();
  digest.record(orgChain, walked.signed, clock.now(), { from: 0n, to: walked });
  const anchors = createMemoryAnchorStore();
  anchors.keep(signAnchor(keys, orgChain, walked, clock.now()));
  witness?.useAnchors({ rebasedAfter: () => false, latest: (each) => anchors.latest(each) });
  return { digest, anchors };
}

/**
 * The attack, up to Tx A: J walked and anchored; the agent suspended on W, its head witnessed there before the answer;
 * the owner cuts the suspension off. What the owner kept, and the request waiting for its hand-off.
 */
async function suspendedOnWThenCut(store: FakeWriteOnceStore, witnessOnJ: boolean, jReadsFirst = true) {
  const { w, acting } = await ready();
  const request = await ask(acting, w, { amount: ALLOWED() });
  const jWitness = witnessOnJ ? witnessOver(store) : undefined;
  const j = await jobsCopy(w, jWitness);
  let row: SavedRow | undefined;
  let head: SavedHead | undefined;
  await asOwner(w, async (owner) => {
    row = await owner.saveRow(w.agent);
    head = await owner.saveHead();
  });
  // W: its own witness log; its answer waited for the suspension's head to land in the store (`now`).
  witnessWith(witnessOver(store));
  await signed(w, (tx, states) =>
    states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
      actor: OPERATOR,
      action: 'agent.suspended',
      details: { reason: 'test' },
    }),
  );
  witnessWith(undefined);
  expect(store.files.size).toBe(1);
  await asOwner(w, async (owner) => {
    if (row === undefined || head === undefined) throw new Error('nothing saved');
    const [saved, back] = [row, head];
    await owner.windBack(back);
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));
  });
  // J reads the store as its job does (unless its job hasn't come round yet), then holds every read to its digest.
  if (jReadsFirst) await jWitness?.refresh();
  checkStatesWith(j.digest);
  witnessWith(jWitness);
  return { w, acting, request, j, jWitness, head };
}

/** J's hand-off run, every call to the partner counted. */
async function handOffOnJ(w: World, j: { digest: DigestLog; anchors: AnchorStore }): Promise<number> {
  let submitted = 0;
  const rail = {
    ...w.rail,
    submitApprovedIntent: (intent: Parameters<typeof w.rail.submitApprovedIntent>[0]) => {
      submitted += 1;
      return w.rail.submitApprovedIntent(intent);
    },
  };
  await createHandoff({
    anchoring: { anchors: j.anchors, anchorFirst: () => Promise.resolve(), digest: j.digest },
    list: () => Promise.resolve([w.org]),
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
  return submitted;
}

describe('TR-1 (1): a stop on one copy, the chain cut back below it, and the jobs copy’s Tx A', () => {
  it('the positive control: J held to its own heads alone (before TR-1) pays the request the stop should have stopped', async () => {
    const store = createFakeWriteOnceStore();
    const { w, request, j } = await suspendedOnWThenCut(store, false);
    expect(await handOffOnJ(w, j)).toBe(1);
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('held to the heads W witnessed: no call to the partner, the alarm at the stop’s head, the organisation held', async () => {
    const store = createFakeWriteOnceStore();
    const { w, request, j, head } = await suspendedOnWThenCut(store, true);
    expect(await handOffOnJ(w, j)).toBe(0);
    expect(await paymentOf(w, request.id)).toEqual({ instruction: 'missing' });
    expect(await statusOf(w, request.id)).not.toBe('HANDED_OFF');
    const cutAt = lines('audit.integrity_failed').map(({ seq }) => BigInt(String(seq)));
    expect(cutAt.length).toBeGreaterThan(0);
    expect(cutAt.every((seq) => seq > BigInt(head?.seq ?? 'x'))).toBe(true);
    checkStatesWith(undefined);
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });
});

describe('TR-1 (7), (5): the anchor check held to the heads witnessed', () => {
  /** J's anchor check over the real trail, its probe and walks held to J's witness log where given. */
  function anchorCheckOnJ(w: World, j: { anchors: AnchorStore }, witness: WitnessLog | undefined) {
    const trail = createAuditTrail({ keys, ids });
    return createAnchorCheck({
      chains: [],
      organizations: {
        list: () => Promise.resolve([w.org]),
        recorded: () => Promise.resolve([w.org]),
        probe: (chains, signal, pages) => trail.probeHeads(app, chains, signal, pages),
        verify: (orgId, anchor, heldTo) => trail.checkFromAnchor(app, orgId, anchor ?? CHAIN_START, undefined, heldTo),
        hold: (orgId, failure) => holdOrganisation(app, orgId, { keys, ids, logger: testLogger(capture) }, failure),
      },
      keys,
      clock,
      logger: testLogger(capture),
      staleAfterMs: 900_000,
      deadlineMs: 120_000,
      anchors: j.anchors,
      witness,
    });
  }

  it('the probe finds a chain cut back below a witnessed head: the alarm (`witness`) and the hold; without it, unchanged', async () => {
    const control = await suspendedOnWThenCut(createFakeWriteOnceStore(), false);
    await anchorCheckOnJ(control.w, control.j, undefined).run();
    expect(lines('audit.integrity_failed')).toEqual([]);
    expect(lines('audit.anchor_check_done').at(-1)).toMatchObject({ unchanged: 1, failed: 0 });

    const { w, j, jWitness } = await suspendedOnWThenCut(createFakeWriteOnceStore(), true);
    await anchorCheckOnJ(w, j, jWitness).run();
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back', chain: 'organisation' }),
    );
    checkStatesWith(undefined);
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });

  it('a chain grown again on the cut: the walk from the anchor refuses to anchor through the head it missed; without it, it anchors', async () => {
    const { w, j, jWitness, head } = await suspendedOnWThenCut(createFakeWriteOnceStore(), true);
    // A copy that never saw the stop writes on the cut chain (it goes on from the cut): the chain moved, every link sound.
    checkStatesWith(undefined);
    witnessWith(undefined);
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: { reason: 'a stale copy' },
      }),
    );
    const trail = createAuditTrail({ keys, ids });
    const anchor = j.anchors.latest({ kind: 'organisation', orgId: w.org });
    if (anchor === undefined || head === undefined) throw new Error('anchored and saved above');
    // Row mixing (5): every row the walk reads is sealed and linked; only the hash at the witnessed place tells.
    expect(await trail.checkFromAnchor(app, w.org, anchor)).toMatchObject({ ok: true });
    const witnessedHeads = jWitness?.pending({ kind: 'organisation', orgId: w.org }) ?? [];
    expect(witnessedHeads.length).toBeGreaterThan(0);
    expect(await trail.checkFromAnchor(app, w.org, anchor, undefined, witnessedHeads)).toEqual({
      ok: false,
      problem: { reason: 'cut_back', seq: witnessedHeads[0]?.seq },
    });
    await anchorCheckOnJ(w, j, jWitness).run();
    // Never anchored past the cut: the anchor stays where the walk began.
    expect(j.anchors.latest({ kind: 'organisation', orgId: w.org })?.seq).toBe(anchor.seq);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back' }),
    );
  });
});

describe('TR-1 review finding 1: the anchor check on a witness view older than the run', () => {
  it('reads the store first: a stop J had not listed yet, cut and grown again on, is the alarm, never anchored past', async () => {
    const { w, j, jWitness } = await suspendedOnWThenCut(createFakeWriteOnceStore(), true, false);
    expect(jWitness?.pending({ kind: 'organisation', orgId: w.org })).toEqual([]);
    checkStatesWith(undefined);
    witnessWith(undefined);
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: { reason: 'a stale copy' },
      }),
    );
    const anchor = j.anchors.latest({ kind: 'organisation', orgId: w.org });
    const trail = createAuditTrail({ keys, ids });
    const check = createAnchorCheck({
      chains: [],
      organizations: {
        list: () => Promise.resolve([w.org]),
        recorded: () => Promise.resolve([w.org]),
        probe: (chains, signal, pages) => trail.probeHeads(app, chains, signal, pages),
        verify: (orgId, from, heldTo) => trail.checkFromAnchor(app, orgId, from ?? CHAIN_START, undefined, heldTo),
        hold: (orgId, failure) => holdOrganisation(app, orgId, { keys, ids, logger: testLogger(capture) }, failure),
      },
      keys,
      clock,
      logger: testLogger(capture),
      staleAfterMs: 900_000,
      deadlineMs: 120_000,
      anchors: j.anchors,
      witness: jWitness,
    });
    // The walk was asked nothing (J hadn't listed the stop): before signing, a read begun after it finds the stop at or
    // below where it reached, never asked of it, so nothing is anchored this run.
    await check.run();
    expect(j.anchors.latest({ kind: 'organisation', orgId: w.org })?.seq).toBe(anchor?.seq);
    // The next walk is asked it, and finds the cut.
    await check.run();
    expect(j.anchors.latest({ kind: 'organisation', orgId: w.org })?.seq).toBe(anchor?.seq);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back' }),
    );
  });
});

describe('TR-1 review finding 2: a retry answered from the stored result', () => {
  /** The agent's suspension under one idempotency key, as a route runs it, through the signed states. */
  const suspendUnderKey = (w: World, key: string) => {
    const idempotency = createIdempotentWrites({ keys, logger: testLogger(capture) });
    const request = {
      orgId: w.org,
      client: { kind: 'agent' as const, id: w.agent },
      operation: 'agents.suspend',
      key,
      payload: '{}',
    };
    // Its lines in the test's capture: the alarm is what it says.
    return () =>
      withSignedStates(app, w.org, { keys, ids, logger: testLogger(capture) }, (tx, states) =>
        idempotency.run(tx, request, async () => {
          await states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
            actor: OPERATOR,
            action: 'agent.suspended',
            details: { reason: 'test' },
          });
          return { status: 200, resourceId: w.agent };
        }),
      );
  };

  /** The first answer: saved, the witness store down, a 503 for it. What the owner kept from before it. */
  async function savedUnwitnessed(w: World, suspend: () => Promise<unknown>) {
    let head: SavedHead | undefined;
    let row: SavedRow | undefined;
    await asOwner(w, async (owner) => {
      head = await owner.saveHead();
      row = await owner.saveRow(w.agent);
    });
    const down = createFakeWriteOnceStore();
    down.instead.put = () => Promise.reject(new Error('store down'));
    witnessWith(witnessOver(down, 100));
    await expect(suspend()).rejects.toBeInstanceOf(WitnessUnconfirmed);
    witnessWith(undefined);
    if (head === undefined || row === undefined) throw new Error('nothing saved');
    return { head, row };
  }

  it('on another copy, holds the chain to the head the write left, then witnesses the head as it stands before it answers', async () => {
    const { w } = await ready();
    const suspend = suspendUnderKey(w, 'tr1-replay-key');
    await savedUnwitnessed(w, suspend);
    const up = createFakeWriteOnceStore();
    witnessWith(witnessOver(up));
    expect(await suspend()).toMatchObject({ result: { status: 200, resourceId: w.agent } });
    witnessWith(undefined);
    let head: SavedHead | undefined;
    await asOwner(w, async (owner) => {
      head = await owner.saveHead();
    });
    const reader = witnessOver(up);
    await reader.refresh();
    expect(reader.pending({ kind: 'organisation', orgId: w.org }).map(({ seq }) => seq)).toEqual([
      BigInt(head?.seq ?? 'x'),
    ]);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('the write cut out since (its head gone, the owner back to before it): the alarm and the hold, and never the stored answer', async () => {
    const { w } = await ready();
    const suspend = suspendUnderKey(w, 'tr1-replay-cut');
    const { head, row } = await savedUnwitnessed(w, suspend);
    await asOwner(w, async (owner) => {
      await owner.windBack(head);
      await owner.withoutStatusGuard(() => owner.restoreRow(row));
    });
    const up = createFakeWriteOnceStore();
    witnessWith(witnessOver(up));
    await expect(suspend()).rejects.toBeInstanceOf(WriteCutBack);
    witnessWith(undefined);
    expect(up.files.size).toBe(0);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back', chain: 'organisation' }),
    );
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });

  it('a row whose record of the head was rewritten past the app: the alarm and the hold too', async () => {
    const { w } = await ready();
    const suspend = suspendUnderKey(w, 'tr1-replay-forged');
    await savedUnwitnessed(w, suspend);
    await asOwner(w, async (owner) => {
      await owner.query('update idempotency.keys set head_mac = $1 where org_id = $2', [Buffer.alloc(32, 9), w.org]);
    });
    witnessWith(witnessOver(createFakeWriteOnceStore()));
    await expect(suspend()).rejects.toBeInstanceOf(WriteCutBack);
    witnessWith(undefined);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back', record: 'forged' }),
    );
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });

  it('the head row garbled or taken away with the write cut: never the stored answer, the alarm and the hold', async () => {
    for (const key of ['tr1-replay-planted', 'tr1-replay-headless'] as const) {
      const { w } = await ready();
      const suspend = suspendUnderKey(w, key);
      await savedUnwitnessed(w, suspend);
      await asOwner(w, async (owner) => {
        if (key === 'tr1-replay-planted') {
          await owner.query('update audit.heads set mac = $1 where org_id = $2', [Buffer.alloc(32, 7), w.org]);
        } else {
          await owner.query('delete from audit.heads where org_id = $1', [w.org]);
        }
      });
      const up = createFakeWriteOnceStore();
      witnessWith(witnessOver(up));
      await expect(suspend()).rejects.toBeInstanceOf(WriteCutBack);
      witnessWith(undefined);
      expect(up.files.size).toBe(0);
      expect(lines('audit.integrity_failed')).toContainEqual(
        expect.objectContaining({ check: 'witness', reason: 'cut_back', orgId: w.org }),
      );
    }
  });

  it('the original row put back at its place beside a cut branch grown past it: the next event isn’t linked to it, the alarm and the hold', async () => {
    const { w } = await ready();
    const suspend = suspendUnderKey(w, 'tr1-replay-mixed');
    const { head, row } = await savedUnwitnessed(w, suspend);
    const kept = BigInt(head.seq) + 1n;
    let original: unknown;
    await asOwner(w, async (owner) => {
      const [found] = await owner.query<{ event: unknown }>(
        'select pg_catalog.row_to_json(e) as event from audit.events e where e.org_id = $1 and e.seq = $2::bigint',
        [w.org, kept.toString()],
      );
      original = found?.event;
      await owner.windBack(head);
      await owner.withoutStatusGuard(() => owner.restoreRow(row));
    });
    // A copy that never saw it grows the cut chain past its place, then the owner puts the original row back there.
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: { reason: 'a stale copy' },
      }),
    );
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'reactivate', {
        actor: OPERATOR,
        action: 'agent.reactivated',
        details: {},
      }),
    );
    await asOwner(w, async (owner) => {
      await owner.query('alter table audit.events disable trigger user');
      await owner.query('delete from audit.events where org_id = $1 and seq = $2::bigint', [w.org, kept.toString()]);
      await owner.query(
        'insert into audit.events select * from pg_catalog.json_populate_record(null::audit.events, $1::json)',
        [JSON.stringify(original)],
      );
      await owner.query('alter table audit.events enable trigger user');
    });
    witnessWith(witnessOver(createFakeWriteOnceStore()));
    await expect(suspend()).rejects.toBeInstanceOf(WriteCutBack);
    witnessWith(undefined);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back', seq: kept.toString() }),
    );
  });
});

describe('TR-1 review 4: a write that recorded on the platform chain too', () => {
  const platformChain = createPlatformChain({ keys, ids });
  const started = { configHash: `sha256:${'ab'.repeat(32)}`, release: 'r-test' };

  /** The agent's suspension and a platform event, under one idempotency key, through the signed states. */
  const bothUnderKey = (w: World, key: string) => {
    const idempotency = createIdempotentWrites({ keys, logger: testLogger(capture) });
    const request = {
      orgId: w.org,
      client: { kind: 'agent' as const, id: w.agent },
      operation: 'agents.suspend',
      key,
      payload: '{}',
    };
    return () =>
      withSignedStates(app, w.org, { keys, ids, logger: testLogger(capture) }, (tx, states) =>
        idempotency.run(tx, request, async () => {
          await states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
            actor: OPERATOR,
            action: 'agent.suspended',
            details: { reason: 'test' },
          });
          await platformChain.record(tx, {
            actor: { type: 'system', id: 'api' },
            action: 'platform.started',
            details: started,
          });
          return { status: 200, resourceId: w.agent };
        }),
      );
  };

  const platformHead = async () => {
    const [row] = await database
      .as('owner')
      .query<{ seq: string; kept: unknown }>(
        'select h.seq::text as seq, pg_catalog.row_to_json(h) as kept from platform_controls.audit_head h',
      );
    return row;
  };

  it('a replay holds the platform chain to the head the write left there too, and witnesses it as it stands', async () => {
    const { w } = await ready();
    const both = bothUnderKey(w, 'tr1-platform-replay');
    const down = createFakeWriteOnceStore();
    down.instead.put = () => Promise.reject(new Error('store down'));
    witnessWith(witnessOver(down, 100));
    await expect(both()).rejects.toBeInstanceOf(WitnessUnconfirmed);
    const up = createFakeWriteOnceStore();
    witnessWith(witnessOver(up));
    await both();
    witnessWith(undefined);
    const reader = witnessOver(up);
    await reader.refresh();
    expect(reader.pending({ kind: 'platform' }).map(({ seq }) => seq)).toEqual([
      BigInt(String((await platformHead())?.seq)),
    ]);
  });

  it('its platform event cut off since: the alarm (the platform’s) and the hold, never the stored answer', async () => {
    const { w } = await ready();
    const before = await platformHead();
    const both = bothUnderKey(w, 'tr1-platform-cut');
    const down = createFakeWriteOnceStore();
    down.instead.put = () => Promise.reject(new Error('store down'));
    witnessWith(witnessOver(down, 100));
    await expect(both()).rejects.toBeInstanceOf(WitnessUnconfirmed);
    witnessWith(undefined);
    const owner = database.as('owner');
    await owner.query('delete from platform_controls.operator_signatures where seq > $1::bigint', [before?.seq]);
    await owner.query('delete from platform_controls.audit_events where seq > $1::bigint', [before?.seq]);
    await owner.query(
      `update platform_controls.audit_head h set (seq, hash, mac, mac_key_version) =
         (select r.seq, r.hash, r.mac, r.mac_key_version
          from pg_catalog.json_populate_record(null::platform_controls.audit_head, $1::json) r)`,
      [JSON.stringify(before?.kept)],
    );
    witnessWith(witnessOver(createFakeWriteOnceStore()));
    await expect(both()).rejects.toMatchObject({ name: 'WriteCutBack', chain: 'platform' });
    witnessWith(undefined);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ chain: 'platform', check: 'witness', reason: 'cut_back' }),
    );
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });
});

describe('TR-1 review 3: a head below an anchor this process didn’t make (a restart, another copy’s)', () => {
  /** The agent suspended, then suspended again: two events, the first's head witnessed where `witnessed` is given. */
  const suspendOn = (w: World, reason: string) =>
    signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: { reason },
      }),
    );

  /** J's anchor check over the real trail, a head below its anchor confirmed by walking from it (passStep). */
  const checkOnJ = (w: World, j: { anchors: AnchorStore }, witness: WitnessLog) => {
    const trail = createAuditTrail({ keys, ids });
    return createAnchorCheck({
      chains: [],
      organizations: {
        list: () => Promise.resolve([w.org]),
        recorded: () => Promise.resolve([w.org]),
        probe: (chains, signal, pages) => trail.probeHeads(app, chains, signal, pages),
        verify: (orgId, anchor, heldTo, recent) =>
          trail.checkFromAnchor(app, orgId, anchor ?? CHAIN_START, undefined, heldTo, recent),
        confirm: (orgId, cursor, target) => trail.passStep(app, orgId, cursor, target, 2_000),
        hold: (orgId, failure) => holdOrganisation(app, orgId, { keys, ids, logger: testLogger(capture) }, failure),
      },
      keys,
      clock,
      logger: testLogger(capture),
      staleAfterMs: 900_000,
      deadlineMs: 120_000,
      anchors: j.anchors,
      witness,
    });
  };

  it('is walked from to the anchor: an honest one on the chain is let go, no alarm', async () => {
    const { w } = await ready();
    const store = createFakeWriteOnceStore();
    witnessWith(witnessOver(store));
    await suspendOn(w, 'witnessed');
    witnessWith(undefined);
    // Another event after it, unwitnessed: the anchor J holds (made elsewhere) stands above the head.
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'reactivate', {
        actor: OPERATOR,
        action: 'agent.reactivated',
        details: {},
      }),
    );
    const jWitness = witnessOver(store);
    const j = await jobsCopy(w, jWitness);
    await jWitness.refresh();
    expect(jWitness.pending({ kind: 'organisation', orgId: w.org })).toHaveLength(1);
    await checkOnJ(w, j, jWitness).run();
    expect(jWitness.pending({ kind: 'organisation', orgId: w.org })).toEqual([]);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('one the chain was cut back below and grown again past (anchored there elsewhere): the walk breaks, the alarm and the hold', async () => {
    const { w } = await ready();
    let head: SavedHead | undefined;
    let row: SavedRow | undefined;
    await asOwner(w, async (owner) => {
      head = await owner.saveHead();
      row = await owner.saveRow(w.agent);
    });
    const store = createFakeWriteOnceStore();
    witnessWith(witnessOver(store));
    await suspendOn(w, 'witnessed');
    witnessWith(undefined);
    await asOwner(w, async (owner) => {
      if (head === undefined || row === undefined) throw new Error('nothing saved');
      const [back, saved] = [head, row];
      await owner.windBack(back);
      await owner.withoutStatusGuard(() => owner.restoreRow(saved));
    });
    // A copy that never saw the stop grows the cut chain past its place; another copy anchors it there.
    await suspendOn(w, 'a stale copy');
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'reactivate', {
        actor: OPERATOR,
        action: 'agent.reactivated',
        details: {},
      }),
    );
    const jWitness = witnessOver(store);
    const j = await jobsCopy(w, jWitness);
    await jWitness.refresh();
    await checkOnJ(w, j, jWitness).run();
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back' }),
    );
    expect(jWitness.pending({ kind: 'organisation', orgId: w.org })).toHaveLength(1);
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });
});

describe('TR-1 review 4: a replayed row with no head seal, judged by the row itself', () => {
  const REQUEST = (w: World, key: string) => ({
    orgId: w.org,
    client: { kind: 'agent' as const, id: w.agent },
    operation: 'agents.suspend',
    key,
    payload: '{}',
  });

  /** A suspension under its key, then its row's head seal taken away; as a v1 row (from before 0115) where `asV1`. */
  const replayWithoutSeal = async (key: string, asV1: boolean, garbleHead = false) => {
    const { w } = await ready();
    const idempotency = createIdempotentWrites({ keys, logger: testLogger(capture) });
    const suspend = () =>
      withSignedStates(app, w.org, { keys, ids, logger: testLogger(capture) }, (tx, states) =>
        idempotency.run(tx, REQUEST(w, key), async () => {
          await states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
            actor: OPERATOR,
            action: 'agent.suspended',
            details: { reason: 'test' },
          });
          return { status: 200, resourceId: w.agent };
        }),
      );
    await suspend();
    const r = REQUEST(w, key);
    // The request hashed as before 0115 (v1), which only the app's key could make.
    const v1 = keys.mac('request-hash', [
      'idempotent-request',
      r.orgId,
      r.client.kind,
      r.client.id,
      r.operation,
      r.key,
      r.payload,
    ]);
    await asOwner(w, async (owner) => {
      await owner.query(
        `update idempotency.keys set head_seq = null, head_hash = null, platform_head_seq = null,
           platform_head_hash = null, head_mac = null, head_mac_key_version = null
         where org_id = $1`,
        [w.org],
      );
      if (asV1) {
        await owner.query(
          'update idempotency.keys set request_hash = $2, request_hash_key_version = $3 where org_id = $1',
          [w.org, v1.mac, v1.keyVersion],
        );
      }
      if (garbleHead)
        await owner.query('update audit.heads set mac = $2 where org_id = $1', [w.org, Buffer.alloc(32, 7)]);
    });
    const up = createFakeWriteOnceStore();
    witnessWith(witnessOver(up));
    try {
      return { w, up, answer: await suspend().catch((error: unknown) => error) };
    } finally {
      witnessWith(undefined);
    }
  };

  it('a v1 row (made before 0115) is answered as before; its head, not sealed, never witnessed', async () => {
    const { answer } = await replayWithoutSeal('tr1-v1', true);
    expect(answer).toMatchObject({ outcome: 'replayed' });
    const garbled = await replayWithoutSeal('tr1-v1-garbled', true, true);
    expect(garbled.answer).toMatchObject({ outcome: 'replayed' });
    expect(garbled.up.files.size).toBe(0);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('a v2 row with its seal taken away: the alarm (`record: missing`) and the hold at once, never the stored answer', async () => {
    const { w, answer } = await replayWithoutSeal('tr1-v2-stripped', false);
    expect(answer).toBeInstanceOf(WriteCutBack);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'witness', reason: 'cut_back', record: 'missing' }),
    );
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });
});

describe('TR-1 (10): a stop whose head can’t be witnessed', () => {
  it('answers WitnessUnconfirmed (503), its change saved; later requests here for the organisation wait for it; once out, all go on', async () => {
    const { w } = await ready();
    const store = createFakeWriteOnceStore();
    let down = true;
    store.instead.put = (name, bytes) => (down ? Promise.reject(new Error('store down')) : store.real.put(name, bytes));
    const witness = witnessOver(store, 100);
    witnessWith(witness);
    await expect(
      signed(w, (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
          actor: OPERATOR,
          action: 'agent.suspended',
          details: { reason: 'test' },
        }),
      ),
    ).rejects.toBeInstanceOf(WitnessUnconfirmed);
    // Saved all the same: the change stands, only its answer waited.
    witnessWith(undefined);
    expect(
      await signed(w, (tx) =>
        tx.selectFrom('agents.agents').select('status').where('id', '=', w.agent).executeTakeFirst(),
      ),
    ).toEqual({
      status: 'SUSPENDED',
    });
    witnessWith(witness);
    // A read for the organisation on this copy waits for the head still queued.
    await expect(signed(w, (tx, states) => states.holdRecord(tx, w.org))).rejects.toBeInstanceOf(WitnessUnconfirmed);
    expect(lines('audit.witness_unconfirmed').length).toBeGreaterThan(0);
    down = false;
    clock.advanceBy(1_000);
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'clear' });
    expect(store.files.size).toBe(1);
  });
});
