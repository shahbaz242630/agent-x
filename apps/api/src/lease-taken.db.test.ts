// TR-1 A (S209): the jobs' lease taken from the one copy for a moment never makes it forget the heads it has seen. The
// database's owner, holding no app key, changes the lease row (job_lease) while the copy's own term still runs: the copy
// says so at once as an error (jobs.lease_taken_early) and stops its jobs, but its digest keeps every head it saw. The
// row put back, the copy leads again; the owner then cuts the organisation's chain back below a head it saw (a stop
// taken away, its events with it, the agent's row put back as it was): Tx A and the next decision still refuse it.
// Before TR-1 A the copy forgot all its digest held at the lease lost, and the cut passed (the positive control:
// handoff.db.test.ts's AT13 cases, with no digest, pay).
import { AGENTS } from '@agentx/core/modules/agents';
import { checkStatesWith, createAuditTrail } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  changeHandoffPause,
  createPlatformChain,
  type PlatformControlsTables,
  releaseJobLease,
  takeJobLease,
} from '@agentx/core/modules/platform-controls';
import { CHAIN_START, createDigestLog, createMemoryAnchorStore, signAnchor } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  FixedClock,
  LogCapture,
  type SavedHead,
  type SavedRow,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import { createLeadership } from './background.ts';
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
let lease: Database<PlatformControlsTables>;
let operator: Database<HandoffWorldTables>;

const ids = new SequentialIds(0x7a1e_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x7a1f_0000_0000) });
const HOLDER = '0199a0f0-0000-7000-8000-0000000071aa';
const OTHER = '0199a0f0-0000-7000-8000-0000000071cc';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'lease-taken',
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
  lease = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
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
        { paused: false, reason: 'TEST-TR1A', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );
});

afterAll(async () => {
  await app.destroy();
  await lease.destroy();
  await operator.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit chain seals each event's time by the database's clock, so the tests start from now.
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

/** The one jobs copy's lease over the real row: a long term, renewed often, so a refusal comes well inside it. */
function theOneCopy() {
  return createLeadership({
    store: {
      take: (beating) => takeJobLease(lease, HOLDER, beating, 30),
      release: () => releaseJobLease(lease, HOLDER),
    },
    logger: testLogger(capture),
    notLeadingAfterMs: 60_000,
    renewEveryMs: 100,
    termMs: 30_000,
    tryWithinMs: 1_000,
    retryAfterMs: 50,
  });
}

/** The owner's own statements, inside the organisation, the connection ended after. */
async function asOwner(w: World, run: (owner: Awaited<ReturnType<typeof tamperAsOwner>>) => Promise<void>) {
  const owner = await tamperAsOwner(database, AGENTS, w.org);
  try {
    await run(owner);
  } finally {
    await owner.end();
  }
}

describe('TR-1 A: the jobs lease taken for a moment, then the chain cut back below a head the copy saw', () => {
  it('the error at once; the copy leads again, and Tx A and the next decision still refuse the cut', async () => {
    await database.as('admin').query("update platform_controls.job_lease set holder = null, until = '-infinity'");
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const copy = theOneCopy();
    await copy.start(() => false);
    expect(copy.leading()).toBe(true);

    // The copy's digest over its store, writing only while it leads (job-list.ts): the anchor check's walk of the chain
    // recorded and written, and the chain anchored where it stands.
    const digest = createDigestLog({
      store: createFakeWriteOnceStore().store,
      keys,
      logger: testLogger(capture),
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 64 * 1024 * 1024,
      writes: () => copy.leading(),
    });
    const orgChain = { kind: 'organisation', orgId: w.org } as const;
    const walked = await createAuditTrail({ keys, ids }).checkFromAnchor(app, w.org, CHAIN_START);
    if (!walked.ok || walked.signed === undefined) throw new Error('The chain should have checked out');
    await digest.read();
    digest.record(orgChain, walked.signed, clock.now(), { from: 0n, to: walked });
    await digest.flush();
    const anchors = createMemoryAnchorStore();
    anchors.keep(signAnchor(keys, orgChain, walked, clock.now()));

    checkStatesWith(digest);
    try {
      // The agent's row and the chain's head as they stand, kept by the owner; then the agent suspended, above them.
      let row: SavedRow | undefined;
      let head: SavedHead | undefined;
      await asOwner(w, async (owner) => {
        row = await owner.saveRow(w.agent);
        head = await owner.saveHead();
      });
      await signed(w, (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
          actor: OPERATOR,
          action: 'agent.suspended',
          details: { reason: 'test' },
        }),
      );
      const seen = digest.heads(orgChain)?.seen;
      expect(seen?.seq).toBeGreaterThan(BigInt(head?.seq ?? 'x'));

      // The owner takes the lease row, the copy's own term still running: the error at once, well before any expiry.
      await asOwner(w, (owner) =>
        owner
          .query("update platform_controls.job_lease set holder = $1, until = 'infinity'", [OTHER])
          .then(() => undefined),
      );
      await vi.waitFor(
        () => {
          expect(lines('jobs.lease_taken_early')).toEqual([expect.objectContaining({ level: 'error' })]);
        },
        { timeout: 2_000, interval: 20 },
      );
      expect(copy.leading()).toBe(false);
      // Requests go on meanwhile, each read held to the digest: still the head it saw (it once forgot it here).
      expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'clear' });
      expect(digest.heads(orgChain)?.seen).toEqual(seen);

      // The row put back as if nothing happened: the copy takes the lease again at its next try.
      await asOwner(w, (owner) =>
        owner.query("update platform_controls.job_lease set holder = null, until = '-infinity'").then(() => undefined),
      );
      await vi.waitFor(
        () => {
          expect(copy.leading()).toBe(true);
        },
        { timeout: 2_000, interval: 20 },
      );
      // Leading again, the anchor check's first run reads the store (anchor-check.ts).
      await digest.read();
      expect(digest.covers(orgChain, walked.seq)).toBe(true);

      // Now the cut: the suspension's events gone with the chain's end, its head put back, the agent's row as it was.
      await asOwner(w, async (owner) => {
        if (row === undefined || head === undefined) throw new Error('nothing saved');
        const [saved, back] = [row, head];
        await owner.windBack(back);
        await owner.withoutStatusGuard(() => owner.restoreRow(saved));
      });

      // Tx A: no call, no instruction, the alarm at the head the copy saw, the organisation held.
      let submitted = 0;
      const rail = {
        ...w.rail,
        submitApprovedIntent: (intent: Parameters<typeof w.rail.submitApprovedIntent>[0]) => {
          submitted += 1;
          return w.rail.submitApprovedIntent(intent);
        },
      };
      await createHandoff({
        anchoring: { anchors, anchorFirst: () => Promise.resolve(), digest },
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
      expect(submitted).toBe(0);
      expect(await paymentOf(w, request.id)).toEqual({ instruction: 'missing' });
      expect(await statusOf(w, request.id)).not.toBe('HANDED_OFF');
      // Even the hold's own read, held to the head seen, finds the chain cut.
      expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'tampered' });
      expect(lines('audit.integrity_failed')).toContainEqual(
        expect.objectContaining({ check: 'state', reason: 'log', seq: String(seen?.seq) }),
      );

      // And the next decision read on the cut chain is refused.
      await expect(ask(acting, w, { amount: ALLOWED() })).rejects.toThrow(/INTEGRITY_FAILED/);
    } finally {
      checkStatesWith(undefined);
      await copy.stop();
    }
    // Read with no digest, the organisation is held.
    expect(await signed(w, (tx, states) => states.holdRecord(tx, w.org))).toMatchObject({ outcome: 'held' });
  });
});
