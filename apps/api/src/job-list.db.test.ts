// The `jobs` side's list as boot makes it (job-list.ts), over the real migrated schema and a folder witness store
// (TR-1): the wiring each job is given run for real, not only made. The anchor check walks and anchors both chains held
// to the heads witnessed, a head another copy wrote is probed at once from the witness job's refresh, and the hand-off
// pays through the frontier and the gate.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { checkStatesWith, witnessWith } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { createWitnessLog } from '@agentx/platform/audit-chain';
import { loadConfig } from '@agentx/platform/config';
import { createDatabase, type Database } from '@agentx/platform/db';
import { folderWriteOnceStore } from '@agentx/platform/storage';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import type { Leadership } from './background.ts';
import { type Booted, sharedParts } from './boot.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables } from './handoff-world.helper.test.ts';
import { oneCopyJobs } from './job-list.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys } from './mandate-world.helper.test.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;
let operator: Database<HandoffWorldTables>;
let heads: string;

const ids = new SequentialIds(0x7b3e_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x7b3f_0000_0000) });

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'job-list-db',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, statusOf } = shared;
const { ready } = handoffWorld({ app: () => app, clock: () => clock, ids, registry: () => registry, shared });

const leadership: Leadership = {
  start: () => Promise.resolve(),
  leading: () => true,
  onlyWhileLeading: (work) => work,
  onlyWhileNotLeading: (work) => work,
  stop: () => Promise.resolve(),
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 8 }, testLogger());
  operator = createDatabase<HandoffWorldTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  heads = mkdtempSync(join(tmpdir(), 'job-list-db-witness-'));
  // Born paused (ADR-014 §4): resumed, as the operator would once the hand-off is live.
  await operator
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: false, reason: 'TEST-JOBS', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );
});

afterAll(async () => {
  checkStatesWith(undefined);
  witnessWith(undefined);
  await app.destroy();
  await operator.destroy();
  await database.drop();
  rmSync(heads, { recursive: true, force: true });
});

beforeEach(() => {
  clock = new FixedClock(new Date());
  const logger = testLogger();
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

/** The jobs side as boot makes it over this database, its witness log over the folder store; its log captured. */
function jobsSide() {
  const config = loadConfig({
    AGENTX_ENV: 'test',
    AGENTX_DB_HOST: 'db',
    AGENTX_DB_PASSWORD: 'app login for these tests',
    AGENTX_KEYS_DIR: '/mnt/secrets',
    AGENTX_PARTNER_MODE: 'fake',
    AGENTX_AUDIT_WITNESS_DIR: heads,
  });
  const capture = new LogCapture();
  const booted: Booted = {
    host: {} as Booted['host'],
    config,
    keys,
    logger: testLogger(capture),
    database: app as unknown as Booted['database'],
    atCrash: () => undefined,
  };
  const made = oneCopyJobs(booted, sharedParts(booted, leadership), leadership);
  const job = (name: string) => {
    const found = made.jobs.find((each) => each.name === name);
    if (found === undefined) throw new Error(`${name} should be listed`);
    return found;
  };
  return { made, job, capture };
}

/** A job started until a line it writes says its run is done, then stopped. */
async function ranUntil(started: { stop(): Promise<void> }, capture: LogCapture, event: string): Promise<void> {
  try {
    await vi.waitFor(
      () => {
        expect(capture.lines().some((line) => line.event === event)).toBe(true);
      },
      { timeout: 60_000, interval: 100 },
    );
  } finally {
    await started.stop();
  }
}

describe('TR-1 the jobs side wired over the database and a witness store', () => {
  it('anchors both chains held to the heads witnessed, probes a head another copy wrote, and pays through the gate', async () => {
    const { w, acting } = await ready();
    const { made, job, capture } = jobsSide();
    try {
      // The anchor check's run: the platform chain from its anchor, every organisation probed and walked.
      await ranUntil(job('anchor_check').start(), capture, 'audit.anchor_check_done');
      expect(capture.lines().filter(({ event }) => event === 'audit.integrity_failed')).toEqual([]);
      // Another copy's head of this organisation, in the store: the witness job's refresh gains it, and probes it.
      const request = await ask(acting, w, { amount: ALLOWED() });
      const [{ seq, hash } = { seq: 0n, hash: Buffer.alloc(0) }] = await app
        .selectFrom('audit.heads')
        .select(['seq', 'hash'])
        .where('org_id', '=', w.org)
        .execute();
      await createWitnessLog({
        store: folderWriteOnceStore(heads),
        keys,
        logger: testLogger(),
        now: () => new Date(),
        epoch: 1,
        alertAfterMs: 60_000,
        mostBytes: 1024 * 1024,
      }).now({ kind: 'organisation', orgId: w.org }, { seq, hash });
      await job('witness').start().stop();
      // The anchor check again, its walk now held to that head and confirming it.
      await ranUntil(job('anchor_check').start(), capture, 'audit.anchor_check_done');
      // The hand-off: Tx A from the frontier, the gate, the partner called once.
      await made.handoff?.run();
      expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
      // A second request there, its Tx A walking from the stretch the first kept; and one in an organisation the anchor
      // check hasn't reached yet, anchored first by the hand-off itself.
      const again = await ask(acting, w, { amount: ALLOWED() });
      const other = await ready();
      const elsewhere = await ask(other.acting, other.w, { amount: ALLOWED() });
      await made.handoff?.run();
      expect(await statusOf(w, again.id)).toBe('HANDED_OFF');
      expect(await statusOf(other.w, elsewhere.id)).toBe('HANDED_OFF');
      expect(capture.lines().filter(({ event }) => event === 'handoff.held_before_sending')).toEqual([]);
      expect(capture.lines().filter(({ event }) => event === 'audit.integrity_failed')).toEqual([]);
    } finally {
      checkStatesWith(undefined);
      witnessWith(undefined);
    }
  });
});
