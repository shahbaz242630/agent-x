// S212 G2 (E2E6 F1): a request read in full carries its payment once handed
// off, against Postgres on the migrated schema as the app role: none before
// the hand-off, its own payment's ID and status after, a payment changed past
// the app refusing the read (503 INTEGRITY_FAILED, the organisation held),
// and another organisation's request, payment and all, never found.
// The route's answer is spend-request-reads.test.ts.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { TRANSACTIONS } from '@agentx/core/modules/transactions';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { handoffWorld, type HandoffWorldTables, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { createRailHealth } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { createSpendRequestReads, type SpendRequestReads } from './spend-request-reads.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;
let operator: Database<HandoffWorldTables>;

const ids = new SequentialIds(0x6212_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x6213_0000_0000) });
const CORRELATION = '0199a0f0-0000-7000-8000-000000006212';
const INTEGRITY_FAILED = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
const NOT_FOUND = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
/** Agent X's own team, as the operator's command names itself: only it resumes the hand-off. */
const PAUSER = { type: 'system', id: 'operator' } as const;
/** A step of the fake's payment: settled at the debtor a minute on, its answer final after two (B2). */
const STEP = 60_000;

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let reads: SpendRequestReads;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'request-payment',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, quiet } = shared;
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const runner = (w: World) => ({
  list: () => Promise.resolve([w.org]),
  database: app,
  outbox: createOutbox({ ids, clock, keys }),
  rail: w.rail,
  keys,
  ids,
  clock,
  logger: testLogger(),
  health: createRailHealth({ clock, logger: testLogger() }),
  databaseGate: handoffDatabaseGate(6),
});

/** A request allowed, read before its hand-off, then handed off and paid, checked two steps on. */
async function paid() {
  const { w, acting } = await ready();
  const request = await ask(acting, w, { amount: SMALL() });
  const before = await reads.show(w.org, request.id, CORRELATION);
  await createHandoff(runner(w)).run();
  clock.advanceBy(2 * STEP);
  await createPaymentChecks(runner(w)).run();
  const payment = await paymentOf(w, request.id);
  if (typeof payment.transaction !== 'object') throw new Error(`not paid: ${JSON.stringify(payment)}`);
  return { w, request, before, transaction: payment.transaction };
}

const heldOf = (w: World) => withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  operator = createDatabase<HandoffWorldTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  // Born paused (ADR-014 §4): resumed for these tests, as the operator would.
  await operator
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: false, reason: 'TEST-S212-G2', actor: PAUSER, release: 'r-test', run: null },
      ),
    );
});

afterAll(async () => {
  await app.destroy();
  await operator.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit chain seals each event's time by the database's clock, so the tests start from now.
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
  reads = createSpendRequestReads({ database: app, keys, ids, logger });
});

describe('a request read in full carries its payment once handed off (S212 G2, BR-17)', () => {
  it('shows none before the hand-off, and its own payment, paid, after', async () => {
    const { w, request, before, transaction } = await paid();

    expect(before).toMatchObject({ outcome: 'found', shown: { request: { status: 'APPROVED' } }, payment: null });
    expect(transaction.status).toBe('SUCCEEDED');
    expect(await reads.show(w.org, request.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      shown: { request: { status: 'HANDED_OFF' } },
      payment: { id: transaction.id.toLowerCase(), status: 'SUCCEEDED' },
    });
  });

  it('SEC-TEN-01 never shows another organisation’s request, nor its payment: each reads its own alone', async () => {
    const mine = await paid();
    const theirs = await paid();

    expect(await reads.show(mine.w.org, theirs.request.id, CORRELATION)).toEqual(NOT_FOUND);
    expect(await reads.show(theirs.w.org, mine.request.id, CORRELATION)).toEqual(NOT_FOUND);
    expect(await reads.show(mine.w.org, mine.request.id, CORRELATION)).toMatchObject({
      payment: { id: mine.transaction.id.toLowerCase() },
    });
    expect(await reads.show(theirs.w.org, theirs.request.id, CORRELATION)).toMatchObject({
      payment: { id: theirs.transaction.id.toLowerCase() },
    });
  });

  it('refuses one whose payment was changed past the app, holding the organisation', async () => {
    const { w, request, transaction } = await paid();
    const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table transactions.transactions disable trigger user');
      await owner.setColumn(transaction.id, 'provider_status', 'Rejected');
      await owner.query('alter table transactions.transactions enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }

    expect(await reads.show(w.org, request.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });
});
