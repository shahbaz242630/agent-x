// Phase 4 E1a: the bank's word on each payment under way, on the real
// migrated schema as the app role (ADR-007 §10–§13; rail map §4; SEC-PTR-02,
// -09; PL-38). A payment handed to the world's own fake partner is checked
// with it as time passes: under way, then credited, SUCCEEDED, its money
// spent and its supplier's remittance queued, once. Rejected with no proof
// of no debit: UNKNOWN, its money blocked, a reconciliation alert said once;
// with the proof: FAILED, its money and order given back. A payment whose
// hand-off died before its answer takes both steps in one transaction, and
// its late answer never replaces the bank's newer word. Not found proves
// nothing; the bank unreachable leaves it as it was, said once a run; an
// answer that can't be read, or is about another payment, is UNKNOWN, never
// success. A payment the bank contradicts once settled stays settled, said.
// Older payments are checked less often; the run beats for /health; failures
// are logged and the run goes on. The model: random batches handed off and
// checked by runs racing each other, the clock moving: each payment sent
// once, settled once, one remittance for each that SUCCEEDED, its holdings as
// its payment ended.
import { withSignedStates } from '@agentx/core/modules/audit';
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { lockHoldingsOf, markFailed, settleHoldings } from '@agentx/core/modules/outcomes';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { type ExecutionLookup, type FakeRail, RailUnavailable } from '@agentx/core/modules/providers';
import { createProviderEvents } from '@agentx/core/modules/provider-events';
import { moveTransaction, TRANSACTIONS, transactionOf as lockedTransaction } from '@agentx/core/modules/transactions';
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

import { asARun } from './background.ts';
import { createHandoff, HEARTBEAT_STALE_MS, handoffDatabaseGate, UNKNOWN_AFTER_MS } from './handoff.ts';
import { createRailHealth, type RailHealth } from './rail-health.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables, HOLDS_AFTER, SMALL } from './handoff-world.helper.test.ts';
import { heartbeatChecks } from './health.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;
/** The operator's own role (PL-57), the one that moves the hand-off pause. */
let operator: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xe1a0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xe1b0_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'payment-checks',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, holdingsOf } = shared;
const { ready, paymentOf, alertsOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Each run's count of the checks that changed nothing, for the runs that had any: those checks have no line of their own. */
const unchangedRuns = () => lines('payment_check.run_unchanged').map(({ unchanged }) => unchanged);

/** A step of the fake's payment: Pending, settled at the debtor a minute on, credited after two (B2). */
const STEP = 60_000;

/** The hand-off over the world alone, paying through `rail`. */
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

/** The bank check over the world alone, asking `rail` (the world's own fake unless given). */
const checksOf = (w: World, rail: FakeRail = w.rail, list = () => Promise.resolve([w.org])) =>
  createPaymentChecks({
    list,
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

/** The world's fake, its lookups answered by `answer` from what the fake itself says. */
const answering = (
  w: World,
  answer: (found: ExecutionLookup) => ExecutionLookup | Promise<ExecutionLookup>,
): FakeRail => ({
  ...w.rail,
  getExecution: async (ref) => answer(await w.rail.getExecution(ref)),
});

/** The world's remittances queued, by the transaction each is about. */
const remittancesOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        // A global table (0021): the world's own organisation's notices alone.
        .selectFrom('notifications.outbox')
        .select('about_id')
        .where('org_id', '=', w.org)
        .where('kind', '=', 'payment_remittance')
        .orderBy('id')
        .execute()
    ).map(({ about_id }) => about_id),
  );

/** The request's transaction as it stands. */
const transactionOf = async (w: World, requestId: string) => {
  const payment = await paymentOf(w, requestId);
  if (typeof payment.transaction !== 'object') throw new Error(`no transaction: ${String(payment.transaction)}`);
  return payment.transaction;
};

/** The signed moves of the request's transaction, in order. */
const movesOf = async (w: World, requestId: string) =>
  (await shared.eventsAbout(w.org, (await transactionOf(w, requestId)).id, TRANSACTIONS.subject)).map(
    ({ action }) => action,
  );

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
        { paused: false, reason: 'TEST-E1A', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );
});

afterAll(async () => {
  await app.destroy();
  await operator.destroy();
  await database.drop();
});

/** The test's clock started at `at`, and what reads it made again with it. */
function startClock(at: Date): void {
  clock = new FixedClock(at);
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
}

// The audit chain seals each event's time by the database's clock, so the tests start from now.
beforeEach(() => {
  startClock(new Date());
});

describe('a payment finished by the bank’s word (E1a; rail map §4)', () => {
  it('follows it as the bank moves it: under way, then credited: SUCCEEDED, its money spent, its remittance queued once', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const checks = checksOf(w);

    await checks.run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING', providerStatus: 'Pending' });

    clock.advanceBy(STEP);
    await checks.run();
    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'PROCESSING',
      providerStatus: 'AcceptedSettlementCompleted',
    });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);

    clock.advanceBy(STEP);
    await checks.run();
    const transaction = await transactionOf(w, request.id);
    expect(transaction).toMatchObject({ status: 'SUCCEEDED', providerStatus: 'AcceptedCreditSettlementCompleted' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(await remittancesOf(w)).toEqual([transaction.id]);

    // Settled: never checked again, never told twice.
    await checks.run();
    expect(await remittancesOf(w)).toEqual([transaction.id]);
    expect((await movesOf(w, request.id)).filter((action) => action === 'transaction.succeed')).toHaveLength(1);
    expect(lines('payment_check.checked').at(-1)).toMatchObject({ from: 'PROCESSING', to: 'SUCCEEDED' });
    // Only the first run's check changed nothing: the second read the bank's new word; the run after it settled checked nothing, or there'd be another.
    expect(unchangedRuns()).toEqual([1]);
  });

  it('finishes one whose answer was lost (.02): UNKNOWN until the bank says credited, then SUCCEEDED and spent', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(2n) });
    await handoffOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });

    // Under way at the bank: an UNKNOWN one can't go back under way, so the bank's word is kept beside it.
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN', providerStatus: 'Pending' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);

    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(await remittancesOf(w)).toHaveLength(1);
  });

  it('marks UNKNOWN one rejected with no proof the money stayed (.04): its money blocked, the alert said once', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(4n) });
    await handoffOf(w).run();

    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'UNKNOWN',
      providerStatus: 'Rejected',
      rejectCode: 'AANI.FF01',
    });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(lines('payment_check.rejected_unproven')).toHaveLength(1);
    expect(await remittancesOf(w)).toEqual([]);
    // Kept in the organisation's audit log and its admins emailed, once (decision 37b).
    expect(await alertsOf(w, (await transactionOf(w, request.id)).id)).toEqual({
      kept: [{ action: 'payment.rejected_unproven', details: { bank: 'Rejected' } }],
      emailed: ['payment_unproven'],
    });
  });

  it.each([
    ['its reject code', 'AANI.AM04', { via: 'bank_check' }],
    [
      'the bank’s own word with no code: its reference the evidence',
      null,
      { evidenceRef: expect.stringMatching(/^bank_status:fake-payment-/) as unknown },
    ],
  ] as const)(
    'marks FAILED one rejected with the proof of no debit, by %s: its money and order given back',
    async (_name, code, details) => {
      const { w, acting } = await ready();
      const request = await ask(acting, w, { amount: ALLOWED(), orderReference: 'INV-E1A-FAILED' });
      await handoffOf(w).run();
      const rejected = answering(w, (found) =>
        found.kind === 'found'
          ? {
              kind: 'found',
              execution: { ...found.execution, providerStatus: 'Rejected', rejectCode: code, noDebitProven: true },
            }
          : found,
      );

      await checksOf(w, rejected).run();

      expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED', rejectCode: code });
      expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
      const events = await shared.eventsAbout(w.org, (await transactionOf(w, request.id)).id, TRANSACTIONS.subject);
      expect(events.at(-1)).toMatchObject({ action: 'transaction.fail', actorType: 'system', details });
      // The order may be asked again.
      const again = await ask(acting, w, { amount: ALLOWED(), orderReference: 'INV-E1A-FAILED' });
      expect(again.status).toBe('APPROVED');
    },
  );

  it('takes both steps for one whose hand-off died before its answer (ADR-007 §13); its late answer never replaces the bank’s newer word', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    // The partner made it, but its answer is held back, as a run that died after the call would leave it.
    const { promise: answer, resolve } = Promise.withResolvers<undefined>();
    const slow: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        const made = await w.rail.submitApprovedIntent(intent);
        await answer;
        return made;
      },
    };
    const run = handoffOf(w, slow).run();
    await expect
      .poll(async () => (await paymentOf(w, request.id)).transaction)
      .toMatchObject({ status: 'SUBMISSION_PENDING' });

    // Its answer not yet due, though past the bank's call's time limit: left to its own Tx B.
    clock.advanceBy(STEP - 1);
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUBMISSION_PENDING' });

    clock.advanceBy(STEP + 1);
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'SUCCEEDED',
      providerStatus: 'AcceptedCreditSettlementCompleted',
    });
    expect((await movesOf(w, request.id)).filter((action) => action !== 'transaction.provider_noted')).toEqual([
      'transaction.opened',
      'transaction.submitted',
      'transaction.succeed',
    ]);
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);

    // The hand-off's answer comes after all: Pending, from before. Late, and the bank's newer word stands.
    resolve(undefined);
    await run;
    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'SUCCEEDED',
      providerStatus: 'AcceptedCreditSettlementCompleted',
    });
    expect(lines('handoff.handed_off')).toEqual([expect.objectContaining({ recorded: 'late' })]);
    expect(await remittancesOf(w)).toHaveLength(1);
  });
});

describe('what the bank’s word can’t prove (ADR-007 §11; SEC-PTR-09)', () => {
  it('says so when the hand-off’s own answer is rejected with no proof the money stayed: UNKNOWN, reconciliation’s', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const rejecting: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        const made = await w.rail.submitApprovedIntent(intent);
        return made.kind === 'accepted'
          ? { ...made, execution: { ...made.execution, providerStatus: 'Rejected', rejectCode: 'AANI.FF01' } }
          : made;
      },
    };

    await handoffOf(w, rejecting).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN', providerStatus: 'Rejected' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(lines('handoff.rejected_unproven')).toHaveLength(1);
    // Kept and its admins emailed once (decision 37b): the bank check finding it as it was says nothing more.
    clock.advanceBy(2 * STEP);
    await checksOf(w, rejecting).run();
    expect(await alertsOf(w, (await transactionOf(w, request.id)).id)).toEqual({
      kept: [{ action: 'payment.rejected_unproven', details: { bank: 'Rejected' } }],
      emailed: ['payment_unproven'],
    });
  });

  it('leaves one the bank doesn’t find as it was: not found proves nothing, but the bank knew it, so its line stays', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();

    await checksOf(
      w,
      answering(w, () => ({ kind: 'not_found' })),
    ).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    expect(lines('payment_check.checked')).toEqual([
      expect.objectContaining({ answer: 'not_found', from: 'PROCESSING', to: 'PROCESSING', bankLost: 'Pending' }),
    ]);
    expect(lines('payment_check.run_unchanged')).toEqual([]);
    expect(lines('payment_check.not_found_long')).toEqual([]);
  });

  it('counts an UNKNOWN payment the bank has never spoken of and can’t find: its status, not its age, keeps it from the warn', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(2n) });
    await handoffOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN', providerStatus: null });
    clock.advanceBy(UNKNOWN_AFTER_MS + STEP);

    await checksOf(
      w,
      answering(w, () => ({ kind: 'not_found' })),
    ).run();

    expect(lines('payment_check.checked')).toEqual([]);
    expect(lines('payment_check.run_unchanged')).toEqual([expect.objectContaining({ unchanged: 0, notFound: 1 })]);
    expect(lines('payment_check.not_found_long')).toEqual([]);
  });

  it('says each check that the bank still can’t find one under way past its time, naming it; the payment stays waiting, its admins told once (S170)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const { id } = await transactionOf(w, request.id);
    const notFound = answering(w, () => ({ kind: 'not_found' }));

    clock.advanceBy(UNKNOWN_AFTER_MS - STEP);
    await checksOf(w, notFound).run();
    expect(lines('payment_check.not_found_long')).toEqual([]);
    expect(await alertsOf(w, id)).toEqual({ kept: [], emailed: [] });

    clock.advanceBy(2 * STEP);
    await checksOf(w, notFound).run();
    await checksOf(w, notFound).run();
    const said: unknown = expect.objectContaining({ level: 'warn', orgId: w.org, transactionId: id });
    expect(lines('payment_check.not_found_long')).toEqual([said, said]);
    expect(lines('payment_check.not_found_long')[0]?.says).toEqual(expect.stringContaining('waiting'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    // Two checks, each its own copy as a restart makes: one entry kept, one email (partner S170).
    const toldOnce = {
      kept: [{ action: 'payment.bank_lost', details: { bank: 'Pending' } }],
      emailed: ['payment_bank_lost'],
    };
    expect(await alertsOf(w, id)).toEqual(toldOnce);

    // Found again, nothing more to say.
    await checksOf(w).run();
    expect(lines('payment_check.not_found_long')).toHaveLength(2);
    expect(await alertsOf(w, id)).toEqual(toldOnce);
  });

  // Null: handed over with no word from the bank yet, still named in its admins' audit entry.
  it.each([
    ['Pending', 'Pending'],
    [null, 'none'],
  ])('says it of one still SUBMITTED past its time too (bank status %s)', async (providerStatus, bank) => {
    const { w, acting } = await ready();
    // .01 fils: the fake declines it, too late, so it stays where the bank's earlier word left it.
    const request = await ask(acting, w, { amount: ALLOWED(1n) });
    const rail: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        const key = { orgId: w.org, id: (await transactionOf(w, request.id)).id };
        await withSignedStates(app, w.org, { keys, ids, logger: testLogger() }, async (tx, states) => {
          await lockedTransaction(tx, states, key, 'change');
          await lockHoldingsOf(tx, request.id);
          const moved = await moveTransaction(
            tx,
            states,
            key,
            'submitted',
            { providerStatus, paymentInstructionRef: null, rejectCode: null, providerChangedAt: null },
            { actor: { type: 'system', id: 'test' }, details: {} },
          );
          if (moved.outcome !== 'moved') throw new Error(`not moved: ${moved.outcome}`);
          await settleHoldings(tx, { requestId: request.id, status: moved.to, at: clock.now() });
        });
        return w.rail.submitApprovedIntent(intent);
      },
    };
    await handoffOf(w, rail).run();
    const { id } = await transactionOf(w, request.id);
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUBMITTED' });
    clock.advanceBy(UNKNOWN_AFTER_MS + STEP);

    await checksOf(
      w,
      answering(w, () => ({ kind: 'not_found' })),
    ).run();

    expect(lines('payment_check.not_found_long')).toEqual([
      expect.objectContaining({ level: 'warn', orgId: w.org, transactionId: id }),
    ]);
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUBMITTED' });
    // Beside the late refusal the hand-off read after the bank's word (decision 37b).
    expect(await alertsOf(w, id)).toEqual({
      kept: [
        { action: 'payment.contradicted', details: { refused: 'AANI.AM04', status: 'SUBMITTED' } },
        { action: 'payment.bank_lost', details: { bank } },
      ],
      emailed: ['payment_contradicted', 'payment_bank_lost'],
    });
  });

  it('leaves them as they were while the bank can’t be reached, and says so once a run', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w, { amount: SMALL() });
    const second = await ask(acting, w, { amount: SMALL() });
    await handoffOf(w).run();

    await checksOf(w, { ...w.rail, getExecution: () => Promise.reject(new RailUnavailable()) }).run();

    for (const request of [first, second]) {
      expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    }
    expect(lines('payment_check.bank_unavailable')).toEqual([
      expect.objectContaining({ unreached: 2, stopped: false }),
    ]);
    expect(lines('payment_check.checked')).toEqual([]);
    expect(unchangedRuns()).toEqual([]);
  });

  it('ends an organisation’s turn after 3 unanswered calls in a row, each of which would wait its time limit', async () => {
    const { w, acting } = await ready();
    for (let n = 0; n < 6; n += 1) await ask(acting, w, { amount: AED(10_000n) });
    await handoffOf(w).run();
    let asked = 0;
    const down: FakeRail = {
      ...w.rail,
      getExecution: () => {
        asked += 1;
        return Promise.reject(new RailUnavailable());
      },
    };

    await checksOf(w, down).run();

    // The third ends it; at 2 at once, one more may already be under way.
    expect(asked).toBeGreaterThanOrEqual(3);
    expect(asked).toBeLessThanOrEqual(4);
    expect(lines('payment_check.bank_unavailable')).toEqual([expect.objectContaining({ stopped: true })]);

    // One at a time: the third exactly.
    asked = 0;
    capture = new LogCapture();
    await createPaymentChecks({
      list: () => Promise.resolve([w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: down,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
      limits: { total: 1, perOrganisation: 1 },
    }).run();
    expect(asked).toBe(3);
  });

  it('counts each organisation’s unanswered calls in a row of its own', async () => {
    const worlds: World[] = [];
    for (let n = 0; n < 2; n += 1) {
      const { w, acting } = await ready();
      for (let at = 0; at < 4; at += 1) await ask(acting, w, { amount: AED(10_000n) });
      await handoffOf(w).run();
      worlds.push(w);
    }
    const asked: string[] = [];
    const [first] = worlds;
    if (first === undefined) throw new Error('no world');
    const down: FakeRail = {
      ...first.rail,
      getExecution: (ref) => {
        asked.push(ref.organizationId);
        return Promise.reject(new RailUnavailable());
      },
    };

    await createPaymentChecks({
      list: () => Promise.resolve(worlds.map(({ org }) => org)),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: down,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
      limits: { total: 1, perOrganisation: 1 },
    }).run();

    // Turn about, each to its own third: not ended by the other's.
    for (const { org } of worlds) expect(asked.filter((asker) => asker === org)).toHaveLength(3);
  });

  it.each([
    ['an answer it can’t read', (): Promise<ExecutionLookup> => Promise.reject(new TypeError('not JSON'))],
    [
      'credited, but about another amount',
      (found: ExecutionLookup): ExecutionLookup =>
        found.kind === 'found'
          ? {
              kind: 'found',
              execution: {
                ...found.execution,
                providerStatus: 'AcceptedCreditSettlementCompleted',
                amountMinor: found.execution.amountMinor + 1n,
              },
            }
          : found,
    ],
    [
      'credited, but about another instruction',
      (found: ExecutionLookup): ExecutionLookup =>
        found.kind === 'found'
          ? {
              kind: 'found',
              execution: {
                ...found.execution,
                providerStatus: 'AcceptedCreditSettlementCompleted',
                instructionId: ids.next(),
              },
            }
          : found,
    ],
  ] as const)('marks UNKNOWN, never success, for %s, and raises the alarm', async (_name, answer) => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();

    await checksOf(w, answering(w, answer)).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN', providerStatus: 'Pending' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(lines('payment_check.unreadable')).toHaveLength(1);
    // Our status moved on no new word of the bank's: the move alone keeps the line.
    expect(lines('payment_check.checked')).toEqual([
      expect.objectContaining({ from: 'PROCESSING', to: 'UNKNOWN', newBankStatus: null }),
    ]);
    expect(await remittancesOf(w)).toEqual([]);
  });

  it('leaves settled one the bank contradicts once its word was read (rail map §4), and says so (forced)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    // One check's word held back until another settled the payment as credited.
    const { promise: release, resolve } = Promise.withResolvers<undefined>();
    const { promise: asked, resolve: asking } = Promise.withResolvers<undefined>();
    const rejectedLate = answering(w, async (found) => {
      asking(undefined);
      await release;
      return found.kind === 'found'
        ? { kind: 'found', execution: { ...found.execution, providerStatus: 'Rejected', rejectCode: 'AANI.FF01' } }
        : found;
    });
    const late = checksOf(w, rejectedLate).run();
    await asked;
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });

    resolve(undefined);
    await late;

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED', providerStatus: 'Rejected' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(lines('payment_check.contradicts')).toEqual([
      expect.objectContaining({ status: 'SUCCEEDED', bank: 'Rejected' }),
    ]);
    expect(await remittancesOf(w)).toHaveLength(1);
    expect(await alertsOf(w, (await transactionOf(w, request.id)).id)).toEqual({
      kept: [{ action: 'payment.contradicted', details: { status: 'SUCCEEDED', bank: 'Rejected' } }],
      emailed: ['payment_contradicted'],
    });
  });

  it('keeps checking a paid one for 7 days: the bank going back on it leaves it paid, said once (rail map §4)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    let asked = 0;
    // At first a newer word that doesn't go back on the payment (settled at the debtor); then Rejected.
    let bank: 'AcceptedSettlementCompleted' | 'Rejected' = 'AcceptedSettlementCompleted';
    const rejectedAfter = answering(w, (found) => {
      asked += 1;
      return found.kind === 'found'
        ? {
            kind: 'found',
            execution: {
              ...found.execution,
              providerStatus: bank,
              rejectCode: bank === 'Rejected' ? 'AANI.FF01' : null,
            },
          }
        : found;
    });
    const checks = checksOf(w, rejectedAfter);

    // Its first run checks every one, the paid among them; then every 30 minutes from that turn, none sooner.
    await checks.run();
    expect(asked).toBe(1);
    expect(await transactionOf(w, request.id)).toMatchObject({ providerStatus: 'AcceptedSettlementCompleted' });
    expect(lines('payment_check.contradicts')).toEqual([]);
    clock.advanceBy(30 * STEP - 1);
    await checks.run();
    expect(asked).toBe(1);
    clock.advanceBy(1);
    bank = 'Rejected';
    await checks.run();
    expect(asked).toBe(2);

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED', providerStatus: 'Rejected' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(lines('payment_check.contradicts')).toEqual([
      expect.objectContaining({ status: 'SUCCEEDED', bank: 'Rejected' }),
    ]);
    expect(await remittancesOf(w)).toHaveLength(1);

    // Past 7 days, no longer asked.
    clock.advanceBy(7 * 24 * 60 * STEP);
    await checksOf(w, rejectedAfter).run();
    expect(asked).toBe(2);
  });

  it('watches one marked failed a week from the mark, not from its hand-off (gate H3; E1c)', async () => {
    // Its hand-off 8 days ago (the database seals the mark at its own now, so the test's clock starts back then).
    const DAY = 24 * 60 * STEP;
    startClock(new Date(Date.now() - 8 * DAY));
    const { w, acting } = await ready();
    // .04 fils: Rejected with no proof the money stayed: UNKNOWN.
    const request = await ask(acting, w, { amount: ALLOWED(4n) });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });

    // Today an admin marks it failed on their bank's written word (its route: mark-failed.db.test.ts).
    clock.advanceBy(8 * DAY - 4 * STEP);
    const transactionId = (await transactionOf(w, request.id)).id;
    await withSignedStates(app, w.org, { keys, ids, logger: testLogger(capture) }, (tx, states) =>
      markFailed(tx, states, createOutbox({ ids, clock }), {
        orgId: w.org,
        transactionId,
        userId: w.admin.userId,
        details: { evidenceRef: 'BANK-NACK-77312' },
        at: clock.now(),
      }),
    );
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED' });

    let asked = 0;
    const counted = answering(w, (found) => {
      asked += 1;
      return found;
    });
    // A run's first pass asks every one watched: this one, its hand-off 8 days back, its mark today.
    await checksOf(w, counted).run();
    expect(asked).toBe(1);

    // A week past the mark (with room for the minutes the test's clock runs behind the database's), no longer asked.
    clock.advanceBy(7 * DAY + 5 * STEP);
    await checksOf(w, counted).run();
    expect(asked).toBe(1);
  });

  it('changes nothing for an answer older than the word kept: already read, never an alert (forced)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(STEP);
    // One check's word (Rejected, a minute in) held back until another read the newer one (credited): were it
    // applied, a paid payment would read as contradicted.
    const { promise: release, resolve } = Promise.withResolvers<undefined>();
    const { promise: asked, resolve: asking } = Promise.withResolvers<undefined>();
    const held = answering(w, async (found) => {
      asking(undefined);
      await release;
      return found.kind === 'found'
        ? { kind: 'found', execution: { ...found.execution, providerStatus: 'Rejected', rejectCode: 'AANI.FF01' } }
        : found;
    });
    const late = checksOf(w, held).run();
    await asked;
    clock.advanceBy(STEP);
    await checksOf(w).run();
    const credited = await transactionOf(w, request.id);
    expect(credited).toMatchObject({ status: 'SUCCEEDED' });

    resolve(undefined);
    await late;

    expect(await transactionOf(w, request.id)).toEqual(credited);
    expect(lines('payment_check.contradicts')).toEqual([]);
    // The middle run's move is the only line; the late one was applied to the settled payment, and changed nothing.
    expect(lines('payment_check.checked')).toEqual([expect.objectContaining({ from: 'PROCESSING', to: 'SUCCEEDED' })]);
    expect(unchangedRuns()).toEqual([1]);
  });

  it('says each check of an UNKNOWN payment unresolved past a day, for reconciliation; its admins told once each (37b)', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w, { amount: SMALL(4n) });
    const second = await ask(acting, w, { amount: SMALL(4n) });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    expect(lines('payment_check.still_unknown')).toEqual([]);

    clock.advanceBy(24 * 60 * STEP);
    await checksOf(w).run();
    await checksOf(w).run();

    expect(lines('payment_check.still_unknown')).toHaveLength(4);
    // Each one's admins emailed once, kept once, beside the rejection that made it UNKNOWN (decision 37b).
    for (const request of [first, second]) {
      expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
      expect(await alertsOf(w, (await transactionOf(w, request.id)).id)).toEqual({
        kept: [
          { action: 'payment.rejected_unproven', details: { bank: 'Rejected' } },
          { action: 'payment.still_unknown', details: {} },
        ],
        emailed: ['payment_unproven', 'payment_still_unknown'],
      });
    }
  });
});

describe('when and how often (the partner’s rate limits)', () => {
  /** The world's fake, its lookups counted, each payment kept under way. */
  const counting = (w: World) => {
    let asked = 0;
    const rail = answering(w, (found) => {
      asked += 1;
      return found.kind === 'found'
        ? { kind: 'found', execution: { ...found.execution, providerStatus: 'Pending' } }
        : found;
    });
    return { rail, asked: () => asked };
  };

  it('checks a payment under 15 minutes old every run, under a day every 5 minutes, older every 30, by its organisation’s own turns; every one first', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const { rail, asked } = counting(w);
    const checks = checksOf(w, rail);
    /** `n` runs, a minute apart. */
    const runs = async (n: number) => {
      for (let run = 0; run < n; run += 1) {
        await checks.run();
        clock.advanceBy(STEP);
      }
    };

    await runs(2);
    expect(asked()).toBe(2);

    // Past 15 minutes: its day's turn, last taken at the first run, is due at once; then 5 minutes on.
    clock.advanceBy(13 * STEP + 1);
    await runs(1);
    expect(asked()).toBe(3);
    await runs(4);
    expect(asked()).toBe(3);
    await runs(1);
    expect(asked()).toBe(4);

    // Past a day: its slower turn, last taken at the first run, at once; then 30 minutes on.
    clock.advanceBy(24 * 60 * STEP);
    await runs(1);
    expect(asked()).toBe(5);
    await runs(29);
    expect(asked()).toBe(5);
    await runs(1);
    expect(asked()).toBe(6);
  });

  it('pages through them all, oldest first, a page at a time', async () => {
    const { w, acting } = await ready();
    const requests = [
      await ask(acting, w, { amount: SMALL() }),
      await ask(acting, w, { amount: SMALL() }),
      await ask(acting, w, { amount: SMALL() }),
    ];
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);

    await createPaymentChecks({
      list: () => Promise.resolve([w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: w.rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: createRailHealth({ clock, logger: testLogger(capture) }),
      databaseGate: handoffDatabaseGate(6),
      page: 2,
    }).run();

    for (const request of requests) expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
  });

  it('stops between payments once the signal is aborted', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: SMALL() });
    await ask(acting, w, { amount: SMALL() });
    await handoffOf(w).run();
    const stopping = new AbortController();
    const rail = answering(w, (found) => {
      stopping.abort();
      return found;
    });

    await checksOf(w, rail).run(stopping.signal);

    // The one that stopped it, and the one already under way beside it, at 2 an organisation.
    const [checked, ...others] = unchangedRuns();
    expect(others).toEqual([]);
    expect(checked).toBeGreaterThanOrEqual(1);
    expect(checked).toBeLessThanOrEqual(2);
  });

  it('begins no more once the signal is aborted, one at a time', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: SMALL() });
    await ask(acting, w, { amount: SMALL() });
    await handoffOf(w).run();
    const stopping = new AbortController();
    const rail = answering(w, (found) => {
      stopping.abort();
      return found;
    });

    await createPaymentChecks({
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
      limits: { total: 1, perOrganisation: 1 },
    }).run(stopping.signal);

    expect(unchangedRuns()).toEqual([1]);
  });

  it('refuses to start with the bank’s time limit past when an answer is due', () => {
    expect(() =>
      createPaymentChecks({
        list: () => Promise.resolve([]),
        database: app,
        outbox: createOutbox({ ids, clock }),
        rail: {} as FakeRail,
        keys,
        ids,
        clock,
        logger: testLogger(capture),
        health: createRailHealth({ clock, logger: testLogger(capture) }),
        databaseGate: handoffDatabaseGate(6),
        callTimeoutMs: 60_000,
      }),
    ).toThrow(RangeError);
  });

  it('beats for /health while it runs; one that can’t list its organisations reads as stopped (ADR-013)', async () => {
    const { w } = await ready();
    const checks = checksOf(w);
    await checks.run();
    const [check] = heartbeatChecks({ payment_checks: checks });
    expect(check?.name).toBe('payment_checks_heartbeat');
    expect(await check?.check()).toBe(true);

    const failing = checksOf(w, w.rail, () => Promise.reject(new Error('directory down')));
    clock.advanceBy(HEARTBEAT_STALE_MS + 1);
    await failing.run();
    expect(failing.beating()).toBe(false);
    expect(await check?.check()).toBe(false);
    expect(lines('payment_check.run_failed')).toHaveLength(1);
  });
});

describe('failures logged, the run going on', () => {
  it.each([
    ['transaction', TRANSACTIONS],
    ['instruction', INSTRUCTIONS],
  ] as const)(
    'says so for a payment whose %s can’t be believed (its alarm raised), and checks the next',
    async (_name, table) => {
      const { w, acting } = await ready();
      const tampered = await ask(acting, w, { amount: SMALL() });
      const fine = await ask(acting, w, { amount: SMALL() });
      await handoffOf(w).run();
      const { id, instructionId } = await transactionOf(w, tampered.id);
      const owner = await tamperAsOwner(database, table, w.org);
      try {
        await owner.stripSeals(table === TRANSACTIONS ? id : instructionId);
      } finally {
        await owner.end();
      }
      clock.advanceBy(2 * STEP);

      await checksOf(w).run();

      expect(lines('payment_check.failed')).toEqual([expect.objectContaining({ orgId: w.org, transactionId: id })]);
      expect(await transactionOf(w, fine.id)).toMatchObject({ status: 'SUCCEEDED' });
      // A check that failed is never counted among those that changed nothing.
      expect(unchangedRuns()).toEqual([]);
    },
  );

  it('says so when an organisation’s payments can’t be listed, and goes on to the next', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);

    // Not an organisation's ID: its list is refused by the database, and the next organisation is still checked.
    await checksOf(w, w.rail, () => Promise.resolve(['not-a-uuid', w.org])).run();

    expect(lines('payment_check.list_failed')).toEqual([expect.objectContaining({ orgId: 'not-a-uuid' })]);
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
  });
});

describe('in the lock order, racing the hand-off (ADR-006 §6; PL-38)', () => {
  it('settles with its holdings locked before the head, so their holder never waits on it (forced)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    const { promise: answered, resolve: answer } = Promise.withResolvers<undefined>();
    const { promise: called, resolve: calling } = Promise.withResolvers<undefined>();
    const run = checksOf(
      w,
      answering(w, async (found) => {
        calling(undefined);
        await answered;
        return found;
      }),
    ).run();
    await called;
    // Something holding the request's reservation (as an ending or a holdings page would) as the word is applied.
    const holder = await database.connect('owner');
    try {
      await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await holder.query('begin');
      await holder.query('select id from limit_reservations.reservations where request_id = $1 for no key update', [
        request.id,
      ]);
      answer(undefined);
      await waitUntilQueued(database.as('admin'), 1);
      // The check waits at the reservation (11) holding nothing of the head (12): the organisation's head is free.
      const looker = await database.connect('owner');
      try {
        await looker.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
        await expect(
          looker.query('select org_id from audit.heads where org_id = $1 for update nowait', [w.org]),
        ).resolves.toHaveLength(1);
      } finally {
        await looker.end();
      }
      await holder.query('commit');
    } finally {
      await holder.end();
    }
    await run;

    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
  });

  /** The hand-off over the world, its partner's answer to the request made at once but held until let go. */
  const answerHeld = (w: World) => {
    const { promise: gate, resolve, reject } = Promise.withResolvers<undefined>();
    const slow: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        const made = await w.rail.submitApprovedIntent(intent);
        await gate;
        return made;
      },
    };
    return {
      run: handoffOf(w, slow).run(),
      answered: () => {
        resolve(undefined);
      },
      lost: () => {
        reject(new RailUnavailable());
      },
    };
  };

  it('leaves as the bank check moved it one whose own answer was then lost: never back to UNKNOWN (forced, ADR-007 §9)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const handoff = answerHeld(w);
    await expect
      .poll(async () => (await paymentOf(w, request.id)).transaction)
      .toMatchObject({ status: 'SUBMISSION_PENDING' });
    // Its answer due, the bank settled at the debtor but not yet credited: under way, which UNKNOWN could still follow.
    clock.advanceBy(STEP + 1);
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });

    // The hand-off's call then fails with no answer: no word at all, so nothing moves.
    handoff.lost();
    await handoff.run;

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
    expect(lines('handoff.handed_off')).toEqual([expect.objectContaining({ answer: 'unknown', recorded: 'late' })]);
  });

  it('SEC-DP-13 settles once though the check and the hand-off’s sweep reach a payment left waiting at once (forced)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const handoff = answerHeld(w);
    await expect
      .poll(async () => (await paymentOf(w, request.id)).transaction)
      .toMatchObject({ status: 'SUBMISSION_PENDING' });
    const { id } = await transactionOf(w, request.id);
    // Past the sweep's wait and the bank's credit both.
    clock.advanceBy(11 * STEP);
    const holder = await database.connect('owner');
    let racing: Promise<unknown>;
    try {
      await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await holder.query('begin');
      await holder.query('select id from transactions.transactions where id = $1 for update', [id]);
      racing = Promise.all([checksOf(w).run(), handoffOf(w).run()]);
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('commit');
    } finally {
      await holder.end();
    }
    await racing;
    handoff.answered();
    await handoff.run;

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    expect((await movesOf(w, request.id)).filter((action) => action === 'transaction.succeed')).toHaveLength(1);
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(await remittancesOf(w)).toHaveLength(1);
    expect(lines('payment_check.failed')).toEqual([]);
    expect(lines('handoff.sweep_failed')).toEqual([]);
  });

  /** Each fake fils outcome (decision 5), and where the bank's word leaves it once credited or rejected. */
  const OUTCOMES = [
    { fils: 0n, status: 'SUCCEEDED' },
    { fils: 1n, status: 'FAILED' },
    { fils: 2n, status: 'SUCCEEDED' },
    { fils: 3n, status: 'SUCCEEDED' },
    { fils: 4n, status: 'UNKNOWN' },
  ] as const;

  it('pays each once, settles each once, one remittance for each that SUCCEEDED, however the runs race', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.constantFrom(...OUTCOMES), { minLength: 2, maxLength: 5 }),
        fc.integer({ min: 1, max: 3 }),
        async (batch, racing) => {
          capture = new LogCapture();
          const { w, acting } = await ready();
          const asked = [];
          for (const outcome of batch) {
            asked.push({ request: await ask(acting, w, { amount: AED(10_000n + outcome.fils) }), outcome });
          }
          const sent = new Map<string, number>();
          const rail: FakeRail = {
            ...w.rail,
            submitApprovedIntent: (intent) => {
              sent.set(intent.instructionId, (sent.get(intent.instructionId) ?? 0) + 1);
              return w.rail.submitApprovedIntent(intent);
            },
          };
          // Hand-offs and checks at once, a minute on each round, until every payment is past credited.
          for (let round = 0; round < 3; round += 1) {
            await Promise.all(
              Array.from({ length: racing }, () => [handoffOf(w, rail).run(), checksOf(w, rail).run()]).flat(),
            );
            clock.advanceBy(STEP);
          }
          await checksOf(w, rail).run();

          const remittances = await remittancesOf(w);
          for (const { request, outcome } of asked) {
            const payment = await paymentOf(w, request.id);
            const transaction = await transactionOf(w, request.id);
            expect(payment).toMatchObject({ transactions: 1 });
            expect(transaction.status, `fils ${String(outcome.fils)}`).toBe(outcome.status);
            expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER[outcome.status]);
            expect(sent.get(transaction.instructionId)).toBe(1);
            const moves = await movesOf(w, request.id);
            expect(
              moves.filter((action) => action === 'transaction.succeed' || action === 'transaction.fail'),
            ).toHaveLength(outcome.status === 'UNKNOWN' ? 0 : 1);
            expect(remittances.filter((id) => id === transaction.id)).toHaveLength(
              outcome.status === 'SUCCEEDED' ? 1 : 0,
            );
          }
          expect(lines('payment_check.failed')).toEqual([]);
          expect(lines('payment_check.contradicts')).toEqual([]);
          expect(lines('handoff.failed')).toEqual([]);
          expect(lines('handoff.answer_unrecorded')).toEqual([]);
        },
      ),
      { numRuns: 6, endOnFailure: true },
    );
  }, 300_000);
});

describe('on lanes, its lookups the breaker’s way open (4D2e F5)', () => {
  /** A world with `count` payments under way at the bank. */
  async function paymentsUnderWay(count: number) {
    const { w, acting } = await ready();
    const requests: string[] = [];
    for (let n = 0; n < count; n += 1) requests.push((await ask(acting, w, { amount: AED(5_000n) })).id);
    await handoffOf(w).run();
    return { w, acting, requests };
  }

  /** One partner for the worlds: each lookup reaching its own world's fake, or hanging till told where `hung` says. */
  function railOf(worlds: readonly World[], hung: (organizationId: string) => boolean = () => false) {
    const [first] = worlds;
    if (first === undefined) throw new Error('no world');
    const asked: string[] = [];
    const waiting: ((lost: boolean) => void)[] = [];
    const rail: FakeRail = {
      ...first.rail,
      getExecution: async (ref) => {
        asked.push(ref.organizationId);
        const own = worlds.find((w) => w.org === ref.organizationId) ?? first;
        if (hung(ref.organizationId)) {
          const { promise, resolve } = Promise.withResolvers<boolean>();
          waiting.push(resolve);
          if (await promise) throw new RailUnavailable();
        }
        return own.rail.getExecution(ref);
      },
    };
    return { rail, asked, waiting };
  }

  type Options = Parameters<typeof createPaymentChecks>[0];

  const checksOver = (worlds: readonly World[], rail: FakeRail, health: RailHealth, options: Partial<Options> = {}) =>
    createPaymentChecks({
      list: () => Promise.resolve(worlds.map(({ org }) => org)),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health,
      databaseGate: handoffDatabaseGate(6),
      ...options,
    });

  const breaker = () => createRailHealth({ clock, logger: testLogger(capture) });

  /** Everyone held, by unknowns from others. */
  const trip = (health: RailHealth) => {
    for (const org of ['x', 'x', 'y', 'y', 'z']) {
      const entry = health.enter(org);
      if ('settle' in entry) entry.settle('unknown');
    }
    expect(health.heldFor('nobody')).toBe('bank');
  };

  it('a hung organisation’s message keeps no other’s regular check from the bank, in the same run', async () => {
    const hung = await paymentsUnderWay(1);
    const other = await paymentsUnderWay(1);
    const instruction = (await transactionOf(hung.w, hung.requests[0] ?? '')).instructionId;
    await database.as('admin').query(
      `insert into provider_events.inbox (id, partner, dedupe_key, event_type, reference_kind, reference, org_id, received_at)
         values ($1, 'fake', $2, 'payment.update', 'instruction', $3, $4, now())`,
      [ids.next(), ids.next(), instruction, hung.w.org],
    );
    const { rail, asked, waiting } = railOf([hung.w, other.w], (org) => org === hung.w.org);
    // A clock that really moves, so a budget spent is spent.
    const moving = { now: () => new Date() };
    // Credited at the bank: the other's answer moves it, so it has a line while this run is still under way.
    clock.advanceBy(2 * STEP);

    const run = createPaymentChecks({
      list: () => Promise.resolve([hung.w.org, other.w.org]),
      database: app,
      outbox: createOutbox({ ids, clock: moving }),
      rail,
      keys,
      ids,
      clock: moving,
      logger: testLogger(capture),
      health: breaker(),
      databaseGate: handoffDatabaseGate(6),
      events: createProviderEvents({ keys, ids, clock: moving, retentionDays: 30 }),
      runBudgetMs: 2_000,
    }).run();

    // Its message's call hangs; the other's goes past it, in this run, and is answered.
    await expect.poll(() => asked.filter((org) => org === hung.w.org).length, { timeout: 20_000 }).toBeGreaterThan(0);
    await expect.poll(() => asked, { timeout: 20_000 }).toContain(other.w.org);
    await expect.poll(() => lines('payment_check.checked').length, { timeout: 20_000 }).toBeGreaterThan(0);
    expect(waiting.length).toBeGreaterThan(0);

    await expect
      .poll(() => {
        for (const answer of waiting.splice(0)) answer(true);
        return lines('payment_check.bank_unavailable').length;
      })
      .toBe(1);
    await run;
  });

  it('one hung organisation first in the list keeps no other’s lookups from the bank, and the hold clears', async () => {
    const hung = await paymentsUnderWay(4);
    const other = await paymentsUnderWay(1);
    const health = breaker();
    trip(health);
    const { rail, asked, waiting } = railOf([hung.w, other.w], (org) => org === hung.w.org);

    const run = checksOver([hung.w, other.w], rail, health).run();

    // Its two slots hang; the other's lookup goes past them, and answers.
    await expect.poll(() => lines('handoff.bank_half_open'), { timeout: 20_000 }).toHaveLength(1);
    expect(asked.filter((org) => org === hung.w.org)).toHaveLength(2);
    expect(asked).toContain(other.w.org);
    expect(health.heldFor('nobody')).toBeUndefined();

    // Then each lost: its turn ends at 3 in a row, no more asked of it.
    await expect
      .poll(() => {
        for (const answer of waiting.splice(0)) answer(true);
        return lines('payment_check.bank_unavailable').length;
      })
      .toBe(1);
    await run;
    expect(asked.filter((org) => org === hung.w.org).length).toBeLessThanOrEqual(4);

    // Real acceptances, each of the step's three places, take it a step on (whole dirhams: the fake bank accepts).
    for (const amount of [5_000n, 5_100n, 5_200n]) await ask(other.acting, other.w, { amount: AED(amount) });
    await createHandoff({
      list: () => Promise.resolve([other.w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: other.w.rail,
      health,
      databaseGate: handoffDatabaseGate(6),
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    }).run();
    expect(lines('handoff.bank_step')).toHaveLength(1);
  });

  it('says nothing to the breaker for a lookup that didn’t answer', async () => {
    const { w } = await paymentsUnderWay(1);
    const health = breaker();
    trip(health);
    const { rail } = railOf([w], () => true);
    const down: FakeRail = { ...rail, getExecution: () => Promise.reject(new RailUnavailable()) };

    await checksOver([w], down, health).run();

    expect(health.heldFor('nobody')).toBe('bank');
  });

  it('tells the breaker for its own organisation, not_found among the answers', async () => {
    const { w, requests } = await paymentsUnderWay(1);
    const health = breaker();
    trip(health);
    const notFound: FakeRail = { ...w.rail, getExecution: () => Promise.resolve({ kind: 'not_found' }) };
    expect(requests).toHaveLength(1);

    await checksOver([w], notFound, health).run();

    expect(health.heldFor('nobody')).toBeUndefined();
  });

  it('counts no lookup begun before the trip, though it answers after', async () => {
    const { w } = await paymentsUnderWay(1);
    const health = breaker();
    const { rail, waiting } = railOf([w], () => true);
    const run = checksOver([w], rail, health).run();
    await expect.poll(() => waiting.length, { timeout: 20_000 }).toBe(1);

    trip(health);
    waiting[0]?.(false);
    await run;

    expect(health.heldFor('nobody')).toBe('bank');
  });

  it('holds 6 of its 8 for the regular turns, and 2 in an organisation, the rest going as those answer', async () => {
    const worlds = [];
    for (let n = 0; n < 5; n += 1) worlds.push((await paymentsUnderWay(3)).w);
    const { rail, asked, waiting } = railOf(worlds, () => true);

    const run = checksOver(worlds, rail, breaker()).run();
    await expect.poll(() => asked.length, { timeout: 30_000 }).toBe(6);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(asked).toHaveLength(6);
    const byOrganisation = new Map<string, number>();
    for (const org of asked) byOrganisation.set(org, (byOrganisation.get(org) ?? 0) + 1);
    expect(Math.max(...byOrganisation.values())).toBe(2);

    await expect
      .poll(
        () => {
          for (const answer of waiting.splice(0)) answer(false);
          return asked.length;
        },
        { timeout: 60_000 },
      )
      .toBe(15);
    for (const answer of waiting.splice(0)) answer(false);
    await run;
  }, 120_000);

  it('starts no new call past its part of the budget; its next run goes on, its own place kept', async () => {
    const { w } = await paymentsUnderWay(3);
    let spentOnce = false;
    const { rail, asked } = railOf([w]);
    const slow: FakeRail = {
      ...rail,
      getExecution: (ref) => {
        if (!spentOnce) clock.advanceBy(1_000);
        spentOnce = true;
        return rail.getExecution(ref);
      },
    };
    const job = checksOver([w], slow, breaker(), {
      limits: { total: 1, perOrganisation: 1 },
      runBudgetMs: 1_000,
    });

    await job.run();
    // The regular turns' part spent on its first; the lap of the rest takes its own turn.
    expect(asked.length).toBeGreaterThanOrEqual(1);
    const first = asked.length;

    await job.run();
    expect(asked.length).toBeGreaterThan(first);
  });

  describe('old payments, more than a run’s budget of them', () => {
    const DAY = 24 * 60 * 60_000;

    /** A world with `paid` payments still under way, then `count` gone UNKNOWN, all older than a day. */
    async function oldPayments(count: number, paid = 0) {
      const { w, acting } = await ready();
      const unknown: string[] = [];
      const settled: string[] = [];
      // The others first, so an UNKNOWN comes after them in any sweep that takes them together.
      for (let n = 0; n < paid; n += 1) settled.push((await ask(acting, w, { amount: AED(5_000n) })).id);
      await handoffOf(w).run();
      // The fake's .02: made at the partner, its answer lost.
      for (let n = 0; n < count; n += 1) unknown.push((await ask(acting, w, { amount: AED(5_002n) })).id);
      const health = createRailHealth({ clock, logger: testLogger(capture), laneUnknowns: 1_000 });
      await createHandoff({
        list: () => Promise.resolve([w.org]),
        database: app,
        outbox: createOutbox({ ids, clock }),
        rail: w.rail,
        health,
        databaseGate: handoffDatabaseGate(6),
        keys,
        ids,
        clock,
        logger: testLogger(capture),
      }).run();
      clock.advanceBy(2 * DAY);
      return { w, unknown, settled };
    }

    /** The world's rail, each lookup costing a second of the clock and noted by its instruction. */
    const costingASecond = (w: World) => {
      const asked: string[] = [];
      const rail: FakeRail = {
        ...w.rail,
        getExecution: (ref) => {
          asked.push(ref.instructionId);
          clock.advanceBy(1_000);
          return w.rail.getExecution(ref);
        },
      };
      return { rail, asked };
    };

    /** The instruction each request's payment went under. */
    const instructionsOf = async (w: World, requests: readonly string[]) =>
      Promise.all(requests.map(async (id) => (await transactionOf(w, id)).id)).then(() =>
        Promise.all(
          requests.map(async (id) =>
            withTenant(app, w.org, async (tx) => {
              const row = await tx
                .selectFrom('instructions.instructions')
                .select('id')
                .where('spend_request_id', '=', id)
                .executeTakeFirstOrThrow();
              return row.id;
            }),
          ),
        ),
      );

    it('reaches every UNKNOWN within as many runs as they need, not the next 30th', async () => {
      const { w, unknown } = await oldPayments(6);
      const { rail, asked } = costingASecond(w);
      // A second a call, and the UNKNOWNs' part of the budget a second: one a run.
      const job = checksOver([w], rail, breaker(), { limits: { total: 1, perOrganisation: 1 }, runBudgetMs: 3_000 });
      const instructions = await instructionsOf(w, unknown);

      for (let run = 0; run < 7; run += 1) await job.run();

      for (const instruction of instructions) expect(asked).toContain(instruction);
    });

    it('asks the UNKNOWNs ahead of the rest, older though the rest are, however many they are', async () => {
      const { w, unknown, settled } = await oldPayments(1, 6);
      const { rail, asked } = costingASecond(w);
      const job = checksOver([w], rail, breaker(), { limits: { total: 1, perOrganisation: 1 }, runBudgetMs: 3_000 });
      const [unknownInstruction] = await instructionsOf(w, unknown);
      const paid = await instructionsOf(w, settled);

      await job.run();

      expect(asked).toContain(unknownInstruction);
      // The rest's part of the budget a little: not all of them this run.
      expect(paid.filter((instruction) => asked.includes(instruction)).length).toBeLessThan(paid.length);
    });

    it('says a lap that outlasts its time, once; none that keeps to it', async () => {
      const { w } = await oldPayments(4);
      const { rail } = costingASecond(w);
      const job = checksOver([w], rail, breaker(), { limits: { total: 1, perOrganisation: 1 }, runBudgetMs: 3_000 });

      await job.run();
      expect(lines('payment_check.lap_behind')).toEqual([]);

      clock.advanceBy(31 * 60_000);
      await job.run();
      await job.run();

      expect(lines('payment_check.lap_behind')).toEqual([expect.objectContaining({ sweep: 'unknown', level: 'warn' })]);
    });

    it('keeps a turn cut short going past its next time, unrestarted: said once however long', async () => {
      const { w } = await oldPayments(1);
      // No budget: it goes nowhere, run after run.
      const job = checksOver([w], w.rail, breaker(), { runBudgetMs: 0 });

      await job.run();
      clock.advanceBy(31 * 60_000);
      for (let run = 1; run < 30; run += 1) await job.run();
      expect(lines('payment_check.lap_behind').filter(({ sweep }) => sweep === 'unknown')).toHaveLength(1);

      // Its 31st run, when another would begin, and one more: a restart would have it said again.
      await job.run();
      clock.advanceBy(31 * 60_000);
      await job.run();
      expect(lines('payment_check.lap_behind').filter(({ sweep }) => sweep === 'unknown')).toHaveLength(1);

      // Past an hour behind, still taken each run, its time is kept: forgetting it would say it again.
      await job.run();
      clock.advanceBy(31 * 60_000);
      await job.run();
      expect(lines('payment_check.lap_behind').filter(({ sweep }) => sweep === 'unknown')).toHaveLength(1);
    });

    it('holds the regular turns to their part of the budget, so the laps get theirs', async () => {
      const { w, acting } = await ready();
      for (let n = 0; n < 4; n += 1) await ask(acting, w, { amount: AED(5_000n) });
      await handoffOf(w).run();
      const { rail, asked } = costingASecond(w);
      const job = checksOver([w], rail, breaker(), { limits: { total: 1, perOrganisation: 1 }, runBudgetMs: 2_000 });

      await job.run();

      // The regular turns' second, spent on one; the lap of the rest takes one more in its own.
      expect(asked).toHaveLength(2);
    });

    it('asks an UNKNOWN again 30 minutes after its last whole turn, however many runs come between', async () => {
      const { w, unknown } = await oldPayments(1);
      const { rail, asked } = costingASecond(w);
      const job = checksOver([w], rail, breaker());
      const [instruction] = await instructionsOf(w, unknown);

      for (let run = 0; run < 30; run += 1) await job.run();
      expect(asked.filter((id) => id === instruction)).toHaveLength(1);

      clock.advanceBy(30 * 60_000);
      await job.run();
      expect(asked.filter((id) => id === instruction)).toHaveLength(2);
    });
  });

  it('a stop never waits out a hung bank: it ends clean, a late answer moving nothing', async () => {
    const { w, requests } = await paymentsUnderWay(1);
    const { rail: hanging, waiting } = railOf([w], () => true);
    // Its late answer would move it, were it read: credited.
    const rail: FakeRail = {
      ...hanging,
      getExecution: async (ref): Promise<ExecutionLookup> => {
        const found = await hanging.getExecution(ref);
        return found.kind === 'found'
          ? {
              kind: 'found',
              execution: { ...found.execution, providerStatus: 'AcceptedCreditSettlementCompleted' as const },
            }
          : found;
      },
    };
    const stopping = new AbortController();
    const run = checksOver([w], rail, breaker(), { stopWaitMs: 50 }).run(stopping.signal);
    await expect.poll(() => waiting.length, { timeout: 20_000 }).toBe(1);

    stopping.abort();
    await within(5_000, run, 'the stop');

    const before = await transactionOf(w, requests[0] ?? '');
    waiting[0]?.(false);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(before).toMatchObject({ status: 'PROCESSING' });
    expect(await transactionOf(w, requests[0] ?? '')).toEqual(before);
    expect(lines('payment_check.checked')).toEqual([]);
    expect(capture.lines().filter((line) => line.level === 'error')).toEqual([]);
  });

  it('waits for what is under way at a stop that isn’t held up', async () => {
    const { w } = await paymentsUnderWay(1);
    const { rail, waiting } = railOf([w], () => true);
    const stopping = new AbortController();
    const run = checksOver([w], rail, breaker()).run(stopping.signal);
    await expect.poll(() => waiting.length, { timeout: 20_000 }).toBe(1);

    stopping.abort();
    waiting[0]?.(false);
    await run;

    expect(unchangedRuns()).toEqual([1]);
  });

  it('keeps the line of a check where the bank moved but our status didn’t; the same word twice has none', async () => {
    const { w, requests } = await paymentsUnderWay(1);
    const checks = checksOf(w);
    await checks.run();
    const before = lines('payment_check.checked').length;
    const counted = unchangedRuns().length;

    // The same word again: nothing changed at all.
    await checks.run();
    expect(lines('payment_check.checked')).toHaveLength(before);
    expect(unchangedRuns()).toHaveLength(counted + 1);

    // The bank moved on, under the same status of ours.
    clock.advanceBy(STEP);
    await checks.run();
    expect(await transactionOf(w, requests[0] ?? '')).toMatchObject({
      status: 'PROCESSING',
      providerStatus: 'AcceptedSettlementCompleted',
    });
    expect(lines('payment_check.checked').slice(before)).toEqual([
      expect.objectContaining({
        from: 'PROCESSING',
        to: 'PROCESSING',
        newBankStatus: 'AcceptedSettlementCompleted',
      }),
    ]);
    expect(unchangedRuns()).toHaveLength(counted + 1);

    // And that word again: nothing changed at all.
    await checks.run();
    expect(lines('payment_check.checked')).toHaveLength(before + 1);
    expect(unchangedRuns()).toHaveLength(counted + 2);
  });

  it('counts the checks that changed nothing once a run; one that moved keeps its line; both name the run', async () => {
    const { w, requests } = await paymentsUnderWay(3);
    const moved = await transactionOf(w, requests[0] ?? '');
    const rail: FakeRail = {
      ...w.rail,
      getExecution: async (ref): Promise<ExecutionLookup> => {
        const found = await w.rail.getExecution(ref);
        return found.kind === 'found' && ref.instructionId === moved.instructionId
          ? {
              kind: 'found',
              execution: { ...found.execution, providerStatus: 'AcceptedCreditSettlementCompleted' as const },
            }
          : found;
      },
    };

    await asARun(() => checksOver([w], rail, breaker()).run());

    const said = lines('payment_check.checked');
    expect(said).toEqual([
      expect.objectContaining({
        transactionId: moved.id,
        from: 'PROCESSING',
        to: 'SUCCEEDED',
        orgId: w.org,
        runId: expect.any(String) as string,
      }),
    ]);
    expect(lines('payment_check.run_unchanged')).toEqual([
      expect.objectContaining({ level: 'info', unchanged: 2, runId: said[0]?.runId }),
    ]);
  });

  it('drops only the line of a check that went well: a warning or an error on an unchanged payment stays, naming its run', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: SMALL(4n) });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    await asARun(() => checksOf(w).run());
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });

    clock.advanceBy(24 * 60 * STEP);
    await asARun(() => checksOf(w).run());
    await asARun(() =>
      checksOf(w, { ...w.rail, getExecution: () => Promise.reject(new Error('an answer past reading')) }).run(),
    );

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    // Both later runs' checks left it as it was, so neither has a line of its own; what each had to say stands.
    expect(lines('payment_check.checked')).toHaveLength(1);
    expect(unchangedRuns()).toEqual([1, 1]);
    const problems = capture
      .lines()
      .filter(({ level, event }) => level !== 'info' && String(event).startsWith('payment_check.'));
    expect(problems.map(({ level, event }) => [level, event])).toEqual([
      ['error', 'payment_check.rejected_unproven'],
      ['warn', 'payment_check.still_unknown'],
      ['error', 'payment_check.unreadable'],
      ['warn', 'payment_check.still_unknown'],
    ]);
    for (const problem of problems) expect(problem.runId).toEqual(expect.any(String));
  });

  it('says it when a page can’t be read, and goes on to the next organisation', async () => {
    const { w } = await paymentsUnderWay(1);
    const { rail, asked } = railOf([w]);

    await createPaymentChecks({
      list: () => Promise.resolve(['not-an-organisation', w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      health: breaker(),
      databaseGate: handoffDatabaseGate(6),
    }).run();

    expect(lines('payment_check.list_failed')).toHaveLength(1);
    expect(asked).toEqual([w.org]);
  });
});
