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
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { type ExecutionLookup, type FakeRail, RailUnavailable } from '@agentx/core/modules/providers';
import { TRANSACTIONS } from '@agentx/core/modules/transactions';
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
} from '@agentx/testing';
import fc from 'fast-check';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, HEARTBEAT_STALE_MS } from './handoff.ts';
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
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

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
  // Born paused (ADR-014 §4): resumed for these tests, as the operator would.
  await app
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
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
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

    // Its answer not yet due: left to its own Tx B.
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUBMISSION_PENDING' });

    clock.advanceBy(2 * STEP);
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
  });

  it('leaves one the bank doesn’t find as it was: not found proves nothing', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();

    await checksOf(
      w,
      answering(w, () => ({ kind: 'not_found' })),
    ).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    expect(lines('payment_check.checked')).toEqual([
      expect.objectContaining({ answer: 'not_found', to: 'PROCESSING' }),
    ]);
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
  });

  it('ends the run after 3 unanswered calls in a row, each of which would wait its time limit', async () => {
    const { w, acting } = await ready();
    for (let n = 0; n < 4; n += 1) await ask(acting, w, { amount: AED(10_000n) });
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

    expect(asked).toBe(3);
    expect(lines('payment_check.bank_unavailable')).toEqual([expect.objectContaining({ unreached: 3, stopped: true })]);
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
  });

  it('keeps checking a paid one for 7 days: the bank going back on it leaves it paid, said once (rail map §4)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    let asked = 0;
    const rejectedAfter = answering(w, (found) => {
      asked += 1;
      return found.kind === 'found'
        ? { kind: 'found', execution: { ...found.execution, providerStatus: 'Rejected', rejectCode: 'AANI.FF01' } }
        : found;
    });
    const checks = checksOf(w, rejectedAfter);

    // Its first run checks every one, the paid among them; then every 30th.
    await checks.run();
    expect(asked).toBe(1);
    for (let run = 1; run < 30; run += 1) await checks.run();
    expect(asked).toBe(1);
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

  it('changes nothing for an answer older than the word kept: already read, never an alert (forced)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(STEP);
    // One check's word (settled at the debtor, a minute in) held back until another read the newer one (credited).
    const { promise: release, resolve } = Promise.withResolvers<undefined>();
    const { promise: asked, resolve: asking } = Promise.withResolvers<undefined>();
    const held = answering(w, async (found) => {
      asking(undefined);
      await release;
      return found;
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
    expect(lines('payment_check.checked').at(-1)).toMatchObject({ from: 'SUCCEEDED', to: 'SUCCEEDED' });
  });

  it('says each check of an UNKNOWN payment unresolved past a day, for reconciliation', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(4n) });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    await checksOf(w).run();
    expect(lines('payment_check.still_unknown')).toEqual([]);

    clock.advanceBy(24 * 60 * STEP);
    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(lines('payment_check.still_unknown')).toHaveLength(1);
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

  it('checks a payment under 15 minutes old every run, under a day every 5th, older every 30th; every one first', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const { rail, asked } = counting(w);
    const checks = checksOf(w, rail);
    const runs = async (n: number) => {
      for (let run = 0; run < n; run += 1) await checks.run();
    };

    await runs(2);
    expect(asked()).toBe(2);

    clock.advanceBy(15 * STEP + 1);
    // Runs 2–4 skip it; the 5th (run 5) checks it.
    await runs(3);
    expect(asked()).toBe(2);
    await runs(1);
    expect(asked()).toBe(3);

    clock.advanceBy(24 * 60 * STEP);
    // Runs 6–29 skip it; run 30 checks it.
    await runs(24);
    expect(asked()).toBe(3);
    await runs(1);
    expect(asked()).toBe(4);
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

    expect(lines('payment_check.checked')).toHaveLength(1);
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

  it('settles once though the check and the hand-off’s sweep reach a payment left waiting at once (forced)', async () => {
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
