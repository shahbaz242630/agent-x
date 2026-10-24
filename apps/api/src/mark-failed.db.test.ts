// Phase 4 E1c: Agent X's own team marks an UNKNOWN payment failed on the
// bank's written word (ADR-007 §10; partner decision, S141: our team only),
// on the real migrated schema as the app role. Marked: FAILED, its held money
// and its order given back, `transaction.fail` on the organisation's chain
// naming both references, its admins told, the platform chain's record; a
// request run again changes nothing; refused, with nothing changed, unless
// the payment is UNKNOWN past a day, or for a request ID naming another
// record, or a payment or organisation that isn't there; a record that can't
// be believed holds the organisation, the hold under an ID of its own. The
// bank check still watches it a week: paid after all, it is said. With the bank check
// at the same payment (forced), whichever takes it first settles it and the
// other finds it settled. The operator's command around it, from its request
// file, is apps/operator's main.db.test.ts.
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import {
  MARK_FAILED_AFTER_MS,
  MarkFailedRefused,
  type MarkFailedRequest,
  markPaymentFailed,
  PLATFORM_MARKED_FAILED,
} from '@agentx/core/modules/outcomes';
import { changeHandoffPause, createPlatformChain, platformEventWith } from '@agentx/core/modules/platform-controls';
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
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables, HOLDS_AFTER } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xe1c0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xe1c1_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'mark-failed',
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

/** Agent X's own team, as the operator's command names itself. */
const OPERATOR = { type: 'system', id: 'operator' } as const;

/** A step of the fake's payment: settled at the debtor a minute on, its answer final after two (B2). */
const STEP = 60_000;

/** The fils that make the fake reject it with no proof the money stayed: UNKNOWN, reconciliation's (rail map §4). */
const REJECTED_UNPROVEN = 4n;

/** The fils that lose the hand-off's answer, the bank crediting it after two steps: UNKNOWN until then. */
const ANSWER_LOST = 2n;

const handoffOf = (w: World) =>
  createHandoff({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail: w.rail,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
  });

const checksOf = (w: World) =>
  createPaymentChecks({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail: w.rail,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
  });

/** The request's transaction as it stands. */
const transactionOf = async (w: World, requestId: string) => {
  const payment = await paymentOf(w, requestId);
  if (typeof payment.transaction !== 'object') throw new Error(`no transaction: ${String(payment.transaction)}`);
  return payment.transaction;
};

/** A payment of the world handed off with these fils, then left as the bank check finds it two steps on, unless unchecked. */
async function handedOff(fils: bigint, { checked = true } = {}) {
  const { w, acting } = await ready();
  const request = await ask(acting, w, { amount: ALLOWED(fils) });
  await handoffOf(w).run();
  clock.advanceBy(2 * STEP);
  if (checked) await checksOf(w).run();
  return { w, acting, request, transaction: await transactionOf(w, request.id) };
}

/** What the operator's request asks, for the world's payment. */
const asking = (w: World, transactionId: string, id = ids.next()): MarkFailedRequest => ({
  actor: OPERATOR,
  orgId: w.org,
  transactionId,
  reason: 'CASE-2026/0042',
  evidence: 'BANK-NACK-77311',
  id,
  release: 'r-test',
  run: null,
});

const mark = (request: MarkFailedRequest) =>
  markPaymentFailed(app, { keys, ids, logger: testLogger(capture), clock }, request);

/** The problems a mark is refused with, or none. */
const refusal = async (request: MarkFailedRequest) => {
  try {
    await mark(request);
    return undefined;
  } catch (error) {
    if (error instanceof MarkFailedRefused) return error.problems;
    throw error;
  }
};

/** The signed moves of the transaction, in order, with their actors and details. */
const movesOf = (w: World, transactionId: string) => shared.eventsAbout(w.org, transactionId, TRANSACTIONS.subject);

/** The world's notices that a payment was marked failed, by the transaction each is about. */
const markNoticesOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        // A global table (0021): the world's own organisation's notices alone.
        .selectFrom('notifications.outbox')
        .select(['about_id', 'recipient_user_id'])
        .where('org_id', '=', w.org)
        .where('kind', '=', 'payment_marked_failed')
        .execute()
    ).map(({ about_id, recipient_user_id }) => ({ aboutId: about_id, to: recipient_user_id })),
  );

/** The IDs of the organisation's integrity holds, on its chain. */
const holdsOf = async (w: World) =>
  (
    await withTenant(app, w.org, (tx) =>
      tx.selectFrom('audit.events').select('id').where('action', '=', 'integrity_hold.set').execute(),
    )
  ).map(({ id }) => id);

/** The ID of the event that opened the transaction, on its organisation's chain. */
const openedEventOf = async (w: World, transactionId: string) => {
  const [opened] = await withTenant(app, w.org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select('id')
      .where('subject_id', '=', transactionId)
      .where('action', '=', 'transaction.opened')
      .execute(),
  );
  return opened?.id ?? '';
};

const platformMarked = (request: MarkFailedRequest) =>
  platformEventWith(app, PLATFORM_MARKED_FAILED, {
    orgId: request.orgId,
    transactionId: request.transactionId,
    requestId: request.id,
    reason: request.reason,
    evidenceRef: request.evidence,
  });

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
        { paused: false, reason: 'TEST-E1C', actor: OPERATOR, release: 'r-test', run: null },
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

describe('an UNKNOWN payment marked failed by our team (E1c; ADR-007 §10)', () => {
  it('moves it to FAILED, gives back its money and its order, signs both chains and tells every admin', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    expect(transaction).toMatchObject({ status: 'UNKNOWN', providerStatus: 'Rejected' });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const asked = asking(w, transaction.id);

    expect(await mark(asked)).toMatchObject({ outcome: 'marked' });

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED', providerStatus: 'Rejected' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect((await movesOf(w, transaction.id)).at(-1)).toMatchObject({
      action: 'transaction.fail',
      actorType: 'system',
      details: { via: 'operator', reason: asked.reason, evidenceRef: asked.evidence, statusFrom: 'UNKNOWN' },
    });
    // To no one person: every admin, found as it is sent.
    expect(await markNoticesOf(w)).toEqual([{ aboutId: transaction.id, to: null }]);
    expect(await platformMarked(asked)).toBe(true);
  });

  it('is still watched by the bank check: the bank paying it after all is said, never applied (rail map §4)', async () => {
    const { w, request, transaction } = await handedOff(ANSWER_LOST, { checked: false });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    await mark(asking(w, transaction.id));

    // A new check's first run checks every one, the watched among them.
    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'FAILED',
      providerStatus: 'AcceptedCreditSettlementCompleted',
    });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(lines('payment_check.contradicts')).toEqual([
      expect.objectContaining({ transactionId: transaction.id, status: 'FAILED' }),
    ]);
  });

  it('says nothing more of one the bank still calls rejected', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    await mark(asking(w, transaction.id));

    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED' });
    expect(lines('payment_check.contradicts')).toEqual([]);
  });

  it('changes nothing for the same request run again: one move, one notice, one platform record', async () => {
    const { w, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const asked = asking(w, transaction.id);
    await mark(asked);

    expect(await mark(asked)).toEqual({ outcome: 'marked_before' });

    expect((await movesOf(w, transaction.id)).filter(({ action }) => action === 'transaction.fail')).toHaveLength(1);
    expect(await markNoticesOf(w)).toHaveLength(1);
  });

  it('is refused, changing nothing, for a payment not UNKNOWN', async () => {
    const { w, request, transaction } = await handedOff(0n, { checked: false });
    expect(transaction.status).toBe('PROCESSING');
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const asked = asking(w, transaction.id);

    expect(await refusal(asked)).toEqual([
      "the payment is PROCESSING: only one whose outcome can't be known (UNKNOWN) is marked failed",
    ]);

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
    expect(await markNoticesOf(w)).toEqual([]);
    expect(await platformMarked(asked)).toBe(false);
  });

  it('is refused within a day of its hand-off, when the bank may still settle it, and marked just past it', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    // Its hand-off was two steps ago: a day on from it, to the millisecond, is still within.
    clock.advanceBy(MARK_FAILED_AFTER_MS - 2 * STEP);

    expect(await refusal(asking(w, transaction.id))).toEqual([
      'the payment was handed off less than 24 hours ago: the bank may still settle it, so wait past that',
    ]);
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);

    clock.advanceBy(1);
    expect(await mark(asking(w, transaction.id))).toMatchObject({ outcome: 'marked' });
  });

  it('is refused for a request ID naming another record: another payment’s mark, here or in another organisation', async () => {
    const first = await handedOff(REJECTED_UNPROVEN);
    const second = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const asked = asking(first.w, first.transaction.id);
    await mark(asked);
    const another = 'the ID names another record: write a new request';

    // Another payment of the same organisation, with the first's ID.
    const third = await ask(first.acting, first.w, { amount: ALLOWED(REJECTED_UNPROVEN) });
    await handoffOf(first.w).run();
    const thirdPayment = await transactionOf(first.w, third.id);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    expect(await refusal({ ...asking(first.w, thirdPayment.id), id: asked.id })).toEqual([another]);
    expect(await transactionOf(first.w, third.id)).toMatchObject({ status: thirdPayment.status });
    // Another organisation's payment, with the first's ID.
    expect(await refusal({ ...asking(second.w, second.transaction.id), id: asked.id })).toEqual([another]);
    expect(await transactionOf(second.w, second.request.id)).toMatchObject({ status: 'UNKNOWN' });
    // The first organisation's own event, its transaction's opening, by its ID.
    expect(await refusal({ ...asked, id: await openedEventOf(first.w, first.transaction.id) })).toEqual([another]);
  });

  it.each([
    ['a payment not of the organisation', 'payment', 'no payment of this organisation has this ID'],
    ['an organisation not there', 'organisation', 'no organisation has this ID'],
  ] as const)('is refused for %s', async (_name, unknown, problem) => {
    const { w, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const asked = asking(w, transaction.id);

    expect(
      await refusal(unknown === 'payment' ? { ...asked, transactionId: ids.next() } : { ...asked, orgId: ids.next() }),
    ).toEqual([problem]);
    expect(await platformMarked(asked)).toBe(false);
  });
});

describe('records that can’t be believed (their alarm raised): refused, nothing changed', () => {
  it.each([
    ['the organisation', ORGANIZATIONS, "the organisation's records can't be verified"],
    ['the payment', TRANSACTIONS, "the payment's records can't be verified"],
  ] as const)('refuses one for which %s can’t be believed', async (_name, table, problem) => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const owner = await tamperAsOwner(database, table, w.org);
    try {
      await owner.stripSeals(table === ORGANIZATIONS ? w.org : transaction.id);
    } finally {
      await owner.end();
    }
    const asked = asking(w, transaction.id);

    expect(await refusal(asked)).toEqual([problem]);
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(await platformMarked(asked)).toBe(false);
    // The hold is kept on the chain, under an ID of its own: the same request run again is still told why.
    const holds = await holdsOf(w);
    expect(holds).toHaveLength(1);
    expect(holds).not.toContain(asked.id);
    expect(await refusal(asked)).toEqual([problem]);
  });

  it('refuses a request ID naming an event that can’t be believed: the audit log can’t be verified', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const opened = await openedEventOf(w, transaction.id);
    // Its details changed past the app: its seal no longer holds.
    const owner = await database.connect('owner');
    try {
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await owner.query(`update audit.events set details = '{"n":9}' where id = $1`, [opened]);
    } finally {
      await owner.end();
    }

    expect(await refusal({ ...asking(w, transaction.id), id: opened })).toEqual([
      "the organisation's audit log can't be verified",
    ]);
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    // Its hold is kept, though the request's ID names an event already on the chain.
    expect(await holdsOf(w)).toHaveLength(1);
  });

  it('fails, changing nothing, for one whose instruction can’t be believed', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const owner = await tamperAsOwner(database, INSTRUCTIONS, w.org);
    try {
      await owner.stripSeals(transaction.instructionId);
    } finally {
      await owner.end();
    }

    await expect(mark(asking(w, transaction.id))).rejects.toThrow("instruction can't be believed");
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
  });
});

describe('with the bank check at the same payment (forced, ADR-006 §6)', () => {
  /**
   * The payment's row held as by another writer, the mark and the check
   * queued behind it in the order given, then let go: each in its turn.
   */
  async function queued(w: World, transactionId: string, first: () => Promise<unknown>, then: () => Promise<unknown>) {
    const holder = await database.connect('owner');
    try {
      await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await holder.query('begin');
      await holder.query('select id from transactions.transactions where id = $1 for no key update', [transactionId]);
      const one = first();
      await waitUntilQueued(database.as('admin'), 1);
      const two = then();
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('commit');
      return await Promise.allSettled([one, two]);
    } finally {
      await holder.end();
    }
  }

  it('marked first: FAILED stands, and the bank’s later credit is said as a contradiction, never applied', async () => {
    const { w, request, transaction } = await handedOff(ANSWER_LOST, { checked: false });
    expect(transaction).toMatchObject({ status: 'UNKNOWN', providerStatus: null });
    clock.advanceBy(MARK_FAILED_AFTER_MS);

    await queued(
      w,
      transaction.id,
      () => mark(asking(w, transaction.id)),
      () => checksOf(w).run(),
    );

    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'FAILED',
      providerStatus: 'AcceptedCreditSettlementCompleted',
    });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(lines('payment_check.contradicts')).toHaveLength(1);
  });

  it('checked first: the bank’s credit settles it, and the mark is refused, changing nothing', async () => {
    const { w, request, transaction } = await handedOff(ANSWER_LOST, { checked: false });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const asked = asking(w, transaction.id);

    const [, marked] = await queued(
      w,
      transaction.id,
      () => checksOf(w).run(),
      () => refusal(asked),
    );

    expect(marked).toEqual({
      status: 'fulfilled',
      value: ["the payment is SUCCEEDED: only one whose outcome can't be known (UNKNOWN) is marked failed"],
    });
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(await platformMarked(asked)).toBe(false);
  });
});
