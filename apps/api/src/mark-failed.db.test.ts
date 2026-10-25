// Phase 4 gate H10 (partner decision 38, replacing decision 35; ADR-007 §10;
// Rule Book §1.9): an admin marks an UNKNOWN payment failed on their bank's
// written word, through the use cases the routes call, on the real migrated
// schema as the app role. Asked with the bank's evidence reference, signed in
// again with a passkey and confirmed: FAILED, its held money and its order
// given back, `transaction.fail` on the organisation's chain as the admin's,
// naming the reference, the statement confirmed and the step-up's evidence,
// every admin told. A frozen organisation still marks. A payment not UNKNOWN
// is PAYMENT_NOT_UNKNOWN; within a day of its hand-off PAYMENT_TOO_RECENT;
// another organisation's or none NOT_FOUND; an approver, a developer or a
// viewer FORBIDDEN; one that can't be believed INTEGRITY_FAILED, its alarm
// raised. A step-up signed in with an app code, asked for another payment or
// another reference is STEP_UP_FAILED; one settled since its ask is refused. The
// key answers its own replay. The bank check still watches it a week: paid
// after all, it is said. With the bank check at the same payment (forced),
// whichever takes it first settles it and the other finds it settled. The
// routes' answers are payments.test.ts.
import { withSignedStates } from '@agentx/core/modules/audit';
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { MARK_FAILED_AFTER_MS, markFailed } from '@agentx/core/modules/outcomes';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { TRANSACTIONS } from '@agentx/core/modules/transactions';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
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
import { ALLOWED, handoffWorld, type HandoffWorldTables, HOLDS_AFTER, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { askedFor, keys, type Member, OPERATOR, refused, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import {
  createPaymentMarks,
  MARK_FAILED_CONFIRM_OPERATION,
  MARK_FAILED_CONFIRMED,
  MARK_FAILED_OPERATION,
  MARK_FAILED_STATEMENT_VERSION,
  type PaymentMarks,
} from './payment-marks.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xe1c0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xe1c1_0000_0000) });
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000e1';
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const EVIDENCE = 'BANK-NACK-77311';
/** Agent X's own team, as the operator's command names itself: only it resumes the hand-off. */
const PAUSER = { type: 'system', id: 'operator' } as const;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let marks: PaymentMarks;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'mark-failed',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, holdingsOf, member, keyed, stepUp, quiet } = shared;
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

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

/** An admin signed in now: a session opened before the day the mark waits for has ended (12 hours at most). */
const adminOf = (w: World) => member(w.org, 'admin');

const asking = (who: Member, paymentId: string, evidenceRef = EVIDENCE) =>
  marks.ask(who, keyed(who, MARK_FAILED_OPERATION), paymentId, evidenceRef, CORRELATION);

const confirming = (
  who: Member,
  paymentId: string,
  stepUpChallengeId: string,
  evidenceRef = EVIDENCE,
  key?: IdempotentRequest,
) =>
  marks.confirm(
    who,
    key ?? keyed(who, MARK_FAILED_CONFIRM_OPERATION),
    paymentId,
    { evidenceRef, stepUpChallengeId },
    CORRELATION,
  );

/** Asks, signs in again with `amr` and confirms: the confirm's answer. */
async function marked(who: Member, paymentId: string, amr?: readonly string[]) {
  const challengeId = askedFor(await asking(who, paymentId));
  await stepUp(who, challengeId, amr);
  return confirming(who, paymentId, challengeId);
}

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

const freeze = (w: World) =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
      actor: OPERATOR,
      action: 'organization.freeze',
      details: {},
    }),
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
        { paused: false, reason: 'TEST-H10', actor: PAUSER, release: 'r-test', run: null },
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
  marks = createPaymentMarks({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger,
  });
});

describe('an UNKNOWN payment marked failed by an admin (H10; decision 38; ADR-007 §10)', () => {
  it('moves it to FAILED, gives back its money and its order, signs it as the admin’s and tells every admin', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    expect(transaction).toMatchObject({ status: 'UNKNOWN', providerStatus: 'Rejected' });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);

    expect(await marked(admin, transaction.id)).toEqual({ outcome: 'marked', paymentId: transaction.id });

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED', providerStatus: 'Rejected' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect((await movesOf(w, transaction.id)).at(-1)).toMatchObject({
      action: 'transaction.fail',
      actorType: 'user',
      details: {
        via: 'admin',
        evidenceRef: EVIDENCE,
        confirmed: MARK_FAILED_CONFIRMED,
        statementVersion: String(MARK_FAILED_STATEMENT_VERSION),
        methods: 'pwd user mfa',
        statusFrom: 'UNKNOWN',
      },
    });
    // To no one person: every admin, found as it is sent.
    expect(await markNoticesOf(w)).toEqual([{ aboutId: transaction.id, to: null }]);
  });

  it('is marked while the organisation is frozen: a mark only gives capacity back (as a reject, decision 3)', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    await freeze(w);

    expect(await marked(admin, transaction.id)).toMatchObject({ outcome: 'marked' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
  });

  it('is still watched by the bank check: the bank paying it after all is said, never applied (rail map §4)', async () => {
    const { w, request, transaction } = await handedOff(ANSWER_LOST, { checked: false });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    await marked(admin, transaction.id);

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
    const admin = await adminOf(w);
    await marked(admin, transaction.id);

    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'FAILED' });
    expect(lines('payment_check.contradicts')).toEqual([]);
  });

  it('answers its key’s replay as before, one move and one notice; asked again, it is PAYMENT_NOT_UNKNOWN', async () => {
    const { w, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    const challengeId = askedFor(await asking(admin, transaction.id));
    await stepUp(admin, challengeId);
    const key = keyed(admin, MARK_FAILED_CONFIRM_OPERATION, 'mark-once');

    const once = await confirming(admin, transaction.id, challengeId, EVIDENCE, key);
    expect(once).toEqual({ outcome: 'marked', paymentId: transaction.id });
    expect(await confirming(admin, transaction.id, challengeId, EVIDENCE, key)).toEqual(once);

    expect((await movesOf(w, transaction.id)).filter(({ action }) => action === 'transaction.fail')).toHaveLength(1);
    expect(await markNoticesOf(w)).toHaveLength(1);
    expect(await asking(admin, transaction.id)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));
  });

  it('refuses one not UNKNOWN as PAYMENT_NOT_UNKNOWN, before any step-up, changing nothing', async () => {
    const { w, request, transaction } = await handedOff(0n, { checked: false });
    expect(transaction.status).toBe('PROCESSING');
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);

    expect(await asking(admin, transaction.id)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
    expect(await markNoticesOf(w)).toEqual([]);
  });

  it('refuses one within a day of its hand-off as PAYMENT_TOO_RECENT, and marks it just past', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    // Its hand-off was two steps ago: a day on from it, to the millisecond, is still within.
    clock.advanceBy(MARK_FAILED_AFTER_MS - 2 * STEP);
    const admin = await adminOf(w);

    expect(await asking(admin, transaction.id)).toEqual(refused(409, 'PAYMENT_TOO_RECENT'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);

    clock.advanceBy(1);
    expect(await marked(admin, transaction.id)).toMatchObject({ outcome: 'marked' });
  });

  it('refuses another organisation’s payment and none as NOT_FOUND', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    const other = await ready();

    expect(await asking(other.w.admin, transaction.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await asking(admin, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s, and changes nothing', async (role) => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    const who = await member(w.org, role);

    expect(await asking(who, transaction.id)).toEqual(refused(403, 'FORBIDDEN'));
    const challengeId = askedFor(await asking(admin, transaction.id));
    await stepUp(admin, challengeId);
    expect(await confirming(who, transaction.id, challengeId)).toEqual(refused(403, 'FORBIDDEN'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it('refuses a step-up signed in with an app code: STEP_UP_FAILED, nothing moved', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);

    expect(await marked(admin, transaction.id, APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
  });

  it('refuses a step-up asked for another payment, or another reference: STEP_UP_FAILED', async () => {
    const first = await handedOff(REJECTED_UNPROVEN);
    // Small: two of ALLOWED to one supplier would together need an approval (the split check).
    const second = await ask(first.acting, first.w, { amount: SMALL(REJECTED_UNPROVEN) });
    await handoffOf(first.w).run();
    clock.advanceBy(2 * STEP);
    await checksOf(first.w).run();
    const secondPayment = await transactionOf(first.w, second.id);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(first.w);
    const challengeId = askedFor(await asking(admin, first.transaction.id));
    await stepUp(admin, challengeId);

    expect(await confirming(admin, secondPayment.id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await confirming(admin, first.transaction.id, challengeId, 'BANK-NACK-00000')).toEqual(
      refused(403, 'STEP_UP_FAILED'),
    );
    expect(await transactionOf(first.w, first.request.id)).toMatchObject({ status: 'UNKNOWN' });
    expect(await transactionOf(first.w, second.id)).toMatchObject({ status: 'UNKNOWN' });
  });

  it('refuses a confirm once the bank’s word settled it since the ask: PAYMENT_NOT_UNKNOWN', async () => {
    const { w, request, transaction } = await handedOff(ANSWER_LOST, { checked: false });
    expect(transaction).toMatchObject({ status: 'UNKNOWN', providerStatus: null });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    const challengeId = askedFor(await asking(admin, transaction.id));
    await stepUp(admin, challengeId);
    // The bank's credit is read: no longer UNKNOWN, and its latest event another.
    await checksOf(w).run();

    expect(await confirming(admin, transaction.id, challengeId)).toEqual(refused(409, 'PAYMENT_NOT_UNKNOWN'));
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
  });
});

describe('records that can’t be believed (their alarm raised): refused, nothing changed (FX-TAMPER)', () => {
  it('refuses a payment that can’t be believed as INTEGRITY_FAILED, holding the organisation', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    const challengeId = askedFor(await asking(admin, transaction.id));
    await stepUp(admin, challengeId);
    const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
    try {
      await owner.stripSeals(transaction.id);
    } finally {
      await owner.end();
    }

    expect(await confirming(admin, transaction.id, challengeId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(await holdsOf(w)).toHaveLength(1);
    expect(await markNoticesOf(w)).toEqual([]);
  });

  it('fails, changing nothing, for one whose instruction can’t be believed', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const admin = await adminOf(w);
    const challengeId = askedFor(await asking(admin, transaction.id));
    await stepUp(admin, challengeId);
    const owner = await tamperAsOwner(database, INSTRUCTIONS, w.org);
    try {
      await owner.stripSeals(transaction.instructionId);
    } finally {
      await owner.end();
    }

    await expect(confirming(admin, transaction.id, challengeId)).rejects.toThrow("instruction can't be believed");
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
  });
});

describe('core’s markFailed, for a caller that didn’t check (its use case reads the payment first)', () => {
  it('throws for a payment under way, changing nothing, though the machine would let it fail', async () => {
    const { w, request, transaction } = await handedOff(0n, { checked: false });
    expect(transaction.status).toBe('PROCESSING');

    await expect(
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        markFailed(tx, states, createOutbox({ ids, clock }), {
          orgId: w.org,
          transactionId: transaction.id,
          userId: w.admin.userId,
          details: { evidenceRef: EVIDENCE },
          at: clock.now(),
        }),
      ),
    ).rejects.toThrow('Only an UNKNOWN payment is marked failed, not PROCESSING');
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
  });
});

describe('with the bank check at the same payment (forced, ADR-006 §6)', () => {
  /**
   * The payment's row held as by another writer, the two queued behind it in
   * the order given, then let go: each in its turn.
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

  /** Asked and signed in again for: the confirm, ready to run. */
  async function readyToConfirm(w: World, transactionId: string) {
    const admin = await adminOf(w);
    const challengeId = askedFor(await asking(admin, transactionId));
    await stepUp(admin, challengeId);
    return () => confirming(admin, transactionId, challengeId);
  }

  it('settles with its holdings locked before the head, so their holder never waits on it', async () => {
    const { w, request, transaction } = await handedOff(REJECTED_UNPROVEN);
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const confirm = await readyToConfirm(w, transaction.id);
    // Something holding the request's reservation (as an ending or a holdings page would) as the mark is made.
    const holder = await database.connect('owner');
    let marking: Promise<unknown> | undefined;
    try {
      await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await holder.query('begin');
      await holder.query('select id from limit_reservations.reservations where request_id = $1 for no key update', [
        request.id,
      ]);
      marking = confirm();
      await waitUntilQueued(database.as('admin'), 1);
      // The mark waits at the reservation (11) holding nothing of the head (12): the organisation's head is free.
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
    await marking;

    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
  });

  it('marked first: FAILED stands, and the bank’s later credit is said as a contradiction, never applied', async () => {
    const { w, request, transaction } = await handedOff(ANSWER_LOST, { checked: false });
    expect(transaction).toMatchObject({ status: 'UNKNOWN', providerStatus: null });
    clock.advanceBy(MARK_FAILED_AFTER_MS);
    const confirm = await readyToConfirm(w, transaction.id);

    const [mark] = await queued(w, transaction.id, confirm, () => checksOf(w).run());

    expect(mark).toEqual({ status: 'fulfilled', value: { outcome: 'marked', paymentId: transaction.id } });
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
    const confirm = await readyToConfirm(w, transaction.id);

    const [, mark] = await queued(w, transaction.id, () => checksOf(w).run(), confirm);

    expect(mark).toEqual({ status: 'fulfilled', value: refused(409, 'PAYMENT_NOT_UNKNOWN') });
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(await markNoticesOf(w)).toEqual([]);
  });
});
