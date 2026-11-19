// Phase 6 C1: the team's reads of payments against Postgres, on the real
// migrated schema as the app role: every payment newest first, page by page
// and by group; the exception list (BR-17), every UNKNOWN payment and every
// settled one the bank's word on its row still contradicts, which leaves it
// once the bank agrees (S196 decision); and one in full, with where marking it
// failed stands and its history. Each through its transaction's, its
// instruction's and its supplier details' signed states: one that can't be
// believed refuses the answer (503 INTEGRITY_FAILED); one that can't be
// checked now leaves only its payment out, named; another organisation's is
// never found; and no answer carries the payee's reference or the consent.
// The routes' answers are payment-reads.test.ts.
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { createSessions, createStepUpChallenges, ESTABLISHED_DAYS } from '@agentx/core/modules/identity';
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  lockPayment,
  MARK_FAILED_AFTER_MS,
  NO_FACTS,
  paymentsPage,
  settlePayment,
} from '@agentx/core/modules/outcomes';
import type { ExecutionLookup, FakeRail } from '@agentx/core/modules/providers';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { SUPPLIER_VERSIONS } from '@agentx/core/modules/suppliers';
import {
  FAILURE_PROPOSALS,
  moveTransaction,
  noteTransactionFacts,
  proposeFailure,
  TRANSACTIONS,
} from '@agentx/core/modules/transactions';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
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
import { handoffWorld, type HandoffWorldTables, payeeRefOf, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { askedFor, keys, type Member, OPERATOR, PASSKEY, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import {
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  createPaymentMarks,
  type PaymentMarks,
  PROPOSE_CONFIRM_OPERATION,
  PROPOSE_OPERATION,
} from './payment-marks.ts';
import { alertAdmins } from './payment-alerts.ts';
import { createPaymentReads, type PaymentReads, TIMELINE_MOST } from './payment-reads.ts';
import { createRailHealth } from './rail-health.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;
let operator: Database<HandoffWorldTables>;

const ids = new SequentialIds(0x6c10_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x6c11_0000_0000) });
const CORRELATION = '0199a0f0-0000-7000-8000-0000000006c1';
const INTEGRITY_FAILED = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
const NOT_FOUND = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
/** Agent X's own team, as the operator's command names itself: only it resumes the hand-off. */
const PAUSER = { type: 'system', id: 'operator' } as const;
/** The API, as the bank check names itself. */
const BANK_CHECK = { type: 'system', id: 'api' } as const;

/** A step of the fake's payment: settled at the debtor a minute on, its answer final after two (B2). */
const STEP = 60_000;
/** The fils that make the fake reject it with no proof the money stayed: UNKNOWN (rail map §4). */
const REJECTED_UNPROVEN = 4n;

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let reads: PaymentReads;
let marks: PaymentMarks;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'payment-reads',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, quiet, member, keyed, stepUp } = shared;
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const handoffOf = (w: World) =>
  createHandoff({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail: w.rail,
    keys,
    ids,
    clock,
    logger: testLogger(),
    health: createRailHealth({ clock, logger: testLogger() }),
    databaseGate: handoffDatabaseGate(6),
  });

const checksOf = (w: World, rail: FakeRail = w.rail) =>
  createPaymentChecks({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail,
    keys,
    ids,
    clock,
    logger: testLogger(),
    health: createRailHealth({ clock, logger: testLogger() }),
    databaseGate: handoffDatabaseGate(6),
  });

/** The request's transaction, as it stands. */
const transactionOf = async (w: World, requestId: string) => {
  const payment = await paymentOf(w, requestId);
  if (typeof payment.transaction !== 'object') throw new Error(`no transaction: ${String(payment.transaction)}`);
  return payment.transaction;
};

/** A world with three payments handed off and checked two steps on: two paid, the newest UNKNOWN. */
async function threePayments() {
  const { w, acting } = await ready();
  const first = await ask(acting, w, { amount: SMALL() });
  const second = await ask(acting, w, { amount: SMALL(5n) });
  const third = await ask(acting, w, { amount: SMALL(REJECTED_UNPROVEN) });
  await handoffOf(w).run();
  clock.advanceBy(2 * STEP);
  await checksOf(w).run();
  const [paid, alsoPaid, unknown] = await Promise.all([first, second, third].map(({ id }) => transactionOf(w, id)));
  if (paid === undefined || alsoPaid === undefined || unknown === undefined) throw new Error('no payments');
  return { w, acting, requests: [first, second, third], paid, alsoPaid, unknown };
}

/** A page as the list gives it: each payment's ID and status, and contradicted where it is. */
const listOf = async (
  org: string,
  which: Parameters<PaymentReads['list']>[2],
  after: string | null = null,
  limit = 50,
) => {
  const listed = await reads.list(org, { after, limit }, which, CORRELATION);
  if (listed.outcome !== 'listed') return listed;
  return {
    rows: listed.payments.map(({ payment }) => [
      payment.transaction.id,
      payment.transaction.status,
      ...(payment.contradicted ? ['contradicted'] : []),
    ]),
    next: listed.next,
    unchecked: listed.unchecked,
  };
};

/** The bank's word kept on a payment, as the bank check notes it: no move, its facts alone. */
const bankSays = (w: World, transactionId: string, providerStatus: string, rejectCode: string | null = null) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    clock.advanceBy(STEP);
    const noted = await noteTransactionFacts(
      tx,
      states,
      { orgId: w.org, id: transactionId },
      { providerStatus, paymentInstructionRef: null, rejectCode, providerChangedAt: clock.now() },
      { actor: BANK_CHECK, details: { via: 'bank_check' } },
    );
    expect(noted).toEqual({ outcome: 'noted' });
  });

/** 1,001 events about the record since its newest signed one: more than one read takes, so it can't be judged now. */
const backlogged = (org: string, type: string, id: string) =>
  withTenant(app, org, async (tx) => {
    const trail = createAuditTrail({ keys, ids });
    for (let added = 0; added < 1001; added += 1) {
      await trail.record(tx, org, {
        actor: OPERATOR,
        action: `${type}.noted`,
        subject: { type, id, version: 1 },
        details: {},
      });
    }
  });

/** One event about the object, as the app's own activity would record it. */
const noteAbout = (w: World, type: string, id: string, action: string) =>
  withTenant(app, w.org, (tx) =>
    createAuditTrail({ keys, ids }).record(tx, w.org, {
      actor: OPERATOR,
      action,
      subject: { type, id, version: 1 },
      details: {},
    }),
  );

/** The instruction's amount doubled by the tables' owner with its guards off: as only something past the app could. */
async function instructionChanged(w: World, instructionId: string) {
  const owner = await tamperAsOwner(database, INSTRUCTIONS, w.org);
  try {
    await owner.query('alter table instructions.instructions disable trigger user');
    await owner.setColumn(instructionId, 'amount_minor', 99_000);
    await owner.query('alter table instructions.instructions enable trigger user');
  } finally {
    await owner.end();
  }
}

/** An admin's proposal to mark the payment failed, made OPEN as payment-marks.ts makes it once confirmed. */
const proposedFor = async (w: World, transactionId: string) => {
  const id = ids.next();
  await withSignedStates(app, w.org, quiet(), (tx, states) =>
    proposeFailure(
      tx,
      states,
      {
        orgId: w.org,
        id,
        transactionId,
        evidenceRef: 'BANK-NACK-77311',
        proposedBy: w.admin.userId,
        createdAt: clock.now(),
      },
      { actor: { type: 'user', id: w.admin.userId }, details: {} },
    ),
  );
  return id;
};

/** The world's fake, every lookup answered with the bank's status `providerStatus` in place of its own. */
const bankAnswering = (
  w: World,
  providerStatus: 'Rejected' | 'AcceptedCreditSettlementCompleted',
  onlyInstructionId?: string,
): FakeRail => ({
  ...w.rail,
  getExecution: async (ref): Promise<ExecutionLookup> => {
    const found = await w.rail.getExecution(ref);
    const asked = onlyInstructionId === undefined || ref.instructionId.toLowerCase() === onlyInstructionId;
    return found.kind === 'found' && asked
      ? {
          kind: 'found',
          execution: {
            ...found.execution,
            providerStatus,
            rejectCode: providerStatus === 'Rejected' ? 'AANI.FF01' : null,
          },
        }
      : found;
  },
});

/** The payment moved to UNKNOWN on an answer that proves nothing, its facts kept as they were (the bank check's own way). */
const lostTrack = (w: World, transactionId: string) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const key = { orgId: w.org, id: transactionId };
    const locked = await lockPayment(tx, states, key);
    await moveTransaction(tx, states, key, 'lose_track', NO_FACTS, {
      actor: BANK_CHECK,
      details: { via: 'bank_check' },
    });
    await settlePayment(tx, states, createOutbox({ ids, clock }), {
      orgId: w.org,
      requestId: locked.instruction.spendRequestId,
      transactionId,
      status: 'UNKNOWN',
      at: clock.now(),
      openProposal: locked.openProposal,
    });
  });

/** The same person signed in again now, with a passkey: a new session, their membership as it was. */
async function signedInAgain(who: Member): Promise<Member> {
  const sessions = createSessions({
    ids,
    clock,
    timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
    keys,
    logger: testLogger(),
  });
  const { sessionId } = await sessions.open(app, who.userId, {
    idpSessionId: 'V1_9',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  return { ...who, sessionId };
}

/** Marked failed as the routes make it: one admin proposes, a second confirms, each with a passkey (gate H10). */
async function markedFailedByTwoAdmins(w: World, paymentId: string) {
  const firstMember = await member(w.org, 'admin');
  const secondMember = await member(w.org, 'admin');
  // Members long enough to be each other's second person (ADR-012 §1), and the payment past its day.
  clock.advanceBy(ESTABLISHED_DAYS * 24 * 60 * 60_000 + 1);
  const first = await signedInAgain(firstMember);
  const second = await signedInAgain(secondMember);
  const evidenceRef = 'BANK-NACK-77311';
  const proposing = askedFor(
    await marks.propose(first, keyed(first, PROPOSE_OPERATION), paymentId, evidenceRef, CORRELATION),
  );
  await stepUp(first, proposing);
  const proposal = await marks.confirmProposal(
    first,
    keyed(first, PROPOSE_CONFIRM_OPERATION),
    paymentId,
    { evidenceRef, stepUpChallengeId: proposing },
    CORRELATION,
  );
  expect(proposal).toMatchObject({ outcome: 'proposed' });
  const approving = askedFor(await marks.approve(second, keyed(second, APPROVE_OPERATION), paymentId, CORRELATION));
  await stepUp(second, approving);
  expect(
    await marks.confirmApproval(second, keyed(second, APPROVE_CONFIRM_OPERATION), paymentId, approving, CORRELATION),
  ).toEqual({ outcome: 'marked', paymentId });
}

/** The IDs of the organisation's integrity holds. */
const holdsOf = async (w: World) =>
  (
    await withTenant(app, w.org, (tx) =>
      tx.selectFrom('audit.events').select('id').where('action', '=', 'integrity_hold.set').execute(),
    )
  ).map(({ id }) => id);

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
        { paused: false, reason: 'TEST-6C1', actor: PAUSER, release: 'r-test', run: null },
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
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  reads = createPaymentReads({ database: app, keys, ids, logger });
  marks = createPaymentMarks({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock, keys, logger: testLogger() }),
    outbox: createOutbox({ ids, clock }),
    logger,
  });
});

describe('the team’s list of payments (Phase 6 C1)', () => {
  it('lists every payment newest first, page by page, and by group', async () => {
    const { w, paid, alsoPaid, unknown } = await threePayments();

    expect(await listOf(w.org, 'all')).toEqual({
      rows: [
        [unknown.id, 'UNKNOWN'],
        [alsoPaid.id, 'SUCCEEDED'],
        [paid.id, 'SUCCEEDED'],
      ],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'all', null, 2)).toMatchObject({ next: alsoPaid.id });
    expect(await listOf(w.org, 'all', alsoPaid.id, 2)).toEqual({
      rows: [[paid.id, 'SUCCEEDED']],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'paid')).toMatchObject({
      rows: [
        [alsoPaid.id, 'SUCCEEDED'],
        [paid.id, 'SUCCEEDED'],
      ],
    });
    expect(await listOf(w.org, 'unknown')).toMatchObject({ rows: [[unknown.id, 'UNKNOWN']] });
    expect(await listOf(w.org, 'pending')).toEqual({ rows: [], next: null, unchecked: [] });
  });

  it('shows each with its amount, its references and the supplier it paid, never the payee or the consent', async () => {
    const { w, requests, paid } = await threePayments();
    const listed = await reads.list(w.org, { after: null, limit: 50 }, 'paid', CORRELATION);
    const payment = await paymentOf(w, requests[0]?.id ?? '');
    if (listed.outcome !== 'listed' || typeof payment.instruction !== 'object') throw new Error('not listed');

    expect(listed.payments.at(-1)).toMatchObject({
      payment: {
        transaction: { id: paid.id, status: 'SUCCEEDED', providerStatus: paid.providerStatus },
        spendRequestId: requests[0]?.id,
        amount: SMALL(),
        paymentReference: payment.instruction.paymentReference,
        contradicted: false,
      },
      supplierId: w.suppliers[0],
      supplierName: 'Gulf Office Supplies LLC',
    });
    const answers = JSON.stringify([listed, await reads.show(w.org, paid.id, CORRELATION)], (_key, value: unknown) =>
      typeof value === 'bigint' ? value.toString() : value,
    );
    expect(answers).not.toContain(payeeRefOf(w));
    expect(answers).not.toContain(payment.instruction.accountConsentId);
    expect(answers).not.toContain(payment.instruction.partnerLegalEntityId);
    expect(answers).not.toContain(payment.instruction.partnerLicenceRef);
  });

  it('never lists or finds another organisation’s payment', async () => {
    const { paid } = await threePayments();
    const other = await ready();

    expect(await listOf(other.w.org, 'all')).toEqual({ rows: [], next: null, unchecked: [] });
    expect(await listOf(other.w.org, 'exceptions')).toEqual({ rows: [], next: null, unchecked: [] });
    expect(await reads.show(other.w.org, paid.id, CORRELATION)).toEqual(NOT_FOUND);
    expect(await reads.show(other.w.org, ids.next(), CORRELATION)).toEqual(NOT_FOUND);
  });

  it('refuses a list holding a transaction that can’t be believed, raising its alarm', async () => {
    const { w, paid } = await threePayments();
    const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
    try {
      await owner.stripSeals(paid.id);
    } finally {
      await owner.end();
    }

    expect(await reads.list(w.org, { after: null, limit: 50 }, 'all', CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await reads.show(w.org, paid.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await holdsOf(w)).toHaveLength(1);
  });

  it('refuses a list and the payment whose instruction was changed past the app', async () => {
    const { w, paid } = await threePayments();
    await instructionChanged(w, paid.instructionId);

    expect(await reads.list(w.org, { after: null, limit: 50 }, 'paid', CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await reads.show(w.org, paid.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
  });

  it('refuses a list and the payment naming supplier details that can’t be believed', async () => {
    const { w, requests, paid } = await threePayments();
    const payment = await paymentOf(w, requests[0]?.id ?? '');
    if (typeof payment.instruction !== 'object') throw new Error('no instruction');
    const owner = await tamperAsOwner(database, SUPPLIER_VERSIONS, w.org);
    try {
      await owner.stripSeals(payment.instruction.supplierVersionId);
    } finally {
      await owner.end();
    }

    expect(await reads.list(w.org, { after: null, limit: 50 }, 'all', CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await reads.show(w.org, paid.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
  });

  it('leaves out, named, a payment whose instruction or supplier details can’t be checked now (A1b)', async () => {
    const { w, paid, alsoPaid, unknown } = await threePayments();
    await backlogged(w.org, INSTRUCTIONS.subject, paid.instructionId);

    expect(await listOf(w.org, 'all')).toEqual({
      rows: [
        [unknown.id, 'UNKNOWN'],
        [alsoPaid.id, 'SUCCEEDED'],
      ],
      next: null,
      unchecked: [paid.id],
    });
  });

  it('leaves out, named, every payment to supplier details that can’t be checked now', async () => {
    const { w, requests, paid, alsoPaid, unknown } = await threePayments();
    const payment = await paymentOf(w, requests[0]?.id ?? '');
    if (typeof payment.instruction !== 'object') throw new Error('no instruction');
    await backlogged(w.org, 'supplier_version', payment.instruction.supplierVersionId);

    expect(await listOf(w.org, 'all')).toEqual({
      rows: [],
      next: null,
      unchecked: [unknown.id, alsoPaid.id, paid.id],
    });
  });
});

describe('the exception list (Phase 6 C1; BR-17; S196 decision)', () => {
  it('lists every UNKNOWN payment, and a paid one the bank check found contradicted, until the bank agrees', async () => {
    const { w, requests, paid, alsoPaid, unknown } = await threePayments();
    expect(await listOf(w.org, 'exceptions')).toEqual({ rows: [[unknown.id, 'UNKNOWN']], next: null, unchecked: [] });

    // The bank check's first run after a start checks every paid one: the bank now rejects both.
    await checksOf(w, bankAnswering(w, 'Rejected')).run();
    expect(await transactionOf(w, requests[0]?.id ?? '')).toMatchObject({
      status: 'SUCCEEDED',
      providerStatus: 'Rejected',
    });

    expect(await listOf(w.org, 'exceptions')).toEqual({
      rows: [
        [unknown.id, 'UNKNOWN'],
        [alsoPaid.id, 'SUCCEEDED', 'contradicted'],
        [paid.id, 'SUCCEEDED', 'contradicted'],
      ],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'exceptions', null, 2)).toMatchObject({ next: alsoPaid.id });
    expect(await listOf(w.org, 'exceptions', alsoPaid.id, 2)).toEqual({
      rows: [[paid.id, 'SUCCEEDED', 'contradicted']],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'paid')).toMatchObject({
      rows: [
        [alsoPaid.id, 'SUCCEEDED', 'contradicted'],
        [paid.id, 'SUCCEEDED', 'contradicted'],
      ],
    });
    expect(await reads.show(w.org, paid.id, CORRELATION)).toMatchObject({
      shown: { payment: { contradicted: true } },
    });

    // The bank agrees again: both leave the list by themselves, their alerts kept in the log (and, crediting the
    // UNKNOWN one too, the bank settles that as paid).
    await checksOf(w, bankAnswering(w, 'AcceptedCreditSettlementCompleted')).run();

    expect(await listOf(w.org, 'exceptions')).toEqual({ rows: [], next: null, unchecked: [] });
    expect(await listOf(w.org, 'paid')).toMatchObject({
      rows: [
        [unknown.id, 'SUCCEEDED'],
        [alsoPaid.id, 'SUCCEEDED'],
        [paid.id, 'SUCCEEDED'],
      ],
    });
    expect(await reads.show(w.org, paid.id, CORRELATION)).toMatchObject({
      shown: { payment: { contradicted: false } },
    });
  });

  it('lists a payment by its own contradiction alert, never by another payment’s (S196 review, M09)', async () => {
    const { w, paid, alsoPaid, unknown } = await threePayments();
    await checksOf(w, bankAnswering(w, 'Rejected', paid.instructionId)).run();
    await bankSays(w, alsoPaid.id, 'Rejected', 'AANI.FF01');

    expect(await listOf(w.org, 'exceptions')).toEqual({
      rows: [
        [unknown.id, 'UNKNOWN'],
        [paid.id, 'SUCCEEDED', 'contradicted'],
      ],
      next: null,
      unchecked: [],
    });
  });

  it('refuses a page of exceptions asked in another organisation’s transaction (the tenant’s check)', async () => {
    const { w } = await ready();
    const other = await ready();

    await expect(
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        paymentsPage(tx, states, other.w.org, { after: null, limit: 50 }, 'exceptions'),
      ),
    ).rejects.toThrow(TenantContextError);
  });

  it('never reads a kept word as contradicted without the bank check’s alert', async () => {
    const { w, paid, unknown } = await threePayments();
    await bankSays(w, paid.id, 'Rejected', 'AANI.FF01');

    expect(await listOf(w.org, 'exceptions')).toEqual({ rows: [[unknown.id, 'UNKNOWN']], next: null, unchecked: [] });
    expect(await listOf(w.org, 'paid')).toMatchObject({ rows: [expect.any(Array), [paid.id, 'SUCCEEDED']] });
  });

  it('keeps a payment under way, lost track of, then marked failed by two admins off the list (S196 review)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: SMALL() });
    await handoffOf(w).run();
    clock.advanceBy(STEP);
    await checksOf(w).run();
    const processing = await transactionOf(w, request.id);
    expect(processing).toMatchObject({ status: 'PROCESSING', providerStatus: 'AcceptedSettlementCompleted' });
    await lostTrack(w, processing.id);
    // Another of its alerts, not a contradiction: it never makes a payment one (S196 review, M10).
    await withSignedStates(app, w.org, quiet(), (tx) =>
      alertAdmins(
        tx,
        { keys, ids, outbox: createOutbox({ ids, clock }) },
        { orgId: w.org, transactionId: processing.id, alert: 'still_unknown' },
      ),
    );

    await markedFailedByTwoAdmins(w, processing.id);

    // The bank's word from before the lost track is kept, and on its own would read as contradicting FAILED.
    expect(await transactionOf(w, request.id)).toMatchObject({
      status: 'FAILED',
      providerStatus: 'AcceptedSettlementCompleted',
    });
    expect(await listOf(w.org, 'exceptions')).toEqual({ rows: [], next: null, unchecked: [] });
    expect(await listOf(w.org, 'failed')).toEqual({ rows: [[processing.id, 'FAILED']], next: null, unchecked: [] });
    expect(await reads.show(w.org, processing.id, CORRELATION)).toMatchObject({
      shown: { payment: { contradicted: false } },
      markFailed: null,
    });
  });

  it('refuses a list whose contradiction alert can’t be believed', async () => {
    const { w, paid } = await threePayments();
    await checksOf(w, bankAnswering(w, 'Rejected')).run();
    const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
    try {
      await owner.query(
        "update audit.events set details = '{}' where org_id = $1 and subject_type = 'payment_alert' and subject_id = $2",
        [w.org, paid.id],
      );
    } finally {
      await owner.end();
    }

    expect(await reads.list(w.org, { after: null, limit: 50 }, 'exceptions', CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await reads.show(w.org, paid.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
  });

  it('refuses an exception list holding one that can’t be believed', async () => {
    const { w, unknown } = await threePayments();
    const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
    try {
      await owner.stripSeals(unknown.id);
    } finally {
      await owner.end();
    }

    expect(await reads.list(w.org, { after: null, limit: 50 }, 'exceptions', CORRELATION)).toEqual(INTEGRITY_FAILED);
  });

  it('refuses a page past the most before any SQL runs', async () => {
    const { w } = await ready();

    await expect(reads.list(w.org, { after: null, limit: 51 }, 'exceptions', CORRELATION)).rejects.toThrow(
      'A page is 1 to 50 payments',
    );
  });
});

describe('one payment in full (Phase 6 C1)', () => {
  it('shows an UNKNOWN one’s open proposal, and the proposal’s events in its history', async () => {
    const { w, unknown } = await threePayments();
    const proposalId = await proposedFor(w, unknown.id);

    const found = await reads.show(w.org, unknown.id, CORRELATION);

    expect(found).toMatchObject({
      outcome: 'found',
      markFailed: {
        openProposal: { id: proposalId, transactionId: unknown.id, evidenceRef: 'BANK-NACK-77311', status: 'OPEN' },
      },
    });
    if (found.outcome !== 'found') throw new Error('not found');
    expect(found.timeline.at(-1)).toMatchObject({
      what: 'failure_proposal.made',
      status: null,
      by: { type: 'user', id: w.admin.userId },
    });
  });

  it('refuses an UNKNOWN payment whose open proposal was changed past the app, raising its alarm (M23)', async () => {
    const { w, unknown } = await threePayments();
    const proposalId = await proposedFor(w, unknown.id);
    const owner = await tamperAsOwner(database, FAILURE_PROPOSALS, w.org);
    try {
      await owner.query('alter table transactions.failure_proposals disable trigger user');
      await owner.setColumn(proposalId, 'evidence_ref', 'BANK-OTHER-00001');
      await owner.query('alter table transactions.failure_proposals enable trigger user');
    } finally {
      await owner.end();
    }

    expect(await reads.show(w.org, unknown.id, CORRELATION)).toEqual(INTEGRITY_FAILED);
    expect(await holdsOf(w)).toHaveLength(1);
  });

  it('never brings another payment’s proposal into a history, its row pointed there past the app', async () => {
    const { w, paid, unknown } = await threePayments();
    const proposalId = await proposedFor(w, unknown.id);
    const owner = await tamperAsOwner(database, FAILURE_PROPOSALS, w.org);
    try {
      await owner.query('alter table transactions.failure_proposals disable trigger user');
      await owner.setColumn(proposalId, 'transaction_id', paid.id);
      await owner.query('alter table transactions.failure_proposals enable trigger user');
    } finally {
      await owner.end();
    }

    const found = await reads.show(w.org, paid.id, CORRELATION);

    if (found.outcome !== 'found') throw new Error('not found');
    expect(found.timeline.map(({ what }) => what)).not.toContain('failure_proposal.made');
  });

  it('throws for a verified payment whose instruction has neither a row nor a history: past the app, a bug', async () => {
    const { w, paid } = await threePayments();
    const owner = await tamperAsOwner(database, INSTRUCTIONS, w.org);
    try {
      const events = await owner.query<{ id: string }>(
        'select id from audit.events where org_id = $1 and subject_id = $2',
        [w.org, paid.instructionId],
      );
      // A policy can't take a bound value: the ID is a UUID the database gave.
      // eslint-disable-next-line agentx/no-string-built-sql -- built from that UUID alone, as the line above says
      await owner.query(
        `create policy tamper_hides_row on instructions.instructions as restrictive using (id <> '${paid.instructionId}'::uuid)`,
      );
      try {
        await owner.withEventsHidden(
          events.map(({ id }) => id),
          async () => {
            await expect(reads.list(w.org, { after: null, limit: 50 }, 'paid', CORRELATION)).rejects.toThrow(
              "A verified transaction's instruction is missing",
            );
          },
        );
      } finally {
        await owner.query('drop policy tamper_hides_row on instructions.instructions');
      }
    } finally {
      await owner.end();
    }
  });

  it('shows an UNKNOWN one with when it may be marked failed and its history, as an allow-list of facts', async () => {
    const { w, requests, unknown } = await threePayments();

    const found = await reads.show(w.org, unknown.id.toUpperCase(), CORRELATION);

    expect(found).toMatchObject({
      outcome: 'found',
      shown: {
        payment: { transaction: { id: unknown.id, status: 'UNKNOWN' }, spendRequestId: requests[2]?.id },
        supplierId: w.suppliers[0],
        supplierName: 'Gulf Office Supplies LLC',
      },
      markFailed: {
        markableFrom: new Date(unknown.createdAt.getTime() + MARK_FAILED_AFTER_MS),
        openProposal: null,
      },
      earlier: false,
    });
    if (found.outcome !== 'found') throw new Error('not found');
    expect(found.timeline.map(({ what, status }) => [what, status])).toEqual([
      ['instruction.made', null],
      ['transaction.opened', 'SUBMISSION_PENDING'],
      ['transaction.provider_noted', null],
      ['transaction.submitted', 'SUBMITTED'],
      ['transaction.processing', 'PROCESSING'],
      ['transaction.provider_noted', null],
      ['transaction.lose_track', 'UNKNOWN'],
      ['payment.rejected_unproven', null],
    ]);
    expect(found.timeline.at(-2)).toMatchObject({ by: BANK_CHECK, via: 'bank_check', evidenceRef: null });
    for (const entry of found.timeline) {
      expect(Object.keys(entry).sort()).toEqual(['at', 'by', 'evidenceRef', 'status', 'via', 'what']);
    }
  });

  it('keeps only events about this payment’s own objects, and no facts past the allow-list', async () => {
    const { w, paid } = await threePayments();
    await withTenant(app, w.org, async (tx) => {
      const trail = createAuditTrail({ keys, ids });
      const note = (type: string, id: string, details: Record<string, string | number>) =>
        trail.record(tx, w.org, {
          actor: OPERATOR,
          action: `${type}.noted`,
          subject: { type, id, version: 1 },
          details,
        });
      // About this payment's transaction, with a status and facts that aren't of their kind.
      await note('transaction', paid.id, { statusTo: 'SIDEWAYS', via: 7, evidenceRef: 9, note: 'kept-out' });
      // Its instruction's ID under the transaction's and the alerts' types, and its own ID under the instruction's.
      await note('transaction', paid.instructionId, {});
      await note('payment_alert', paid.instructionId, {});
      await note('instruction', paid.id, {});
    });

    const found = await reads.show(w.org, paid.id, CORRELATION);

    if (found.outcome !== 'found') throw new Error('not found');
    expect(found.timeline.filter(({ what }) => what.endsWith('.noted'))).toEqual([
      {
        at: expect.any(Date) as Date,
        what: 'transaction.noted',
        status: null,
        by: OPERATOR,
        via: null,
        evidenceRef: null,
      },
    ]);
    expect(JSON.stringify(found.timeline)).not.toContain('kept-out');
  });

  it('shows a paid one with no mark, and its newest events alone past the most, saying older were left out', async () => {
    const { w, paid } = await threePayments();
    expect(await reads.show(w.org, paid.id, CORRELATION)).toMatchObject({ outcome: 'found', markFailed: null });

    await backlogged(w.org, 'payment_alert', paid.id);
    await noteAbout(w, 'payment_alert', paid.id, 'payment_alert.latest');
    const found = await reads.show(w.org, paid.id, CORRELATION);

    expect(found).toMatchObject({ outcome: 'found', earlier: true });
    if (found.outcome !== 'found') throw new Error('not found');
    expect(found.timeline).toHaveLength(TIMELINE_MOST);
    // Oldest first, of the newest: the latest event last (M30).
    expect(found.timeline.at(-1)?.what).toBe('payment_alert.latest');
    expect(found.timeline.slice(0, -1).every(({ what }) => what === 'payment_alert.noted')).toBe(true);
  });

  it('shows exactly the most events whole, saying none were left out (M29)', async () => {
    const { w, paid } = await threePayments();
    const held = await withTenant(app, w.org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select((row) => row.fn.countAll<string>().as('events'))
        .where('subject_type', 'in', ['instruction', 'transaction', 'failure_proposal', 'payment_alert'])
        .where('subject_id', 'in', [paid.id, paid.instructionId])
        .executeTakeFirstOrThrow(),
    );
    for (let added = Number(held.events); added < TIMELINE_MOST; added += 1) {
      await noteAbout(w, 'payment_alert', paid.id, 'payment_alert.noted');
    }

    const found = await reads.show(w.org, paid.id, CORRELATION);

    expect(found).toMatchObject({ outcome: 'found', earlier: false });
    if (found.outcome !== 'found') throw new Error('not found');
    expect(found.timeline).toHaveLength(TIMELINE_MOST);
  });
});
