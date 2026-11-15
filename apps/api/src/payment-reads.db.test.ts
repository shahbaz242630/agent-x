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
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { MARK_FAILED_AFTER_MS } from '@agentx/core/modules/outcomes';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { SUPPLIER_VERSIONS } from '@agentx/core/modules/suppliers';
import { noteTransactionFacts, TRANSACTIONS } from '@agentx/core/modules/transactions';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
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
import { ALLOWED, handoffWorld, type HandoffWorldTables, payeeRefOf, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { createPaymentReads, type PaymentReads } from './payment-reads.ts';
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

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'payment-reads',
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

const checksOf = (w: World) =>
  createPaymentChecks({
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
  it('lists every UNKNOWN payment, and a paid one while the bank’s word contradicts it, until the bank agrees', async () => {
    const { w, paid, alsoPaid, unknown } = await threePayments();
    expect(await listOf(w.org, 'exceptions')).toEqual({ rows: [[unknown.id, 'UNKNOWN']], next: null, unchecked: [] });

    await bankSays(w, paid.id, 'Rejected', 'AANI.FF01');

    expect(await listOf(w.org, 'exceptions')).toEqual({
      rows: [
        [unknown.id, 'UNKNOWN'],
        [paid.id, 'SUCCEEDED', 'contradicted'],
      ],
      next: null,
      unchecked: [],
    });
    expect(await listOf(w.org, 'exceptions', null, 1)).toMatchObject({ next: unknown.id });
    expect(await listOf(w.org, 'exceptions', unknown.id, 1)).toEqual({
      rows: [[paid.id, 'SUCCEEDED', 'contradicted']],
      next: null,
      unchecked: [],
    });
    // The whole list says it too, and the one still agreed with isn't.
    expect(await listOf(w.org, 'paid')).toMatchObject({
      rows: [
        [alsoPaid.id, 'SUCCEEDED'],
        [paid.id, 'SUCCEEDED', 'contradicted'],
      ],
    });

    await bankSays(w, paid.id, 'AcceptedCreditSettlementCompleted');

    expect(await listOf(w.org, 'exceptions')).toEqual({ rows: [[unknown.id, 'UNKNOWN']], next: null, unchecked: [] });
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

  it('shows a paid one with no mark, and its newest events alone past the most, saying older were left out', async () => {
    const { w, paid } = await threePayments();
    expect(await reads.show(w.org, paid.id, CORRELATION)).toMatchObject({ outcome: 'found', markFailed: null });

    await backlogged(w.org, 'payment_alert', paid.id);
    const found = await reads.show(w.org, paid.id, CORRELATION);

    expect(found).toMatchObject({ outcome: 'found', earlier: true });
    if (found.outcome !== 'found') throw new Error('not found');
    expect(found.timeline).toHaveLength(100);
    expect(found.timeline.every(({ what }) => what === 'payment_alert.noted')).toBe(true);
  });
});
