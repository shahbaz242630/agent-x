// Phase 6 C2a: a spend request's evidence, downloaded by an admin, against
// Postgres on the real migrated schema as the app role (BR-16, PRD §8): the
// download recorded on the organisation's chain before a byte is read; the
// bundle of a request allowed and paid, one denied, one rejected, each with
// every signed event about it and its objects, their chain links and actors
// named, a retry answering the same record; one moment though a hand-off lands
// between the reads (read again, or EVIDENCE_CHANGED_WHILE_READING); never a
// secret or a seal (SEC-EVD-04); another organisation's request NOT_FOUND with
// nothing written; a member not an admin FORBIDDEN; the hourly budget (20) and
// the events' cap; and a record that can't be believed refusing the bundle, 503
// INTEGRITY_FAILED, the organisation held. 6C2c: the same bundle read on
// screen, writing nothing (no event, no idempotency key) and never counted
// against the budget, at one moment too (who may read it is the route's:
// spend-request-evidence.test.ts, role-matrix.test.ts).
import { createAuditTrail, type SignedRowRead, signedMoment, withSignedStates } from '@agentx/core/modules/audit';
import { EVIDENCE_EXPORTED, EVIDENCE_SUBJECT, EXPORT_BATCH } from '@agentx/core/modules/evidence';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { INSTRUCTIONS, type InstructionRecord } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { SPEND_REQUESTS, voidPendingOf } from '@agentx/core/modules/spend-requests';
import { SUPPLIER_VERSIONS, SUPPLIERS, VERIFIER_RECORDED } from '@agentx/core/modules/suppliers';
import { TRANSACTIONS } from '@agentx/core/modules/transactions';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { AED } from './mandate-world.helper.test.ts';
import { handoffWorld, type HandoffWorldTables, payeeRefOf, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { askedFor, keys, type Member, refused, type World } from './mandate-world.helper.test.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { createRailHealth } from './rail-health.ts';
import {
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  createSpendRequestApprovals,
  type SpendRequestApprovals,
} from './spend-request-approvals.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import {
  createSpendRequestEvidence,
  type Evidence,
  EVIDENCE_OPERATION,
  type EvidenceRead,
  type EvidenceView,
  type EvidenceWrite,
  type SpendRequestEvidence,
} from './spend-request-evidence.ts';
import {
  createSpendRequestRejects,
  REJECT_CONFIRM_OPERATION,
  REJECT_OPERATION,
  type SpendRequestRejects,
} from './spend-request-rejects.ts';
import { changedPastTheApp, spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;
let operator: Database<HandoffWorldTables>;

const ids = new SequentialIds(0x6c2a_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x6c2b_0000_0000) });
const CORRELATION = '0199a0f0-0000-7000-8000-0000000006c2';
/** Agent X's own team, as the operator's command names itself: only it resumes the hand-off. */
const PAUSER = { type: 'system', id: 'operator' } as const;
/** A step of the fake's payment: settled at the debtor a minute on, its answer final after two (B2). */
const STEP = 60_000;
const REASON = 'Not needed this month';

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let rejects: SpendRequestRejects;
let approvals: SpendRequestApprovals;
let evidence: SpendRequestEvidence;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'request-evidence',
  registry: () => registry,
  decisions: () => decisions,
});
const { ask, member, keyed, stepUp, quiet, statusOf, signed } = shared;
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

/** A request allowed, handed off and paid, checked two steps on: its instruction too. */
async function paid() {
  const { w, acting } = await ready();
  const request = await ask(acting, w, { amount: SMALL() });
  await createHandoff(runner(w)).run();
  clock.advanceBy(2 * STEP);
  await createPaymentChecks(runner(w)).run();
  const payment = await paymentOf(w, request.id);
  if (typeof payment.instruction !== 'object' || typeof payment.transaction !== 'object') {
    throw new Error(`not paid: ${JSON.stringify(payment)}`);
  }
  return { w, acting, request, instruction: payment.instruction, transaction: payment.transaction };
}

/** Rejected by an admin with a passkey and a reason, as the routes make it (B4a). */
async function rejectedBy(who: Member, requestId: string) {
  const challengeId = askedFor(await rejects.ask(who, keyed(who, REJECT_OPERATION), requestId, REASON, CORRELATION));
  await stepUp(who, challengeId);
  const done = await rejects.confirm(
    who,
    keyed(who, REJECT_CONFIRM_OPERATION),
    requestId,
    { reason: REASON, stepUpChallengeId: challengeId },
    CORRELATION,
  );
  expect(done).toMatchObject({ outcome: 'rejected' });
}

/** Approved by an admin with a passkey, as the routes make it (B4b). */
async function approvedBy(who: Member, requestId: string) {
  const challengeId = askedFor(await approvals.ask(who, keyed(who, APPROVE_OPERATION), requestId, false, CORRELATION));
  await stepUp(who, challengeId);
  const done = await approvals.confirm(
    who,
    keyed(who, APPROVE_CONFIRM_OPERATION),
    requestId,
    challengeId,
    false,
    CORRELATION,
  );
  expect(done).toMatchObject({ outcome: 'approved' });
}

const exported = (who: Member, requestId: string, key?: string, using: SpendRequestEvidence = evidence) =>
  using.export(who, keyed(who, EVIDENCE_OPERATION, key), requestId, CORRELATION);

/** The use case as the app makes it, but for what a test sets. */
const evidenceWith = (options: Partial<Parameters<typeof createSpendRequestEvidence>[0]> = {}) =>
  createSpendRequestEvidence({
    database: app,
    keys,
    ids,
    clock,
    logger: testLogger(new LogCapture()),
    directory: undefined,
    ...options,
  });

const bundleOf = (write: EvidenceWrite): Evidence => {
  if (write.outcome !== 'exported') throw new Error(`not exported: ${JSON.stringify(write)}`);
  return write.evidence;
};

/** The bundle as read on screen (6C2c): nothing written. */
const viewed = (w: World, requestId: string, using: SpendRequestEvidence = evidence) =>
  using.read(w.org, requestId, CORRELATION);

const readOf = (view: EvidenceView): EvidenceRead => {
  if (view.outcome !== 'read') throw new Error(`not read: ${JSON.stringify(view)}`);
  return view.evidence;
};

/** Each event's action, in the bundle's order. */
const actionsOf = (bundle: EvidenceRead) => bundle.events.map(({ action }) => action);

/** What the organisation has written: its audit events and its idempotency keys, counted past the app. */
async function writtenOf(w: World) {
  const owner = await database.connect('owner');
  try {
    // The tenant wall holds even the owner: in the organisation.
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
    const [counted] = await owner.query(
      `select (select pg_catalog.count(*)::int from audit.events where org_id = $1) as events,
              (select pg_catalog.count(*)::int from idempotency.keys where org_id = $1) as keys`,
      [w.org],
    );
    return counted;
  } finally {
    await owner.end();
  }
}

/** The organisation's evidence downloads, as its log holds them. */
const downloadsOf = (w: World) =>
  withTenant(app, w.org, (tx) =>
    tx.selectFrom('audit.events').select(['id', 'seq']).where('action', '=', EVIDENCE_EXPORTED).execute(),
  );

const heldOf = (w: World) => withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));

type Owner = Awaited<ReturnType<typeof tamperAsOwner>>;
type Guard = (owner: Owner) => Promise<unknown>;

/** Each table's guards, off then on again, each by its fixed text (SEC-TEN-07). */
const GUARDS = {
  [INSTRUCTIONS.table]: [
    (o) => o.query('alter table instructions.instructions disable trigger user'),
    (o) => o.query('alter table instructions.instructions enable trigger user'),
  ],
  [SOURCES.table]: [
    (o) => o.query('alter table funding_sources.sources disable trigger user'),
    (o) => o.query('alter table funding_sources.sources enable trigger user'),
  ],
  [SPEND_REQUESTS.table]: [
    (o) => o.query('alter table spend_requests.requests disable trigger user'),
    (o) => o.query('alter table spend_requests.requests enable trigger user'),
  ],
  [SUPPLIER_VERSIONS.table]: [
    (o) => o.query('alter table suppliers.supplier_versions disable trigger user'),
    (o) => o.query('alter table suppliers.supplier_versions enable trigger user'),
  ],
  [TRANSACTIONS.table]: [
    (o) => o.query('alter table transactions.transactions disable trigger user'),
    (o) => o.query('alter table transactions.transactions enable trigger user'),
  ],
} as const satisfies Record<string, readonly [Guard, Guard]>;

/** A record's column changed by its table's owner with its guards off for that change alone: as only something past the app could. */
async function changedByOwner(
  w: World,
  target: typeof INSTRUCTIONS | typeof SOURCES | typeof SPEND_REQUESTS | typeof SUPPLIER_VERSIONS | typeof TRANSACTIONS,
  id: string,
  [column, value]: readonly [string, string | number],
) {
  const owner = await tamperAsOwner(database, target, w.org);
  const [off, on] = GUARDS[target.table];
  try {
    await owner.query('begin');
    await off(owner);
    await owner.setColumn(id, column, value);
    await on(owner);
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

/** What must never be in a bundle (SEC-EVD-04): the payee's key, and anything shaped as an account number. */
const PAYEE_KEY = `fake-payee-${'b'.repeat(32)}`;
const IBAN_SHAPED = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/;

/** The bundle carries no secret: no payee key, no IBAN; no signed event's facts a consent or payee (evidenceFacts). */
function expectNoSecret(bundle: Evidence): void {
  const text = JSON.stringify(bundle);
  expect(text).not.toContain(PAYEE_KEY);
  expect(text).not.toMatch(IBAN_SHAPED);
  const signed = [bundle.events, bundle.mandate?.acceptance, bundle.supplier.version?.verification];
  for (const part of signed.filter((events) => events !== undefined && events !== null)) {
    const shown = JSON.stringify(part);
    for (const name of ['beneficiary', 'consent', 'payee', 'KeyVersion', 'Fingerprint', '"mac"']) {
      expect(shown).not.toContain(name);
    }
  }
}

/** The partner's opaque references the bundle carries (GA2, BR-16), from the instruction and the version it was decided under. */
function expectReferences(bundle: Evidence, w: World, instruction: InstructionRecord): void {
  expect(bundle.payment?.instruction).toMatchObject({
    accountConsentId: instruction.accountConsentId,
    beneficiaryRef: instruction.beneficiaryRef,
  });
  expect(instruction.beneficiaryRef).toBe(payeeRefOf(w));
  expect(bundle.supplier.version?.beneficiaryRef).toBe(payeeRefOf(w));
  expect(bundle.fundingSource.accountConsentId).toBe(instruction.accountConsentId);
}

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
        { paused: false, reason: 'TEST-6C2', actor: PAUSER, release: 'r-test', run: null },
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
  const logger = testLogger(new LogCapture());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock, keys }),
    keys,
    ids,
    clock,
    logger,
  });
  rejects = createSpendRequestRejects({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock, keys, logger: testLogger() }),
    logger,
  });
  approvals = createSpendRequestApprovals({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock, keys, logger: testLogger() }),
    logger,
  });
  evidence = evidenceWith({ logger });
});

describe('a spend request’s evidence (Phase 6 C2a, BR-16)', () => {
  it('SEC-EVD-03 records the download first, then gives a paid request whole: decided, handed off, paid, every event linked', async () => {
    const { w, request, instruction, transaction } = await paid();

    const bundle = bundleOf(await exported(w.admin, request.id));

    expect(bundle.spendRequest).toMatchObject({
      id: request.id,
      status: 'HANDED_OFF',
      decision: 'ALLOW',
      amountMinor: Number(SMALL().minor),
      currency: 'AED',
      purpose: 'Printer paper',
      orderReference: request.orderReference,
    });
    expect(bundle.spendRequest.inputHash).toMatch(/^[0-9a-f]+$/);
    expect(bundle.spendRequest.decidedAt).not.toBeNull();
    expect(bundle.agent).toMatchObject({ id: w.agent, name: 'Purchasing agent' });
    expect(bundle.agent.keyId).not.toBeNull();
    expect(bundle.mandate?.id).toBe(request.mandateId);
    expect(bundle.mandate?.acceptance).toMatchObject({ action: 'mandate.accepted' });
    expect(bundle.policies.organizationPolicyVersionId).not.toBeNull();
    expect(bundle.supplier.version).toMatchObject({ id: instruction.supplierVersionId });
    expect(bundle.supplier.version?.verification).toMatchObject({ action: 'supplier.verifier_recorded' });
    expect(bundle.fundingSource).toMatchObject({ id: w.source });
    expect(bundle.reservation).toMatchObject({ state: 'FINALISED', amountMinor: Number(SMALL().minor) });
    expect(bundle.approval).toBeNull();
    expect(bundle.payment).toMatchObject({
      id: transaction.id,
      status: 'SUCCEEDED',
      instruction: { id: instruction.id, intentHash: instruction.intentHash, route: 'push' },
      reconciliation: { contradicted: false, markableFrom: null, openProposalId: null },
    });
    // Every event about it, oldest first, each linked to the one before it in the chain.
    expect(actionsOf(bundle)).toEqual(
      expect.arrayContaining(['spend_request.decided', 'instruction.made', 'transaction.opened', EVIDENCE_EXPORTED]),
    );
    expect(actionsOf(bundle).at(-1)).toBe(EVIDENCE_EXPORTED);
    const seqs = bundle.events.map(({ seq }) => BigInt(seq));
    expect(seqs).toEqual([...seqs].sort((a, b) => (a < b ? -1 : 1)));
    expect(bundle.events.every(({ hash, prevHash }) => /^[0-9a-f]{64}$/.test(hash) && prevHash.length > 0)).toBe(true);
    expect(bundle.events.find(({ action }) => action === EVIDENCE_EXPORTED)?.actor).toMatchObject({
      type: 'user',
      id: w.admin.userId,
    });
    expect(bundle.events.find(({ action }) => action === 'spend_request.decided')?.actor).toMatchObject({
      type: 'agent',
      id: w.agent,
      name: 'Purchasing agent',
      shownFrom: 'agent',
    });

    // The download, on the organisation's own chain, about the request's evidence, naming what it read.
    const recorded = await withTenant(app, w.org, (tx) =>
      createAuditTrail({ keys, ids }).recordedEvent(tx, w.org, { eventId: bundle.id }),
    );
    expect(recorded).toMatchObject({
      kind: 'recorded',
      seq: BigInt(bundle.upToSeq),
      event: {
        actor: { type: 'user', id: w.admin.userId },
        action: EVIDENCE_EXPORTED,
        subject: { type: EVIDENCE_SUBJECT, id: request.id, version: 1 },
        details: { spendRequestId: request.id, status: 'HANDED_OFF', format: 'json' },
      },
    });
  });

  it('carries no secret and no seal, the partner’s opaque consent and payee references alone (SEC-EVD-04, GA2)', async () => {
    const { w, request, instruction } = await paid();

    const bundle = bundleOf(await exported(w.admin, request.id));
    const text = JSON.stringify(bundle);

    expectNoSecret(bundle);
    // The licensed partner's public references are evidence (BR-16), kept.
    expect(text).toContain(instruction.partnerLegalEntityId);
    expect(text).toContain(instruction.partnerLicenceRef);
    expectReferences(bundle, w, instruction);
    for (const seal of [
      'stateFingerprint',
      'stateKeyVersion',
      'KeyVersion',
      '"mac"',
      'payeeKey',
      'payeeHint',
      'iban',
    ]) {
      expect(text).not.toContain(seal);
    }
  });

  it('answers a retry with its key with the same bundle, read to the same seq, and records the download once', async () => {
    const { w, request } = await paid();

    const first = bundleOf(await exported(w.admin, request.id, 'evidence-again'));
    const again = bundleOf(await exported(w.admin, request.id, 'evidence-again'));

    expect(again).toEqual(first);
    expect(await downloadsOf(w)).toHaveLength(1);
  });

  it('SEC-EVD-03 gives a denied request too: its decision and reasons, no reservation and no payment', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });
    expect(denied.status).toBe('DENIED');

    const bundle = bundleOf(await exported(w.admin, denied.id));

    expect(bundle.spendRequest).toMatchObject({ id: denied.id, status: 'DENIED', decision: denied.decision });
    expect(bundle.spendRequest.reasons.map(({ code }) => code)).toEqual(denied.reasons);
    expect(bundle).toMatchObject({ reservation: null, payment: null, approval: null, rejection: null, voiding: null });
    expect(actionsOf(bundle)).toEqual(['spend_request.received', 'spend_request.decided', EVIDENCE_EXPORTED]);
  });

  // S208: PRD §12's third case beside denial and success, a partner's decline (the fake's .01 fils, B2).
  it('SEC-EVD-03 gives a request the partner declined whole: decided, handed off, declined with its code, released, every event linked, no secret', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: SMALL(1n) });
    await createHandoff(runner(w)).run();
    const payment = await paymentOf(w, request.id);
    if (typeof payment.instruction !== 'object' || typeof payment.transaction !== 'object') {
      throw new Error(`not handed off: ${JSON.stringify(payment)}`);
    }

    const bundle = bundleOf(await exported(w.admin, request.id));

    expect(bundle.spendRequest).toMatchObject({
      id: request.id,
      decision: 'ALLOW',
      amountMinor: Number(SMALL(1n).minor),
    });
    expect(bundle.reservation).toMatchObject({ state: 'RELEASED' });
    expect(bundle.payment).toMatchObject({
      id: payment.transaction.id,
      status: 'FAILED',
      rejectCode: 'AANI.AM04',
      instruction: { id: payment.instruction.id, intentHash: payment.instruction.intentHash },
    });
    expect(actionsOf(bundle)).toEqual(
      expect.arrayContaining(['spend_request.decided', 'instruction.made', 'transaction.opened', EVIDENCE_EXPORTED]),
    );
    expect(bundle.events.every(({ hash, prevHash }) => /^[0-9a-f]{64}$/.test(hash) && prevHash.length > 0)).toBe(true);
    expectNoSecret(bundle);
    expectReferences(bundle, w, payment.instruction);
  });

  it('gives a rejected request with who rejected it, when, why and the step-up it was bound to', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    expect(waiting.status).toBe('APPROVAL_REQUIRED');
    await rejectedBy(w.admin, waiting.id);

    const bundle = bundleOf(await exported(w.admin, waiting.id));

    expect(await statusOf(w, waiting.id)).toBe('DENIED');
    expect(bundle.rejection).toMatchObject({ byUserId: w.admin.userId, reason: REASON });
    expect(bundle.rejection?.changeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(bundle.rejection?.stepUpChallengeId).not.toBeNull();
    expect(bundle.reservation).toMatchObject({ state: 'RELEASED' });
    expect(bundle.payment).toBeNull();
    expect(actionsOf(bundle)).toEqual([
      'spend_request.received',
      'spend_request.decided',
      'spend_request.rejected',
      EVIDENCE_EXPORTED,
    ]);
  });

  it('gives one waiting with when it expires and its reservation held, then approved with who and the step-up bound', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    const before = bundleOf(await exported(w.admin, waiting.id));
    expect(before.spendRequest).toMatchObject({ status: 'APPROVAL_REQUIRED' });
    expect(before.spendRequest.expiresAt).not.toBeNull();
    expect(before.reservation).toMatchObject({ state: 'HELD' });
    expect(before.approval).toBeNull();

    await approvedBy(w.admin, waiting.id);
    const after = bundleOf(await exported(w.admin, waiting.id));
    expect(after.spendRequest).toMatchObject({ status: 'APPROVED', expiresAt: null });
    expect(after.approval).toMatchObject({ byUserId: w.admin.userId });
    expect(after.approval?.changeHash).toMatch(/^[0-9a-f]{64}$/);
    // Each download is on the request's evidence, and the later one reads the earlier.
    expect(actionsOf(after).filter((action) => action === EVIDENCE_EXPORTED)).toHaveLength(2);
  });

  it('gives a voided request with when and why', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await signed(w, (tx, states) =>
      voidPendingOf(tx, states, keys, w.org, { agentId: w.agent }, 'AGENT_SUSPENDED', clock.now(), 10),
    );

    const bundle = bundleOf(await exported(w.admin, waiting.id));

    expect(bundle.spendRequest.status).toBe('DENIED');
    expect(bundle.voiding?.reasons.map(({ code }) => code)).toEqual(['AGENT_SUSPENDED']);
    expect(bundle.rejection).toBeNull();
  });

  it('gives a request decided with no mandate in force: no mandate, nor its acceptance', async () => {
    const w = await shared.world();
    const acting = await shared.agentKey(w);
    const denied = await ask(acting, w);

    const bundle = bundleOf(await exported(w.admin, denied.id));

    expect(bundle.spendRequest).toMatchObject({ status: 'DENIED', decision: 'DENY' });
    expect(bundle.mandate).toBeNull();
  });

  it.each([
    ['the request itself', 'request'],
    ['the agent that asked', 'agent'],
    ['its funding source', 'source'],
    ['the supplier’s details it was decided under', 'version'],
    ['its payment', 'transaction'],
  ] as const)(
    'refuses a bundle when %s can’t be believed: INTEGRITY_FAILED, the organisation held',
    async (_what, which) => {
      const { w, request, instruction, transaction } = await paid();
      if (which === 'request') await changedByOwner(w, SPEND_REQUESTS, request.id, ['amount_minor', 1]);
      if (which === 'source') await changedByOwner(w, SOURCES, w.source, ['consent_status', 'Revoked']);
      if (which === 'version') {
        await changedByOwner(w, SUPPLIER_VERSIONS, instruction.supplierVersionId, [
          'display_name',
          'Pay me instead LLC',
        ]);
      }
      if (which === 'transaction')
        await changedByOwner(w, TRANSACTIONS, transaction.id, ['provider_status', 'Rejected']);
      if (which === 'agent') {
        await withTenant(app, w.org, (tx) =>
          tx.updateTable('agents.agents').set({ scopes: 'requests:read' }).where('id', '=', w.agent).execute(),
        );
      }

      expect(await exported(w.admin, request.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
      expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
    },
  );

  it('reads the rows again when a hand-off lands between them: one moment, handed off with its payment and events', async () => {
    const { w, acting } = await ready();
    const approved = await ask(acting, w, { amount: SMALL() });
    let between = 0;
    const handingOff = evidenceWith({
      betweenReads: async () => {
        between += 1;
        if (between === 1) await createHandoff(runner(w)).run();
      },
    });

    const bundle = bundleOf(await exported(w.admin, approved.id, undefined, handingOff));

    // The first read saw it APPROVED and then its payment: not one moment, so it was read again.
    expect(between).toBe(2);
    expect(bundle.spendRequest.status).toBe('HANDED_OFF');
    expect(bundle.payment).not.toBeNull();
    expect(actionsOf(bundle)).toEqual(expect.arrayContaining(['instruction.made', 'transaction.opened']));
    expect(BigInt(bundle.upToSeq)).toBeGreaterThan(BigInt(bundle.recordSeq));
    expect(bundle.events.every(({ seq }) => BigInt(seq) <= BigInt(bundle.upToSeq))).toBe(true);
  });

  it('gives up after its reads when the rows never hold still: EVIDENCE_CHANGED_WHILE_READING, the download logged', async () => {
    const { w, acting } = await ready();
    const approved = await ask(acting, w, { amount: SMALL() });
    const once = evidenceWith({ mostReads: 1, betweenReads: () => createHandoff(runner(w)).run() });

    expect(await exported(w.admin, approved.id, undefined, once)).toEqual(
      refused(409, 'EVIDENCE_CHANGED_WHILE_READING'),
    );
    expect(await downloadsOf(w)).toHaveLength(1);
  });

  it('reads the rows again when the payment settles between them: its reservation and status at one moment', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: SMALL() });
    await createHandoff(runner(w)).run();
    const settled = async () => {
      clock.advanceBy(2 * STEP);
      await createPaymentChecks(runner(w)).run();
    };
    let between = 0;
    const settling = evidenceWith({
      betweenReads: async () => {
        between += 1;
        if (between === 1) await settled();
      },
    });

    const bundle = bundleOf(await exported(w.admin, request.id, undefined, settling));

    // The first read judged the reservation HELD with the payment under way, then read the payment paid: read again.
    expect(between).toBe(2);
    expect(bundle.payment).toMatchObject({ status: 'SUCCEEDED' });
    expect(bundle.reservation).toMatchObject({ state: 'FINALISED' });
  });

  it('refuses with one read when the payment settles between the reads: EVIDENCE_CHANGED_WHILE_READING', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: SMALL() });
    await createHandoff(runner(w)).run();
    const once = evidenceWith({
      mostReads: 1,
      betweenReads: async () => {
        clock.advanceBy(2 * STEP);
        await createPaymentChecks(runner(w)).run();
      },
    });

    expect(await exported(w.admin, request.id, undefined, once)).toEqual(
      refused(409, 'EVIDENCE_CHANGED_WHILE_READING'),
    );
  });

  it('answers a retry after an approval with the same record and the approval: the bundle as it stands then', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    const first = bundleOf(await exported(w.admin, waiting.id, 'evidence-later'));
    await approvedBy(w.admin, waiting.id);
    const later = bundleOf(await exported(w.admin, waiting.id, 'evidence-later'));

    expect(later).toMatchObject({ id: first.id, recordSeq: first.recordSeq });
    expect(first.approval).toBeNull();
    expect(later.approval).toMatchObject({ byUserId: w.admin.userId });
    expect(actionsOf(later)).toContain('spend_request.approved');
    expect(await downloadsOf(w)).toHaveLength(1);
  });

  it('refuses an admin’s 21st download in an hour, reads on screen not counted: EVIDENCE_EXPORTS_SPENT, nothing written', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });
    // Six reads first, past the audit log's own budget of 5: none is a download, so all 20 downloads are made.
    for (let read = 0; read < 6; read += 1) readOf(await viewed(w, denied.id));
    for (let made = 0; made < 20; made += 1) bundleOf(await exported(w.admin, denied.id));

    expect(await exported(w.admin, denied.id)).toEqual(refused(409, 'EVIDENCE_EXPORTS_SPENT'));
    expect(await downloadsOf(w)).toHaveLength(20);
    // Reading on screen is never capped.
    expect(readOf(await viewed(w, denied.id)).events).toHaveLength(22);
  });

  it('refuses a request with more events than a bundle holds: EVIDENCE_TOO_LARGE, nothing written', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });

    expect(await exported(w.admin, denied.id, undefined, evidenceWith({ mostEvents: 1 }))).toEqual(
      refused(409, 'EVIDENCE_TOO_LARGE'),
    );
    expect(await downloadsOf(w)).toEqual([]);
  });

  it('counts the download’s own record against the cap: a request already at it is refused before it is logged', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });
    // Its events with one download recorded: the next bundle holds these and its own record, one more.
    const held = bundleOf(await exported(w.admin, denied.id)).events.length;

    expect(await exported(w.admin, denied.id, undefined, evidenceWith({ mostEvents: held }))).toEqual(
      refused(409, 'EVIDENCE_TOO_LARGE'),
    );
    expect(await downloadsOf(w)).toHaveLength(1);
    // The control: one more fits.
    expect(
      bundleOf(await exported(w.admin, denied.id, undefined, evidenceWith({ mostEvents: held + 1 }))).events,
    ).toHaveLength(held + 1);
  });

  it('answers another organisation’s request as NOT_FOUND, writing nothing', async () => {
    const { request } = await paid();
    const { w: other } = await ready();

    expect(await exported(other.admin, request.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await downloadsOf(other)).toEqual([]);
  });

  it('refuses a member who is not an admin, writing nothing (decision 24)', async () => {
    const { w, request } = await paid();
    const approver = await member(w.org, 'approver');

    expect(await exported(approver, request.id)).toEqual(refused(403, 'FORBIDDEN'));
    expect(await downloadsOf(w)).toEqual([]);
  });

  it('refuses a bundle when its payment’s instruction can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const { w, request, instruction } = await paid();
    await changedByOwner(w, INSTRUCTIONS, instruction.id, ['amount_minor', 99_000]);

    expect(await exported(w.admin, request.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('refuses a bundle when an event about it can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const { w, request, transaction } = await paid();
    const owner = await database.connect('owner');
    try {
      // Past the app: the owner, in the organisation, as the tenant wall holds even it.
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await owner.query(
        `update audit.events set details = '{"x":1}' where org_id = $1 and subject_id = $2 and action = 'transaction.opened'`,
        [w.org, transaction.id],
      );
    } finally {
      await owner.end();
    }

    expect(await exported(w.admin, request.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('refuses a retry when its own download’s record can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const { w, request } = await paid();
    const first = bundleOf(await exported(w.admin, request.id, 'evidence-record'));
    const owner = await database.connect('owner');
    try {
      // Past the app: the owner, in the organisation, as the tenant wall holds even it.
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await owner.query(`update audit.events set details = '{"x":1}' where org_id = $1 and id = $2`, [w.org, first.id]);
    } finally {
      await owner.end();
    }

    expect(await exported(w.admin, request.id, 'evidence-record')).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('refuses a bundle when its reservation was changed past the app: INTEGRITY_FAILED, the organisation held', async () => {
    const { w, request } = await paid();
    await changedPastTheApp(database, w.org, request.id, 'amount halved');

    expect(await exported(w.admin, request.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('refuses a bundle when its payment is changed past the app between the reads: INTEGRITY_FAILED, the organisation held', async () => {
    const { w, request, transaction } = await paid();
    // After the request's transaction read it whole: only the second read's own check can catch it.
    const tampering = evidenceWith({
      betweenReads: () => changedByOwner(w, TRANSACTIONS, transaction.id, ['provider_status', 'Rejected']),
    });

    expect(await exported(w.admin, request.id, undefined, tampering)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('refuses a bundle when the supplier’s details it was decided under change past the app between the reads: INTEGRITY_FAILED', async () => {
    const { w, acting } = await ready();
    // Waiting, so no payment of its own reads those details again after the read of them.
    const waiting = await ask(acting, w);
    const versionId = bundleOf(await exported(w.admin, waiting.id)).supplier.version?.id ?? '';
    const tampering = evidenceWith({
      betweenReads: () => changedByOwner(w, SUPPLIER_VERSIONS, versionId, ['display_name', 'Pay me instead LLC']),
    });

    expect(await exported(w.admin, waiting.id, undefined, tampering)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('holds the log at its moment: a download recorded while the rows are read is left out of it', async () => {
    const { w, request } = await paid();
    let between = 0;
    const reading = evidenceWith({
      betweenReads: async () => {
        between += 1;
        if (between === 1) bundleOf(await exported(w.admin, request.id));
      },
    });

    const bundle = bundleOf(await exported(w.admin, request.id, undefined, reading));

    expect(await downloadsOf(w)).toHaveLength(2);
    // The other download is newer than every row read and than this one's record: past the moment.
    expect(bundle.upToSeq).toBe(bundle.recordSeq);
    expect(bundle.events.filter(({ action }) => action === EVIDENCE_EXPORTED).map(({ id }) => id)).toEqual([bundle.id]);
  });

  it('refuses a bundle whose events grew past the cap while it was read, rather than cut it short: EVIDENCE_TOO_LARGE', async () => {
    const { w, acting } = await ready();
    const approved = await ask(acting, w, { amount: SMALL() });
    // As it stands, with one download recorded: the next fits the cap with its own record, and no more.
    const before = bundleOf(await exported(w.admin, approved.id)).events.length;
    let between = 0;
    // A hand-off landing between the reads: read again, its instruction's and payment's events push it over.
    const growing = evidenceWith({
      mostEvents: before + 1,
      betweenReads: async () => {
        between += 1;
        if (between === 1) await createHandoff(runner(w)).run();
      },
    });

    expect(await exported(w.admin, approved.id, undefined, growing)).toEqual(refused(409, 'EVIDENCE_TOO_LARGE'));
    expect(between).toBe(2);
    expect(await downloadsOf(w)).toHaveLength(2);
  });

  it('finds the verification of the very supplier details it was decided under, past a batch of newer ones', async () => {
    const { w, request } = await paid();
    const first = bundleOf(await exported(w.admin, request.id));
    const verification = first.supplier.version?.verification;
    expect(verification).toMatchObject({ action: VERIFIER_RECORDED });
    // A full batch of newer verifications of the supplier, each naming other details: the search pages past them.
    await withTenant(app, w.org, async (tx) => {
      const trail = createAuditTrail({ keys, ids });
      for (let made = 0; made < EXPORT_BATCH; made += 1) {
        await trail.record(tx, w.org, {
          actor: { type: 'user', id: w.admin.userId },
          action: VERIFIER_RECORDED,
          subject: { type: SUPPLIERS.subject, id: first.supplier.id, version: 1 },
          details: { verifiedVersionId: ids.next() },
        });
      }
    });

    const later = bundleOf(await exported(w.admin, request.id));

    expect(later.supplier.version?.verification?.id).toBe(verification?.id);
  });
});

describe('a spend request’s evidence read on screen (6C2c, decision 24: a page read, not logged)', () => {
  it('reads a paid request whole, writing nothing: no event, no idempotency key, no record of its own', async () => {
    const { w, request, transaction } = await paid();
    const before = await writtenOf(w);

    const bundle = readOf(await viewed(w, request.id));

    expect(await writtenOf(w)).toEqual(before);
    expect(bundle).not.toHaveProperty('id');
    expect(bundle).not.toHaveProperty('recordSeq');
    expect(bundle.spendRequest).toMatchObject({ id: request.id, status: 'HANDED_OFF' });
    expect(bundle.payment).toMatchObject({ id: transaction.id, status: 'SUCCEEDED' });
    expect(actionsOf(bundle)).toEqual(expect.arrayContaining(['spend_request.decided', 'instruction.made']));
    expect(actionsOf(bundle)).not.toContain(EVIDENCE_EXPORTED);
    expect(bundle.events.at(-1)?.seq).toBe(bundle.upToSeq);
  });

  it('is the download’s bundle without its record, held at the newest event about its objects (a download too)', async () => {
    const { w, request } = await paid();
    const { id: _id, recordSeq, ...downloaded } = bundleOf(await exported(w.admin, request.id));

    const read = readOf(await viewed(w, request.id));

    // The download's record is newer than every row's signed event, and has no state: the read's moment is it.
    expect(read.upToSeq).toBe(recordSeq);
    expect(read).toEqual(downloaded);
  });

  it('reads a denied request too: its decision, no reservation and no payment', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });

    const bundle = readOf(await viewed(w, denied.id));

    expect(bundle.spendRequest).toMatchObject({ id: denied.id, status: 'DENIED' });
    expect(bundle).toMatchObject({ reservation: null, payment: null });
    expect(actionsOf(bundle)).toEqual(['spend_request.received', 'spend_request.decided']);
  });

  it('answers another organisation’s request as NOT_FOUND, writing nothing', async () => {
    const { request } = await paid();
    const { w: other } = await ready();
    const before = await writtenOf(other);

    expect(await viewed(other, request.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await writtenOf(other)).toEqual(before);
  });

  it('refuses a read when the request can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const { w, request } = await paid();
    await changedByOwner(w, SPEND_REQUESTS, request.id, ['amount_minor', 1]);

    expect(await viewed(w, request.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('reads the rows again when a hand-off lands between them: one moment, handed off with its payment', async () => {
    const { w, acting } = await ready();
    const approved = await ask(acting, w, { amount: SMALL() });
    let between = 0;
    const handingOff = evidenceWith({
      betweenReads: async () => {
        between += 1;
        if (between === 1) await createHandoff(runner(w)).run();
      },
    });

    const bundle = readOf(await viewed(w, approved.id, handingOff));

    expect(between).toBe(2);
    expect(bundle.spendRequest.status).toBe('HANDED_OFF');
    expect(bundle.payment).not.toBeNull();
    expect(actionsOf(bundle)).toEqual(expect.arrayContaining(['instruction.made', 'transaction.opened']));
    expect(bundle.events.every(({ seq }) => BigInt(seq) <= BigInt(bundle.upToSeq))).toBe(true);
  });

  it('finds its moment after the rows are read: a download recorded while they are read is in it, at its seq', async () => {
    const { w, request } = await paid();
    let between = 0;
    let other: Evidence | undefined;
    const reading = evidenceWith({
      betweenReads: async () => {
        between += 1;
        if (between === 1) other = bundleOf(await exported(w.admin, request.id));
      },
    });

    const bundle = readOf(await viewed(w, request.id, reading));

    // The download seals no state, so no row moved: found with the moment, after the rows, it is the moment.
    expect(between).toBe(1);
    expect(bundle.upToSeq).toBe(other?.recordSeq);
    expect(bundle.events.filter(({ action }) => action === EVIDENCE_EXPORTED).map(({ id }) => id)).toEqual([other?.id]);
  });

  it('gives up after its reads when the rows never hold still: EVIDENCE_CHANGED_WHILE_READING, nothing logged', async () => {
    const { w, acting } = await ready();
    const approved = await ask(acting, w, { amount: SMALL() });
    const once = evidenceWith({ mostReads: 1, betweenReads: () => createHandoff(runner(w)).run() });

    expect(await viewed(w, approved.id, once)).toEqual(refused(409, 'EVIDENCE_CHANGED_WHILE_READING'));
    expect(await downloadsOf(w)).toEqual([]);
  });

  it('refuses a request with more events than a bundle holds: EVIDENCE_TOO_LARGE', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });

    expect(await viewed(w, denied.id, evidenceWith({ mostEvents: 1 }))).toEqual(refused(409, 'EVIDENCE_TOO_LARGE'));
  });
});

describe('signedMoment: rows read in more than one transaction, at one moment (Phase 6 C2a)', () => {
  /** The request's events that seal its state, oldest first. */
  const sealedOf = (w: World, requestId: string) =>
    withTenant(app, w.org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['id', 'seq'])
        .where('subject_type', '=', SPEND_REQUESTS.subject)
        .where('subject_id', '=', requestId)
        .where('details', 'like', '%"stateFingerprint":%')
        .orderBy('seq')
        .execute(),
    );

  const momentOf = (w: World, rows: readonly SignedRowRead[], fromSeq: bigint) =>
    withTenant(app, w.org, (tx) => signedMoment(tx, w.org, rows, fromSeq));

  /** A request approved, so its state is sealed by at least two events; the newest two of them. */
  async function approvedRequest() {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await approvedBy(w.admin, waiting.id);
    const sealed = await sealedOf(w, waiting.id);
    const [older, newest] = sealed.slice(-2);
    if (older === undefined || newest === undefined) throw new Error(`not sealed twice: ${JSON.stringify(sealed)}`);
    const read = (eventId: string): SignedRowRead => ({
      subject: { type: SPEND_REQUESTS.subject, id: waiting.id },
      eventId,
    });
    return { w, requestId: waiting.id, older, newest, read };
  }

  it('holds at the newest seq read when nothing moved, and counts a move at that very seq', async () => {
    const { w, older, newest, read } = await approvedRequest();

    expect(await momentOf(w, [read(newest.id)], 0n)).toEqual({ outcome: 'moment', upToSeq: newest.seq });
    // Read once at its older event and once at its newest: the newest, the moment itself, is a move in between.
    expect(await momentOf(w, [read(older.id), read(newest.id)], 0n)).toEqual({ outcome: 'moved' });
  });

  it('counts only signed states as moves: an event about the row with no state sealed leaves the moment standing', async () => {
    const { w, requestId, newest, read } = await approvedRequest();
    const noted = await withTenant(app, w.org, (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: { type: 'user', id: w.admin.userId },
        action: 'probe.noted',
        subject: { type: SPEND_REQUESTS.subject, id: requestId, version: 1 },
        details: {},
      }),
    );

    expect(await momentOf(w, [read(newest.id)], noted.seq)).toEqual({ outcome: 'moment', upToSeq: noted.seq });
  });

  it('never gives a moment for a row believed by an event the log doesn’t hold', async () => {
    const { w, newest, read } = await approvedRequest();

    expect(
      await momentOf(
        w,
        [read(newest.id), { subject: { type: SOURCES.subject, id: w.source }, eventId: ids.next() }],
        0n,
      ),
    ).toEqual({ outcome: 'moved' });
  });
});
