// Phase 6 C2a: a spend request's evidence, downloaded by an admin, against
// Postgres on the real migrated schema as the app role (BR-16, PRD §8): the
// download recorded on the organisation's chain before a byte is read; the
// bundle of a request allowed and paid, one denied, one rejected, each with
// every signed event about it and its objects, their chain links and actors
// named, a retry answering the same record; one moment though a hand-off lands
// between the reads (read again, or EVIDENCE_CHANGED_WHILE_READING); never a
// secret or a seal (SEC-EVD-04); another organisation's request NOT_FOUND with
// nothing written; a member not an admin FORBIDDEN; the hourly budget and the
// events' cap; and a record that can't be believed refusing the bundle, 503
// INTEGRITY_FAILED, the organisation held.
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { EVIDENCE_EXPORTED, EVIDENCE_SUBJECT } from '@agentx/core/modules/evidence';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { INSTRUCTIONS, type InstructionRecord } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { SPEND_REQUESTS, voidPendingOf } from '@agentx/core/modules/spend-requests';
import { SUPPLIER_VERSIONS } from '@agentx/core/modules/suppliers';
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
  outbox: createOutbox({ ids, clock }),
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

/** Each event's action, in the bundle's order. */
const actionsOf = (bundle: Evidence) => bundle.events.map(({ action }) => action);

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

/** The instruction's secrets, each of which must never be in a bundle (SEC-EVD-04). */
const secretsOf = (w: World, instruction: InstructionRecord) => [
  payeeRefOf(w),
  instruction.beneficiaryRef,
  instruction.accountConsentId,
];

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
    outbox: createOutbox({ ids, clock }),
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
    challenges: createStepUpChallenges({ ids, clock }),
    logger,
  });
  approvals = createSpendRequestApprovals({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    logger,
  });
  evidence = evidenceWith({ logger });
});

describe('a spend request’s evidence (Phase 6 C2a, BR-16)', () => {
  it('records the download first, then gives a paid request whole: decided, handed off, paid, every event linked', async () => {
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
    expect(bundle.supplier.version.verification).toMatchObject({ action: 'supplier.verifier_recorded' });
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

  it('carries no secret and no seal: no payee, consent, partner legal reference, fingerprint or key version (SEC-EVD-04)', async () => {
    const { w, request, instruction } = await paid();

    const text = JSON.stringify(bundleOf(await exported(w.admin, request.id)));

    for (const secret of secretsOf(w, instruction)) expect(text).not.toContain(secret);
    // The licensed partner's public references are evidence (BR-16), kept.
    expect(text).toContain(instruction.partnerLegalEntityId);
    expect(text).toContain(instruction.partnerLicenceRef);
    for (const seal of ['stateFingerprint', 'stateKeyVersion', 'KeyVersion', '"mac"', 'beneficiary', 'consent']) {
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

  it('gives a denied request too: its decision and reasons, no reservation and no payment', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });
    expect(denied.status).toBe('DENIED');

    const bundle = bundleOf(await exported(w.admin, denied.id));

    expect(bundle.spendRequest).toMatchObject({ id: denied.id, status: 'DENIED', decision: denied.decision });
    expect(bundle.spendRequest.reasons.map(({ code }) => code)).toEqual(denied.reasons);
    expect(bundle).toMatchObject({ reservation: null, payment: null, approval: null, rejection: null, voiding: null });
    expect(actionsOf(bundle)).toEqual(['spend_request.received', 'spend_request.decided', EVIDENCE_EXPORTED]);
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

  it('refuses an admin’s sixth download in an hour: EVIDENCE_EXPORTS_SPENT, nothing written', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });
    for (let made = 0; made < 5; made += 1) bundleOf(await exported(w.admin, denied.id));

    expect(await exported(w.admin, denied.id)).toEqual(refused(409, 'EVIDENCE_EXPORTS_SPENT'));
    expect(await downloadsOf(w)).toHaveLength(5);
  });

  it('refuses a request with more events than a bundle holds: EVIDENCE_TOO_LARGE, nothing written', async () => {
    const { w, acting } = await ready();
    const denied = await ask(acting, w, { amount: AED(w.maxPayment * 10n) });

    expect(await exported(w.admin, denied.id, undefined, evidenceWith({ mostEvents: 1 }))).toEqual(
      refused(409, 'EVIDENCE_TOO_LARGE'),
    );
    expect(await downloadsOf(w)).toEqual([]);
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
});
