// Phase 6 C2a: a spend request's evidence, downloaded by an admin, against
// Postgres on the real migrated schema as the app role (BR-16, PRD §8): the
// download recorded on the organisation's chain before a byte is read; the
// bundle of a request allowed and paid, one denied, one rejected, each with
// every signed event about it and its objects, their chain links and actors
// named, a retry answering the same; never a secret or a seal (SEC-EVD-04);
// another organisation's request NOT_FOUND with nothing written; a member not
// an admin FORBIDDEN; and a record that can't be believed refusing the bundle,
// 503 INTEGRITY_FAILED, the organisation held.
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { EVIDENCE_EXPORTED, EVIDENCE_SUBJECT } from '@agentx/core/modules/evidence';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { INSTRUCTIONS, type InstructionRecord } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { SPEND_REQUESTS, voidPendingOf } from '@agentx/core/modules/spend-requests';
import { SOURCES } from '@agentx/core/modules/funding-sources';
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

const exported = (who: Member, requestId: string, key?: string) =>
  evidence.export(who, keyed(who, EVIDENCE_OPERATION, key), requestId, CORRELATION);

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

/** A record's column changed by its table's owner with its guards off: as only something past the app could. */
async function changedByOwner(
  w: World,
  target: typeof INSTRUCTIONS | typeof SOURCES | typeof SPEND_REQUESTS,
  id: string,
  [column, value]: readonly [string, string | number],
) {
  const owner = await tamperAsOwner(database, target, w.org);
  // One transaction, so each table's guards are off for this change alone; each by its fixed text (SEC-TEN-07).
  const guards = async (on: boolean) => {
    if (target === INSTRUCTIONS && on) await owner.query('alter table instructions.instructions enable trigger user');
    if (target === INSTRUCTIONS && !on) await owner.query('alter table instructions.instructions disable trigger user');
    if (target === SOURCES && on) await owner.query('alter table funding_sources.sources enable trigger user');
    if (target === SOURCES && !on) await owner.query('alter table funding_sources.sources disable trigger user');
    if (target === SPEND_REQUESTS && on) await owner.query('alter table spend_requests.requests enable trigger user');
    if (target === SPEND_REQUESTS && !on) await owner.query('alter table spend_requests.requests disable trigger user');
  };
  try {
    await owner.query('begin');
    await guards(false);
    await owner.setColumn(id, column, value);
    await guards(true);
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
  instruction.partnerLegalEntityId,
  instruction.partnerLicenceRef,
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
  evidence = createSpendRequestEvidence({ database: app, keys, ids, logger, directory: undefined });
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
  ] as const)(
    'refuses a bundle when %s can’t be believed: INTEGRITY_FAILED, the organisation held',
    async (_what, which) => {
      const { w, request } = await paid();
      if (which === 'request') await changedByOwner(w, SPEND_REQUESTS, request.id, ['amount_minor', 1]);
      if (which === 'source') await changedByOwner(w, SOURCES, w.source, ['consent_status', 'Revoked']);
      if (which === 'agent') {
        await withTenant(app, w.org, (tx) =>
          tx.updateTable('agents.agents').set({ scopes: 'requests:read' }).where('id', '=', w.agent).execute(),
        );
      }

      expect(await exported(w.admin, request.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
      expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
    },
  );

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

  it('refuses a bundle when its reservation was changed past the app: INTEGRITY_FAILED, the organisation held', async () => {
    const { w, request } = await paid();
    await changedPastTheApp(database, w.org, request.id, 'amount halved');

    expect(await exported(w.admin, request.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await heldOf(w)).toMatchObject({ outcome: 'held' });
  });
});
