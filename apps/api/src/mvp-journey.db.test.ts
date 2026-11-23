// S212 G1, the Phase 6 gate's first fix: the BRD §7 MVP acceptance criteria,
// 1 to 10 in order, for one organisation, through the real routes on the
// real migrated schema as the app role (the INJ+DB pattern): every use case
// the API builds, on one test clock, with the fake partner over its own
// records in the app's database, as staging runs it. Taken past HTTP, each
// commented where it happens: the organisation and its cap made as sign-up
// would (no route makes one yet), sessions and the step-up's sign-in (the
// login service's return), the hand-off and bank-check jobs (no route by
// design: the API's job role), and admin reads of the partner-side IDs and the
// inbox (what the partner knows and our API never gives out).
//
// 1 a bank account linked through the partner's flow; 2 an agent registered
// (suspended at the end); 3 a supplier made payable to a partner-issued
// payee, cooled off and verified; 4 a mandate drafted, accepted with a
// passkey and revoked at the end; 5 the agent's AED request, sent with its
// own key, waiting for approval with its reasons; 6 approved with a passkey,
// nothing material changed; 7 handed off to the partner (the job); 8 the
// partner's message through its front door and the bank's outcome read on
// the payment's timeline; 9 a settled payment and an unknown one on the
// exception list; 10 the request's evidence exported whole. Then a duplicate
// order refused and a denial with its reason, its evidence exported too.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createAgentKeyCheck } from '@agentx/core/modules/agents';
import {
  createSessions,
  createStepUpChallenges,
  type LiveSession,
  membershipFor,
  type SignIn,
} from '@agentx/core/modules/identity';
import { setPolicy } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createOrganization } from '@agentx/core/modules/organizations';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { createProviderEvents } from '@agentx/core/modules/provider-events';
import { createDatabaseRecords, createFakeRail, type FakeRail, SANDBOX_ACCOUNTS } from '@agentx/core/modules/providers';
import { PAYEE_COOLING_OFF_MS } from '@agentx/core/modules/suppliers';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createTestDatabase, FixedClock, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { createAgentChanges } from './agent-changes.ts';
import { createAgentRegistrations } from './agent-registering.ts';
import type { ApiTables } from './boot.ts';
import { createFundingSourceLinks } from './funding-source-links.ts';
import { createHandoff, handoffDatabaseGate } from './handoff.ts';
import { createMandateAcceptance } from './mandate-acceptance.ts';
import { createMandateMoves } from './mandate-moves.ts';
import { createMandateRegistry } from './mandate-registry.ts';
import { keys, mandateWorld, type Member, OPERATOR } from './mandate-world.helper.test.ts';
import { capChoiceDetails, SUGGESTED_MONTHLY_CAP_MINOR } from './monthly-cap-choice.ts';
import { createPartnerEventIntake, PARTNER_EVENTS_PATH } from './partner-events.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { createPaymentReads } from './payment-reads.ts';
import { createRailHealth } from './rail-health.ts';
import { closeServers, COOKIE, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { createSpendRequestApprovals } from './spend-request-approvals.ts';
import { createSpendRequestDecisions } from './spend-request-decisions.ts';
import { createSpendRequestEvidence } from './spend-request-evidence.ts';
import { createSpendRequestReads } from './spend-request-reads.ts';
import { worded } from './statement-words.helper.test.ts';
import { createSupplierPayeeChanges } from './supplier-payee-changes.ts';
import { createSupplierPayees } from './supplier-payees.ts';
import { createSupplierRegistry } from './supplier-registry.ts';
import { createSupplierVerifications } from './supplier-verifications.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<ApiTables>;
/** The operator's own role (PL-57): only it lifts the hand-off pause every database is born with. */
let operator: Database<ApiTables>;

const ids = new SequentialIds(0x5212_0001_0000);
let clock: FixedClock;
let rail: FakeRail;
let api: FastifyInstance;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'mvp-journey' });

/** Well past the journey's own run on a busy machine. */
const LONG = 180_000;
/** A step of the fake's payment: settled at the debtor a minute on, its answer final after two (B2). */
const STEP = 60_000;
/** The fils that make the fake reject a payment with no proof the money stayed: UNKNOWN (rail map §4). */
const REJECTED_UNPROVEN = 4;
/** The fake bank's account the organisation pays from, and the sandbox business its supplier is paid as. */
const PAYING_ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const PAYEE = SANDBOX_ACCOUNTS.find((account) => account.AccountHolderName === 'Meridian Auto Spares LLC');
const PAYEE_NAME = PAYEE?.AccountHolderName ?? '';
const PAYEE_IBAN = PAYEE?.AccountIdentifiers.find((each) => each.SchemeName === 'IBAN')?.Identification ?? '';
/** Above it a person approves: AED 1,000. */
const THRESHOLD_MINOR = 100_000;
/** The most one order may be, AED 10,000: within the bank's consent and the organisation's monthly cap. */
const PER_ORDER_MINOR = 1_000_000;

/** The signed-in admin, as their console session stands: a fresh one replaces it after a long move of the clock. */
let admin: Member;
let org: string;

const liveOf = (who: Member): LiveSession => ({
  sessionId: who.sessionId,
  userId: who.userId,
  idpSessionId: 'V1_1',
  authTime: clock.now(),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: clock.now(),
  lastSeenAt: clock.now(),
  endsAt: new Date(clock.now().getTime() + 3_600_000),
  idleEndsAt: new Date(clock.now().getTime() + 1_800_000),
});

/** The console's sign-in: COOKIE is the admin's session as it now stands; the login service itself is never called. */
const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in this test')),
  beginStepUp: () => Promise.reject(new Error('not in this test')),
  complete: () => Promise.reject(new Error('not in this test')),
  signOut: () => Promise.resolve(undefined),
  holderOf: (cookie) => Promise.resolve(cookie === COOKIE ? admin.userId : undefined),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? liveOf(admin) : undefined),
};

const services = () => {
  const logger = testLogger();
  return {
    database: app,
    keys,
    ids,
    clock,
    logger,
    challenges: createStepUpChallenges({ ids, clock, keys, logger }),
    outbox: createOutbox({ ids, clock, keys }),
  };
};

const providerEvents = () => createProviderEvents({ keys, ids, clock, logger: testLogger(), retentionDays: 30 });

/** The API as start-web.ts builds it for these routes, every use case on the test's clock and the fake partner. */
async function apiServer(): Promise<FastifyInstance> {
  const all = services();
  const keyCheck = createAgentKeyCheck({ database: app, keys, ids, clock, logger: all.logger });
  return routeServer({
    signIn: { service: SIGN_IN, sessionSeconds: 43_200 },
    findMembership: (orgId, userId) => membershipFor(app, { keys, ids, logger: all.logger }, orgId, userId),
    checkAgentKey: keyCheck.check.bind(keyCheck),
    fundingSourceLinks: createFundingSourceLinks({ ...all, rail, partner: 'fake' }),
    fakeBank: rail.bank,
    agentRegistrations: createAgentRegistrations(all),
    agentChanges: createAgentChanges(all),
    supplierRegistry: createSupplierRegistry(all),
    supplierPayees: createSupplierPayees({ ...all, rail, partner: 'fake' }),
    supplierPayeeChanges: createSupplierPayeeChanges(all),
    supplierVerifications: createSupplierVerifications(all),
    mandateRegistry: createMandateRegistry(all),
    mandateAcceptance: createMandateAcceptance(all),
    mandateMoves: createMandateMoves(all),
    spendRequestDecisions: createSpendRequestDecisions(all),
    spendRequestReads: createSpendRequestReads(all),
    spendRequestApprovals: createSpendRequestApprovals(all),
    spendRequestEvidence: createSpendRequestEvidence({ ...all, directory: undefined }),
    paymentReads: createPaymentReads(all),
    partnerEvents: createPartnerEventIntake({
      database: app,
      rail,
      events: providerEvents(),
      securityEvents: { note: () => undefined },
      clock,
    }),
  });
}

/** The jobs' own settings, as job-list.ts runs them, over the one organisation. */
const jobParts = () => ({
  list: () => Promise.resolve([org]),
  database: app,
  outbox: createOutbox({ ids, clock, keys }),
  rail,
  keys,
  ids,
  clock,
  logger: testLogger(),
  health: createRailHealth({ clock, logger: testLogger() }),
  databaseGate: handoffDatabaseGate(6),
});

let keysUsed = 0;
/** A fresh idempotency key for each write. */
const nextKey = (): string => {
  keysUsed += 1;
  return `mvp-${String(keysUsed)}`;
};

/** A request as the admin's browser sends it: a write from our own origin with a fresh key and its words' versions. */
function asAdmin(method: 'GET' | 'POST', url: string, body: object = {}): Promise<LightMyRequestResponse> {
  const request: InjectOptions = {
    method,
    url,
    headers: {
      cookie: `${SESSION_COOKIE}=${COOKIE}`,
      [ORGANIZATION_HEADER]: org,
      ...(method === 'POST' && { origin: PUBLIC_ORIGIN, 'idempotency-key': nextKey() }),
    },
    ...(method === 'POST' && { payload: worded(url, body) as object }),
  };
  return api.inject(request);
}

/** The answer, once its status is the one expected (its body shown when it isn't). */
function answered(response: LightMyRequestResponse, status: number): LightMyRequestResponse {
  expect(response.statusCode, response.body).toBe(status);
  return response;
}

/** A change asked, the admin's passkey given for its step-up, then confirmed: the confirm's answer. */
async function steppedUp(url: string, body: object, confirmUrl: string, confirmBody: object = body) {
  const { stepUpChallengeId } = answered(await asAdmin('POST', url, body), 202).json<{ stepUpChallengeId: string }>();
  // The login service's return, as the step-up's callback records it: the one sign-in no route here can stand in for.
  await shared.stepUp(admin, stepUpChallengeId);
  return asAdmin('POST', confirmUrl, { ...confirmBody, stepUpChallengeId });
}

/** The agent's request with its own key, as its SDK sends it. */
const askAs = (agentKey: string, body: object) =>
  api.inject({
    method: 'POST',
    url: '/v1/spend-requests',
    headers: { authorization: `Bearer ${agentKey}`, 'idempotency-key': nextKey() },
    payload: body,
  });

interface Decided {
  readonly id: string;
  readonly status: string;
  readonly decision: string;
  readonly reasons: readonly { readonly code: string }[];
  readonly amountMinor: number;
  readonly supplierId: string;
  readonly orderReference: string;
}

const codesOf = (decided: Pick<Decided, 'reasons'>) => decided.reasons.map(({ code }) => code);

/** The admin signed in afresh with a passkey: the console's session after the clock has moved past their last. */
async function signedInAfresh(): Promise<void> {
  const sessions = createSessions({
    ids,
    clock,
    timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
    keys,
    logger: testLogger(),
  });
  const { sessionId } = await sessions.open(app, admin.userId, {
    idpSessionId: 'V1_3',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
  });
  admin = { ...admin, sessionId };
}

/**
 * The organisation as sign-up leaves it, made past the routes (no route makes one before Phase 6's sign-up): its
 * admin, signed in with a passkey, and its monthly cap chosen, AED 20,000, as its admin's policy change records it
 * (E2: no agent spends until it is).
 */
async function signedUp(): Promise<void> {
  org = ids.next();
  await withSignedStates(app, org, shared.quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  admin = await shared.signedInMember(org, 'admin');
  await withSignedStates(app, org, shared.quiet(), (tx, states) =>
    setPolicy(tx, states, {
      orgId: org,
      existing: null,
      scope: 'organization',
      mandateId: null,
      versionId: ids.next(),
      rules: {
        currency: 'AED',
        perOrderCap: null,
        monthlyCap: { minor: BigInt(SUGGESTED_MONTHLY_CAP_MINOR), currency: 'AED' },
        approvalThreshold: null,
        supplierIds: null,
      },
      madeBy: admin.membershipId,
      madeAt: clock.now(),
      actor: { type: 'user', id: admin.userId },
      details: capChoiceDetails('amount'),
    }),
  );
}

/** Criterion 1: the organisation's bank account linked through the partner's flow, its source ACTIVE. Its source, and its per-payment consent. */
async function linkedSource(): Promise<{ sourceId: string; maxPaymentMinor: number }> {
  const started = answered(await asAdmin('POST', '/v1/funding-sources/link-sessions'), 201).json<{
    link: { id: string; status: string };
    authoriseUrl: string;
  }>();
  expect(started.link.status).toBe('open');
  const sessionRef = started.authoriseUrl.slice(started.authoriseUrl.lastIndexOf('/') + 1);
  // The admin at their bank: the account chosen from those it holds, and the consent approved.
  const { accounts } = answered(await asAdmin('GET', '/v1/fake-bank/accounts'), 200).json<{
    accounts: { accountId: string }[];
  }>();
  expect(accounts.map(({ accountId }) => accountId)).toContain(PAYING_ACCOUNT);
  answered(await asAdmin('POST', `/v1/fake-bank/sessions/${sessionRef}/approve`, { accountId: PAYING_ACCOUNT }), 200);
  const confirmed = answered(
    await asAdmin('POST', `/v1/funding-sources/link-sessions/${started.link.id}/confirm`, {
      consentExpiry: 'cancel',
    }),
    200,
  ).json<{
    link: { status: string; sourceId: string };
    source: { id: string; status: string; controls: { maxPaymentMinor: string } };
  }>();
  expect(confirmed.link).toMatchObject({ status: 'linked', sourceId: confirmed.source.id });
  expect(confirmed.source.status).toBe('ACTIVE');
  return { sourceId: confirmed.source.id, maxPaymentMinor: Number(confirmed.source.controls.maxPaymentMinor) };
}

/** Criterion 2: an agent registered by the admin with a passkey, ACTIVE. Its ID and its first key, shown once. */
async function registeredAgent(name: string): Promise<{ agentId: string; agentKey: string }> {
  const asked = { name, scopes: ['requests:write', 'requests:read'] };
  const registered = answered(await steppedUp('/v1/agents', asked, '/v1/agents/confirm'), 201).json<{
    agent: { id: string; status: string };
    key: string;
  }>();
  expect(registered.agent.status).toBe('ACTIVE');
  expect(registered.key).toMatch(/^axk_/);
  return { agentId: registered.agent.id, agentKey: registered.key };
}

/**
 * Criterion 3, its first half: a supplier added UNVERIFIED, its bank details entered on the partner's own form with
 * the holder's own name, the partner's beneficiary reference checked REGISTERED, and the payee confirmed with the
 * admin's passkey: its 24 h cooling-off begun.
 */
async function supplierWithPayee(): Promise<string> {
  const added = answered(
    await asAdmin('POST', '/v1/suppliers', {
      displayName: PAYEE_NAME,
      phone: '+971501234567',
      source: { kind: 'registry', ref: 'DED-123456' },
      remittanceEmail: 'on',
    }),
    201,
  ).json<{ id: string; status: string }>();
  expect(added.status).toBe('UNVERIFIED');
  const supplierId = added.id;
  const started = answered(
    await asAdmin('POST', `/v1/suppliers/${supplierId}/payee-registrations`, { pendingRequests: 'cancel' }),
    201,
  ).json<{ id: string; form: { url: string } }>();
  answered(
    await asAdmin('POST', '/v1/fake-bank/payee-forms', { url: started.form.url, name: PAYEE_NAME, iban: PAYEE_IBAN }),
    200,
  );
  const checked = answered(
    await asAdmin('POST', `/v1/suppliers/${supplierId}/payee-registrations/${started.id}/check`),
    200,
  ).json<{ status: string }>();
  expect(checked.status).toBe('REGISTERED');
  answered(
    await steppedUp(
      `/v1/suppliers/${supplierId}/payee-change/approve`,
      {},
      `/v1/suppliers/${supplierId}/payee-change/approve/confirm`,
    ),
    200,
  );
  return supplierId;
}

/** Criterion 3, its second half: past the cooling-off, the supplier verified by the admin with a passkey. */
async function verified(supplierId: string): Promise<void> {
  const callBack = {
    calledBack: true,
    note: 'Spoke to Sara in accounts on the number on file; she confirmed the details',
  };
  const supplier = answered(
    await steppedUp(`/v1/suppliers/${supplierId}/verify`, callBack, `/v1/suppliers/${supplierId}/verify/confirm`),
    200,
  ).json<{ status: string }>();
  expect(supplier.status).toBe('VERIFIED');
}

/** Criterion 4: a mandate drafted for the agent and accepted with the admin's passkey, ACTIVE. Its ID. */
async function mandateInForce(
  agentId: string,
  { sourceId, supplierId, maxPaymentMinor }: { sourceId: string; supplierId: string; maxPaymentMinor: number },
): Promise<string> {
  expect(PER_ORDER_MINOR).toBeLessThanOrEqual(maxPaymentMinor);
  const drafted = answered(
    await asAdmin('POST', '/v1/mandates', {
      agentId,
      timeZone: 'Asia/Dubai',
      splitWindowHours: 24,
      purpose: 'Office supplies',
      currency: 'AED',
      perOrderLimitMinor: PER_ORDER_MINOR,
      monthlyLimitMinor: SUGGESTED_MONTHLY_CAP_MINOR,
      approvalThresholdMinor: THRESHOLD_MINOR,
      supplierIds: [supplierId],
      fundingSourceId: sourceId,
      splitCheck: true,
      consentLimits: 'strict',
      endsAt: null,
      overLimit: 'refuse',
    }),
    201,
  ).json<{ id: string; status: string; pending: { id: string } }>();
  const accepted = answered(
    await steppedUp(
      `/v1/mandates/${drafted.id}/accept`,
      { versionId: drafted.pending.id },
      `/v1/mandates/${drafted.id}/accept/confirm`,
      {},
    ),
    200,
  ).json<{ status: string; current: { id: string } }>();
  expect(accepted).toMatchObject({ status: 'ACTIVE', current: { id: drafted.pending.id } });
  return drafted.id;
}

/** Criteria 1 to 4 for a newly signed-up organisation: everything an agent needs to ask, in force. */
async function readyToSpend(agentName: string) {
  await signedUp();
  const source = await linkedSource();
  const agent = await registeredAgent(agentName);
  const supplierId = await supplierWithPayee();
  // Past the payee's cooling-off: the admin signs in afresh, their session having idled out on the clock.
  clock.advanceBy(PAYEE_COOLING_OFF_MS + STEP);
  await signedInAfresh();
  await verified(supplierId);
  const mandateId = await mandateInForce(agent.agentId, { ...source, supplierId });
  return { ...source, ...agent, supplierId, mandateId };
}

/** A request's body as its agent writes it: AED to the supplier, from the source. */
const askingFor = (
  { supplierId, sourceId }: { supplierId: string; sourceId: string },
  amountMinor: number,
  orderReference: string,
) => ({
  amountMinor,
  currency: 'AED',
  supplierId,
  fundingSourceId: sourceId,
  orderReference,
  purpose: 'Printer paper',
});

/** Criterion 6: the request approved with the admin's passkey, as the agent asked it. */
const approved = (requestId: string) =>
  steppedUp(`/v1/spend-requests/${requestId}/approve`, {}, `/v1/spend-requests/${requestId}/approve/confirm`);

/** The organisation's payments, as the team's list shows them. */
const paymentsListed = async () =>
  answered(await asAdmin('GET', '/v1/payments'), 200).json<{
    payments: { id: string; spendRequestId: string; status: string }[];
  }>().payments;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<ApiTables>({ ...database.connection('app'), maxConnections: 8 }, testLogger());
  operator = createDatabase<ApiTables>({ ...database.connection('operator'), maxConnections: 2 }, testLogger());
  // Born paused (ADR-014 §4): resumed for the journey's payments, as the operator would.
  await operator.transaction().execute((tx) =>
    changeHandoffPause(
      tx,
      { chain: createPlatformChain({ keys, ids: new SequentialIds(0x5212_0002_0000) }), keys, logger: testLogger() },
      {
        paused: false,
        reason: 'TEST-S212-G1',
        actor: { type: 'system', id: 'operator' },
        release: 'r-test',
        run: null,
      },
    ),
  );
});

afterAll(async () => {
  await app.destroy();
  await operator.destroy();
  await database.drop();
});

afterEach(closeServers);

/** Each test's own clock from the database's now (its sealed times are Postgres's), its partner and its API on it. */
async function started(): Promise<void> {
  clock = new FixedClock(new Date());
  rail = createFakeRail({ clock, ids, records: createDatabaseRecords(app) });
  api = await apiServer();
}

describe(`BR-01..BR-17 SEC-HA-12 SEC-PAY-04 SEC-PTR-02 G1 the MVP journey over HTTP (BRD §7 1-10, Postgres ${server.version})`, () => {
  it(
    'links, registers, verifies, mandates, asks, approves, hands off, settles, reconciles and exports; then revokes and suspends',
    async () => {
      await started();
      // Criteria 1-4.
      const ready = await readyToSpend('Purchasing agent');

      // Criterion 5: the agent asks with its own key; above the threshold, it waits for a person, with its reasons.
      const asked = askingFor(ready, 200_000, 'INV-2026-0042');
      const waiting = answered(await askAs(ready.agentKey, asked), 201).json<Decided & { mandateId: string }>();
      expect(waiting).toMatchObject({
        status: 'APPROVAL_REQUIRED',
        decision: 'REQUIRE_APPROVAL',
        mandateId: ready.mandateId,
      });
      expect(codesOf(waiting)).toContain('APPROVAL_THRESHOLD');
      const queue = answered(await asAdmin('GET', '/v1/approvals'), 200).json<{ waiting: { id: string }[] }>();
      expect(queue.waiting.map(({ id }) => id)).toEqual([waiting.id]);

      // Criterion 6: approved with a passkey, nothing material changed.
      const decided = answered(await approved(waiting.id), 200).json<Decided>();
      expect(decided).toMatchObject({
        id: waiting.id,
        status: 'APPROVED',
        amountMinor: asked.amountMinor,
        supplierId: ready.supplierId,
        orderReference: asked.orderReference,
      });

      // A second order, AED 200.04: its fils make the fake partner lose track of it (criterion 9's exception). Together
      // with the first it passes the threshold in the split window, so it too waits for a person.
      const unproven = answered(
        await askAs(ready.agentKey, askingFor(ready, 20_000 + REJECTED_UNPROVEN, 'INV-2026-0043')),
        201,
      ).json<Decided>();
      expect(unproven).toMatchObject({ status: 'APPROVAL_REQUIRED', decision: 'REQUIRE_APPROVAL' });
      answered(await approved(unproven.id), 200);

      // Criterion 7: the approved payment intents handed off to the partner. No route: the hand-off is the API job
      // role's own (job-list.ts), so it runs here as that job runs it.
      await createHandoff(jobParts()).run();
      const handedOff = await paymentsListed();
      const paid = handedOff.find(({ spendRequestId }) => spendRequestId === waiting.id);
      const lost = handedOff.find(({ spendRequestId }) => spendRequestId === unproven.id);
      expect(paid).toBeDefined();
      expect(lost).toBeDefined();

      // Criterion 8: past the fake's two steps, its message about the payment comes through its front door, signed
      // as it signs one. The message names the partner's own consent and our instruction, which the partner holds
      // (read here from the directory, as the partner has no route that gives them).
      clock.advanceBy(2 * STEP + 1000);
      const [named] = await database
        .as('admin')
        .query<{ instruction_id: string; account_consent_id: string }>(
          'select i.instruction_id, i.account_consent_id from directory.instructions i join instructions.instructions n on n.id = i.instruction_id where i.org_id = $1 and n.spend_request_id = $2',
          [org, waiting.id],
        );
      if (named === undefined) throw new Error('no instruction was handed off for the request');
      const message = await rail.bank.signEvent({
        eventType: 'payment.status',
        consentId: named.account_consent_id,
        instructionId: named.instruction_id,
      });
      const front = await api.inject({
        method: 'POST',
        url: PARTNER_EVENTS_PATH,
        payload: message.body,
        headers: message.headers,
        remoteAddress: '203.0.113.7',
      });
      expect(front.statusCode, front.body).toBe(202);
      // The message's own word never moves a payment (SEC-PTR-02): the bank check takes it from the inbox and asks
      // the bank. Also no route, as the hand-off: the job role's own.
      await createPaymentChecks({ ...jobParts(), events: providerEvents() }).run();
      const inbox = await database
        .as('admin')
        .query<{ taken: boolean }>(
          'select taken_at is not null as taken from provider_events.inbox where org_id = $1',
          [org],
        );
      expect(inbox).toEqual([{ taken: true }]);
      const settled = answered(await asAdmin('GET', `/v1/payments/${paid?.id ?? ''}`), 200).json<{
        status: string;
        timeline: { what: string; status: string | null }[];
      }>();
      expect(settled.status).toBe('SUCCEEDED');
      const moves = settled.timeline.map(({ what, status }) => [what, status]);
      // The hand-off first, the partner's settled outcome last.
      expect(moves[0]).toEqual(['instruction.made', null]);
      expect(moves.filter(([, status]) => status !== null)).toEqual([
        ['transaction.opened', 'SUBMISSION_PENDING'],
        ['transaction.submitted', 'SUBMITTED'],
        ['transaction.processing', 'PROCESSING'],
        ['transaction.succeed', 'SUCCEEDED'],
      ]);
      // The partner's own word on it, kept as the bank check heard it.
      expect(moves.filter(([what]) => what === 'transaction.provider_noted').length).toBeGreaterThan(0);

      // Criterion 9: reconciled, the settled one is no exception and the lost one is, UNKNOWN, on the team's list.
      const exceptions = answered(await asAdmin('GET', '/v1/payments/exceptions'), 200).json<{
        payments: { id: string; status: string }[];
      }>();
      expect(exceptions.payments.map(({ id, status }) => [id, status])).toEqual([[lost?.id, 'UNKNOWN']]);
      const unknown = answered(await asAdmin('GET', `/v1/payments/${lost?.id ?? ''}`), 200).json<{
        status: string;
        markFailed: unknown;
      }>();
      expect(unknown.status).toBe('UNKNOWN');
      expect(unknown.markFailed).not.toBeNull();

      // Criterion 10: the request's evidence exported whole: what was asked and decided, the person's approval, and
      // the partner's evidence of the payment.
      const { evidence } = answered(
        await asAdmin('POST', `/v1/spend-requests/${waiting.id}/evidence-exports`),
        201,
      ).json<{
        evidence: {
          spendRequest: { id: string; decision: string; reasons: { code: string }[]; amountMinor: number };
          payment: { id: string; status: string; partnerReference: string | null; instruction: { partner: string } };
          events: { action: string }[];
        };
      }>();
      expect(evidence.spendRequest).toMatchObject({
        id: waiting.id,
        decision: 'REQUIRE_APPROVAL',
        amountMinor: asked.amountMinor,
      });
      expect(codesOf(evidence.spendRequest)).toContain('APPROVAL_THRESHOLD');
      expect(evidence.payment).toMatchObject({ id: paid?.id, status: 'SUCCEEDED', instruction: { partner: 'fake' } });
      expect(evidence.payment.partnerReference).not.toBeNull();
      const actions = evidence.events.map(({ action }) => action);
      expect(actions).toEqual(expect.arrayContaining(['spend_request.approved', 'spend_request.evidence_exported']));
      const read = answered(await asAdmin('GET', `/v1/spend-requests/${waiting.id}/evidence`), 200).json<{
        evidence: { spendRequest: { id: string } };
      }>();
      expect(read.evidence.spendRequest.id).toBe(waiting.id);

      // Criteria 4 and 2, their ends: the mandate revoked with a passkey, and a new request is refused for it.
      const revoked = answered(
        await steppedUp(`/v1/mandates/${ready.mandateId}/revoke`, {}, `/v1/mandates/${ready.mandateId}/revoke/confirm`),
        200,
      ).json<{ status: string }>();
      expect(revoked.status).toBe('REVOKED');
      const unmandated = answered(
        await askAs(ready.agentKey, askingFor(ready, 10_000, 'INV-2026-0044')),
        201,
      ).json<Decided>();
      expect(unmandated).toMatchObject({ status: 'DENIED', decision: 'DENY' });
      expect(codesOf(unmandated)).toEqual(['MANDATE_NOT_IN_FORCE']);
      // The agent suspended (the kill switch, no step-up): its key works no more.
      const suspended = answered(
        await asAdmin('POST', `/v1/agents/${ready.agentId}/suspend`, { pendingRequests: 'cancel' }),
        200,
      ).json<{ agent: { status: string } }>();
      expect(suspended.agent.status).toBe('SUSPENDED');
      const refused = await askAs(ready.agentKey, askingFor(ready, 10_000, 'INV-2026-0045'));
      expect(answered(refused, 401).json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });
    },
    LONG,
  );

  it(
    'refuses a duplicate order, denies one past its limit with its reason, and exports the denial’s evidence',
    async () => {
      await started();
      const ready = await readyToSpend('Second purchasing agent');
      const first = answered(await askAs(ready.agentKey, askingFor(ready, 50_000, 'INV-7')), 201).json<Decided>();
      expect(first).toMatchObject({ status: 'APPROVED', decision: 'ALLOW' });

      // The same order again, under a new idempotency key: denied, as one order is paid once.
      const again = answered(await askAs(ready.agentKey, askingFor(ready, 50_000, 'INV-7')), 201).json<Decided>();
      expect(again).toMatchObject({ status: 'DENIED', decision: 'DENY' });
      expect(codesOf(again)).toContain('DUPLICATE_ORDER_REFERENCE');

      // A fil past the mandate's per-order limit, which it refuses: denied with that reason.
      const tooMuch = answered(
        await askAs(ready.agentKey, askingFor(ready, PER_ORDER_MINOR + 1, 'INV-8')),
        201,
      ).json<Decided>();
      expect(tooMuch).toMatchObject({ status: 'DENIED', decision: 'REQUIRE_NEW_MANDATE' });
      // The agent is shown the refusal's own reasons alone (decision 11c); a person, every one.
      expect(codesOf(tooMuch)).toEqual(['MANDATE_ORDER_LIMIT']);

      const { evidence } = answered(
        await asAdmin('POST', `/v1/spend-requests/${tooMuch.id}/evidence-exports`),
        201,
      ).json<{
        evidence: { spendRequest: { id: string; decision: string; reasons: { code: string }[] }; payment: unknown };
      }>();
      expect(evidence.spendRequest).toMatchObject({ id: tooMuch.id, decision: 'REQUIRE_NEW_MANDATE' });
      expect(codesOf(evidence.spendRequest)).toContain('MANDATE_ORDER_LIMIT');
      expect(evidence.payment).toBeNull();
    },
    LONG,
  );
});
