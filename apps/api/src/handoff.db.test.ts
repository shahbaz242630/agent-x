// Phase 4 B4: the hand-off, on the real migrated schema as the app role
// (PRD §5.3, §6, §11; ADR-007 §6–§10, §14; BR-11–BR-14; partner decisions
// 1–3, S135; PL-46). An approved request is handed to the world's own fake
// partner once, after its authority is checked again: HANDED_OFF, one signed
// instruction naming the payee of the supplier's verified version in force,
// one transaction moved by the partner's answer (each of the fake's fils
// outcomes, decision 5), its holdings still held. A second run, or two at
// once, makes nothing more (SEC-DP-01). Paused by the platform, held for
// integrity, a stop chosen to pause, a frozen organisation or a payee not yet
// registered: it waits, then goes once the way is clear (SEC-AV-01). A stop
// chosen to cancel, or the payee changed, denies it now with its holdings
// freed (payee substitution, SEC-PAY-01); its key ended at once since its
// approval denies it (`AGENT_KEY_ENDED`, SEC-AG-12/13). A cancel holding the
// request is waited for, and wins (SEC-DP-12); a pause taken during Tx A is
// waited for, and holds it. Once handed off it is never voided (the in-flight
// rule). Failures are logged and the run goes on: the partner's unexpected
// error (UNKNOWN, never resent), an answer that can't be recorded (its
// transaction changed past the app: never logged as handed off), a request
// that can't be believed, a list that can't be read.
import { AGENT_KEYS, AGENTS } from '@agentx/core/modules/agents';
import { holdOrganisation, withSignedStates } from '@agentx/core/modules/audit';
import { instructionOfRequest, type InstructionsTables } from '@agentx/core/modules/instructions';
import { MANDATES } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import {
  changeHandoffPause,
  createPlatformChain,
  type PlatformControlsTables,
} from '@agentx/core/modules/platform-controls';
import { type FakeRail, RailUnavailable } from '@agentx/core/modules/providers';
import { cancelRequest, type PendingChoice, SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import {
  addVersion,
  confirmPayeeChange,
  nextVersionNumber,
  recordRegistered,
  registrationOf,
  stagePayeeChange,
  startRegistration,
  supplierOf,
  versionOf,
} from '@agentx/core/modules/suppliers';
import { TRANSACTIONS, transactionOf, type TransactionsTables } from '@agentx/core/modules/transactions';
import { createDatabase, type Database } from '@agentx/platform/db';
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
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff } from './handoff.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createRequestVoids } from './request-voids.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';
import { choiceDetails, SUSPENDS } from './suspensions.ts';

type Tables = SpendWorldTables & PlatformControlsTables & InstructionsTables & TransactionsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0xb4a0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xb4b0_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'handoff',
  registry: () => registry,
  decisions: () => decisions,
});
const { quiet, ask, statusOf, holdingsOf, signed, STOPS, mandateIdOf } = shared;

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The job over the world alone, paying through `rail` (the world's own fake unless given). */
const handoffOf = (w: World, rail: FakeRail = w.rail, list = () => Promise.resolve([w.org])) =>
  createHandoff({ list, database: app, rail, keys, ids, clock, logger: testLogger(capture) });

/** AED 500 and the fils that choose the fake's answer (decision 5): under the approval threshold, so APPROVED. */
const ALLOWED = (fils = 0n) => AED(50_000n + fils);

/** The platform's hand-off pause moved, as the operator's command moves it (B1). */
const pauseMoved = (paused: boolean) =>
  app
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused, reason: 'TEST-B4', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );

/** The partner's reference for the world's first supplier's payee. */
const payeeRefOf = (w: World) => `fake-beneficiary-${w.org.slice(-12)}`;

/**
 * The world's first supplier given a payee, as E2's registration and its
 * admin's confirmation would: a version made from a registration REGISTERED
 * for it, made current with its payee key, its cooling-off already over.
 */
async function payeeRegistered(w: World): Promise<void> {
  const supplierId = w.suppliers[0] ?? '';
  const key = { orgId: w.org, id: supplierId };
  const registrationId = ids.next();
  const versionId = ids.next();
  await signed(w, async (tx, states) => {
    await supplierOf(tx, states, key, 'change');
    await startRegistration(tx, states, {
      orgId: w.org,
      id: registrationId,
      supplierId,
      versionId,
      partner: 'fake',
      route: 'hosted',
      startedBy: w.admin.membershipId,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
  });
  const registration = await signed(w, async (tx, states) => {
    const found = await registrationOf(tx, states, { orgId: w.org, id: registrationId }, supplierId, 'change');
    if (found.outcome !== 'found') throw new Error(`no registration: ${found.outcome}`);
    return recordRegistered(tx, states, { orgId: w.org, id: registrationId }, found, {
      beneficiary: {
        organizationId: w.org,
        registrationId,
        beneficiaryRef: payeeRefOf(w),
        payeeIdentity: null,
        nameCheck: 'match',
        maskedName: 'G*** O***** S******* L**',
        hint: 'AE…6026',
        registeredAt: clock.now(),
      },
      payee: { key: `fake-payee-${'b'.repeat(32)}`, keyVersion: null },
      actor: OPERATOR,
    });
  });
  await signed(w, async (tx, states) => {
    const found = await supplierOf(tx, states, key, 'change');
    if (found.outcome !== 'found') throw new Error(`no supplier: ${found.outcome}`);
    const current = await versionOf(tx, states, { orgId: w.org, id: found.supplier.currentVersionId }, supplierId);
    if (current.outcome !== 'found') throw new Error(`no version: ${current.outcome}`);
    await addVersion(tx, states, keys, {
      orgId: w.org,
      id: versionId,
      supplierId,
      version: await nextVersionNumber(tx, w.org, supplierId),
      supplier: {
        displayName: 'Gulf Office Supplies LLC',
        contacts: { phone: '+971501234567', email: null, tradeLicence: null },
        source: { kind: 'registry', ref: 'DED-123456' },
      },
      enteredBy: w.admin.membershipId,
      enteredAt: clock.now(),
      actor: OPERATOR,
      of: found,
      follows: current.version,
      registration,
    });
    const made = await versionOf(tx, states, { orgId: w.org, id: versionId }, supplierId);
    if (made.outcome !== 'found') throw new Error(`no new version: ${made.outcome}`);
    const change = { version: made.version, registration, current: current.version };
    const staged = await stagePayeeChange(tx, states, key, found, change, { actor: OPERATOR });
    const restaged = await supplierOf(tx, states, key, 'change');
    if (restaged.outcome !== 'found') throw new Error(`no supplier: ${restaged.outcome}`);
    await confirmPayeeChange(tx, states, key, { supplier: staged, state: restaged.state }, change, {
      actor: OPERATOR,
      coolingOffUntil: new Date(clock.now().getTime() - 1),
    });
  });
}

/** A world whose first supplier has a payee, both verified, with a mandate in force and the agent's key. */
async function ready() {
  const w = await shared.world();
  await payeeRegistered(w);
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, { approvalThreshold: AED(100_000n) });
  return { w, acting: await shared.agentKey(w) };
}

/** The request's instruction, if one was made, and its transaction. */
async function paymentOf(w: World, requestId: string) {
  return withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const instruction = await instructionOfRequest(tx, states, { orgId: w.org, spendRequestId: requestId });
    if (instruction.outcome !== 'found') return { instruction: instruction.outcome };
    const rows = await tx
      .selectFrom('transactions.transactions')
      .select('id')
      .where('instruction_id', '=', instruction.instruction.id)
      .execute();
    const transaction = await transactionOf(tx, states, { orgId: w.org, id: rows[0]?.id ?? '' }, 'share');
    return {
      instruction: instruction.instruction,
      transactions: rows.length,
      transaction: transaction.outcome === 'found' ? transaction.transaction : transaction.outcome,
    };
  });
}

/** The world's rail, every submission counted. */
function counted(w: World): { rail: FakeRail; submitted: () => number } {
  let submitted = 0;
  return {
    rail: {
      ...w.rail,
      submitApprovedIntent: (intent) => {
        submitted += 1;
        return w.rail.submitApprovedIntent(intent);
      },
    },
    submitted: () => submitted,
  };
}

/** Suspends it with the choice (as its use case records one), or lifts it; past the use case. */
const stopped = (w: World, which: 'organization' | 'agent' | 'mandate', id: string, choice: PendingChoice | 'resume') =>
  signed(w, async (tx, states): Promise<unknown> => {
    const key = { orgId: w.org, id };
    const suspend = choice !== 'resume';
    const change = {
      actor: OPERATOR,
      action: suspend ? SUSPENDS[which].action : `${SUSPENDS[which].type}.resumed`,
      details: suspend ? choiceDetails(choice) : {},
    };
    if (which === 'organization') {
      return states.changeStatus(tx, ORGANIZATIONS, key, suspend ? 'freeze' : 'unfreeze', change);
    }
    if (which === 'agent') return states.changeStatus(tx, AGENTS, key, suspend ? 'suspend' : 'reactivate', change);
    return states.changeStatus(tx, MANDATES, key, suspend ? 'suspend' : 'resume', change);
  });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  // Born paused (ADR-014 §4): resumed for these tests, as the operator would once B4 is live.
  await pauseMoved(false);
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

describe('an approved request handed to the partner once (B4)', () => {
  it('hands it off: HANDED_OFF, one instruction with the verified payee, its transaction moved, its holdings held', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(), orderReference: 'INV-B4-1' });
    expect(request.status).toBe('APPROVED');

    await handoffOf(w).run();

    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'HELD', released: false });
    const payment = await paymentOf(w, request.id);
    expect(payment).toMatchObject({
      instruction: {
        spendRequestId: request.id,
        route: 'push',
        routeReason: 'mandate_source_push_rail',
        fundingSourceId: w.source,
        partner: 'fake',
        partnerLegalEntityId: 'FAKE-NOT-REGULATED',
        accountConsentId: w.state.accountConsentId,
        beneficiaryRef: payeeRefOf(w),
        amountMinor: 50_000n,
        currency: 'AED',
      },
      transactions: 1,
      // Pending at the partner at once (rail map §4).
      transaction: { status: 'PROCESSING', providerStatus: 'Pending', rejectCode: null },
    });
    const events = await shared.eventsAbout(w.org, request.id, SPEND_REQUESTS.subject);
    expect(events.slice(-2).map((event) => [event.action, event.actorType])).toEqual([
      ['spend_request.made_ready', 'system'],
      ['spend_request.handed_off', 'system'],
    ]);
    expect(lines('handoff.handed_off')).toEqual([
      expect.objectContaining({ requestId: request.id, answer: 'accepted' }),
    ]);
  });

  it.each([
    ['declined (.01): FAILED with the rail’s code', 1n, { status: 'FAILED', rejectCode: 'AANI.AM04' }],
    ['the answer lost (.02): UNKNOWN, never resent', 2n, { status: 'UNKNOWN', rejectCode: null }],
    ['the rail’s 409 (.03): UNKNOWN, never resent', 3n, { status: 'UNKNOWN', rejectCode: null }],
    ['rejected after the debit (.04): under way at first', 4n, { status: 'PROCESSING', rejectCode: null }],
  ] as const)('records the fake’s answer: %s', async (_name, fils, transaction) => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(fils) });
    const { rail, submitted } = counted(w);

    await handoffOf(w, rail).run();
    await handoffOf(w, rail).run();

    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    expect(await paymentOf(w, request.id)).toMatchObject({ transactions: 1, transaction });
    // Once, whatever it answered: an answer not known is never resent (ADR-007 §10).
    expect(submitted()).toBe(1);
    // Its holdings stay held until an outcome is proven (C3).
    expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'HELD', released: false });
  });

  it('makes one instruction and calls the partner once, though two runs go at once (SEC-DP-01)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const { rail, submitted } = counted(w);

    await Promise.all([handoffOf(w, rail).run(), handoffOf(w, rail).run(), handoffOf(w, rail).run()]);

    expect(await paymentOf(w, request.id)).toMatchObject({ transactions: 1 });
    expect(submitted()).toBe(1);
    expect(lines('handoff.failed')).toEqual([]);
  });

  it('leaves a request waiting for approval, and every one not approved, alone', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    expect(waiting.status).toBe('APPROVAL_REQUIRED');

    await handoffOf(w).run();

    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect(await paymentOf(w, waiting.id)).toEqual({ instruction: 'missing' });
  });

  it('stops between requests once the signal is aborted', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const stopping = new AbortController();
    stopping.abort();

    await handoffOf(w).run(stopping.signal);

    expect(await statusOf(w, request.id)).toBe('APPROVED');
  });
});

describe('the way not clear: the request waits, then goes once (SEC-AV-01, ADR-007 §14)', () => {
  it('waits while the platform is paused, and goes on resume', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await pauseMoved(true);
    try {
      await handoffOf(w).run();
      expect(await statusOf(w, request.id)).toBe('APPROVED');
      expect(lines('handoff.waiting')).toEqual([
        expect.objectContaining({ requestId: request.id, why: 'pause_paused' }),
      ]);
    } finally {
      await pauseMoved(false);
    }

    await handoffOf(w).run();

    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });

  it('waits for a pause taken during its Tx A, and holds the request (forced)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The operator's pause holds the row (level 1) until it commits.
    const pausing = app.transaction().execute(async (tx) => {
      await changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: true, reason: 'TEST-B4', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      );
      holding(undefined);
      await gate;
    });
    await held;
    try {
      const running = within(20_000, handoffOf(w).run(), 'the run');
      await waitUntilQueued(database.as('admin'), 1);
      open(undefined);
      await pausing;
      await running;

      expect(await statusOf(w, request.id)).toBe('APPROVED');
      expect(await paymentOf(w, request.id)).toEqual({ instruction: 'missing' });
    } finally {
      open(undefined);
      await pausing;
      await pauseMoved(false);
    }
  });

  it('waits while the organisation is on its integrity hold', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await holdOrganisation(app, w.org, quiet(), 'test');

    await handoffOf(w).run();

    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toEqual([expect.objectContaining({ requestId: request.id, why: 'hold_held' })]);
    expect(await paymentOf(w, request.id)).toEqual({ instruction: 'missing' });
  });

  it.each([
    ['the organisation frozen', 'organization', 'organization'],
    ['the agent suspended', 'agent', 'agent'],
    ['the mandate suspended', 'mandate', 'mandate'],
  ] as const)('waits while %s chosen to pause, and goes once lifted', async (_name, which, why) => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const id = { organization: w.org, agent: w.agent, mandate: await mandateIdOf(w) }[which];
    await stopped(w, which, id, 'pause');

    await handoffOf(w).run();
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toEqual([expect.objectContaining({ requestId: request.id, why })]);

    await stopped(w, which, id, 'resume');
    await handoffOf(w).run();
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });

  it('waits while the source is suspended by the partner', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await STOPS['the source suspended by the partner'](w);

    await handoffOf(w).run();

    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toEqual([expect.objectContaining({ requestId: request.id, why: 'source' })]);
  });

  it('waits for a supplier with no payee registered yet', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED(), supplierId: w.suppliers[1] ?? '' });

    await handoffOf(w).run();

    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toEqual([expect.objectContaining({ requestId: request.id, why: 'payee' })]);
  });
});

describe('authority withdrawn since the approval: denied now, its holdings freed (decision 3, PL-46)', () => {
  it.each([
    ['the mandate superseded', 'MANDATE_NOT_IN_FORCE'],
    ['the agent suspended', 'AGENT_SUSPENDED'],
    // Payee substitution (SEC-PAY-01): its details changed after the approval, never paid on the old decision.
    ['the supplier’s details changed', 'SUPPLIER_NOT_VERIFIED,SUPPLIER_CHANGED'],
  ] as const)('denies it once %s', async (what, causes) => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await STOPS[what](w, await mandateIdOf(w));
    const { rail, submitted } = counted(w);

    await handoffOf(w, rail).run();

    expect(await statusOf(w, request.id)).toBe('DENIED');
    expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'RELEASED', released: true });
    expect(await paymentOf(w, request.id)).toEqual({ instruction: 'missing' });
    expect(submitted()).toBe(0);
    expect(lines('handoff.denied')).toEqual([expect.objectContaining({ requestId: request.id, causes })]);
  });

  it('denies it once its agent key was ended at once (AGENT_KEY_ENDED, SEC-AG-12/13)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: { reason: 'test' },
      }),
    );

    await handoffOf(w).run();

    expect(await statusOf(w, request.id)).toBe('DENIED');
    expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'RELEASED', released: true });
    expect(await paymentOf(w, request.id)).toEqual({ instruction: 'missing' });
    const events = await shared.eventsAbout(w.org, request.id, SPEND_REQUESTS.subject);
    expect(events.at(-1)).toMatchObject({
      action: 'spend_request.voided',
      actorType: 'system',
      details: { statusTo: 'DENIED', causes: 'AGENT_KEY_ENDED' },
    });
  });

  it('waits for a cancel holding the request, and the cancel wins (forced, SEC-DP-12)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // As the agent's cancel would: the request (level 8) held, then ended.
    const cancelling = signed(w, async (tx, states) => {
      await tx
        .selectFrom('spend_requests.requests')
        .select('id')
        .where('id', '=', request.id)
        .forNoKeyUpdate()
        .execute();
      holding(undefined);
      await gate;
      return cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: request.id },
        { kind: 'user', userId: ids.next() },
        clock.now(),
      );
    });
    await held;
    const running = within(20_000, handoffOf(w).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    expect(await cancelling).toMatchObject({ outcome: 'ended' });
    await running;
    expect(await statusOf(w, request.id)).toBe('CANCELLED');
    expect(await paymentOf(w, request.id)).toEqual({ instruction: 'missing' });
    expect(lines('handoff.failed')).toEqual([]);
  });
});

describe('handed off, tracked to its outcome, never voided (the in-flight rule)', () => {
  it('leaves a handed-off request as it is when its mandate is stopped after', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    await stopped(w, 'mandate', await mandateIdOf(w), 'cancel');

    await createRequestVoids({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    }).run();
    await handoffOf(w).run();

    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    expect(await holdingsOf(w, request.id)).toEqual({ reservation: 'HELD', released: false });
    expect(await paymentOf(w, request.id)).toMatchObject({ transactions: 1 });
  });
});

describe('failures logged, the run going on', () => {
  it('marks an unexpected partner error UNKNOWN, never resent, and says so', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const rail: FakeRail = { ...w.rail, submitApprovedIntent: () => Promise.reject(new Error('socket hang up')) };

    await handoffOf(w, rail).run();

    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN' } });
    expect(lines('handoff.partner_failed')).toEqual([expect.objectContaining({ requestId: request.id })]);
  });

  it('marks the partner unreachable UNKNOWN quietly: no error, as its own adapter said why', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const rail: FakeRail = { ...w.rail, submitApprovedIntent: () => Promise.reject(new RailUnavailable()) };

    await handoffOf(w, rail).run();

    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN' } });
    expect(lines('handoff.partner_failed')).toEqual([]);
  });

  it('says the answer went unrecorded, never handed off, when the transaction can’t be believed (its alarm raised)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    // Its transaction changed past the app while the partner answers: Tx B can't believe it.
    const rail: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        const answer = await w.rail.submitApprovedIntent(intent);
        const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
        try {
          const [row] = await owner.query<{ id: string }>(
            'select id from transactions.transactions where instruction_id = $1',
            [intent.instructionId],
          );
          await owner.stripSeals(row?.id ?? '');
        } finally {
          await owner.end();
        }
        return answer;
      },
    };

    await handoffOf(w, rail).run();

    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    expect(lines('handoff.answer_unrecorded')).toEqual([expect.objectContaining({ requestId: request.id })]);
    expect(lines('handoff.handed_off')).toEqual([]);
    expect(lines('audit.integrity_failed').length).toBeGreaterThan(0);
  });

  it('hands nothing off for a request whose key can’t be believed, and goes on to the next', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w, { amount: ALLOWED() });
    const owner = await tamperAsOwner(database, AGENT_KEYS, w.org);
    try {
      await owner.stripSeals(acting.keyId);
    } finally {
      await owner.end();
    }
    const other = await ready();
    const second = await ask(other.acting, other.w, { amount: ALLOWED() });

    await handoffOf(w, w.rail, () => Promise.resolve([w.org, other.w.org])).run();

    expect(await statusOf(w, first.id)).toBe('APPROVED');
    expect(lines('handoff.failed')).toEqual([expect.objectContaining({ requestId: first.id })]);
    // The other organisation's goes, through its own partner's consent... which only its own fake holds.
    expect(await statusOf(other.w, second.id)).toBe('HANDED_OFF');
  });

  it('says so when the organisations can’t be listed, and hands nothing off', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });

    await handoffOf(w, w.rail, () => Promise.reject(new Error('directory down'))).run();

    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.run_failed')).toHaveLength(1);
  });

  it('says so when an organisation’s requests can’t be read, and goes on to the next', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });

    await handoffOf(w, w.rail, () => Promise.resolve(['not-an-organisation', w.org])).run();

    expect(lines('handoff.failed')).toHaveLength(1);
    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
  });
});
