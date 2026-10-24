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
// that can't be believed, a list that can't be read. Phase 4 D1 (PL-38):
// random batches handed off by runs racing each other, some runs dying
// before their answer is recorded, a sweep between: whatever order they go
// in, each request is sent once, makes one instruction and one transaction,
// and one left waiting is marked UNKNOWN, never sent again. Phase 4 C3:
// what it holds follows its payment (spent, blocked while unknown, given back
// after a proven failure), refused past the app (0060) and alarmed by the
// holdings check where it gets past.
import { AGENT_KEYS } from '@agentx/core/modules/agents';
import { holdOrganisation, withSignedStates } from '@agentx/core/modules/audit';
import { INSTRUCTIONS } from '@agentx/core/modules/instructions';
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { type FakeRail, type PaymentExecution, RailUnavailable } from '@agentx/core/modules/providers';
import { cancelRequest, SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import {
  REMITTANCE_SETTINGS,
  remittanceOf,
  setRemittance,
  SUPPLIER_VERSIONS,
  supplierOf,
} from '@agentx/core/modules/suppliers';
import { lockHoldingsOf, settleHoldings } from '@agentx/core/modules/outcomes';
import {
  moveTransaction,
  type ProviderFacts,
  type TransactionEvent,
  TRANSACTIONS,
  transactionOf,
} from '@agentx/core/modules/transactions';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import fc from 'fast-check';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff, HEARTBEAT_STALE_MS } from './handoff.ts';
import {
  ALLOWED,
  handoffWorld,
  type HandoffWorldTables,
  HOLDS_AFTER,
  payeeRefOf,
  SMALL,
} from './handoff-world.helper.test.ts';
import { heartbeatChecks } from './health.ts';
import { createHoldingsCheck } from './holdings-check.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import { createRemittances } from './remittances.ts';
import { createRequestVoids } from './request-voids.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

type Tables = HandoffWorldTables;

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
const { quiet, ask, statusOf, holdingsOf, spentOf, signed, moved, STOPS, mandateIdOf } = shared;
const { ready, paymentOf } = handoffWorld({
  app: () => app,
  clock: () => clock,
  ids,
  registry: () => registry,
  shared,
});

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The requests the world's admins were told were stopped before the bank (B4b, 0059), by their IDs. */
const stoppedToldOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        // A global table (0021): the world's own organisation's notices alone.
        .selectFrom('notifications.outbox')
        .select('about_id')
        .where('org_id', '=', w.org)
        .where('kind', '=', 'spend_request_stopped')
        .where('recipient_user_id', 'is', null)
        .orderBy('id')
        .execute()
    ).map(({ about_id }) => about_id),
  );

/** The job over the world alone, paying through `rail` (the world's own fake unless given). */
const handoffOf = (w: World, rail: FakeRail = w.rail, list = () => Promise.resolve([w.org])) =>
  createHandoff({
    list,
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
  });

/** The platform's hand-off pause moved in the caller's transaction, as the operator's command moves it (B1). */
const pauseIn = (tx: Parameters<typeof changeHandoffPause>[0], paused: boolean) =>
  changeHandoffPause(
    tx,
    { chain, keys, logger: testLogger() },
    { paused, reason: 'TEST-B4', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
  );

/** The platform's hand-off pause moved, in a transaction of its own. */
const pauseMoved = (paused: boolean) => app.transaction().execute((tx) => pauseIn(tx, paused));

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
    // Its holdings follow its payment (C3): released only after a proven refusal, blocked while unknown.
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER[transaction.status]);
  });

  it('makes one instruction and calls the partner once, though two runs reach the request at once (forced, SEC-DP-01)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const { rail, submitted } = counted(w);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The request (level 8) held, so both runs' Tx A queue on it, then go as one lets go.
    const holder = signed(w, async (tx) => {
      await tx
        .selectFrom('spend_requests.requests')
        .select('id')
        .where('id', '=', request.id)
        .forNoKeyUpdate()
        .execute();
      holding(undefined);
      await gate;
    });
    await held;
    const runs = within(20_000, Promise.all([handoffOf(w, rail).run(), handoffOf(w, rail).run()]), 'the runs');
    await waitUntilQueued(database.as('admin'), 2);
    open(undefined);
    await holder;
    await runs;

    expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
    expect(await paymentOf(w, request.id)).toMatchObject({ transactions: 1 });
    expect(submitted()).toBe(1);
    expect(lines('handoff.failed')).toEqual([]);
  });

  it('pages past requests left waiting, so a younger one still goes in the same run', async () => {
    const { w, acting } = await ready();
    // Older, to the supplier with no payee yet: it waits.
    const stuck = await ask(acting, w, { amount: ALLOWED(), supplierId: w.suppliers[1] ?? '' });
    const younger = await ask(acting, w, { amount: ALLOWED() });

    await createHandoff({
      list: () => Promise.resolve([w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: w.rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      page: 1,
    }).run();

    expect(await statusOf(w, stuck.id)).toBe('APPROVED');
    expect(await statusOf(w, younger.id)).toBe('HANDED_OFF');
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
      // Waiting is no stop: no one is told.
      expect(await stoppedToldOf(w)).toEqual([]);
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
      await pauseIn(tx, true);
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
    ['the supplier suspended', 'supplier', 'supplier'],
  ] as const)('waits while %s chosen to pause, and goes once lifted', async (_name, which, why) => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const mandateId = await mandateIdOf(w);
    await moved(w, mandateId, which, 'pause');

    await handoffOf(w).run();
    expect(await statusOf(w, request.id)).toBe('APPROVED');
    expect(lines('handoff.waiting')).toEqual([expect.objectContaining({ requestId: request.id, why })]);

    await moved(w, mandateId, which, 'resume');
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
    // Approved, then stopped before the bank: the admins told, with the denial (decision 3, B4b).
    expect(await stoppedToldOf(w)).toEqual([request.id]);
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
    expect(await stoppedToldOf(w)).toEqual([request.id]);
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
    await moved(w, await mandateIdOf(w), 'mandate', 'cancel');

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

/** An answer with nothing more to say than its move. */
const NO_ANSWER_FACTS = {
  providerStatus: null,
  paymentInstructionRef: null,
  rejectCode: null,
  providerChangedAt: null,
};

describe('an answer that never comes: UNKNOWN, never resent (B5; ADR-007 §8, §10)', () => {
  interface Limits {
    callTimeoutMs: number;
    unknownAfterMs: number;
  }

  /** The job with the given time limits, paying through `rail`. */
  const timed = (w: World, rail: FakeRail, limits: Limits) =>
    createHandoff({
      list: () => Promise.resolve([w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      ...limits,
    });

  /**
   * The request handed off by a run whose partner answers only when the test
   * lets it: its transaction left SUBMISSION_PENDING, as a run that died
   * between Tx A and Tx B would leave it. `answered` lets the answer come.
   */
  async function leftWaiting(w: World, requestId: string, limits: Limits) {
    const { promise: answer, resolve } = Promise.withResolvers<undefined>();
    const slow: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        await answer;
        return w.rail.submitApprovedIntent(intent);
      },
    };
    const first = timed(w, slow, limits).run();
    await expect
      .poll(async () => (await paymentOf(w, requestId)).transaction)
      .toMatchObject({ status: 'SUBMISSION_PENDING' });
    return {
      answered: async () => {
        resolve(undefined);
        await first;
      },
    };
  }

  it('marks UNKNOWN a transaction left waiting past its wait, never one within it; the late answer kept as facts', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    // The call's limit runs on real time, the wait on the test's clock: the answer is held back well within both.
    const limits = { callTimeoutMs: 20_000, unknownAfterMs: 60_000 };
    const { answered } = await leftWaiting(w, request.id, limits);

    // Within its wait: left be.
    await timed(w, w.rail, limits).run();
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'SUBMISSION_PENDING' } });
    expect(lines('handoff.marked_unknown')).toEqual([]);

    // Past it: UNKNOWN, said in plain words, never sent again.
    clock.advanceBy(60_001);
    await timed(w, w.rail, limits).run();
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN' } });
    expect(lines('handoff.marked_unknown')).toHaveLength(1);

    // The answer comes after all: kept as the transaction's facts, never a move, and not an error.
    await answered();
    expect(await paymentOf(w, request.id)).toMatchObject({
      transaction: { status: 'UNKNOWN', providerStatus: 'Pending' },
    });
    expect(lines('handoff.handed_off')).toEqual([
      expect.objectContaining({ requestId: request.id, answer: 'accepted', recorded: 'late' }),
    ]);
    expect(lines('handoff.answer_unrecorded')).toEqual([]);
  });

  it('settles FAILED a refusal that comes once the transaction was marked UNKNOWN: its code the proof (ADR-007 §11)', async () => {
    const { w, acting } = await ready();
    // .01 fils: the fake declines it.
    const request = await ask(acting, w, { amount: ALLOWED(1n) });
    const limits = { callTimeoutMs: 20_000, unknownAfterMs: 60_000 };
    const { answered } = await leftWaiting(w, request.id, limits);
    clock.advanceBy(60_001);
    await timed(w, w.rail, limits).run();
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN' } });

    await answered();
    expect(await paymentOf(w, request.id)).toMatchObject({
      transaction: { status: 'FAILED', rejectCode: 'AANI.AM04' },
    });
    expect(lines('handoff.handed_off')).toEqual([
      expect.objectContaining({ requestId: request.id, answer: 'refused', recorded: 'recorded' }),
    ]);
  });

  it('sweeps once a minute, not every run: few database calls', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const limits = { callTimeoutMs: 20_000, unknownAfterMs: 30_000 };
    const { answered } = await leftWaiting(w, request.id, limits);
    const job = timed(w, w.rail, limits);
    await job.run();

    // Past its wait, but the job swept under a minute ago: left for its next sweep.
    clock.advanceBy(30_001);
    await job.run();
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'SUBMISSION_PENDING' } });

    clock.advanceBy(30_000);
    await job.run();
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN' } });
    await answered();
  });

  it('leaves be a transaction its answer moved after the sweep listed it (forced)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const limits = { callTimeoutMs: 20_000, unknownAfterMs: 60_000 };
    const { answered } = await leftWaiting(w, request.id, limits);
    const waiting = await paymentOf(w, request.id);
    const key = { orgId: w.org, id: typeof waiting.transaction === 'object' ? waiting.transaction.id : '' };
    clock.advanceBy(60_001);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The transaction (level 10) held by an answer being recorded: the sweep lists it, then queues on it.
    const answering = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await transactionOf(tx, states, key, 'change');
      holding(undefined);
      await gate;
      await moveTransaction(tx, states, key, 'submitted', NO_ANSWER_FACTS, {
        actor: { type: 'system', id: 'api' },
        details: { via: 'test' },
      });
    });
    await held;
    const sweeping = within(20_000, timed(w, w.rail, limits).run(), 'the sweep');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await answering;
    await sweeping;

    // SUBMITTED may lose track too: only the sweep's own check leaves the answer be.
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'SUBMITTED' } });
    expect(lines('handoff.marked_unknown')).toEqual([]);
    expect(lines('handoff.sweep_failed')).toEqual([]);
    await answered();
  });

  it('sweeps nothing once stopped, so the process stops promptly', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const limits = { callTimeoutMs: 20_000, unknownAfterMs: 60_000 };
    const { answered } = await leftWaiting(w, request.id, limits);
    clock.advanceBy(60_001);
    const stopping = new AbortController();
    stopping.abort();

    await timed(w, w.rail, limits).run(stopping.signal);
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'SUBMISSION_PENDING' } });

    await timed(w, w.rail, limits).run();
    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN' } });
    await answered();
  });

  it('gives the partner its time limit: no answer by then is UNKNOWN, said in plain words', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const silent: FakeRail = { ...w.rail, submitApprovedIntent: () => new Promise(() => undefined) };

    await timed(w, silent, { callTimeoutMs: 50, unknownAfterMs: 60_000 }).run();

    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN' } });
    expect(lines('handoff.partner_timeout')).toEqual([expect.objectContaining({ requestId: request.id })]);
    expect(lines('handoff.partner_failed')).toEqual([]);
  });

  it('refuses to start with a wait no longer than the partner’s time limit (ADR-007 §10)', async () => {
    const { w } = await ready();

    expect(() => timed(w, w.rail, { callTimeoutMs: 60_000, unknownAfterMs: 60_000 })).toThrow(RangeError);
    expect(() => timed(w, w.rail, { callTimeoutMs: 60_000, unknownAfterMs: 60_001 })).not.toThrow();
  });

  it('beats from its start and with each run, for /health; past its limit with no run, it reads as stopped (ADR-013)', async () => {
    const { w } = await ready();
    const handoff = handoffOf(w);
    expect(handoff.beating()).toBe(true);
    clock.advanceBy(HEARTBEAT_STALE_MS + 1);
    expect(handoff.beating()).toBe(false);

    await handoff.run();
    expect(handoff.beating()).toBe(true);

    clock.advanceBy(HEARTBEAT_STALE_MS);
    expect(handoff.beating()).toBe(true);
    clock.advanceBy(1);
    expect(handoff.beating()).toBe(false);
  });

  it('gives /health its heartbeat, and nothing where there is no hand-off', async () => {
    const { w } = await ready();
    const handoff = handoffOf(w);
    await handoff.run();

    const [check, ...rest] = heartbeatChecks({ handoff });
    expect(check?.name).toBe('handoff_heartbeat');
    expect(rest).toEqual([]);
    expect(await check?.check()).toBe(true);
    clock.advanceBy(HEARTBEAT_STALE_MS + 1);
    expect(await check?.check()).toBe(false);
    expect(heartbeatChecks({ handoff: undefined })).toEqual([]);
  });

  it('never beats for a run that can’t read its organisations: one failing every time reads as stopped', async () => {
    const { w } = await ready();
    const failing = handoffOf(w, w.rail, () => Promise.reject(new Error('directory down')));
    clock.advanceBy(HEARTBEAT_STALE_MS + 1);

    await failing.run();

    expect(failing.beating()).toBe(false);
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

describe('the answer believed only about this payment, never undoing the bank’s word (gate H1; SEC-PTR-09)', () => {
  it.each([
    ['another organisation', (e: PaymentExecution) => ({ ...e, organizationId: ids.next() })],
    ['another instruction', (e: PaymentExecution) => ({ ...e, instructionId: ids.next() })],
    ['another amount', (e: PaymentExecution) => ({ ...e, amountMinor: e.amountMinor + 1n })],
    ['another currency', (e: PaymentExecution) => ({ ...e, currency: 'USD' })],
  ])('never counts as paid a credit about %s: UNKNOWN, its money held, no remittance, said', async (_, other) => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });

    await handoffOf(
      w,
      answeredAs(w, (e) => other(credited(e))),
    ).run();

    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'UNKNOWN', providerStatus: null } });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(await remittancesOf(w)).toEqual([]);
    expect(lines('handoff.unreadable')).toEqual([
      expect.objectContaining({ transactionId: await transactionIdOf(w, request.id), why: 'not_this_payment' }),
    ]);
  });

  it('leaves a payment the bank check found under way as it found it, when a refusal comes late: said, never FAILED', async () => {
    const { w, acting } = await ready();
    // .01 fils: the fake declines it, after the bank check has already seen it Pending at the bank.
    const request = await ask(acting, w, { amount: ALLOWED(1n) });
    const rail: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        await settledBy(w, request.id, 'submitted', { providerStatus: 'Pending' });
        return w.rail.submitApprovedIntent(intent);
      },
    };

    await handoffOf(w, rail).run();

    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'SUBMITTED', rejectCode: null } });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
    expect(lines('handoff.refused_late')).toEqual([
      expect.objectContaining({ transactionId: await transactionIdOf(w, request.id), status: 'SUBMITTED' }),
    ]);
    expect(lines('handoff.handed_off')).toEqual([expect.objectContaining({ answer: 'refused', recorded: 'late' })]);
  });

  it('settles FAILED an accepted answer the bank rejected with no debit proven and no code: its reference the proof', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    const rejected = (e: PaymentExecution): PaymentExecution => ({
      ...e,
      providerStatus: 'Rejected',
      noDebitProven: true,
      rejectCode: null,
    });

    await handoffOf(w, answeredAs(w, rejected)).run();

    expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status: 'FAILED', rejectCode: null } });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(lines('handoff.answer_unrecorded')).toEqual([]);
  });
});

describe('the model: random batches handed off by runs racing each other (D1; SEC-DP-01, ADR-007 §10)', () => {
  /** The fake's fils outcome, and the status each leaves (decision 5). */
  const OUTCOMES = [
    { fils: 0n, status: 'PROCESSING' },
    { fils: 1n, status: 'FAILED' },
    { fils: 2n, status: 'UNKNOWN' },
    { fils: 3n, status: 'UNKNOWN' },
    { fils: 4n, status: 'PROCESSING' },
  ] as const;
  const REQUEST = fc.record({
    outcome: fc.constantFrom(...OUTCOMES),
    // The second supplier has no payee: its requests wait.
    supplier: fc.integer({ min: 0, max: 1 }),
    // A run that reaches it dies before its answer is recorded.
    dies: fc.boolean(),
  });
  /** AED 100, or 150 for one whose run dies, and the fils: six stay under the approval threshold together (the split check). */
  const LIVES = 10_000n;
  const DIES = 15_000n;
  // The call's limit, on real time, is never reached here (B5's own tests time it; checked below): an answer held
  // back stands for a run that died. The wait is on the test's clock, which each run moves past it.
  const LIMITS = { callTimeoutMs: 180_000, unknownAfterMs: 180_001 };
  /** Two runs at once that die at the first two, one a refusal that comes late; the rest go in the second round. */
  const dying = (fils: bigint) => ({
    outcome: OUTCOMES.find((outcome) => outcome.fils === fils) ?? OUTCOMES[0],
    supplier: 0,
    dies: true,
  });
  const ROUND_TWO: [ReturnType<typeof dying>[], number] = [
    [dying(1n), dying(4n), { ...dying(2n), dies: false }, dying(0n)],
    2,
  ];

  it('sends each request once, one instruction and one transaction; one left waiting UNKNOWN, never sent again', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(REQUEST, { minLength: 2, maxLength: 6 }),
        fc.integer({ min: 1, max: 4 }),
        async (batch, racing) => {
          capture = new LogCapture();
          const { w, acting } = await ready();
          const asked: { request: { id: string }; outcome: (typeof OUTCOMES)[number]; supplier: number }[] = [];
          for (const r of batch) {
            const { outcome } = r;
            const amount = AED((r.dies ? DIES : LIVES) + outcome.fils);
            const request = await ask(acting, w, { amount, supplierId: w.suppliers[r.supplier] ?? '' });
            expect(request.status).toBe('APPROVED');
            asked.push({ request, outcome, supplier: r.supplier });
          }
          // Every submission counted by its instruction; in the first runs, an answer to one that dies held back.
          const sent = new Map<string, number>();
          const held = new Set<string>();
          let holding = true;
          const { promise: released, resolve: release } = Promise.withResolvers<undefined>();
          const rail: FakeRail = {
            ...w.rail,
            submitApprovedIntent: async (intent) => {
              sent.set(intent.instructionId, (sent.get(intent.instructionId) ?? 0) + 1);
              if (holding && intent.amountMinor >= DIES) {
                held.add(intent.instructionId);
                await released;
              }
              return w.rail.submitApprovedIntent(intent);
            },
          };
          const run = () =>
            createHandoff({
              list: () => Promise.resolve([w.org]),
              database: app,
              outbox: createOutbox({ ids, clock }),
              rail,
              keys,
              ids,
              clock,
              logger: testLogger(capture),
              ...LIMITS,
            }).run();

          // The first runs at once, each going until it finishes or reaches one that dies (one each at most).
          let finished = 0;
          const first = Array.from({ length: racing }, () => run().then(() => (finished += 1)));
          await expect.poll(() => finished + held.size, { timeout: 60_000 }).toBe(racing);
          // Past every wait, more at once: the rest handed off, those left waiting swept.
          holding = false;
          clock.advanceBy(LIMITS.unknownAfterMs + 1);
          await Promise.all(Array.from({ length: racing }, run));
          // The dead runs' answers come after all.
          release(undefined);
          await Promise.all(first);

          for (const { request, outcome, supplier } of asked) {
            const payment = await paymentOf(w, request.id);
            if (supplier === 1) {
              expect(await statusOf(w, request.id)).toBe('APPROVED');
              expect(payment).toEqual({ instruction: 'missing' });
              continue;
            }
            expect(await statusOf(w, request.id)).toBe('HANDED_OFF');
            const instructionId = typeof payment.instruction === 'object' ? payment.instruction.id : '';
            // Left waiting: UNKNOWN, whatever its late answer; a late refusal is still proof (B5).
            const left = outcome.status === 'FAILED' ? 'FAILED' : 'UNKNOWN';
            const status = held.has(instructionId) ? left : outcome.status;
            expect(payment).toMatchObject({ transactions: 1, transaction: { status } });
            // What it holds follows where its payment ended, however the runs raced (C3).
            expect(await holdingsOf(w, request.id), status).toEqual(HOLDS_AFTER[status]);
            expect(sent.get(instructionId)).toBe(1);
          }
          // Nothing sent but the instructions made, each once.
          expect([...sent.values()].reduce((total, count) => total + count, 0)).toBe(
            asked.filter(({ supplier }) => supplier === 0).length,
          );
          expect(lines('handoff.marked_unknown')).toHaveLength(held.size);
          expect(lines('handoff.failed')).toEqual([]);
          expect(lines('handoff.answer_unrecorded')).toEqual([]);
          expect(lines('handoff.sweep_failed')).toEqual([]);
          expect(lines('handoff.partner_timeout')).toEqual([]);
        },
      ),
      // Shrinking replays whole worlds, and a race may not replay at all: the failing batch is printed as it was.
      { numRuns: 8, endOnFailure: true, examples: [ROUND_TWO] },
    );
  }, 300_000);
});

/** The world's remittances, by the transaction each is about. */
const remittancesOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        // A global table (0021): the world's own organisation's notices alone.
        .selectFrom('notifications.outbox')
        .select(['about_id', 'recipient_user_id', 'recipient_contact_id', 'to_contacts'])
        .where('org_id', '=', w.org)
        .where('kind', '=', 'payment_remittance')
        .orderBy('id')
        .execute()
    ).map((row) => ({ ...row })),
  );

/** The request's transaction's ID, through its instruction. */
const transactionIdOf = (w: World, requestId: string) =>
  withTenant(app, w.org, async (tx) => {
    const row = await tx
      .selectFrom('transactions.transactions as t')
      .innerJoin('instructions.instructions as i', 'i.id', 't.instruction_id')
      .select('t.id')
      .where('i.spend_request_id', '=', requestId)
      .executeTakeFirstOrThrow();
    return row.id;
  });

/** The world's fake, its accepted answers changed as a mixed-up or garbled connection might give them. */
const answeredAs = (w: World, change: (execution: PaymentExecution) => PaymentExecution): FakeRail => ({
  ...w.rail,
  submitApprovedIntent: async (intent) => {
    const answer = await w.rail.submitApprovedIntent(intent);
    return answer.kind === 'accepted' ? { ...answer, execution: change(answer.execution) } : answer;
  },
});
const credited = (execution: PaymentExecution): PaymentExecution => ({
  ...execution,
  providerStatus: 'AcceptedCreditSettlementCompleted',
});

/** The world's fake, its accepted answers the creditor's account credited at once, as a faster rail might answer. */
const creditedAtOnce = (w: World): FakeRail => answeredAs(w, credited);

/** The partner's later word on the payment, applied as the outcomes module applies it: in lock order, then settled. */
const settledBy = async (w: World, requestId: string, event: TransactionEvent, facts: Partial<ProviderFacts> = {}) => {
  const key = { orgId: w.org, id: await transactionIdOf(w, requestId) };
  await withSignedStates(app, w.org, quiet(), async (tx, states) => {
    await transactionOf(tx, states, key, 'change');
    await lockHoldingsOf(tx, requestId);
    const moved = await moveTransaction(
      tx,
      states,
      key,
      event,
      { ...NO_ANSWER_FACTS, ...facts },
      { actor: { type: 'system', id: 'test' }, details: {} },
    );
    if (moved.outcome !== 'moved') throw new Error(`not moved by ${event}: ${moved.outcome}`);
    await settleHoldings(tx, { requestId, status: moved.to, at: clock.now() });
  });
};

describe('what a handed-off request holds follows its payment (C3; ADR-006 §10–§11, SEC-LIM-02)', () => {
  /** The world's holdings checked as the API's job checks them, its pass logged. */
  const holdingsChecked = async (w: World) => {
    await createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run();
    return lines('holdings_check.passed');
  };

  it('spends it on success, its order kept for good; a reversal after gives nothing back', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);

    await settledBy(w, request.id, 'succeed');
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    // Later: its reservation, spent once, is left as it was (it settles once: 0040).
    clock.advanceBy(60_000);
    await settledBy(w, request.id, 'reverse');
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);

    expect(await holdingsChecked(w)).toEqual([expect.objectContaining({ mismatched: 0, tampered: 0 })]);
  });

  it('keeps an unknown one blocked until it is known: then spent on success, given back after a proven failure', async () => {
    const { w, acting } = await ready();
    const paid = await ask(acting, w, { amount: SMALL(2n) });
    const failed = await ask(acting, w, { amount: SMALL(2n) });
    await handoffOf(w).run();
    expect(await holdingsOf(w, paid.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(await holdingsOf(w, failed.id)).toEqual(HOLDS_AFTER.UNKNOWN);

    await settledBy(w, paid.id, 'succeed');
    await settledBy(w, failed.id, 'fail', { rejectCode: 'AANI.AM04' });

    expect(await holdingsOf(w, paid.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(await holdingsOf(w, failed.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(await holdingsChecked(w)).toEqual([expect.objectContaining({ mismatched: 0, tampered: 0 })]);
  });

  it('SEC-LIM-02: an unknown payment still uses the month and blocks its order; a failed one gives both back', async () => {
    const { w, acting } = await ready();
    const unknown = await ask(acting, w, { amount: SMALL(2n), orderReference: 'INV-C3-UNKNOWN' });
    const refused = await ask(acting, w, { amount: SMALL(1n), orderReference: 'INV-C3-REFUSED' });
    await handoffOf(w).run();

    expect(await spentOf(w, acting)).toBe(SMALL(2n).minor);
    const twice = await ask(acting, w, { amount: SMALL(), orderReference: 'INV-C3-UNKNOWN' });
    expect(twice.reasons).toContain('DUPLICATE_ORDER_REFERENCE');
    const again = await ask(acting, w, { amount: SMALL(), orderReference: 'INV-C3-REFUSED' });
    expect(again.reasons).not.toContain('DUPLICATE_ORDER_REFERENCE');
    expect(again.status).toBe('APPROVED');
    expect(await holdingsOf(w, refused.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(await holdingsOf(w, unknown.id)).toEqual(HOLDS_AFTER.UNKNOWN);
  });

  describe('refused past the app (0060), and alarmed by the holdings check where it got past', () => {
    /** `change` run as the tables' owner on the world's rows, with the guards on, or switched off for it. */
    const asOwner = async (w: World, change: (owner: TestClient) => Promise<unknown>, guards: 'on' | 'off') => {
      const owner = await database.connect('owner');
      try {
        await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
        await owner.query('begin');
        if (guards === 'off') {
          await owner.query('alter table limit_reservations.reservations disable trigger user');
          await owner.query('alter table spend_requests.order_claims disable trigger user');
        }
        await change(owner);
        if (guards === 'off') {
          await owner.query('alter table limit_reservations.reservations enable trigger user');
          await owner.query('alter table spend_requests.order_claims enable trigger user');
        }
        await owner.query('commit');
      } catch (error) {
        await owner.query('rollback');
        throw error;
      } finally {
        await owner.end();
      }
    };
    /** The request's reservation moved to `state`, settled or not as 0040's `settled_at_its_end` needs. */
    const reservationTo = (state: string) => (id: string) => (owner: TestClient) =>
      owner.query(
        `update limit_reservations.reservations
           set state = $1, settled_at = case when $1 in ('FINALISED', 'RELEASED') then reserved_at end
           where request_id = $2`,
        [state, id],
      );
    const claimReleased = (id: string) => (owner: TestClient) =>
      owner.query('update spend_requests.order_claims set released_at = claimed_at where request_id = $1', [id]);

    it.each([
      ['released while under way', 'PROCESSING', 0n, reservationTo('RELEASED')],
      ['finalised while under way', 'PROCESSING', 0n, reservationTo('FINALISED')],
      ['blocked while under way', 'PROCESSING', 0n, reservationTo('BLOCKED_UNKNOWN')],
      ['released while unknown', 'UNKNOWN', 2n, reservationTo('RELEASED')],
      ['finalised while unknown', 'UNKNOWN', 2n, reservationTo('FINALISED')],
      ['its claim released while unknown', 'UNKNOWN', 2n, claimReleased],
      ['its claim released while under way', 'PROCESSING', 0n, claimReleased],
    ] as const)('a reservation or claim %s', async (_name, status, fils, change) => {
      const { w, acting } = await ready();
      const request = await ask(acting, w, { amount: ALLOWED(fils) });
      await handoffOf(w).run();
      expect(await paymentOf(w, request.id)).toMatchObject({ transaction: { status } });

      await expect(asOwner(w, change(request.id), 'on')).rejects.toThrow(
        /only as its payment does|only after its payment failed/,
      );
      expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER[status]);

      await asOwner(w, change(request.id), 'off');
      expect(await holdingsChecked(w)).toEqual([expect.objectContaining({ mismatched: 1 })]);
    });

    it('a failed one kept held: never given back is a mismatch too', async () => {
      const { w, acting } = await ready();
      const request = await ask(acting, w, { amount: ALLOWED(1n) });
      await handoffOf(w).run();
      await asOwner(
        w,
        (owner) =>
          owner.query(
            `update limit_reservations.reservations set state = 'HELD', settled_at = null where request_id = $1`,
            [request.id],
          ),
        'off',
      );

      expect(await holdingsChecked(w)).toEqual([expect.objectContaining({ mismatched: 1 })]);
    });

    it('a handed-off request whose transaction is gone holds nothing it can be matched against', async () => {
      const { w, acting } = await ready();
      const request = await ask(acting, w, { amount: ALLOWED() });
      await handoffOf(w).run();
      const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
      try {
        await owner.query(
          `delete from transactions.transactions where instruction_id =
             (select id from instructions.instructions where spend_request_id = $1)`,
          [request.id],
        );
      } finally {
        await owner.end();
      }

      expect(await holdingsChecked(w)).toEqual([expect.objectContaining({ mismatched: 1 })]);
    });
    it.each([
      ['instruction', INSTRUCTIONS],
      ['transaction', TRANSACTIONS],
    ] as const)(
      'a handed-off request whose %s can’t be believed holds nothing it can be matched against',
      async (_name, table) => {
        const { w, acting } = await ready();
        const request = await ask(acting, w, { amount: SMALL() });
        await handoffOf(w).run();
        const payment = await paymentOf(w, request.id);
        const instructionId = typeof payment.instruction === 'object' ? payment.instruction.id : '';
        const transactionId = typeof payment.transaction === 'object' ? payment.transaction.id : '';
        const owner = await tamperAsOwner(database, table, w.org);
        try {
          await owner.stripSeals(table === INSTRUCTIONS ? instructionId : transactionId);
        } finally {
          await owner.end();
        }

        expect(await holdingsChecked(w)).toEqual([expect.objectContaining({ mismatched: 1 })]);
      },
    );
  });

  it('settles in the lock order: its holdings locked before the head, so their holder never waits on it (ADR-006 §6)', async () => {
    const { w, acting } = await ready();
    // Refused: Tx B gives its holdings back, so it writes them.
    const request = await ask(acting, w, { amount: SMALL(1n) });
    const { promise: answered, resolve: answer } = Promise.withResolvers<undefined>();
    const { promise: called, resolve: calling } = Promise.withResolvers<undefined>();
    const rail: FakeRail = {
      ...w.rail,
      submitApprovedIntent: async (intent) => {
        calling(undefined);
        await answered;
        return w.rail.submitApprovedIntent(intent);
      },
    };
    const run = handoffOf(w, rail).run();
    await called;
    // Something holding the request's reservation (as an ending or a holdings page would) as the answer is recorded.
    const holder = await database.connect('owner');
    try {
      await holder.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await holder.query('begin');
      await holder.query('select id from limit_reservations.reservations where request_id = $1 for no key update', [
        request.id,
      ]);
      answer(undefined);
      await waitUntilQueued(database.as('admin'), 1);
      // Tx B waits at the reservation (11) holding nothing of the head (12): the organisation's head is free.
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

    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(lines('handoff.handed_off')).toEqual([
      expect.objectContaining({ requestId: request.id, recorded: 'recorded' }),
    ]);
  });
});

describe('a payment that SUCCEEDED queues its supplier’s remittance email, once (C2b; partner decision 34a)', () => {
  it('queues one remittance to the supplier itself, about the transaction, in the Tx B that records SUCCEEDED', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });

    await handoffOf(w, creditedAtOnce(w)).run();

    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect(await remittancesOf(w)).toEqual([
      {
        about_id: await transactionIdOf(w, request.id),
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: false,
      },
    ]);
    // Another run finds nothing approved: the payment, and its remittance, once.
    await handoffOf(w, creditedAtOnce(w)).run();
    expect(await remittancesOf(w)).toHaveLength(1);
  });

  it('queues none for a payment under way, refused or unknown: only one that SUCCEEDED is told', async () => {
    const { w, acting } = await ready();
    const underWay = await ask(acting, w, { amount: SMALL() });
    const refused = await ask(acting, w, { amount: SMALL(1n) });
    const unknown = await ask(acting, w, { amount: SMALL(2n) });

    await handoffOf(w).run();

    expect(await holdingsOf(w, underWay.id)).toEqual(HOLDS_AFTER.PROCESSING);
    expect(await holdingsOf(w, refused.id)).toEqual(HOLDS_AFTER.FAILED);
    expect(await holdingsOf(w, unknown.id)).toEqual(HOLDS_AFTER.UNKNOWN);
    expect(await remittancesOf(w)).toEqual([]);
  });

  describe('read as it is sent, from the payment’s verified records (remittances.ts)', () => {
    const SUPPLIER_EMAIL = 'accounts@gulf-office.example.test';
    const remittances = () => createRemittances({ database: app, keys, ids, logger: testLogger(capture) });
    /** An invoice number the rail can't carry whole: its bank reference keeps the Latin part alone. */
    const INVOICE = 'فاتورة INV-C2B-0042';

    /** What the world's audit log keeps of its remittances (partner S119): readable by its admins. */
    const remittanceEvents = (w: World) =>
      withTenant(app, w.org, async (tx) =>
        (
          await tx
            .selectFrom('audit.events')
            .select(['actor_type', 'actor_id', 'action', 'subject_id', 'details'])
            .where('org_id', '=', w.org)
            .where('subject_type', '=', 'payment_remittance')
            .orderBy('seq')
            .execute()
        ).map((row) => ({ ...row, details: JSON.parse(row.details) as unknown })),
      );

    /** A world whose first supplier holds SUPPLIER_EMAIL (unless `email` says otherwise), and one payment to it credited. */
    async function paid(email: string | null = SUPPLIER_EMAIL) {
      const { w, acting } = await ready();
      const supplierId = w.suppliers[0] ?? '';
      if (email !== null) await shared.detailsChanged(w, supplierId, undefined, email);
      const request = await ask(acting, w, { amount: ALLOWED(), orderReference: INVOICE });
      await handoffOf(w, creditedAtOnce(w)).run();
      return { w, supplierId, request, transactionId: await transactionIdOf(w, request.id) };
    }

    it('gives the supplier’s address and the payment’s four facts: who paid, the invoice, the bank reference, the amount', async () => {
      const { w, request, transactionId } = await paid();
      const payment = await paymentOf(w, request.id);
      if (typeof payment.instruction === 'string') throw new Error('no instruction');

      expect(payment.instruction.paymentReference).toBe('INV-C2B-0042');
      expect(await remittances().remittanceOf(w.org, transactionId)).toEqual({
        outcome: 'send',
        to: SUPPLIER_EMAIL,
        paid: {
          payerName: 'Acme Trading LLC',
          invoiceNumber: INVOICE,
          bankReference: 'INV-C2B-0042',
          amountMinor: ALLOWED().minor,
          currency: 'AED',
        },
      });
      // Nothing kept until it is sent; then that it was, by the API, never the address.
      expect(await remittanceEvents(w)).toEqual([]);
      await remittances().emailed(w.org, transactionId);
      expect(await remittanceEvents(w)).toEqual([
        {
          actor_type: 'system',
          actor_id: 'api',
          action: 'payment.remittance_emailed',
          subject_id: transactionId,
          details: {},
        },
      ]);
    });

    it('says no email when the version paid holds none (34c), and off once the setting is turned off since (34b)', async () => {
      const bare = await paid(null);
      expect(await remittances().remittanceOf(bare.w.org, bare.transactionId)).toEqual({ outcome: 'no_email' });
      expect(await remittanceEvents(bare.w)).toMatchObject([
        { action: 'payment.remittance_skipped', subject_id: bare.transactionId, details: { reason: 'no_email' } },
      ]);

      const { w, supplierId, transactionId } = await paid();
      await signed(w, async (tx, states) => {
        await supplierOf(tx, states, { orgId: w.org, id: supplierId }, 'change');
        const read = await remittanceOf(tx, states, { orgId: w.org, supplierId }, 'change');
        if (read.outcome === 'tampered') throw new Error('tampered');
        await setRemittance(tx, states, read, {
          orgId: w.org,
          supplierId,
          remittanceEmail: 'off',
          at: clock.now(),
          actor: OPERATOR,
        });
      });
      expect(await remittances().remittanceOf(w.org, transactionId)).toEqual({ outcome: 'off' });
      expect(await remittanceEvents(w)).toMatchObject([
        { action: 'payment.remittance_skipped', subject_id: transactionId, details: { reason: 'setting_off' } },
      ]);
    });

    it('says not succeeded for a payment still under way, whatever its setting and address', async () => {
      const { w, acting } = await ready();
      await shared.detailsChanged(w, w.suppliers[0] ?? '', undefined, SUPPLIER_EMAIL);
      const request = await ask(acting, w, { amount: ALLOWED() });
      await handoffOf(w).run();

      const transactionId = await transactionIdOf(w, request.id);
      expect(await remittances().remittanceOf(w.org, transactionId)).toEqual({ outcome: 'not_succeeded' });
      expect(await remittanceEvents(w)).toMatchObject([
        {
          action: 'payment.remittance_skipped',
          subject_id: transactionId,
          details: { reason: 'payment_not_succeeded' },
        },
      ]);
    });

    it('throws, sending nothing, for a transaction it can’t find or can’t believe (its alarm raised)', async () => {
      const { w, transactionId } = await paid();
      await expect(remittances().remittanceOf(w.org, ids.next())).rejects.toThrow("can't be believed");

      const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
      try {
        await owner.stripSeals(transactionId);
      } finally {
        await owner.end();
      }
      await expect(remittances().remittanceOf(w.org, transactionId)).rejects.toThrow("can't be believed");
      expect(lines('audit.integrity_failed').length).toBeGreaterThan(0);
    });

    it.each([
      ['its supplier version', SUPPLIER_VERSIONS],
      ['its supplier’s setting', REMITTANCE_SETTINGS],
      ['its request', SPEND_REQUESTS],
    ] as const)('throws, sending nothing, when %s can’t be believed', async (_what, table) => {
      const { w, supplierId, request, transactionId } = await paid();
      const payment = await paymentOf(w, request.id);
      if (typeof payment.instruction === 'string') throw new Error('no instruction');
      const id = {
        [SUPPLIER_VERSIONS.table]: payment.instruction.supplierVersionId,
        [REMITTANCE_SETTINGS.table]: supplierId,
        [SPEND_REQUESTS.table]: request.id,
      }[table.table];
      const owner = await tamperAsOwner(database, table, w.org);
      try {
        await owner.stripSeals(id);
      } finally {
        await owner.end();
      }

      await expect(remittances().remittanceOf(w.org, transactionId)).rejects.toThrow("can't be believed");
    });
  });
});
