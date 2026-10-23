// Phase 4 E1b: the partner's messages end to end, on the real migrated
// schema as the app role (ADR-007 §12–13; rail map §1.8; SEC-PTR-01–06). The
// world's own fake partner signs real-looking messages; they come through the
// front door, are kept in the inbox, routed by the directory, and the bank
// check then asks the bank about the payments they name, ahead of their
// turn. The message's own word never moves a payment (SEC-PTR-02); a replay
// adds nothing (-03); early, duplicate and out-of-order messages make one
// move (-04); an unknown reference is kept encrypted and alerted, nothing
// changing (-05); a malformed body is refused (-06); a bad signature or a
// stale time is refused, counted, kept encrypted as evidence a few an hour
// from an address, and alerted (-01).
import { createOutbox } from '@agentx/core/modules/notifications';
import { changeHandoffPause, createPlatformChain } from '@agentx/core/modules/platform-controls';
import { createProviderEvents } from '@agentx/core/modules/provider-events';
import { TRANSACTIONS } from '@agentx/core/modules/transactions';
import {
  type FakeMessage,
  type FakeRail,
  FAKE_SIGNATURE_HEADER,
  RailUnavailable,
} from '@agentx/core/modules/providers';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  tamperAsOwner,
  testLogger,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHandoff } from './handoff.ts';
import { ALLOWED, handoffWorld, type HandoffWorldTables, HOLDS_AFTER, SMALL } from './handoff-world.helper.test.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, type World } from './mandate-world.helper.test.ts';
import { createPartnerEventIntake, PARTNER_EVENTS_PATH } from './partner-events.ts';
import { createPaymentChecks } from './payment-checks.ts';
import { closeServers, routeServer } from './route-server.helper.test.ts';
import type { SecurityEventNote } from './security-recorder.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<HandoffWorldTables>;

const ids = new SequentialIds(0xe1c0_0000_0000);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xe1d0_0000_0000) });

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'partner-events',
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
const STEP = 60_000;

const events = () => createProviderEvents({ keys, ids, clock, retentionDays: 30 });

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

/** The bank check over the world alone, taking the inbox's messages first, asking `rail`. */
const checksOf = (w: World, rail: FakeRail = w.rail) =>
  createPaymentChecks({
    list: () => Promise.resolve([w.org]),
    database: app,
    outbox: createOutbox({ ids, clock }),
    rail,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
    events: events(),
  });

/** The world's fake, every lookup counted by the instruction asked about. */
function counted(w: World) {
  const asked: string[] = [];
  const rail: FakeRail = {
    ...w.rail,
    getExecution: (ref) => {
      asked.push(ref.instructionId);
      return w.rail.getExecution(ref);
    },
  };
  return { rail, asked };
}

/** The front door over the world's partner, every security event noted. */
async function door(w: World) {
  const noted: SecurityEventNote[] = [];
  const front = await routeServer({
    partnerEvents: createPartnerEventIntake({
      database: app,
      rail: w.rail,
      events: events(),
      securityEvents: { note: (event) => noted.push(event) },
    }),
    logger: testLogger(capture),
  });
  /** A message sent as the fake partner signs it, or as given. */
  const send = async (message: FakeMessage | { body: Buffer; headers: Record<string, string> }, ip = '203.0.113.7') => {
    const signed = 'body' in message ? message : await w.rail.bank.signEvent(message);
    return front.inject({
      method: 'POST',
      url: PARTNER_EVENTS_PATH,
      payload: signed.body,
      headers: signed.headers,
      remoteAddress: ip,
    });
  };
  return { send, noted };
}

/** The request's payment: its transaction and our instruction's ID. */
const transactionOf = async (w: World, requestId: string) => {
  const payment = await paymentOf(w, requestId);
  if (typeof payment.transaction !== 'object' || typeof payment.instruction !== 'object') {
    throw new Error('no payment');
  }
  return {
    ...payment.transaction,
    instructionId: payment.instruction.id,
    consentId: payment.instruction.accountConsentId,
  };
};

/**
 * The world's consent its own alone in the directory: every world's fake hands
 * out the same consent IDs, so earlier worlds' payments name it too. A real
 * partner's consent IDs are its own, one organisation's each.
 */
const consentOnlyOurs = (w: World) =>
  database
    .as('admin')
    .query(
      'update directory.instructions set account_consent_id = null where account_consent_id = $1 and org_id <> $2',
      [w.state.accountConsentId, w.org],
    );

/** The inbox's rows, oldest first. */
const inbox = () =>
  app
    .selectFrom('provider_events.inbox')
    .select(['id', 'reference_kind', 'reference', 'org_id', 'taken_at', 'body_ciphertext'])
    .orderBy('received_at')
    .orderBy('id')
    .execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<HandoffWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  await app
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused: false, reason: 'TEST-E1B', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
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
  // Each test sees only its own messages.
  await database.as('admin').query('truncate provider_events.inbox, security.partner_event_evidence');
});

afterEach(closeServers);

describe('a message names a payment: it is checked with the bank, ahead of its turn (ADR-007 §13)', () => {
  it('keeps it in the inbox, routed by the directory, and the next check asks the bank about it', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);
    // Past its 15 minutes: a check's second run wouldn't reach it on its own.
    const { rail, asked } = counted(w);
    const checks = checksOf(w, rail);
    await checks.run();
    clock.advanceBy(16 * STEP);
    asked.length = 0;

    const reply = await send({
      eventType: 'payment.status',
      consentId: payment.consentId,
      instructionId: payment.instructionId,
    });
    expect(reply.statusCode).toBe(202);
    expect(await inbox()).toEqual([
      expect.objectContaining({
        reference_kind: 'instruction',
        reference: payment.instructionId,
        org_id: w.org,
        taken_at: null,
      }),
    ]);

    await checks.run();

    expect(asked).toEqual([payment.instructionId]);
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.SUCCEEDED);
    expect((await inbox())[0]?.taken_at).not.toBeNull();
    // A routed one keeps no body.
    expect(await events().unknownBody(app, (await inbox())[0]?.id ?? '')).toBeUndefined();
    // Taken once: the next run asks nothing more of it.
    asked.length = 0;
    await checks.run();
    expect(asked).toEqual([]);
  });

  it('writes each instruction’s consent in the directory, with its organisation (0063)', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);

    const row = await app
      .selectFrom('directory.instructions')
      .select(['org_id', 'account_consent_id'])
      .where('instruction_id', '=', payment.instructionId)
      .executeTakeFirstOrThrow();

    expect(row).toEqual({ org_id: w.org, account_consent_id: w.state.accountConsentId });
  });

  it('checks every payment under way under a consent the message names alone (rail map §1.8)', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w, { amount: SMALL() });
    const second = await ask(acting, w, { amount: SMALL() });
    await handoffOf(w).run();
    await consentOnlyOurs(w);
    const { send } = await door(w);
    const { rail, asked } = counted(w);
    clock.advanceBy(2 * STEP);

    expect((await send({ eventType: 'consent.payments', consentId: w.state.accountConsentId })).statusCode).toBe(202);
    await checksOf(w, rail).run();

    const ids = [(await transactionOf(w, first.id)).instructionId, (await transactionOf(w, second.id)).instructionId];
    // Each by the message, then each by its own turn (a new check's first run takes every one).
    expect(asked.slice(0, 2).sort()).toEqual([...ids].sort());
    for (const request of [first, second]) {
      expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    }
  });

  it('checks only the payments under the consent a message names, not the rest of its organisation’s', async () => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const { rail, asked } = counted(w);
    const checks = checksOf(w, rail);
    // Its own turn taken, then past 15 minutes: only a message could bring it forward now.
    await checks.run();
    clock.advanceBy(16 * STEP);
    asked.length = 0;
    // A message routed to the organisation, naming another consent of its.
    await database.as('admin').query(
      `insert into provider_events.inbox (id, partner, dedupe_key, event_type, reference_kind, reference, org_id, received_at)
         values ($1, 'fake', $2, 'consent.payments', 'consent', 'another-consent', $3, now())`,
      [ids.next(), ids.next(), w.org],
    );

    await checks.run();

    expect(asked).toEqual([]);
    expect((await inbox())[0]?.taken_at).not.toBeNull();
  });

  it('SEC-PTR-02: the message’s word never moves a payment: the bank says Pending, and it stays under way', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);

    // A message that says it was paid, while the bank still says Pending.
    await send({
      eventType: 'AcceptedCreditSettlementCompleted',
      consentId: payment.consentId,
      instructionId: payment.instructionId,
    });
    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'PROCESSING', providerStatus: 'Pending' });
    expect(await holdingsOf(w, request.id)).toEqual(HOLDS_AFTER.PROCESSING);
  });

  it('SEC-PTR-03: a replay is kept once and checked once', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);
    const signed = await w.rail.bank.signEvent({
      eventType: 'payment.status',
      consentId: payment.consentId,
      instructionId: payment.instructionId,
    });

    expect((await send(signed)).statusCode).toBe(202);
    expect((await send(signed)).statusCode).toBe(202);

    expect(await inbox()).toHaveLength(1);
    expect(lines('partner_event.taken_in').map((line) => line.replay)).toEqual([false, true]);
  });

  it('SEC-PTR-04: early, duplicate and out-of-order messages make one move, by the bank’s word', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);
    clock.advanceBy(2 * STEP);

    // Credited first, then under way, then pending: in the wrong order, each a new message.
    for (const eventType of ['credited', 'settled', 'pending']) {
      await send({ eventType, consentId: payment.consentId, instructionId: payment.instructionId });
    }
    await checksOf(w).run();
    await checksOf(w).run();

    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
    const moves = await shared.eventsAbout(w.org, payment.id, 'transaction');
    expect(moves.filter(({ action }) => action === 'transaction.succeed')).toHaveLength(1);
    expect((await inbox()).every((row) => row.taken_at !== null)).toBe(true);
  });
});

describe('a message the check can’t take yet waits for the next run', () => {
  it('leaves it waiting while the bank can’t be reached, and takes it once it can', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);
    await send({ eventType: 'payment.status', consentId: payment.consentId, instructionId: payment.instructionId });

    await checksOf(w, { ...w.rail, getExecution: () => Promise.reject(new RailUnavailable()) }).run();
    expect((await inbox())[0]?.taken_at).toBeNull();

    await checksOf(w).run();
    expect((await inbox())[0]?.taken_at).not.toBeNull();
  });

  it('says so when the inbox can’t be read, and checks the payments in their turn all the same', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    clock.advanceBy(2 * STEP);
    const unreadable = { ...events(), waiting: () => Promise.reject(new Error('inbox down')) };

    await createPaymentChecks({
      list: () => Promise.resolve([w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: w.rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      events: unreadable,
    }).run();

    expect(lines('payment_check.nudge_failed')).toHaveLength(1);
    expect(await transactionOf(w, request.id)).toMatchObject({ status: 'SUCCEEDED' });
  });

  it('takes one routed to an organisation holding no such payment: nothing to check', async () => {
    const { w } = await ready();
    const { send } = await door(w);
    await send({ eventType: 'x', consentId: 'nowhere' });
    // Routed there by hand: the body kept for an unknown one goes with it, as the table holds.
    await database
      .as('admin')
      .query('update provider_events.inbox set org_id = $1, body_ciphertext = null, body_key_version = null', [w.org]);

    await checksOf(w).run();

    expect(lines('payment_check.nudge_failed')).toEqual([]);
    expect((await inbox())[0]?.taken_at).not.toBeNull();
  });

  it('sets a message aside after 5 runs that couldn’t take it, said once, so it never holds up the rest', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);
    await send({ eventType: 'payment.status', consentId: payment.consentId, instructionId: payment.instructionId });
    // The bank never answers for it, but answers the rest: never 3 in a row, so the run goes on.
    const silent: FakeRail = {
      ...w.rail,
      getExecution: (ref) =>
        ref.instructionId === payment.instructionId ? Promise.reject(new RailUnavailable()) : w.rail.getExecution(ref),
    };

    for (let run = 0; run < 6; run += 1) await checksOf(w, silent).run();

    const [row] = await app.selectFrom('provider_events.inbox').select(['attempts', 'taken_at']).execute();
    expect(row).toEqual({ attempts: 5, taken_at: null });
    expect(lines('payment_check.nudge_given_up')).toHaveLength(1);
  });

  it('leaves a message untaken when its payment’s answer couldn’t be recorded: tried again next run', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);
    await send({ eventType: 'payment.status', consentId: payment.consentId, instructionId: payment.instructionId });
    const owner = await tamperAsOwner(database, TRANSACTIONS, w.org);
    try {
      await owner.stripSeals(payment.id);
    } finally {
      await owner.end();
    }

    await checksOf(w).run();

    expect(lines('payment_check.failed')).toHaveLength(1);
    expect((await inbox())[0]?.taken_at).toBeNull();
  });

  it('says so when a message can’t be marked taken, and goes on: it is checked again next run', async () => {
    const { w, acting } = await ready();
    const request = await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const payment = await transactionOf(w, request.id);
    const { send } = await door(w);
    await send({ eventType: 'payment.status', consentId: payment.consentId, instructionId: payment.instructionId });
    const stuck = { ...events(), taken: () => Promise.reject(new Error('inbox down')) };

    await createPaymentChecks({
      list: () => Promise.resolve([w.org]),
      database: app,
      outbox: createOutbox({ ids, clock }),
      rail: w.rail,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      events: stuck,
    }).run();

    expect(lines('payment_check.nudge_failed')).toHaveLength(1);
    expect((await inbox())[0]?.taken_at).toBeNull();
  });
});

describe('what the front door refuses or can’t place (SEC-PTR-01, -05, -06)', () => {
  it('SEC-PTR-05: keeps an unknown reference encrypted, alerts once, and changes nothing', async () => {
    const { w } = await ready();
    const { send } = await door(w);
    const signed = await w.rail.bank.signEvent({
      eventType: 'payment.status',
      consentId: 'no-such-consent',
      instructionId: ids.next(),
    });

    expect((await send(signed)).statusCode).toBe(202);
    expect((await send(signed)).statusCode).toBe(202);

    const [row] = await inbox();
    expect(row).toMatchObject({ org_id: null, taken_at: null });
    expect(row?.body_ciphertext?.includes(signed.body)).toBe(false);
    expect(await events().unknownBody(app, row?.id ?? '')).toEqual(signed.body);
    expect(lines('partner_event.unknown_reference')).toHaveLength(1);
    // Nothing kept to open for a row that isn't there, nor in the evidence for an inbox row.
    expect(await events().unknownBody(app, ids.next())).toBeUndefined();
    expect(await events().refusedBody(app, row?.id ?? '')).toBeUndefined();
    // Never taken by the check: it names nothing it can ask about.
    await checksOf(w).run();
    expect((await inbox())[0]?.taken_at).toBeNull();
  });

  it('routes a consent no payment was made under nowhere: unknown', async () => {
    const { w } = await ready();
    await consentOnlyOurs(w);
    const { send } = await door(w);

    await send({ eventType: 'consent.revoked', consentId: w.state.accountConsentId });

    expect(await inbox()).toEqual([expect.objectContaining({ reference_kind: 'consent', org_id: null })]);
  });

  it.each([
    ['a bad signature', 'signature', 401],
    ['a stale time', 'stale', 401],
    ['a malformed signed body', 'malformed', 400],
  ] as const)('SEC-PTR-01/-06: refuses %s, counts it, keeps it encrypted and alerts', async (_name, reason, status) => {
    const { w, acting } = await ready();
    await ask(acting, w, { amount: ALLOWED() });
    await handoffOf(w).run();
    const { send, noted } = await door(w);
    const good = await w.rail.bank.signEvent({ eventType: 'x', consentId: w.state.accountConsentId });
    const body = reason === 'malformed' ? Buffer.from('{"Meta":{}}') : good.body;
    // Signed now, then sent when its time no longer holds; or signed over another body.
    const message =
      reason === 'stale'
        ? good
        : reason === 'malformed'
          ? await w.rail.bank.signBody(body)
          : {
              body,
              headers: {
                ...good.headers,
                [FAKE_SIGNATURE_HEADER]:
                  good.headers[FAKE_SIGNATURE_HEADER]?.replace(/.$/, (c) => (c === '0' ? '1' : '0')) ?? '',
              },
            };
    if (reason === 'stale') clock.advanceBy(5 * STEP + 1);

    const reply = await send(message);

    expect(reply.statusCode).toBe(status);
    expect(await inbox()).toEqual([]);
    expect(noted).toEqual([{ kind: 'partner_event_refused', reason, ip: '203.0.113.7' }]);
    const kept = await app
      .selectFrom('security.partner_event_evidence')
      .select(['id', 'reason', 'ip', 'body_bytes'])
      .execute();
    expect(kept).toEqual([expect.objectContaining({ reason, ip: '203.0.113.7', body_bytes: message.body.length })]);
    expect(await events().refusedBody(app, kept[0]?.id ?? '')).toEqual(message.body);
    expect(lines('partner_event.refused')).toEqual([expect.objectContaining({ reason })]);
  });

  /** A message forged at the clock's time: a signature no key made. */
  const forgedNow = () => ({
    body: Buffer.from('{}'),
    headers: {
      'content-type': 'application/json',
      [FAKE_SIGNATURE_HEADER]: `t=${clock.now().toISOString()},v1=${'0'.repeat(64)}`,
    },
  });
  const kept = () => app.selectFrom('security.partner_event_evidence').select('ip').execute();

  it('keeps the first 5 an hour from one network, counts every one, and alerts once a network an hour (a flood is a count)', async () => {
    const { w } = await ready();
    const { send, noted } = await door(w);

    for (let n = 0; n < 7; n += 1) expect((await send(forgedNow())).statusCode).toBe(401);
    await send(forgedNow(), '198.51.100.9');

    expect(noted).toHaveLength(8);
    expect(await kept()).toHaveLength(6);
    expect(lines('partner_event.refused')).toHaveLength(2);

    // An hour on, kept again, and said again.
    clock.advanceBy(60 * STEP + 1);
    await send(forgedNow());
    expect(await kept()).toHaveLength(7);
    expect(lines('partner_event.refused')).toHaveLength(3);
  });

  it('keeps a refused body’s first 16 KiB alone, said as kept', async () => {
    const { w } = await ready();
    const { send } = await door(w);
    const long = { ...forgedNow(), body: Buffer.alloc(20 * 1024, 0x61) };

    expect((await send(long)).statusCode).toBe(401);

    const [row] = await app.selectFrom('security.partner_event_evidence').select(['id', 'body_bytes']).execute();
    expect(row?.body_bytes).toBe(16 * 1024);
    expect(await events().refusedBody(app, row?.id ?? '')).toEqual(long.body.subarray(0, 16 * 1024));
  });

  it('counts an IPv6 /64 as one network, as the rate limit does: a new address in it gets no 5 of its own', async () => {
    const { w } = await ready();
    const { send } = await door(w);

    for (let n = 1; n <= 7; n += 1) await send(forgedNow(), `2001:db8:1:2::${String(n)}`);
    await send(forgedNow(), '2001:db8:1:3::1');

    expect(await kept()).toHaveLength(6);
  });

  it('keeps at most 50 an hour from every network together', async () => {
    const { w } = await ready();
    const { send } = await door(w);

    for (let n = 1; n <= 55; n += 1) await send(forgedNow(), `198.51.100.${String(n)}`);

    expect(await kept()).toHaveLength(50);
  });

  it('holds the cap under a burst at once: one lock, so none slips past (S102)', async () => {
    const { w } = await ready();
    const { send } = await door(w);

    await Promise.all(Array.from({ length: 20 }, () => send(forgedNow())));

    expect(await kept()).toHaveLength(5);
    expect(lines('partner_event.refused')).toHaveLength(1);
  });

  it('sweeps both tables past their retention', async () => {
    const { w } = await ready();
    const { send } = await door(w);
    await send({ eventType: 'x', consentId: 'nowhere' });
    await send({ body: Buffer.from('{}'), headers: { 'content-type': 'application/json' } });

    // Within the retention: kept.
    expect(await events().sweep(app, 10)).toBe(0);
    clock.advanceBy(30 * 24 * 60 * STEP + 1);
    expect(await events().sweep(app, 10)).toBe(2);
    expect(await inbox()).toEqual([]);
    await expect(events().sweep(app, 0)).rejects.toThrow(RangeError);
  });
});
