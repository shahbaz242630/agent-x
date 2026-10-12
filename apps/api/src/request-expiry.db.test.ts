// Phase 2 D7: spend requests waiting for approval expired after 72 hours, on
// the real migrated schema as the app role (PRD §4.2; ADR-006 §10–§11;
// partner decision 10). A request waiting 72 hours from its decision is
// EXPIRED, recorded as the API's, its reservation and order claim released:
// the agent's month and the order are free again, and the holdings check
// still passes. One not yet due, an allowed one and a denied one are left as
// they are; one whose unsealed `created_at` was moved back past the app is
// judged by its decision's sealed time and left; one tampered with is refused
// and paged past, the others still expired; one that can't be expired, and an
// organisation whose requests can't be read, logged and passed over; a run's share, the rest left to the next; a
// stopped run; a holdings check holding the request, or a holder of its
// reservation or claim reaching for the audit head (forced), is waited for;
// expireRequest's own answers for a request moved on or not there; and an
// organisation list that can't be read, logged as an error.
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { type LimitReservationsTables, monthSpent } from '@agentx/core/modules/limit-reservations';
import {
  checkHoldings,
  expireRequest,
  requestOf,
  SPEND_REQUESTS,
  type SpendRequestsTables,
} from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
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

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, mandateWorld, type MandateWorldTables, type World } from './mandate-world.helper.test.ts';
import { createRequestExpiry, type RequestExpiry } from './request-expiry.ts';
import {
  type AgentActing,
  createSpendRequestDecisions,
  DECIDE_OPERATION,
  type SpendAskedByAgent,
  type SpendRequestDecisions,
} from './spend-request-decisions.ts';

type Tables = MandateWorldTables & SpendRequestsTables & LimitReservationsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0xd700_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000d7';
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
/** Partner decision 10's wait, written out here so the code's constant is held to it. */
const SEVENTY_TWO_HOURS = 72 * HOUR;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
/** The job over these organisations, expiring at most `most` of each one's requests a run, a page as long. */
let expiryOf: (orgs: () => Promise<readonly string[]>, most?: number) => RequestExpiry;
const only = (w: World) => () => Promise.resolve([w.org]);

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'request-expiry' });
const { world, quiet, agentKey } = shared;

/** A world whose agent has a key and a mandate in force (approval above AED 1,000), both suppliers verified. */
async function ready() {
  const w = await world();
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, { approvalThreshold: AED(100_000n) });
  return { w, acting: await agentKey(w) };
}

let keysUsed = 0;
/** The agent's request, decided: AED 2,000 to the first supplier by default, so it waits for approval. */
const ask = async (acting: AgentActing, w: World, overrides: Partial<SpendAskedByAgent> = {}) => {
  keysUsed += 1;
  const asked: SpendAskedByAgent = {
    amount: AED(200_000n),
    supplierId: w.suppliers[0] ?? '',
    fundingSourceId: w.source,
    orderReference: `INV-${String(keysUsed)}`,
    purpose: 'Printer paper',
    ...overrides,
  };
  const answer = await decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `expiry-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor) }),
    },
    asked,
    CORRELATION,
  );
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

const statusOf = (w: World, id: string) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await requestOf(tx, states, { orgId: w.org, id });
    return read.outcome === 'found' ? read.request.status : read.outcome;
  });

/** What the request holds: its reservation's state and whether its claim is released. */
const holdingsOf = (w: World, id: string) =>
  withTenant(app, w.org, async (tx) => {
    const reservation = await tx
      .selectFrom('limit_reservations.reservations')
      .select(['state', 'settled_at'])
      .where('request_id', '=', id)
      .executeTakeFirstOrThrow();
    const claim = await tx
      .selectFrom('spend_requests.order_claims')
      .select('released_at')
      .where('request_id', '=', id)
      .executeTakeFirstOrThrow();
    return { reservation: reservation.state, released: claim.released_at !== null };
  });

const spentOf = (w: World, acting: AgentActing) =>
  withTenant(app, w.org, async (tx) => {
    const { month } = await tx
      .selectFrom('limit_reservations.reservations')
      .select('month')
      .where('agent_id', '=', acting.agentId)
      .executeTakeFirstOrThrow();
    return monthSpent(tx, { agentId: acting.agentId, month });
  });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/**
 * 72 hours and a minute on (the decision's sealed time is the database's,
 * a moment after the clock's start), less `early`.
 */
const pastTheWait = (early = 0) => {
  clock.advanceBy(SEVENTY_TWO_HOURS + MINUTE - early);
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
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
  decisions = createSpendRequestDecisions({ database: app, keys, ids, clock, logger });
  expiryOf = (orgs, most) =>
    createRequestExpiry({
      list: orgs,
      database: app,
      keys,
      ids,
      clock,
      logger,
      ...(most !== undefined && { most }),
    });
});

describe('spend requests waiting for approval expired after 72 hours (D7)', () => {
  it('expires one waiting 72 hours, as the API’s, releasing its reservation and claim: the month and the order free again', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w, { orderReference: 'INV-72' });
    expect(waiting).toMatchObject({ decision: 'REQUIRE_APPROVAL', status: 'APPROVAL_REQUIRED' });
    expect(await spentOf(w, acting)).toBe(200_000n);
    pastTheWait();

    await expiryOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
    expect(await spentOf(w, acting)).toBe(0n);
    expect(lines('request_expiry.expired')).toEqual([expect.objectContaining({ orgId: w.org, requestId: waiting.id })]);
    const events = await shared.eventsAbout(w.org, waiting.id, SPEND_REQUESTS.subject);
    expect(events.at(-1)).toMatchObject({
      action: 'spend_request.expired',
      actorType: 'system',
      details: { statusFrom: 'APPROVAL_REQUIRED', statusTo: 'EXPIRED' },
    });
    // The same order may be asked for again, and the holdings check still finds everything as signed.
    const again = await ask(acting, w, { orderReference: 'inv-72' });
    expect(again.reasons).not.toContain('DUPLICATE_ORDER_REFERENCE');
    const checked = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }),
    );
    expect(checked).toMatchObject({ mismatched: 0, tampered: 0 });
  });

  it('leaves one not yet due, an allowed one and a denied one as they are', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    // To the other supplier, so the first's split total doesn't hold it for approval.
    const other = { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' };
    const allowed = await ask(acting, w, other);
    const denied = await ask(acting, w, { ...other, orderReference: allowed.orderReference });
    expect([allowed.decision, denied.decision]).toEqual(['ALLOW', 'DENY']);
    pastTheWait(2 * MINUTE);

    await expiryOf(only(w)).run();
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    clock.advanceBy(SEVENTY_TWO_HOURS);
    await expiryOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    expect(await statusOf(w, allowed.id)).toBe('APPROVED');
    expect(await statusOf(w, denied.id)).toBe('DENIED');
    expect(await holdingsOf(w, allowed.id)).toEqual({ reservation: 'HELD', released: false });
  });

  it('judges a request by its decision’s sealed time, not its row’s: one whose created_at was moved back past the app waits on', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.query(
        "update spend_requests.requests set created_at = created_at - interval '5 days' where id = $1",
        [waiting.id],
      );
    } finally {
      await owner.end();
    }
    // An hour on: a candidate by its row, five days old, but its decision only an hour old.
    clock.advanceBy(HOUR);

    await expiryOf(only(w)).run();

    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'HELD', released: false });
  });

  it('refuses a request tampered with past the app, and pages past it when it fills a page, expiring the one after (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const bad = await ask(acting, w);
    const good = await ask(acting, w);
    // Its seals stripped: still waiting by its row, but no longer its signed state.
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(bad.id);
    } finally {
      await owner.end();
    }
    pastTheWait();

    // A page of one: the tampered request (made first, so first by ID) fills it, and the run goes on past it.
    await expiryOf(only(w), 1).run();

    expect(lines('audit.integrity_failed')).not.toEqual([]);
    expect(await holdingsOf(w, bad.id)).toEqual({ reservation: 'HELD', released: false });
    expect(await statusOf(w, good.id)).toBe('EXPIRED');
  });

  it('expires its share of an organisation’s requests a run, the rest the next', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);
    pastTheWait();
    const job = expiryOf(only(w), 1);

    await job.run();
    expect([await statusOf(w, first.id), await statusOf(w, second.id)].sort()).toEqual([
      'APPROVAL_REQUIRED',
      'EXPIRED',
    ]);
    await job.run();
    expect([await statusOf(w, first.id), await statusOf(w, second.id)]).toEqual(['EXPIRED', 'EXPIRED']);
  });

  it('a run stopped expires nothing more', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    pastTheWait();

    await expiryOf(only(w)).run(AbortSignal.abort());
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  // ADR-006's order: the reservation and claim (11) before the audit head (12). A holder that takes them in that
  // order, as Phase 4's outcomes will, is waited for; were the expiry to sign first, the two would deadlock.
  for (const table of ['limit_reservations.reservations', 'spend_requests.order_claims'] as const) {
    it(`locks the request's ${table} before the audit head (forced: one holding it, then the head, is waited for)`, async () => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      pastTheWait();
      const trail = createAuditTrail({ keys, ids });
      const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
      const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
      const locking = withTenant(app, w.org, async (tx) => {
        await tx.selectFrom(table).select('id').where('request_id', '=', waiting.id).forNoKeyUpdate().execute();
        holding(undefined);
        await gate;
        await trail.record(tx, w.org, {
          actor: { type: 'system', id: 'request-expiry-test' },
          action: 'probe.locked',
          subject: { type: 'probe', id: ids.next(), version: 1 },
          details: {},
        });
      });
      await held;
      const running = within(20_000, expiryOf(only(w)).run(), 'the run');
      await waitUntilQueued(database.as('admin'), 1);
      open(undefined);

      await locking;
      await running;
      expect(lines('request_expiry.failed')).toEqual([]);
      expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    });
  }

  it('waits for a holdings check holding the request, then expires it (forced: no deadlock in the lock order)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    pastTheWait();
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // A page of the holdings check holds the request FOR SHARE (level 8) until the gate opens.
    const checking = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const read = await requestOf(tx, states, { orgId: w.org, id: waiting.id });
      if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
      holding(undefined);
      await gate;
      return checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 });
    });
    await held;
    const running = within(20_000, expiryOf(only(w)).run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    expect(await checking).toMatchObject({ mismatched: 0, tampered: 0 });
    await running;
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
  });

  it('logs a request it can’t expire and goes on to the next; expires both once it can', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);
    pastTheWait();
    // The app's right to lock and release claims taken away for the run, so every expiry fails at its claim's lock.
    const owner = await database.connect('owner');
    try {
      await owner.query('revoke update on spend_requests.order_claims from agentx_app');
      await expiryOf(only(w)).run();
    } finally {
      await owner.query('grant update (released_at) on spend_requests.order_claims to agentx_app');
      await owner.end();
    }
    expect(lines('request_expiry.failed').map(({ requestId }) => requestId)).toEqual([first.id, second.id]);
    expect([await statusOf(w, first.id), await statusOf(w, second.id)]).toEqual([
      'APPROVAL_REQUIRED',
      'APPROVAL_REQUIRED',
    ]);

    await expiryOf(only(w)).run();
    expect([await statusOf(w, first.id), await statusOf(w, second.id)]).toEqual(['EXPIRED', 'EXPIRED']);
  });

  it('logs an organisation whose waiting requests can’t be read, and goes on to the next organisation', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    pastTheWait();

    await expiryOf(() => Promise.resolve(['not-an-organisation', w.org])).run();

    expect(lines('request_expiry.unreadable')).toEqual([expect.objectContaining({ orgId: 'not-an-organisation' })]);
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
  });

  it('expireRequest answers what it found: one not yet due, one already moved on, or none of the organisation’s, is left as it is', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    clock.advanceBy(SEVENTY_TWO_HOURS - MINUTE);
    const expire = (id: string) =>
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        expireRequest(tx, states, { orgId: w.org, id }, clock.now()),
      );

    expect(await expire(waiting.id)).toEqual({ outcome: 'not_due' });
    expect(await expire(allowed.id)).toEqual({ outcome: 'not_open', status: 'APPROVED' });
    expect(await expire(ids.next())).toEqual({ outcome: 'missing' });
    expect(await holdingsOf(w, allowed.id)).toEqual({ reservation: 'HELD', released: false });
  });

  it('logs an organisation list that can’t be read as an error, which the integrity-runs alert counts, and expires nothing', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    pastTheWait();

    await expiryOf(() => Promise.reject(new Error('the directory is down'))).run();

    expect(lines('request_expiry.run_failed')).toEqual([expect.objectContaining({ level: 'error' })]);
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });
});
