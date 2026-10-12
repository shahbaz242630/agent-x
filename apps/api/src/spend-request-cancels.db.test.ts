// Phase 2 D8: cancelling a spend request before hand-off, on the real migrated
// schema as the app role (PRD §4.2, §7.2; ADR-006 §10–§11; partner decision
// 10). An admin cancels one waiting for approval and an approver an approved
// one, recorded as theirs: CANCELLED, the reservation and order claim
// released, the agent's month and the order free again, the holdings check
// still clean. The agent cancels its own, recorded as its own, but another
// agent's is NOT_FOUND. A developer or viewer is FORBIDDEN. Cancelled already
// is answered as it stands; denied or expired is REQUEST_NOT_CANCELLABLE; none
// of the organisation's is NOT_FOUND; one tampered with is INTEGRITY_FAILED.
// The key answers its own replay. A cancel waiting on an expiry that holds
// the request (forced) finds it expired.
import { withSignedStates } from '@agentx/core/modules/audit';
import {
  cancelRequest,
  checkHoldings,
  expireRequest,
  requestOf,
  SPEND_REQUESTS,
} from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type Member, refused, type World } from './mandate-world.helper.test.ts';
import {
  AGENT_CANCEL_OPERATION,
  CANCEL_OPERATION,
  createSpendRequestCancels,
  type SpendRequestCancels,
} from './spend-request-cancels.ts';
import {
  type AgentActing,
  createSpendRequestDecisions,
  type SpendRequestDecisions,
} from './spend-request-decisions.ts';
import { releasedPastTheApp, spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xd800_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000d8';

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let cancels: SpendRequestCancels;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'request-cancels',
  registry: () => registry,
  decisions: () => decisions,
});
const { quiet, ready, ask, statusOf, holdingsOf, spentOf, member, eventsAbout } = shared;

let keysUsed = 0;
/** The idempotency request, as the route makes it: the request's ID is in its address, so in its payload. */
const idempotent = (
  orgId: string,
  client: { readonly kind: 'user' | 'agent'; readonly id: string },
  operation: string,
  requestId: string,
  key?: string,
) => {
  keysUsed += 1;
  return {
    orgId,
    client,
    operation,
    key: key ?? `cancel-${String(keysUsed)}`,
    payload: JSON.stringify({ params: { id: requestId } }),
  };
};

/** The member's cancel, under a key of its own unless one is given. */
const byMember = (who: Member, requestId: string, key?: string) =>
  cancels.byMember(
    who,
    idempotent(who.orgId, { kind: 'user', id: who.userId }, CANCEL_OPERATION, requestId, key),
    requestId,
    CORRELATION,
  );

/** The agent's cancel. */
const byAgent = (acting: AgentActing, requestId: string) =>
  cancels.byAgent(
    acting,
    idempotent(acting.orgId, { kind: 'agent', id: acting.agentId }, AGENT_CANCEL_OPERATION, requestId),
    requestId,
    CORRELATION,
  );

/** The request's events, newest last. */
const eventsOf = (w: World, id: string) => eventsAbout(w.org, id, SPEND_REQUESTS.subject);

const cleanHoldings = (w: World) =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date());
  const logger = testLogger();
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({ database: app, keys, ids, clock, logger });
  cancels = createSpendRequestCancels({ database: app, keys, ids, clock, logger });
});

describe('cancelling a spend request before hand-off (D8)', () => {
  it('an admin cancels one waiting for approval, as theirs: its holdings released, the month and the order free again', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w, { orderReference: 'INV-C1' });
    expect(await spentOf(w, acting)).toBe(200_000n);

    expect(await byMember(w.admin, waiting.id)).toMatchObject({
      outcome: 'cancelled',
      request: { id: waiting.id, status: 'CANCELLED' },
    });
    expect(await statusOf(w, waiting.id)).toBe('CANCELLED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
    expect(await spentOf(w, acting)).toBe(0n);
    expect((await eventsOf(w, waiting.id)).at(-1)).toMatchObject({
      action: 'spend_request.cancelled',
      actorType: 'user',
      details: { statusFrom: 'APPROVAL_REQUIRED', statusTo: 'CANCELLED' },
    });
    const again = await ask(acting, w, { orderReference: 'inv-c1' });
    expect(again.reasons).not.toContain('DUPLICATE_ORDER_REFERENCE');
    expect(await cleanHoldings(w)).toMatchObject({ mismatched: 0, tampered: 0 });
  });

  it('an approver cancels an approved one', async () => {
    const { w, acting } = await ready();
    const approver = await member(w.org, 'approver');
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    expect(allowed.status).toBe('APPROVED');

    expect(await byMember(approver, allowed.id)).toMatchObject({ outcome: 'cancelled' });
    expect(await holdingsOf(w, allowed.id)).toEqual({ reservation: 'RELEASED', released: true });
  });

  it.each(['developer', 'viewer'] as const)('refuses a %s, and changes nothing', async (role) => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    expect(await byMember(await member(w.org, role), waiting.id)).toEqual(refused(403, 'FORBIDDEN'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('the agent cancels its own, as its own; another agent’s is NOT_FOUND and untouched', async () => {
    const { w, acting } = await ready();
    const mine = await ask(acting, w);
    const other = await shared.secondAgent(registry, w, { approvalThreshold: AED(100_000n) });
    const theirs = await ask(other, w);

    expect(await byAgent(acting, theirs.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await statusOf(w, theirs.id)).toBe('APPROVAL_REQUIRED');
    expect(await byAgent(acting, mine.id)).toMatchObject({ outcome: 'cancelled', request: { status: 'CANCELLED' } });
    expect((await eventsOf(w, mine.id)).at(-1)).toMatchObject({
      action: 'spend_request.cancelled',
      actorType: 'agent',
    });
    expect(await holdingsOf(w, mine.id)).toEqual({ reservation: 'RELEASED', released: true });
  });

  it('answers one cancelled already as it stands, recording nothing more: a brake pressed twice', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await byMember(w.admin, waiting.id);
    const events = (await eventsOf(w, waiting.id)).length;

    expect(await byAgent(acting, waiting.id)).toMatchObject({ outcome: 'cancelled', request: { status: 'CANCELLED' } });
    expect(await eventsOf(w, waiting.id)).toHaveLength(events);
  });

  it('refuses one denied or expired as REQUEST_NOT_CANCELLABLE, and one not the organisation’s as NOT_FOUND', async () => {
    const { w, acting } = await ready();
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    const denied = await ask(acting, w, {
      amount: AED(50_000n),
      supplierId: w.suppliers[1] ?? '',
      orderReference: allowed.orderReference,
    });
    const waiting = await ask(acting, w);
    clock.advanceBy(73 * 3_600_000);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      expireRequest(tx, states, { orgId: w.org, id: waiting.id }, clock.now()),
    );

    expect(await byMember(w.admin, denied.id)).toEqual(refused(409, 'REQUEST_NOT_CANCELLABLE'));
    expect(await byAgent(acting, waiting.id)).toEqual(refused(409, 'REQUEST_NOT_CANCELLABLE'));
    expect(await byMember(w.admin, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
  });

  it('refuses one tampered with past the app as INTEGRITY_FAILED, and changes nothing (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(waiting.id);
    } finally {
      await owner.end();
    }

    expect(await byMember(w.admin, waiting.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'HELD', released: false });
  });

  it('answers its key’s replay as before, and the key used for another request as a conflict', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);

    const once = await byMember(w.admin, first.id, 'cancel-once');
    expect(await byMember(w.admin, first.id, 'cancel-once')).toEqual(once);
    expect(await byMember(w.admin, second.id, 'cancel-once')).toEqual({ outcome: 'conflict' });
    expect(await statusOf(w, second.id)).toBe('APPROVAL_REQUIRED');
  });

  it.each(['claim', 'reservation'] as const)(
    'still cancels one whose %s was released past the app, raising the alarm and the hold rather than hiding it (G2)',
    async (what) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      await releasedPastTheApp(database, w.org, waiting.id, what);

      expect(await byAgent(acting, waiting.id)).toMatchObject({
        outcome: 'cancelled',
        request: { status: 'CANCELLED' },
      });
      const hold = await withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
      expect(hold).toMatchObject({ outcome: 'held' });
    },
  );

  it('ends one holding just what it was decided with, raising no alarm (G2)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    expect(await byAgent(acting, waiting.id)).toMatchObject({ outcome: 'cancelled' });
    const hold = await withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
    expect(hold).toMatchObject({ outcome: 'clear' });
  });

  it('waits for an expiry holding the request, then finds it expired (forced)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    clock.advanceBy(73 * 3_600_000);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const expiring = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const read = await requestOf(tx, states, { orgId: w.org, id: waiting.id }, 'change');
      if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
      holding(undefined);
      await gate;
      return expireRequest(tx, states, { orgId: w.org, id: waiting.id }, clock.now());
    });
    await held;
    const cancelling = within(20_000, byMember(w.admin, waiting.id), 'the cancel');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    expect(await expiring).toMatchObject({ outcome: 'ended', request: { id: waiting.id, status: 'EXPIRED' } });
    expect(await cancelling).toEqual(refused(409, 'REQUEST_NOT_CANCELLABLE'));
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
  });

  it('answers the request ended as it now stands, CANCELLED, to whoever cancels it in core', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    const ended = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, { orgId: w.org, id: waiting.id }, { kind: 'agent', agentId: w.agent }, clock.now()),
    );

    expect(ended).toMatchObject({ outcome: 'ended', request: { id: waiting.id, status: 'CANCELLED' } });
  });
});
