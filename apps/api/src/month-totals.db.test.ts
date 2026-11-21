// GM-1a (0110; Threat-Model R-15): an agent's monthly total kept as a signed
// running total, on the real migrated schema as the app role (ADR-012 §2;
// FX-TAMPER). The database's owner, holding the owner login but none of the
// app's keys, deleting, zeroing or releasing reservations no longer gives
// capacity back: an over-limit request is still refused. The total itself
// changed past the app (zeroed, rolled back, deleted, planted, swapped, pointed
// at another event) refuses every decision on it, raises the integrity alarm
// and holds the organisation. Endings and a brake's voids give capacity back
// to it; the holdings check holds it to its reservations; and an organisation
// made before GM-1a is refused busy until its cutover opens its months from
// its signed requests.
import { checkStatesWith, createAuditTrail, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import {
  CUTOVER_ACTION,
  CUTOVER_SUBJECT,
  givenBack,
  type LimitReservationsTables,
  MONTH_TOTALS,
  monthTotalId,
  monthTotalOf,
  WINDOWS_CUTOVER_ACTION,
  WINDOWS_CUTOVER_SUBJECT,
} from '@agentx/core/modules/limit-reservations';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  cancelRequest,
  cutOverMonthTotals,
  expireRequest,
  lockedTotalOf,
  rejectRequest,
  requestOf,
  settleCarried,
  SLOTS_CUTOVER_ACTION,
  SLOTS_CUTOVER_SUBJECT,
  SPEND_REQUESTS,
  type SpendRequestsTables,
  voidedWith,
  voidPendingOf,
} from '@agentx/core/modules/spend-requests';
import type { PaymentsTables } from '@agentx/core/modules/transactions';
import { createDigestLog, type DigestLog } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, type DatabaseTransaction } from '@agentx/platform/db';
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

import { createHoldingsCheck, CUTOVER_HOLD_OFF_MS } from './holdings-check.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';
import {
  type AgentActing,
  createSpendRequestDecisions,
  DECIDE_OPERATION,
  monthSpentWeighed,
  type SpendAskedByAgent,
  type SpendRequestDecisions,
  totalMadeMeanwhile,
} from './spend-request-decisions.ts';

type Tables = MandateWorldTables & SpendRequestsTables & LimitReservationsTables & PaymentsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0x0110_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-000000000110';
const MONTH = '2026-10';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'month-totals' });
const { world, quiet, agentKey, eventsAbout } = shared;

/** A world whose agent has a key and a mandate in force: its month's limit twice its per-order limit (`max`). */
async function ready(options: Parameters<typeof world>[0] = {}) {
  const w = await world(options);
  for (const id of w.suppliers) await shared.verified(w, id);
  // Under the organisation's suggested cap (AED 20,000), so the mandate's own month is the one reached.
  const max = 800_000n;
  await shared.inForce(registry, w, {
    perOrderLimit: AED(max),
    monthlyLimit: AED(2n * max),
    approvalThreshold: AED(max),
  });
  return { w, acting: await agentKey(w), max };
}

let keysUsed = 0;
/** To `supplierId` when given, else to the world's two suppliers by turns. */
const asking = (w: World, amount: bigint, supplierId?: string): SpendAskedByAgent => ({
  amount: AED(amount),
  supplierId: supplierId ?? w.suppliers[keysUsed % 2] ?? '',
  fundingSourceId: w.source,
  orderReference: `INV-${String(keysUsed)}`,
  purpose: 'Printer paper',
});
const ask = (acting: AgentActing, w: World, amount: bigint, supplierId?: string) => {
  keysUsed += 1;
  const asked = asking(w, amount, supplierId);
  return decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `total-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor), n: keysUsed }),
    },
    asked,
    CORRELATION,
  );
};
/** The decision a request was answered with. */
const decisionOf = async (acting: AgentActing, w: World, amount: bigint, supplierId?: string) => {
  const answer = await ask(acting, w, amount, supplierId);
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

const key = (w: World, agentId = w.agent) => ({ agentId, month: MONTH, currency: 'AED' });
const totalOf = (w: World, agentId = w.agent) =>
  withSignedStates(app, w.org, quiet(), (tx, states) => monthTotalOf(tx, states, w.org, key(w, agentId), 'share'));
const heldIn = async (w: World, agentId = w.agent) => {
  const total = await totalOf(w, agentId);
  return total.outcome === 'held' ? total.held : total.outcome;
};
const holdOf = (w: World) => withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const alarmedOn = (subjectType: string, reason: string) => {
  expect(lines('audit.integrity_failed')).toContainEqual(expect.objectContaining({ subjectType, reason }));
};

type Owner = Awaited<ReturnType<typeof tamperAsOwner>>;

/** The owner's statements in one transaction, inside the organisation, the user triggers of the limit tables off for them. */
async function asOwner(w: World, work: (owner: Owner) => Promise<unknown>) {
  const owner = await tamperAsOwner(database, MONTH_TOTALS, w.org);
  try {
    await owner.query('begin');
    await owner.query('alter table limit_reservations.reservations disable trigger user');
    await owner.query('alter table limit_reservations.agent_periods disable trigger user');
    await owner.query('alter table limit_reservations.month_totals disable trigger user');
    await work(owner);
    await owner.query('alter table limit_reservations.reservations enable trigger user');
    await owner.query('alter table limit_reservations.agent_periods enable trigger user');
    await owner.query('alter table limit_reservations.month_totals enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}
const totalTamper = async (w: World, work: (owner: Owner) => Promise<void>) => {
  const owner = await tamperAsOwner(database, MONTH_TOTALS, w.org);
  try {
    await work(owner);
  } finally {
    await owner.end();
  }
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
  clock = new FixedClock(new Date('2026-10-08T08:00:00Z'));
  capture = new LogCapture();
  const logger = testLogger(capture);
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock, keys }),
    keys,
    ids,
    clock,
    logger,
  });
});

describe("an agent's month total, signed (GM-1a)", () => {
  it("is made by the month's first decision and added to by each one holding capacity, each sealed", async () => {
    const { w, acting, max } = await ready();
    expect(await heldIn(w)).toBe('none');
    await decisionOf(acting, w, max / 2n);
    await decisionOf(acting, w, max / 4n);
    expect(await heldIn(w)).toBe(max / 2n + max / 4n);
    const events = await eventsAbout(w.org, monthTotalId(w.org, key(w)), MONTH_TOTALS.subject);
    expect(events.map(({ action }) => action)).toEqual(['month_total.held', 'month_total.held']);
    // Its own events go first in the decision's step of the chain, before the request's.
    expect(events[1]).toMatchObject({ actorType: 'agent' });
  });

  it('refuses a request over the limit as before, and holds nothing for a denied one', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max);
    await decisionOf(acting, w, max);
    const over = await decisionOf(acting, w, 1n);
    expect(over.decision).not.toBe('ALLOW');
    expect(await heldIn(w)).toBe(2n * max);
  });

  it.each<[string, (owner: Owner) => Promise<unknown>]>([
    ['deleted', (owner) => owner.query('delete from limit_reservations.reservations')],
    ['zeroed', (owner) => owner.query('update limit_reservations.reservations set amount_minor = 0')],
    [
      'released',
      (owner) => owner.query("update limit_reservations.reservations set state = 'RELEASED', settled_at = reserved_at"),
    ],
  ])(
    'R-15: still refuses an over-limit request once the owner has %s every reservation of the month',
    async (_what, change) => {
      const { w, acting, max } = await ready();
      await decisionOf(acting, w, max);
      await decisionOf(acting, w, max);
      await asOwner(w, change);

      expect((await decisionOf(acting, w, max)).decision).not.toBe('ALLOW');
      expect(await heldIn(w)).toBe(2n * max);
    },
  );

  it('is caught zeroed by its seal: every decision on it refused, alarmed, the organisation held', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max);
    await totalTamper(w, (owner) => owner.setColumn(monthTotalId(w.org, key(w)), 'held_minor', 0));

    expect(await ask(acting, w, max)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn(MONTH_TOTALS.subject, 'seal');
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('is caught rolled back to an older, validly signed state: its version is not the newest', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max / 2n);
    const id = monthTotalId(w.org, key(w));
    let saved: Awaited<ReturnType<Owner['saveRow']>> | undefined;
    await totalTamper(w, async (owner) => {
      saved = await owner.saveRow(id);
    });
    await decisionOf(acting, w, max);
    await totalTamper(w, (owner) => owner.restoreRow(saved ?? ({} as never)));

    expect(await ask(acting, w, max / 2n)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn(MONTH_TOTALS.subject, 'pointer');
  });

  it('is caught deleted: its events name it, so it never reads as a month with nothing held', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max);
    await totalTamper(w, (owner) => owner.deleteRow(monthTotalId(w.org, key(w))));

    expect(await ask(acting, w, max)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn(MONTH_TOTALS.subject, 'deleted');
  });

  it('is caught planted with no event of its own', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max);
    // Next month's total, planted at nothing before its first decision.
    clock.advanceBy(30 * 24 * 3_600_000);
    const next = { agentId: w.agent, month: '2026-11', currency: 'AED' };
    await asOwner(w, (owner) =>
      owner.query(
        'insert into limit_reservations.agent_periods (org_id, agent_id, month, created_at) values ($1, $2, $3, now())',
        [w.org, w.agent, next.month],
      ),
    );
    await asOwner(w, (owner) =>
      owner.query(
        "insert into limit_reservations.month_totals (org_id, id, agent_id, month, currency, held_minor, created_at) values ($1, $2, $3, $4, 'AED', 0, now())",
        [w.org, monthTotalId(w.org, next), w.agent, next.month],
      ),
    );

    expect(await ask(acting, w, max)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn(MONTH_TOTALS.subject, 'unsigned');
  });

  it("is caught swapped with another agent's, each signed: the seal names its own object", async () => {
    const { w, acting, max } = await ready();
    const theirs = await shared.secondAgent(registry, w);
    await decisionOf(acting, w, max);
    await decisionOf(theirs, w, 1n);
    const mine = monthTotalId(w.org, key(w));
    const other = monthTotalId(w.org, key(w, theirs.agentId));
    await asOwner(w, (owner) =>
      owner.query(
        'update limit_reservations.month_totals t set held_minor = o.held_minor, state_version = o.state_version, state_event_id = o.state_event_id from limit_reservations.month_totals o where t.id = $1 and o.id = $2',
        [mine, other],
      ),
    );

    expect(await ask(acting, w, max)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn(MONTH_TOTALS.subject, 'pointer');
  });

  it('is caught pointed at a forged event ID', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max);
    await totalTamper(w, (owner) =>
      owner.setColumn(monthTotalId(w.org, key(w)), 'state_event_id', '0199a0f0-0000-7000-8000-00000000f0f0'),
    );

    expect(await ask(acting, w, max)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn(MONTH_TOTALS.subject, 'pointer');
  });
});

describe("the total's own rules", () => {
  it('is named apart for each organisation, agent, month and currency (G4: a cap is in one currency)', () => {
    const named = { agentId: '0199a0f0-0000-7000-8000-00000000a001', month: MONTH, currency: 'AED' };
    const org = '0199a0f0-0000-7000-8000-00000000b001';
    const id = monthTotalId(org, named);
    expect(monthTotalId(org, named)).toBe(id);
    expect(monthTotalId(org, { ...named, currency: 'USD' })).not.toBe(id);
    expect(monthTotalId(org, { ...named, month: '2026-11' })).not.toBe(id);
    expect(monthTotalId(org, { ...named, agentId: '0199a0f0-0000-7000-8000-00000000a002' })).not.toBe(id);
    expect(monthTotalId('0199a0f0-0000-7000-8000-00000000b002', named)).not.toBe(id);
  });

  /** `amount` given back to the agent's month, as an ending gives it. */
  const giveBack = (w: World, amount: bigint) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const total = await monthTotalOf(tx, states, w.org, key(w), 'change');
      await givenBack(
        tx,
        states,
        w.org,
        { key: key(w), total, amount },
        {
          at: clock.now(),
          change: { actor: { type: 'system', id: 'test' }, action: 'month_total.released', details: {} },
        },
      );
    });

  it('gives back no more than it holds: past it, nothing held, and the mismatch alarmed', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max / 2n);
    await giveBack(w, max);
    expect(await heldIn(w)).toBe(0n);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: MONTH_TOTALS.subject });
  });

  it('alarms a give-back to a month with no total once cut over, and gives nothing back before', async () => {
    const { w } = await ready();
    await giveBack(w, 1n);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: MONTH_TOTALS.subject });

    const before = await ready({ madeBeforeMonthTotals: true });
    await giveBack(before.w, 1n);
    expect(await holdOf(before.w)).toMatchObject({ outcome: 'clear' });
    expect(await heldIn(before.w)).toBe('none');
  });

  it('finds no total to give back to for a request holding none: denied by its decision, or not there', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max);
    await decisionOf(acting, w, max);
    const denied = await decisionOf(acting, w, max);
    expect(denied.decision).not.toBe('ALLOW');
    const lockedOf = (id: string) =>
      withSignedStates(app, w.org, quiet(), (tx, states) => lockedTotalOf(tx, states, { orgId: w.org, id }, 'share'));
    expect(await lockedOf(denied.id)).toBeNull();
    expect(await lockedOf('0199a0f0-0000-7000-8000-00000000dead')).toBeNull();
  });

  /** What an approval or a carry weighs the agent's month at, `own` theirs. */
  const spentFor = (w: World, own: bigint) =>
    withSignedStates(app, w.org, quiet(), (tx, states) =>
      monthSpentWeighed(tx as never, states, w.org, key(w), 'share', own),
    );

  it('weighs a month again less what the requests weighed hold there, refusing a total holding less', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max / 2n);
    expect(await spentFor(w, max / 4n)).toBe(max / 4n);
    await expect(spentFor(w, max)).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' });
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: MONTH_TOTALS.subject });
  });

  it('weighs a month with no total at nothing once cut over, refusing it where requests weighed hold capacity, busy before', async () => {
    const { w } = await ready();
    expect(await spentFor(w, 0n)).toBe(0n);
    await expect(spentFor(w, 1n)).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' });
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: MONTH_TOTALS.subject });
    const before = await ready({ madeBeforeMonthTotals: true });
    await expect(spentFor(before.w, 0n)).rejects.toMatchObject({ code: 'ORGANISATION_BUSY' });
  });
});

describe('capacity given back to the total', () => {
  it("by a brake's voids: once a total, however many of its requests, across agents", async () => {
    const { w, acting, max } = await ready();
    const theirs = await shared.secondAgent(registry, w);
    await decisionOf(acting, w, max / 2n);
    await decisionOf(acting, w, max / 4n);
    await decisionOf(theirs, w, max / 2n);

    const voided = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      voidPendingOf(tx, states, keys, w.org, { organizationId: w.org }, 'ORG_FROZEN', clock.now()),
    );
    expect(voided).toBe(3);
    expect(await heldIn(w)).toBe(0n);
    expect(await heldIn(w, theirs.agentId)).toBe(0n);
    const released = (await eventsAbout(w.org, monthTotalId(w.org, key(w)), MONTH_TOTALS.subject)).filter(
      ({ action }) => action === 'month_total.released',
    );
    expect(released).toHaveLength(1);
    expect(await holdOf(w)).toMatchObject({ outcome: 'clear' });
  });

  it('by a void of one request: its own amount alone', async () => {
    const { w, acting, max } = await ready();
    const first = await decisionOf(acting, w, max / 2n);
    await decisionOf(acting, w, max / 4n);
    await withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await requestOf(tx, states, { orgId: w.org, id: first.id }, 'change');
      await voidedWith(tx, states, keys, { orgId: w.org, id: first.id }, ['AGENT_SUSPENDED'], clock.now());
    });
    expect(await heldIn(w)).toBe(max / 4n);
  });
});

describe("two brakes over the same totals, in the totals' ID order, forced", () => {
  it('makes a brake take the lower total first and wait for the higher, and a second brake wait for it: neither deadlocks', async () => {
    const { w, acting, max } = await ready();
    const theirs = await shared.secondAgent(registry, w);
    const [first = '', second = ''] = w.suppliers;
    // Each agent holds capacity to both suppliers: each supplier's brake voids a request in each agent's month.
    for (const agent of [acting, theirs]) {
      await decisionOf(agent, w, max / 4n, first);
      await decisionOf(agent, w, max / 4n, second);
    }
    const [low = '', high = ''] = [monthTotalId(w.org, key(w)), monthTotalId(w.org, key(w, theirs.agentId))].toSorted();
    const highAgent = high === monthTotalId(w.org, key(w)) ? w.agent : theirs.agentId;

    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The higher total held for change, as a decision holds it with its month.
    const holder = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await monthTotalOf(tx, states, w.org, key(w, highAgent), 'change');
      holding(undefined);
      await gate;
    });
    await held;
    const brake = (supplierId: string) =>
      within(
        20_000,
        withSignedStates(app, w.org, quiet(), (tx, states) =>
          voidPendingOf(tx, states, keys, w.org, { supplierId }, 'SUPPLIER_NOT_VERIFIED', clock.now()),
        ),
        `the brake on ${supplierId}`,
      );
    const one = brake(first);
    await waitUntilQueued(database.as('admin'), 1);
    // It holds the lower total already, waiting only for the higher.
    await expect(
      database
        .as('admin')
        .query('select 1 from limit_reservations.month_totals where id = $1 for no key update nowait', [low]),
    ).rejects.toMatchObject({ code: '55P03' });
    const other = brake(second);
    // The second waits for the lower total, behind the first: never holding one the first waits for.
    await waitUntilQueued(database.as('admin'), 2);
    open(undefined);
    await holder;

    expect(await one).toBe(2);
    expect(await other).toBe(2);
    expect(await heldIn(w)).toBe(0n);
    expect(await heldIn(w, theirs.agentId)).toBe(0n);
  });
});

describe('in the lock order (11a: after a request and its reservation, before the head), forced', () => {
  /** A void of `requestId` in a transaction of its own, held open at `gate` once it has given its capacity back. */
  const voidHeldOpen = (w: World, requestId: string, gate: Promise<unknown>, given: () => void) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await requestOf(tx, states, { orgId: w.org, id: requestId }, 'change');
      await voidedWith(tx, states, keys, { orgId: w.org, id: requestId }, ['AGENT_SUSPENDED'], clock.now());
      given();
      await gate;
    });

  it("makes a decision wait for an ending holding its month's total, then weighs the capacity given back", async () => {
    const { w, acting, max } = await ready();
    const first = await decisionOf(acting, w, max);
    await decisionOf(acting, w, max);
    const { promise: given, resolve: giving } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const voiding = voidHeldOpen(w, first.id, gate, () => {
      giving(undefined);
    });
    await given;
    const deciding = within(20_000, decisionOf(acting, w, max), 'the decision');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await voiding;

    // Full before the void: weighed after it, against the total it gave back to. Its payee's window, read behind the
    // total's lock since GM-1b, no longer counts the voided request either: allowed, capacity held.
    expect((await deciding).decision).toBe('ALLOW');
    expect(await heldIn(w)).toBe(2n * max);
  });

  it('makes an ending take its request (8) and reservation (11) before it waits for the total (11a)', async () => {
    const { w, acting, max } = await ready();
    const first = await decisionOf(acting, w, max);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The month's total held for change, as a decision holds it with its month.
    const holder = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await monthTotalOf(tx, states, w.org, key(w), 'change');
      holding(undefined);
      await gate;
    });
    await held;
    const voiding = within(
      20_000,
      voidHeldOpen(w, first.id, Promise.resolve(), () => undefined),
      'the void',
    );
    await waitUntilQueued(database.as('admin'), 1);
    const admin = database.as('admin');
    await expect(
      admin.query('select 1 from spend_requests.requests where id = $1 for no key update nowait', [first.id]),
    ).rejects.toMatchObject({ code: '55P03' });
    await expect(
      admin.query('select 1 from limit_reservations.reservations where request_id = $1 for no key update nowait', [
        first.id,
      ]),
    ).rejects.toMatchObject({ code: '55P03' });
    open(undefined);
    await holder;
    await voiding;
    expect(await heldIn(w)).toBe(0n);
  });
});

describe('the holdings check, every reservation gone', () => {
  it('counts a total tampered with apart, its read raising the alarm', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max / 2n);
    await totalTamper(w, (owner) => owner.setColumn(monthTotalId(w.org, key(w)), 'held_minor', 0));
    await createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run();
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ totals: 1, totalsTampered: 1, totalsMismatched: 0 });
  });

  it('finds a total whose month holds no reservation at all a mismatch', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max / 2n);
    await asOwner(w, (owner) => owner.query('delete from limit_reservations.reservations'));
    await createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run();
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ totals: 1, totalsMismatched: 1 });
  });
});

describe('the holdings check', () => {
  it('holds each total to its reservations: a reservation deleted past the app is a mismatch, alarmed', async () => {
    const { w, acting, max } = await ready();
    const first = await decisionOf(acting, w, max / 2n);
    await decisionOf(acting, w, max / 4n);
    const check = () =>
      createHoldingsCheck({
        list: () => Promise.resolve([w.org]),
        database: app,
        keys,
        ids,
        logger: testLogger(capture),
      }).run();
    await check();
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ totals: 1, totalsMismatched: 0 });

    await asOwner(w, (owner) =>
      owner.query('delete from limit_reservations.reservations where request_id = $1', [first.id]),
    );
    await check();
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ totals: 1, totalsMismatched: 1 });
    alarmedOn(MONTH_TOTALS.subject, 'holding');
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });
});

describe('an organisation made before GM-1a, until its cutover', () => {
  /**
   * Its cutover event, as the job records it: here so it can decide, then taken away again as before GM-1a. The
   * payee windows' too (GM-1b), and the order slots' (TR-2), which stay: these tests are the month totals'.
   */
  const cutOverByHand = (w: World) =>
    withSignedStates(app, w.org, quiet(), async (tx) => {
      const trail = createAuditTrail({ keys, ids });
      for (const [action, type] of [
        [CUTOVER_ACTION, CUTOVER_SUBJECT],
        [WINDOWS_CUTOVER_ACTION, WINDOWS_CUTOVER_SUBJECT],
        [SLOTS_CUTOVER_ACTION, SLOTS_CUTOVER_SUBJECT],
      ] as const) {
        await trail.record(tx, w.org, {
          actor: { type: 'system', id: 'test' },
          action,
          subject: { type, id: w.org, version: 1 },
          details: {},
        });
      }
    });
  /**
   * The organisation as one before GM-1a with capacity held: the totals its decisions made, their events and the
   * cutover's taken away by the owner, its reservations and signed requests left.
   */
  const asBeforeGm1a = async (w: World, agents: readonly string[]) => {
    const owner = await tamperAsOwner(database, MONTH_TOTALS, w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table audit.events disable trigger user');
      for (const agentId of agents) {
        const id = monthTotalId(w.org, key(w, agentId));
        await owner.query('delete from limit_reservations.month_totals where org_id = $1 and id = $2', [w.org, id]);
        await owner.query('delete from audit.events where org_id = $1 and subject_type = $2 and subject_id = $3', [
          w.org,
          MONTH_TOTALS.subject,
          id,
        ]);
      }
      await owner.query('delete from audit.events where org_id = $1 and action = $2', [w.org, CUTOVER_ACTION]);
      await owner.query('alter table audit.events enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }
  };
  const visit = (w: World) =>
    createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      clock,
      cutoverHoldOffMs: 0,
    }).run();

  it('is refused busy, never weighed from its reservations, until its cutover, with nothing to open', async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    expect(await ask(acting, w, max)).toEqual(refused(503, 'ORGANISATION_BUSY'));
    await visit(w);
    expect(lines('month_totals.cut_over')).toEqual([expect.objectContaining({ opened: 0, mismatched: 0 })]);
    expect(['ALLOW', 'REQUIRE_APPROVAL']).toContain((await decisionOf(acting, w, max)).decision);
  });

  it('is not cut over over a total planted before it, nor over a request that cannot be believed', async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    await cutOverByHand(w);
    await decisionOf(acting, w, max);
    await asBeforeGm1a(w, [w.agent]);
    // A total planted where the opening will look: unsigned.
    await asOwner(w, (owner) =>
      owner.query(
        "insert into limit_reservations.month_totals (org_id, id, agent_id, month, currency, held_minor, created_at) values ($1, $2, $3, $4, 'AED', 0, now())",
        [w.org, monthTotalId(w.org, key(w)), w.agent, MONTH],
      ),
    );
    await visit(w);
    expect(lines('month_totals.cutover_held')).toHaveLength(1);
    expect(lines('month_totals.cut_over')).toEqual([]);

    const other = await ready({ madeBeforeMonthTotals: true });
    await cutOverByHand(other.w);
    const theirs = await decisionOf(other.acting, other.w, max);
    await asBeforeGm1a(other.w, [other.w.agent]);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, other.w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table spend_requests.requests disable trigger user');
      await owner.setColumn(theirs.id, 'purpose', 'changed');
      await owner.query('alter table spend_requests.requests enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }
    await visit(other.w);
    expect(lines('month_totals.cutover_held')).toHaveLength(2);
  });

  it("counts nothing for a handed-off request whose payment ended (as the outcomes module's reader says)", async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    await cutOverByHand(w);
    const ended = await decisionOf(acting, w, max);
    await decisionOf(acting, w, max / 2n);
    await asBeforeGm1a(w, [w.agent]);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cutOverMonthTotals(tx as never, states, w.org, {
        payments: () => Promise.resolve(new Map([[ended.id, 'ended' as const]])),
        record: (event) => createAuditTrail({ keys, ids }).record(tx, w.org, event),
        at: clock.now(),
      }),
    );
    expect(await heldIn(w)).toBe(max / 2n);
  });

  it("is cut over at the holdings check's first visit, each month held opened from the signed requests", async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    const theirs = await shared.secondAgent(registry, w);
    await cutOverByHand(w);
    await decisionOf(acting, w, max);
    await decisionOf(acting, w, max / 2n);
    await decisionOf(theirs, w, max / 4n);
    await asBeforeGm1a(w, [w.agent, theirs.agentId]);
    expect(await ask(acting, w, 1n)).toEqual(refused(503, 'ORGANISATION_BUSY'));

    await visit(w);
    expect(lines('month_totals.cut_over')).toEqual([expect.objectContaining({ opened: 2, mismatched: 0 })]);
    expect(await heldIn(w)).toBe(max + max / 2n);
    expect(await heldIn(w, theirs.agentId)).toBe(max / 4n);
    expect(
      (await eventsAbout(w.org, monthTotalId(w.org, key(w)), MONTH_TOTALS.subject)).map(({ action }) => action),
    ).toEqual(['month_total.opened']);
    // Counted from then on: the month is full at twice `max`.
    expect((await decisionOf(acting, w, max)).decision).not.toBe('ALLOW');
    expect((await decisionOf(acting, w, max / 2n)).decision).toBe('ALLOW');
    expect(await holdOf(w)).toMatchObject({ outcome: 'clear' });
    // A second visit finds it cut over already.
    await visit(w);
    expect(lines('month_totals.cut_over')).toHaveLength(1);
  });

  it('opens from the signed requests even where the owner cut the reservations, the mismatch alarmed', async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    await cutOverByHand(w);
    await decisionOf(acting, w, max);
    await decisionOf(acting, w, max);
    await asBeforeGm1a(w, [w.agent]);
    await asOwner(w, (owner) => owner.query('delete from limit_reservations.reservations'));

    await visit(w);
    expect(lines('month_totals.cut_over')).toEqual([expect.objectContaining({ opened: 1, mismatched: 1 })]);
    expect(await heldIn(w)).toBe(2n * max);
    alarmedOn(MONTH_TOTALS.subject, 'holding');
  });

  it('counts nothing for a request ended before it', async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    await cutOverByHand(w);
    const first = await decisionOf(acting, w, max);
    await decisionOf(acting, w, max / 2n);
    await withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await requestOf(tx, states, { orgId: w.org, id: first.id }, 'change');
      await voidedWith(tx, states, keys, { orgId: w.org, id: first.id }, ['AGENT_SUSPENDED'], clock.now());
    });
    await asBeforeGm1a(w, [w.agent]);

    await visit(w);
    expect(await heldIn(w)).toBe(max / 2n);
  });

  /** The organisation's cutover events: none while it is refused. */
  const cutoverEvents = async (w: World) =>
    (await eventsAbout(w.org, w.org, CUTOVER_SUBJECT)).filter(({ action }) => action === CUTOVER_ACTION);

  /**
   * An organisation before GM-1a holding one approved request: its newest signed state the approval's, so its decided
   * event can be changed or moved with its row still verifying, and only the cutover's reading of decisions sees it.
   */
  const approvedBeforeGm1a = async () => {
    const w = await world({ madeBeforeMonthTotals: true });
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry, w, {
      perOrderLimit: AED(800_000n),
      monthlyLimit: AED(1_600_000n),
      approvalThreshold: AED(100_000n),
    });
    const acting = await agentKey(w);
    await cutOverByHand(w);
    const approved = await decisionOf(acting, w, 400_000n);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, SPEND_REQUESTS, { orgId: w.org, id: approved.id }, 'approve', {
        actor: { type: 'system', id: 'test' },
        action: 'spend_request.approved',
        details: {},
      }),
    );
    await asBeforeGm1a(w, [w.agent]);
    return { w, approved };
  };

  it('refuses a cutover over a decision the owner edited: nothing opened, no cutover recorded, alarmed and held', async () => {
    const { w, approved: edited } = await approvedBeforeGm1a();
    await asOwner(w, async (owner) => {
      await owner.query('alter table audit.events disable trigger user');
      await owner.query(
        "update audit.events set details = pg_catalog.replace(details, '\"heldMonth\"', '\"heldMonthX\"') where subject_id = $1 and action = 'spend_request.decided'",
        [edited.id],
      );
      await owner.query('alter table audit.events enable trigger user');
    });

    await visit(w);
    expect(lines('month_totals.cut_over')).toEqual([]);
    expect(lines('month_totals.cutover_held')).toHaveLength(1);
    expect(await cutoverEvents(w)).toEqual([]);
    expect(await heldIn(w)).toBe('none');
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
    // Refused by the decisions' read itself (their log not believed), not by reading them as absent.
    alarmedOn('organisation', 'log');
    expect(lines('audit.integrity_failed')).not.toContainEqual(
      expect.objectContaining({ subjectType: SPEND_REQUESTS.subject, reason: 'holding' }),
    );
  });

  it('refuses a cutover over a request still holding with no decision at all, its log otherwise whole', async () => {
    const { w, approved } = await approvedBeforeGm1a();
    // Its decided event moved off to a subject type nothing reads as a spend request's.
    await asOwner(w, async (owner) => {
      await owner.query('alter table audit.events disable trigger user');
      await owner.query(
        "update audit.events set subject_type = 'spend_request_elsewhere' where subject_id = $1 and action = 'spend_request.decided'",
        [approved.id],
      );
      await owner.query('alter table audit.events enable trigger user');
    });

    await visit(w);
    expect(lines('month_totals.cutover_held')).toHaveLength(1);
    expect(await cutoverEvents(w)).toEqual([]);
    alarmedOn(SPEND_REQUESTS.subject, 'holding');
  });

  it('refuses a cutover over a request still holding whose decision was deleted', async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    await cutOverByHand(w);
    const bare = await decisionOf(acting, w, max);
    await asBeforeGm1a(w, [w.agent]);
    await asOwner(w, async (owner) => {
      await owner.query('alter table audit.events disable trigger user');
      await owner.query("delete from audit.events where subject_id = $1 and action = 'spend_request.decided'", [
        bare.id,
      ]);
      await owner.query('alter table audit.events enable trigger user');
    });

    await visit(w);
    expect(lines('month_totals.cutover_held')).toHaveLength(1);
    expect(await cutoverEvents(w)).toEqual([]);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('leaves a request decided before E1 (its decision sealing no month) out of the totals and the reservations alike', async () => {
    const { w, acting, max } = await ready({ madeBeforeMonthTotals: true });
    await cutOverByHand(w);
    const legacy = await decisionOf(acting, w, max);
    await decisionOf(acting, w, max / 2n);
    await asBeforeGm1a(w, [w.agent]);
    // Its newest decided event as one made before E1: no month, no instant (the app's own keys, as the log's).
    await withSignedStates(app, w.org, quiet(), (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: { type: 'system', id: 'api' },
        action: 'spend_request.decided',
        subject: { type: SPEND_REQUESTS.subject, id: legacy.id, version: 2 },
        details: {},
      }),
    );

    await visit(w);
    expect(lines('month_totals.cut_over')).toEqual([expect.objectContaining({ opened: 1, mismatched: 0 })]);
    expect(await heldIn(w)).toBe(max / 2n);
    // And on every pass after, no alarm for its reservation (decision 49).
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ totalsMismatched: 0, totalsMissing: 0 });
    // Its payee's windows were filled by the GM-1b decision that made it here, which a decision before E1 never was:
    // their alarm is this test's making, not the totals'.
    expect(lines('audit.integrity_failed').filter(({ subjectType }) => subjectType !== 'payee_window')).toEqual([]);
  });

  it('logs a cutover that fails and goes on, the hold-off waited by its own timer', async () => {
    // Not an organisation's ID at all: its transaction refused before anything is read.
    await createHoldingsCheck({
      list: () => Promise.resolve(['not an organisation']),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      cutoverHoldOffMs: 5,
    }).run();
    expect(lines('month_totals.cutover_failed')).toHaveLength(1);
  });

  it('cuts nothing over when stopped during the hold-off: the next run does', async () => {
    const old = await ready({ madeBeforeMonthTotals: true });
    const stop = new AbortController();
    const check = createHoldingsCheck({
      list: () => Promise.resolve([old.w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      clock,
      // The process told to stop while it waits.
      wait: () => {
        stop.abort();
        return Promise.resolve();
      },
    });
    await check.run(stop.signal);
    expect(lines('month_totals.cut_over')).toEqual([]);
    expect(await ask(old.acting, old.w, 1n)).toEqual(refused(503, 'ORGANISATION_BUSY'));

    await check.run();
    expect(lines('month_totals.cut_over')).toHaveLength(1);
  });

  it('waits out the hold-off once, at its first run, before cutting any organisation over; none for one cut over', async () => {
    const waits: number[] = [];
    const check = (w: World) =>
      createHoldingsCheck({
        list: () => Promise.resolve([w.org]),
        database: app,
        keys,
        ids,
        logger: testLogger(capture),
        clock,
        wait: (ms) => {
          waits.push(ms);
          return Promise.resolve();
        },
      });
    const born = await ready();
    await check(born.w).run();
    expect(waits).toEqual([]);

    const old = await ready({ madeBeforeMonthTotals: true });
    const job = check(old.w);
    await job.run();
    expect(waits).toEqual([CUTOVER_HOLD_OFF_MS]);
    expect(lines('month_totals.cut_over')).toHaveLength(1);
    expect(CUTOVER_HOLD_OFF_MS).toBeGreaterThan(25_000);
  });
});

describe('a decision racing a total made meanwhile, forced', () => {
  it('is answered busy, never a 500, when the total its month read empty is made before it adds its own', async () => {
    const { w, acting, max } = await ready();
    // Its zone kept by a first decision; then next month: its period there, its total not yet.
    await decisionOf(acting, w, max / 4n);
    clock.advanceBy(30 * 24 * 3_600_000);
    const next = { agentId: w.agent, month: '2026-11', currency: 'AED' };
    await asOwner(w, (owner) =>
      owner.query(
        'insert into limit_reservations.agent_periods (org_id, agent_id, month, created_at) values ($1, $2, $3, now())',
        [w.org, w.agent, next.month],
      ),
    );
    const { promise: inserted, resolve: inserting } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // Another's total for the month, inserted and not yet committed, as a cutover's would be.
    const maker = withSignedStates(app, w.org, quiet(), async (tx) => {
      await tx
        .insertInto('limit_reservations.month_totals')
        .values({
          org_id: w.org,
          id: monthTotalId(w.org, next),
          agent_id: w.agent,
          month: next.month,
          currency: 'AED',
          held_minor: 0n,
          created_at: clock.now(),
        })
        .execute();
      inserting(undefined);
      await gate;
    });
    await inserted;
    const deciding = within(20_000, ask(acting, w, max / 4n), 'the decision');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await maker;
    // Its key taken by the time it adds its own: busy, so the agent asks again and is weighed against that total.
    expect(await deciding).toEqual(refused(503, 'ORGANISATION_BUSY'));
  });

  it('maps the total key taken to ORGANISATION_BUSY, any other error as it was', () => {
    const taken = Object.assign(new Error('duplicate key'), { code: '23505', constraint: 'month_totals_pkey' });
    expect(totalMadeMeanwhile(taken)).toMatchObject({ status: 503, code: 'ORGANISATION_BUSY' });
    const byMonth = Object.assign(new Error('duplicate key'), { code: '23505', constraint: 'one_total_a_month' });
    expect(totalMadeMeanwhile(byMonth)).toMatchObject({ code: 'ORGANISATION_BUSY' });
    const other = Object.assign(new Error('duplicate key'), { code: '23505', constraint: 'one_reservation_a_request' });
    expect(totalMadeMeanwhile(other)).toBe(other);
    expect(totalMadeMeanwhile(null)).toBeNull();
  });
});

describe('AT13f: a month’s total made above the last anchor, cut off with the chain’s end', () => {
  type SavedHead = Awaited<ReturnType<Owner['saveHead']>>;
  const headOf = async (w: World): Promise<SavedHead> => {
    const saved: SavedHead[] = [];
    await totalTamper(w, async (owner) => {
      saved.push(await owner.saveHead());
    });
    const [head] = saved;
    if (head === undefined) throw new Error('The owner should have found the head');
    return head;
  };

  /**
   * The owner cuts the chain's end since `saved` off: its events, an earlier sealed head put back, and every row they
   * named as if never made (the month's total, the payee's windows, the requests and their reservations). Every seal
   * left is true and no event is missing between the anchor and the head.
   */
  const cutBack = (w: World, saved: SavedHead) =>
    asOwner(w, async (owner) => {
      const named = await owner.query<{ type: string; id: string }>(
        'select distinct subject_type as type, subject_id::text as id from audit.events where org_id = $1 and seq > $2::bigint',
        [w.org, saved.seq],
      );
      const of = (type: string) => named.filter((one) => one.type === type).map((one) => one.id);
      await owner.query('alter table audit.events disable trigger user');
      await owner.query('alter table limit_reservations.payee_windows disable trigger user');
      await owner.query('alter table spend_requests.requests disable trigger user');
      await owner.query('delete from limit_reservations.month_totals where org_id = $1 and id = any($2::uuid[])', [
        w.org,
        of(MONTH_TOTALS.subject),
      ]);
      await owner.query('delete from limit_reservations.payee_windows where org_id = $1 and id = any($2::uuid[])', [
        w.org,
        of('payee_window'),
      ]);
      await owner.query(
        'delete from limit_reservations.reservations where org_id = $1 and request_id = any($2::uuid[])',
        [w.org, of(SPEND_REQUESTS.subject)],
      );
      await owner.query('delete from spend_requests.order_claims where org_id = $1 and request_id = any($2::uuid[])', [
        w.org,
        of(SPEND_REQUESTS.subject),
      ]);
      await owner.query('delete from spend_requests.requests where org_id = $1 and id = any($2::uuid[])', [
        w.org,
        of(SPEND_REQUESTS.subject),
      ]);
      // The agent's time zone, made with its first reservation, and the months locked under it.
      await owner.query('alter table limit_reservations.agent_zones disable trigger user');
      await owner.query(
        'delete from limit_reservations.agent_periods where org_id = $1 and agent_id = any($2::uuid[])',
        [w.org, of('agent_zone')],
      );
      await owner.query('delete from limit_reservations.agent_zones where org_id = $1 and id = any($2::uuid[])', [
        w.org,
        of('agent_zone'),
      ]);
      await owner.query('alter table limit_reservations.agent_zones enable trigger user');
      await owner.windBack(saved);
      await owner.query('alter table spend_requests.requests enable trigger user');
      await owner.query('alter table limit_reservations.payee_windows enable trigger user');
      await owner.query('alter table audit.events enable trigger user');
    });

  /** A digest as the process that keeps the anchors keeps one, every signed state read here held to it in `work`. */
  async function heldToADigest<T>(work: (digest: DigestLog) => Promise<T>): Promise<T> {
    const digest = createDigestLog({
      keys,
      logger: testLogger(capture),
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 64 * 1024 * 1024,
    });
    checkStatesWith(digest);
    try {
      return await work(digest);
    } finally {
      checkStatesWith(undefined);
    }
  }

  it('the positive control: read without the heads seen, the month reads as nothing held and its limit passes again', async () => {
    const { w, acting, max } = await ready();
    const saved = await headOf(w);
    const first = await decisionOf(acting, w, max);
    await decisionOf(acting, w, max);
    expect((await decisionOf(acting, w, 1n)).decision).not.toBe('ALLOW');
    expect(await heldIn(w)).toBe(2n * max);
    await cutBack(w, saved);

    // The month's total gone with its events: none, read as nothing held, so a third request of the month's limit holds.
    expect(await heldIn(w)).toBe('none');
    expect((await decisionOf(acting, w, max)).decision).toBe(first.decision);
    expect(await heldIn(w)).toBe(max);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('R-15: with the head seen, a decision on the month cut off is refused, the alarm at that head, the organisation held', async () => {
    const { w, seenAt } = await heldToADigest(async (digest) => {
      const { w, acting, max } = await ready();
      const saved = await headOf(w);
      await decisionOf(acting, w, max);
      await decisionOf(acting, w, max);
      // Any read of the chain since (the hand-off's, a list's, the next decision's): the head it read is seen here.
      expect(await heldIn(w)).toBe(2n * max);
      const seen = digest.heads({ kind: 'organisation', orgId: w.org })?.seen?.seq;
      await cutBack(w, saved);

      expect(await ask(acting, w, max)).toEqual(refused(503, 'INTEGRITY_FAILED'));
      expect(await heldIn(w)).toBe('tampered');
      return { w, seenAt: seen };
    });
    expect(seenAt).toBeDefined();
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ check: 'state', reason: 'log', seq: String(seenAt) }),
    );
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('a month grown honestly under the heads seen decides as ever: its limit refuses, no alarm', async () => {
    await heldToADigest(async (digest) => {
      const { w, acting, max } = await ready();
      await decisionOf(acting, w, max);
      expect(await heldIn(w)).toBe(max);
      const seen = digest.heads({ kind: 'organisation', orgId: w.org })?.seen?.seq ?? 0n;
      await decisionOf(acting, w, max);
      expect((await decisionOf(acting, w, 1n)).decision).not.toBe('ALLOW');
      expect(await heldIn(w)).toBe(2n * max);
      expect(digest.heads({ kind: 'organisation', orgId: w.org })?.seen?.seq).toBeGreaterThan(seen);
    });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });
});

describe('the holdings check, a total gone without a trace', () => {
  it('alarms a month whose reservations hold capacity with no total and nothing signed for one', async () => {
    const { w, acting, max } = await ready();
    await decisionOf(acting, w, max / 2n);
    const id = monthTotalId(w.org, key(w));
    await asOwner(w, async (owner) => {
      await owner.query('alter table audit.events disable trigger user');
      await owner.query('delete from limit_reservations.month_totals where id = $1', [id]);
      await owner.query("delete from audit.events where subject_type = 'month_total' and subject_id = $1", [id]);
      await owner.query('alter table audit.events enable trigger user');
    });
    await createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run();
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ totals: 0, totalsMissing: 1 });
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });
});

describe('every ending gives its amount back to its month, the holdings check finding nothing apart', () => {
  type Ending = (w: World, acting: AgentActing, requestId: string) => Promise<unknown>;
  /** A person ending it, by their user ID (the use cases check their role; these core steps don't). */
  const OPERATOR_USER = '0199a0f0-0000-7000-8000-0000000000aa';
  const inOrg = <Result>(w: World, work: (tx: DatabaseTransaction<Tables>, states: SignedStates) => Promise<Result>) =>
    withSignedStates(app, w.org, quiet(), work);
  const endings: [string, Ending][] = [
    [
      'an expiry',
      // Past its 72-hour wait from its decision, whose time the chain seals by the database's clock.
      (w, _acting, id) =>
        inOrg(w, (tx, states) =>
          expireRequest(tx, states, keys, { orgId: w.org, id }, new Date(Date.now() + 73 * 3_600_000)),
        ),
    ],
    [
      "its agent's cancel",
      (w, acting, id) =>
        inOrg(w, (tx, states) =>
          cancelRequest(
            tx,
            states,
            keys,
            { orgId: w.org, id },
            { kind: 'agent', agentId: acting.agentId, agentKeyId: acting.keyId },
            clock.now(),
          ),
        ),
    ],
    [
      "a person's cancel",
      (w, _acting, id) =>
        inOrg(w, (tx, states) =>
          cancelRequest(tx, states, keys, { orgId: w.org, id }, { kind: 'user', userId: OPERATOR_USER }, clock.now()),
        ),
    ],
    [
      "a person's reject (an approver's, or a waiting rejection's)",
      (w, _acting, id) =>
        inOrg(w, async (tx, states) => {
          await requestOf(tx, states, { orgId: w.org, id }, 'change');
          await rejectRequest(
            tx,
            states,
            keys,
            { orgId: w.org, id },
            { userId: OPERATOR_USER, reason: 'Not this month', stepUp: {} },
            clock.now(),
          );
        }),
    ],
    [
      "a hand-off's void (its key ended, its supplier changed)",
      (w, _acting, id) =>
        inOrg(w, async (tx, states) => {
          await requestOf(tx, states, { orgId: w.org, id }, 'change');
          await voidedWith(tx, states, keys, { orgId: w.org, id }, ['AGENT_KEY_ENDED'], clock.now());
        }),
    ],
    [
      "a carry's cancel",
      (w, _acting, id) =>
        inOrg(w, async (tx, states) => {
          await requestOf(tx, states, { orgId: w.org, id }, 'change');
          await settleCarried(
            tx,
            states,
            keys,
            { orgId: w.org, id },
            { outcome: 'cancel', causes: ['MANDATE_NOT_IN_FORCE'] },
            clock.now(),
          );
        }),
    ],
    [
      "a brake's void",
      (w, acting) =>
        inOrg(w, (tx, states) =>
          voidPendingOf(tx, states, keys, w.org, { agentId: acting.agentId }, 'AGENT_SUSPENDED', clock.now(), 1),
        ),
    ],
  ];

  it.each(endings)('%s', async (_what, end) => {
    const w = await world();
    for (const id of w.suppliers) await shared.verified(w, id);
    const max = 800_000n;
    // Approvals from AED 1,000: both wait for one, so every ending can take the first.
    await shared.inForce(registry, w, {
      perOrderLimit: AED(max),
      monthlyLimit: AED(2n * max),
      approvalThreshold: AED(100_000n),
    });
    const acting = await agentKey(w);
    const ended = await decisionOf(acting, w, max / 2n);
    expect(ended.decision).toBe('REQUIRE_APPROVAL');
    await decisionOf(acting, w, max / 4n);
    await end(w, acting, ended.id);
    expect(await heldIn(w)).toBe(max / 4n);
    await createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run();
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ totals: 1, totalsMismatched: 0, totalsMissing: 0 });
  });
});
