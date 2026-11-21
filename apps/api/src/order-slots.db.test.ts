// TR-2 (0114; Threat-Model R-15): an order's claim kept as signed slots, on
// the real migrated schema as the app role (ADR-012 §2; FX-TAMPER). The
// database's owner, holding the owner login but none of the app's keys,
// releasing or deleting an order's claim no longer has the same invoice
// decided again: its slot still holds it, so the duplicate is still refused and
// the lookalike still sent for approval. The slot itself changed past the app
// (emptied, rolled back, deleted, planted, swapped, pointed at another event)
// refuses every decision on the order, raises the integrity alarm and holds the
// organisation. Every ending lets go of the slots its decision sealed; the
// holdings check holds each slot to the open claims; locks are taken at 11c,
// after the payee windows and in order of ID, before the audit head; and an
// organisation made before TR-2 is refused busy until its cutover opens its
// slots from its signed requests.
import {
  type AuditDetails,
  checkStatesWith,
  createAuditTrail,
  type SignedStates,
  withSignedStates,
} from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { createOutbox } from '@agentx/core/modules/notifications';
import { paymentHoldsOf } from '@agentx/core/modules/outcomes';
import {
  bankKeyOf,
  cancelRequest,
  cutOverOrderSlots,
  expireRequest,
  keyHashOf,
  ORDER_SLOTS,
  type OrderSlotCheck,
  orderSlotId,
  type OrderSlotKey,
  orderSlotKeys,
  orderSlotOf,
  orderSlotsOf,
  rejectRequest,
  requestOf,
  settleCarried,
  SLOTS_CUTOVER_ACTION,
  SLOTS_CUTOVER_SUBJECT,
  SLOTS_NAMED_SUBJECT,
  slotsLetGo,
  SPEND_REQUESTS,
  type SpendRequestsTables,
  totalsWeighed,
  voidedWith,
  voidPendingOf,
} from '@agentx/core/modules/spend-requests';
import { SUPPLIERS, supplierOf } from '@agentx/core/modules/suppliers';
import type { PaymentsTables } from '@agentx/core/modules/transactions';
import { CHAIN_START, createDigestLog } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, type DatabaseTransaction, withTenant } from '@agentx/platform/db';
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

import { createHoldingsCheck } from './holdings-check.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';
import { weighedAgain } from './spend-request-approvals.ts';
import {
  type AgentActing,
  createSpendRequestDecisions,
  DECIDE_OPERATION,
  type SpendRequestDecisions,
} from './spend-request-decisions.ts';

type Tables = MandateWorldTables & SpendRequestsTables & LimitReservationsTables & PaymentsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0x0114_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-000000000114';
const OPERATOR = { type: 'system', id: 'test' } as const;
const PERSON = '0199a0f0-0000-7000-8000-0000000000aa';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'order-slots' });
const { world, quiet, agentKey, eventsAbout } = shared;

/** The tests' clock, the database's own hour: an expiry is judged by the database's clock (the chain seals by it). */
const START = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000);

/** An order of 1,000: well under every limit, so only its order is weighed. */
const ORDER = 100_000n;
const TERMS = { perOrderLimit: AED(800_000n), monthlyLimit: AED(1_600_000n), approvalThreshold: AED(500_000n) };
const DUPLICATE = { decision: 'DENY', reasons: ['DUPLICATE_ORDER_REFERENCE'] };
const LOOKALIKE = { decision: 'REQUIRE_APPROVAL', reasons: ['POSSIBLE_DUPLICATE_ORDER'] };

/** A world whose agent has a key and a mandate in force, and its suppliers verified. */
async function ready(options: Parameters<typeof world>[0] = {}, terms: Partial<typeof TERMS> = TERMS) {
  const w = await world(options);
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, terms);
  return { w, acting: await agentKey(w) };
}

/** The world's first supplier, or its second. */
const supplierOf_ = (w: World, which: 0 | 1 = 0) => w.suppliers[which] ?? '';

let keysUsed = 0;
/** The agent's decision on `reference` to the supplier, as its route asks it. */
const ask = (acting: AgentActing, w: World, reference: string, supplierId = supplierOf_(w), amount = ORDER) => {
  keysUsed += 1;
  const asked = {
    amount: AED(amount),
    supplierId,
    fundingSourceId: w.source,
    orderReference: reference,
    purpose: 'Printer paper',
  };
  return decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `slot-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(amount), n: keysUsed }),
    },
    asked,
    CORRELATION,
  );
};
/** The request a decision answered with. */
const decided = async (
  acting: AgentActing,
  w: World,
  reference: string,
  supplierId = supplierOf_(w),
  amount = ORDER,
) => {
  const answer = await ask(acting, w, reference, supplierId, amount);
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

/** The canonical form the database works out for a reference (0067). */
const canonical = async (reference: string): Promise<string> => {
  const [row] = await database
    .as('admin')
    .query<{ key: string }>('select spend_requests.order_key_of($1) as key', [reference]);
  return row?.key ?? '';
};
/** An order's slots, in orderSlotKeys' order, as its decision names them. */
const slotKeys = async (w: World, reference: string, supplierId: string, payeeKey: string | null = null) =>
  orderSlotKeys({ supplierId, payeeKey, orderKey: await canonical(reference), bankKey: bankKeyOf(reference) });
/** A supplier's order slot for the reference: the one a duplicate is refused by. */
const orderSlot = async (w: World, reference: string, supplierId = supplierOf_(w)) => {
  const [key] = await slotKeys(w, reference, supplierId);
  return key ?? ({} as OrderSlotKey);
};
/** A supplier's bank slot for the reference: the one a lookalike is seen by. */
const bankSlot = async (w: World, reference: string, supplierId = supplierOf_(w)) => {
  const [, key] = await slotKeys(w, reference, supplierId);
  return key ?? ({} as OrderSlotKey);
};
const slotOf = (w: World, key: OrderSlotKey) =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    orderSlotOf(tx, states, w.org, orderSlotId(w.org, key), 'share'),
  );
/** Who a slot holds, as its text, or how it read. */
const holdersIn = async (w: World, key: OrderSlotKey): Promise<string> => {
  const read: OrderSlotCheck = await slotOf(w, key);
  if (read.outcome !== 'held') return read.outcome;
  return read.holders.kind === 'order'
    ? (read.holders.holder ?? '')
    : read.holders.entries.map(({ requestId }) => requestId).join(',');
};
const holdOf = (w: World) => withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const alarmedOn = (reason: string) => {
  expect(lines('audit.integrity_failed')).toContainEqual(
    expect.objectContaining({ subjectType: ORDER_SLOTS.subject, reason }),
  );
};
/** What the claim rows alone say of an order: the look before TR-2. */
const claimsSay = (w: World, reference: string, supplierId = supplierOf_(w)) =>
  withTenant(
    app,
    w.org,
    async (tx) => (await totalsWeighed(tx, { month: null, order: { supplierId, payeeKey: null, reference } })).claims,
  );

/** The supplier's payee key set past the use cases, signed. */
const payeeKeyOf = (w: World, id: string, payeeKey: string | null) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId: w.org, id }, 'change');
    if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
    await states.record(
      tx,
      SUPPLIERS,
      { orgId: w.org, id },
      found.state,
      { payee_key: payeeKey, payee_key_version: payeeKey === null ? null : 1 },
      { actor: OPERATOR, action: 'supplier.payee_key_moved', details: {} },
    );
  });

type Owner = Awaited<ReturnType<typeof tamperAsOwner>>;

/** The owner's statements in one transaction, inside the organisation, the user triggers of the slots and claims off. */
async function asOwner(w: World, work: (owner: Owner) => Promise<unknown>) {
  const owner = await tamperAsOwner(database, ORDER_SLOTS, w.org);
  try {
    await owner.query('begin');
    await owner.query('alter table spend_requests.order_claims disable trigger user');
    await owner.query('alter table spend_requests.order_slots disable trigger user');
    await work(owner);
    await owner.query('alter table spend_requests.order_claims enable trigger user');
    await owner.query('alter table spend_requests.order_slots enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}
const slotTamper = async (w: World, work: (owner: Owner) => Promise<void>) => {
  const owner = await tamperAsOwner(database, ORDER_SLOTS, w.org);
  try {
    await work(owner);
  } finally {
    await owner.end();
  }
};
/** The request's claim released past the app, as the owner can. */
const claimReleased = (w: World, requestId: string) =>
  asOwner(w, (owner) =>
    owner.query('update spend_requests.order_claims set released_at = claimed_at where request_id = $1', [requestId]),
  );

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

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(START);
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

describe("an order's slots, signed (TR-2)", () => {
  it("are made by the order's first decision, each held by it, sealed, their IDs in the decision", async () => {
    const { w, acting } = await ready();
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    const request = await decided(acting, w, 'INV-7', supplierId);
    const slots = await slotKeys(w, 'INV-7', supplierId, 'payee-1');
    expect(slots.map(({ kind }) => kind)).toEqual(['supplier_order', 'payee_order', 'supplier_bank', 'payee_bank']);
    for (const key of slots) expect(await holdersIn(w, key)).toBe(request.id);
    const [first] = slots;
    const events = await eventsAbout(w.org, orderSlotId(w.org, first ?? ({} as OrderSlotKey)), ORDER_SLOTS.subject);
    expect(events).toEqual([expect.objectContaining({ action: 'order_slot.held', actorType: 'agent' })]);
    const decidedEvent = (await eventsAbout(w.org, request.id, SPEND_REQUESTS.subject)).find(
      ({ action }) => action === 'spend_request.decided',
    );
    expect(decidedEvent?.details).toMatchObject({ orderSlots: slots.map((key) => orderSlotId(w.org, key)).join(',') });
  });

  it('refuses the same order again, however written, and sends a lookalike for approval, listed beside it', async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 'INV-7');
    expect(await decided(acting, w, 'INV-7')).toMatchObject(DUPLICATE);
    expect(await decided(acting, w, ' inv-7 ')).toMatchObject(DUPLICATE);
    const lookalike = await decided(acting, w, 'INV_7');
    expect(lookalike).toMatchObject(LOOKALIKE);
    expect((await holdersIn(w, await bankSlot(w, 'INV-7'))).split(',').toSorted()).toEqual(
      [first.id, lookalike.id].toSorted(),
    );
    // An order slot no one holds is no duplicate: no slot for a reference never asked.
    expect(await holdersIn(w, await orderSlot(w, 'INV-8'))).toBe('none');
  });

  it('lets an order be asked again once its request ended, its slots let go of', async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 'INV-7');
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, keys, { orgId: w.org, id: first.id }, { kind: 'user', userId: PERSON }, clock.now()),
    );
    expect(await holdersIn(w, await orderSlot(w, 'INV-7'))).toBe('');
    const events = await eventsAbout(w.org, orderSlotId(w.org, await orderSlot(w, 'INV-7')), ORDER_SLOTS.subject);
    expect(events.map(({ action }) => action)).toEqual(['order_slot.held', 'order_slot.released']);
    expect(events[1]?.details).toMatchObject({ requestIds: first.id });
    expect((await decided(acting, w, 'INV-7')).decision).toBe('ALLOW');
  });

  it.each<[string, (w: World, requestId: string) => Promise<unknown>]>([
    ['released', claimReleased],
    [
      'deleted',
      (w, requestId) =>
        asOwner(w, (owner) =>
          owner.query('delete from spend_requests.order_claims where request_id = $1', [requestId]),
        ),
    ],
  ])('R-15: still refuses a paid-for order asked again once the owner has %s its claim', async (_what, cut) => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 'INV-7');
    await cut(w, first.id);
    // The would-fail check: the claim rows alone no longer see the order, as the decision did before TR-2.
    expect(await claimsSay(w, 'INV-7')).toEqual({ duplicate: false, possible: false });

    // Its signed slot still holds it: refused, as an honest duplicate is.
    expect(await decided(acting, w, 'INV-7')).toMatchObject(DUPLICATE);
  });

  it("R-15: still sends a lookalike for approval once the owner has deleted the other's claim", async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 'INV-7');
    await asOwner(w, (owner) =>
      owner.query('delete from spend_requests.order_claims where request_id = $1', [first.id]),
    );
    expect(await claimsSay(w, 'INV_7')).toEqual({ duplicate: false, possible: false });

    expect(await decided(acting, w, 'INV_7')).toMatchObject(LOOKALIKE);
  });

  it('is caught deleted: its events name it, so it never reads as an order no one holds', async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 'INV-7');
    await claimReleased(w, first.id);
    await slotTamper(w, async (owner) => owner.deleteRow(orderSlotId(w.org, await orderSlot(w, 'INV-7'))));

    expect(await ask(acting, w, 'INV-7')).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('deleted');
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('is caught emptied by its seal: every decision on the order refused, alarmed, the organisation held', async () => {
    const { w, acting } = await ready();
    await decided(acting, w, 'INV-7');
    await slotTamper(w, async (owner) =>
      owner.setColumn(orderSlotId(w.org, await orderSlot(w, 'INV-7')), 'holders', ''),
    );

    expect(await ask(acting, w, 'INV-7')).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('seal');
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('is caught rolled back to an older, validly signed state held by no one: its version is not the newest', async () => {
    const { w, acting } = await ready();
    const earlier = await decided(acting, w, 'INV-7');
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, keys, { orgId: w.org, id: earlier.id }, { kind: 'user', userId: PERSON }, clock.now()),
    );
    const id = orderSlotId(w.org, await orderSlot(w, 'INV-7'));
    let saved: Awaited<ReturnType<Owner['saveRow']>> | undefined;
    await slotTamper(w, async (owner) => {
      saved = await owner.saveRow(id);
    });
    const paid = await decided(acting, w, 'INV-7');
    // The positive control: held again, the order asked once more is an honest duplicate.
    expect(await decided(acting, w, 'INV-7')).toMatchObject(DUPLICATE);
    await claimReleased(w, paid.id);
    await slotTamper(w, (owner) => owner.restoreRow(saved ?? ({} as never)));

    expect(await ask(acting, w, 'INV-7')).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('pointer');
  });

  it('is caught planted with no event of its own', async () => {
    const { w, acting } = await ready();
    const key = await orderSlot(w, 'INV-9', supplierOf_(w, 1));
    await asOwner(w, (owner) =>
      owner.query(
        "insert into spend_requests.order_slots (org_id, id, kind, supplier_id, payee_key, key_hash, holders, created_at) values ($1, $2, 'supplier_order', $3, null, $4, '', now())",
        [w.org, orderSlotId(w.org, key), key.supplierId, key.keyHash],
      ),
    );

    expect(await ask(acting, w, 'INV-9', supplierOf_(w, 1))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('unsigned');
  });

  it("is caught swapped with another supplier's slot's signed state: the seal names its own object", async () => {
    const { w, acting } = await ready();
    const [first, second] = [supplierOf_(w), supplierOf_(w, 1)];
    const held = await decided(acting, w, 'INV-7', first);
    // Another supplier's slot for another order, held by no one now.
    const other = await decided(acting, w, 'INV-8', second);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, keys, { orgId: w.org, id: other.id }, { kind: 'user', userId: PERSON }, clock.now()),
    );
    await claimReleased(w, held.id);
    const [mine, theirs] = [await orderSlot(w, 'INV-7', first), await orderSlot(w, 'INV-8', second)];
    await asOwner(w, (owner) =>
      owner.query(
        `update spend_requests.order_slots t set holders = o.holders, state_version = o.state_version,
           state_event_id = o.state_event_id
         from spend_requests.order_slots o where t.id = $1 and o.id = $2`,
        [orderSlotId(w.org, mine), orderSlotId(w.org, theirs)],
      ),
    );

    expect(await ask(acting, w, 'INV-7', first)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('pointer');
  });

  it('is caught pointed at a forged event ID', async () => {
    const { w, acting } = await ready();
    await decided(acting, w, 'INV-7');
    await slotTamper(w, async (owner) =>
      owner.setColumn(
        orderSlotId(w.org, await orderSlot(w, 'INV-7')),
        'state_event_id',
        '0199a0f0-0000-7000-8000-00000000f0f0',
      ),
    );

    expect(await ask(acting, w, 'INV-7')).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('pointer');
  });

  it('AT13: is caught at decision time rolled back with its newest event deleted below the anchor; the anchor alone lets it pass', async () => {
    const { w, acting } = await ready();
    const earlier = await decided(acting, w, 'INV-7');
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, keys, { orgId: w.org, id: earlier.id }, { kind: 'user', userId: PERSON }, clock.now()),
    );
    const id = orderSlotId(w.org, await orderSlot(w, 'INV-7'));
    let saved: Awaited<ReturnType<Owner['saveRow']>> | undefined;
    await slotTamper(w, async (owner) => {
      saved = await owner.saveRow(id);
    });
    const paid = await decided(acting, w, 'INV-7');
    // The anchor check's walk of the whole chain, kept in the digest, the slot's newest state in it.
    const digest = createDigestLog({
      keys,
      logger: testLogger(capture),
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 64 * 1024 * 1024,
    });
    const step = await createAuditTrail({ keys, ids }).checkFromAnchor(app, w.org, CHAIN_START);
    if (!step.ok || step.signed === undefined) throw new Error('The chain should have checked out');
    digest.record({ kind: 'organisation', orgId: w.org }, step.signed, clock.now());
    // Below that anchor, the owner deletes the slot's newest event, rolls its row back to no one, and releases the
    // paid request's claim: the order looks free everywhere the app would look without the digest.
    await claimReleased(w, paid.id);
    const owner = await tamperAsOwner(database, ORDER_SLOTS, w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table audit.events disable trigger user');
      await owner.query(
        'delete from audit.events where org_id = $1 and seq = (select max(seq) from audit.events where org_id = $1 and subject_type = $2 and subject_id = $3)',
        [w.org, ORDER_SLOTS.subject, id],
      );
      await owner.query('alter table audit.events enable trigger user');
      await owner.query('commit');
      await owner.restoreRow(saved ?? ({} as never));
    } finally {
      await owner.end();
    }

    // The positive control: with no digest, the slot reads as no one's, validly signed: the order would be decided again.
    expect(await holdersIn(w, await orderSlot(w, 'INV-7'))).toBe('');
    // Held to the digest: the slot's newest signed state is gone, so the order asked again is refused.
    checkStatesWith(digest);
    try {
      expect(await ask(acting, w, 'INV-7')).toEqual(refused(503, 'INTEGRITY_FAILED'));
    } finally {
      checkStatesWith(undefined);
    }
    alarmedOn('log');
  });
});

describe("the slot's own rules", () => {
  it('is named apart for each organisation, kind, supplier, payee key (its case too) and order', () => {
    const org = '0199a0f0-0000-7000-8000-00000000b001';
    const supplierId = '0199a0f0-0000-7000-8000-00000000a001';
    const keyHash = keyHashOf('inv-7');
    const named = (key: Partial<OrderSlotKey>, orgId = org) =>
      orderSlotId(orgId, { kind: 'supplier_order', supplierId, payeeKey: null, keyHash, ...key });
    const all = [
      named({}),
      named({}, '0199a0f0-0000-7000-8000-00000000b002'),
      named({ kind: 'supplier_bank' }),
      named({ supplierId: '0199a0f0-0000-7000-8000-00000000a002' }),
      named({ keyHash: keyHashOf('inv-8') }),
      named({ kind: 'payee_order', supplierId: null, payeeKey: 'payee-1' }),
      named({ kind: 'payee_order', supplierId: null, payeeKey: 'Payee-1' }),
    ];
    expect(new Set(all).size).toBe(all.length);
    expect(named({})).toBe(named({}));
    expect(named({ supplierId: supplierId.toUpperCase() })).toBe(named({}));
  });

  it('is one slot alone for an order with no payee key and nothing the bank would carry', () => {
    const supplierId = '0199a0f0-0000-7000-8000-00000000a001';
    expect(orderSlotKeys({ supplierId, payeeKey: null, orderKey: '#_#', bankKey: bankKeyOf('#_#') })).toEqual([
      { kind: 'supplier_order', supplierId, payeeKey: null, keyHash: keyHashOf('#_#') },
    ]);
  });

  /** The slot let go of by `requestId` in a transaction of its own, read for change first, as an ending does. */
  const letGoBy = (w: World, key: OrderSlotKey, requestId: string) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const id = orderSlotId(w.org, key);
      const read = await orderSlotsOf(tx, states, w.org, [id], 'change');
      await slotsLetGo(tx, states, w.org, read, [{ id, requestId }], {
        at: clock.now(),
        change: { actor: OPERATOR, action: 'order_slot.released', details: {} },
      });
    });

  it('lets a slot tampered with be at an ending: the request still ends, as a brake must, the alarm raised by its read', async () => {
    const { w, acting } = await ready();
    const held = await decided(acting, w, 'INV-7');
    const key = await orderSlot(w, 'INV-7');
    await slotTamper(w, (owner) => owner.setColumn(orderSlotId(w.org, key), 'holders', ''));
    const ended = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, keys, { orgId: w.org, id: held.id }, { kind: 'user', userId: PERSON }, clock.now()),
    );
    expect(ended).toMatchObject({ outcome: 'ended' });
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', foundOn: ORDER_SLOTS.subject });
    const events = await eventsAbout(w.org, orderSlotId(w.org, key), ORDER_SLOTS.subject);
    expect(events.map(({ action }) => action)).toEqual(['order_slot.held']);
  });

  it('lets go of nothing a request does not hold: the mismatch alarmed, the slot as it was', async () => {
    const { w, acting } = await ready();
    const held = await decided(acting, w, 'INV-7');
    const key = await orderSlot(w, 'INV-7');
    await letGoBy(w, key, PERSON);
    expect(await holdersIn(w, key)).toBe(held.id);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: ORDER_SLOTS.subject });
    const events = await eventsAbout(w.org, orderSlotId(w.org, key), ORDER_SLOTS.subject);
    expect(events.map(({ action }) => action)).toEqual(['order_slot.held']);
  });

  it('alarms a let-go of an order with no slot once cut over, and lets go of nothing before', async () => {
    const { w } = await ready();
    await letGoBy(w, await orderSlot(w, 'INV-7'), PERSON);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: ORDER_SLOTS.subject });
    const before = await ready({ madeBeforeOrderSlots: true });
    capture = new LogCapture();
    await letGoBy(before.w, await orderSlot(before.w, 'INV-7'), PERSON);
    expect(await holdOf(before.w)).toMatchObject({ outcome: 'clear' });
  });
});

describe('every ending lets go of the slots its decision sealed, the holdings check finding nothing apart', () => {
  type Ending = (w: World, acting: AgentActing, requestId: string) => Promise<unknown>;
  const inOrg = <Result>(w: World, work: (tx: DatabaseTransaction<Tables>, states: SignedStates) => Promise<Result>) =>
    withSignedStates(app, w.org, quiet(), work);
  const endings: [string, Ending][] = [
    [
      'an expiry',
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
      "a person's reject",
      (w, _acting, id) =>
        inOrg(w, async (tx, states) => {
          await requestOf(tx, states, { orgId: w.org, id }, 'change');
          await rejectRequest(
            tx,
            states,
            keys,
            { orgId: w.org, id },
            { userId: PERSON, reason: 'Not this month', stepUp: {} },
            clock.now(),
          );
        }),
    ],
    [
      'a void',
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
    // Approvals from AED 1,000: both wait for one, so every ending can take the first.
    const { w, acting } = await ready({}, { ...TERMS, approvalThreshold: AED(50_000n) });
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    const ended = await decided(acting, w, 'INV-7', supplierId);
    expect(ended.decision).toBe('REQUIRE_APPROVAL');
    const kept = await decided(acting, w, 'INV_7', supplierId);
    await end(w, acting, ended.id);
    const [supplierOrder, payeeOrder, supplierBank, payeeBank] = await slotKeys(w, 'INV-7', supplierId, 'payee-1');
    for (const key of [supplierOrder, payeeOrder]) expect(await holdersIn(w, key ?? ({} as OrderSlotKey))).toBe('');
    // The lookalike still listed in the bank slots it shares: only the ended one let go.
    for (const key of [supplierBank, payeeBank]) expect(await holdersIn(w, key ?? ({} as OrderSlotKey))).toBe(kept.id);
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({
      slots: 6,
      slotsMismatched: 0,
      slotsMissing: 0,
      slotsTampered: 0,
    });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it("lets go once a slot for a brake's whole batch: two lookalikes on one bank slot, one record", async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 'INV-7');
    const second = await decided(acting, w, 'INV_7');
    expect(second).toMatchObject(LOOKALIKE);
    const voided = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      voidPendingOf(tx, states, keys, w.org, { agentId: acting.agentId }, 'AGENT_SUSPENDED', clock.now()),
    );
    expect(voided).toBe(2);
    const events = await eventsAbout(w.org, orderSlotId(w.org, await bankSlot(w, 'INV-7')), ORDER_SLOTS.subject);
    const released = events.filter(({ action }) => action === 'order_slot.released');
    expect(released).toHaveLength(1);
    expect(String(released[0]?.details.requestIds).split(',').toSorted()).toEqual([first.id, second.id].toSorted());
    expect(await holdersIn(w, await bankSlot(w, 'INV-7'))).toBe('');
  });
});

describe('in the lock order (11c: after the payee windows, in order of ID, before the audit head), forced', () => {
  /** A void of `requestId` in a transaction of its own, held open at `gate` once it has let go of its slots. */
  const voidHeldOpen = (w: World, requestId: string, gate: Promise<unknown>, done: () => void) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await requestOf(tx, states, { orgId: w.org, id: requestId }, 'change');
      await voidedWith(tx, states, keys, { orgId: w.org, id: requestId }, ['AGENT_SUSPENDED'], clock.now());
      done();
      await gate;
    });
  /** The slot held for change in a transaction of its own until `gate`, as a decision holds it with its month. */
  const slotHeld = (w: World, key: OrderSlotKey, gate: Promise<unknown>, held: () => void) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await orderSlotOf(tx, states, w.org, orderSlotId(w.org, key), 'change');
      held();
      await gate;
    });
  const admin = () => database.as('admin');
  /** A row's lock asked for without waiting: refused, as another holds it. */
  const locked = async (asked: Promise<unknown>) => {
    await expect(asked).rejects.toMatchObject({ code: '55P03' });
  };

  it('makes two decisions on one order wait at its slot, the second then refused as a duplicate', async () => {
    const { w, acting } = await ready();
    const theirs = await shared.secondAgent(registry, w, TERMS);
    // Made once and let go of, so the slot is there to hold.
    const earlier = await decided(acting, w, 'INV-7');
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, keys, { orgId: w.org, id: earlier.id }, { kind: 'user', userId: PERSON }, clock.now()),
    );
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = slotHeld(w, await orderSlot(w, 'INV-7'), gate, () => {
      holding(undefined);
    });
    await held;
    const one = within(20_000, decided(acting, w, 'INV-7'), 'the first decision');
    await waitUntilQueued(admin(), 1);
    // The first holds the supplier, its month and its windows already: it waits at the slot alone.
    await locked(
      admin().query(
        'select 1 from limit_reservations.payee_windows where org_id = $1 and supplier_id = $2 for no key update nowait',
        [w.org, supplierOf_(w)],
      ),
    );
    const two = within(20_000, decided(theirs, w, 'INV-7'), 'the second decision');
    await waitUntilQueued(admin(), 2);
    open(undefined);
    await holder;

    expect((await one).decision).toBe('ALLOW');
    expect(await two).toMatchObject(DUPLICATE);
  });

  it("makes another agent's decision on the order wait for an ending holding its slot, then weighs it let go of", async () => {
    const { w, acting } = await ready();
    const theirs = await shared.secondAgent(registry, w, TERMS);
    const first = await decided(acting, w, 'INV-7');
    const { promise: done, resolve: ending } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const voiding = voidHeldOpen(w, first.id, gate, () => {
      ending(undefined);
    });
    await done;
    const deciding = within(20_000, decided(theirs, w, 'INV-7'), 'the decision');
    await waitUntilQueued(admin(), 1);
    open(undefined);
    await voiding;

    // Weighed after the void, against the slot it let go of: the order free again, allowed.
    expect((await deciding).decision).toBe('ALLOW');
  });

  it('makes an ending take its request (8), reservation (11), month total (11a) and windows (11b) before it waits for a slot (11c)', async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 'INV-7');
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = slotHeld(w, await orderSlot(w, 'INV-7'), gate, () => {
      holding(undefined);
    });
    await held;
    const voiding = within(
      20_000,
      voidHeldOpen(w, first.id, Promise.resolve(), () => undefined),
      'the void',
    );
    await waitUntilQueued(admin(), 1);
    await locked(
      admin().query('select 1 from spend_requests.requests where id = $1 for no key update nowait', [first.id]),
    );
    await locked(
      admin().query('select 1 from limit_reservations.reservations where request_id = $1 for no key update nowait', [
        first.id,
      ]),
    );
    await locked(
      admin().query('select 1 from limit_reservations.month_totals where agent_id = $1 for no key update nowait', [
        w.agent,
      ]),
    );
    await locked(
      admin().query(
        'select 1 from limit_reservations.payee_windows where org_id = $1 and supplier_id = $2 for no key update nowait',
        [w.org, supplierOf_(w)],
      ),
    );
    // Never the audit head while it waits: a slot is always taken before it (12).
    const head = await admin().query('select 1 from audit.heads where org_id = $1 for update nowait', [w.org]);
    expect(head).toHaveLength(1);
    open(undefined);
    await holder;
    await voiding;
    expect(await holdersIn(w, await orderSlot(w, 'INV-7'))).toBe('');
  });

  it("makes an approval's confirm take its request's own sealed slots with its order's: it waits for one held", async () => {
    const { w, acting } = await ready({}, { ...TERMS, approvalThreshold: AED(50_000n) });
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    const waiting = await decided(acting, w, 'INV-7', supplierId);
    expect(waiting.decision).toBe('REQUIRE_APPROVAL');
    // The supplier's key changes while it waits: its order's slots now are the new key's, not those it sealed.
    await payeeKeyOf(w, supplierId, null);
    await payeeKeyOf(w, supplierId, 'payee-2');
    const [, sealedOnly] = await slotKeys(w, 'INV-7', supplierId, 'payee-1');
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = slotHeld(w, sealedOnly ?? ({} as OrderSlotKey), gate, () => {
      holding(undefined);
    });
    await held;
    let weighed = false;
    const confirming = within(
      20_000,
      withSignedStates(app, w.org, quiet(), async (tx, states) => {
        const again = await weighedAgain(tx, states, {
          orgId: w.org,
          requestId: waiting.id,
          now: clock.now(),
          decides: true,
        });
        weighed = true;
        return again;
      }),
      'the confirm',
    );
    // It waits for the old key's slot, which its reject would let go of, as it reads its order's slots.
    await waitUntilQueued(admin(), 1);
    expect(weighed).toBe(false);
    open(undefined);
    await holder;
    // Its own hold is never its own duplicate: weighed as before, waiting for an approver.
    expect((await confirming).made.decision).toBe('REQUIRE_APPROVAL');
  });

  it("never weighs an approval's own hold of its order as a duplicate, its claim there or gone", async () => {
    const { w, acting } = await ready({}, { ...TERMS, approvalThreshold: AED(50_000n) });
    const waiting = await decided(acting, w, 'INV-7');
    expect(waiting.decision).toBe('REQUIRE_APPROVAL');
    // Its own claim released past the app and another request holding its order slot: as the slot says so, refused.
    const key = await orderSlot(w, 'INV-7');
    await asOwner(w, async (owner) => {
      await owner.query('update spend_requests.order_claims set released_at = claimed_at where request_id = $1', [
        waiting.id,
      ]);
    });
    const { made } = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      weighedAgain(tx, states, { orgId: w.org, requestId: waiting.id, now: clock.now(), decides: false }),
    );
    // Held by itself alone, it is no duplicate of its own.
    expect(made.decision).toBe('REQUIRE_APPROVAL');
    expect(await holdersIn(w, key)).toBe(waiting.id);
  });
});

describe('the holdings check', () => {
  it('holds each slot to its open claims: a claim released past the app is a mismatch, alarmed', async () => {
    const { w, acting } = await ready();
    const held = await decided(acting, w, 'INV-7');
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ slots: 2, slotsMismatched: 0, slotsMissing: 0 });
    capture = new LogCapture();
    await claimReleased(w, held.id);
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ slots: 2, slotsMismatched: 2 });
    alarmedOn('holding');
  });

  it('counts a slot tampered with apart, its read raising the alarm', async () => {
    const { w, acting } = await ready();
    await decided(acting, w, 'INV-7');
    await slotTamper(w, async (owner) =>
      owner.setColumn(orderSlotId(w.org, await orderSlot(w, 'INV-7')), 'holders', ''),
    );
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ slots: 2, slotsTampered: 1 });
    alarmedOn('seal');
  });

  it('alarms an open claim with no slot and nothing signed for one', async () => {
    const { w, acting } = await ready();
    await decided(acting, w, 'INV-7');
    // Both slots and every event of theirs gone: no read of a slot names them now.
    for (const key of await slotKeys(w, 'INV-7', supplierOf_(w))) {
      await slotTamper(w, async (owner) => {
        await owner.deleteEvents(orderSlotId(w.org, key));
        await owner.deleteRow(orderSlotId(w.org, key));
      });
    }
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ slots: 0, slotsMissing: 2 });
    alarmedOn('holding');
  });
});

describe('an organisation made before TR-2, until its cutover', () => {
  /** Its slots' cutover by hand, so its decisions can be made: then taken away with the slots, as before TR-2. */
  const cutOverByHand = (w: World) =>
    withSignedStates(app, w.org, quiet(), (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: OPERATOR,
        action: SLOTS_CUTOVER_ACTION,
        subject: { type: SLOTS_CUTOVER_SUBJECT, id: w.org, version: 1 },
        details: {},
      }),
    );
  /**
   * The organisation as one before TR-2 with orders held: the slots its decisions filled, their events and the
   * cutover's taken away by the owner, each request's decision sealed again as before TR-2 (no slots named).
   */
  const asBeforeTr2 = async (w: World, requestIds: readonly string[]) => {
    for (const id of requestIds) {
      const sealed = (await eventsAbout(w.org, id, SPEND_REQUESTS.subject)).findLast(
        ({ action }) => action === 'spend_request.decided',
      );
      // What a decision between GM-1b and TR-2 sealed of what it holds: no slots named, nothing of its own state.
      const kept = sealed?.details ?? {};
      const details = Object.fromEntries(
        [
          'decision',
          'heldMonth',
          'heldAt',
          'payeeSeal',
          'payeeSealKeyVersion',
          'possibleDuplicate',
          'approvalWaitHours',
          'payeeWindows',
        ]
          .filter((name) => Object.hasOwn(kept, name))
          .map((name) => [name, kept[name]]),
      );
      await withSignedStates(app, w.org, quiet(), (tx) =>
        createAuditTrail({ keys, ids }).record(tx, w.org, {
          actor: { type: 'system', id: 'api' },
          action: 'spend_request.decided',
          subject: { type: SPEND_REQUESTS.subject, id, version: 2 },
          details: details as AuditDetails,
        }),
      );
    }
    const owner = await tamperAsOwner(database, ORDER_SLOTS, w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table audit.events disable trigger user');
      await owner.query('delete from spend_requests.order_slots where org_id = $1', [w.org]);
      await owner.query('delete from audit.events where org_id = $1 and (subject_type = $2 or action = $3)', [
        w.org,
        ORDER_SLOTS.subject,
        SLOTS_CUTOVER_ACTION,
      ]);
      await owner.query('alter table audit.events enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }
  };
  const cut = (w: World) =>
    withSignedStates(app, w.org, quiet(), (tx, states) =>
      cutOverOrderSlots(tx, states, w.org, {
        keys,
        payments: paymentHoldsOf,
        record: (event) => createAuditTrail({ keys, ids }).record(tx, w.org, event),
        at: clock.now(),
      }),
    );

  it('is refused busy, never weighed from its claims, until its cutover, with nothing to open', async () => {
    const { w, acting } = await ready({ madeBeforeOrderSlots: true });
    expect(await ask(acting, w, 'INV-7')).toEqual(refused(503, 'ORGANISATION_BUSY'));
    await visit(w);
    expect(lines('order_slots.cut_over')).toEqual([expect.objectContaining({ opened: 0, mismatched: 0 })]);
    expect((await decided(acting, w, 'INV-7')).decision).toBe('ALLOW');
  });

  it('opens each slot from the signed requests, names them for each request, and weighs them from then on', async () => {
    const { w, acting } = await ready({ madeBeforeOrderSlots: true });
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    await cutOverByHand(w);
    const held = await decided(acting, w, 'INV-7', supplierId);
    const lookalike = await decided(acting, w, 'INV_7', supplierId);
    const ended = await decided(acting, w, 'INV-9', supplierId);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(tx, states, keys, { orgId: w.org, id: ended.id }, { kind: 'user', userId: PERSON }, clock.now()),
    );
    await asBeforeTr2(w, [held.id, lookalike.id, ended.id]);
    expect(await ask(acting, w, 'INV-7', supplierId)).toEqual(refused(503, 'ORGANISATION_BUSY'));

    await visit(w);
    // Its order and lookalike: each order's two order slots, and the two bank slots they share; nothing for the ended.
    expect(lines('order_slots.cut_over')).toEqual([expect.objectContaining({ opened: 6, mismatched: 0 })]);
    const slots = await slotKeys(w, 'INV-7', supplierId, 'payee-1');
    expect(await holdersIn(w, slots[0] ?? ({} as OrderSlotKey))).toBe(held.id);
    expect(await holdersIn(w, await orderSlot(w, 'INV-9', supplierId))).toBe('none');
    const named = await eventsAbout(w.org, held.id, SLOTS_NAMED_SUBJECT);
    expect(named).toEqual([
      expect.objectContaining({ details: { orderSlots: slots.map((key) => orderSlotId(w.org, key)).join(',') } }),
    ]);
    // Weighed from then on: the order refused, the lookalike's ending letting go of the slots the cutover named.
    // A duplicate, and a lookalike of the lookalike too, as the claims would have said.
    expect(await decided(acting, w, 'INV-7', supplierId)).toMatchObject({
      decision: 'DENY',
      reasons: ['DUPLICATE_ORDER_REFERENCE', 'POSSIBLE_DUPLICATE_ORDER'],
    });
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: lookalike.id },
        { kind: 'user', userId: PERSON },
        clock.now(),
      ),
    );
    expect(await holdersIn(w, slots[2] ?? ({} as OrderSlotKey))).toBe(held.id);
    expect(await holdOf(w)).toMatchObject({ outcome: 'clear' });
    // A second visit finds it cut over already, nothing apart.
    await visit(w);
    expect(lines('order_slots.cut_over')).toHaveLength(1);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('opens from the signed requests even where the owner released the claims, the mismatch alarmed', async () => {
    const { w, acting } = await ready({ madeBeforeOrderSlots: true });
    await cutOverByHand(w);
    const held = await decided(acting, w, 'INV-7');
    await asBeforeTr2(w, [held.id]);
    await claimReleased(w, held.id);

    await visit(w);
    expect(lines('order_slots.cut_over')).toEqual([expect.objectContaining({ opened: 2, mismatched: 2 })]);
    expect(await holdersIn(w, await orderSlot(w, 'INV-7'))).toBe(held.id);
    alarmedOn('holding');
    // Still refused, though no claim says so.
    expect(await ask(acting, w, 'INV-7')).toMatchObject({ outcome: 'decided', request: DUPLICATE });
  });

  it('is not cut over over a slot planted before it: nothing opened, no cutover, still busy', async () => {
    const { w, acting } = await ready({ madeBeforeOrderSlots: true });
    await cutOverByHand(w);
    const held = await decided(acting, w, 'INV-7');
    await asBeforeTr2(w, [held.id]);
    const key = await orderSlot(w, 'INV-7');
    await asOwner(w, (owner) =>
      owner.query(
        "insert into spend_requests.order_slots (org_id, id, kind, supplier_id, payee_key, key_hash, holders, created_at) values ($1, $2, 'supplier_order', $3, null, $4, '', now())",
        [w.org, orderSlotId(w.org, key), key.supplierId, key.keyHash],
      ),
    );
    await visit(w);
    expect(lines('order_slots.cutover_held')).toHaveLength(1);
    expect(lines('order_slots.cut_over')).toEqual([]);
    alarmedOn('unsigned');
    // The stop part way left nothing: no other slot opened, no request named, the organisation still busy.
    expect(await holdersIn(w, await bankSlot(w, 'INV-7'))).toBe('none');
    expect(await eventsAbout(w.org, held.id, SLOTS_NAMED_SUBJECT)).toEqual([]);
    expect(await ask(acting, w, 'INV-8')).toEqual(refused(503, 'ORGANISATION_BUSY'));
  });

  it('is not cut over over two signed requests holding one order (made past the claims): nothing opened, alarmed', async () => {
    const { w, acting } = await ready({ madeBeforeOrderSlots: true });
    await cutOverByHand(w);
    const first = await decided(acting, w, 'INV-7');
    // The slots gone and the first's claim released past the app: the same order decided again, both still holding.
    await asBeforeTr2(w, [first.id]);
    await cutOverByHand(w);
    await claimReleased(w, first.id);
    const second = await decided(acting, w, 'INV-7');
    expect(second.decision).toBe('ALLOW');
    await asBeforeTr2(w, [second.id]);

    await visit(w);
    expect(lines('order_slots.cutover_held')).toHaveLength(1);
    expect(lines('order_slots.cut_over')).toEqual([]);
    alarmedOn('holding');
    expect(await holdersIn(w, await orderSlot(w, 'INV-7'))).toBe('none');
  });

  it("counts a request on its supplier alone where its claim's payee key doesn't hold to its seal, alarmed", async () => {
    const { w, acting } = await ready({ madeBeforeOrderSlots: true });
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    await cutOverByHand(w);
    const held = await decided(acting, w, 'INV-7', supplierId);
    await asBeforeTr2(w, [held.id]);
    await asOwner(w, (owner) =>
      owner.query("update spend_requests.order_claims set payee_key = 'planted-payee' where request_id = $1", [
        held.id,
      ]),
    );

    await visit(w);
    // Its supplier's order and bank slots alone: no signed fact names its key.
    expect(lines('order_slots.cut_over')).toEqual([expect.objectContaining({ opened: 2 })]);
    const [supplierOrder, payeeOrder] = await slotKeys(w, 'INV-7', supplierId, 'payee-1');
    expect(await holdersIn(w, supplierOrder ?? ({} as OrderSlotKey))).toBe(held.id);
    expect(await holdersIn(w, payeeOrder ?? ({} as OrderSlotKey))).toBe('none');
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ subjectType: SPEND_REQUESTS.subject, objectId: held.id, reason: 'holding' }),
    );
  });

  it('is not cut over over a decision that already names its slots (made past the app): alarmed', async () => {
    const { w, acting } = await ready({ madeBeforeOrderSlots: true });
    await cutOverByHand(w);
    await decided(acting, w, 'INV-7');
    await asBeforeTr2(w, []);
    await visit(w);
    expect(lines('order_slots.cutover_held')).toHaveLength(1);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ subjectType: SPEND_REQUESTS.subject, reason: 'holding' }),
    );
  });

  it('answers a cutover asked directly: already for one born counted, waiting for its payee windows before them', async () => {
    expect(await cut((await ready()).w)).toEqual({ outcome: 'already' });
    expect(await cut((await ready({ madeBeforePayeeWindows: true })).w)).toEqual({ outcome: 'not_yet' });
  });

  it('is cut over after its payee windows, at the same first visit, for one made before both', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    expect(await ask(acting, w, 'INV-7')).toEqual(refused(503, 'ORGANISATION_BUSY'));
    await visit(w);
    expect(lines('payee_windows.cut_over')).toHaveLength(1);
    expect(lines('order_slots.cut_over')).toHaveLength(1);
    expect((await decided(acting, w, 'INV-7')).decision).toBe('ALLOW');
  });

  it('logs a slots cutover that fails and goes on', async () => {
    // Not an organisation's ID at all: its transaction refused before anything is read.
    await createHoldingsCheck({
      list: () => Promise.resolve(['not an organisation']),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      cutoverHoldOffMs: 0,
    }).run();
    expect(lines('order_slots.cutover_failed')).toHaveLength(1);
  });
});
