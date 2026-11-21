// GM-1b (0112; Threat-Model R-15): a payee's split window kept as signed
// hourly totals, on the real migrated schema as the app role (ADR-012 §2;
// FX-TAMPER). The database's owner, holding the owner login but none of the
// app's keys, deleting, zeroing or releasing a payee's reservations no longer
// takes a split payment past its approval: it is still sent for approval. The
// window itself changed past the app (zeroed, rolled back, deleted, planted,
// swapped, pointed at another event) refuses every decision on the payee,
// raises the integrity alarm and holds the organisation. Every ending gives
// capacity back to the windows its decision sealed; the holdings check holds
// each window to its reservations; locks are taken at 11b, after the month
// totals and in order of ID; and an organisation made before GM-1b is refused
// busy until its cutover opens its windows from its signed requests.
import {
  type AuditDetails,
  checkStatesWith,
  createAuditTrail,
  type SignedStates,
  withSignedStates,
} from '@agentx/core/modules/audit';
import {
  hourOf,
  type LimitReservationsTables,
  PAYEE_WINDOWS,
  type PayeeWindowCheck,
  payeeWindowId,
  type PayeeWindowKey,
  payeeWindowOf,
  payeeWindowsOf,
  WINDOWS_CUTOVER_ACTION,
  WINDOWS_CUTOVER_SUBJECT,
  windowsGivenBack,
} from '@agentx/core/modules/limit-reservations';
import { createOutbox } from '@agentx/core/modules/notifications';
import { paymentHoldsOf } from '@agentx/core/modules/outcomes';
import {
  cancelRequest,
  cutOverPayeeWindows,
  expireRequest,
  rejectRequest,
  requestOf,
  settleCarried,
  SPEND_REQUESTS,
  type SpendRequestsTables,
  voidedWith,
  voidPendingOf,
} from '@agentx/core/modules/spend-requests';
import { SUPPLIERS, supplierOf } from '@agentx/core/modules/suppliers';
import type { PaymentsTables } from '@agentx/core/modules/transactions';
import { CHAIN_START, createDigestLog } from '@agentx/platform/audit-chain';
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

import { createHoldingsCheck } from './holdings-check.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { weighedAgain } from './spend-request-approvals.ts';
import { AED, keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';
import {
  type AgentActing,
  createSpendRequestDecisions,
  DECIDE_OPERATION,
  type SpendAskedByAgent,
  type SpendRequestDecisions,
} from './spend-request-decisions.ts';

type Tables = MandateWorldTables & SpendRequestsTables & LimitReservationsTables & PaymentsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0x0112_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-000000000112';
const OPERATOR = { type: 'system', id: 'test' } as const;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'payee-windows' });
const { world, quiet, agentKey, eventsAbout } = shared;

/**
 * The tests' clock starts at this hour, the database's own: a window lets go of hours a month old, and an expiry is
 * judged by the database's clock (the chain seals a decision's time by it), so the two must agree to the hour.
 */
const START = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000);

/** An order of 3,000: two to one payee in a day cross the 5,000 approval threshold together, never alone. */
const ORDER = 300_000n;
const SPLIT = { decision: 'REQUIRE_APPROVAL', reasons: ['AGGREGATE_THRESHOLD'] };

/** Every agent's mandate here: the split check on (its default), approval above 5,000. */
const TERMS = { perOrderLimit: AED(800_000n), monthlyLimit: AED(1_600_000n), approvalThreshold: AED(500_000n) };

/** A world whose agent has a key and a mandate in force with the split check on, and its suppliers verified. */
async function ready(options: Parameters<typeof world>[0] = {}) {
  const w = await world(options);
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, TERMS);
  return { w, acting: await agentKey(w) };
}

/** The world's first supplier, or its second. */
const supplierOf_ = (w: World, which: 0 | 1 = 0) => w.suppliers[which] ?? '';

let keysUsed = 0;
const asking = (w: World, amount: bigint, supplierId: string): SpendAskedByAgent => ({
  amount: AED(amount),
  supplierId,
  fundingSourceId: w.source,
  orderReference: `INV-${String(keysUsed)}`,
  purpose: 'Printer paper',
});
const ask = (acting: AgentActing, w: World, amount: bigint, supplierId = supplierOf_(w)) => {
  keysUsed += 1;
  const asked = asking(w, amount, supplierId);
  return decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `window-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor), n: keysUsed }),
    },
    asked,
    CORRELATION,
  );
};
/** The request a decision answered with. */
const decided = async (acting: AgentActing, w: World, amount = ORDER, supplierId = supplierOf_(w)) => {
  const answer = await ask(acting, w, amount, supplierId);
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

/** A supplier's own window, in AED. */
const supplierKey = (supplierId: string): PayeeWindowKey => ({ supplierId, payeeKey: null, currency: 'AED' });
const windowOf = (w: World, key: PayeeWindowKey) =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    payeeWindowOf(tx, states, w.org, payeeWindowId(w.org, key), 'share'),
  );
/** What a window holds in all, or how it read. */
const heldIn = async (w: World, key: PayeeWindowKey) => {
  const read = await windowOf(w, key);
  return read.outcome === 'held' ? [...read.held.values()].reduce((sum, amount) => sum + amount, 0n) : read.outcome;
};
const holdOf = (w: World) => withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
const lines = (event: string) => capture.lines().filter((line) => line.event === event);
const alarmedOn = (reason: string) => {
  expect(lines('audit.integrity_failed')).toContainEqual(
    expect.objectContaining({ subjectType: PAYEE_WINDOWS.subject, reason }),
  );
};

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

/** The owner's statements in one transaction, inside the organisation, the user triggers of the limit tables off. */
async function asOwner(w: World, work: (owner: Owner) => Promise<unknown>) {
  const owner = await tamperAsOwner(database, PAYEE_WINDOWS, w.org);
  try {
    await owner.query('begin');
    await owner.query('alter table limit_reservations.reservations disable trigger user');
    await owner.query('alter table limit_reservations.payee_windows disable trigger user');
    await work(owner);
    await owner.query('alter table limit_reservations.reservations enable trigger user');
    await owner.query('alter table limit_reservations.payee_windows enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}
const windowTamper = async (w: World, work: (owner: Owner) => Promise<void>) => {
  const owner = await tamperAsOwner(database, PAYEE_WINDOWS, w.org);
  try {
    await work(owner);
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

describe("a payee's split window, signed (GM-1b)", () => {
  it("is made by the payee's first decision and added to at each one's hour, sealed, its ID in the decision", async () => {
    const { w, acting } = await ready();
    const supplier = supplierKey(supplierOf_(w));
    expect(await heldIn(w, supplier)).toBe('none');
    const first = await decided(acting, w, ORDER);
    clock.advanceBy(3_600_000);
    await decided(acting, w, 100_000n);
    const read = await windowOf(w, supplier);
    expect(read.outcome === 'held' ? read.held : undefined).toEqual(
      new Map([
        [hourOf(START), ORDER],
        [hourOf(START) + 1, 100_000n],
      ]),
    );
    const id = payeeWindowId(w.org, supplier);
    const events = await eventsAbout(w.org, id, PAYEE_WINDOWS.subject);
    expect(events.map(({ action }) => action)).toEqual(['payee_window.held', 'payee_window.held']);
    expect(events[0]).toMatchObject({ actorType: 'agent' });
    // The decision seals the windows its capacity went into: a supplier with no key, its own alone.
    const decidedEvent = (await eventsAbout(w.org, first.id, SPEND_REQUESTS.subject)).find(
      ({ action }) => action === 'spend_request.decided',
    );
    expect(decidedEvent?.details).toMatchObject({ payeeWindows: id });
  });

  it("counts a supplier with a payee key in its own window, its key's and the pair's", async () => {
    const { w, acting } = await ready();
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    const request = await decided(acting, w, ORDER, supplierId);
    const rows = [
      supplierKey(supplierId),
      { supplierId: null, payeeKey: 'payee-1', currency: 'AED' },
      { supplierId, payeeKey: 'payee-1', currency: 'AED' },
    ];
    for (const row of rows) expect(await heldIn(w, row)).toBe(ORDER);
    const decidedEvent = (await eventsAbout(w.org, request.id, SPEND_REQUESTS.subject)).find(
      ({ action }) => action === 'spend_request.decided',
    );
    expect(decidedEvent?.details).toMatchObject({
      payeeWindows: rows.map((row) => payeeWindowId(w.org, row)).join(','),
    });
  });

  it("weighs a payee's orders under another supplier holding its key, never twice those of the pair", async () => {
    const { w, acting } = await ready();
    const [first, second] = [supplierOf_(w), supplierOf_(w, 1)];
    await payeeKeyOf(w, first, 'payee-1');
    expect((await decided(acting, w, ORDER, first)).decision).toBe('ALLOW');
    // The key moves to the second supplier (one supplier a key at a time, 0033).
    await payeeKeyOf(w, first, null);
    await payeeKeyOf(w, second, 'payee-1');
    expect(await decided(acting, w, ORDER, second)).toMatchObject(SPLIT);
    // The first supplier, with no key now, still counts its own orders, made under the key, once each.
    const third = await decided(acting, w, 100_000n, first);
    expect(third.decision).toBe('ALLOW');
    expect(await heldIn(w, supplierKey(first))).toBe(ORDER + 100_000n);
  });

  it.each<[string, (owner: Owner) => Promise<unknown>]>([
    ['deleted', (owner) => owner.query('delete from limit_reservations.reservations')],
    ['zeroed', (owner) => owner.query('update limit_reservations.reservations set amount_minor = 0')],
    [
      'released',
      (owner) => owner.query("update limit_reservations.reservations set state = 'RELEASED', settled_at = reserved_at"),
    ],
  ])(
    "R-15: still sends a split order for approval once the owner has %s every one of the payee's reservations",
    async (_what, change) => {
      const { w, acting } = await ready();
      const theirs = await shared.secondAgent(registry, w, TERMS);
      expect((await decided(acting, w)).decision).toBe('ALLOW');
      await asOwner(w, change);

      // Another agent's order to the same payee: its month is empty, the payee's window isn't.
      expect(await decided(theirs, w)).toMatchObject(SPLIT);
      expect(await heldIn(w, supplierKey(supplierOf_(w)))).toBe(2n * ORDER);
    },
  );

  it('is caught zeroed by its seal: every decision on the payee refused, alarmed, the organisation held', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    await windowTamper(w, (owner) =>
      owner.setColumn(payeeWindowId(w.org, supplierKey(supplierOf_(w))), 'held_by_hour', ''),
    );

    expect(await ask(acting, w, ORDER)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('seal');
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('is caught rolled back to an older, validly signed state: its version is not the newest', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    const id = payeeWindowId(w.org, supplierKey(supplierOf_(w)));
    let saved: Awaited<ReturnType<Owner['saveRow']>> | undefined;
    await windowTamper(w, async (owner) => {
      saved = await owner.saveRow(id);
    });
    await decided(acting, w, 100_000n);
    await windowTamper(w, (owner) => owner.restoreRow(saved ?? ({} as never)));

    expect(await ask(acting, w, 100_000n)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('pointer');
  });

  it('is caught deleted: its events name it, so it never reads as a payee with nothing held', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    await windowTamper(w, (owner) => owner.deleteRow(payeeWindowId(w.org, supplierKey(supplierOf_(w)))));

    expect(await ask(acting, w, ORDER)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('deleted');
  });

  it('is caught planted with no event of its own', async () => {
    const { w, acting } = await ready();
    const second = supplierOf_(w, 1);
    await asOwner(w, (owner) =>
      owner.query(
        "insert into limit_reservations.payee_windows (org_id, id, supplier_id, payee_key, currency, held_by_hour, created_at) values ($1, $2, $3, null, 'AED', '', now())",
        [w.org, payeeWindowId(w.org, supplierKey(second)), second],
      ),
    );

    expect(await ask(acting, w, ORDER, second)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('unsigned');
  });

  it("is caught swapped with another payee's, each signed: the seal names its own object", async () => {
    const { w, acting } = await ready();
    const [first, second] = [supplierOf_(w), supplierOf_(w, 1)];
    await decided(acting, w, ORDER, first);
    await decided(acting, w, 1n, second);
    await asOwner(w, (owner) =>
      owner.query(
        'update limit_reservations.payee_windows t set held_by_hour = o.held_by_hour, state_version = o.state_version, state_event_id = o.state_event_id from limit_reservations.payee_windows o where t.id = $1 and o.id = $2',
        [payeeWindowId(w.org, supplierKey(first)), payeeWindowId(w.org, supplierKey(second))],
      ),
    );

    expect(await ask(acting, w, ORDER, first)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('pointer');
  });

  it('AT13: is caught at decision time rolled back with its newest event deleted below the anchor; the anchor alone lets it pass', async () => {
    const { w, acting } = await ready();
    const theirs = await shared.secondAgent(registry, w, TERMS);
    await decided(acting, w, 100_000n);
    const id = payeeWindowId(w.org, supplierKey(supplierOf_(w)));
    let saved: Awaited<ReturnType<Owner['saveRow']>> | undefined;
    await windowTamper(w, async (owner) => {
      saved = await owner.saveRow(id);
    });
    await decided(acting, w, 200_000n);
    // The anchor check's walk of the whole chain, kept in the digest, the window's newest state in it.
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
    // Below that anchor, the owner deletes the window's newest event and rolls its row back to the state before.
    const owner = await tamperAsOwner(database, PAYEE_WINDOWS, w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table audit.events disable trigger user');
      await owner.query(
        'delete from audit.events where org_id = $1 and seq = (select max(seq) from audit.events where org_id = $1 and subject_type = $2 and subject_id = $3)',
        [w.org, PAYEE_WINDOWS.subject, id],
      );
      await owner.query('alter table audit.events enable trigger user');
      await owner.query('commit');
      await owner.restoreRow(saved ?? ({} as never));
    } finally {
      await owner.end();
    }

    // The positive control: with no digest, the window reads as it was, 1,000 held, and the split passes.
    const control = await windowOf(w, supplierKey(supplierOf_(w)));
    expect(control.outcome === 'held' ? [...control.held.values()] : control.outcome).toEqual([100_000n]);
    // Held to the digest: the window's newest signed state is gone, so another agent's decision on it is refused.
    checkStatesWith(digest);
    try {
      expect(await ask(theirs, w, 300_000n)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    } finally {
      checkStatesWith(undefined);
    }
    alarmedOn('log');
  });

  it('is caught pointed at a forged event ID', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    await windowTamper(w, (owner) =>
      owner.setColumn(
        payeeWindowId(w.org, supplierKey(supplierOf_(w))),
        'state_event_id',
        '0199a0f0-0000-7000-8000-00000000f0f0',
      ),
    );

    expect(await ask(acting, w, ORDER)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    alarmedOn('pointer');
  });
});

describe("the window's own rules", () => {
  it('is named apart for each organisation, supplier, payee key (its case too) and currency', () => {
    const org = '0199a0f0-0000-7000-8000-00000000b001';
    const supplierId = '0199a0f0-0000-7000-8000-00000000a001';
    const named = (key: Partial<PayeeWindowKey>, orgId = org) =>
      payeeWindowId(orgId, { supplierId, payeeKey: null, currency: 'AED', ...key });
    const all = [
      named({}),
      named({}, '0199a0f0-0000-7000-8000-00000000b002'),
      named({ currency: 'USD' }),
      named({ supplierId: '0199a0f0-0000-7000-8000-00000000a002' }),
      named({ payeeKey: 'payee-1' }),
      named({ payeeKey: 'Payee-1' }),
      named({ supplierId: null, payeeKey: 'payee-1' }),
    ];
    expect(new Set(all).size).toBe(all.length);
    expect(named({})).toBe(named({}));
    expect(named({ supplierId: supplierId.toUpperCase() })).toBe(named({}));
  });

  /** The window's capacity given back in a transaction of its own, read for change first, as an ending does. */
  const givenBack = (w: World, key: PayeeWindowKey, hour: number, amount: bigint) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const id = payeeWindowId(w.org, key);
      const read = await payeeWindowsOf(tx, states, w.org, [id], 'change');
      await windowsGivenBack(tx, states, w.org, read, [{ id, requestId: id, hour, amount }], {
        at: clock.now(),
        change: { actor: OPERATOR, action: 'payee_window.released', details: {} },
      });
    });

  it('gives back no more than an hour holds: past it, nothing held, and the mismatch alarmed', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    const supplier = supplierKey(supplierOf_(w));
    await givenBack(w, supplier, hourOf(clock.now()), ORDER + 1n);
    expect(await heldIn(w, supplier)).toBe(0n);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: PAYEE_WINDOWS.subject });
  });

  it('gives back nothing to an hour no window counts any more, and raises nothing', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    const supplier = supplierKey(supplierOf_(w));
    await givenBack(w, supplier, hourOf(clock.now()) - 800, ORDER);
    expect(await heldIn(w, supplier)).toBe(ORDER);
    expect(lines('audit.integrity_failed')).toEqual([]);
    // Nothing to give back is nothing recorded: the window keeps its state.
    const events = await eventsAbout(w.org, payeeWindowId(w.org, supplier), PAYEE_WINDOWS.subject);
    expect(events.map(({ action }) => action)).toEqual(['payee_window.held']);
  });

  it('alarms a give-back to a payee with no window once cut over, and gives nothing back before', async () => {
    const { w } = await ready();
    await givenBack(w, supplierKey(supplierOf_(w)), hourOf(clock.now()), 1n);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held', reason: 'holding', foundOn: PAYEE_WINDOWS.subject });
    const before = await ready({ madeBeforePayeeWindows: true });
    capture = new LogCapture();
    await givenBack(before.w, supplierKey(supplierOf_(before.w)), hourOf(clock.now()), 1n);
    expect(await holdOf(before.w)).toMatchObject({ outcome: 'clear' });
  });
});

describe('every ending gives its amount back to the windows its decision sealed, the holdings check finding nothing apart', () => {
  type Ending = (w: World, acting: AgentActing, requestId: string) => Promise<unknown>;
  const OPERATOR_USER = '0199a0f0-0000-7000-8000-0000000000aa';
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
      "a person's cancel",
      (w, _acting, id) =>
        inOrg(w, (tx, states) =>
          cancelRequest(tx, states, keys, { orgId: w.org, id }, { kind: 'user', userId: OPERATOR_USER }, clock.now()),
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
            { userId: OPERATOR_USER, reason: 'Not this month', stepUp: {} },
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
    const w = await world();
    for (const id of w.suppliers) await shared.verified(w, id);
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    // Approvals from AED 1,000: both wait for one, so every ending can take the first.
    await shared.inForce(registry, w, {
      perOrderLimit: AED(800_000n),
      monthlyLimit: AED(1_600_000n),
      approvalThreshold: AED(100_000n),
    });
    const acting = await agentKey(w);
    const ended = await decided(acting, w, ORDER, supplierId);
    expect(ended.decision).toBe('REQUIRE_APPROVAL');
    await decided(acting, w, 50_000n, supplierId);
    await end(w, acting, ended.id);
    const rows = [
      supplierKey(supplierId),
      { supplierId: null, payeeKey: 'payee-1', currency: 'AED' },
      { supplierId, payeeKey: 'payee-1', currency: 'AED' },
    ];
    for (const row of rows) expect(await heldIn(w, row)).toBe(50_000n);
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({
      windows: 3,
      windowsMismatched: 0,
      windowsMissing: 0,
      windowsTampered: 0,
    });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it("gives back once a window for a brake's whole batch, across agents", async () => {
    const { w, acting } = await ready();
    const theirs = await shared.secondAgent(registry, w, TERMS);
    await decided(acting, w, 100_000n);
    await decided(theirs, w, 100_000n);
    const voided = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      voidPendingOf(tx, states, keys, w.org, { supplierId: supplierOf_(w) }, 'SUPPLIER_NOT_VERIFIED', clock.now()),
    );
    expect(voided).toBe(2);
    const supplier = supplierKey(supplierOf_(w));
    expect(await heldIn(w, supplier)).toBe(0n);
    const released = (await eventsAbout(w.org, payeeWindowId(w.org, supplier), PAYEE_WINDOWS.subject)).filter(
      ({ action }) => action === 'payee_window.released',
    );
    expect(released).toHaveLength(1);
    expect(await holdOf(w)).toMatchObject({ outcome: 'clear' });
  });
});

describe('in the lock order (11b: after the month totals, in order of ID), forced', () => {
  /** A void of `requestId` in a transaction of its own, held open at `gate` once it has given its capacity back. */
  const voidHeldOpen = (w: World, requestId: string, gate: Promise<unknown>, given: () => void) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await requestOf(tx, states, { orgId: w.org, id: requestId }, 'change');
      await voidedWith(tx, states, keys, { orgId: w.org, id: requestId }, ['AGENT_SUSPENDED'], clock.now());
      given();
      await gate;
    });
  /** The window held for change in a transaction of its own until `gate`, as a decision holds it with its month. */
  const windowHeld = (w: World, key: PayeeWindowKey, gate: Promise<unknown>, held: () => void) =>
    withSignedStates(app, w.org, quiet(), async (tx, states) => {
      await payeeWindowOf(tx, states, w.org, payeeWindowId(w.org, key), 'change');
      held();
      await gate;
    });

  it("makes another agent's decision to the payee wait for an ending holding its window, then weighs what it gave back", async () => {
    const { w, acting } = await ready();
    const theirs = await shared.secondAgent(registry, w, TERMS);
    const first = await decided(acting, w);
    const { promise: given, resolve: giving } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const voiding = voidHeldOpen(w, first.id, gate, () => {
      giving(undefined);
    });
    await given;
    // Its own month's total is free: it waits on the payee's window alone.
    const deciding = within(20_000, decided(theirs, w), 'the decision');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await voiding;

    // Weighed after the void, against the window it gave back to: alone in the window, allowed.
    expect((await deciding).decision).toBe('ALLOW');
    expect(await heldIn(w, supplierKey(supplierOf_(w)))).toBe(ORDER);
  });

  it('makes an ending take its request (8), reservation (11) and month total (11a) before it waits for the window (11b)', async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = windowHeld(w, supplierKey(supplierOf_(w)), gate, () => {
      holding(undefined);
    });
    await held;
    const voiding = within(
      20_000,
      voidHeldOpen(w, first.id, Promise.resolve(), () => undefined),
      'the void',
    );
    await waitUntilQueued(database.as('admin'), 1);
    await expect(
      database
        .as('admin')
        .query('select 1 from spend_requests.requests where id = $1 for no key update nowait', [first.id]),
    ).rejects.toMatchObject({
      code: '55P03',
    });
    await expect(
      database
        .as('admin')
        .query('select 1 from limit_reservations.reservations where request_id = $1 for no key update nowait', [
          first.id,
        ]),
    ).rejects.toMatchObject({ code: '55P03' });
    await expect(
      database
        .as('admin')
        .query('select 1 from limit_reservations.month_totals where agent_id = $1 for no key update nowait', [w.agent]),
    ).rejects.toMatchObject({ code: '55P03' });
    open(undefined);
    await holder;
    await voiding;
    expect(await heldIn(w, supplierKey(supplierOf_(w)))).toBe(0n);
  });

  it("makes an approval's confirm take its request's own sealed windows with its payee's, before anything after them: it waits for one held", async () => {
    const { w, acting } = await ready();
    const supplierId = supplierOf_(w);
    await payeeKeyOf(w, supplierId, 'payee-1');
    // Over the threshold alone: it waits for an approver, its capacity in the old key's windows.
    const waiting = await decided(acting, w, 600_000n, supplierId);
    expect(waiting.decision).toBe('REQUIRE_APPROVAL');
    // The supplier's key changes while it waits: its payee's windows now are the new key's, not those it sealed.
    await payeeKeyOf(w, supplierId, null);
    await payeeKeyOf(w, supplierId, 'payee-2');
    const sealedOnly: PayeeWindowKey = { supplierId: null, payeeKey: 'payee-1', currency: 'AED' };
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = windowHeld(w, sealedOnly, gate, () => {
      holding(undefined);
    });
    await held;
    let weighed = false;
    const confirming = within(
      20_000,
      withSignedStates(app, w.org, quiet(), async (tx, states) => {
        await weighedAgain(tx, states, {
          orgId: w.org,
          requestId: waiting.id,
          now: clock.now(),
          decides: true,
        });
        weighed = true;
      }),
      'the confirm',
    );
    // It waits for the old key's window, which its reject would give back to, as it reads its payee's windows.
    await waitUntilQueued(database.as('admin'), 1);
    expect(weighed).toBe(false);
    open(undefined);
    await holder;
    await confirming;
    expect(weighed).toBe(true);
  });

  it('makes two brakes over the same windows take the lower first and wait for the higher: neither deadlocks', async () => {
    const { w, acting } = await ready();
    const theirs = await shared.secondAgent(registry, w, TERMS);
    const [first, second] = [supplierOf_(w), supplierOf_(w, 1)];
    // Each agent holds capacity with both suppliers: each agent's brake voids a request in each supplier's window.
    for (const agent of [acting, theirs]) {
      await decided(agent, w, 100_000n, first);
      await decided(agent, w, 100_000n, second);
    }
    const [low = '', high = ''] = [
      payeeWindowId(w.org, supplierKey(first)),
      payeeWindowId(w.org, supplierKey(second)),
    ].toSorted();
    const highKey = high === payeeWindowId(w.org, supplierKey(first)) ? supplierKey(first) : supplierKey(second);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = windowHeld(w, highKey, gate, () => {
      holding(undefined);
    });
    await held;
    const brake = (agentId: string) =>
      within(
        20_000,
        withSignedStates(app, w.org, quiet(), (tx, states) =>
          voidPendingOf(tx, states, keys, w.org, { agentId }, 'AGENT_SUSPENDED', clock.now()),
        ),
        `the brake on ${agentId}`,
      );
    const one = brake(acting.agentId);
    await waitUntilQueued(database.as('admin'), 1);
    // It holds the lower window already, waiting only for the higher.
    await expect(
      database
        .as('admin')
        .query('select 1 from limit_reservations.payee_windows where id = $1 for no key update nowait', [low]),
    ).rejects.toMatchObject({
      code: '55P03',
    });
    const other = brake(theirs.agentId);
    // The second waits for the lower window, behind the first: never holding one the first waits for.
    await waitUntilQueued(database.as('admin'), 2);
    open(undefined);
    await holder;

    expect(await one).toBe(2);
    expect(await other).toBe(2);
    expect(await heldIn(w, supplierKey(first))).toBe(0n);
    expect(await heldIn(w, supplierKey(second))).toBe(0n);
  });
});

describe('the holdings check', () => {
  it('holds each window to its reservations: a reservation deleted past the app is a mismatch, alarmed', async () => {
    const { w, acting } = await ready();
    const first = await decided(acting, w, 100_000n);
    await decided(acting, w, 100_000n, supplierOf_(w, 1));
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ windows: 2, windowsMismatched: 0 });
    await asOwner(w, (owner) =>
      owner.query('delete from limit_reservations.reservations where request_id = $1', [first.id]),
    );
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ windows: 2, windowsMismatched: 1 });
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('counts a window tampered with apart, its read raising the alarm', async () => {
    const { w, acting } = await ready();
    await decided(acting, w, 100_000n);
    await windowTamper(w, (owner) =>
      owner.setColumn(payeeWindowId(w.org, supplierKey(supplierOf_(w))), 'held_by_hour', '1:1'),
    );
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ windows: 1, windowsTampered: 1 });
    alarmedOn('seal');
  });

  it('alarms a payee whose reservations hold capacity with no window and nothing signed for one', async () => {
    const { w, acting } = await ready();
    await decided(acting, w, 100_000n);
    const id = payeeWindowId(w.org, supplierKey(supplierOf_(w)));
    await windowTamper(w, async (owner) => {
      await owner.deleteRow(id);
      await owner.deleteEvents(id);
    });
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ windows: 0, windowsMissing: 1 });
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });
});

describe('an organisation made before GM-1b, until its cutover', () => {
  /** Its windows' cutover by hand, so its decisions can be made: then taken away with the windows, as before GM-1b. */
  const cutOverByHand = (w: World) =>
    withSignedStates(app, w.org, quiet(), (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: OPERATOR,
        action: WINDOWS_CUTOVER_ACTION,
        subject: { type: WINDOWS_CUTOVER_SUBJECT, id: w.org, version: 1 },
        details: {},
      }),
    );
  /**
   * The organisation as one before GM-1b with capacity held: the windows its decisions filled, their events and the
   * cutover's taken away by the owner, each request's decision sealed again as before GM-1b (no windows named).
   */
  const asBeforeGm1b = async (
    w: World,
    requestIds: readonly string[],
    windows: 'delete windows' | 'keep windows' = 'delete windows',
  ) => {
    for (const id of requestIds) {
      const sealed = (await eventsAbout(w.org, id, SPEND_REQUESTS.subject)).findLast(
        ({ action }) => action === 'spend_request.decided',
      );
      // What a decision before GM-1b sealed of what it holds, and nothing of the request's own signed state.
      const details = (sealed?.details ?? {}) as AuditDetails;
      const before = Object.fromEntries(
        [
          'decision',
          'heldMonth',
          'heldAt',
          'payeeSeal',
          'payeeSealKeyVersion',
          'possibleDuplicate',
          'approvalWaitHours',
        ]
          .filter((name) => Object.hasOwn(details, name))
          .map((name) => [name, details[name]]),
      ) as AuditDetails;
      await withSignedStates(app, w.org, quiet(), (tx) =>
        createAuditTrail({ keys, ids }).record(tx, w.org, {
          actor: { type: 'system', id: 'api' },
          action: 'spend_request.decided',
          subject: { type: SPEND_REQUESTS.subject, id, version: 2 },
          details: before,
        }),
      );
    }
    const owner = await tamperAsOwner(database, PAYEE_WINDOWS, w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table audit.events disable trigger user');
      if (windows === 'delete windows') {
        await owner.query('delete from limit_reservations.payee_windows where org_id = $1', [w.org]);
      }
      // The windows' own events go with them; kept windows keep theirs, signed.
      await owner.query('delete from audit.events where org_id = $1 and (subject_type = $2 or action = $3)', [
        w.org,
        windows === 'delete windows' ? PAYEE_WINDOWS.subject : 'none',
        WINDOWS_CUTOVER_ACTION,
      ]);
      await owner.query('alter table audit.events enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }
  };

  it('is refused busy, never weighed from its reservations, until its cutover, with nothing to open', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    expect(await ask(acting, w, ORDER)).toEqual(refused(503, 'ORGANISATION_BUSY'));
    await visit(w);
    expect(lines('payee_windows.cut_over')).toEqual([expect.objectContaining({ opened: 0, mismatched: 0 })]);
    expect((await decided(acting, w)).decision).toBe('ALLOW');
  });

  it('is cut over after its month totals, at the same first visit, for one made before either', async () => {
    const { w, acting } = await ready({ madeBeforeMonthTotals: true });
    expect(await ask(acting, w, ORDER)).toEqual(refused(503, 'ORGANISATION_BUSY'));
    await visit(w);
    expect(lines('month_totals.cut_over')).toHaveLength(1);
    expect(lines('payee_windows.cut_over')).toHaveLength(1);
    expect((await decided(acting, w)).decision).toBe('ALLOW');
  });

  it("opens each payee's window from the signed requests, at their sealed hours, and weighs them from then on", async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    await cutOverByHand(w);
    const held = await decided(acting, w);
    clock.advanceBy(2 * 3_600_000);
    const other = await decided(acting, w, 100_000n, supplierOf_(w, 1));
    await asBeforeGm1b(w, [held.id, other.id]);
    expect(await ask(acting, w, ORDER)).toEqual(refused(503, 'ORGANISATION_BUSY'));

    await visit(w);
    expect(lines('payee_windows.cut_over')).toEqual([expect.objectContaining({ opened: 2, mismatched: 0 })]);
    const read: PayeeWindowCheck = await windowOf(w, supplierKey(supplierOf_(w)));
    expect(read.outcome === 'held' ? read.held : undefined).toEqual(new Map([[hourOf(START), ORDER]]));
    expect(await heldIn(w, supplierKey(supplierOf_(w, 1)))).toBe(100_000n);
    // Weighed from the window opened: a second order to the payee in the day is a split.
    expect(await decided(acting, w)).toMatchObject(SPLIT);
    await visit(w);
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ windowsMismatched: 0, windowsMissing: 0 });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('opens from the signed requests even where the owner cut the reservations, the mismatch alarmed', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    await cutOverByHand(w);
    const held = await decided(acting, w);
    await asBeforeGm1b(w, [held.id]);
    await asOwner(w, (owner) => owner.query('delete from limit_reservations.reservations'));

    await visit(w);
    expect(lines('payee_windows.cut_over')).toEqual([expect.objectContaining({ opened: 1, mismatched: 1 })]);
    expect(await heldIn(w, supplierKey(supplierOf_(w)))).toBe(ORDER);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('alarms a payee the reservations hold capacity with that no signed request does, and opens nothing for it', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    await cutOverByHand(w);
    const ended = await decided(acting, w, ORDER, supplierOf_(w, 1));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: ended.id },
        { kind: 'user', userId: '0199a0f0-0000-7000-8000-0000000000aa' },
        clock.now(),
      ),
    );
    await asBeforeGm1b(w, [ended.id]);
    // Its reservation held again past the app.
    await asOwner(w, (owner) =>
      owner.query(
        "update limit_reservations.reservations set state = 'HELD', settled_at = null where request_id = $1",
        [ended.id],
      ),
    );

    await visit(w);
    expect(lines('payee_windows.cut_over')).toEqual([expect.objectContaining({ opened: 0, mismatched: 1 })]);
    expect(await heldIn(w, supplierKey(supplierOf_(w, 1)))).toBe('none');
  });

  it('answers a cutover asked directly: already for one born counted, waiting for its month totals before them', async () => {
    const cut = (w: World) =>
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        cutOverPayeeWindows(tx, states, w.org, {
          payments: paymentHoldsOf,
          record: (event) => createAuditTrail({ keys, ids }).record(tx, w.org, event),
          at: clock.now(),
        }),
      );
    expect(await cut((await ready()).w)).toEqual({ outcome: 'already' });
    expect(await cut((await ready({ madeBeforeMonthTotals: true })).w)).toEqual({ outcome: 'not_yet' });
  });

  it('opens nothing for an hour no window counts any more, nor for a request ended before it', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    await cutOverByHand(w);
    const old = await decided(acting, w, 100_000n);
    const ended = await decided(acting, w, 100_000n, supplierOf_(w, 1));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: ended.id },
        { kind: 'user', userId: '0199a0f0-0000-7000-8000-0000000000aa' },
        clock.now(),
      ),
    );
    await asBeforeGm1b(w, [old.id]);
    // 32 days on: past every window, the request still waiting (its approval long expired but not yet swept).
    clock.advanceBy(32 * 24 * 3_600_000);
    await visit(w);
    expect(lines('payee_windows.cut_over')).toEqual([expect.objectContaining({ opened: 0, mismatched: 0 })]);
  });

  it('is not cut over over a window planted before it: nothing opened, alarmed', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    await cutOverByHand(w);
    const held = await decided(acting, w);
    const other = await decided(acting, w, 100_000n, supplierOf_(w, 1));
    await asBeforeGm1b(w, [held.id, other.id]);
    const supplierId = supplierOf_(w);
    await asOwner(w, (owner) =>
      owner.query(
        "insert into limit_reservations.payee_windows (org_id, id, supplier_id, payee_key, currency, held_by_hour, created_at) values ($1, $2, $3, null, 'AED', '', now())",
        [w.org, payeeWindowId(w.org, supplierKey(supplierId)), supplierId],
      ),
    );
    await visit(w);
    expect(lines('payee_windows.cutover_held')).toHaveLength(1);
    expect(lines('payee_windows.cut_over')).toEqual([]);
    alarmedOn('unsigned');
    // Not cut over, the other payee's window is none to look for: not counted missing.
    expect(lines('holdings_check.passed').at(-1)).toMatchObject({ windowsMissing: 0 });
  });

  it('is not cut over over a window already signed before it (its cutover gone): nothing opened over it', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    await cutOverByHand(w);
    const held = await decided(acting, w);
    await asBeforeGm1b(w, [held.id]);
    // A window signed by a decision of its own, left; only the cutover taken away.
    await cutOverByHand(w);
    const second = await decided(acting, w, 100_000n, supplierOf_(w, 1));
    await asBeforeGm1b(w, [second.id], 'keep windows');
    await visit(w);
    expect(lines('payee_windows.cutover_held')).toHaveLength(1);
    expect(lines('payee_windows.cut_over')).toEqual([]);
  });

  it('is not cut over over a decision that already names its windows (made past the app): alarmed', async () => {
    const { w, acting } = await ready({ madeBeforePayeeWindows: true });
    await cutOverByHand(w);
    await decided(acting, w);
    // The windows and cutover gone, the decision still naming its windows.
    await asBeforeGm1b(w, []);
    await visit(w);
    expect(lines('payee_windows.cutover_held')).toHaveLength(1);
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ subjectType: SPEND_REQUESTS.subject, reason: 'holding' }),
    );
  });

  it('logs a windows cutover that fails and goes on', async () => {
    // Not an organisation's ID at all: its transaction refused before anything is read.
    await createHoldingsCheck({
      list: () => Promise.resolve(['not an organisation']),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      cutoverHoldOffMs: 0,
    }).run();
    expect(lines('payee_windows.cutover_failed')).toHaveLength(1);
  });
});
