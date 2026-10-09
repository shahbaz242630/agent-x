// Phase 2 E1: the holdings check, on the real migrated schema as the app role
// (ADR-012 §2; SEC-DB-09; FX-TAMPER). Requests made by the agent's own
// decisions (an allowed one, one waiting for approval, a denied duplicate)
// pass, a page at a time and across runs; then each way a reservation or an
// order claim can be changed past the app, by the table's owner with its
// guards switched off, raises the integrity alarm (`holding`) naming the
// request, and puts the organisation on hold: a reservation released,
// lowered or deleted, a claim deleted or released. (A claim moved to another
// order or supplier is refused even then, by 0039's `for_its_request` key.)
import { withSignedStates } from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { SPEND_REQUESTS, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestClient,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHoldingsCheck } from './holdings-check.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, mandateWorld, type MandateWorldTables, type World } from './mandate-world.helper.test.ts';
import {
  type AgentActing,
  createSpendRequestDecisions,
  DECIDE_OPERATION,
  type SpendAskedByAgent,
  type SpendRequestDecided,
  type SpendRequestDecisions,
} from './spend-request-decisions.ts';

type Tables = MandateWorldTables & SpendRequestsTables & LimitReservationsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0xe1a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000e1';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'holdings-check' });
const { world, quiet, agentKey } = shared;

/** A world whose agent has a key and a mandate in force (approval above AED 15,000), both suppliers verified. */
async function ready() {
  const w = await world();
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, { approvalThreshold: AED(1_500_000n) });
  return { w, acting: await agentKey(w) };
}

let keysUsed = 0;
const ask = async (acting: AgentActing, w: World, overrides: Partial<SpendAskedByAgent>) => {
  keysUsed += 1;
  const asked: SpendAskedByAgent = {
    amount: AED(100_000n),
    supplierId: w.suppliers[0] ?? '',
    fundingSourceId: w.source,
    orderReference: 'INV-1',
    purpose: 'Printer paper',
    ...overrides,
  };
  const answer: SpendRequestDecided = await decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `check-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor) }),
    },
    asked,
    CORRELATION,
  );
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

/** An allowed request (AED 1,000), one waiting for approval (AED 16,000) and a denied duplicate: their IDs. */
async function requests(acting: AgentActing, w: World) {
  const allowed = await ask(acting, w, {});
  const waiting = await ask(acting, w, { amount: AED(1_600_000n), orderReference: 'INV-2' });
  const denied = await ask(acting, w, { orderReference: 'inv-1' });
  expect([allowed.decision, waiting.decision, denied.decision]).toEqual(['ALLOW', 'REQUIRE_APPROVAL', 'DENY']);
  return { allowed: allowed.id, waiting: waiting.id, denied: denied.id };
}

const job = (w: World, page = 200, pagesARun = 50) =>
  createHoldingsCheck({
    list: () => Promise.resolve([w.org]),
    database: app,
    keys,
    ids,
    logger: testLogger(capture),
    page,
    pagesARun,
  });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

const holdOf = (w: World) => withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));

/**
 * `change` run on the organisation's rows by the tables' owner, the
 * reservation and claim guards switched off for it: as only something past the
 * app could change them.
 */
async function pastTheApp(w: World, change: (owner: TestClient) => Promise<unknown>) {
  const owner = await database.connect('owner');
  try {
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
    await owner.query('begin');
    await owner.query('alter table limit_reservations.reservations disable trigger user');
    await owner.query('alter table spend_requests.order_claims disable trigger user');
    await change(owner);
    await owner.query('alter table limit_reservations.reservations enable trigger user');
    await owner.query('alter table spend_requests.order_claims enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
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
  decisions = createSpendRequestDecisions({ database: app, keys, ids, clock, logger });
});

describe('the holdings check (E1)', () => {
  it('passes requests holding exactly what their signed states say, a page at a time across runs', async () => {
    const { w, acting } = await ready();
    await requests(acting, w);
    const check = job(w, 2, 1);

    await check.run();
    expect(lines('holdings_check.paused')).toEqual([expect.objectContaining({ requests: 2, mismatched: 0 })]);
    await check.run();

    expect(lines('holdings_check.passed')).toEqual([expect.objectContaining({ requests: 1, mismatched: 0 })]);
    expect(lines('audit.integrity_failed')).toEqual([]);
    expect(await holdOf(w)).toMatchObject({ outcome: 'clear' });
    // A pass ended starts again from the beginning.
    await check.run();
    expect(lines('holdings_check.paused')).toHaveLength(2);
  });

  type Held = Awaited<ReturnType<typeof requests>>;
  const tampered: [string, (owner: TestClient, held: Held) => Promise<unknown>, keyof Held][] = [
    [
      'a reservation released',
      (owner, { allowed }) =>
        owner.query(
          "update limit_reservations.reservations set state = 'RELEASED', settled_at = now() where request_id = $1",
          [allowed],
        ),
      'allowed',
    ],
    [
      'a reservation lowered',
      (owner, { waiting }) =>
        owner.query('update limit_reservations.reservations set amount_minor = 1 where request_id = $1', [waiting]),
      'waiting',
    ],
    [
      'a reservation deleted',
      (owner, { allowed }) =>
        owner.query('delete from limit_reservations.reservations where request_id = $1', [allowed]),
      'allowed',
    ],
    [
      'a claim deleted',
      (owner, { waiting }) => owner.query('delete from spend_requests.order_claims where request_id = $1', [waiting]),
      'waiting',
    ],
    [
      'a reservation moved to another month',
      async (owner, { allowed }) => {
        await owner.query(
          "insert into limit_reservations.agent_periods (org_id, agent_id, month, created_at) select org_id, agent_id, '2026-09', now() from limit_reservations.reservations where request_id = $1",
          [allowed],
        );
        return owner.query("update limit_reservations.reservations set month = '2026-09' where request_id = $1", [
          allowed,
        ]);
      },
      'allowed',
    ],
    [
      'a reservation moved back out of the split window',
      (owner, { waiting }) =>
        owner.query(
          "update limit_reservations.reservations set reserved_at = reserved_at - interval '30 days' where request_id = $1",
          [waiting],
        ),
      'waiting',
    ],
    [
      'a claim released',
      (owner, { allowed }) =>
        owner.query('update spend_requests.order_claims set released_at = now() where request_id = $1', [allowed]),
      'allowed',
    ],
  ];

  it.each(tampered)('raises the alarm and the hold for %s past the app (SEC-DB-09)', async (_, change, whose) => {
    const { w, acting } = await ready();
    const held = await requests(acting, w);
    await pastTheApp(w, (owner) => change(owner, held));

    await job(w).run();

    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'holding', subjectType: 'spend_request', objectId: held[whose] }),
    ]);
    expect(lines('holdings_check.passed')).toEqual([expect.objectContaining({ requests: 3, mismatched: 1 })]);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('passes an organisation with no requests yet', async () => {
    const { w } = await ready();

    await job(w).run();

    expect(lines('holdings_check.passed')).toEqual([expect.objectContaining({ requests: 0, mismatched: 0 })]);
    expect(await holdOf(w)).toMatchObject({ outcome: 'clear' });
  });

  it('passes over a request tampered with, its read raising the alarm and the hold, and checks the rest', async () => {
    const { w, acting } = await ready();
    const { allowed } = await requests(acting, w);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(allowed);
    } finally {
      await owner.end();
    }

    await job(w).run();

    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'unsigned', objectId: allowed }),
    ]);
    expect(lines('holdings_check.passed')).toEqual([
      expect.objectContaining({ requests: 2, mismatched: 0, tampered: 1 }),
    ]);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('finds a request deleted with its claim, as the log still holds it, so its order can’t be paid twice unseen', async () => {
    const { w, acting } = await ready();
    const { allowed } = await requests(acting, w);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.query('delete from spend_requests.order_claims where request_id = $1', [allowed]);
      await owner.deleteRow(allowed);
    } finally {
      await owner.end();
    }

    await job(w).run();

    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'deleted', objectId: allowed }),
    ]);
    expect(lines('holdings_check.passed')).toEqual([
      expect.objectContaining({ requests: 2, mismatched: 0, tampered: 1 }),
    ]);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('logs a page that fails and an organisation list that can’t be read, and goes on; stops when told to', async () => {
    const { w } = await ready();

    // A page of none is refused before any SQL runs.
    await job(w, 0).run();
    expect(lines('holdings_check.failed')).toHaveLength(1);

    const unlisted = createHoldingsCheck({
      list: () => Promise.reject(new Error('the directory is down')),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });
    await unlisted.run();
    expect(lines('holdings_check.run_failed')).toHaveLength(1);

    await job(w).run(AbortSignal.abort());
    expect(lines('holdings_check.passed')).toEqual([]);
  });
});
