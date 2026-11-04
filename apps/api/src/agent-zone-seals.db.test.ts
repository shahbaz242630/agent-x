// PL-40 (0054): the agent's month time zone as a signed record, on the real
// migrated schema as the app role (ADR-012 §2; FX-TAMPER). The agent's first
// decision keeps and seals it; a zone changed past the app (by the table's
// owner, its guard off) refuses every decision, simulation and draft that
// reads it, raises the integrity alarm and holds the organisation, and the
// holdings check finds it too, as it finds a month sealed that isn't its
// instant's month in the agent's zone. A zone with no signed event (as one
// kept before 0054 was: here, one whose events the owner deleted and whose
// pointer it cleared) is a tamper sign: the job that sealed those once is
// retired (4D2e D11), every environment's having been sealed by it.
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import {
  AGENT_ZONES,
  keptZoneOf,
  keptZonesOf,
  type LimitReservationsTables,
} from '@agentx/core/modules/limit-reservations';
import { createOutbox } from '@agentx/core/modules/notifications';
import { SPEND_REQUESTS, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import type { PaymentsTables } from '@agentx/core/modules/transactions';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createHoldingsCheck } from './holdings-check.ts';
import { createMandateRegistry, DRAFT_OPERATION, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';
import { createPolicySimulations, type PolicySimulations } from './policy-simulations.ts';
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

const ids = new SequentialIds(0x0540_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-000000000054';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let simulations: PolicySimulations;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'agent-zones' });
const { world, quiet, agentKey, keyed, termsOf, eventsAbout } = shared;

/** A world whose agent has a key and a mandate in force (Asia/Dubai), both suppliers verified. */
async function ready() {
  const w = await world();
  for (const id of w.suppliers) await shared.verified(w, id);
  const mandateId = await shared.inForce(registry, w, { approvalThreshold: AED(1_500_000n) });
  return { w, mandateId, acting: await agentKey(w) };
}

let keysUsed = 0;
const asking = (w: World, overrides: Partial<SpendAskedByAgent> = {}): SpendAskedByAgent => ({
  amount: AED(100_000n),
  supplierId: w.suppliers[0] ?? '',
  fundingSourceId: w.source,
  orderReference: `INV-${String(keysUsed)}`,
  purpose: 'Printer paper',
  ...overrides,
});
const ask = (acting: AgentActing, asked: SpendAskedByAgent) => {
  keysUsed += 1;
  return decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `zone-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor), n: keysUsed }),
    },
    asked,
    CORRELATION,
  );
};
const decided = async (acting: AgentActing, w: World) => {
  const answer = await ask(acting, asking(w));
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

const zoneOf = (w: World) =>
  withSignedStates(app, w.org, quiet(), (tx, states) => keptZoneOf(tx, states, { orgId: w.org, agentId: w.agent }));
const holdOf = (w: World) => withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The agent's zone moved to another, or (`unsealed`) its pointer cleared too, by its owner with `made_once` off. */
const MOVE_ZONE = 'update limit_reservations.agent_zones set time_zone = $2 where agent_id = $1';
const UNSEAL_ZONE =
  'update limit_reservations.agent_zones set state_event_id = null, time_zone = $2 where agent_id = $1';

/** The agent's zone row changed past the app: what an attacker with owner-level access could do. */
async function zoneChanged(w: World, change: 'moved' | 'unsealed', zone = 'Pacific/Kiritimati') {
  const owner = await tamperAsOwner(database, AGENT_ZONES, w.org);
  try {
    await owner.query('begin');
    await owner.query('alter table limit_reservations.agent_zones disable trigger made_once');
    if (change === 'moved') await owner.query(MOVE_ZONE, [w.agent, zone]);
    else await owner.query(UNSEAL_ZONE, [w.agent, zone]);
    await owner.query('alter table limit_reservations.agent_zones enable trigger made_once');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

/** The zone as one kept before 0054 is: no signed event about it and no pointer, its zone `zone`. */
async function keptBefore0054(w: World, zone = 'Asia/Dubai') {
  const owner = await tamperAsOwner(database, AGENT_ZONES, w.org);
  try {
    await owner.deleteEvents(w.agent);
  } finally {
    await owner.end();
  }
  await zoneChanged(w, 'unsealed', zone);
}

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
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  simulations = createPolicySimulations({ database: app, keys, ids, clock, logger });
});

describe("the agent's month zone, a signed record (PL-40)", () => {
  it("is kept and sealed by the agent's first decision, and read through its seal from then on", async () => {
    const { w, acting } = await ready();
    expect(await zoneOf(w)).toEqual({ outcome: 'none' });

    await decided(acting, w);
    await decided(acting, w);

    expect(await zoneOf(w)).toEqual({ outcome: 'kept', zone: 'Asia/Dubai' });
    // Many at once, as the holdings check reads them: none asked, none read.
    const many = (agents: string[]) =>
      withSignedStates(app, w.org, quiet(), (tx, states) => keptZonesOf(tx, states, w.org, agents));
    expect(await many([w.agent])).toEqual(new Map([[w.agent, { outcome: 'kept', zone: 'Asia/Dubai' }]]));
    expect(await many([])).toEqual(new Map());
    expect(await eventsAbout(w.org, w.agent, AGENT_ZONES.subject)).toEqual([
      expect.objectContaining({
        action: 'agent_zone.kept',
        actorType: 'agent',
        details: expect.objectContaining({ agentId: w.agent }) as unknown,
      }),
    ]);
  });

  it('refuses every decision, simulation and draft on a zone changed past the app, alarmed and the organisation held', async () => {
    const { w, mandateId, acting } = await ready();
    await decided(acting, w);
    await zoneChanged(w, 'moved');

    expect(await ask(acting, asking(w))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await simulations.simulate(w.org, mandateId, asking(w), {}, CORRELATION)).toEqual(
      refused(503, 'INTEGRITY_FAILED'),
    );
    const draft = {
      agentId: w.agent,
      timeZone: 'Asia/Dubai',
      splitWindowHours: 24,
      terms: termsOf(w),
      overLimit: 'refuse' as const,
    };
    expect(await registry.draft(w.admin, keyed(w.admin, DRAFT_OPERATION), draft, CORRELATION)).toEqual(
      refused(503, 'INTEGRITY_FAILED'),
    );
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ subjectType: AGENT_ZONES.subject }),
    );
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it('is checked by the holdings check: a zone changed past the app is a mismatch of every request it holds for', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    await decided(acting, w);
    await zoneChanged(w, 'moved');

    await createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run();

    expect(lines('holdings_check.passed')).toEqual([expect.objectContaining({ requests: 2, mismatched: 2 })]);
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });

  it("finds a decision whose sealed month isn't its instant's month in the agent's zone, all else matching", async () => {
    const { w, acting } = await ready();
    const request = await decided(acting, w);
    // 21:30 UTC on 31 October is already 1 November in Dubai: sealed, and held, as October.
    const at = '2026-10-31T21:30:00.000Z';
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.query('begin');
      await owner.query('alter table limit_reservations.reservations disable trigger user');
      await owner.query('update limit_reservations.reservations set reserved_at = $2 where request_id = $1', [
        request.id,
        at,
      ]);
      await owner.query('alter table limit_reservations.reservations enable trigger user');
      await owner.query('commit');
    } finally {
      await owner.end();
    }
    // Its decision's details as sealed (the payee seal among them), signing no state: only the instant moves.
    const {
      stateFingerprint: _f,
      stateKeyVersion: _k,
      correlationId: _c,
      ...sealedDetails
    } = (await eventsAbout(w.org, request.id, SPEND_REQUESTS.subject)).find(
      ({ action }) => action === 'spend_request.decided',
    )?.details ?? {};
    await withTenant(app, w.org, (tx) =>
      createAuditTrail({ keys, ids }).record(tx, w.org, {
        actor: { type: 'agent', id: w.agent },
        action: 'spend_request.decided',
        subject: { type: SPEND_REQUESTS.subject, id: request.id, version: 1 },
        details: { ...sealedDetails, heldMonth: '2026-10', heldAt: at },
      }),
    );

    await createHoldingsCheck({
      list: () => Promise.resolve([w.org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run();

    expect(lines('holdings_check.passed')).toEqual([expect.objectContaining({ requests: 1, mismatched: 1 })]);
  });
});

describe('a zone with no signed event, as one kept before 0054 was (4D2e D11: no job seals one now)', () => {
  it('refuses every decision on it, alarmed and the organisation held: fails closed, never read as kept', async () => {
    const { w, acting } = await ready();
    await decided(acting, w);
    await keptBefore0054(w);

    expect(await zoneOf(w)).toMatchObject({ outcome: 'tampered' });
    expect(await ask(acting, asking(w))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(lines('audit.integrity_failed')).toContainEqual(
      expect.objectContaining({ subjectType: AGENT_ZONES.subject }),
    );
    expect(await holdOf(w)).toMatchObject({ outcome: 'held' });
  });
});
