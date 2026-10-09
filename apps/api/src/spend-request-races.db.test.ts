// Phase 2 D6: spend decisions under real concurrency, on the real migrated
// schema as the app role (ADR-006 §6; SEC-AV-04, SEC-LIM-01, SEC-LIM-04,
// SEC-DP-10). Unlike D4's forced tests, nothing here is lined up: each test
// lets requests and a competing change start together at a barrier, and
// checks what came out against the order the audit chain committed them in
// (each transaction takes the chain's head last, so its events' order is the
// commit order):
// - the deadlock suite: an agent suspended, its mandate superseded, both at
//   once, its mandate revoked, its supplier suspended, its key revoked, each
//   racing the agent's requests. No deadlock (A2's retry never logged), and
//   the right winner: a request committed before the change was decided
//   without it, one after it with it;
// - the model: random batches of requests by two agents to two suppliers,
//   some naming the same order, all at once (fast-check). Whatever order they
//   commit in, no agent's month passes its cap, no order is held twice, and
//   no supplier's orders allowed without approval pass the approval
//   threshold together (the split check).
import { AGENT_KEYS, AGENTS } from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import type { SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { supplierOf, suspendSupplier } from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, TRANSACTION_RETRIED, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  race,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import fc from 'fast-check';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry, type MandateRegistry, REDRAFT_OPERATION } from './mandate-registry.ts';
import { AED, keys, mandateWorld, type MandateWorldTables, OPERATOR, type World } from './mandate-world.helper.test.ts';
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

const ids = new SequentialIds(0xd6a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000d6';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'spend-request-races' });
const { world, quiet, keyed, agentKey } = shared;

/** Approval above AED 15,000 and the default cap (AED 20,000 a month), so splits and the month both bind. */
const TERMS = { approvalThreshold: AED(1_500_000n) };

/** A world whose agent has a key and a mandate in force on TERMS, both suppliers verified. */
async function ready() {
  const w = await world();
  for (const id of w.suppliers) await shared.verified(w, id);
  const mandateId = await shared.inForce(registry, w, TERMS);
  return { w, mandateId, acting: await agentKey(w) };
}

/** AED 1,000 to the first supplier, order `INV-<n>`, unless changed. */
const asking = (w: World, n: number, overrides: Partial<SpendAskedByAgent> = {}): SpendAskedByAgent => ({
  amount: AED(100_000n),
  supplierId: w.suppliers[0] ?? '',
  fundingSourceId: w.source,
  orderReference: `INV-${String(n)}`,
  purpose: 'Printer paper',
  ...overrides,
});

let keysUsed = 0;
const ask = (acting: AgentActing, asked: SpendAskedByAgent) => {
  keysUsed += 1;
  return decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: `race-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor) }),
    },
    asked,
    CORRELATION,
  );
};

/**
 * The requests around `change`: the first two answered before it starts, the
 * last started once it is done, and those between started with it at one
 * barrier, racing it for real. So each test sees both sides of the change
 * (started all together, the change's short transaction has always won
 * outright). The requests' answers, in order (a rejection fails
 * the test: every request is answered, never thrown).
 */
async function racing(requests: (() => Promise<SpendRequestDecided>)[], change: () => Promise<unknown>) {
  const before = await Promise.all(requests.slice(0, 2).map((request) => request()));
  const between = [...requests.slice(2, -1), change];
  const outcomes = await race(between.length, async (n, sync) => {
    await sync();
    return between[n]?.();
  });
  expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toEqual([]);
  const raced = outcomes.slice(0, -1).map((outcome) => {
    if (outcome.status !== 'fulfilled') throw new Error('a request failed');
    return outcome.value as SpendRequestDecided;
  });
  const after = await Promise.all(requests.slice(-1).map((request) => request()));
  return [...before, ...raced, ...after];
}

const decidedOf = (answer: SpendRequestDecided) => {
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

/** Each audit event's place in the organisation's chain (its commit order), by action and subject. */
const chainOf = async (org: string) => {
  const events = await withTenant(app, org, (tx) =>
    tx.selectFrom('audit.events').select(['seq', 'action', 'subject_id']).orderBy('seq').execute(),
  );
  return (action: string, subject: string): bigint => {
    const found = events.filter((e) => e.action === action && e.subject_id === subject).at(-1);
    if (found === undefined) throw new Error(`no ${action} event for ${subject}`);
    return found.seq;
  };
};

/** The decided requests, each with when it committed: the answers that were `decided`. */
async function committed(org: string, answers: readonly SpendRequestDecided[]) {
  const at = await chainOf(org);
  return answers.flatMap((answer) =>
    answer.outcome === 'decided'
      ? [{ request: answer.request, seq: at('spend_request.decided', answer.request.id) }]
      : [],
  );
}

/** A deadlock or serialisation failure retried anywhere (A2 logs each): none, ever (SEC-AV-04). */
const retries = () => capture.lines().filter((line) => line.event === TRANSACTION_RETRIED);

/** Six of the agent's requests, each its own order, within every limit together: two before, three racing, one after. */
const six = (w: World, acting: AgentActing) => [1, 2, 3, 4, 5, 6].map((n) => () => ask(acting, asking(w, n)));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 10 }, testLogger());
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

describe('the deadlock suite (SEC-AV-04): each change racing the agent’s requests', () => {
  it('an agent suspended: no deadlock; a request after it denied AGENT_SUSPENDED, one before allowed', async () => {
    const { w, acting } = await ready();

    const answers = await racing(six(w, acting), () =>
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
          actor: OPERATOR,
          action: 'agent.suspended',
          details: {},
        }),
      ),
    );

    const suspended = (await chainOf(w.org))('agent.suspended', w.agent);
    const decided = await committed(w.org, answers);
    expect(decided).toHaveLength(6);
    for (const { request, seq } of decided) {
      expect(request.decision).toBe(seq < suspended ? 'ALLOW' : 'DENY');
      if (seq > suspended) expect(request.reasons).toEqual(['AGENT_SUSPENDED']);
    }
    expect(retries()).toEqual([]);
  });

  it('a mandate superseded: no deadlock; each request decided under the version in force when it committed', async () => {
    const { w, mandateId: id, acting } = await ready();
    const versionOf = async (requestId: string) =>
      (
        await withTenant(app, w.org, (tx) =>
          tx
            .selectFrom('spend_requests.requests')
            .select('mandate_version_id')
            .where('id', '=', requestId)
            .executeTakeFirstOrThrow(),
        )
      ).mandate_version_id;
    const before = await versionOf(decidedOf(await ask(acting, asking(w, 0))).id);
    const redrafted = await registry.redraft(
      w.admin,
      keyed(w.admin, REDRAFT_OPERATION),
      id,
      shared.termsOf(w, { ...TERMS, purpose: 'Office supplies, renewed' }),
      CORRELATION,
    );
    expect(redrafted.outcome).toBe('drafted');

    const answers = await racing(six(w, acting), () => shared.acceptedPastTheUseCase(w, id));

    const accepted = (await chainOf(w.org))('mandate.accepted', id);
    const decided = await committed(w.org, answers);
    expect(decided.map(({ request }) => request.decision)).toEqual(Array(6).fill('ALLOW'));
    for (const { request, seq } of decided) {
      const version = await versionOf(request.id);
      if (seq < accepted) expect(version).toBe(before);
      else expect(version).not.toBe(before);
    }
    expect(retries()).toEqual([]);
  });

  it('an agent suspended while its mandate is superseded, with its requests: no deadlock', async () => {
    const { w, mandateId, acting } = await ready();
    await registry.redraft(
      w.admin,
      keyed(w.admin, REDRAFT_OPERATION),
      mandateId,
      shared.termsOf(w, { ...TERMS, purpose: 'Office supplies, renewed' }),
      CORRELATION,
    );
    const suspend = () =>
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
          actor: OPERATOR,
          action: 'agent.suspended',
          details: {},
        }),
      );

    // The suspension and the supersede race each other and the requests between.
    const answers = await racing(six(w, acting), () =>
      Promise.all([suspend(), shared.acceptedPastTheUseCase(w, mandateId)]),
    );

    const suspended = (await chainOf(w.org))('agent.suspended', w.agent);
    const decided = await committed(w.org, answers);
    expect(decided).toHaveLength(6);
    for (const { request, seq } of decided) {
      expect(request.decision).toBe(seq < suspended ? 'ALLOW' : 'DENY');
    }
    expect(retries()).toEqual([]);
  });

  it('a mandate revoked: no deadlock; a request after it denied MANDATE_NOT_IN_FORCE', async () => {
    const { w, mandateId, acting } = await ready();

    const answers = await racing(six(w, acting), () => shared.movedPastTheUseCase(w, mandateId, 'revoke'));

    const revoked = (await chainOf(w.org))('mandate.revoke', mandateId);
    const decided = await committed(w.org, answers);
    expect(decided).toHaveLength(6);
    for (const { request, seq } of decided) {
      expect(request.decision).toBe(seq < revoked ? 'ALLOW' : 'DENY');
      if (seq > revoked) expect(request.reasons).toContain('MANDATE_NOT_IN_FORCE');
    }
    expect(retries()).toEqual([]);
  });

  it('its supplier suspended: no deadlock; a request after it denied SUPPLIER_NOT_VERIFIED', async () => {
    const { w, acting } = await ready();
    const supplier = w.suppliers[0] ?? '';

    const answers = await racing(six(w, acting), () =>
      withSignedStates(app, w.org, quiet(), async (tx, states) => {
        const key = { orgId: w.org, id: supplier };
        const found = await supplierOf(tx, states, key, 'change');
        if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
        await suspendSupplier(tx, states, key, found, { actor: OPERATOR });
      }),
    );

    const suspended = (await chainOf(w.org))('supplier.suspend', supplier);
    const decided = await committed(w.org, answers);
    expect(decided).toHaveLength(6);
    for (const { request, seq } of decided) {
      expect(request.decision).toBe(seq < suspended ? 'ALLOW' : 'DENY');
      if (seq > suspended) expect(request.reasons).toEqual(['SUPPLIER_NOT_VERIFIED']);
    }
    expect(retries()).toEqual([]);
  });

  it('its key revoked: no deadlock; each request decided committed before it, the rest refused', async () => {
    const { w, acting } = await ready();

    const answers = await racing(six(w, acting), () =>
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'revoke', {
          actor: OPERATOR,
          action: 'agent_key.revoked',
          details: {},
        }),
      ),
    );

    const revoked = (await chainOf(w.org))('agent_key.revoked', acting.keyId);
    const decided = await committed(w.org, answers);
    for (const { seq } of decided) expect(seq < revoked).toBe(true);
    expect(answers.slice(0, 2).map((answer) => answer.outcome)).toEqual(['decided', 'decided']);
    expect(answers.filter((answer) => answer.outcome !== 'decided')).toEqual(
      Array(6 - decided.length).fill({ outcome: 'refused', status: 401, code: 'UNAUTHENTICATED' }),
    );
    expect(retries()).toEqual([]);
  });
});

/** One request in a random batch: whose, to which supplier, how much, and which of four orders. */
const REQUEST = fc.record({
  agent: fc.integer({ min: 0, max: 1 }),
  supplier: fc.integer({ min: 0, max: 1 }),
  // AED 1,000 to 12,000, in AED 500 steps.
  amount: fc.integer({ min: 2, max: 24 }).map((halves) => BigInt(halves) * 50_000n),
  order: fc.integer({ min: 1, max: 4 }),
});

describe('the model: random batches all at once (SEC-LIM-01, SEC-LIM-04, SEC-DP-10)', () => {
  it('never passes a month’s cap, holds an order twice, or allows a split past the threshold', async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(REQUEST, { minLength: 4, maxLength: 8 }), async (batch) => {
        // A log of this run's own, so a retry in one run never fails another.
        capture = new LogCapture();
        decisions = createSpendRequestDecisions({ database: app, keys, ids, clock, logger: testLogger(capture) });
        const { w, acting } = await ready();
        const agents = [acting, await shared.secondAgent(registry, w, TERMS)];

        // Every request started at once, each on its own connection.
        const answers = await Promise.all(
          batch.map((r) =>
            ask(
              agents[r.agent] ?? acting,
              asking(w, r.order, { amount: AED(r.amount), supplierId: w.suppliers[r.supplier] ?? '' }),
            ),
          ),
        );

        const decided = answers.map(decidedOf);
        const holding = decided.filter(
          (request) => request.decision === 'ALLOW' || request.decision === 'REQUIRE_APPROVAL',
        );
        const sum = (requests: typeof decided) => requests.reduce((total, request) => total + request.amount.minor, 0n);

        // The default cap, AED 20,000 a month, per agent (decision 5).
        for (const agent of agents) {
          expect(sum(holding.filter((request) => request.agentId === agent.agentId))).toBeLessThanOrEqual(2_000_000n);
        }
        // One holding request an order (supplier and reference).
        const orders = holding.map((request) => `${request.supplierId} ${request.orderReference}`);
        expect(new Set(orders).size).toBe(orders.length);
        // Allowed without approval, a supplier's orders together stay within the threshold (the split check).
        for (const supplier of w.suppliers) {
          const allowed = decided.filter((request) => request.decision === 'ALLOW' && request.supplierId === supplier);
          expect(sum(allowed)).toBeLessThanOrEqual(1_500_000n);
        }
        // What the tables hold matches: one reservation and one open claim a holding request, nothing else.
        const held = await withTenant(app, w.org, async (tx) => ({
          reservations: await tx.selectFrom('limit_reservations.reservations').select('request_id').execute(),
          claims: await tx
            .selectFrom('spend_requests.order_claims')
            .select('request_id')
            .where('released_at', 'is', null)
            .execute(),
        }));
        const holdingIds = holding.map((request) => request.id).sort();
        expect(held.reservations.map((row) => row.request_id).sort()).toEqual(holdingIds);
        expect(held.claims.map((row) => row.request_id).sort()).toEqual(holdingIds);
        expect(retries()).toEqual([]);
      }),
      // Shrinking replays whole worlds, and a race may not replay at all: the failing batch is printed as it was.
      { numRuns: 8, endOnFailure: true },
    );
  }, 120_000);
});
