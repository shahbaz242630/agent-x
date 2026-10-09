// Phase 2 D4: deciding a spend request and reserving its capacity, composed in
// the API, on the real migrated schema as the app role: ALLOW approved and
// REQUIRE_APPROVAL waiting, each holding its reservation in the agent's month
// and its order claim; REQUIRE_NEW_MANDATE and DENY recorded DENIED, holding
// nothing; no mandate, an unverified or unknown supplier, a source not the
// organisation's, a suspended mandate, each a recorded denial; the same order
// asked again however written (SEC-DP-10); the agent's month across its
// mandates (decision 4) and both policies weighed (decision 5); two decisions
// on one agent's month, and one waiting on a revocation, forced through the
// lock order (SEC-LIM-01), as are the duplicate check on one supplier, a key's
// revocation and a freeze; only the agent's own month counted (another month,
// a released reservation and another agent's never); a retry answered as it
// was; what is refused with nothing made (a currency not taken, a revoked or
// expired key or another agent's, a frozen organisation, a tampered
// mandate); the agent's route over HTTP with its real key check (D4r); the
// simulator (C4): the same decision as a request, the month's total, proposed
// rules, and nothing written anywhere (SEC-AG-09); and no request ever left
// VALIDATING.
import { addAgent, AGENT_KEYS, AGENTS, createAgentKeyCheck } from '@agentx/core/modules/agents';
import { type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { MANDATES, type PolicyRules, setPolicy } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { releaseClaim, SPEND_REQUESTS, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { SUPPLIERS, supplierOf, verifySupplier } from '@agentx/core/modules/suppliers';
import { DAY_MS, HOUR_MS, money } from '@agentx/core/shared-kernel';
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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { createPolicySimulations, type PolicySimulations, type WhatIf } from './policy-simulations.ts';
import { closeServers, routeServer } from './route-server.helper.test.ts';
import {
  AED,
  keys,
  mandateWorld,
  type MandateWorldTables,
  OPERATOR,
  refused,
  type World,
} from './mandate-world.helper.test.ts';
import {
  type AgentActing,
  createSpendRequestDecisions,
  DECIDE_OPERATION,
  type SpendAskedByAgent,
  type SpendRequestDecided,
  type SpendRequestDecisions,
  type SpendWeighed,
} from './spend-request-decisions.ts';

type Tables = MandateWorldTables & SpendRequestsTables & LimitReservationsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0xd4a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000d4';

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let simulations: PolicySimulations;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'spend-request-decisions' });
const { world, quiet, movedPastTheUseCase, agentKey, eventsAbout } = shared;

/** The supplier verified by the world's admin, as E3 does. */
const verified = (w: World, id: string) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId: w.org, id }, 'change');
    if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
    await verifySupplier(tx, states, { orgId: w.org, id }, found, {
      verifiedBy: w.admin.membershipId,
      actor: OPERATOR,
    });
  });

/**
 * A world whose agent has a key and a mandate in force (unless `mandate` is
 * false), both suppliers verified: the mandate's terms the world's own
 * (AED 50,000 an order, 100,000 a month, approval above 25,000) changed by
 * `terms`, so the default cap (AED 20,000 a month) binds first.
 */
async function ready({
  terms = {},
  mandate = true,
}: { terms?: Parameters<typeof shared.termsOf>[1]; mandate?: boolean } = {}) {
  const w = await world();
  for (const supplier of w.suppliers) await verified(w, supplier);
  const mandateId = mandate ? await shared.inForce(registry, w, terms) : null;
  return { w, mandateId, acting: await agentKey(w) };
}

/** Within every limit unless changed: AED 10,000 to the first supplier, from the source. */
const asking = (w: World, overrides: Partial<SpendAskedByAgent> = {}): SpendAskedByAgent => ({
  amount: AED(1_000_000n),
  supplierId: w.suppliers[0] ?? '',
  fundingSourceId: w.source,
  orderReference: 'INV-1001',
  purpose: 'Printer paper',
  ...overrides,
});

let keysUsed = 0;
/** The agent's request, by its idempotency key: a fresh one unless named. */
const ask = (acting: AgentActing, asked: SpendAskedByAgent, key?: string) => {
  keysUsed += 1;
  return decisions.decideAndReserve(
    acting,
    {
      orgId: acting.orgId,
      client: { kind: 'agent', id: acting.agentId },
      operation: DECIDE_OPERATION,
      key: key ?? `decide-${String(keysUsed)}`,
      payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor) }),
    },
    asked,
    CORRELATION,
  );
};

const decidedOf = (answer: SpendRequestDecided) => {
  if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
  return answer.request;
};

/** What the request holds, as its tables do: its row, its reservation and its claim, each or undefined. */
const heldBy = (org: string, requestId: string) =>
  withTenant(app, org, async (tx) => ({
    row: await tx.selectFrom('spend_requests.requests').selectAll().where('id', '=', requestId).executeTakeFirst(),
    reservation: await tx
      .selectFrom('limit_reservations.reservations')
      .selectAll()
      .where('request_id', '=', requestId)
      .executeTakeFirst(),
    claim: await tx
      .selectFrom('spend_requests.order_claims')
      .selectAll()
      .where('request_id', '=', requestId)
      .executeTakeFirst(),
  }));

/** How many requests the organisation has, and how many agent months: none after a refusal. */
const made = (org: string) =>
  withTenant(app, org, async (tx) => ({
    requests: (await tx.selectFrom('spend_requests.requests').select('id').execute()).length,
    months: (await tx.selectFrom('limit_reservations.agent_periods').select('month').execute()).length,
  }));

/** The policy's rules set past the use case (C3b's setPolicy): only a monthly cap of `minor` fils. */
const capped = (w: World, scope: 'organization' | 'mandate', mandateId: string | null, minor: bigint) => {
  const rules: PolicyRules = {
    currency: 'AED',
    perOrderCap: null,
    monthlyCap: AED(minor),
    approvalThreshold: null,
    supplierIds: null,
  };
  return withSignedStates(app, w.org, quiet(), (tx, states) =>
    setPolicy(tx, states, {
      orgId: w.org,
      existing: null,
      scope,
      mandateId,
      versionId: ids.next(),
      rules,
      madeBy: w.admin.membershipId,
      madeAt: clock.now(),
      actor: OPERATOR,
      details: {},
    }),
  );
};

/** A second agent of the world's organisation with a mandate in force on `terms` and a key: acting as it. */
async function secondAgent(w: World, terms: Parameters<typeof shared.termsOf>[1] = {}) {
  const other = ids.next();
  await withSignedStates(app, w.org, quiet(), (tx, states) =>
    addAgent(tx, states, {
      orgId: w.org,
      id: other,
      name: 'Second purchasing agent',
      owner: w.admin.membershipId,
      scopes: ['requests:write'],
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  const theirs = { ...w, agent: other };
  await shared.inForce(registry, theirs, terms);
  return agentKey(theirs);
}

/**
 * The requests `asked` sends, made while `holding`'s transaction holds its
 * locks open (it calls its `wait` once they are taken), each queued behind it
 * before it is let go: their answers.
 */
async function whileHeld(
  holding: (wait: () => Promise<void>) => Promise<unknown>,
  asked: () => Promise<SpendRequestDecided>[],
): Promise<SpendRequestDecided[]> {
  const { promise: held, resolve: holds } = Promise.withResolvers<undefined>();
  const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
  const holder = holding(async () => {
    holds(undefined);
    await gate;
  });
  await held;
  const asking = asked().map((answer, n) => within(20_000, answer, `request ${String(n)}`));
  await waitUntilQueued(database.as('admin'), asking.length);
  open(undefined);
  await holder;
  return Promise.all(asking);
}

/** A status move of the organisation, its agent or a key, in its own transaction, which `wait`s once it is made. */
const movedIn = (
  w: World,
  wait: () => Promise<void>,
  move: (tx: DatabaseTransaction<Tables>, states: SignedStates) => Promise<unknown>,
) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    await move(tx, states);
    await wait();
  });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterEach(closeServers);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-08T08:00:00Z'));
  const logger = testLogger(new LogCapture());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({ database: app, keys, ids, clock, logger });
  simulations = createPolicySimulations({ database: app, keys, ids, clock, logger });
});

describe('deciding a spend request and reserving it (D4)', () => {
  it('allows one within every limit: APPROVED, its capacity held in the agent’s month and its order claimed', async () => {
    const { w, mandateId, acting } = await ready();

    const request = decidedOf(await ask(acting, asking(w)));

    expect(request).toMatchObject({
      agentId: w.agent,
      mandateId,
      supplierId: w.suppliers[0],
      amount: AED(1_000_000n),
      orderReference: 'INV-1001',
      decision: 'ALLOW',
      reasons: [],
      status: 'APPROVED',
    });
    const { row, reservation, claim } = await heldBy(w.org, request.id);
    expect(row).toMatchObject({
      agent_key_id: acting.keyId,
      mandate_version_id: expect.any(String) as unknown,
      supplier_version_id: expect.any(String) as unknown,
      organization_policy_version_id: null,
      mandate_policy_version_id: null,
      input_hash: expect.stringMatching(/^[0-9a-f]{64}$/) as unknown,
      input_hash_key_version: 1,
      reason_codes: null,
      created_at: clock.now(),
    });
    expect(reservation).toMatchObject({
      agent_id: w.agent,
      mandate_id: mandateId,
      month: '2026-10',
      supplier_id: w.suppliers[0],
      amount_minor: 1_000_000n,
      currency: 'AED',
      state: 'HELD',
      reserved_at: clock.now(),
      settled_at: null,
    });
    expect(claim).toMatchObject({ supplier_id: w.suppliers[0], order_reference: 'inv-1001', released_at: null });
    // Signed twice: received VALIDATING, then moved by its decision.
    expect(await eventsAbout(w.org, request.id, 'spend_request')).toEqual([
      expect.objectContaining({ action: 'spend_request.received', actorType: 'agent' }),
      expect.objectContaining({ action: 'spend_request.decided', actorType: 'agent' }),
    ]);
    // The agent's months are named in its first mandate's zone, kept for good.
    expect(
      await withTenant(app, w.org, (tx) =>
        tx.selectFrom('limit_reservations.agent_zones').select('time_zone').execute(),
      ),
    ).toEqual([{ time_zone: 'Asia/Dubai' }]);
  });

  it('sends one over the approval threshold for approval, its capacity held while it waits', async () => {
    const { w, acting } = await ready({ terms: { approvalThreshold: AED(500_000n) } });

    const request = decidedOf(await ask(acting, asking(w)));

    expect(request).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['APPROVAL_THRESHOLD'],
      status: 'APPROVAL_REQUIRED',
    });
    const { reservation, claim } = await heldBy(w.org, request.id);
    expect(reservation).toMatchObject({ state: 'HELD', amount_minor: 1_000_000n });
    expect(claim).toMatchObject({ released_at: null });
  });

  it('denies one over the mandate’s own limit as REQUIRE_NEW_MANDATE, holding nothing (SEC-LIM-06)', async () => {
    const { w, acting } = await ready({ terms: { perOrderLimit: AED(100_000n), approvalThreshold: AED(50_000n) } });

    const request = decidedOf(await ask(acting, asking(w, { amount: AED(150_000n) })));

    expect(request).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'],
      status: 'DENIED',
    });
    const { row, reservation, claim } = await heldBy(w.org, request.id);
    expect(row).toMatchObject({ reason_codes: 'MANDATE_ORDER_LIMIT APPROVAL_THRESHOLD' });
    expect(reservation).toBeUndefined();
    expect(claim).toBeUndefined();
    // The order wasn't claimed, so it may be asked for again once the limit allows it.
    expect(decidedOf(await ask(acting, asking(w, { amount: AED(50_000n) }))).decision).toBe('ALLOW');
  });

  it('records a request with no mandate, DENIED, locking no month', async () => {
    const { w, acting } = await ready({ mandate: false });
    await shared.drafted(registry, w);

    const request = decidedOf(await ask(acting, asking(w)));

    expect(request).toMatchObject({ mandateId: null, decision: 'DENY', reasons: ['MANDATE_NOT_IN_FORCE'] });
    expect((await heldBy(w.org, request.id)).row).toMatchObject({ mandate_version_id: null, status: 'DENIED' });
    expect(await made(w.org)).toEqual({ requests: 1, months: 0 });
  });

  it('denies what the organisation can’t give, each recorded with its reason', async () => {
    const { w, mandateId, acting } = await ready();
    const unverified = await world();
    const elsewhere = { supplierId: unverified.suppliers[0] ?? '', fundingSourceId: unverified.source };

    const notOurs = decidedOf(await ask(acting, asking(w, elsewhere)));
    expect(notOurs).toMatchObject({
      decision: 'DENY',
      reasons: ['SUPPLIER_NOT_VERIFIED', 'SOURCE_NOT_USABLE', 'SUPPLIER_NOT_ALLOWED', 'SOURCE_NOT_MANDATED'],
      status: 'DENIED',
    });
    expect((await heldBy(w.org, notOurs.id)).row).toMatchObject({ supplier_version_id: null });

    await movedPastTheUseCase(w, mandateId ?? '', 'suspend');
    expect(decidedOf(await ask(acting, asking(w, { orderReference: 'INV-2' })))).toMatchObject({
      mandateId,
      decision: 'DENY',
      reasons: ['MANDATE_NOT_IN_FORCE'],
    });
  });

  it('denies an unverified supplier, recording the version weighed', async () => {
    const w = await world();
    await shared.inForce(registry, w);
    const acting = await agentKey(w);

    const request = decidedOf(await ask(acting, asking(w)));

    expect(request).toMatchObject({ decision: 'DENY', reasons: ['SUPPLIER_NOT_VERIFIED'] });
    expect((await heldBy(w.org, request.id)).row).toMatchObject({ supplier_version_id: expect.any(String) as unknown });
  });

  it('denies the same order asked again however written, and not the same number at another supplier (SEC-DP-10)', async () => {
    const { w, acting } = await ready();
    expect(decidedOf(await ask(acting, asking(w, { amount: AED(10_000n) }))).decision).toBe('ALLOW');

    for (const written of [' inv-1001 ', 'ＩＮＶ-1001', 'Inv-1001']) {
      expect(decidedOf(await ask(acting, asking(w, { amount: AED(10_000n), orderReference: written })))).toMatchObject({
        decision: 'DENY',
        reasons: ['DUPLICATE_ORDER_REFERENCE'],
        status: 'DENIED',
      });
    }
    const another = asking(w, { amount: AED(10_000n), supplierId: w.suppliers[1] ?? '' });
    expect(decidedOf(await ask(acting, another)).decision).toBe('ALLOW');
  });

  it('counts the agent’s month under every mandate: a new mandate never resets it (decision 4)', async () => {
    const { w, mandateId, acting } = await ready();
    expect(decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n) }))).decision).toBe('ALLOW');
    await movedPastTheUseCase(w, mandateId ?? '', 'revoke');
    const next = await shared.inForce(registry, w);

    // To the other supplier, so the split check (D5) adds nothing.
    const other = w.suppliers[1] ?? '';
    const over = decidedOf(
      await ask(acting, asking(w, { amount: AED(1_500_000n), supplierId: other, orderReference: 'INV-2' })),
    );

    // AED 15,000 held under the revoked mandate and 15,000 asked: past the default AED 20,000 cap.
    expect(over).toMatchObject({ mandateId: next, decision: 'DENY', reasons: ['POLICY_MONTHLY_CAP'] });
    // Exactly at the cap passes.
    const rest = asking(w, { amount: AED(500_000n), supplierId: other, orderReference: 'INV-3' });
    expect(decidedOf(await ask(acting, rest)).decision).toBe('ALLOW');
  });

  it('weighs both policies, recording their versions: the mandate’s cap over the organisation’s (decision 5)', async () => {
    const { w, mandateId, acting } = await ready();
    await capped(w, 'organization', null, 1_000_000n);
    const tight = decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n) })));
    expect(tight).toMatchObject({ decision: 'DENY', reasons: ['POLICY_MONTHLY_CAP'] });
    expect((await heldBy(w.org, tight.id)).row).toMatchObject({
      organization_policy_version_id: expect.any(String) as unknown,
      mandate_policy_version_id: null,
    });

    await capped(w, 'mandate', mandateId, 3_000_000n);
    const raised = decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n), orderReference: 'INV-2' })));
    expect(raised.decision).toBe('ALLOW');
    expect((await heldBy(w.org, raised.id)).row).toMatchObject({
      organization_policy_version_id: expect.any(String) as unknown,
      mandate_policy_version_id: expect.any(String) as unknown,
    });
  });

  it('answers a retry with the request it made, deciding nothing again', async () => {
    const { w, acting } = await ready();
    const first = decidedOf(await ask(acting, asking(w), 'the-same-key'));

    expect(decidedOf(await ask(acting, asking(w), 'the-same-key'))).toEqual(first);
    expect(await ask(acting, asking(w, { orderReference: 'INV-2' }), 'the-same-key')).toEqual({
      outcome: 'conflict',
    });
    expect((await made(w.org)).requests).toBe(1);
  });

  it('refuses with nothing made a currency the deployment doesn’t take, a revoked key and a frozen organisation', async () => {
    const { w, acting } = await ready();
    expect(await ask(acting, asking(w, { amount: money(1_000_000n, 'USD') }))).toEqual(
      refused(422, 'CURRENCY_NOT_ALLOWED'),
    );

    const freeze = (event: 'freeze' | 'unfreeze') =>
      withSignedStates(app, w.org, quiet(), (tx, states) =>
        states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, event, {
          actor: OPERATOR,
          action: `organization.${event}`,
          details: {},
        }),
      );
    await freeze('freeze');
    expect(await ask(acting, asking(w), 'while-frozen')).toEqual(refused(409, 'ORG_FROZEN'));
    await freeze('unfreeze');
    // A temporary refusal leaves the key unused (ADR-007 §4).
    expect(decidedOf(await ask(acting, asking(w), 'while-frozen')).decision).toBe('ALLOW');

    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    );
    expect(await ask(acting, asking(w, { orderReference: 'INV-2' }))).toEqual(refused(401, 'UNAUTHENTICATED'));
    expect((await made(w.org)).requests).toBe(1);
  });

  it('counts only the agent’s own month: a new month starts afresh (decision 4)', async () => {
    const { w, acting } = await ready();
    expect(decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n) }))).decision).toBe('ALLOW');
    // 1 November in Dubai: the October reservation no longer counts.
    clock.advanceBy(24 * DAY_MS);

    const next = decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n), orderReference: 'INV-2' })));

    expect(next.decision).toBe('ALLOW');
    expect((await heldBy(w.org, next.id)).reservation).toMatchObject({ month: '2026-11' });
  });

  it('frees a released reservation’s capacity, and never counts another agent’s', async () => {
    const { w, acting } = await ready();
    const first = decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n) })));
    // Ended and given back past the use cases (cancel and expiry come with D7 and D8).
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, SPEND_REQUESTS, { orgId: w.org, id: first.id }, 'deny', {
        actor: OPERATOR,
        action: 'spend_request.denied',
        details: {},
      }),
    );
    await withTenant(app, w.org, async (tx) => {
      await tx
        .updateTable('limit_reservations.reservations')
        .set({ state: 'RELEASED', settled_at: clock.now() })
        .where('request_id', '=', first.id)
        .execute();
      await releaseClaim(tx, { requestId: first.id, releasedAt: clock.now() });
    });
    expect(decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n), orderReference: 'INV-2' }))).decision).toBe(
      'ALLOW',
    );

    const theirKey = await secondAgent(w);
    // AED 15,000 held by the first agent this month; the second's own month is empty. To the other supplier, so
    // the split check (D5) adds nothing.
    const other = asking(w, { amount: AED(1_500_000n), supplierId: w.suppliers[1] ?? '', orderReference: 'INV-3' });
    expect(decidedOf(await ask(theirKey, other)).decision).toBe('ALLOW');
    // A key is its own agent's alone.
    expect(await ask({ ...acting, keyId: theirKey.keyId }, asking(w, { orderReference: 'INV-4' }))).toEqual(
      refused(401, 'UNAUTHENTICATED'),
    );
  });

  it('denies a suspended agent, and refuses its key once expired', async () => {
    const { w, acting } = await ready();
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: {},
      }),
    );
    expect(decidedOf(await ask(acting, asking(w)))).toMatchObject({ decision: 'DENY', reasons: ['AGENT_SUSPENDED'] });

    clock.advanceBy(90 * DAY_MS);
    expect(await ask(acting, asking(w, { orderReference: 'INV-2' }))).toEqual(refused(401, 'UNAUTHENTICATED'));
  });

  it('refuses a mandate tampered with past the app, making nothing (FX-TAMPER)', async () => {
    const { w, mandateId, acting } = await ready();
    const owner = await tamperAsOwner(database, MANDATES, w.org);
    try {
      await owner.withoutStatusGuard(() =>
        owner.query("update mandates.mandates set status = 'SUSPENDED' where id = $1", [mandateId]),
      );
    } finally {
      await owner.end();
    }

    expect(await ask(acting, asking(w))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await made(w.org)).toEqual({ requests: 0, months: 0 });
  });
});

describe('the lock order (ADR-006 §6, forced)', () => {
  it('runs two decisions on one agent’s month one after the other: the second sees the first’s capacity (SEC-LIM-01)', async () => {
    const { w, acting } = await ready();
    // The month's first request adds its period row: AED 1,000 of the AED 20,000 cap.
    expect(decidedOf(await ask(acting, asking(w, { amount: AED(100_000n), orderReference: 'INV-0' }))).decision).toBe(
      'ALLOW',
    );

    // Each alone fits; the two together are AED 1,000 past the cap. On two suppliers, so only the month serialises them.
    const answers = await whileHeld(
      (wait) =>
        withTenant(app, w.org, async (tx) => {
          await tx
            .selectFrom('limit_reservations.agent_periods')
            .select('month')
            .where('agent_id', '=', w.agent)
            .forNoKeyUpdate()
            .execute();
          await wait();
        }),
      () =>
        [0, 1].map((n) =>
          ask(acting, asking(w, { supplierId: w.suppliers[n] ?? '', orderReference: `INV-${String(n + 1)}` })),
        ),
    );

    expect(answers.map((answer) => decidedOf(answer).decision).sort()).toEqual(['ALLOW', 'DENY']);
    const reservations = await withTenant(app, w.org, (tx) =>
      tx.selectFrom('limit_reservations.reservations').select('amount_minor').execute(),
    );
    expect(reservations.reduce((sum, { amount_minor }) => sum + BigInt(amount_minor), 0n)).toBe(1_100_000n);
  });

  it('runs two requests for one supplier’s order one after the other: the second is the duplicate (SEC-DP-10)', async () => {
    const { w, acting } = await ready();
    const supplier = w.suppliers[0] ?? '';

    const answers = await whileHeld(
      (wait) =>
        withSignedStates(app, w.org, quiet(), async (tx, states) => {
          await supplierOf(tx, states, { orgId: w.org, id: supplier }, 'change');
          await wait();
        }),
      () => [0, 1].map(() => ask(acting, asking(w, { amount: AED(100_000n) }))),
    );

    expect(answers.map((answer) => decidedOf(answer)).sort((a, b) => a.decision.localeCompare(b.decision))).toEqual([
      expect.objectContaining({ decision: 'ALLOW' }),
      expect.objectContaining({ decision: 'DENY', reasons: ['DUPLICATE_ORDER_REFERENCE'] }),
    ]);
  });

  it('waits for a revocation holding the mandate, then denies (MANDATE_NOT_IN_FORCE)', async () => {
    const { w, mandateId, acting } = await ready();

    const [answer] = await whileHeld(
      (wait) =>
        movedIn(w, wait, (tx, states) =>
          states.changeStatus(tx, MANDATES, { orgId: w.org, id: mandateId ?? '' }, 'revoke', {
            actor: OPERATOR,
            action: 'mandate.revoke',
            details: {},
          }),
        ),
      () => [ask(acting, asking(w))],
    );

    const request = decidedOf(answer ?? { outcome: 'busy' });
    expect(request).toMatchObject({ mandateId, decision: 'DENY', reasons: ['MANDATE_NOT_IN_FORCE'] });
    expect(await heldBy(w.org, request.id)).toMatchObject({ reservation: undefined, claim: undefined });
  });

  it('waits for a key’s revocation, then refuses the request', async () => {
    const { w, acting } = await ready();

    const answers = await whileHeld(
      (wait) =>
        movedIn(w, wait, (tx, states) =>
          states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'revoke', {
            actor: OPERATOR,
            action: 'agent_key.revoked',
            details: {},
          }),
        ),
      () => [ask(acting, asking(w))],
    );

    expect(answers).toEqual([refused(401, 'UNAUTHENTICATED')]);
  });

  it('waits for a freeze, then refuses the request with nothing made (ORG_FROZEN)', async () => {
    const { w, acting } = await ready();

    const answers = await whileHeld(
      (wait) =>
        movedIn(w, wait, (tx, states) =>
          states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
            actor: OPERATOR,
            action: 'organization.freeze',
            details: {},
          }),
        ),
      () => [ask(acting, asking(w))],
    );

    expect(answers).toEqual([refused(409, 'ORG_FROZEN')]);
    expect(await made(w.org)).toEqual({ requests: 0, months: 0 });
  });
});

describe("through the agent's route (D4r)", () => {
  it('answers the agent’s request over HTTP with its key, the bank reference that differs, and a retry as it was', async () => {
    const { w, mandateId, acting } = await ready();
    const logger = testLogger(new LogCapture());
    const keyCheck = createAgentKeyCheck({ database: app, keys, ids, clock, logger });
    const api = await routeServer({ checkAgentKey: keyCheck.check.bind(keyCheck), spendRequestDecisions: decisions });
    const post = (orderReference: string) =>
      api.inject({
        method: 'POST',
        url: '/v1/spend-requests',
        headers: { authorization: `Bearer ${acting.text}`, 'idempotency-key': 'route-1' },
        payload: {
          amountMinor: 1_000_000,
          currency: 'AED',
          supplierId: w.suppliers[0],
          fundingSourceId: w.source,
          orderReference,
          purpose: 'Printer paper',
        },
      });

    const first = await post('INV_22');
    expect(first.statusCode).toBe(201);
    expect(first.json()).toMatchObject({
      status: 'APPROVED',
      decision: 'ALLOW',
      mandateId,
      amountMinor: 1_000_000,
      orderReference: 'INV_22',
      bankReference: 'INV-22',
    });
    const again = await post('INV_22');
    expect(again.statusCode).toBe(201);
    expect(again.json()).toEqual(first.json());
    expect((await post('INV_23')).json()).toMatchObject({ error: { code: 'IDEMPOTENCY_KEY_REUSED' } });
    expect((await made(w.org)).requests).toBe(1);
  });
});

/** The supplier's payee key set or cleared past the use cases, signed: a key moving between records. */
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

/** Approval above AED 15,000, so two orders within the default cap (AED 20,000 a month) can cross it together. */
const SPLIT_TERMS = { approvalThreshold: AED(1_500_000n) };
const SPLIT = { decision: 'REQUIRE_APPROVAL', reasons: ['AGGREGATE_THRESHOLD'], status: 'APPROVAL_REQUIRED' };

describe('the split check (D5, SEC-LIM-04)', () => {
  it('sends a split order for approval: the supplier’s orders in the window crossing the threshold, across midnight', async () => {
    const { w, mandateId, acting } = await ready({ terms: SPLIT_TERMS });
    // 23:30 in Dubai.
    clock.advanceBy(11.5 * HOUR_MS);
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe('ALLOW');

    // 00:30 the next day: a calendar day would start afresh, the rolling window doesn't.
    clock.advanceBy(HOUR_MS);
    const second = asking(w, { amount: AED(600_000n), orderReference: 'INV-2' });
    // The simulator weighs the same split total, writing nothing.
    expect(simulatedOf(await simulated(w, mandateId ?? '', second)).made).toMatchObject({
      decision: SPLIT.decision,
      reasons: SPLIT.reasons,
    });
    const split = decidedOf(await ask(acting, second));

    expect(split).toMatchObject(SPLIT);
    expect((await heldBy(w.org, split.id)).reservation).toMatchObject({ state: 'HELD', amount_minor: 600_000n });
    // Another supplier's orders are its own: AED 20,000 in the month, exactly the cap.
    const other = asking(w, { amount: AED(400_000n), supplierId: w.suppliers[1] ?? '', orderReference: 'INV-3' });
    expect(decidedOf(await ask(acting, other)).decision).toBe('ALLOW');
  });

  it('counts an order only while it is in the window', async () => {
    const { w, acting } = await ready({ terms: SPLIT_TERMS });
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe('ALLOW');

    clock.advanceBy(DAY_MS + 60_000);

    expect(decidedOf(await ask(acting, asking(w, { amount: AED(600_000n), orderReference: 'INV-2' }))).decision).toBe(
      'ALLOW',
    );
  });

  it('adds up every agent’s orders to the supplier', async () => {
    const { w, acting } = await ready({ terms: SPLIT_TERMS });
    const theirKey = await secondAgent(w, SPLIT_TERMS);
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe('ALLOW');

    // The second agent's month is empty; the supplier's window isn't.
    const split = decidedOf(await ask(theirKey, asking(w, { amount: AED(600_000n), orderReference: 'INV-2' })));

    expect(split).toMatchObject(SPLIT);
  });

  it('adds up the payee’s orders under another supplier record holding its key', async () => {
    const { w, acting } = await ready({ terms: SPLIT_TERMS });
    const [first, second] = [w.suppliers[0] ?? '', w.suppliers[1] ?? ''];
    await payeeKeyOf(w, first, 'payee-1');
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe('ALLOW');
    // The payee's key moved to the second supplier record, as a supplier re-created for the same account.
    await payeeKeyOf(w, first, null);
    await payeeKeyOf(w, second, 'payee-1');

    const split = decidedOf(
      await ask(acting, asking(w, { amount: AED(600_000n), supplierId: second, orderReference: 'INV-2' })),
    );

    expect(split).toMatchObject(SPLIT);
  });

  it('keeps counting the supplier’s orders under a revoked mandate: a new one never resets the window', async () => {
    const { w, mandateId, acting } = await ready({ terms: SPLIT_TERMS });
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe('ALLOW');
    await movedPastTheUseCase(w, mandateId ?? '', 'revoke');
    const next = await shared.inForce(registry, w, SPLIT_TERMS);

    const split = decidedOf(await ask(acting, asking(w, { amount: AED(600_000n), orderReference: 'INV-2' })));

    expect(split).toMatchObject({ ...SPLIT, mandateId: next });
  });

  it('with the check off, weighs each order alone, and still denies the same order twice', async () => {
    const { w, acting } = await ready({ terms: { ...SPLIT_TERMS, splitCheck: false } });
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe('ALLOW');
    const second = asking(w, { amount: AED(600_000n), orderReference: 'INV-2' });

    expect(decidedOf(await ask(acting, second)).decision).toBe('ALLOW');
    // The same order again, for AED 100: within every limit, and still the duplicate.
    expect(decidedOf(await ask(acting, { ...second, amount: AED(10_000n) }))).toMatchObject({
      decision: 'DENY',
      reasons: ['DUPLICATE_ORDER_REFERENCE'],
    });
  });

  it('runs two agents’ orders to one supplier one after the other: the second sees the first’s (forced)', async () => {
    const { w, acting } = await ready({ terms: SPLIT_TERMS });
    const theirKey = await secondAgent(w, SPLIT_TERMS);
    const supplier = w.suppliers[0] ?? '';

    // Each alone within the threshold, the two past it; two agents' months, so only the supplier serialises them.
    const answers = await whileHeld(
      (wait) =>
        withSignedStates(app, w.org, quiet(), async (tx, states) => {
          await supplierOf(tx, states, { orgId: w.org, id: supplier }, 'change');
          await wait();
        }),
      () => [
        ask(acting, asking(w, { orderReference: 'INV-1' })),
        ask(theirKey, asking(w, { orderReference: 'INV-2' })),
      ],
    );

    expect(answers.map((answer) => decidedOf(answer).decision).sort()).toEqual(['ALLOW', 'REQUIRE_APPROVAL']);
  });
});

/**
 * Every table's rows, as the database admin sees them, in one fixed
 * statement: each table's count and a checksum of every row, so an update
 * shows as well as an insert or a delete (C4's review). What a simulation
 * must leave as it was.
 */
const EVERY_TABLE = `select schemaname || '.' || tablename as name,
  (pg_catalog.xpath('/row/n/text()', pg_catalog.query_to_xml(pg_catalog.format(
    'select count(*) || '':'' || pg_catalog.md5(coalesce(pg_catalog.string_agg(t::text, '','' order by t::text), '''')) as n from %I.%I t',
    schemaname, tablename), false, true, '')))[1]::text as n
  from pg_catalog.pg_tables where schemaname not in ('pg_catalog', 'information_schema') order by 1`;

const everyTable = async (): Promise<Record<string, string>> =>
  Object.fromEntries(
    (await database.as('admin').query<{ name: string; n: string }>(EVERY_TABLE)).map(({ name, n }) => [name, n]),
  );

/** The simulator's answer for the world's mandate, the request as `asking` makes it unless changed. */
const simulated = async (w: World, mandateId: string, overrides: Partial<SpendWeighed> = {}, whatIf: WhatIf = {}) =>
  simulations.simulate(w.org, mandateId, { ...asking(w), ...overrides }, whatIf, CORRELATION);

const simulatedOf = (answer: Awaited<ReturnType<typeof simulated>>) => {
  if (answer.outcome !== 'simulated') throw new Error(`not simulated: ${JSON.stringify(answer)}`);
  return answer;
};

/** A mandate policy's or the organisation's proposed rules: only a monthly cap, or an approval threshold. */
const proposed = (rules: { monthlyCap?: bigint; approvalThreshold?: bigint; supplierIds?: string[] }) => ({
  currency: 'AED',
  perOrderCap: null,
  monthlyCap: rules.monthlyCap === undefined ? null : AED(rules.monthlyCap),
  approvalThreshold: rules.approvalThreshold === undefined ? null : AED(rules.approvalThreshold),
  supplierIds: rules.supplierIds ?? null,
});

describe('the simulator (C4, decision 9)', () => {
  it('decides as a request would, from the same totals, writing nothing anywhere (SEC-AG-09)', async () => {
    const { w, mandateId, acting } = await ready({ terms: { approvalThreshold: AED(1_500_000n) } });
    const id = mandateId ?? '';
    const before = await everyTable();
    // Each a count and a checksum, so equal tables are a real check.
    expect(Object.values(before).every((rows) => /^[0-9]+:[0-9a-f]{32}$/.test(rows))).toBe(true);

    // A new agent's month, before its first request: named in the mandate's zone, its zone left unkept.
    const first = simulatedOf(await simulated(w, id));
    expect(first).toMatchObject({
      mandateId,
      month: '2026-10',
      monthSpent: AED(0n),
      proposed: { organizationPolicy: false, mandatePolicy: false },
    });
    expect(first.made).toMatchObject({ decision: 'ALLOW', reasons: [], monthlyCapFrom: 'default' });
    const approval = simulatedOf(await simulated(w, id, { amount: AED(1_600_000n) }));
    expect(approval.made).toMatchObject({ decision: 'REQUIRE_APPROVAL', reasons: ['APPROVAL_THRESHOLD'] });
    await simulated(w, id, {}, { organizationPolicy: proposed({ monthlyCap: 1n }) });
    expect(await everyTable()).toEqual(before);

    // The same engine and totals: a request made now gets what was simulated.
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe(first.made.decision);
    // To the other supplier, so only the month adds it (D5 would add the first supplier's as a split).
    const other = w.suppliers[1] ?? '';
    expect(
      decidedOf(await ask(acting, asking(w, { amount: AED(600_000n), supplierId: other, orderReference: 'INV-2' }))),
    ).toMatchObject({ decision: 'ALLOW' });
    // AED 16,000 held: AED 16,000 more is past the default cap (AED 20,000), as a request would find it.
    const held = simulatedOf(await simulated(w, id, { amount: AED(1_600_000n), orderReference: 'INV-3' }));
    expect(held).toMatchObject({ monthSpent: AED(1_600_000n), month: '2026-10' });
    expect(held.made).toMatchObject({ decision: 'DENY' });
    expect([...held.made.reasons].sort()).toEqual(['APPROVAL_THRESHOLD', 'POLICY_MONTHLY_CAP']);
    const request = decidedOf(await ask(acting, asking(w, { amount: AED(1_600_000n), orderReference: 'INV-3' })));
    expect({ decision: request.decision, reasons: request.reasons }).toEqual({
      decision: held.made.decision,
      reasons: held.made.reasons,
    });
  });

  it('weighs proposed rules in place of those in force, changing nothing', async () => {
    const { w, mandateId, acting } = await ready();
    const id = mandateId ?? '';
    await capped(w, 'organization', null, 3_000_000n);

    const tighter = simulatedOf(await simulated(w, id, {}, { organizationPolicy: proposed({ monthlyCap: 500_000n }) }));
    expect(tighter.made).toMatchObject({
      decision: 'DENY',
      reasons: ['POLICY_MONTHLY_CAP'],
      monthlyCapFrom: 'organization-policy',
    });
    expect(tighter.made.versions.organizationPolicy).toBe('proposed');
    expect(tighter.proposed).toEqual({ organizationPolicy: true, mandatePolicy: false });

    // The mandate's own, proposed: an approval threshold below the amount, its cap the organisation's.
    const mandates = simulatedOf(
      await simulated(w, id, {}, { mandatePolicy: proposed({ approvalThreshold: 100_000n }) }),
    );
    expect(mandates.made).toMatchObject({ decision: 'REQUIRE_APPROVAL', reasons: ['APPROVAL_THRESHOLD'] });
    expect(mandates.made.versions.mandatePolicy).toBe('proposed');
    expect(mandates.made.versions.organizationPolicy).toEqual(expect.any(String));

    // Nothing proposed was kept: a request is weighed by the rules in force.
    expect(decidedOf(await ask(acting, asking(w))).decision).toBe('ALLOW');
  });

  it('refuses a proposed mandate policy wider than the mandate, or for a mandate not in force', async () => {
    const { w, mandateId } = await ready();
    expect(await simulated(w, mandateId ?? '', {}, { mandatePolicy: proposed({ monthlyCap: 100_000_000n }) })).toEqual(
      refused(409, 'POLICY_WIDER_THAN_MANDATE'),
    );
    expect(await simulated(w, mandateId ?? '', {}, { mandatePolicy: proposed({ supplierIds: [ids.next()] }) })).toEqual(
      refused(409, 'POLICY_WIDER_THAN_MANDATE'),
    );

    const drafting = await ready({ mandate: false });
    const { id: draftId } = await shared.drafted(registry, drafting.w);
    expect(await simulated(drafting.w, draftId, {}, { mandatePolicy: proposed({ approvalThreshold: 1n }) })).toEqual(
      refused(409, 'MANDATE_NOT_IN_FORCE'),
    );
    // An ended mandate, its agent's new one in force: proposed rules for the old one are refused.
    const renewed = await ready();
    await movedPastTheUseCase(renewed.w, renewed.mandateId ?? '', 'revoke');
    await shared.inForce(registry, renewed.w);
    expect(
      await simulated(renewed.w, renewed.mandateId ?? '', {}, { mandatePolicy: proposed({ approvalThreshold: 1n }) }),
    ).toEqual(refused(409, 'MANDATE_NOT_IN_FORCE'));

    // Without proposed rules, a draft's agent is weighed as it stands: no mandate in force.
    const asItStands = simulatedOf(await simulated(drafting.w, draftId));
    expect(asItStands).toMatchObject({ mandateId: null, month: null });
    expect(asItStands.made).toMatchObject({ decision: 'DENY', reasons: ['MANDATE_NOT_IN_FORCE'] });
  });

  it('names the month in the agent’s kept zone, not its mandate’s, as a decision would', async () => {
    const { w, mandateId } = await ready();
    // A zone kept from an earlier mandate (UTC+14): already November when Dubai is still in October.
    await withTenant(app, w.org, (tx) =>
      tx
        .insertInto('limit_reservations.agent_zones')
        .values({ org_id: w.org, agent_id: w.agent, time_zone: 'Pacific/Kiritimati', created_at: clock.now() })
        .execute(),
    );
    clock.advanceBy(Date.parse('2026-10-31T12:00:00Z') - clock.now().getTime());

    expect(simulatedOf(await simulated(w, mandateId ?? '')).month).toBe('2026-11');
  });

  it('finds an order already claimed when one is named, however written, and none when none is', async () => {
    const { w, mandateId, acting } = await ready();
    const id = mandateId ?? '';
    decidedOf(await ask(acting, asking(w)));

    const again = simulatedOf(await simulated(w, id, { orderReference: ' inv-1001 ' }));
    expect(again.made.reasons).toContain('DUPLICATE_ORDER_REFERENCE');
    const unnamed = simulatedOf(await simulated(w, id, { orderReference: null }));
    expect(unnamed.made.reasons).not.toContain('DUPLICATE_ORDER_REFERENCE');
  });

  it('refuses another organisation’s mandate, a currency not taken and a frozen organisation, as a request is', async () => {
    const { w, mandateId } = await ready();
    const other = await ready();
    expect(await simulated(other.w, mandateId ?? '')).toEqual(refused(404, 'NOT_FOUND'));
    expect(await simulated(w, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
    expect(await simulated(w, mandateId ?? '', { amount: money(1_000_000n, 'USD') })).toEqual(
      refused(422, 'CURRENCY_NOT_ALLOWED'),
    );
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
        actor: OPERATOR,
        action: 'organization.freeze',
        details: {},
      }),
    );
    expect(await simulated(w, mandateId ?? '')).toEqual(refused(409, 'ORG_FROZEN'));
  });
});

describe('every request', () => {
  it('leaves VALIDATING in the transaction that made it (D1’s review)', async () => {
    const left = await database
      .as('admin')
      .query<{ n: number }>("select count(*)::int as n from spend_requests.requests where status = 'VALIDATING'");
    expect(left).toEqual([{ n: 0 }]);
    expect(
      (await database.as('admin').query<{ n: number }>('select count(*)::int as n from spend_requests.requests'))[0]?.n,
    ).toBeGreaterThan(10);
  });
});
