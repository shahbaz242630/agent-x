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
// mandate); the agent's route over HTTP with its real key check (D4r); and
// no request ever left VALIDATING.
import { addAgent, AGENT_KEYS, AGENTS, createAgentKeyCheck } from '@agentx/core/modules/agents';
import { type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { MANDATES, type PolicyRules, setPolicy } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { releaseClaim, SPEND_REQUESTS, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { supplierOf, verifySupplier } from '@agentx/core/modules/suppliers';
import { DAY_MS, money } from '@agentx/core/shared-kernel';
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

    const over = decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n), orderReference: 'INV-2' })));

    // AED 15,000 held under the revoked mandate and 15,000 asked: past the default AED 20,000 cap.
    expect(over).toMatchObject({ mandateId: next, decision: 'DENY', reasons: ['POLICY_MONTHLY_CAP'] });
    // Exactly at the cap passes.
    const rest = asking(w, { amount: AED(500_000n), orderReference: 'INV-3' });
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
    await shared.inForce(registry, theirs);
    const theirKey = await agentKey(theirs);
    // AED 15,000 held by the first agent this month; the second's own month is empty.
    expect(
      decidedOf(await ask(theirKey, asking(w, { amount: AED(1_500_000n), orderReference: 'INV-3' }))).decision,
    ).toBe('ALLOW');
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
