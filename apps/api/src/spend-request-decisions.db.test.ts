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
// mandate, a version's limit or a supplier's payee key changed past the app:
// SEC-DB-02/03); a mandate past its end before the job (SEC-AG-12), a
// suspended source of the organisation's own (SEC-AG-03), and a supersede
// mid-month keeping the month (SEC-LIM-03) (G8); the agent's route over HTTP
// with its real key check (D4r); the simulator (C4): the same decision as a request, the month's total, proposed
// rules, and nothing written anywhere (SEC-AG-09); and no request ever left
// VALIDATING.
import { AGENT_KEYS, AGENTS, createAgentKeyCheck } from '@agentx/core/modules/agents';
import { type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import { addZone, type LimitReservationsTables, sealNewZone } from '@agentx/core/modules/limit-reservations';
import {
  draftMandate,
  MANDATE_VERSIONS,
  MANDATES,
  policyOf,
  type PolicyRules,
  setPolicy,
} from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import {
  releaseClaim,
  SPEND_REQUESTS,
  type SpendRequestsTables,
  totalsWeighed,
} from '@agentx/core/modules/spend-requests';
import { SUPPLIERS, supplierOf } from '@agentx/core/modules/suppliers';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
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

import { TURNS_AN_AGENT, TurnWaitExceeded } from './agent-turns.ts';
import { createMandateMoves } from './mandate-moves.ts';
import { createMandateRegistry, type MandateRegistry, REDRAFT_OPERATION } from './mandate-registry.ts';
import { createPolicySimulations, type PolicySimulations, type WhatIf } from './policy-simulations.ts';
import { closeServers, routeServer } from './route-server.helper.test.ts';
import {
  AED,
  askedFor,
  keys,
  mandateWorld,
  type MandateWorldTables,
  OPERATOR,
  refused,
  type World,
} from './mandate-world.helper.test.ts';
import { capChoiceDetails } from './monthly-cap-choice.ts';
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
let capture: LogCapture;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'spend-request-decisions' });
const { world, quiet, movedPastTheUseCase, agentKey, eventsAbout, verified, acceptedPastTheUseCase } = shared;

/**
 * A world whose agent has a key and a mandate in force (unless `mandate` is
 * false), both suppliers verified: the mandate's terms the world's own
 * (AED 50,000 an order, 100,000 a month, approval above 25,000) changed by
 * `terms`, so the organisation's cap (AED 20,000 a month, the world's) binds first;
 * none chosen at all with `capChosen` false (E2).
 */
async function ready({
  terms = {},
  mandate = true,
  capChosen = true,
}: { terms?: Parameters<typeof shared.termsOf>[1]; mandate?: boolean; capChosen?: boolean } = {}) {
  const w = await world({ capChosen });
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
  return withSignedStates(app, w.org, quiet(), async (tx, states) => {
    // The organisation's is set already, as the world chose its cap (E2).
    const read = await policyOf(tx, states, { orgId: w.org, id: mandateId ?? w.org }, 'change');
    return setPolicy(tx, states, {
      orgId: w.org,
      existing: read.outcome === 'found' ? read : null,
      scope,
      mandateId,
      versionId: ids.next(),
      rules,
      madeBy: w.admin.membershipId,
      madeAt: clock.now(),
      actor: OPERATOR,
      details: scope === 'organization' ? capChoiceDetails('amount') : {},
    });
  });
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

/** The organisation's notices that a request waits for approval (Phase 3 B2): whom they go to, and what about. */
// The outbox is global (0021, the sender works across organisations): no tenant wall filters it.
const waitingNotices = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['recipient_user_id', 'about_id'])
      .where('org_id', '=', org)
      .where('kind', '=', 'spend_request_waiting')
      .execute(),
  );

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
      // The world's, its cap chosen (E2).
      organization_policy_version_id: expect.any(String) as unknown,
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
      expect.objectContaining({
        action: 'spend_request.decided',
        actorType: 'agent',
        // What was weighed that no record keeps, sealed with it, so its input hash can be checked again (G3).
        details: expect.objectContaining({
          weighedAt: clock.now().toISOString(),
          agentStatus: 'ACTIVE',
          mandateStatus: 'ACTIVE',
          supplierStatus: 'VERIFIED',
          sourceMayFund: true,
          monthSpent: '0 AED',
          splitOpen: '0 AED',
          duplicateOrder: false,
          defaultMonthlyCap: null,
          organizationCapChosen: true,
        }) as unknown,
      }),
    ]);
    // The agent's months are named in its first mandate's zone, kept for good.
    expect(
      await withTenant(app, w.org, (tx) =>
        tx.selectFrom('limit_reservations.agent_zones').select('time_zone').execute(),
      ),
    ).toEqual([{ time_zone: 'Asia/Dubai' }]);
    // Allowed at once: no one is told it waits.
    expect(await waitingNotices(w.org)).toEqual([]);
  });

  it('sends one over the approval threshold for approval, its capacity held while it waits (SEC-LIM-09)', async () => {
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
    // Every admin and approver is told it waits, in its decision's transaction (Phase 3 B2, partner decision 2).
    expect(await waitingNotices(w.org)).toEqual([{ recipient_user_id: null, about_id: request.id }]);
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
    expect(await waitingNotices(w.org)).toEqual([]);
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

  it('sends for approval an order an open claim’s looks like on the rail, holding it; the exact one still denied (decision 11a)', async () => {
    const { w, acting } = await ready();
    const small = (orderReference: string, supplierId = w.suppliers[0] ?? '') =>
      asking(w, { amount: AED(10_000n), orderReference, supplierId });
    const first = decidedOf(await ask(acting, small('INV_22')));
    expect(first.decision).toBe('ALLOW');
    expect((await heldBy(w.org, first.id)).claim).toMatchObject({ bank_key: 'inv-22', released_at: null });

    for (const written of ['INV-22', 'INV-٢٢']) {
      const possible = decidedOf(await ask(acting, small(written)));
      expect(possible).toMatchObject({
        decision: 'REQUIRE_APPROVAL',
        reasons: ['POSSIBLE_DUPLICATE_ORDER'],
        status: 'APPROVAL_REQUIRED',
      });
      // Held while it waits, its claim beside the one it looks like.
      expect((await heldBy(w.org, possible.id)).claim).toMatchObject({ bank_key: 'inv-22', released_at: null });
    }
    // The first's own order, however written, is refused; INV-22's open claims also look like it.
    expect(decidedOf(await ask(acting, small('inv_22')))).toMatchObject({
      decision: 'DENY',
      reasons: ['DUPLICATE_ORDER_REFERENCE', 'POSSIBLE_DUPLICATE_ORDER'],
    });
    expect(decidedOf(await ask(acting, small('INV-22', w.suppliers[1] ?? ''))).decision).toBe('ALLOW');
    expect(decidedOf(await ask(acting, small('INV-23'))).decision).toBe('ALLOW');
  });

  it('looks for a possible duplicate under the payee’s key at another supplier record, and not past a released claim', async () => {
    const { w, acting } = await ready();
    const [first, second] = [w.suppliers[0] ?? '', w.suppliers[1] ?? ''];
    const small = (orderReference: string, supplierId: string) =>
      asking(w, { amount: AED(10_000n), orderReference, supplierId });
    await payeeKeyOf(w, first, 'payee-1');
    const claimed = decidedOf(await ask(acting, small('PO_7', first)));
    await payeeKeyOf(w, first, null);
    await payeeKeyOf(w, second, 'payee-1');

    expect(decidedOf(await ask(acting, small('PO-7', second)))).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['POSSIBLE_DUPLICATE_ORDER'],
    });

    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, SPEND_REQUESTS, { orgId: w.org, id: claimed.id }, 'deny', {
        actor: OPERATOR,
        action: 'spend_request.denied',
        details: {},
      }),
    );
    await withTenant(app, w.org, (tx) => releaseClaim(tx, { requestId: claimed.id, releasedAt: clock.now() }));
    // Its claim released, and the first supplier without the payee's key now, nothing open there looks like PO-7.
    expect(decidedOf(await ask(acting, small('PO-7', first))).decision).toBe('ALLOW');
  });

  it('never makes an order with nothing the rail carries a possible duplicate of another', async () => {
    const { w, acting } = await ready();
    const small = (orderReference: string) => asking(w, { amount: AED(10_000n), orderReference });
    expect(decidedOf(await ask(acting, small('فاتورة'))).decision).toBe('ALLOW');
    expect(decidedOf(await ask(acting, small('#_#'))).decision).toBe('ALLOW');
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

    // AED 15,000 held under the revoked mandate and 15,000 asked: past the organisation's AED 20,000 cap.
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

  it('logs each decision once it is made, with how long it took, for the denial-surge alert, and never for its key’s replay (E2)', async () => {
    const { w, acting } = await ready();
    const decided = () => capture.lines().filter((line) => line.event === 'spend_request.decided');
    const allowed = decidedOf(await ask(acting, asking(w), 'logged-once'));
    const denied = decidedOf(await ask(acting, asking(w, { orderReference: 'inv-1001' })));

    expect(denied.decision).toBe('DENY');
    expect(decided()).toEqual([
      expect.objectContaining({ orgId: w.org, agentId: acting.agentId, decision: 'ALLOW', reasons: '' }),
      expect.objectContaining({
        orgId: w.org,
        agentId: acting.agentId,
        decision: 'DENY',
        reasons: denied.reasons.join(' '),
      }),
    ]);
    // The whole decision in whole milliseconds, for the policy target (PL-38): never below the transaction's own work.
    for (const line of decided()) {
      expect(Number.isInteger(line.durationMs)).toBe(true);
      expect(line.durationMs).toBeGreaterThan(0);
      // Where its time went (4D2d): its trips, the commit's among them, each timed, in the line.
      expect(line.trips).toBeGreaterThan(5);
      expect(line.commitMs).toBeGreaterThan(0);
      expect(line.databaseMs).toBeGreaterThanOrEqual(line.slowestTripMs as number);
      expect(line.turnWaitMs).toBeGreaterThanOrEqual(0);
      expect(line.poolWaitMs).toBeGreaterThanOrEqual(0);
    }
    // The signal alone: no order, amount or supplier in the line.
    const lines = JSON.stringify(decided());
    for (const value of ['inv-1001', 'INV-1001', w.suppliers[0] ?? '', '1000000', 'Printer paper']) {
      expect(lines).not.toContain(value);
    }

    expect(decidedOf(await ask(acting, asking(w), 'logged-once'))).toEqual(allowed);
    expect(await ask(acting, asking(w, { orderReference: 'INV-9' }), 'logged-once')).toEqual({ outcome: 'conflict' });
    expect(decided()).toHaveLength(2);
  });

  it('answers a fresh decision as its own transaction read it, in that one transaction; its key’s replay reads it in another, alike (4D2d P4)', async () => {
    const { w, acting } = await ready();
    let opened = 0;
    // The same pool, each transaction it opens counted.
    const counted = new Proxy(app, {
      get: (target, name): unknown => {
        if (name === 'transaction') opened += 1;
        // Kysely's own fields are private: each method runs on the pool itself.
        const value = Reflect.get(target, name, target) as unknown;
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    decisions = createSpendRequestDecisions({
      database: counted,
      outbox: createOutbox({ ids, clock }),
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    });

    const fresh = decidedOf(await ask(acting, asking(w), 'fresh-answer'));
    const freshOpened = opened;
    const replayed = decidedOf(await ask(acting, asking(w), 'fresh-answer'));

    expect(freshOpened).toBe(1);
    expect(opened - freshOpened).toBe(2);
    expect(replayed).toEqual(fresh);
    expect(fresh).toMatchObject({ decision: 'ALLOW', status: 'APPROVED' });
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

    const theirKey = await shared.secondAgent(registry, w);
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

  it('refuses a mandate version’s limit raised past the app, making nothing (FX-TAMPER, SEC-DB-03)', async () => {
    const w = await world();
    for (const supplier of w.suppliers) await verified(w, supplier);
    const { id, versionId } = await shared.drafted(registry, w);
    await shared.acceptedPastTheUseCase(w, id);
    const acting = await agentKey(w);
    const owner = await tamperAsOwner(database, MANDATE_VERSIONS, w.org);
    try {
      await owner.query('alter table mandates.versions disable trigger made_once');
      await owner.setColumn(versionId, 'monthly_limit_minor', '99000000');
    } finally {
      await owner.query('alter table mandates.versions enable trigger made_once');
      await owner.end();
    }

    expect(await ask(acting, asking(w))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await made(w.org)).toEqual({ requests: 0, months: 0 });
  });

  it('refuses a supplier’s payee key changed past the app, making nothing (FX-TAMPER, SEC-DB-02)', async () => {
    const { w, acting } = await ready();
    const owner = await tamperAsOwner(database, SUPPLIERS, w.org);
    try {
      await owner.setColumn(w.suppliers[0] ?? '', 'payee_key', 'planted-payee');
    } finally {
      await owner.end();
    }

    expect(await ask(acting, asking(w))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await made(w.org)).toEqual({ requests: 0, months: 0 });
  });

  it('denies a mandate past its end before the expiry job reaches it (SEC-AG-12)', async () => {
    const { w, mandateId, acting } = await ready({ terms: { endsAt: new Date(clock.now().getTime() + HOUR_MS) } });
    clock.advanceBy(2 * HOUR_MS);

    expect(decidedOf(await ask(acting, asking(w)))).toMatchObject({
      mandateId,
      decision: 'DENY',
      reasons: ['MANDATE_NOT_IN_FORCE'],
      status: 'DENIED',
    });
    const row = await withTenant(app, w.org, (tx) =>
      tx
        .selectFrom('mandates.mandates')
        .select('status')
        .where('id', '=', mandateId ?? '')
        .executeTakeFirstOrThrow(),
    );
    expect(row.status).toBe('ACTIVE');
  });

  it('denies a source of the organisation’s own the partner suspended (SEC-AG-03)', async () => {
    const { w, acting } = await ready();
    await shared.partnerSays(w, { availability: 'SUSPENDED' });

    expect(decidedOf(await ask(acting, asking(w)))).toMatchObject({
      decision: 'DENY',
      reasons: ['SOURCE_NOT_USABLE'],
      status: 'DENIED',
    });
  });

  it('keeps the agent’s month when its mandate is superseded mid-month (SEC-LIM-03)', async () => {
    const { w, mandateId, acting } = await ready();
    const first = decidedOf(await ask(acting, asking(w, { amount: AED(1_500_000n) })));
    expect(first.decision).toBe('ALLOW');
    const redrafted = await registry.redraft(
      w.admin,
      shared.keyed(w.admin, REDRAFT_OPERATION),
      mandateId ?? '',
      { terms: shared.termsOf(w, { purpose: 'Office supplies, renewed' }), overLimit: 'refuse' },
      CORRELATION,
    );
    expect(redrafted.outcome).toBe('drafted');
    await shared.acceptedPastTheUseCase(w, mandateId ?? '');

    // To the other supplier, so the split check (D5) adds nothing.
    const other = w.suppliers[1] ?? '';
    const over = decidedOf(
      await ask(acting, asking(w, { amount: AED(1_500_000n), supplierId: other, orderReference: 'INV-2' })),
    );

    // AED 15,000 held under the version superseded and 15,000 asked: past the organisation's AED 20,000 cap.
    expect(over).toMatchObject({ mandateId, decision: 'DENY', reasons: ['POLICY_MONTHLY_CAP'] });
    const versions = [first.id, over.id].map(async (id) => (await heldBy(w.org, id)).row?.mandate_version_id);
    const [before, after] = await Promise.all(versions);
    expect(after).not.toBe(before);
  });
});

describe('its writes on one trip, one forced to fail (4D2d P16)', () => {
  /** `action` with every write to the table meeting `body` first. */
  async function withWritesTo<T>(table: string, body: string, action: () => Promise<T>): Promise<T> {
    const owner = database.as('owner');
    await owner.query(`create function ${table}_forced() returns trigger language plpgsql as $$ begin ${body} end $$`);
    await owner.query(
      `create trigger forced before insert on ${table} for each row execute function ${table}_forced()`,
    );
    try {
      return await action();
    } finally {
      await owner.query(`drop trigger forced on ${table}`);
      await owner.query(`drop function ${table}_forced()`);
    }
  }

  const left = (org: string) =>
    withTenant(app, org, async (tx) => ({
      requests: await tx.selectFrom('spend_requests.requests').select('id').execute(),
      reservations: await tx.selectFrom('limit_reservations.reservations').select('id').execute(),
      claims: await tx.selectFrom('spend_requests.order_claims').select('id').execute(),
    }));

  it.each([
    ['the request', 'spend_requests.requests'],
    ['the reservation', 'limit_reservations.reservations'],
    ['the claim', 'spend_requests.order_claims'],
  ])('keeps nothing when %s fails, and says what failed', async (_, table) => {
    const { w, acting } = await ready();
    await withWritesTo(table, `raise exception 'forced on ${table}';`, async () => {
      await expect(ask(acting, asking(w))).rejects.toThrow(`forced on ${table}`);
    });
    expect(await left(w.org)).toEqual({ requests: [], reservations: [], claims: [] });
  });

  it("refuses when the agent's month was not there to lock, keeping nothing", async () => {
    const { w, acting } = await ready();
    await withWritesTo('limit_reservations.agent_periods', 'return null;', async () => {
      await expect(ask(acting, asking(w))).rejects.toThrow('was not there to lock');
    });
    expect(await left(w.org)).toEqual({ requests: [], reservations: [], claims: [] });
  });

  it('decides as usual once the writes go through again', async () => {
    const { w, acting } = await ready();
    await withWritesTo('spend_requests.order_claims', "raise exception 'forced';", async () => {
      await expect(ask(acting, asking(w), 'again')).rejects.toThrow('forced');
    });
    expect(decidedOf(await ask(acting, asking(w), 'again'))).toMatchObject({ decision: 'ALLOW' });
  });

  it('counts its writes as one trip', async () => {
    const { w, acting } = await ready();
    decidedOf(await ask(acting, asking(w)));
    decidedOf(await ask(acting, asking(w, { orderReference: 'INV-ONE-TRIP' })));
    const line = capture
      .lines()
      .filter(({ event }) => event === 'spend_request.decided')
      .at(-1);
    // The trip list's count on main was 24; these two batches take 3 off it.
    expect(line?.['trips']).toBeLessThanOrEqual(22);
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

  it('answers a decision whose turn waited past its bound busy, with nothing made and the key unused (S161)', async () => {
    const { w, acting } = await ready();
    decisions = createSpendRequestDecisions({
      database: app,
      outbox: createOutbox({ ids, clock }),
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      turns: { run: () => Promise.reject(new TurnWaitExceeded(7_500)), agentsInHand: () => 0 },
    });

    expect(await ask(acting, asking(w), 'busy-turn')).toEqual({ outcome: 'refused', status: 503, code: 'AGENT_BUSY' });
    expect(capture.lines().filter((line) => line.event === 'spend_request.agent_busy')).toEqual([
      expect.objectContaining({ level: 'warn', agentId: acting.agentId, waitedMs: 7_500 }),
    ]);
    const made = await withTenant(app, w.org, (tx) =>
      tx.selectFrom('spend_requests.requests').select('id').where('idempotency_key', '=', 'busy-turn').execute(),
    );
    expect(made).toEqual([]);
    // Sent again with the same key once its turn comes: decided, as a first ask.
    decisions = createSpendRequestDecisions({
      database: app,
      outbox: createOutbox({ ids, clock }),
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    });
    expect(await ask(acting, asking(w), 'busy-turn')).toMatchObject({ outcome: 'decided' });
  });

  it('fails a decision whose turn fails otherwise, as it always did', async () => {
    const { w, acting } = await ready();
    decisions = createSpendRequestDecisions({
      database: app,
      outbox: createOutbox({ ids, clock }),
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      turns: { run: () => Promise.reject(new Error('the pool is gone')), agentsInHand: () => 0 },
    });

    await expect(ask(acting, asking(w))).rejects.toThrow('the pool is gone');
  });

  it('takes one agent’s burst two at a time: the rest hold no connection, so another agent’s goes on (S160)', async () => {
    const { w, acting } = await ready();
    // Of the same organisation, so the turns are the agent's, not its organisation's.
    const theirKey = await shared.secondAgent(registry, w);
    // The month's period row first, so the burst queues on its lock.
    decidedOf(await ask(acting, asking(w, { amount: AED(10_000n), orderReference: 'INV-0' })));
    const { promise: held, resolve: holds } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holder = withTenant(app, w.org, async (tx) => {
      await tx
        .selectFrom('limit_reservations.agent_periods')
        .select('month')
        .where('agent_id', '=', w.agent)
        .forNoKeyUpdate()
        .execute();
      holds(undefined);
      await gate;
    });
    await held;

    // Five and the lock's holder would fill the pool of six, with no turns.
    const burst = Array.from({ length: 5 }, (_, n) =>
      within(20_000, ask(acting, asking(w, { amount: AED(10_000n), orderReference: `INV-${String(n + 1)}` })), 'burst'),
    );
    await waitUntilQueued(database.as('admin'), TURNS_AN_AGENT);
    // To the other supplier: the burst's first turn holds the first one's lock.
    const theirs = asking(w, { supplierId: w.suppliers[1] ?? '', orderReference: 'INV-THEIRS' });
    const meanwhile = await within(20_000, ask(theirKey, theirs), 'the other agent');
    expect(decidedOf(meanwhile).decision).toBe('ALLOW');
    expect(await waitUntilQueued(database.as('admin'), 1)).toHaveLength(TURNS_AN_AGENT);
    open(undefined);
    await holder;

    expect((await Promise.all(burst)).map((answer) => decidedOf(answer).decision)).toEqual(
      Array.from({ length: 5 }, () => 'ALLOW'),
    );
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

describe('what is weighed once the locks are held, in one statement (4D2d P12)', () => {
  it('answers each part only where it is asked', async () => {
    const { w, acting } = await ready();
    const supplierId = w.suppliers[0] ?? '';
    const first = decidedOf(await ask(acting, asking(w, { amount: AED(100_000n), orderReference: 'INV-1' })));
    expect(first.decision).toBe('ALLOW');

    await withTenant(app, w.org, async (tx) => {
      const { month } = await tx
        .selectFrom('limit_reservations.reservations')
        .select('month')
        .where('agent_id', '=', acting.agentId)
        .executeTakeFirstOrThrow();
      const asked = { agentId: acting.agentId, month, currency: 'AED' };
      const window = { supplierId, payeeKey: null, since: new Date(0), currency: 'AED' };
      const order = { supplierId, payeeKey: null, reference: 'INV-1' };

      expect(await totalsWeighed(tx, { month: asked, split: window, order })).toEqual({
        spent: 100_000n,
        split: 100_000n,
        claims: { duplicate: true, possible: false },
      });
      expect(await totalsWeighed(tx, { month: asked, split: null, order: null })).toEqual({
        spent: 100_000n,
        split: 0n,
        claims: { duplicate: false, possible: false },
      });
      expect(await totalsWeighed(tx, { month: null, split: window, order: null })).toMatchObject({
        spent: 0n,
        split: 100_000n,
      });
      expect(await totalsWeighed(tx, { month: null, split: null, order })).toEqual({
        spent: 0n,
        split: 0n,
        claims: { duplicate: true, possible: false },
      });
      // A lookalike: another form the rail would carry alike.
      expect(
        await totalsWeighed(tx, { month: null, split: null, order: { ...order, reference: 'INV_1' } }),
      ).toMatchObject({ claims: { duplicate: false, possible: true } });
    });
  });

  it('makes no trip when nothing is asked', async () => {
    // A transaction any use of which would fail.
    const none = null as unknown as Parameters<typeof totalsWeighed>[0];

    expect(await totalsWeighed(none, { month: null, split: null, order: null })).toEqual({
      spent: 0n,
      split: 0n,
      claims: { duplicate: false, possible: false },
    });
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

/** Approval above AED 15,000, so two orders within the organisation's cap (AED 20,000 a month) can cross it together. */
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
    const theirKey = await shared.secondAgent(registry, w, SPLIT_TERMS);
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
    // Nothing weighed, so nothing sealed: the first order's AED is on this supplier, and unread.
    const sealed = await database
      .as('admin')
      .query<{ details: string }>(
        "select details from audit.events where org_id = $1 and action = 'spend_request.decided' order by seq",
        [w.org],
      );
    expect(sealed.map(({ details }) => (JSON.parse(details) as Record<string, unknown>).splitOpen)).toEqual([
      '0 AED',
      '0 AED',
    ]);
    // The same order again, for AED 100: within every limit, and still the duplicate.
    expect(decidedOf(await ask(acting, { ...second, amount: AED(10_000n) }))).toMatchObject({
      decision: 'DENY',
      reasons: ['DUPLICATE_ORDER_REFERENCE'],
    });
  });

  it('runs two agents’ orders to one supplier one after the other: the second sees the first’s (forced)', async () => {
    const { w, acting } = await ready({ terms: SPLIT_TERMS });
    const theirKey = await shared.secondAgent(registry, w, SPLIT_TERMS);
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
    expect(first.made).toMatchObject({ decision: 'ALLOW', reasons: [], monthlyCapFrom: 'organization-policy' });
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
    // AED 16,000 held: AED 16,000 more is past the organisation's cap (AED 20,000), as a request would find it.
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
    await withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const zone = { orgId: w.org, agentId: w.agent, zone: 'Pacific/Kiritimati', at: clock.now() };
      await addZone(tx, zone);
      await sealNewZone(tx, states, { ...zone, actor: { type: 'agent', id: w.agent } });
    });
    clock.advanceBy(Date.parse('2026-10-31T12:00:00Z') - clock.now().getTime());

    expect(simulatedOf(await simulated(w, mandateId ?? '')).month).toBe('2026-11');
  });

  it('finds an order already claimed when one is named, however written, and none when none is', async () => {
    const { w, mandateId, acting } = await ready();
    const id = mandateId ?? '';
    decidedOf(await ask(acting, asking(w)));

    const again = simulatedOf(await simulated(w, id, { orderReference: ' inv-1001 ' }));
    expect(again.made.reasons).toContain('DUPLICATE_ORDER_REFERENCE');
    const alike = simulatedOf(await simulated(w, id, { orderReference: 'INV_1001' }));
    expect(alike.made).toMatchObject({ decision: 'REQUIRE_APPROVAL', reasons: ['POSSIBLE_DUPLICATE_ORDER'] });
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

/** The organisation's policy made one with no cap, its event's choice `details`: none chosen, or none recorded (before E2). */
const uncapped = (w: World, details: Readonly<Record<string, string | number>>) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await policyOf(tx, states, { orgId: w.org, id: w.org }, 'change');
    return setPolicy(tx, states, {
      orgId: w.org,
      existing: read.outcome === 'found' ? read : null,
      scope: 'organization',
      mandateId: null,
      versionId: ids.next(),
      rules: { currency: 'AED', perOrderCap: null, monthlyCap: null, approvalThreshold: null, supplierIds: null },
      madeBy: w.admin.membershipId,
      madeAt: clock.now(),
      actor: OPERATOR,
      details,
    });
  });

describe("the organisation's monthly cap, chosen by its admin (E2, decision 15)", () => {
  it("denies every request until an admin chose it, even under a mandate policy's cap, holding nothing", async () => {
    const { w, mandateId, acting } = await ready({ capChosen: false });

    const first = decidedOf(await ask(acting, asking(w)));
    expect(first).toMatchObject({ decision: 'DENY', reasons: ['ORG_MONTHLY_CAP_NOT_SET'], status: 'DENIED' });
    expect((await heldBy(w.org, first.id)).reservation).toBeUndefined();
    await capped(w, 'mandate', mandateId, 2_000_000n);
    expect(decidedOf(await ask(acting, asking(w, { orderReference: 'INV-2' })))).toMatchObject({
      decision: 'DENY',
      reasons: ['ORG_MONTHLY_CAP_NOT_SET'],
    });
  });

  it('simulates proposed organisation rules as chosen, the rules in force as they are: not chosen, denied', async () => {
    const { w, mandateId } = await ready({ capChosen: false });
    const id = mandateId ?? '';

    expect(simulatedOf(await simulated(w, id)).made).toMatchObject({
      decision: 'DENY',
      reasons: ['ORG_MONTHLY_CAP_NOT_SET'],
      monthlyCapFrom: 'not-set',
    });
    const none = simulatedOf(await simulated(w, id, {}, { organizationPolicy: proposed({}) }));
    expect(none.made).toMatchObject({ decision: 'ALLOW', reasons: [], monthlyCapFrom: 'none' });
  });

  it('reads a version with no cap and no choice on its event (made before E2) as not chosen: never the old default', async () => {
    const { w, acting } = await ready();
    await uncapped(w, {});

    expect(decidedOf(await ask(acting, asking(w)))).toMatchObject({
      decision: 'DENY',
      reasons: ['ORG_MONTHLY_CAP_NOT_SET'],
    });
  });

  it("holds the agent to its mandate's own monthly limit alone with none chosen: past AED 20,000, sealed as chosen", async () => {
    const { w, acting } = await ready();
    await uncapped(w, capChoiceDetails('none'));

    // AED 25,000 to each supplier (one supplier's would be a split): AED 50,000 in the month, within the mandate's 100,000.
    for (const [n, supplierId] of w.suppliers.entries()) {
      const order = { amount: AED(2_500_000n), supplierId, orderReference: `INV-${String(n)}` };
      expect(decidedOf(await ask(acting, asking(w, order)))).toMatchObject({ decision: 'ALLOW', reasons: [] });
    }
    const [, request] = await withTenant(app, w.org, (tx) =>
      tx.selectFrom('spend_requests.requests').select('id').orderBy('created_at').orderBy('id').execute(),
    );
    const decided = (await eventsAbout(w.org, request?.id ?? '', 'spend_request')).at(-1);
    expect(decided?.details).toMatchObject({ organizationCapChosen: true, defaultMonthlyCap: null });
  });
});

describe('over the mandate’s own limits: refuse, or an admin’s approval (E9, decision 23)', () => {
  /** A world whose mandate allows half the source's consent per order, its version choosing `overLimit`. */
  async function overLimited(overLimit: 'refuse' | 'approval') {
    const w = await world();
    for (const supplier of w.suppliers) await verified(w, supplier);
    // No organisation cap, so only the mandate's limits and the consent weigh the amounts (the cap stays hard: decide.test.ts).
    await uncapped(w, capChoiceDetails('none'));
    const limits = { perOrderLimit: AED(w.maxPayment / 2n), approvalThreshold: AED(w.maxPayment / 4n) };
    const mandateId = await shared.inForce(registry, w, limits, overLimit);
    return { w, mandateId, acting: await agentKey(w) };
  }

  it('sends one past its per-order limit for approval as its version chose, up to the consent: held, sealed with both', async () => {
    const { w, acting } = await overLimited('approval');

    const atConsent = decidedOf(await ask(acting, asking(w, { amount: AED(w.maxPayment) })));
    expect(atConsent).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'],
      status: 'APPROVAL_REQUIRED',
    });
    expect((await heldBy(w.org, atConsent.id)).reservation).toMatchObject({ state: 'HELD' });
    expect(await waitingNotices(w.org)).toEqual([{ recipient_user_id: null, about_id: atConsent.id }]);
    const decided = (await eventsAbout(w.org, atConsent.id, 'spend_request')).at(-1);
    expect(decided?.details).toMatchObject({ overLimit: 'approval', consentMaxPayment: `${String(w.maxPayment)} AED` });

    // A fils past the bank consent the bank would refuse: a new mandate, holding nothing.
    const past = decidedOf(await ask(acting, asking(w, { amount: AED(w.maxPayment + 1n), orderReference: 'INV-2' })));
    expect(past).toMatchObject({ decision: 'REQUIRE_NEW_MANDATE', status: 'DENIED' });
    expect((await heldBy(w.org, past.id)).reservation).toBeUndefined();
  });

  it('refuses one past its limit as REQUIRE_NEW_MANDATE when its version chose refuse, sealed so', async () => {
    const { w, acting } = await overLimited('refuse');

    const request = decidedOf(await ask(acting, asking(w, { amount: AED(w.maxPayment) })));
    expect(request).toMatchObject({ decision: 'REQUIRE_NEW_MANDATE', status: 'DENIED' });
    expect((await eventsAbout(w.org, request.id, 'spend_request')).at(-1)?.details).toMatchObject({
      overLimit: 'refuse',
    });
  });

  it('weighs a choice made later on the version in force over its drafted one (E9b)', async () => {
    const { w, mandateId, acting } = await overLimited('refuse');
    const moves = createMandateMoves({
      database: app,
      keys,
      ids,
      clock,
      challenges: createStepUpChallenges({ ids, clock }),
      outbox: createOutbox({ ids, clock }),
      logger: testLogger(new LogCapture()),
    });
    const challengeId = askedFor(
      await moves.chooseOverLimit(
        w.admin,
        shared.keyed(w.admin, 'mandates.over-limit'),
        mandateId,
        'approval',
        CORRELATION,
      ),
    );
    await shared.stepUp(w.admin, challengeId);
    const chosen = await moves.chooseOverLimitConfirm(
      w.admin,
      shared.keyed(w.admin, 'mandates.over-limit.confirm'),
      mandateId,
      'approval',
      challengeId,
      CORRELATION,
    );
    expect(chosen.outcome).toBe('moved');

    expect(decidedOf(await ask(acting, asking(w, { amount: AED(w.maxPayment) })))).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      status: 'APPROVAL_REQUIRED',
    });
  });

  it('keeps the choice on the version’s drafted event, with the words confirmed', async () => {
    const { w, mandateId } = await overLimited('approval');
    const view = await registry.show(w.org, mandateId, CORRELATION);
    if (view.outcome !== 'found') throw new Error(`not found: ${view.outcome}`);

    expect(view.current?.overLimit).toBe('approval');
    const drafted = await eventsAbout(w.org, view.current?.version.id ?? '', 'mandate_version');
    expect(drafted.at(0)?.details).toMatchObject({ overLimit: 'approval', overLimitStatementVersion: 1 });
  });

  it('refuses past the limit under a version with no choice on its event (drafted before E9), shown not chosen', async () => {
    const w = await world();
    for (const supplier of w.suppliers) await verified(w, supplier);
    await uncapped(w, capChoiceDetails('none'));
    const [id, versionId] = [ids.next(), ids.next()];
    // As a version drafted before E9: its event keeps no choice, whatever went into its hash.
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      draftMandate(tx, states, {
        orgId: w.org,
        id,
        versionId,
        agentId: w.agent,
        timeZone: 'Asia/Dubai',
        splitWindowHours: 24,
        terms: shared.termsOf(w, { perOrderLimit: AED(w.maxPayment / 2n), approvalThreshold: AED(w.maxPayment / 4n) }),
        overLimit: 'approval',
        draftedBy: w.admin.membershipId,
        draftedAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    await acceptedPastTheUseCase(w, id);
    const acting = await agentKey(w);

    const request = decidedOf(await ask(acting, asking(w, { amount: AED(w.maxPayment) })));
    expect(request).toMatchObject({ decision: 'REQUIRE_NEW_MANDATE', status: 'DENIED' });
    const view = await registry.show(w.org, id, CORRELATION);
    expect(view.outcome === 'found' ? view.current?.overLimit : view.outcome).toBeNull();
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
