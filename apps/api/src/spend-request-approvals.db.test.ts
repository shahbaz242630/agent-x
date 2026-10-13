// Phase 3 B4b: approving a spend request waiting for approval, on the real
// migrated schema as the app role (PRD §4.2, §7.2; partner decisions 1 and
// 3). An approver asks, signs in again with a passkey and confirms, and so
// does an admin: APPROVED, recorded as theirs with the step-up's evidence
// (SEC-EVD-05), its reservation and order claim kept, the agent's month
// counting it once, the holdings check still clean, and the agent reads it
// approved. Weighed again, it is counted once (a request over half the
// monthly cap is approved, its own order no duplicate of itself), in the
// month its capacity is held in (one decided before midnight on the 31st is
// approved after it, the new month's spending aside). Anything it was decided
// on changed since (a policy, the mandate superseded or suspended, the
// supplier's details or status, the source, the agent, its key) is
// REQUEST_CHANGED (SEC-LIM-10); past its 72 hours REQUEST_EXPIRED, and then
// expired, its holdings released (SEC-LIM-12); a frozen organisation
// ORG_FROZEN (decision 3). A developer or viewer is FORBIDDEN, and a role
// raised past the app INTEGRITY_FAILED (SEC-DB-06). Approved twice, rejected
// or cancelled is REQUEST_NOT_WAITING; another organisation's or none is
// NOT_FOUND; a request tampered with, or holdings changed past the app,
// INTEGRITY_FAILED. A step-up signed in with an app code, or asked for
// another request or for a reject, is STEP_UP_FAILED. The key answers its own
// replay. Forced: an approval waiting on a cancel or an expiry holding the
// request finds it no longer waiting, and one waiting on a mandate's revoke
// finds it changed (revoke-during-approval).
import { AGENT_KEYS, AGENTS } from '@agentx/core/modules/agents';
import { type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { MANDATES, type PolicyRules, setPolicy } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import {
  cancelRequest,
  checkHoldings,
  expireRequest,
  requestOf,
  SPEND_REQUESTS,
  type SpendRequestRecord,
} from '@agentx/core/modules/spend-requests';
import {
  changeDetails,
  nextVersionNumber,
  supplierOf,
  suspendSupplier,
  versionOf,
} from '@agentx/core/modules/suppliers';
import { HOUR_MS } from '@agentx/core/shared-kernel';
import {
  createDatabase,
  type Database,
  type DatabaseTransaction,
  type IdempotentRequest,
  withTenant,
} from '@agentx/platform/db';
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

import { createMandateRegistry, type MandateRegistry, REDRAFT_OPERATION } from './mandate-registry.ts';
import { AED, askedFor, keys, type Member, OPERATOR, refused, type World } from './mandate-world.helper.test.ts';
import {
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  createSpendRequestApprovals,
  type SpendRequestApprovals,
} from './spend-request-approvals.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { createSpendRequestReads } from './spend-request-reads.ts';
import { createSpendRequestRejects, REJECT_OPERATION } from './spend-request-rejects.ts';
import { changedPastTheApp, spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xb4bb_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000bb';
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let approvals: SpendRequestApprovals;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'request-approvals',
  registry: () => registry,
  decisions: () => decisions,
});
const { quiet, ready, ask, statusOf, holdingsOf, spentOf, member, keyed, stepUp, eventsAbout } = shared;

const asking = (who: Member, requestId: string) =>
  approvals.ask(who, keyed(who, APPROVE_OPERATION), requestId, CORRELATION);

const confirming = (who: Member, requestId: string, challengeId: string, key?: IdempotentRequest) =>
  approvals.confirm(who, key ?? keyed(who, APPROVE_CONFIRM_OPERATION), requestId, challengeId, CORRELATION);

/** Asks, signs in again with `amr` and confirms: the confirm's answer. */
async function approved(who: Member, requestId: string, amr?: readonly string[]) {
  const challengeId = askedFor(await asking(who, requestId));
  await stepUp(who, challengeId, amr);
  return confirming(who, requestId, challengeId);
}

const requestOfAnswer = (answer: Awaited<ReturnType<SpendRequestApprovals['confirm']>>): SpendRequestRecord => {
  if (answer.outcome !== 'approved') throw new Error(`not approved: ${JSON.stringify(answer)}`);
  return answer.request;
};

/** The request's events, newest last. */
const eventsOf = (w: World, id: string) => eventsAbout(w.org, id, SPEND_REQUESTS.subject);

type Signing = (tx: DatabaseTransaction<SpendWorldTables>, states: SignedStates) => Promise<unknown>;

/** A change past the use cases, signed, as each brake or edit would make it, in the organisation's transaction. */
const signed = <T>(w: World, change: (...args: Parameters<Signing>) => Promise<T>) =>
  withSignedStates(app, w.org, quiet(), change);

const freeze = (w: World) =>
  signed(w, (tx, states) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
      actor: OPERATOR,
      action: 'organization.freeze',
      details: {},
    }),
  );

/** The organisation's first policy, set past the use case: a monthly cap of AED 50,000, looser than the default. */
const policySet = (w: World) => {
  const rules: PolicyRules = {
    currency: 'AED',
    perOrderCap: null,
    monthlyCap: AED(5_000_000n),
    approvalThreshold: null,
    supplierIds: null,
  };
  return signed(w, (tx, states) =>
    setPolicy(tx, states, {
      orgId: w.org,
      existing: null,
      scope: 'organization',
      mandateId: null,
      versionId: ids.next(),
      rules,
      madeBy: w.admin.membershipId,
      madeAt: clock.now(),
      actor: OPERATOR,
      details: {},
    }),
  );
};

/** The supplier's details changed (a new version), then verified again: only its version differs. */
async function detailsChanged(w: World, supplierId: string) {
  await signed(w, async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId: w.org, id: supplierId }, 'change');
    if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
    const current = await versionOf(tx, states, { orgId: w.org, id: found.supplier.currentVersionId }, supplierId);
    if (current.outcome !== 'found') throw new Error(`no version: ${current.outcome}`);
    await changeDetails(tx, states, keys, { orgId: w.org, id: supplierId }, found, {
      orgId: w.org,
      id: ids.next(),
      supplierId,
      version: await nextVersionNumber(tx, w.org, supplierId),
      supplier: {
        displayName: 'Gulf Office Supplies Trading LLC',
        contacts: { phone: '+971501234567', email: null, tradeLicence: null },
        source: { kind: 'registry', ref: 'DED-123456' },
      },
      enteredBy: ids.next(),
      enteredAt: clock.now(),
      actor: OPERATOR,
      follows: current.version,
    });
  });
  await shared.verified(w, supplierId);
}

/** Each change since a request was decided that makes it another's to approve (SEC-LIM-10). */
const CHANGES = {
  'a policy set': (w: World) => policySet(w),
  'the mandate superseded': async (w: World, mandateId: string) => {
    const redrafted = await registry.redraft(
      w.admin,
      keyed(w.admin, REDRAFT_OPERATION),
      mandateId,
      shared.termsOf(w, { purpose: 'Office supplies, renewed', approvalThreshold: AED(100_000n) }),
      CORRELATION,
    );
    expect(redrafted.outcome).toBe('drafted');
    await shared.acceptedPastTheUseCase(w, mandateId);
  },
  'the mandate suspended': (w: World, mandateId: string) => shared.movedPastTheUseCase(w, mandateId, 'suspend'),
  'the supplier’s details changed': (w: World) => detailsChanged(w, w.suppliers[0] ?? ''),
  'the supplier suspended': (w: World) =>
    signed(w, async (tx, states) => {
      const key = { orgId: w.org, id: w.suppliers[0] ?? '' };
      const found = await supplierOf(tx, states, key, 'change');
      if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
      await suspendSupplier(tx, states, key, found, { actor: OPERATOR });
    }),
  'the source suspended by the partner': (w: World) => shared.partnerSays(w, { availability: 'SUSPENDED' }),
  'the agent suspended': (w: World) =>
    signed(w, (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspended',
        details: {},
      }),
    ),
  'the key it asked with revoked': (w: World, _mandateId: string, keyId: string) =>
    signed(w, (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    ),
} as const;

/** The agent's mandate in force: the world's only one. */
const mandateOf = (w: World) =>
  withTenant(app, w.org, async (tx) => {
    const { id } = await tx.selectFrom('mandates.mandates').select('id').executeTakeFirstOrThrow();
    return id;
  });

/** The months the agent's reservations sit in, oldest first. */
const monthsOf = (w: World) =>
  withTenant(app, w.org, async (tx) =>
    (await tx.selectFrom('limit_reservations.reservations').select('month').orderBy('reserved_at').execute()).map(
      ({ month }) => month,
    ),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** The use cases on a clock started at `start`. */
function startedAt(start: Date) {
  clock = new FixedClock(start);
  const logger = testLogger(new LogCapture());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger,
  });
  approvals = createSpendRequestApprovals({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    logger,
  });
}

beforeEach(() => {
  startedAt(new Date());
});

describe('approving a spend request waiting for approval (B4b)', () => {
  it('an approver approves with a passkey: APPROVED as theirs with the step-up’s evidence, its holdings kept and counted once', async () => {
    const { w, acting } = await ready();
    const approver = await member(w.org, 'approver');
    const waiting = await ask(acting, w, { orderReference: 'INV-A1' });

    const challengeId = askedFor(await asking(approver, waiting.id));
    await stepUp(approver, challengeId);
    const request = requestOfAnswer(await confirming(approver, waiting.id, challengeId));
    expect(request).toMatchObject({ id: waiting.id, status: 'APPROVED', reasons: ['APPROVAL_THRESHOLD'] });
    expect(await statusOf(w, waiting.id)).toBe('APPROVED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'HELD', released: false });
    expect(await spentOf(w, acting)).toBe(200_000n);
    // SEC-EVD-05: the challenge, when and how they signed in, the change's hash, and the proof's.
    const last = (await eventsOf(w, waiting.id)).at(-1);
    expect(last).toMatchObject({
      action: 'spend_request.approved',
      actorType: 'user',
      details: {
        statusFrom: 'APPROVAL_REQUIRED',
        statusTo: 'APPROVED',
        stepUpChallengeId: challengeId,
        signedInAt: clock.now().toISOString(),
        methods: 'pwd user mfa',
      },
    });
    expect(last?.details.changeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(last?.details.proofHash).toMatch(/^[0-9a-f]{64}$/);
    // Its order is still claimed: the same again is a duplicate.
    const again = await ask(acting, w, { orderReference: 'inv-a1' });
    expect(again.reasons).toContain('DUPLICATE_ORDER_REFERENCE');
    const holdings = await signed(w, (tx, states) =>
      checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }),
    );
    expect(holdings).toMatchObject({ mismatched: 0, tampered: 0 });

    const reads = createSpendRequestReads({ database: app, keys, ids, logger: testLogger(new LogCapture()) });
    expect(await reads.ofAgent(w.org, acting.agentId, waiting.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      request: { status: 'APPROVED' },
      rejected: false,
    });
  });

  it('an admin approves too', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    expect(requestOfAnswer(await approved(w.admin, waiting.id)).status).toBe('APPROVED');
  });

  it('counts the request once: one over half the monthly cap is approved (its own reservation and claim left out)', async () => {
    const { w, acting } = await ready();
    // AED 12,000 of the default AED 20,000 cap: counted twice it would be past it.
    const waiting = await ask(acting, w, { amount: AED(1_200_000n) });
    expect(waiting.status).toBe('APPROVAL_REQUIRED');

    expect(requestOfAnswer(await approved(w.admin, waiting.id)).status).toBe('APPROVED');
    expect(await spentOf(w, acting)).toBe(1_200_000n);
  });

  it('weighs it in the month its capacity is held in: decided before midnight on the 31st, approved after', async () => {
    // 22:00 in Dubai (UTC+4) on last month's last day, so the agent's month turns two hours later. Before the
    // database's own time: the 72 hours run from the decision's sealed time, which is that.
    const now = new Date();
    startedAt(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1) - 6 * HOUR_MS));
    const { w, acting } = await ready();
    const waiting = await ask(acting, w, { amount: AED(1_200_000n) });
    clock.advanceBy(3 * HOUR_MS);
    // AED 12,000 asked in the new month, to the other supplier: 24,000 there with the waiting one, past the cap.
    const later = await ask(acting, w, { amount: AED(1_200_000n), supplierId: w.suppliers[1] ?? '' });
    expect(later.status).toBe('APPROVAL_REQUIRED');
    const [held, now2] = await monthsOf(w);
    expect(now2).not.toBe(held);

    expect(requestOfAnswer(await approved(w.admin, waiting.id)).status).toBe('APPROVED');
    expect(requestOfAnswer(await approved(w.admin, later.id)).status).toBe('APPROVED');
  });

  it.each(Object.keys(CHANGES) as (keyof typeof CHANGES)[])(
    'refuses it once %s: REQUEST_CHANGED, its ask and its confirm, nothing changed (SEC-LIM-10)',
    async (what) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      const challengeId = askedFor(await asking(w.admin, waiting.id));
      await stepUp(w.admin, challengeId);
      await CHANGES[what](w, await mandateOf(w), acting.keyId);

      expect(await confirming(w.admin, waiting.id, challengeId)).toEqual(refused(409, 'REQUEST_CHANGED'));
      expect(await asking(w.admin, waiting.id)).toEqual(refused(409, 'REQUEST_CHANGED'));
      expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
      expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'HELD', released: false });
    },
  );

  it('refuses one past its 72 hours as REQUEST_EXPIRED, then expires it, its holdings released (SEC-LIM-12)', async () => {
    const { w, acting } = await ready();
    // Their decisions' sealed times are the database's: each made now, as the clock starts.
    const inTime = await ask(acting, w);
    const waiting = await ask(acting, w);
    const asked = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, waiting.id));
    await stepUp(w.admin, challengeId);
    clock.advanceBy(71 * HOUR_MS);
    // Signed in now: the admin's session has long been idle.
    expect(requestOfAnswer(await approved(await member(w.org, 'approver'), inTime.id)).status).toBe('APPROVED');
    clock.advanceBy(2 * HOUR_MS);

    expect(await confirming(w.admin, waiting.id, challengeId)).toEqual(refused(409, 'REQUEST_EXPIRED'));
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
    expect(await asking(w.admin, waiting.id)).toEqual(refused(409, 'REQUEST_NOT_WAITING'));
    expect(await asking(w.admin, asked.id)).toEqual(refused(409, 'REQUEST_EXPIRED'));
    expect(await statusOf(w, asked.id)).toBe('EXPIRED');
    expect(await holdingsOf(w, asked.id)).toEqual({ reservation: 'RELEASED', released: true });
  });

  it('refuses it while the organisation is frozen: ORG_FROZEN, nothing changed (decision 3)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, waiting.id));
    await stepUp(w.admin, challengeId);
    await freeze(w);

    expect(await confirming(w.admin, waiting.id, challengeId)).toEqual(refused(409, 'ORG_FROZEN'));
    expect(await asking(w.admin, waiting.id)).toEqual(refused(409, 'ORG_FROZEN'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it.each(['developer', 'viewer'] as const)('refuses a %s, and changes nothing', async (role) => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const who = await member(w.org, role);

    expect(await asking(who, waiting.id)).toEqual(refused(403, 'FORBIDDEN'));
    const challengeId = askedFor(await asking(w.admin, waiting.id));
    await stepUp(w.admin, challengeId);
    expect(await confirming(who, waiting.id, challengeId)).toEqual(refused(403, 'FORBIDDEN'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses a role raised to approver past the app as INTEGRITY_FAILED (SEC-DB-06)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const viewer = await member(w.org, 'viewer');
    await database
      .as('admin')
      .query(`update identity.memberships set role = 'approver' where org_id = $1 and id = $2`, [
        w.org,
        viewer.membershipId,
      ]);

    expect(await asking(viewer, waiting.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses one approved already, rejected or cancelled as REQUEST_NOT_WAITING', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await approved(w.admin, waiting.id);
    const events = (await eventsOf(w, waiting.id)).length;
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    const cancelled = await ask(acting, w);
    await signed(w, (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: cancelled.id },
        { kind: 'user', userId: w.admin.userId },
        clock.now(),
      ),
    );

    for (const id of [waiting.id, allowed.id, cancelled.id]) {
      expect(await asking(w.admin, id)).toEqual(refused(409, 'REQUEST_NOT_WAITING'));
    }
    expect(await eventsOf(w, waiting.id)).toHaveLength(events);
  });

  it('refuses another organisation’s request and none as NOT_FOUND', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const other = await ready();

    expect(await asking(other.w.admin, waiting.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await asking(w.admin, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses one tampered with past the app as INTEGRITY_FAILED, and changes nothing (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, waiting.id));
    await stepUp(w.admin, challengeId);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(waiting.id);
    } finally {
      await owner.end();
    }

    expect(await confirming(w.admin, waiting.id, challengeId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'HELD', released: false });
  });

  it('refuses one whose reservation was changed past the app as INTEGRITY_FAILED, nothing moved', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, waiting.id));
    await stepUp(w.admin, challengeId);
    await changedPastTheApp(database, w.org, waiting.id, 'amount halved');

    expect(await confirming(w.admin, waiting.id, challengeId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses a step-up signed in with an app code: STEP_UP_FAILED, nothing moved', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    expect(await approved(w.admin, waiting.id, APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses a step-up asked for another request, or for a reject: STEP_UP_FAILED', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, first.id));
    await stepUp(w.admin, challengeId);
    const rejects = createSpendRequestRejects({
      database: app,
      keys,
      ids,
      clock,
      challenges: createStepUpChallenges({ ids, clock }),
      logger: testLogger(),
    });
    const forReject = askedFor(
      await rejects.ask(w.admin, keyed(w.admin, REJECT_OPERATION), first.id, 'No', CORRELATION),
    );
    await stepUp(w.admin, forReject);

    expect(await confirming(w.admin, second.id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await confirming(w.admin, first.id, forReject)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await statusOf(w, first.id)).toBe('APPROVAL_REQUIRED');
    expect(await statusOf(w, second.id)).toBe('APPROVAL_REQUIRED');
  });

  it('answers its key’s replay as before, and the key used for another request as a conflict', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, first.id));
    await stepUp(w.admin, challengeId);
    const key = keyed(w.admin, APPROVE_CONFIRM_OPERATION, 'approve-once');

    const once = await confirming(w.admin, first.id, challengeId, key);
    expect(once).toMatchObject({ outcome: 'approved', request: { status: 'APPROVED' } });
    expect(await confirming(w.admin, first.id, challengeId, key)).toEqual(once);
    const other = keyed(w.admin, APPROVE_CONFIRM_OPERATION, 'approve-once');
    expect(await confirming(w.admin, second.id, challengeId, { ...other, payload: second.id })).toEqual({
      outcome: 'conflict',
    });
    expect(await statusOf(w, second.id)).toBe('APPROVAL_REQUIRED');
  });
});

describe('approving while a brake holds the request or its mandate (forced)', () => {
  /** The confirm, made while `brake`'s transaction holds its lock, queued behind it, then let go: both answers. */
  async function whileHeld(
    w: World,
    requestId: string,
    brake: (...args: [...Parameters<Signing>, gate: () => Promise<void>]) => Promise<unknown>,
  ) {
    const challengeId = askedFor(await asking(w.admin, requestId));
    await stepUp(w.admin, challengeId);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const braking = signed(w, (tx, states) =>
      brake(tx, states, async () => {
        holding(undefined);
        await gate;
      }),
    );
    await held;
    const racing = within(20_000, confirming(w.admin, requestId, challengeId), 'the approval');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    return { braking: await braking, racing: await racing };
  }

  it.each(['cancel', 'expiry'] as const)(
    'waits for a %s holding the request, then finds it no longer waiting',
    async (kind) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      const key = { orgId: w.org, id: waiting.id };
      // The job's clock 73 hours on, the approval's not: what it finds is the move, not the time.
      const { braking, racing } = await whileHeld(w, waiting.id, async (tx, states, gate) => {
        const read = await requestOf(tx, states, key, 'change');
        if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
        await gate();
        return kind === 'cancel'
          ? cancelRequest(tx, states, keys, key, { kind: 'user', userId: w.admin.userId }, clock.now())
          : expireRequest(tx, states, keys, key, new Date(clock.now().getTime() + 73 * HOUR_MS));
      });

      expect(braking).toMatchObject({ outcome: 'ended' });
      expect(racing).toEqual(refused(409, 'REQUEST_NOT_WAITING'));
      expect(await statusOf(w, waiting.id)).toBe(kind === 'cancel' ? 'CANCELLED' : 'EXPIRED');
    },
  );

  it('waits for a revoke holding its mandate, then finds it changed (revoke-during-approval)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const mandateId = await mandateOf(w);
    const { racing } = await whileHeld(w, waiting.id, async (tx, states, gate) => {
      await states.verifiedState(tx, MANDATES, { orgId: w.org, id: mandateId }, 'change');
      await gate();
      return states.changeStatus(tx, MANDATES, { orgId: w.org, id: mandateId }, 'revoke', {
        actor: OPERATOR,
        action: 'mandate.revoke',
        details: {},
      });
    });

    expect(racing).toEqual(refused(409, 'REQUEST_CHANGED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });
});
