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
// on changed since (the mandate superseded or suspended, the supplier's
// details or status, the source, the agent, its key revoked) is
// REQUEST_CHANGED (SEC-LIM-10), while routine changes (a looser policy, its
// key rotated out) leave it approvable; a policy tightened past it is shown
// at the ask as rejected, with what to do, and the confirm rejects it, its
// holdings released (decision 18, E5b), unless a stop refuses it too; past its 72 hours REQUEST_EXPIRED, and then
// expired, its holdings released (SEC-LIM-12); a frozen organisation
// ORG_FROZEN (decision 3), one unfrozen past the app INTEGRITY_FAILED and held
// (SEC-DB-08). A developer or viewer is FORBIDDEN, and a role
// raised past the app INTEGRITY_FAILED (SEC-DB-06). Approved twice, rejected
// or cancelled is REQUEST_NOT_WAITING; another organisation's or none is
// NOT_FOUND; a request tampered with, or holdings changed past the app,
// INTEGRITY_FAILED. A step-up signed in with an app code, or asked for
// another request or for a reject, is STEP_UP_FAILED. The key answers its own
// replay. Forced: an approval waiting on a cancel or an expiry holding the
// request finds it no longer waiting, and one waiting on a mandate's revoke
// finds it changed (revoke-during-approval).
import { AGENT_KEYS, agentKeyOf, bringKeyExpiryForward } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import {
  acceptDraft,
  MANDATES,
  mandateOf as mandateRead,
  policyOf,
  type PolicyRules,
  setPolicy,
} from '@agentx/core/modules/mandates';
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
import { capChoiceDetails } from './monthly-cap-choice.ts';
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
const { ready, ask, statusOf, holdingsOf, spentOf, member, keyed, stepUp, eventsAbout } = shared;

const asking = (who: Member, requestId: string) =>
  approvals.ask(who, keyed(who, APPROVE_OPERATION), requestId, false, CORRELATION);

const confirming = (who: Member, requestId: string, challengeId: string, key?: IdempotentRequest) =>
  approvals.confirm(who, key ?? keyed(who, APPROVE_CONFIRM_OPERATION), requestId, challengeId, false, CORRELATION);

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

const { signed } = shared;

const freeze = (w: World) =>
  signed(w, (tx, states) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
      actor: OPERATOR,
      action: 'organization.freeze',
      details: {},
    }),
  );

/**
 * A policy's new version, the organisation's (set already, as the world chose
 * its cap, E2) or the mandate's, set past the use case: a monthly cap of `cap`
 * minor units.
 */
const policySet = (w: World, mandateId: string | null, cap: bigint) => {
  const rules: PolicyRules = {
    currency: 'AED',
    perOrderCap: null,
    monthlyCap: AED(cap),
    approvalThreshold: null,
    supplierIds: null,
  };
  return signed(w, async (tx, states) => {
    const read = await policyOf(tx, states, { orgId: w.org, id: mandateId ?? w.org }, 'change');
    return setPolicy(tx, states, {
      orgId: w.org,
      existing: read.outcome === 'found' ? read : null,
      scope: mandateId === null ? 'organization' : 'mandate',
      mandateId,
      versionId: ids.next(),
      rules,
      madeBy: w.admin.membershipId,
      madeAt: clock.now(),
      actor: OPERATOR,
      details: mandateId === null ? capChoiceDetails('amount') : {},
    });
  });
};

/** Each policy tightened past a request since it was decided: AED 1,000 a month, below the AED 2,000 it asks. */
const TIGHTENED = {
  'the organisation’s policy': (w: World) => policySet(w, null, 100_000n),
  'the mandate’s policy': (w: World, mandateId: string) => policySet(w, mandateId, 100_000n),
} as const;

/** Each change since a request was decided that makes it another's to approve (SEC-LIM-10). */
const CHANGES = {
  ...shared.STOPS,
  'the key it asked with revoked': (w: World, _mandateId: string, keyId: string) =>
    signed(w, (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    ),
} as const;

const { mandateIdOf: mandateOf } = shared;

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
        // The policies it was weighed under: the organisation's, its cap chosen (E2), and no mandate's.
        organizationPolicyVersionId: expect.any(String) as unknown,
        mandatePolicyVersionId: null,
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
      endedBecause: null,
    });
  });

  it('an admin approves too', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    expect(requestOfAnswer(await approved(w.admin, waiting.id)).status).toBe('APPROVED');
  });

  it('only an admin approves one sent for approval past its mandate’s own limit (decision 23); an approver is refused', async () => {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await policySet(w, null, w.maxPayment * 4n);
    const limits = { perOrderLimit: AED(w.maxPayment / 2n), approvalThreshold: AED(w.maxPayment / 4n) };
    await shared.inForce(registry, w, limits, 'approval');
    const acting = await shared.agentKey(w);
    const waiting = await ask(acting, w, { amount: AED(w.maxPayment) });
    expect(waiting.status).toBe('APPROVAL_REQUIRED');

    expect(await asking(await member(w.org, 'approver'), waiting.id)).toEqual(refused(403, 'ADMIN_APPROVAL_ONLY'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
    expect(requestOfAnswer(await approved(w.admin, waiting.id)).status).toBe('APPROVED');
  });

  it('counts the request once: one over half the monthly cap is approved (its own reservation and claim left out)', async () => {
    const { w, acting } = await ready();
    // AED 12,000 of the organisation's AED 20,000 cap: counted twice it would be past it.
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

  it.each(Object.keys(TIGHTENED) as (keyof typeof TIGHTENED)[])(
    '%s tightened past it: shown as rejected with what to do; the confirm rejects it, its holdings released (decision 18, E5b)',
    async (which) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w, { orderReference: 'INV-R1' });
      const earlier = askedFor(await asking(w.admin, waiting.id));
      await stepUp(w.admin, earlier);
      await TIGHTENED[which](w, await mandateOf(w));

      // The step-up asked before bound an approval: confirming it now is another change.
      expect(await confirming(w.admin, waiting.id, earlier)).toEqual(refused(403, 'STEP_UP_FAILED'));
      const asked = await asking(w.admin, waiting.id);
      expect(asked).toMatchObject({ outcome: 'asked', recheck: null, rejection: ['POLICY_MONTHLY_CAP'] });
      const challengeId = askedFor(asked);
      await stepUp(w.admin, challengeId);
      const answer = await confirming(w.admin, waiting.id, challengeId);
      expect(answer).toMatchObject({ outcome: 'rejected', request: { id: waiting.id, status: 'DENIED' } });

      expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
      expect(await spentOf(w, acting)).toBe(0n);
      expect((await eventsOf(w, waiting.id)).at(-1)).toMatchObject({
        action: 'spend_request.rejected',
        actorType: 'user',
        details: {
          stepUpChallengeId: challengeId,
          causes: 'POLICY_MONTHLY_CAP',
          reason:
            'Rejected on approval: today’s check denies it under your team’s rules (POLICY_MONTHLY_CAP). Change them in settings, then the agent asks again.',
        },
      });
      // Its order is no longer claimed, and the agent learns only that a person rejected it (decision 6).
      expect((await ask(acting, w, { amount: AED(50_000n), orderReference: 'INV-R1' })).reasons).not.toContain(
        'DUPLICATE_ORDER_REFERENCE',
      );
      const reads = createSpendRequestReads({ database: app, keys, ids, logger: testLogger(new LogCapture()) });
      expect(await reads.ofAgent(w.org, acting.agentId, waiting.id, CORRELATION)).toMatchObject({
        request: { status: 'DENIED' },
        endedBecause: ['APPROVAL_REJECTED'],
      });
    },
  );

  it('a policy tightened past it and a stop as well: REQUEST_CHANGED, still waiting (a stop is never a rejection)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await policySet(w, null, 100_000n);
    await shared.STOPS['the agent suspended'](w);

    expect(await asking(w.admin, waiting.id)).toEqual(refused(409, 'REQUEST_CHANGED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it.each([null, 'mandate'] as const)(
    'approves it under a looser policy set since (%s scope; the organisation’s if null): weighed as it now is',
    async (scope) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      // AED 50,000 a month, past the mandate's own cap.
      await policySet(w, scope === null ? null : await mandateOf(w), 5_000_000n);

      expect(requestOfAnswer(await approved(w.admin, waiting.id)).status).toBe('APPROVED');
      // The approval keeps the version it was weighed under, newer than its decision's (none).
      const details = (await eventsOf(w, waiting.id)).at(-1)?.details;
      const weighed = scope === null ? details?.organizationPolicyVersionId : details?.mandatePolicyVersionId;
      expect(weighed).toMatch(/^[0-9a-f-]{36}$/);
    },
  );

  it('approves it once the key it asked with is rotated out (expired, not revoked)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    // What a rotation's overlap ending leaves: the old key ACTIVE, its expiry passed.
    await signed(w, async (tx, states) => {
      const found = await agentKeyOf(tx, states, { orgId: w.org, id: acting.keyId }, 'change');
      if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
      await bringKeyExpiryForward(tx, states, {
        orgId: w.org,
        key: found.key,
        state: found.state,
        // A key expires after it was made (0027's check): a minute on, then the clock past it.
        expiresAt: new Date(clock.now().getTime() + 60_000),
        actor: OPERATOR,
        action: 'agent_key.rotated',
        details: {},
      });
    });
    clock.advanceBy(2 * 60_000);

    expect(requestOfAnswer(await approved(w.admin, waiting.id)).status).toBe('APPROVED');
  });

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

  it('refuses one past the 24 hours its organisation chose when it was asked, one asked before keeping 72 (E6)', async () => {
    const { w, acting } = await ready();
    const before = await ask(acting, w);
    await shared.waitChosen(w, 24);
    const after = await ask(acting, w);
    clock.advanceBy(24 * HOUR_MS + 60_000);

    expect(await asking(w.admin, after.id)).toEqual(refused(409, 'REQUEST_EXPIRED'));
    expect(await statusOf(w, after.id)).toBe('EXPIRED');
    // Signed in now: the admin's session has long been idle.
    expect(requestOfAnswer(await approved(await member(w.org, 'approver'), before.id)).status).toBe('APPROVED');
  });

  it('runs its 72 hours from its decision, not a later event of its own: past it by its decision, refused (E4b)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    // Sealed times are the database's own, so the later event comes a moment later, not hours.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const later = await signed(w, async (tx, states) => {
      const read = await requestOf(tx, states, { orgId: w.org, id: waiting.id }, 'change');
      if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
      // A signed change that moves nothing, as E4's carry is a later event on a request still waiting.
      await states.record(
        tx,
        SPEND_REQUESTS,
        { orgId: w.org, id: waiting.id },
        read.state,
        {},
        {
          actor: OPERATOR,
          action: 'spend_request.signed_again',
          details: {},
        },
      );
      const after = await requestOf(tx, states, { orgId: w.org, id: waiting.id });
      if (after.outcome !== 'found') throw new Error(`not found: ${after.outcome}`);
      return after.state.recordedAt.getTime();
    });
    // 72 hours past its decision, not yet past the later event's.
    clock.advanceBy(later + 72 * HOUR_MS - 1 - clock.now().getTime());

    expect(await asking(await member(w.org, 'approver'), waiting.id)).toEqual(refused(409, 'REQUEST_EXPIRED'));
    expect(await statusOf(w, waiting.id)).toBe('EXPIRED');
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

  it('refuses it on an organisation unfrozen past the app as INTEGRITY_FAILED, its hold set (SEC-DB-08, D1)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await freeze(w);
    await database
      .as('admin')
      .query(`update organizations.organizations set status = 'ACTIVE' where org_id = $1`, [w.org]);

    expect(await asking(w.admin, waiting.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    const hold = await signed(w, (tx, states) => states.holdRecord(tx, w.org));
    expect(hold).toMatchObject({ outcome: 'held' });
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

  it('refuses one whose agent key was tampered with as INTEGRITY_FAILED, not as changed (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const owner = await tamperAsOwner(database, AGENT_KEYS, w.org);
    try {
      await owner.stripSeals(acting.keyId);
    } finally {
      await owner.end();
    }

    expect(await asking(w.admin, waiting.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
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

  it('waits for a new version accepted holding its mandate, then finds it changed (supersede-during-approval)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const mandateId = await mandateOf(w);
    const redrafted = await registry.redraft(
      w.admin,
      shared.keyed(w.admin, REDRAFT_OPERATION),
      mandateId,
      { terms: shared.termsOf(w, { purpose: 'Office supplies, renewed' }), overLimit: 'refuse' },
      CORRELATION,
    );
    expect(redrafted.outcome).toBe('drafted');
    const { racing } = await whileHeld(w, waiting.id, async (tx, states, gate) => {
      const read = await mandateRead(tx, states, { orgId: w.org, id: mandateId }, 'change');
      if (read.outcome !== 'found' || read.mandate.pendingVersionId === null) throw new Error('no draft waiting');
      await gate();
      await acceptDraft(tx, states, read, {
        orgId: w.org,
        versionId: read.mandate.pendingVersionId,
        acceptedBy: w.admin.membershipId,
        acceptedAt: clock.now(),
        actor: OPERATOR,
        details: {},
      });
    });

    expect(racing).toEqual(refused(409, 'REQUEST_CHANGED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });
});
