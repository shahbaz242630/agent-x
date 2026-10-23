// Phase 3 B4a: rejecting a spend request waiting for approval, on the real
// migrated schema as the app role (PRD §4.2, §7.2; partner decisions 1, 3
// and 6). An approver asks, signs in again with a passkey and confirms, and
// so does an admin: DENIED, recorded as theirs with the step-up's evidence and
// the reason (never in the decision's reason codes), the reservation and
// order claim released at once, the agent's month and the order free again,
// the holdings check still clean, and the team's view shows who, when and
// why. A developer or viewer is FORBIDDEN. Rejected twice, approved,
// cancelled or expired is REQUEST_NOT_WAITING; another organisation's or none
// is NOT_FOUND; one tampered with is INTEGRITY_FAILED. A step-up signed in
// with an app code, asked for another request, another reason or the request
// as it stood before is STEP_UP_FAILED. A frozen organisation still rejects.
// The key answers its own replay. A reject waiting on a cancel or an expiry
// that holds the request (forced) finds it no longer waiting. The agent
// reads its own afterwards (B4c): rejected, and not for one denied by its
// decision; another agent's is NOT_FOUND; one tampered with INTEGRITY_FAILED.
import { withSignedStates } from '@agentx/core/modules/audit';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import {
  cancelRequest,
  checkHoldings,
  denialOf,
  expireRequest,
  NO_PAYMENTS,
  requestOf,
  SPEND_REQUESTS,
  type SpendRequestRecord,
} from '@agentx/core/modules/spend-requests';
import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
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

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, askedFor, keys, type Member, OPERATOR, refused, type World } from './mandate-world.helper.test.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { createSpendRequestReads } from './spend-request-reads.ts';
import {
  createSpendRequestRejects,
  REJECT_CONFIRM_OPERATION,
  REJECT_OPERATION,
  type SpendRequestRejects,
} from './spend-request-rejects.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xb4aa_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000ba';
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const REASON = 'Not needed this month';

let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;
let rejects: SpendRequestRejects;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'request-rejects',
  registry: () => registry,
  decisions: () => decisions,
});
const { quiet, ready, ask, statusOf, holdingsOf, spentOf, member, keyed, stepUp, eventsAbout } = shared;

const asking = (who: Member, requestId: string) =>
  rejects.ask(who, keyed(who, REJECT_OPERATION), requestId, REASON, CORRELATION);

const confirming = (who: Member, requestId: string, challengeId: string, reason = REASON, key?: IdempotentRequest) =>
  rejects.confirm(
    who,
    key ?? keyed(who, REJECT_CONFIRM_OPERATION),
    requestId,
    { reason, stepUpChallengeId: challengeId },
    CORRELATION,
  );

/** Asks, signs in again with `amr` and confirms: the confirm's answer. */
async function rejected(who: Member, requestId: string, amr?: readonly string[]) {
  const challengeId = askedFor(await asking(who, requestId));
  await stepUp(who, challengeId, amr);
  return confirming(who, requestId, challengeId);
}

const requestOfAnswer = (answer: Awaited<ReturnType<SpendRequestRejects['confirm']>>): SpendRequestRecord => {
  if (answer.outcome !== 'rejected') throw new Error(`not rejected: ${JSON.stringify(answer)}`);
  return answer.request;
};

/** The request's events, newest last. */
const eventsOf = (w: World, id: string) => eventsAbout(w.org, id, SPEND_REQUESTS.subject);

const freeze = (w: World) =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
      actor: OPERATOR,
      action: 'organization.freeze',
      details: {},
    }),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date());
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
  rejects = createSpendRequestRejects({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    logger,
  });
});

describe('rejecting a spend request waiting for approval (B4a)', () => {
  it('an approver rejects with a passkey and a reason: DENIED as theirs, its holdings freed at once, the order free again', async () => {
    const { w, acting } = await ready();
    const approver = await member(w.org, 'approver');
    const waiting = await ask(acting, w, { orderReference: 'INV-R1' });
    expect(await spentOf(w, acting)).toBe(200_000n);

    const request = requestOfAnswer(await rejected(approver, waiting.id));
    expect(request).toMatchObject({ id: waiting.id, status: 'DENIED', reasons: ['APPROVAL_THRESHOLD'] });
    expect(await statusOf(w, waiting.id)).toBe('DENIED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
    expect(await spentOf(w, acting)).toBe(0n);
    const last = (await eventsOf(w, waiting.id)).at(-1);
    expect(last).toMatchObject({
      action: 'spend_request.rejected',
      actorType: 'user',
      details: { statusFrom: 'APPROVAL_REQUIRED', statusTo: 'DENIED', reason: REASON, methods: 'pwd user mfa' },
    });
    // The decision's reasons stay the decision's (0039): the reject's reason is in its event alone.
    const again = await ask(acting, w, { orderReference: 'inv-r1' });
    expect(again.reasons).not.toContain('DUPLICATE_ORDER_REFERENCE');
    const holdings = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      checkHoldings(tx, states, keys, w.org, { after: null, limit: 200 }, NO_PAYMENTS),
    );
    expect(holdings).toMatchObject({ mismatched: 0, tampered: 0 });

    const reads = createSpendRequestReads({ database: app, keys, ids, logger: testLogger(new LogCapture()) });
    expect(await reads.show(w.org, waiting.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      rejection: { byUserId: approver.userId, reason: REASON },
    });
    expect(await reads.show(w.org, again.id, CORRELATION)).toMatchObject({ outcome: 'found', rejection: null });
  });

  it('an admin rejects too, and while the organisation is frozen (decision 3)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await freeze(w);

    expect(requestOfAnswer(await rejected(w.admin, waiting.id)).status).toBe('DENIED');
    expect(await holdingsOf(w, waiting.id)).toEqual({ reservation: 'RELEASED', released: true });
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

  it('refuses one rejected already, approved, cancelled or expired as REQUEST_NOT_WAITING', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    await rejected(w.admin, waiting.id);
    const events = (await eventsOf(w, waiting.id)).length;
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    const cancelled = await ask(acting, w);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      cancelRequest(
        tx,
        states,
        keys,
        { orgId: w.org, id: cancelled.id },
        { kind: 'user', userId: w.admin.userId },
        clock.now(),
      ),
    );
    const expired = await ask(acting, w);
    clock.advanceBy(73 * 3_600_000);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      expireRequest(tx, states, keys, { orgId: w.org, id: expired.id }, clock.now()),
    );

    for (const id of [waiting.id, allowed.id, cancelled.id, expired.id]) {
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

  it('never shows a reject whose event was tampered with: its read and its key’s replay refused (FX-TAMPER)', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, waiting.id));
    await stepUp(w.admin, challengeId);
    const key = keyed(w.admin, REJECT_CONFIRM_OPERATION);
    expect(await confirming(w.admin, waiting.id, challengeId, REASON, key)).toMatchObject({ outcome: 'rejected' });
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(waiting.id);
    } finally {
      await owner.end();
    }

    const read = await withSignedStates(app, w.org, quiet(), (tx, states) =>
      denialOf(tx, states, { orgId: w.org, id: waiting.id }),
    );
    expect(read).toEqual({ outcome: 'tampered' });
    expect(await confirming(w.admin, waiting.id, challengeId, REASON, key)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it('refuses a step-up signed in with an app code: STEP_UP_FAILED, nothing moved', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);

    expect(await rejected(w.admin, waiting.id, APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await statusOf(w, waiting.id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses a step-up asked for another request, or for another reason: STEP_UP_FAILED', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, first.id));
    await stepUp(w.admin, challengeId);

    expect(await confirming(w.admin, second.id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await confirming(w.admin, first.id, challengeId, 'Another reason')).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await statusOf(w, first.id)).toBe('APPROVAL_REQUIRED');
    expect(await statusOf(w, second.id)).toBe('APPROVAL_REQUIRED');
  });

  it('answers its key’s replay as before, and the key used for another request as a conflict', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    const second = await ask(acting, w);
    const challengeId = askedFor(await asking(w.admin, first.id));
    await stepUp(w.admin, challengeId);
    const key = keyed(w.admin, REJECT_CONFIRM_OPERATION, 'reject-once');

    const once = await confirming(w.admin, first.id, challengeId, REASON, key);
    expect(once).toMatchObject({ outcome: 'rejected', request: { status: 'DENIED' } });
    expect(await confirming(w.admin, first.id, challengeId, REASON, key)).toEqual(once);
    const other = keyed(w.admin, REJECT_CONFIRM_OPERATION, 'reject-once');
    expect(await confirming(w.admin, second.id, challengeId, REASON, { ...other, payload: second.id })).toEqual({
      outcome: 'conflict',
    });
    expect(await statusOf(w, second.id)).toBe('APPROVAL_REQUIRED');
  });

  it.each(['cancel', 'expiry'] as const)(
    'waits for a %s holding the request, then finds it no longer waiting (forced)',
    async (brake) => {
      const { w, acting } = await ready();
      const waiting = await ask(acting, w);
      const challengeId = askedFor(await asking(w.admin, waiting.id));
      await stepUp(w.admin, challengeId);
      if (brake === 'expiry') clock.advanceBy(73 * 3_600_000);
      const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
      const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
      const key = { orgId: w.org, id: waiting.id };
      const braking = withSignedStates(app, w.org, quiet(), async (tx, states) => {
        const read = await requestOf(tx, states, key, 'change');
        if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
        holding(undefined);
        await gate;
        return brake === 'cancel'
          ? cancelRequest(tx, states, keys, key, { kind: 'user', userId: w.admin.userId }, clock.now())
          : expireRequest(tx, states, keys, key, clock.now());
      });
      await held;
      const racing = within(20_000, confirming(w.admin, waiting.id, challengeId), 'the reject');
      await waitUntilQueued(database.as('admin'), 1);
      open(undefined);

      expect(await braking).toMatchObject({ outcome: 'ended' });
      expect(await racing).toEqual(refused(409, 'REQUEST_NOT_WAITING'));
      expect(await statusOf(w, waiting.id)).toBe(brake === 'cancel' ? 'CANCELLED' : 'EXPIRED');
    },
  );
});

describe('the agent reads its own request after a reject (B4c)', () => {
  const reads = () => createSpendRequestReads({ database: app, keys, ids, logger: testLogger(new LogCapture()) });

  it('learns that a person rejected it, and that one its decision denied was not', async () => {
    const { w, acting } = await ready();
    const waiting = await ask(acting, w);
    const allowed = await ask(acting, w, { amount: AED(50_000n), supplierId: w.suppliers[1] ?? '' });
    const denied = await ask(acting, w, {
      amount: AED(50_000n),
      supplierId: w.suppliers[1] ?? '',
      orderReference: allowed.orderReference,
    });
    await rejected(w.admin, waiting.id);

    expect(await reads().ofAgent(w.org, acting.agentId, waiting.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      request: { id: waiting.id, status: 'DENIED' },
      endedBecause: ['APPROVAL_REJECTED'],
    });
    expect(await reads().ofAgent(w.org, acting.agentId, denied.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      request: { status: 'DENIED' },
      endedBecause: null,
    });
    expect(await reads().ofAgent(w.org, acting.agentId, allowed.id, CORRELATION)).toMatchObject({
      request: { status: 'APPROVED' },
      endedBecause: null,
    });
  });

  it('answers another agent’s, and none, as NOT_FOUND; one tampered with as INTEGRITY_FAILED', async () => {
    const { w, acting } = await ready();
    const other = await shared.secondAgent(registry, w, { approvalThreshold: AED(100_000n) });
    const theirs = await ask(other, w);
    const mine = await ask(acting, w);
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(mine.id);
    } finally {
      await owner.end();
    }

    expect(await reads().ofAgent(w.org, acting.agentId, theirs.id, CORRELATION)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await reads().ofAgent(w.org, acting.agentId, ids.next(), CORRELATION)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await reads().ofAgent(w.org, acting.agentId, mine.id, CORRELATION)).toEqual(
      refused(503, 'INTEGRITY_FAILED'),
    );
  });
});
