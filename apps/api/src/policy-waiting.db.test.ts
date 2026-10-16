// Phase 3 E5d-a: the requests waiting for approval a policy change would
// reject (partner decision 19, S117; S118's answers), on the real migrated
// schema as the app role, through the preview an admin asks before choosing.
// Listed, oldest first, with the team's rules that would refuse each: a
// lowered monthly cap rejects the younger ones once the oldest stand; a
// lowered per-order cap, the organisation's or a mandate's (that mandate's
// requests alone); each agent against its own month, oldest first across
// them. Not listed: one the rules in force refuse already, each weighed as
// its approver's confirm weighs it; one with a stop (a suspended agent), one
// asked with a revoked key, one past its 72 hours, one decided under a
// mandate version or supplier details no longer in force, one the rules
// still allow. One that can't go is counted against the older ones. At most 20, `more` saying there are
// others; past 100 waiting, the oldest 100 weighed, the younger holding theirs. It writes nothing; a member not an admin is refused; a request
// tampered with refuses it, its alarm raised.
import { AGENT_KEYS } from '@agentx/core/modules/agents';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { policyOf, type PolicyRules, setPolicy } from '@agentx/core/modules/mandates';
import { rejectRequest, requestOf } from '@agentx/core/modules/spend-requests';
import type { SignedStates } from '@agentx/core/modules/audit';
import { supplierOf } from '@agentx/core/modules/suppliers';
import { createOutbox } from '@agentx/core/modules/notifications';
import { SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import { HOUR_MS } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, type DatabaseTransaction, type IdempotentRequest } from '@agentx/platform/db';
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

import { mandateIn } from './mandate-reads.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type Member, OPERATOR, refused, type World } from './mandate-world.helper.test.ts';
import { capChoiceDetails } from './monthly-cap-choice.ts';
import { createPolicyChanges, POLICY_OPERATIONS, type PolicyChanged, type PolicyTarget } from './policy-changes.ts';
import type { WaitingChoice } from './policy-waiting.ts';
import { createSpendRequestReads } from './spend-request-reads.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from './spend-request-decisions.ts';
import { spendWorld, type SpendWorldTables } from './spend-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SpendWorldTables>;

const ids = new SequentialIds(0xe5da_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000e5';

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'policy-waiting',
  registry: () => registry,
  decisions: () => decisions,
});
const { ready, ask, statusOf, holdingsOf, signed, mandateIdOf, eventsAbout, keyed, stepUp, spentOf } = shared;

const ORGANIZATION: PolicyTarget = { scope: 'organization' };

/** Rules with a monthly cap of `monthly` and, if given, a per-order cap of `perOrder` that denies over it. */
const rulesOf = (monthly: bigint, perOrder?: bigint): PolicyRules => ({
  currency: 'AED',
  perOrderCap: perOrder === undefined ? null : { cap: AED(perOrder), over: 'DENY' },
  monthlyCap: AED(monthly),
  approvalThreshold: null,
  supplierIds: null,
});

/** The world's own monthly cap (AED 20,000): what the rules in force allow. */
const LOOSE = rulesOf(2_000_000n);

type SignedTx = DatabaseTransaction<SpendWorldTables>;

/** The policy changes' use case, as the app makes it. */
const changes = () =>
  createPolicyChanges({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger: testLogger(capture),
  });

/** `rules` as a change of `target` sends them: the organisation's with its monthly cap chosen. */
const askedOf = (target: PolicyTarget, rules: PolicyRules) => ({
  rules,
  capChoice: target.scope === 'organization' ? ('amount' as const) : null,
});

/** The preview of `rules` on `target`, asked by `who`. */
const preview = (who: Member, target: PolicyTarget, rules: PolicyRules) =>
  changes().preview(who, target, askedOf(target, rules), CORRELATION);

/** The change of `target` to `rules` asked by the admin with `waiting`: the ask's answer. */
const asking = (w: World, target: PolicyTarget, rules: PolicyRules, waiting?: WaitingChoice, key?: IdempotentRequest) =>
  changes().ask(
    w.admin,
    key ?? keyed(w.admin, POLICY_OPERATIONS[target.scope].ask),
    target,
    askedOf(target, rules),
    waiting,
    CORRELATION,
  );

/** The step-up of an ask signed in for with a passkey, then the change confirmed with `waiting`. */
async function confirming(
  w: World,
  target: PolicyTarget,
  rules: PolicyRules,
  waiting: WaitingChoice | undefined,
  challengeId: string,
) {
  await stepUp(w.admin, challengeId);
  return changes().confirm(
    w.admin,
    keyed(w.admin, POLICY_OPERATIONS[target.scope].confirm),
    target,
    askedOf(target, rules),
    waiting,
    challengeId,
    CORRELATION,
  );
}

/** Asked then confirmed with `waiting`: the confirm's answer, and the plan the ask showed. */
async function changed(w: World, target: PolicyTarget, rules: PolicyRules, waiting?: WaitingChoice) {
  const asked = await asking(w, target, rules, waiting);
  if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
  return { done: await confirming(w, target, rules, waiting, asked.stepUpChallengeId), shown: asked.waiting };
}

/** The event of the version a change made, with its choice. */
async function versionEvent(w: World, done: PolicyChanged) {
  if (done.outcome !== 'changed' || done.current === null) throw new Error(`not changed: ${JSON.stringify(done)}`);
  return (await eventsAbout(w.org, done.current.id, 'policy_version')).at(-1);
}

/** The request rejected by a person, past the use case, in the caller's transaction. */
const rejectedPastTheUseCase = (tx: SignedTx, states: SignedStates, w: World, id: string) =>
  rejectRequest(
    tx,
    states,
    keys,
    { orgId: w.org, id },
    { userId: w.admin.userId, reason: 'Not needed now', stepUp: {} },
    clock.now(),
  );

/** The preview's listed requests as their IDs and reasons, and whether there are more. */
async function listed(who: Member, target: PolicyTarget, rules: PolicyRules) {
  const previewed = await preview(who, target, rules);
  if (previewed.outcome !== 'previewed') throw new Error(`not previewed: ${JSON.stringify(previewed)}`);
  return { rejected: previewed.rejected.map(({ id, reasons }) => [id, reasons]), more: previewed.more };
}

/** The organisation's policy set past the use case, as a change before this one would have. */
const policySet = (w: World, rules: PolicyRules) =>
  signed(w, async (tx, states) => {
    const read = await policyOf(tx, states, { orgId: w.org, id: w.org }, 'change');
    return setPolicy(tx, states, {
      orgId: w.org,
      existing: read.outcome === 'found' ? read : null,
      scope: 'organization',
      mandateId: null,
      versionId: ids.next(),
      rules,
      madeBy: w.admin.membershipId,
      madeAt: clock.now(),
      actor: OPERATOR,
      details: capChoiceDetails('amount'),
    });
  });

/** Three requests of AED 2,000, each waiting, a minute apart so their order is when each was made. */
async function threeWaiting() {
  const { w, acting } = await ready();
  const made = [];
  for (let at = 0; at < 3; at += 1) {
    made.push(await ask(acting, w));
    clock.advanceBy(60_000);
  }
  expect(made.map(({ status }) => status)).toEqual(['APPROVAL_REQUIRED', 'APPROVAL_REQUIRED', 'APPROVAL_REQUIRED']);
  return { w, acting, made: made.map(({ id }) => id) };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SpendWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit chain seals each event's time by the database's clock, so the tests start from now.
  clock = new FixedClock(new Date());
  capture = new LogCapture();
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger: testLogger(capture) });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger: testLogger(capture),
  });
});

describe('the requests waiting for approval a policy change would reject (E5d, decision 19)', () => {
  it('lists the younger ones a lowered monthly cap can’t hold, oldest first, the oldest standing; writes nothing', async () => {
    const { w, made } = await threeWaiting();
    const [first, second, third] = made;
    const before = await Promise.all(made.map((id) => eventsAbout(w.org, id, SPEND_REQUESTS.subject)));

    // AED 3,000 a month: the first's AED 2,000 fits, the next two don't once it is counted.
    expect(await listed(w.admin, ORGANIZATION, rulesOf(300_000n))).toEqual({
      rejected: [
        [second, ['POLICY_MONTHLY_CAP']],
        [third, ['POLICY_MONTHLY_CAP']],
      ],
      more: false,
    });
    // AED 1,000: none fits.
    expect((await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).rejected.map(([id]) => id)).toEqual([
      first,
      second,
      third,
    ]);
    // The rules in force, or looser: none.
    expect(await listed(w.admin, ORGANIZATION, LOOSE)).toEqual({ rejected: [], more: false });

    for (const [at, id] of made.entries()) {
      expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
      expect(await holdingsOf(w, id)).toEqual({ reservation: 'HELD', released: false });
      expect(await eventsAbout(w.org, id, SPEND_REQUESTS.subject)).toEqual(before[at]);
    }
  });

  it('lists the ones over a lowered per-order cap, the organisation’s or the mandate’s, with what each names', async () => {
    const { w, acting } = await ready();
    const over = await ask(acting, w);
    const under = await ask(acting, w, { amount: AED(150_000n) });
    const mandateId = await mandateIdOf(w);

    const atOrderCap = { rejected: [[over.id, ['POLICY_ORDER_CAP']]], more: false };
    expect(await listed(w.admin, ORGANIZATION, rulesOf(2_000_000n, 180_000n))).toEqual(atOrderCap);
    expect(await listed(w.admin, { scope: 'mandate', mandateId }, rulesOf(2_000_000n, 180_000n))).toEqual(atOrderCap);
    expect(await statusOf(w, under.id)).toBe('APPROVAL_REQUIRED');
  });

  it('leaves out one the rules in force refuse already: it stays with its approver (S118)', async () => {
    const { w, made } = await threeWaiting();
    // An earlier change, left for the approvers: AED 5,000 a month. Each is weighed as its approver's confirm
    // weighs it, the others counted: AED 6,000, so today's rules refuse each already.
    await policySet(w, rulesOf(500_000n));

    expect(await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual({ rejected: [], more: false });
    // AED 6,000 holds them all today; AED 3,000 holds the first alone.
    await policySet(w, rulesOf(600_000n));
    expect((await listed(w.admin, ORGANIZATION, rulesOf(300_000n))).rejected.map(([id]) => id)).toEqual(made.slice(1));
  });

  it('counts a younger one that can’t go (its key revoked) against an older one: as its approver’s confirm would', async () => {
    const { w, acting } = await ready();
    const older = await ask(acting, w);
    clock.advanceBy(60_000);
    const theirs = await shared.agentKey(w);
    const younger = await ask(theirs, w);
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: theirs.keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    );

    // AED 3,000 a month: the younger one's AED 2,000 stays held whatever is chosen, so the older one doesn't fit.
    expect(await listed(w.admin, ORGANIZATION, rulesOf(300_000n))).toEqual({
      rejected: [[older.id, ['POLICY_MONTHLY_CAP']]],
      more: false,
    });
    expect(await statusOf(w, younger.id)).toBe('APPROVAL_REQUIRED');
  });

  it('weighs each agent against its own month, oldest first across them; a mandate’s change lists its agent’s alone', async () => {
    const { w, acting } = await ready();
    // The first agent's mandate, read before the second's is made.
    const mandateId = await mandateIdOf(w);
    const theirs = await shared.secondAgent(registry, w, { approvalThreshold: AED(100_000n) });
    const first = await ask(acting, w);
    clock.advanceBy(60_000);
    const second = await ask(theirs, w);
    clock.advanceBy(60_000);
    const third = await ask(acting, w);

    // AED 3,000 a month each: each agent's oldest fits, the first agent's younger one doesn't.
    expect(await listed(w.admin, ORGANIZATION, rulesOf(300_000n))).toEqual({
      rejected: [[third.id, ['POLICY_MONTHLY_CAP']]],
      more: false,
    });
    expect((await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).rejected.map(([id]) => id)).toEqual([
      first.id,
      second.id,
      third.id,
    ]);
    expect(
      (await listed(w.admin, { scope: 'mandate', mandateId }, rulesOf(100_000n))).rejected.map(([id]) => id),
    ).toEqual([first.id, third.id]);
  });

  it.each(['the agent suspended', 'the mandate suspended'] as const)(
    'leaves out every one with a stop: %s',
    async (which) => {
      const { w } = await threeWaiting();
      await shared.STOPS[which](w, await mandateIdOf(w));

      expect(await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual({ rejected: [], more: false });
    },
  );

  it('leaves out every one of an agent with no mandate in force: revoked, its requests not yet voided by the job', async () => {
    const { w } = await threeWaiting();
    await shared.movedPastTheUseCase(w, await mandateIdOf(w), 'revoke');

    expect(await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual({ rejected: [], more: false });
  });

  it('lets a younger, smaller one stand when an older one goes: one that goes is never counted', async () => {
    const { w, acting } = await ready();
    const first = await ask(acting, w);
    clock.advanceBy(60_000);
    const second = await ask(acting, w);
    clock.advanceBy(60_000);
    const third = await ask(acting, w, { amount: AED(150_000n) });

    // AED 3,600 a month: the first's AED 2,000 fits, the second's doesn't, the third's AED 1,500 does beside the first.
    expect(await listed(w.admin, ORGANIZATION, rulesOf(360_000n))).toEqual({
      rejected: [[second.id, ['POLICY_MONTHLY_CAP']]],
      more: false,
    });
    expect([first.status, third.status]).toEqual(['APPROVAL_REQUIRED', 'APPROVAL_REQUIRED']);
  });

  it('leaves out one asked with a key since revoked, and one past its 72 hours', async () => {
    const { w, acting, made } = await threeWaiting();
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    );
    expect(await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual({ rejected: [], more: false });

    const { w: other, made: others } = await threeWaiting();
    clock.advanceBy(72 * HOUR_MS);
    expect(await listed(other.admin, ORGANIZATION, rulesOf(100_000n))).toEqual({ rejected: [], more: false });
    expect([...made, ...others]).toHaveLength(6);
  });

  it.each(['the mandate superseded', 'the supplier’s details changed'] as const)(
    'leaves out every one decided under versions no longer in force: %s (its approver’s, or a void’s)',
    async (which) => {
      const { w } = await threeWaiting();
      await shared.STOPS[which](w, await mandateIdOf(w));

      expect(await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual({ rejected: [], more: false });
    },
  );

  it('refuses it when a key a waiting request names was tampered with, its alarm raised (FX-TAMPER)', async () => {
    const { w, acting } = await threeWaiting();
    const owner = await tamperAsOwner(database, AGENT_KEYS, w.org);
    try {
      await owner.stripSeals(acting.keyId);
    } finally {
      await owner.end();
    }

    expect(await preview(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it('lists a mandate’s change of its own requests alone; another mandate’s change lists none', async () => {
    const { w, made } = await threeWaiting();
    const mandateId = await mandateIdOf(w);
    const { w: other } = await threeWaiting();
    const otherMandate = await mandateIdOf(other);

    expect((await listed(w.admin, { scope: 'mandate', mandateId }, rulesOf(100_000n))).rejected).toHaveLength(3);
    expect(made).toHaveLength(3);
    // Another organisation's mandate isn't this one's to change.
    expect(await preview(w.admin, { scope: 'mandate', mandateId: otherMandate }, rulesOf(100_000n))).toEqual(
      refused(404, 'NOT_FOUND'),
    );
  });

  it('lists at most 20, oldest first, and says there are more', async () => {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    // Approval above AED 100, so each AED 200 waits: 21 of them, AED 4,200, within every limit in force.
    await shared.inForce(registry, w, { approvalThreshold: AED(10_000n) });
    const acting = await shared.agentKey(w);
    const made: string[] = [];
    for (let at = 0; at < 21; at += 1) {
      made.push((await ask(acting, w, { amount: AED(20_000n) })).id);
      clock.advanceBy(1_000);
    }

    // AED 200 a month: the oldest stands, the 20 younger would be rejected.
    const plan = await listed(w.admin, ORGANIZATION, rulesOf(20_000n));
    expect(plan.more).toBe(false);
    expect(plan.rejected.map(([id]) => id)).toEqual(made.slice(1));
    // AED 100: all 21, the oldest 20 listed.
    const all = await listed(w.admin, ORGANIZATION, rulesOf(10_000n));
    expect(all).toEqual({ rejected: made.slice(0, 20).map((id) => [id, ['POLICY_MONTHLY_CAP']]), more: true });
  });

  it('past 100 waiting, weighs the oldest 100, the younger holding theirs: the oldest listed, never none (S118)', async () => {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry, w, { approvalThreshold: AED(5_000n) });
    const acting = await shared.agentKey(w);
    // The oldest AED 300, then 100 of AED 100: 101 waiting, AED 10,300, within every limit in force.
    const made: string[] = [];
    for (let at = 0; at < 101; at += 1) {
      made.push((await ask(acting, w, { amount: AED(at === 0 ? 30_000n : 10_000n) })).id);
      clock.advanceBy(1_000);
    }

    // AED 200 an order: the oldest alone, and there may be more beyond the 100 weighed.
    expect(await listed(w.admin, ORGANIZATION, rulesOf(2_000_000n, 20_000n))).toEqual({
      rejected: [[made[0], ['POLICY_ORDER_CAP']]],
      more: true,
    });
    // AED 150 a month, the younger one's AED 100 counted held: none of the oldest fits, the oldest 20 listed.
    expect(await listed(w.admin, ORGANIZATION, rulesOf(15_000n))).toEqual({
      rejected: made.slice(0, 20).map((id) => [id, ['POLICY_MONTHLY_CAP']]),
      more: true,
    });

    // The rules in force: none of the oldest 100 listed, yet the younger weren't weighed, so the admin still chooses.
    expect(await listed(w.admin, ORGANIZATION, LOOSE)).toEqual({ rejected: [], more: true });
    expect(await asking(w, ORGANIZATION, LOOSE)).toEqual(refused(409, 'WAITING_CHOICE_REQUIRED'));
    expect(await asking(w, ORGANIZATION, rulesOf(2_000_000n, 20_000n), 'reject')).toEqual(
      refused(409, 'WAITING_REQUESTS_TOO_MANY_TO_REJECT'),
    );
    const { done, shown } = await changed(w, ORGANIZATION, rulesOf(2_000_000n, 20_000n), 'leave');
    expect(shown).toMatchObject({ more: true, rejected: [{ id: made[0] }] });
    expect(await versionEvent(w, done)).toMatchObject({ details: { waitingListed: 1, waitingMore: true } });
    expect(await statusOf(w, made[0] ?? '')).toBe('APPROVAL_REQUIRED');
  });

  it('refuses a member who isn’t an admin, and rules the change itself would refuse', async () => {
    const { w } = await threeWaiting();
    const approver = await shared.member(w.org, 'approver');

    expect(await preview(approver, ORGANIZATION, rulesOf(100_000n))).toEqual(refused(403, 'FORBIDDEN'));
    expect(await preview(w.admin, ORGANIZATION, { ...rulesOf(100_000n), supplierIds: [ids.next()] })).toEqual(
      refused(409, 'POLICY_SUPPLIER_UNKNOWN'),
    );
  });

  it('refuses it when a waiting request was tampered with, its alarm raised (FX-TAMPER)', async () => {
    const { w, made } = await threeWaiting();
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(made[1] ?? '');
    } finally {
      await owner.end();
    }

    expect(await preview(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(capture.lines().some(({ event }) => event === 'audit.integrity_failed')).toBe(true);
  });
});

describe('the admin chooses: reject them now, or leave them for their approvers (E5d-b, decision 19)', () => {
  it('rejects each one listed when the change is confirmed: its money freed, the rules and the version kept', async () => {
    const { w, acting, made } = await threeWaiting();
    const [first = '', second = '', third = ''] = made;

    const { done, shown } = await changed(w, ORGANIZATION, rulesOf(300_000n), 'reject');

    expect(shown.rejected.map(({ id }) => id)).toEqual([second, third]);
    expect(done).toMatchObject({ outcome: 'changed' });
    expect(await versionEvent(w, done)).toMatchObject({
      action: 'policy_version.made',
      actorType: 'user',
      details: { waitingRequests: 'reject', waitingStatementVersion: 1, waitingListed: 2, waitingMore: false },
    });
    const versionId = done.outcome === 'changed' ? done.current?.id : undefined;
    for (const id of [second, third]) {
      expect(await statusOf(w, id)).toBe('DENIED');
      expect(await holdingsOf(w, id)).toEqual({ reservation: 'RELEASED', released: true });
      expect((await eventsAbout(w.org, id, SPEND_REQUESTS.subject)).at(-1)).toMatchObject({
        action: 'spend_request.rejected',
        actorType: 'user',
        details: {
          causes: 'POLICY_MONTHLY_CAP',
          policyVersionId: versionId,
          reason:
            'Rejected when your team’s policy changed: the new rules deny it under your team’s rules (POLICY_MONTHLY_CAP). Change them in settings, then the agent asks again.',
        },
      });
    }
    expect(await statusOf(w, first)).toBe('APPROVAL_REQUIRED');
    expect(await spentOf(w, acting)).toBe(200_000n);
    // The agent learns only that a person rejected it (decision 6).
    const reads = createSpendRequestReads({ database: app, keys, ids, logger: testLogger(capture) });
    expect(await reads.ofAgent(w.org, acting.agentId, second, CORRELATION)).toMatchObject({
      endedBecause: ['APPROVAL_REJECTED'],
    });
  });

  it('leaves them waiting, their money held, when the admin chooses to', async () => {
    const { w, made } = await threeWaiting();

    const { done } = await changed(w, ORGANIZATION, rulesOf(300_000n), 'leave');

    expect(done).toMatchObject({ outcome: 'changed' });
    expect(await versionEvent(w, done)).toMatchObject({
      details: { waitingRequests: 'leave', waitingStatementVersion: 1, waitingListed: 2, waitingMore: false },
    });
    for (const id of made) {
      expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
      expect(await holdingsOf(w, id)).toEqual({ reservation: 'HELD', released: false });
    }
  });

  it('rejects a mandate’s listed ones on its policy’s change', async () => {
    const { w, made } = await threeWaiting();
    const mandateId = await mandateIdOf(w);
    const target: PolicyTarget = { scope: 'mandate', mandateId };

    const { done } = await changed(w, target, rulesOf(100_000n), 'reject');

    for (const id of made) expect(await statusOf(w, id)).toBe('DENIED');
    expect(await versionEvent(w, done)).toMatchObject({ details: { waitingRequests: 'reject', waitingListed: 3 } });
  });

  it('asks for a choice only when the change would reject one: required, or refused, nothing changed', async () => {
    const { w } = await threeWaiting();

    expect(await asking(w, ORGANIZATION, rulesOf(300_000n))).toEqual(refused(409, 'WAITING_CHOICE_REQUIRED'));
    expect(await asking(w, ORGANIZATION, LOOSE, 'leave')).toEqual(refused(400, 'WAITING_CHOICE_NOT_OFFERED'));
    const none = await changed(w, ORGANIZATION, LOOSE);
    expect(none.done).toMatchObject({ outcome: 'changed' });
    expect((await versionEvent(w, none.done))?.details).not.toHaveProperty('waitingRequests');
  });

  it('refuses to reject more than 20 at once, and saves the change leaving them', async () => {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry, w, { approvalThreshold: AED(10_000n) });
    const acting = await shared.agentKey(w);
    for (let at = 0; at < 22; at += 1) {
      await ask(acting, w, { amount: AED(20_000n) });
      clock.advanceBy(1_000);
    }

    expect(await asking(w, ORGANIZATION, rulesOf(10_000n), 'reject')).toEqual(
      refused(409, 'WAITING_REQUESTS_TOO_MANY_TO_REJECT'),
    );
    const { done } = await changed(w, ORGANIZATION, rulesOf(10_000n), 'leave');
    expect(done).toMatchObject({ outcome: 'changed' });
    expect(await versionEvent(w, done)).toMatchObject({ details: { waitingListed: 20, waitingMore: true } });
  });

  it('refuses the step-up once the plan changed since the ask: another one waiting, nothing rejected', async () => {
    const { w, acting, made } = await threeWaiting();
    const asked = await asking(w, ORGANIZATION, rulesOf(300_000n), 'reject');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    // A fourth decided under the rules in force: the new ones would reject it too.
    const fourth = await ask(acting, w);

    expect(await confirming(w, ORGANIZATION, rulesOf(300_000n), 'reject', asked.stepUpChallengeId)).toEqual(
      refused(403, 'STEP_UP_FAILED'),
    );
    for (const id of [...made, fourth.id]) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses the step-up, not the choice, once one listed passed its 72 hours before the job reached it', async () => {
    const { w, made } = await threeWaiting();
    const asked = await asking(w, ORGANIZATION, rulesOf(300_000n), 'reject');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    clock.advanceBy(72 * HOUR_MS);

    expect(await confirming(w, ORGANIZATION, rulesOf(300_000n), 'reject', asked.stepUpChallengeId)).toEqual(
      refused(403, 'STEP_UP_FAILED'),
    );
    for (const id of made) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
  });

  it('refuses the step-up for another choice than the ask’s: the admin confirms what they saw', async () => {
    const { w, made } = await threeWaiting();
    const asked = await asking(w, ORGANIZATION, rulesOf(300_000n), 'leave');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);

    expect(await confirming(w, ORGANIZATION, rulesOf(300_000n), 'reject', asked.stepUpChallengeId)).toEqual(
      refused(403, 'STEP_UP_FAILED'),
    );
    for (const id of made) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
  });

  it('answers a replayed ask with the plan worked out again', async () => {
    const { w, made } = await threeWaiting();
    const key = keyed(w.admin, POLICY_OPERATIONS.organization.ask);
    const once = await asking(w, ORGANIZATION, rulesOf(300_000n), 'reject', key);

    const again = await asking(w, ORGANIZATION, rulesOf(300_000n), 'reject', key);

    expect(again).toEqual(once);
    expect(again.outcome === 'asked' && again.waiting.rejected.map(({ id }) => id)).toEqual(made.slice(1));
  });

  it('rejects them while the organisation is frozen: it only frees money (S118)', async () => {
    const { w, made } = await threeWaiting();
    await signed(w, (tx, states) =>
      states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'freeze', {
        actor: OPERATOR,
        action: 'organization.freeze',
        details: {},
      }),
    );

    await changed(w, ORGANIZATION, rulesOf(300_000n), 'reject');

    expect(await Promise.all(made.map((id) => statusOf(w, id)))).toEqual(['APPROVAL_REQUIRED', 'DENIED', 'DENIED']);
  });
});

describe('the confirm waits in the lock order, never crosswise (forced)', () => {
  /** The confirm, made while `holder`'s transaction holds its locks, queued behind it, then let go: both answers. */
  async function whileHeld(
    w: World,
    holder: (tx: SignedTx, states: SignedStates, gate: () => Promise<void>) => Promise<unknown>,
  ) {
    const asked = await asking(w, ORGANIZATION, rulesOf(300_000n), 'reject');
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    await stepUp(w.admin, asked.stepUpChallengeId);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holding_ = signed(w, (tx, states) =>
      holder(tx, states, async () => {
        holding(undefined);
        await gate;
      }),
    );
    await held;
    const racing = within(
      20_000,
      changes().confirm(
        w.admin,
        keyed(w.admin, POLICY_OPERATIONS.organization.confirm),
        ORGANIZATION,
        askedOf(ORGANIZATION, rulesOf(300_000n)),
        'reject',
        asked.stepUpChallengeId,
        CORRELATION,
      ),
      'the policy’s confirm',
    );
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    return { held: await holding_, racing: await racing };
  }

  it('waits for an acceptance holding the mandate, which then reads the policy: both go through', async () => {
    const { w, made } = await threeWaiting();
    const mandateId = await mandateIdOf(w);

    const { racing } = await whileHeld(w, async (tx, states, gate) => {
      await mandateIn(tx, states, w.org, mandateId, 'change');
      await gate();
      // As an acceptance weighs its carry: the policies, after the mandate.
      return policyOf(tx, states, { orgId: w.org, id: w.org }, 'share');
    });

    expect(racing).toMatchObject({ outcome: 'changed' });
    expect(await statusOf(w, made[1] ?? '')).toBe('DENIED');
  });

  it('waits for a brake holding a supplier, which then locks a request: both go through', async () => {
    const { w, made } = await threeWaiting();

    const { racing } = await whileHeld(w, async (tx, states, gate) => {
      await supplierOf(tx, states, { orgId: w.org, id: w.suppliers[0] ?? '' }, 'change');
      await gate();
      // As a brake's void: its requests, after the supplier.
      return requestOf(tx, states, { orgId: w.org, id: made[0] ?? '' }, 'change');
    });

    expect(racing).toMatchObject({ outcome: 'changed' });
    expect(await statusOf(w, made[2] ?? '')).toBe('DENIED');
  });

  it('waits for a request held for change, then refuses: it is no longer the plan the step-up bound', async () => {
    const { w, made } = await threeWaiting();

    const { racing } = await whileHeld(w, async (tx, states, gate) => {
      await requestOf(tx, states, { orgId: w.org, id: made[2] ?? '' }, 'change');
      await gate();
      return rejectedPastTheUseCase(tx, states, w, made[2] ?? '');
    });

    expect(racing).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await statusOf(w, made[1] ?? '')).toBe('APPROVAL_REQUIRED');
  });
});
