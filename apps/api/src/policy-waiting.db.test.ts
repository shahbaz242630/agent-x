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
// tampered with refuses it, its alarm raised. Past 20 a `reject` rejects 20
// at once, keeps the rest on the version, and the job rejects them as their
// approvers' confirms would (decision 33b, F1 G8).
import { AGENT_KEYS } from '@agentx/core/modules/agents';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { POLICIES, policyOf, type PolicyRules, setPolicy } from '@agentx/core/modules/mandates';
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
import { createWaitingRejections } from './waiting-rejections.ts';

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
  approvalWait: target.scope === 'organization' ? (72 as const) : null,
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

/** 22 requests of AED 200, each waiting (approval above AED 100), a second apart; within every limit in force. */
async function twentyTwoWaiting() {
  const w = await shared.world();
  for (const id of w.suppliers) await shared.verified(w, id);
  await shared.inForce(registry, w, { approvalThreshold: AED(10_000n) });
  const acting = await shared.agentKey(w);
  const made: string[] = [];
  for (let at = 0; at < 22; at += 1) {
    made.push((await ask(acting, w, { amount: AED(20_000n) })).id);
    clock.advanceBy(1_000);
  }
  return { w, acting, made };
}

/** The waiting-rejections job over `w`'s organisation alone, as main.ts makes it. */
const rejections = (w: World, most?: number, page?: number) =>
  createWaitingRejections({
    list: () => Promise.resolve([w.org]),
    database: app,
    keys,
    ids,
    clock,
    logger: testLogger(capture),
    ...(most === undefined ? {} : { most }),
    ...(page === undefined ? {} : { page }),
  });

/** The log lines of `event`. */
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

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

  it('leaves out one past the 24 hours its organisation chose when it was asked; one asked before keeps 72 (E6)', async () => {
    const { w, acting } = await ready();
    const before = await ask(acting, w);
    await shared.waitChosen(w, 24);
    await ask(acting, w);
    clock.advanceBy(24 * HOUR_MS + 60_000);

    // AED 10 a month: neither fits, but the younger one's wait is over: its approver can no longer approve it.
    expect(await listed(w.admin, ORGANIZATION, rulesOf(1_000n))).toEqual({
      rejected: [[before.id, ['POLICY_MONTHLY_CAP']]],
      more: false,
    });
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
      details: { waitingRequests: 'reject', waitingStatementVersion: 3, waitingListed: 2, waitingMore: false },
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
      details: { waitingRequests: 'leave', waitingStatementVersion: 3, waitingListed: 2, waitingMore: false },
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

  it('rejects 20 at once past 20, keeping the rest on the version for the job (decision 33b): never refused', async () => {
    const { w, made } = await twentyTwoWaiting();

    const { done, shown } = await changed(w, ORGANIZATION, rulesOf(10_000n), 'reject');

    expect(shown).toMatchObject({ more: true, rejected: made.slice(0, 20).map((id) => ({ id })) });
    const details = (await versionEvent(w, done))?.details;
    expect(details).toMatchObject({
      waitingRequests: 'reject',
      waitingStatementVersion: 3,
      waitingListed: 20,
      waitingMore: true,
      waitingLeftover1: `${made[20]} ${made[21]}`,
    });
    expect(details).not.toHaveProperty('waitingLeftover2');
    expect(await Promise.all(made.map((id) => statusOf(w, id)))).toEqual([
      ...Array<string>(20).fill('DENIED'),
      'APPROVAL_REQUIRED',
      'APPROVAL_REQUIRED',
    ]);
  });

  it('keeps no leftovers when the admin leaves them, past 20 too', async () => {
    const { w, made } = await twentyTwoWaiting();

    const { done } = await changed(w, ORGANIZATION, rulesOf(10_000n), 'leave');

    const details = (await versionEvent(w, done))?.details;
    expect(details).toMatchObject({ waitingRequests: 'leave', waitingListed: 20, waitingMore: true });
    expect(details).not.toHaveProperty('waitingLeftover1');
    await rejections(w).run();
    for (const id of made) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
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

describe('the job rejects the rest an admin chose to reject (decision 33b, F1 G8)', () => {
  /** 22 waiting, then the organisation's monthly cap lowered to AED 100 with `reject`: 20 rejected, 2 left. */
  async function leftTwo() {
    const world = await twentyTwoWaiting();
    const { done } = await changed(world.w, ORGANIZATION, rulesOf(10_000n), 'reject');
    const versionId = done.outcome === 'changed' ? done.current?.id : undefined;
    return { ...world, versionId, left: world.made.slice(20) };
  }

  it('rejects each as the admin who confirmed, with the rules kept, its money freed; a second run does nothing', async () => {
    const { w, acting, versionId, left } = await leftTwo();

    await rejections(w).run();

    for (const id of left) {
      expect(await statusOf(w, id)).toBe('DENIED');
      expect(await holdingsOf(w, id)).toEqual({ reservation: 'RELEASED', released: true });
      expect((await eventsAbout(w.org, id, SPEND_REQUESTS.subject)).at(-1)).toMatchObject({
        action: 'spend_request.rejected',
        actorType: 'user',
        details: {
          causes: 'POLICY_MONTHLY_CAP',
          policyVersionId: versionId,
          via: 'waiting_rejections',
          reason:
            'Rejected when your team’s policy changed: the new rules deny it under your team’s rules (POLICY_MONTHLY_CAP). Change them in settings, then the agent asks again.',
        },
      });
    }
    expect(await spentOf(w, acting)).toBe(0n);
    expect(lines('waiting_rejection.rejected').map(({ requestId }) => requestId)).toEqual(left);
    await rejections(w).run();
    expect(lines('waiting_rejection.rejected')).toHaveLength(2);
    expect(lines('waiting_rejection.failed')).toEqual([]);
  });

  it('rejects them in the name of the admin who confirmed the change', async () => {
    const { w, left } = await leftTwo();

    await rejections(w).run();

    const actors = await database
      .as('admin')
      .query<{ actor_id: string }>(
        "select actor_id from audit.events where action = 'spend_request.rejected' and subject_id = any($1::uuid[])",
        [left],
      );
    expect(actors.map(({ actor_id }) => actor_id)).toEqual([w.admin.userId, w.admin.userId]);
  });

  it('leaves one its key was revoked since, as its approver could no longer approve it', async () => {
    const { w, acting, left } = await leftTwo();
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    );

    await rejections(w).run();

    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
  });

  it('leaves those carried to new supplier details by a pause: their approvers re-check them first (E5a)', async () => {
    const { w, left } = await leftTwo();
    await shared.detailsChanged(w, w.suppliers[0] ?? '', { pendingRequests: 'pause' });

    await rejections(w).run();

    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.failed')).toEqual([]);
  });

  it('leaves one the rules in force now let stand: capacity freed by another settled since', async () => {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry, w, { approvalThreshold: AED(10_000n) });
    const acting = await shared.agentKey(w);
    const made: string[] = [];
    for (let at = 0; at < 26; at += 1) {
      made.push((await ask(acting, w, { amount: AED(20_000n) })).id);
      clock.advanceBy(1_000);
    }
    // AED 1,000 a month: the oldest 5 stand, the 21 younger go, the youngest left for the job.
    const { done } = await changed(w, ORGANIZATION, rulesOf(100_000n), 'reject');
    expect((await versionEvent(w, done))?.details).toMatchObject({ waitingLeftover1: made[25] });
    // One of the 5 rejected by its approver: the youngest's AED 200 now fits.
    await signed(w, async (tx, states) => {
      await requestOf(tx, states, { orgId: w.org, id: made[0] ?? '' }, 'change');
      return rejectedPastTheUseCase(tx, states, w, made[0] ?? '');
    });

    await rejections(w).run();

    expect(await statusOf(w, made[25] ?? '')).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.failed')).toEqual([]);
  });

  it('stops at its share a run, the rest on the next', async () => {
    const { w, left } = await leftTwo();

    await rejections(w, 1).run();
    expect(await Promise.all(left.map((id) => statusOf(w, id)))).toEqual(['DENIED', 'APPROVAL_REQUIRED']);
    await rejections(w, 1).run();
    expect(await statusOf(w, left[1] ?? '')).toBe('DENIED');
  });

  it('reads the candidate policies a page at a time, each after the last: both policies’ rest in one run', async () => {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry, w, { approvalThreshold: AED(10_000n) });
    const acting = await shared.agentKey(w);
    const made: string[] = [];
    for (let at = 0; at < 44; at += 1) {
      made.push((await ask(acting, w, { amount: AED(at % 2 === 0 ? 30_000n : 20_000n) })).id);
      clock.advanceBy(1_000);
    }
    // The organisation's AED 250 an order goes for the 22 of AED 300; then the mandate's AED 150, for the 22 of AED 200.
    await changed(w, ORGANIZATION, rulesOf(2_000_000n, 25_000n), 'reject');
    const mandateId = await mandateIdOf(w);
    await changed(w, { scope: 'mandate', mandateId }, rulesOf(2_000_000n, 15_000n), 'reject');

    await rejections(w, undefined, 1).run();

    for (const id of made) expect(await statusOf(w, id)).toBe('DENIED');
    expect(lines('waiting_rejection.rejected')).toHaveLength(4);
  });

  it('pages past a policy whose rest stands, ending the run', async () => {
    const { w, acting, left } = await leftTwo();
    await signed(w, (tx, states) =>
      states.changeStatus(tx, AGENT_KEYS, { orgId: w.org, id: acting.keyId }, 'revoke', {
        actor: OPERATOR,
        action: 'agent_key.revoked',
        details: {},
      }),
    );

    await within(20_000, rejections(w, undefined, 1).run(), 'a run of one-policy pages');

    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
  });

  it('stops when its signal is aborted, rejecting nothing more', async () => {
    const { w, left } = await leftTwo();

    await rejections(w).run(AbortSignal.abort());

    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
  });

  it('ends with the version: a later change of the policy leaves them with their approvers', async () => {
    const { w, left } = await leftTwo();
    // The rules in force refuse the two already, so the new change lists none and takes no choice.
    await changed(w, ORGANIZATION, rulesOf(10_000n, 5_000n));

    await rejections(w).run();

    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.rejected')).toEqual([]);
  });

  it('leaves one settled meanwhile, and one past its wait (the expiry job’s), with no error', async () => {
    const { w, left } = await leftTwo();
    const [settled = '', waited = ''] = left;
    await signed(w, async (tx, states) => {
      await requestOf(tx, states, { orgId: w.org, id: settled }, 'change');
      return rejectedPastTheUseCase(tx, states, w, settled);
    });
    clock.advanceBy(72 * HOUR_MS);

    await rejections(w).run();

    expect((await eventsAbout(w.org, settled, SPEND_REQUESTS.subject)).at(-1)).toMatchObject({
      details: { reason: 'Not needed now' },
    });
    expect(await statusOf(w, waited)).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.rejected')).toEqual([]);
    expect(lines('waiting_rejection.failed')).toEqual([]);
  });

  it('leaves them while the organisation is frozen with its requests paused, then rejects them once unfrozen', async () => {
    const { w, left } = await leftTwo();
    const freeze = (event: 'freeze' | 'unfreeze', details: Record<string, string>) =>
      signed(w, (tx, states) =>
        states.changeStatus(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, event, {
          actor: OPERATOR,
          action: `organization.${event}`,
          details,
        }),
      );
    await freeze('freeze', { pendingRequests: 'pause' });

    await rejections(w).run();
    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');

    await freeze('unfreeze', {});
    await rejections(w).run();
    for (const id of left) expect(await statusOf(w, id)).toBe('DENIED');
  });

  // 101 requests decided and 100 rejected, a transaction each: near the default 30 s under coverage.
  it('past 100 waiting, rejects the other 80 of the oldest 100; the younger stays with its approver', async () => {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry, w, { approvalThreshold: AED(5_000n) });
    const acting = await shared.agentKey(w);
    const made: string[] = [];
    for (let at = 0; at < 101; at += 1) {
      made.push((await ask(acting, w, { amount: AED(10_000n) })).id);
      clock.advanceBy(1_000);
    }

    // AED 50 a month: every one of the oldest 100 would go, the youngest counted as holding its AED 100.
    const { done } = await changed(w, ORGANIZATION, rulesOf(5_000n), 'reject');
    const details = (await versionEvent(w, done))?.details;
    expect(details).toMatchObject({
      waitingListed: 20,
      waitingMore: true,
      waitingLeftover1: made.slice(20, 40).join(' '),
      waitingLeftover4: made.slice(80, 100).join(' '),
    });
    await rejections(w).run();

    expect(await Promise.all(made.slice(0, 100).map((id) => statusOf(w, id)))).toEqual(
      Array<string>(100).fill('DENIED'),
    );
    expect(await statusOf(w, made[100] ?? '')).toBe('APPROVAL_REQUIRED');
  }, 120_000);

  it('rejects a mandate’s rest on its policy’s change', async () => {
    const { w, made } = await twentyTwoWaiting();
    const mandateId = await mandateIdOf(w);

    await changed(w, { scope: 'mandate', mandateId }, rulesOf(10_000n), 'reject');
    await rejections(w).run();

    for (const id of made) expect(await statusOf(w, id)).toBe('DENIED');
  });

  it('rejects nothing on a version whose record was changed past the app, raising the alarm (FX-TAMPER)', async () => {
    const { w, versionId, left, made } = await leftTwo();
    await database
      .as('admin')
      .query('update audit.events set details = replace(details, $1, $2) where subject_id = $3', [
        left[1],
        made[0],
        versionId,
      ]);

    await rejections(w).run();

    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.unreadable')).toHaveLength(1);
    expect(capture.lines().map((line) => line.event)).toContain('audit.integrity_failed');
  });

  it('rejects nothing on a policy whose row was changed past the app (FX-TAMPER)', async () => {
    const { w, left } = await leftTwo();
    const owner = await tamperAsOwner(database, POLICIES, w.org);
    try {
      await owner.stripSeals(w.org);
    } finally {
      await owner.end();
    }

    await rejections(w).run();

    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.unreadable')).toHaveLength(1);
  });

  it('logs a leftover changed past the app and rejects it not, the alarm raised; rejects the other (FX-TAMPER)', async () => {
    const { w, left } = await leftTwo();
    const [tampered = '', other = ''] = left;
    const owner = await tamperAsOwner(database, SPEND_REQUESTS, w.org);
    try {
      await owner.stripSeals(tampered);
    } finally {
      await owner.end();
    }

    await rejections(w).run();

    expect(lines('waiting_rejection.failed').map(({ requestId }) => requestId)).toEqual([tampered]);
    expect(await statusOf(w, other)).toBe('DENIED');
    expect(capture.lines().map((line) => line.event)).toContain('audit.integrity_failed');
  });

  it('logs a run whose organisation list can’t be read, and rejects nothing', async () => {
    const { w, left } = await leftTwo();
    const job = createWaitingRejections({
      list: () => Promise.reject(new Error('the directory is down')),
      database: app,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
    });

    await job.run();

    expect(lines('waiting_rejection.run_failed')).toHaveLength(1);
    for (const id of left) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
  });
});

describe('the job waits in the lock order, never crosswise (forced, F1 G8)', () => {
  /** The job run while `holder`'s transaction holds its locks, queued behind it, then let go. */
  async function runWhileHeld(
    w: World,
    holder: (tx: SignedTx, states: SignedStates, gate: () => Promise<void>) => Promise<unknown>,
  ) {
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    const holding_ = signed(w, (tx, states) =>
      holder(tx, states, async () => {
        holding(undefined);
        await gate;
      }),
    );
    await held;
    const racing = within(20_000, rejections(w).run(), 'the waiting-rejections job');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await holding_;
    await racing;
  }

  it('waits for a policy change holding the policy, then rejects nothing: its version is no longer in force', async () => {
    const { w, made } = await twentyTwoWaiting();
    await changed(w, ORGANIZATION, rulesOf(10_000n), 'reject');

    await runWhileHeld(w, async (tx, states, gate) => {
      const read = await policyOf(tx, states, { orgId: w.org, id: w.org }, 'change');
      await gate();
      if (read.outcome !== 'found') throw new Error('no policy');
      return setPolicy(tx, states, {
        orgId: w.org,
        existing: read,
        scope: 'organization',
        mandateId: null,
        versionId: ids.next(),
        rules: rulesOf(10_000n),
        madeBy: w.admin.membershipId,
        madeAt: clock.now(),
        actor: OPERATOR,
        details: capChoiceDetails('amount'),
      });
    });

    for (const id of made.slice(20)) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.failed')).toEqual([]);
  });

  it('waits for a change holding the organisation, then the policy: the version that named them gone, it rejects nothing', async () => {
    const { w, made } = await twentyTwoWaiting();
    await changed(w, ORGANIZATION, rulesOf(10_000n), 'reject');

    // The job reads the leftovers first, then waits on the organisation (2) while the policy (4) moves on.
    await runWhileHeld(w, async (tx, states, gate) => {
      await states.verifiedState(tx, ORGANIZATIONS, { orgId: w.org, id: w.org }, 'change');
      await gate();
      const read = await policyOf(tx, states, { orgId: w.org, id: w.org }, 'change');
      if (read.outcome !== 'found') throw new Error('no policy');
      return setPolicy(tx, states, {
        orgId: w.org,
        existing: read,
        scope: 'organization',
        mandateId: null,
        versionId: ids.next(),
        rules: rulesOf(10_000n),
        madeBy: w.admin.membershipId,
        madeAt: clock.now(),
        actor: OPERATOR,
        details: capChoiceDetails('amount'),
      });
    });

    for (const id of made.slice(20)) expect(await statusOf(w, id)).toBe('APPROVAL_REQUIRED');
    expect(lines('waiting_rejection.failed')).toEqual([]);
  });

  it('waits for an approver holding a request, then leaves it once rejected; rejects the other', async () => {
    const { w, made } = await twentyTwoWaiting();
    await changed(w, ORGANIZATION, rulesOf(10_000n), 'reject');
    const [first = '', second = ''] = made.slice(20);

    await runWhileHeld(w, async (tx, states, gate) => {
      await requestOf(tx, states, { orgId: w.org, id: first }, 'change');
      await gate();
      return rejectedPastTheUseCase(tx, states, w, first);
    });

    expect((await eventsAbout(w.org, first, SPEND_REQUESTS.subject)).at(-1)).toMatchObject({
      details: { reason: 'Not needed now' },
    });
    expect((await eventsAbout(w.org, second, SPEND_REQUESTS.subject)).at(-1)).toMatchObject({
      details: { via: 'waiting_rejections' },
    });
    expect(lines('waiting_rejection.failed')).toEqual([]);
  });
});
