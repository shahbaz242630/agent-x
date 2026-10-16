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
// others. It writes nothing; a member not an admin is refused; a request
// tampered with refuses it, its alarm raised.
import { AGENT_KEYS } from '@agentx/core/modules/agents';
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { policyOf, type PolicyRules, setPolicy } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import { HOUR_MS } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
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

import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { AED, keys, type Member, OPERATOR, refused, type World } from './mandate-world.helper.test.ts';
import { capChoiceDetails } from './monthly-cap-choice.ts';
import { createPolicyChanges, type PolicyTarget } from './policy-changes.ts';
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
const { ready, ask, statusOf, holdingsOf, signed, mandateIdOf, eventsAbout } = shared;

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

/** The preview of `rules` on `target`, asked by `who`. */
const preview = (who: Member, target: PolicyTarget, rules: PolicyRules) =>
  createPolicyChanges({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger: testLogger(capture),
  }).preview(who, target, { rules, capChoice: target.scope === 'organization' ? 'amount' : null }, CORRELATION);

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

  it('leaves out every one with a stop: the agent suspended', async () => {
    const { w } = await threeWaiting();
    await shared.STOPS['the agent suspended'](w);

    expect(await listed(w.admin, ORGANIZATION, rulesOf(100_000n))).toEqual({ rejected: [], more: false });
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
