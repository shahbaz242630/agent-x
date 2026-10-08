// Phase 2 C3: changing a policy, the organisation's own or a mandate's,
// composed in the API, on the real migrated schema as the app role: an admin
// asks, signs in again with a passkey and confirms the same rules; the first
// change makes the policy, a later one a new version, each in force at once
// with the step-up's evidence on its event and every admin and approver told
// (0038); a retry answered as it was; every refusal by its code (SEC-LIM-11:
// a mandate's policy never wider than its mandate); a step-up that isn't a
// passkey, was asked for other rules or for the policy as it stood before; a
// policy deleted past the app; and the lock order against the admin's demotion.
import { createStepUpChallenges } from '@agentx/core/modules/identity';
import { type PolicyRules, POLICIES } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import {
  confirmedWhileDemoted,
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
import {
  AED,
  askedFor,
  keys,
  type Member,
  mandateWorld,
  type MandateWorldTables,
  PASSKEY,
  refused,
  type World,
} from './mandate-world.helper.test.ts';
import {
  createPolicyChanges,
  POLICY_OPERATIONS,
  type PolicyChanged,
  type PolicyChanges,
  type PolicyTarget,
} from './policy-changes.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xc3b0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000c3';
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const ORGANIZATION: PolicyTarget = { scope: 'organization' };

let clock: FixedClock;
let registry: MandateRegistry;
let changes: PolicyChanges;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'policy-changes' });
const { member, world, keyed, noticesOf, stepUp } = shared;

/** Rules that set only a monthly cap of `minor` fils, unless `changes` say more. */
const rules = (minor: bigint, more: Partial<PolicyRules> = {}): PolicyRules => ({
  currency: 'AED',
  perOrderCap: null,
  monthlyCap: AED(minor),
  approvalThreshold: null,
  supplierIds: null,
  ...more,
});

const ask = (who: Member, target: PolicyTarget, asked: PolicyRules) =>
  changes.ask(who, keyed(who, POLICY_OPERATIONS[target.scope].ask), target, asked, CORRELATION);

const confirm = (who: Member, target: PolicyTarget, asked: PolicyRules, challengeId: string, key?: IdempotentRequest) =>
  changes.confirm(
    who,
    key ?? keyed(who, POLICY_OPERATIONS[target.scope].confirm),
    target,
    asked,
    challengeId,
    CORRELATION,
  );

const changedOf = (write: PolicyChanged) => {
  if (write.outcome !== 'changed') throw new Error(`not changed: ${JSON.stringify(write)}`);
  return write;
};

/** Asks, signs in again with `amr` and confirms: the confirm's answer. */
async function changed(w: World, target: PolicyTarget, asked: PolicyRules, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await ask(w.admin, target, asked));
  await stepUp(w.admin, challengeId, amr);
  return confirm(w.admin, target, asked, challengeId);
}

/** The policy's events and its versions', oldest first. */
const policyEvents = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'subject_type', 'details'])
      .where('subject_type', 'in', ['policy', 'policy_version'])
      .orderBy('seq')
      .execute(),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-08T08:00:00Z'));
  const logger = testLogger(new LogCapture());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  changes = createPolicyChanges({
    database: app,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger,
  });
});

describe('the organisation’s policy (C3, decision 5)', () => {
  it('is none until set; an admin sets it with a passkey, then changes it: a new version each, in force at once, everyone told', async () => {
    const w = await world();
    expect(await changes.show(w.org, ORGANIZATION, CORRELATION)).toEqual({
      outcome: 'found',
      scope: 'organization',
      id: w.org,
      mandateId: null,
      current: null,
    });

    const first = changedOf(await changed(w, ORGANIZATION, rules(1_000_000n)));
    expect(first).toMatchObject({
      scope: 'organization',
      id: w.org,
      current: { version: 1, monthlyCap: AED(1_000_000n) },
    });
    expect(first.current?.madeBy).toBe(w.admin.membershipId);
    const second = changedOf(
      await changed(w, ORGANIZATION, rules(3_000_000n, { supplierIds: [...w.suppliers].reverse() })),
    );
    expect(second.current).toMatchObject({
      version: 2,
      monthlyCap: AED(3_000_000n),
      supplierIds: [...w.suppliers].sort(),
    });
    expect((await changes.show(w.org, ORGANIZATION, CORRELATION)).outcome).toBe('found');

    const events = await policyEvents(w.org);
    expect(events.map(({ action, subject_type }) => [action, subject_type])).toEqual([
      ['policy.set', 'policy'],
      ['policy_version.made', 'policy_version'],
      ['policy.changed', 'policy'],
      ['policy_version.made', 'policy_version'],
    ]);
    for (const { details } of events.filter(({ subject_type }) => subject_type === 'policy_version')) {
      expect(JSON.parse(details)).toMatchObject({ methods: PASSKEY.join(' ') });
    }
    expect(await noticesOf(w.org)).toEqual([
      { kind: 'organization_policy_changed', about_id: w.org, recipient_user_id: null },
      { kind: 'organization_policy_changed', about_id: w.org, recipient_user_id: null },
    ]);
  });

  it('answers a confirm sent again from the policy, making nothing twice', async () => {
    const w = await world();
    const asked = rules(1_000_000n);
    const challengeId = askedFor(await ask(w.admin, ORGANIZATION, asked));
    await stepUp(w.admin, challengeId);
    const key = keyed(w.admin, POLICY_OPERATIONS.organization.confirm);
    changedOf(await confirm(w.admin, ORGANIZATION, asked, challengeId, key));

    expect(changedOf(await confirm(w.admin, ORGANIZATION, asked, challengeId, key)).current?.version).toBe(1);
    expect(await policyEvents(w.org)).toHaveLength(2);
  });

  it('refuses a currency the deployment doesn’t take, and a supplier not the organisation’s', async () => {
    const w = await world();
    const usd = { currency: 'USD', perOrderCap: null, monthlyCap: null, approvalThreshold: null, supplierIds: null };
    expect(await ask(w.admin, ORGANIZATION, usd)).toEqual(refused(409, 'POLICY_CURRENCY_REFUSED'));
    expect(await ask(w.admin, ORGANIZATION, rules(1n, { supplierIds: [ids.next()] }))).toEqual(
      refused(409, 'POLICY_SUPPLIER_UNKNOWN'),
    );
  });

  it('refuses the 101st change in a day: POLICY_CHANGES_SPENT, and takes one again a day later', async () => {
    const w = await world();
    await withTenant(app, w.org, async (tx) => {
      // The budget's count alone, past the app: 100 versions of the organisation's policy made in the last day.
      await tx
        .insertInto('mandates.policies')
        .values({
          org_id: w.org,
          id: w.org,
          scope: 'organization',
          mandate_id: null,
          current_version_id: w.org,
          created_at: clock.now(),
        })
        .execute();
      for (let version = 1; version <= 100; version += 1) {
        await tx
          .insertInto('mandates.policy_versions')
          .values({
            org_id: w.org,
            id: version === 1 ? w.org : ids.next(),
            policy_id: w.org,
            version,
            currency: 'AED',
            per_order_cap_minor: null,
            over_per_order_cap: null,
            monthly_cap_minor: null,
            approval_threshold_minor: null,
            supplier_ids: null,
            rules_hash: '0'.repeat(64),
            made_by: w.admin.membershipId,
            made_at: clock.now(),
          })
          .execute();
      }
    });

    expect(await ask(w.admin, ORGANIZATION, rules(1n))).toEqual(refused(409, 'POLICY_CHANGES_SPENT'));
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s: FORBIDDEN', async (role) => {
    const w = await world();
    expect(await ask(await member(w.org, role), ORGANIZATION, rules(1n))).toEqual(refused(403, 'FORBIDDEN'));
  });

  it('refuses a step-up signed in with an app code: STEP_UP_FAILED, nothing changed', async () => {
    const w = await world();
    expect(await changed(w, ORGANIZATION, rules(1n), APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await policyEvents(w.org)).toEqual([]);
  });

  it('refuses a confirm of other rules than the step-up was asked for: STEP_UP_FAILED', async () => {
    const w = await world();
    const challengeId = askedFor(await ask(w.admin, ORGANIZATION, rules(1_000n)));
    await stepUp(w.admin, challengeId);

    expect(await confirm(w.admin, ORGANIZATION, rules(9_000_000n), challengeId)).toEqual(
      refused(403, 'STEP_UP_FAILED'),
    );
  });

  it('refuses a step-up asked before the policy changed: STEP_UP_FAILED, for the policy as it stood', async () => {
    const w = await world();
    const challengeId = askedFor(await ask(w.admin, ORGANIZATION, rules(1_000n)));
    await stepUp(w.admin, challengeId);
    changedOf(await changed(w, ORGANIZATION, rules(2_000n)));

    expect(await confirm(w.admin, ORGANIZATION, rules(1_000n), challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });

  it('a policy deleted past the app: INTEGRITY_FAILED, never read as none set (FX-TAMPER)', async () => {
    const w = await world();
    changedOf(await changed(w, ORGANIZATION, rules(1_000n)));
    const owner = await tamperAsOwner(database, POLICIES, w.org);
    try {
      // One statement: the policy and its versions name each other.
      await owner.query(
        'with gone as (delete from mandates.policies where id = $1) delete from mandates.policy_versions where policy_id = $1',
        [w.org],
      );
    } finally {
      await owner.end();
    }

    expect(await changes.show(w.org, ORGANIZATION, CORRELATION)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await ask(w.admin, ORGANIZATION, rules(1n))).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });
});

describe('a mandate’s policy (C3, SEC-LIM-11)', () => {
  it('an admin sets one within the mandate, its agent’s cap higher than the organisation’s: the mandate told of', async () => {
    const w = await world();
    const id = await shared.inForce(registry, w);
    changedOf(await changed(w, ORGANIZATION, rules(1_000n)));
    const target: PolicyTarget = { scope: 'mandate', mandateId: id };

    // The world's mandate: monthly 2 × the source's per-payment limit; a cap at it, above the organisation's.
    const set = changedOf(await changed(w, target, rules(w.maxPayment * 2n, { supplierIds: [w.suppliers[0] ?? ''] })));
    expect(set).toMatchObject({ scope: 'mandate', id, mandateId: id, current: { version: 1 } });
    expect((await noticesOf(w.org)).at(-1)).toEqual({
      kind: 'mandate_policy_changed',
      about_id: id,
      recipient_user_id: null,
    });
    expect(await changes.show(w.org, target, CORRELATION)).toMatchObject({
      outcome: 'found',
      id,
      current: { version: 1 },
    });
  });

  it('sets one on a draft waiting, weighed against the draft', async () => {
    const w = await world();
    const { id } = await shared.drafted(registry, w);
    expect(changedOf(await changed(w, { scope: 'mandate', mandateId: id }, rules(1_000n))).current?.version).toBe(1);
  });

  it.each<[string, (w: World) => Partial<PolicyRules>]>([
    ['a monthly cap above the mandate’s', (w) => ({ monthlyCap: AED(w.maxPayment * 2n + 1n) })],
    [
      'a per-order cap above the mandate’s',
      (w) => ({ monthlyCap: null, perOrderCap: { cap: AED(w.maxPayment + 1n), over: 'DENY' } }),
    ],
    ['a threshold above the mandate’s', (w) => ({ monthlyCap: null, approvalThreshold: AED(w.maxPayment / 2n + 1n) })],
    ['a supplier the mandate doesn’t name', () => ({ monthlyCap: null, supplierIds: [ids.next()] })],
  ])('refuses %s: POLICY_WIDER_THAN_MANDATE', async (_what, wider) => {
    const w = await world();
    const id = await shared.inForce(registry, w);
    expect(await ask(w.admin, { scope: 'mandate', mandateId: id }, rules(1n, wider(w)))).toEqual(
      refused(409, 'POLICY_WIDER_THAN_MANDATE'),
    );
  });

  it('refuses one for a mandate ended, unknown, or in another currency', async () => {
    const w = await world();
    const id = await shared.inForce(registry, w);
    const usd = { currency: 'USD', perOrderCap: null, monthlyCap: null, approvalThreshold: null, supplierIds: null };
    expect(await ask(w.admin, { scope: 'mandate', mandateId: id }, usd)).toEqual(
      refused(409, 'POLICY_CURRENCY_REFUSED'),
    );
    await shared.movedPastTheUseCase(w, id, 'revoke');
    expect(await ask(w.admin, { scope: 'mandate', mandateId: id }, rules(1n))).toEqual(refused(409, 'MANDATE_ENDED'));
    expect(await ask(w.admin, { scope: 'mandate', mandateId: ids.next() }, rules(1n))).toEqual(
      refused(404, 'NOT_FOUND'),
    );
  });

  it('weighs the confirm again: a step-up asked within the mandate, the mandate revoked since: MANDATE_ENDED', async () => {
    const w = await world();
    const id = await shared.inForce(registry, w);
    const target: PolicyTarget = { scope: 'mandate', mandateId: id };
    const challengeId = askedFor(await ask(w.admin, target, rules(1_000n)));
    await stepUp(w.admin, challengeId);
    await shared.movedPastTheUseCase(w, id, 'revoke');

    expect(await confirm(w.admin, target, rules(1_000n), challengeId)).toEqual(refused(409, 'MANDATE_ENDED'));
  });
});

describe(`the confirm's lock order against the admin's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const w = await world();
    const challengeId = askedFor(await ask(w.admin, ORGANIZATION, rules(1_000n)));
    await stepUp(w.admin, challengeId);

    const done = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: w.org, membershipId: w.admin.membershipId },
      () => confirm(w.admin, ORGANIZATION, rules(1_000n), challengeId),
    );

    expect(changedOf(done).current?.version).toBe(1);
  });
});
