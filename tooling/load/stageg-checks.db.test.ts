// Stage G's set-based checks (stageg-checks.ts) on a migrated database: a step's
// requests made through the app's own decisions in two organisations pass every
// check, and each check catches the fault it is for, planted past the app by the
// tables' owner in ordinary SQL on the test's own rows (never a forged chained
// event): a replay recorded twice, an order held twice, a lost request, a
// reservation in the wrong organisation, a month over its limit, holdings that
// don't match their decisions; the integrity hold through the app's own path.
// Given a role the tenant walls bind, they refuse rather than find nothing.
import { holdOrganisation } from '../../packages/core/src/modules/audit/index.ts';
import { createOutbox } from '../../packages/core/src/modules/notifications/index.ts';
import { createDatabase, type Database } from '../../packages/platform/src/db/index.ts';
import {
  createTestDatabase,
  FixedClock,
  SequentialIds,
  type TestClient,
  type TestDatabase,
  testLogger,
} from '../../packages/testing/src/index.ts';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry, type MandateRegistry } from '../../apps/api/src/mandate-registry.ts';
import { AED, keys, type MandateWorldTables, type World } from '../../apps/api/src/mandate-world.helper.test.ts';
import { createSpendRequestDecisions, type SpendRequestDecisions } from '../../apps/api/src/spend-request-decisions.ts';
import { spendWorld } from '../../apps/api/src/spend-world.helper.test.ts';
import { LOAD_CHECKS } from './checks.ts';
import { stageGChecks, type StageGCheckedStep, WalledCheckRole } from './stageg-checks.ts';
import type { CohortAgent } from './stageg-seed.ts';

const server = inject('postgres');
const ids = new SequentialIds(0x5c6e_0000_0000);
let database: TestDatabase;
let app: Database<MandateWorldTables>;
let everyOrganisation: Database<MandateWorldTables>;
let clock: FixedClock;
let registry: MandateRegistry;
let decisions: SpendRequestDecisions;

const shared = spendWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'stage-g-checks',
  registry: () => registry,
  decisions: () => decisions,
});

beforeEach(async () => {
  // Each test its own database: the checks read every organisation, so one test's fault must not reach the next.
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>(database.connection('app'), testLogger());
  everyOrganisation = createDatabase<MandateWorldTables>(database.connection('backup'), testLogger());
  clock = new FixedClock(new Date());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger: testLogger() });
  decisions = createSpendRequestDecisions({
    database: app,
    outbox: createOutbox({ ids, clock }),
    keys,
    ids,
    clock,
    logger: testLogger(),
  });
});

afterEach(async () => {
  await app.destroy();
  await everyOrganisation.destroy();
  await database.drop();
});

const LABEL = 'orgs-100';
const order = (n: number) => `G-${LABEL}-r1-S-${String(n)}`;

interface Organisation {
  readonly w: World;
  readonly agent: CohortAgent;
  /** The step's requests by their order's number: 1 and 3 allowed, 2 waiting for approval, 4 the duplicate of 3. */
  readonly requests: Readonly<Record<1 | 2 | 3 | 4, string>>;
}

/** An organisation of the step: its agent's four requests, three holding money and the duplicate denied. */
async function organisation(): Promise<Organisation> {
  const { w, acting } = await shared.ready();
  const small = { amount: AED(10_000n) };
  const one = await shared.ask(acting, w, { ...small, orderReference: order(1) });
  const two = await shared.ask(acting, w, { orderReference: order(2) });
  // Its other supplier: a second small one to the first would be weighed as a split order.
  const other = { ...small, supplierId: w.suppliers[1] ?? '', orderReference: order(3) };
  const three = await shared.ask(acting, w, other);
  const four = await shared.ask(acting, w, other);
  expect([one.status, two.status, three.status, four.status]).toEqual([
    'APPROVED',
    'APPROVAL_REQUIRED',
    'APPROVED',
    'DENIED',
  ]);
  return {
    w,
    agent: {
      kind: 'ample',
      orgId: w.org,
      agentId: acting.agentId,
      sourceId: w.source,
      supplierIds: w.suppliers,
      monthlyLimitMinor: String(w.maxPayment * 2n),
    },
    requests: { 1: one.id, 2: two.id, 3: three.id, 4: four.id },
  };
}

/** Two organisations' requests as one step k6 was answered 201 for eight times. */
async function aStep() {
  const startedAt = clock.now().toISOString();
  const a = await organisation();
  const b = await organisation();
  const step: StageGCheckedStep = {
    label: LABEL,
    created: 8,
    startedAt,
    endedAt: new Date(clock.now().getTime() + 1000).toISOString(),
  };
  return { a, b, step, cohort: [a.agent, b.agent] };
}

const checked = (step: StageGCheckedStep, cohort: readonly CohortAgent[]) =>
  stageGChecks({ everyOrganisation, app }, step, cohort);

/** What each check found, by its name. */
const byName = async (step: StageGCheckedStep, cohort: readonly CohortAgent[]) =>
  Object.fromEntries((await checked(step, cohort)).map(({ name, failures }) => [name, failures]));

const DUPLICATES = 'recorded each request of the step once: no key twice, no order holding money twice';
const LOST = 'lost no request: the step’s own requests are as many as k6 was answered 201 for';
const ELSEWHERE = 'put no row in another organisation';
const LIMITS = 'kept every month the step touched within its agent’s limit';
const HOLDINGS =
  'holds exactly one reservation and one open claim for each request holding money, and none for one that ended';
const HOLDS = 'put no organisation on an integrity hold since the step began';

/** A change by the tables' owner with their guards off, in the organisation's rows: as only something past the app could. */
async function pastTheApp(org: string, change: (owner: TestClient) => Promise<unknown>): Promise<void> {
  const owner = await database.connect('owner');
  try {
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [org]);
    await owner.query('begin');
    await owner.query('alter table spend_requests.requests disable trigger user');
    await owner.query('alter table limit_reservations.reservations disable trigger user');
    await change(owner);
    await owner.query('alter table spend_requests.requests enable trigger user');
    await owner.query('alter table limit_reservations.reservations enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

/** The request copied as a new row named `id`, under `key` (its own if none). */
const copied = (owner: TestClient, org: string, from: string, id: string, key: string | null) =>
  owner.query(
    `insert into spend_requests.requests (
       org_id, id, agent_id, agent_key_id, mandate_id, mandate_version_id, organization_policy_version_id,
       mandate_policy_version_id, supplier_id, supplier_version_id, funding_source_id, amount_minor, currency, purpose,
       order_reference, idempotency_key, input_hash, input_hash_key_version, decision, reason_codes, status, created_at,
       state_version, state_event_id, waits_until)
     select org_id, $3, agent_id, agent_key_id, mandate_id, mandate_version_id, organization_policy_version_id,
       mandate_policy_version_id, supplier_id, supplier_version_id, funding_source_id, amount_minor, currency, purpose,
       order_reference, coalesce($4, idempotency_key), input_hash, input_hash_key_version, decision, reason_codes,
       status, created_at, state_version, state_event_id, waits_until
     from spend_requests.requests where org_id = $1 and id = $2`,
    [org, from, id, key],
  );

describe("Stage G's checks over the whole copy (4D2e item 8)", () => {
  it('pass a step made through the app, the cohort’s own checks with them, all in one snapshot', async () => {
    const { step, cohort } = await aStep();
    const results = await checked(step, cohort);
    expect(results).toEqual([
      { name: DUPLICATES, failures: [] },
      { name: LOST, failures: [] },
      { name: ELSEWHERE, failures: [] },
      { name: LIMITS, failures: [] },
      { name: HOLDINGS, failures: [] },
      { name: HOLDS, failures: [] },
      {
        name: 'the active cohort: kept every agent’s month within its limit, and stopped the capped one at it',
        failures: [],
      },
      {
        name: 'the active cohort: handed nothing off: the hand-off is paused, as staging’s is, so the check below holds',
        failures: [],
      },
      {
        name: 'the active cohort: holds exactly one reservation and one open claim for each request holding money, and none for the rest',
        failures: [],
      },
      { name: 'the active cohort: left one open claim an order', failures: [] },
      { name: 'the active cohort: put no organisation on an integrity hold', failures: [] },
    ]);
  });

  it('leave out the whole run’s count, which only PL-38’s run compares: there it still counts', async () => {
    const { cohort } = await aStep();
    const counted = LOAD_CHECKS.filter(({ countsTheRun }) => countsTheRun === true);
    expect(counted.map(({ name }) => name)).toEqual(['recorded each request k6 was answered 201 for, once']);
    const [count] = counted;
    expect(await count?.run(app, cohort, 8)).toEqual([]);
    expect(await count?.run(app, cohort, 9)).toEqual([
      'The database holds 8 requests, but k6 was answered 201 for 9 new ones.',
    ]);
    expect(await count?.run(app, cohort, Number.NaN)).toEqual([
      'k6 recorded no new request, so nothing could be checked.',
    ]);
  });

  it('run the cohort’s checks as PL-38’s run does: a capped agent must fill its month, an organisation must hold money', async () => {
    const { a, step } = await aStep();
    const { w, acting } = await shared.ready();
    const idle: CohortAgent = { ...a.agent, orgId: w.org, agentId: acting.agentId };
    const found = await byName(step, [{ ...a.agent, kind: 'capped' }, idle]);
    expect(
      found['the active cohort: kept every agent’s month within its limit, and stopped the capped one at it'],
    ).toEqual([
      'The capped agent holds 220000 fils with 1 denied: the spike should have filled its month exactly and been refused past it.',
    ]);
    expect(
      found[
        'the active cohort: holds exactly one reservation and one open claim for each request holding money, and none for the rest'
      ],
    ).toEqual([`Organisation ${w.org} has no request holding money to compare.`]);
  });

  it('refuse a role the tenant walls bind, which would read nothing and find nothing wrong', async () => {
    const { step, cohort } = await aStep();
    await expect(stageGChecks({ everyOrganisation: app, app }, step, cohort)).rejects.toThrow(WalledCheckRole);
  });

  it('catch a replay recorded twice, under another organisation’s request ID and unsigned', async () => {
    const { a, b, step, cohort } = await aStep();
    await pastTheApp(a.w.org, (owner) => copied(owner, a.w.org, a.requests[1], b.requests[1], null));
    const found = await byName(step, cohort);
    const key = (
      await everyOrganisation
        .selectFrom('spend_requests.requests')
        .select('idempotency_key')
        .where('id', '=', a.requests[1])
        .where('org_id', '=', a.w.org)
        .executeTakeFirstOrThrow()
    ).idempotency_key;
    expect(found[DUPLICATES]).toEqual([
      `Organisation ${a.w.org} recorded 2 requests under the key ${key}: a replay made a request again.`,
      // A replay of a request holding money holds it twice too.
      `Organisation ${a.w.org} holds money for the order g-orgs-100-r1-s-1 2 times: a duplicate under another key was not denied.`,
    ]);
    expect(found[LOST]).toEqual([
      'The database holds 9 requests of step orgs-100, but k6 was answered 201 for 8 new ones.',
    ]);
    expect(found[ELSEWHERE]).toEqual([
      `The request ${b.requests[1]} is recorded in 2 organisations.`,
      `Organisation ${a.w.org}'s request ${b.requests[1]} has no event in its own audit chain.`,
    ]);
  });

  it('catch an order holding money twice, a duplicate under another key not denied', async () => {
    const { a, step, cohort } = await aStep();
    await pastTheApp(a.w.org, (owner) => copied(owner, a.w.org, a.requests[3], ids.next(), 'another-key'));
    expect((await byName(step, cohort))[DUPLICATES]).toEqual([
      `Organisation ${a.w.org} holds money for the order g-orgs-100-r1-s-3 2 times: a duplicate under another key was not denied.`,
    ]);
  });

  it('catch a lost request, and a step k6 recorded nothing for', async () => {
    const { a, step, cohort } = await aStep();
    await pastTheApp(a.w.org, (owner) =>
      owner.query('delete from spend_requests.requests where org_id = $1 and id = $2', [a.w.org, a.requests[4]]),
    );
    expect((await byName(step, cohort))[LOST]).toEqual([
      'The database holds 7 requests of step orgs-100, but k6 was answered 201 for 8 new ones.',
    ]);
    expect((await byName({ ...step, created: Number.NaN }, cohort))[LOST]).toEqual([
      'k6 recorded no new request in step orgs-100, so nothing could be checked.',
    ]);
  });

  it('catch a reservation held in another organisation for a request not its own', async () => {
    const { a, b, step, cohort } = await aStep();
    await pastTheApp(b.w.org, (owner) =>
      owner.query(
        `insert into limit_reservations.reservations (
           org_id, id, request_id, agent_id, mandate_id, month, supplier_id, payee_key, amount_minor, currency, state,
           reserved_at, settled_at)
         select org_id, $3, $4, agent_id, mandate_id, month, supplier_id, payee_key, amount_minor, currency, state,
           reserved_at, settled_at
         from limit_reservations.reservations where org_id = $1 and request_id = $2`,
        [b.w.org, b.requests[1], ids.next(), a.requests[1]],
      ),
    );
    expect((await byName(step, cohort))[ELSEWHERE]).toEqual([
      `Organisation ${b.w.org} holds a reservation for the request ${a.requests[1]}, which is not its own.`,
    ]);
  });

  it('catch a month held past its agent’s limit', async () => {
    const { a, step, cohort } = await aStep();
    const huge = 1_000_000_000_000_000n;
    await pastTheApp(a.w.org, (owner) =>
      owner.query(
        'update limit_reservations.reservations set amount_minor = $3 where org_id = $1 and request_id = $2',
        [a.w.org, a.requests[1], huge.toString()],
      ),
    );
    const { month } = await everyOrganisation
      .selectFrom('limit_reservations.reservations')
      .select('month')
      .where('org_id', '=', a.w.org)
      .where('request_id', '=', a.requests[1])
      .executeTakeFirstOrThrow();
    const found = await byName(step, cohort);
    expect(found[LIMITS]).toEqual([
      `Organisation ${a.w.org}'s agent ${a.agent.agentId} holds ${String(huge + 210_000n)} fils in ${month}, over its limit of ${a.agent.monthlyLimitMinor}.`,
    ]);
    expect(
      found[`the active cohort: kept every agent’s month within its limit, and stopped the capped one at it`],
    ).toEqual([
      `Agent ${a.agent.agentId} holds ${String(huge + 210_000n)} fils this month, over its limit of ${a.agent.monthlyLimitMinor}.`,
    ]);
  });

  it('catch requests holding money with their reservations released, naming five and counting the rest', async () => {
    const { a, b, step, cohort } = await aStep();
    for (const org of [a.w.org, b.w.org]) {
      await pastTheApp(org, (owner) =>
        owner.query(
          "update limit_reservations.reservations set state = 'RELEASED', settled_at = reserved_at where org_id = $1",
          [org],
        ),
      );
    }
    const found = (await byName(step, cohort))[HOLDINGS] ?? [];
    expect(found).toHaveLength(6);
    expect(found.at(-1)).toBe('And 1 more like these.');
    expect(found[0]).toMatch(/is (APPROVED|APPROVAL_REQUIRED) but holds this: RELEASED, claim open\.$/);
  });

  it('catch an organisation put on an integrity hold during the step', async () => {
    const { a, step, cohort } = await aStep();
    await holdOrganisation(app, a.w.org, { keys, ids, logger: testLogger() }, 'planted by the Stage G checks test');
    const found = await byName(step, cohort);
    expect(found[HOLDS]).toEqual([`Organisation ${a.w.org} was put on an integrity hold during the step.`]);
    expect(found['the active cohort: put no organisation on an integrity hold']).toEqual([
      `Organisation ${a.w.org} was put on an integrity hold.`,
    ]);
  });
});
