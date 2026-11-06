// Stage G's seed (stageg-seed.ts) against a migrated database: each kind made
// through the app's own path, a re-run making only what is missing, an
// organisation made by another execution at the same moment counted as found,
// a half-made active one reported and left out of the cohort, and the cohort
// read back from the database by the run's IDs.
import { withSignedStates } from '../../packages/core/src/modules/audit/index.ts';
import { createOrganization, OrganizationRefused } from '../../packages/core/src/modules/organizations/index.ts';
import { uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import { createDatabase, type Database, withTenant } from '../../packages/platform/src/db/index.ts';
import type { KeyProvider } from '../../packages/platform/src/keys/index.ts';
import {
  createTestDatabase,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { keys, type MandateWorldTables, OPERATOR } from '../../apps/api/src/mandate-world.helper.test.ts';
import { loadOrgName } from './plan.ts';
import { stageGCohort, stageGOrgId, stageGSeed } from './stageg-seed.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

const seeded = (runId: string, orgs: number, workers = 3, hugeChainEvents = 5, keyring: KeyProvider = keys) =>
  stageGSeed({ database: app, keyring, runId, orgs, workers, hugeChainEvents });

const eventsOf = (orgId: string, action: string) =>
  withTenant(app, orgId, async (tx) =>
    Number(
      (
        await tx
          .selectFrom('audit.events')
          .select((eb) => eb.fn.countAll<string>().as('n'))
          .where('action', '=', action)
          .executeTakeFirstOrThrow()
      ).n,
    ),
  );

/** An organisation of the run made as the operator makes one, and nothing more: an active one stopped half-way. */
const bareOrganisation = (orgId: string, runId: string) =>
  withSignedStates(app, orgId, { keys, ids: uuidV7Ids, logger: testLogger() }, (tx, states) =>
    createOrganization(tx, states, { id: orgId, name: loadOrgName(runId), actor: OPERATOR }),
  );

describe('stageGSeed', () => {
  it('makes each kind through the app, then grows the set making only what is missing', async () => {
    const first = await seeded('grow', 6);
    expect(first).toMatchObject({
      orgs: 6,
      found: 0,
      made: { idle: 3, light: 1, heavy: 1, 'huge-chain': 1 },
      incomplete: [],
    });
    expect(Object.values(first.seconds).every((seconds) => seconds > 0)).toBe(true);
    // The long chain: its source refreshed five times, each its own signed event.
    expect(await eventsOf(stageGOrgId('grow', 0), 'funding_source.partner_changed')).toBe(5);
    // An idle organisation: founded, its admin joined, its cap chosen and a supplier verified.
    expect(await eventsOf(stageGOrgId('grow', 3), 'organization.created')).toBe(1);
    expect(await eventsOf(stageGOrgId('grow', 3), 'membership.created')).toBe(1);
    expect(await eventsOf(stageGOrgId('grow', 3), 'policy_version.made')).toBe(1);
    expect(await eventsOf(stageGOrgId('grow', 3), 'supplier.verify')).toBe(1);

    const grown = await seeded('grow', 8);
    expect(grown).toMatchObject({
      found: 6,
      made: { idle: 2, light: 0, heavy: 0, 'huge-chain': 0 },
      incomplete: [],
    });
  });

  it('finishes a long chain an earlier execution stopped short, to the exact length', async () => {
    await seeded('chain', 1, 1, 3);
    expect(await eventsOf(stageGOrgId('chain', 0), 'funding_source.partner_changed')).toBe(3);
    expect(await seeded('chain', 1, 1, 5)).toMatchObject({ found: 1, refreshesAdded: 2, incomplete: [] });
    expect(await eventsOf(stageGOrgId('chain', 0), 'funding_source.partner_changed')).toBe(5);
    expect(await seeded('chain', 1, 1, 5)).toMatchObject({ found: 1, refreshesAdded: 0 });
    expect(await eventsOf(stageGOrgId('chain', 0), 'funding_source.partner_changed')).toBe(5);
  });

  it('leaves no trace of an idle organisation that failed inside its transaction, and makes it whole on a re-run', async () => {
    await seeded('idle-fail', 3);
    // The supplier's contact is the idle organisation's one encryption, after it is founded, joined and capped.
    const failing = new Proxy(keys, {
      get: (target, name, receiver) =>
        name === 'encrypt'
          ? () => {
              throw new Error('no encryption key');
            }
          : (Reflect.get(target, name, receiver) as unknown),
    });
    await expect(seeded('idle-fail', 4, 1, 5, failing)).rejects.toThrow('no encryption key');
    expect(await eventsOf(stageGOrgId('idle-fail', 3), 'organization.created')).toBe(0);
    expect(await eventsOf(stageGOrgId('idle-fail', 3), 'membership.created')).toBe(0);
    expect(await seeded('idle-fail', 4)).toMatchObject({ found: 3, made: { idle: 1 }, incomplete: [] });
    expect(await eventsOf(stageGOrgId('idle-fail', 3), 'supplier.verify')).toBe(1);
  });

  it('judges an organisation another execution made at the same moment as any found: here half-made', async () => {
    const orgId = stageGOrgId('race', 0);
    const { promise: held, resolve: holds } = Promise.withResolvers<undefined>();
    const { promise: release, resolve: lets } = Promise.withResolvers<undefined>();
    // Index 0 alone is the long chain's: its first step founds the organisation, as the holder already has.
    const holder = withSignedStates(app, orgId, { keys, ids: uuidV7Ids, logger: testLogger() }, async (tx, states) => {
      await createOrganization(tx, states, { id: orgId, name: loadOrgName('race'), actor: OPERATOR });
      holds(undefined);
      await release;
    });
    await held;
    const seeding = seeded('race', 1, 1);
    try {
      await waitUntilQueued(database.as('admin'), 1);
    } finally {
      lets(undefined);
      await holder;
    }
    // The other execution founded it and stopped: no agent, so it is incomplete, never counted found.
    expect(await seeding).toMatchObject({ found: 0, made: { 'huge-chain': 0 }, incomplete: [0] });
  });

  it('reports an active organisation found half-made, and leaves it out of the cohort', async () => {
    await bareOrganisation(stageGOrgId('half', 2), 'half');
    const seed = await seeded('half', 3);
    expect(seed).toMatchObject({ found: 0, made: { light: 0, heavy: 1, 'huge-chain': 1 }, incomplete: [2] });
    await expect(stageGCohort({ database: app, runId: 'half', orgs: 3, mix: 'steady' })).rejects.toThrow(
      "The steady cohort of run half's first 3 organisations has no ample agent: organisations 2 are half-made (an execution stopped inside each) and left out. A re-run can't finish them and their audit chains can't be removed: seed more organisations, so whole ones take their place, or seed under a new run ID.",
    );
  });

  it(
    'never makes a half-made heavy organisation the busy one: the next whole one is',
    { timeout: 120_000 },
    async () => {
      await bareOrganisation(stageGOrgId('heavy', 1), 'heavy');
      expect(await seeded('heavy', 202, 5)).toMatchObject({ made: { heavy: 1 }, incomplete: [1] });
      const cohort = stageGCohort({ database: app, runId: 'heavy', orgs: 202, mix: 'neighbours' });
      await expect(cohort).rejects.toThrow('has no neighbour-stuck agent: organisations 1 are half-made');
    },
  );

  it('throws what failed: a name no organisation may have', async () => {
    await expect(
      stageGSeed({ database: app, keyring: keys, runId: 'x'.repeat(300), orgs: 1, workers: 1 }),
    ).rejects.toThrow(OrganizationRefused);
  });
});

describe('stageGCohort', () => {
  it("reads the steady cohort's agents from the database by the run's IDs", async () => {
    await seeded('cohort', 3);
    const agents = await stageGCohort({ database: app, runId: 'cohort', orgs: 3, mix: 'steady' });
    expect(agents).toEqual([
      {
        kind: 'ample',
        orgId: stageGOrgId('cohort', 2),
        agentId: expect.any(String) as string,
        sourceId: expect.any(String) as string,
        supplierIds: [expect.any(String), expect.any(String), expect.any(String)] as string[],
        monthlyLimitMinor: expect.stringMatching(/^\d+$/) as string,
      },
    ]);
    await expect(stageGCohort({ database: app, runId: 'cohort', orgs: 3, mix: 'neighbours' })).rejects.toThrow(
      'has no neighbour-stuck agent',
    );
  });
});
