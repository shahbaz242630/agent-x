// The freeze asked during phase 5 (PL-63 item 3) against a migrated database:
// its answer in each case the report has to word, whether it holds a lock's wait
// open, and whether the database checks and the clean-up accept what it leaves.
import { createDatabase, type Database, withTenant } from '../../packages/platform/src/db/index.ts';
import {
  createTestDatabase,
  FixedClock,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createMandateRegistry } from '../../apps/api/src/mandate-registry.ts';
import { AED, keys, mandateWorld, type MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { LOAD_CHECKS } from './checks.ts';
import { cleanUpFailures, cleanUpRun } from './cleanup.ts';
import { probeFreeze } from './freeze-probe.ts';
import { firstJob, type JobSteps, type LoadTables, secondJob } from './job.ts';
import type { PhaseResult } from './report.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;
const clock = new FixedClock(new Date());
const ids = new SequentialIds(0xf5ee_0000_0000);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'freeze-probe', keyring: keys });

/** An organisation as the seed makes it, its supplier verified. */
async function stuckOrg() {
  const w = await shared.world({ suppliers: 1 });
  for (const id of w.suppliers) await shared.verified(w, id);
  const registry = createMandateRegistry({ database: app, keys, ids, clock, logger: testLogger() });
  await shared.inForce(registry, w, { approvalThreshold: AED(500n), splitCheck: false });
  return { w, agents: [{ kind: 'neighbour-stuck' as const, orgId: w.org }] };
}

const statusOf = (orgId: string) =>
  withTenant(app, orgId, (tx) =>
    tx.selectFrom('organizations.organizations').select('status').executeTakeFirstOrThrow(),
  );

describe('an admin’s freeze asked of the stuck organisation', () => {
  it('freezes it, says so, and pausing leaves what its requests hold for the checks and the clean-up', async () => {
    const { w, agents } = await stuckOrg();
    expect(await probeFreeze(app, keys, agents)).toEqual({ ms: expect.any(Number) as number, answer: 'frozen' });
    expect(await statusOf(w.org)).toEqual({ status: 'FROZEN' });

    // The clean-up finds it frozen already, and leaves it inert.
    await cleanUpRun(app, keys, [w.org]);
    expect(await cleanUpFailures(app, [w.org])).toEqual([]);
  });

  it('says what it was answered when asked twice: the same key, the same click', async () => {
    const { agents } = await stuckOrg();
    await probeFreeze(app, keys, agents);
    expect((await probeFreeze(app, keys, agents)).answer).toBe('frozen');
  });

  it('says its lock’s wait ran out when decisions hold the organisation’s row past it, and freezes nothing', async () => {
    const { w, agents } = await stuckOrg();
    const { promise: held, resolve: holds } = Promise.withResolvers<undefined>();
    const { promise: release, resolve: lets } = Promise.withResolvers<undefined>();
    const holder = withTenant(app, w.org, async (tx) => {
      await tx.selectFrom('organizations.organizations').select('id').forShare().execute();
      holds(undefined);
      await release;
    });
    await held;
    let probed;
    try {
      const probing = probeFreeze(app, keys, agents);
      await waitUntilQueued(database.as('admin'), 1);
      probed = await probing;
    } finally {
      lets(undefined);
      await holder;
    }
    expect(probed.answer).toBe("not frozen: its wait for the organisation's lock ran out");
    expect(probed.ms).toBeGreaterThan(1_000);
    expect(await statusOf(w.org)).toEqual({ status: 'ACTIVE' });
  });

  it('says so when the run has no stuck organisation, never throwing into the run', async () => {
    expect(await probeFreeze(app, keys, [{ kind: 'neighbour-calm', orgId: 'x' }])).toEqual({
      ms: expect.any(Number) as number,
      answer: 'not frozen: the run has no stuck organisation',
    });
  });

  it('says so when no admin of the organisation can be found, never throwing into the run', async () => {
    const stranger = '019b0000-0000-7000-8000-00000000f5ee';
    expect((await probeFreeze(app, keys, [{ kind: 'neighbour-stuck', orgId: stranger }])).answer).toMatch(
      /^not frozen: /,
    );
  });
});

describe('the second job’s phase 5', () => {
  const NO_REQUESTS: PhaseResult = {
    phase: 5,
    requests: 0,
    created: 0,
    serverErrors: 0,
    rateLimited: 0,
    checksFailed: 0,
    dropped: 0,
    asksMs: { p50: 0, p95: 0, p99: 0, max: 0 },
    spikeMs: null,
    thresholds: {},
  };

  it(
    'prints the freeze’s answer for the report, and every check and the clean-up accept the frozen organisation',
    { timeout: 600_000 },
    async () => {
      // The job's own tables, its hand-off pause's among them; a migrated database is born paused.
      const loadApp = createDatabase<LoadTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
      try {
        const printed: Record<string, unknown>[] = [];
        const steps = (k6: JobSteps['k6'], freezeProbeAfterMs: number): JobSteps => ({
          database: loadApp,
          keyring: keys,
          k6,
          print: (line) => printed.push(line),
          freezeProbeAfterMs,
        });
        expect(
          await firstJob(
            steps(() => ({ finished: true, result: NO_REQUESTS }), 0),
            'probe run',
          ),
        ).toBe(0);
        const agents = printed
          .filter(({ event }) => event === 'load.seeded_agent')
          .map(({ agent }) => agent as Parameters<typeof secondJob>[2][number]);

        const second = steps(async (phase) => {
          // Phase 5 waits long enough for the freeze to be asked and answered, as k6's does.
          if (phase === 5) await new Promise((resolve) => setTimeout(resolve, 1_000));
          return { finished: true, result: { ...NO_REQUESTS, phase } };
        }, 0);
        // No traffic stands in here, so the count's check fails; the frozen organisation's others must not.
        expect(await secondJob(second, 'probe run', agents, 0)).toBe(1);
        expect(printed.find(({ event }) => event === 'load.freeze_probe')).toEqual({
          event: 'load.freeze_probe',
          ms: expect.any(Number) as number,
          answer: 'frozen',
        });
        const checked = printed.find(({ event }) => event === 'load.checked');
        const checks = checked?.checks as { name: string; problems: string[] }[];
        expect(checks.map(({ name }) => name)).toEqual(LOAD_CHECKS.map(({ name }) => name));
        expect(checks.filter(({ problems }) => problems.length === 0)).toHaveLength(3);
        expect(printed.find(({ event }) => event === 'load.cleaned')).toMatchObject({ problems: [] });
      } finally {
        await loadApp.destroy();
      }
    },
  );
});
