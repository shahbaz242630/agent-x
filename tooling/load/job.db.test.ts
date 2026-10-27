// The load test's jobs (D2c, job.ts) against a migrated database, k6 stood
// in for (job.test.ts runs the real command): the first job only while every
// hand-off is paused, the second job's new keys, checks and clean-up, and the
// clean-up whatever phase 2 did.
import { changeHandoffPause, createPlatformChain } from '../../packages/core/src/modules/platform-controls/index.ts';
import { createDatabase, type Database } from '../../packages/platform/src/db/index.ts';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { keys } from '../../apps/api/src/mandate-world.helper.test.ts';
import { cleanUpFailures } from './cleanup.ts';
import {
  cleanupJob,
  firstJob,
  type JobSteps,
  type LoadTables,
  type PhaseRun,
  type PrintedAgent,
  secondJob,
} from './job.ts';
import { AMPLE_AGENTS, type Seeded } from './plan.ts';
import type { PhaseResult } from './report.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<LoadTables>;
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xd2c0_0000_0000) });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<LoadTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** The platform's hand-off pause moved, as the operator's command moves it (B1). */
const pauseMoved = (paused: boolean) =>
  app
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused, reason: 'TEST-D2C', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );

const NO_REQUESTS: PhaseResult = {
  phase: 1,
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

/** A job's steps over the test database, k6 answering `answer` and recording what it was given; every line printed kept. */
function stepsWith(answer: PhaseRun = { finished: true, result: NO_REQUESTS }) {
  const printed: ({ readonly event: string } & Record<string, unknown>)[] = [];
  const k6Calls: { phase: 1 | 2; seeded: Seeded }[] = [];
  const steps: JobSteps = {
    database: app,
    keyring: keys,
    k6: (phase, seeded) => {
      k6Calls.push({ phase, seeded });
      return answer;
    },
    print: (line) => printed.push(line),
  };
  const lineOf = (event: string) => printed.find((line) => line.event === event);
  return { steps, printed, k6Calls, lineOf };
}

describe('the load run on Azure, its jobs (D2c, PL-38)', () => {
  it('refuses the first job, seeding nothing, unless every hand-off is paused', async () => {
    await pauseMoved(false);
    try {
      const { steps, printed, k6Calls } = stepsWith();
      expect(await firstJob(steps, 'refused')).toBe(1);
      expect(printed).toEqual([
        {
          event: 'load.refused',
          reason:
            'hand-offs are running, not paused: pause them first (handoff-pause), so no request of the run can reach the bank',
        },
      ]);
      expect(k6Calls).toEqual([]);
    } finally {
      await pauseMoved(true);
    }
  });

  it(
    'seeds while paused, prints the agents without keys, then phase 2 has new keys, runs every check and leaves the run inert',
    { timeout: 600_000 },
    async () => {
      const first = stepsWith();
      expect(await firstJob(first.steps, 'job test')).toBe(0);
      const seeded = first.lineOf('load.seeded');
      const agents = seeded?.agents as PrintedAgent[];
      expect(agents).toHaveLength(AMPLE_AGENTS + 1);
      expect(JSON.stringify(seeded)).not.toMatch(/"key"/);
      expect(first.k6Calls.map(({ phase }) => phase)).toEqual([1]);
      const firstKeys = first.k6Calls[0]?.seeded.agents.map(({ key }) => key) ?? [];
      expect(firstKeys.every((key) => key.length > 20)).toBe(true);

      const second = stepsWith({ finished: true, result: { ...NO_REQUESTS, phase: 2 } });
      // No traffic stands in here, and the checks refuse to pass a run with none (the laptop's run holds them with it).
      expect(await secondJob(second.steps, agents, 0)).toBe(1);
      const secondKeys = second.k6Calls[0]?.seeded.agents.map(({ key }) => key) ?? [];
      expect(secondKeys.filter((key, n) => key === firstKeys[n] || key.length <= 20)).toEqual([]);
      const checked = second.lineOf('load.checked');
      expect(checked).toMatchObject({ created: 0, finished: true });
      const checks = checked?.checks as { name: string; problems: string[] }[];
      expect(checks.map(({ name }) => name)).toHaveLength(6);
      expect(
        checks.find(({ problems }) => problems.includes('k6 recorded no new request, so nothing could be checked.')),
      ).toBeDefined();
      // What holds with no traffic at all: nothing handed off, one open claim an order, no integrity hold.
      expect(checks.filter(({ problems }) => problems.length === 0)).toHaveLength(3);
      expect(second.lineOf('load.cleaned')).toEqual({
        event: 'load.cleaned',
        organizations: agents.length,
        problems: [],
      });
      expect(
        await cleanUpFailures(
          app,
          agents.map(({ orgId }) => orgId),
        ),
      ).toEqual([]);

      // The clean-up alone, run again over the same run, finds the work done.
      const again = stepsWith();
      expect(await cleanupJob(again.steps, agents)).toBe(0);
    },
  );

  it('cleans the run up even when phase 2 stops half-way, and says the job failed', { timeout: 600_000 }, async () => {
    const first = stepsWith();
    expect(await firstJob(first.steps, 'job test stopped')).toBe(0);
    const agents = first.lineOf('load.seeded')?.agents as PrintedAgent[];
    const second = stepsWith({ finished: false, result: undefined });
    expect(await secondJob(second.steps, agents, 0)).toBe(1);
    expect(second.lineOf('load.checked')).toMatchObject({ finished: false });
    expect(second.lineOf('load.cleaned')).toMatchObject({ problems: [] });
    expect(
      await cleanUpFailures(
        app,
        agents.map(({ orgId }) => orgId),
      ),
    ).toEqual([]);
  });
});
