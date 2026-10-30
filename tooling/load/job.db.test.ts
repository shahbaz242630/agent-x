// The load test's jobs (D2c, job.ts) against a migrated database, k6 stood
// in for (job.test.ts runs the real command): the first job only while every
// hand-off is paused; the second job and the clean-up only on the run's own
// organisations, its new keys, checks and clean-up, and the clean-up whatever
// phase 2 did.
import { changeHandoffPause, createPlatformChain } from '../../packages/core/src/modules/platform-controls/index.ts';
import { createDatabase, type Database } from '../../packages/platform/src/db/index.ts';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { keys } from '../../apps/api/src/mandate-world.helper.test.ts';
import { LOAD_CHECKS } from './checks.ts';
import { cleanUpFailures } from './cleanup.ts';
import {
  cleanupJob,
  firstJob,
  type JobSteps,
  type LoadTables,
  notTheRuns,
  type PhaseRun,
  type PrintedAgent,
  type PrintedLine,
  secondJob,
} from './job.ts';
import { type LoadPhase, orgsOf, type Seeded, SEEDED_AGENTS } from './plan.ts';
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

/** The platform's hand-off pause moved, as the operator's command moves it (B1). A migrated database is born paused. */
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

/** A job's steps over the test database, k6 answering as `answer` does and recording what it was given; every line printed kept. */
function stepsWith(
  answer: (phase: LoadPhase) => PhaseRun | Promise<PhaseRun> = () => ({ finished: true, result: NO_REQUESTS }),
) {
  const printed: PrintedLine[] = [];
  const k6Calls: { phase: LoadPhase; seeded: Seeded }[] = [];
  const steps: JobSteps = {
    database: app,
    keyring: keys,
    k6: (phase, seeded) => {
      k6Calls.push({ phase, seeded });
      return answer(phase);
    },
    print: (line) => printed.push(line),
  };
  const lineOf = (event: string) => printed.find((line) => line.event === event);
  return { steps, printed, k6Calls, lineOf };
}

/** A run seeded by the first job: its agents as load.ts collects them, one line each, and the keys k6 was given. */
async function seededRun(runId: string) {
  const first = stepsWith();
  expect(await firstJob(first.steps, runId)).toBe(0);
  const agents = first.printed
    .filter(({ event }) => event === 'load.seeded_agent')
    .map(({ agent }) => agent as PrintedAgent);
  return { agents, first, keys: first.k6Calls[0]?.seeded.agents.map(({ key }) => key) ?? [] };
}

const leftUndone = (agents: readonly PrintedAgent[]) =>
  cleanUpFailures(
    app,
    agents.map(({ orgId }) => orgId),
  );

describe('the load run on Azure, its jobs (D2c, PL-38)', () => {
  /** Changes the pause's row past the app, as its owner can: its signed history then no longer agrees with it. */
  const tamperPause = async (paused: boolean): Promise<void> => {
    const owner = await database.connect('owner');
    try {
      await owner.query('update platform_controls.handoff_pause set paused = $1', [paused]);
    } finally {
      await owner.end();
    }
  };

  it('refuses the first job, seeding nothing, while the pause is tampered with: nothing is believed', async () => {
    await tamperPause(false);
    try {
      const { steps, printed, k6Calls } = stepsWith();
      expect(await firstJob(steps, 'tampered')).toBe(1);
      expect(printed.map(({ reason }) => reason)).toEqual([
        'hand-offs are tampered before the seed, not paused: pause them (handoff-pause), so no request of the run can reach the bank',
      ]);
      expect(k6Calls).toEqual([]);
    } finally {
      await tamperPause(true);
    }
  });

  it('refuses the first job, seeding nothing, unless every hand-off is paused', async () => {
    await pauseMoved(false);
    try {
      const { steps, printed, k6Calls } = stepsWith();
      expect(await firstJob(steps, 'refused')).toBe(1);
      expect(printed).toEqual([
        {
          event: 'load.refused',
          reason:
            'hand-offs are running before the seed, not paused: pause them (handoff-pause), so no request of the run can reach the bank',
        },
      ]);
      expect(k6Calls).toEqual([]);
    } finally {
      await pauseMoved(true);
    }
  });

  it(
    'prints each agent without its key as it is seeded; phase 2 has new keys, runs every check and leaves the run inert',
    { timeout: 600_000 },
    async () => {
      const run = await seededRun('job test');
      expect(run.agents).toHaveLength(SEEDED_AGENTS);
      expect(run.first.lineOf('load.seeded')).toEqual({
        event: 'load.seeded',
        runId: 'job test',
        agents: SEEDED_AGENTS,
      });
      expect(JSON.stringify(run.first.printed)).not.toMatch(/"key"/);
      expect(run.keys.every((key) => key.length > 20)).toBe(true);

      const second = stepsWith(() => ({ finished: true, result: { ...NO_REQUESTS, phase: 2 } }));
      // No traffic stands in here, and the checks refuse to pass a run with none (the laptop's run holds them with it).
      expect(await secondJob(second.steps, 'job test', run.agents, 0)).toBe(1);
      expect(second.k6Calls.map(({ phase }) => phase)).toEqual([2, 3, 4]);
      const secondKeys = second.k6Calls[0]?.seeded.agents.map(({ key }) => key) ?? [];
      expect(secondKeys.filter((key, n) => key === run.keys[n] || key.length <= 20)).toEqual([]);
      const checked = second.lineOf('load.checked');
      expect(checked).toMatchObject({ created: 0, finished: true });
      const checks = checked?.checks as { name: string; problems: string[] }[];
      expect(checks.map(({ name }) => name)).toEqual(LOAD_CHECKS.map(({ name }) => name));
      expect(
        checks.find(({ problems }) => problems.includes('k6 recorded no new request, so nothing could be checked.')),
      ).toBeDefined();
      // What holds with no traffic at all: nothing handed off, one open claim an order, no integrity hold.
      expect(checks.filter(({ problems }) => problems.length === 0)).toHaveLength(3);
      expect(second.lineOf('load.cleaned')).toEqual({
        event: 'load.cleaned',
        organizations: orgsOf(run.agents).length,
        problems: [],
      });
      expect(await leftUndone(run.agents)).toEqual([]);

      // The clean-up alone, run again over the same run, finds the work done.
      expect(await cleanupJob(stepsWith().steps, 'job test', run.agents)).toBe(0);
    },
  );

  it(
    "touches nothing that isn't the run's: another run's organisation, or an ID from another organisation",
    { timeout: 600_000 },
    async () => {
      const run = await seededRun('job test owner');
      const [one, two] = run.agents;
      if (one === undefined || two === undefined) throw new Error('the seed made too few agents');
      expect(await notTheRuns(app, 'job test owner', run.agents)).toEqual([]);
      expect(await notTheRuns(app, 'another run', [one])).toEqual([
        `Organisation ${one.orgId} is not one of run another run's.`,
      ]);
      for (const borrowed of [
        { ...one, agentId: two.agentId },
        { ...one, sourceId: two.sourceId },
        { ...one, supplierIds: [...one.supplierIds, two.supplierIds[0] ?? ''] },
      ]) {
        expect(await notTheRuns(app, 'job test owner', [borrowed])).toEqual([
          `Agent ${borrowed.agentId}, its funding source or a supplier is not organisation ${one.orgId}'s.`,
        ]);
      }
      const refused = stepsWith();
      await expect(cleanupJob(refused.steps, 'another run', run.agents)).rejects.toThrow(/^Nothing was changed: /);
      await expect(secondJob(refused.steps, 'another run', run.agents, 0)).rejects.toThrow(/^Nothing was changed: /);
      await expect(secondJob(refused.steps, 'job test owner', run.agents.slice(0, 2), 0)).rejects.toThrow(
        "phase 2 needs the run's one capped agent",
      );
      expect(refused.printed).toEqual([]);
      expect(refused.k6Calls).toEqual([]);
      // Untouched: the organisations are still live, so their clean-up has everything left to do.
      expect(await leftUndone(run.agents)).not.toEqual([]);
      expect(await cleanupJob(stepsWith().steps, 'job test owner', run.agents)).toBe(0);
    },
  );

  it(
    'cleans the run up when phase 2 stops half-way, throws, or finds hand-offs running',
    { timeout: 600_000 },
    async () => {
      const stopped = await seededRun('job test stopped');
      const second = stepsWith(() => ({ finished: false, result: undefined }));
      expect(await secondJob(second.steps, 'job test stopped', stopped.agents, 0)).toBe(1);
      expect(second.lineOf('load.checked')).toMatchObject({ finished: false });
      expect(second.lineOf('load.cleaned')).toMatchObject({ problems: [] });
      expect(await leftUndone(stopped.agents)).toEqual([]);

      const thrown = await seededRun('job test thrown');
      const broken = new Error('k6 could not start');
      const throwing = stepsWith(() => {
        throw broken;
      });
      await expect(secondJob(throwing.steps, 'job test thrown', thrown.agents, 0)).rejects.toBe(broken);
      expect(throwing.lineOf('load.cleaned')).toMatchObject({ problems: [] });
      expect(await leftUndone(thrown.agents)).toEqual([]);

      // Resumed while phase 2 ran: the run fails, said, and is still cleaned up.
      const during = await seededRun('job test during');
      const resuming = stepsWith(async () => {
        await pauseMoved(false);
        return { finished: true, result: { ...NO_REQUESTS, phase: 2 } };
      });
      try {
        expect(await secondJob(resuming.steps, 'job test during', during.agents, 0)).toBe(1);
        expect(resuming.lineOf('load.refused')?.reason).toMatch(/^hand-offs are running after the phases, not paused/);
      } finally {
        await pauseMoved(true);
      }
      expect(await leftUndone(during.agents)).toEqual([]);

      const resumed = await seededRun('job test resumed');
      await pauseMoved(false);
      try {
        const refused = stepsWith();
        expect(await secondJob(refused.steps, 'job test resumed', resumed.agents, 0)).toBe(1);
        expect(refused.lineOf('load.refused')?.reason).toMatch(/^hand-offs are running before phase 2, not paused/);
        expect(refused.k6Calls).toEqual([]);
        expect(refused.lineOf('load.cleaned')).toMatchObject({ problems: [] });
        expect(await leftUndone(resumed.agents)).toEqual([]);
      } finally {
        await pauseMoved(true);
      }
    },
  );
});
