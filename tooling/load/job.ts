/**
 * The load test's jobs on Azure (Phase 4 D2c, PL-38), run by the load image
 * (tooling/load/Dockerfile) inside staging's network, as the app's own role
 * with the app's keys, the way the laptop's run (run.ts) does each step:
 *
 *   node tooling/load/job.ts first     the hand-off pause read, the seed, k6's phase 1
 *   node tooling/load/job.ts second    new keys, k6's phase 2, the database checks, the clean-up
 *   node tooling/load/job.ts cleanup   the clean-up alone, for a run that stopped half-way
 *
 * Between the two, deploy/azure/load.ts restarts the API, as the laptop's run
 * does, so its holdings check runs over phase 1's requests. Each job keeps no
 * files: what the report needs it prints as one JSON line (`event`), which
 * Log Analytics keeps and load.ts reads. The agents' keys are never printed:
 * the second job makes its own, and is given the run's agents without them
 * (`load.seeded`, read back by load.ts), as no job can list the run's
 * organisations, each behind its own tenant wall.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  handoffPauseOf,
  type PlatformControlsTables,
} from '../../packages/core/src/modules/platform-controls/index.ts';
import { createDatabase, type Database } from '../../packages/platform/src/db/index.ts';
import { type KeyProvider, loadKeys } from '../../packages/platform/src/keys/index.ts';
import { createStartupLogger } from '../../packages/platform/src/observability/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { LOAD_CHECKS } from './checks.ts';
import { cleanUpFailures, cleanUpRun } from './cleanup.ts';
import { loadConnection, type Seeded, type SeededAgent } from './plan.ts';
import type { PhaseResult } from './report.ts';
import { rekeyed, seedRun } from './seed.ts';

export type LoadTables = MandateWorldTables & PlatformControlsTables;

/** One of the run's agents as a job may print it: everything the next job needs but its key. */
export type PrintedAgent = Omit<SeededAgent, 'key'>;

/** k6's answer for one phase: whether it ran to the end (its thresholds are the report's to judge), and its numbers. */
export interface PhaseRun {
  readonly finished: boolean;
  readonly result: PhaseResult | undefined;
}

export interface JobSteps {
  readonly database: Database<LoadTables>;
  readonly keyring: KeyProvider;
  readonly k6: (phase: 1 | 2, seeded: Seeded) => PhaseRun;
  readonly print: (line: { readonly event: string } & Record<string, unknown>) => void;
}

const printed = (seeded: Seeded): PrintedAgent[] => seeded.agents.map(({ key: _key, ...agent }) => agent);

/**
 * Phase 1: only while every hand-off is paused, so no request of the run is
 * ever handed to the bank (PL-46), then the seed and k6. 0 when k6 ran to the end.
 */
export async function firstJob(steps: JobSteps, runId: string): Promise<number> {
  const logger = createStartupLogger({ service: 'load' });
  const pause = await steps.database
    .transaction()
    .execute((tx) => handoffPauseOf(tx, 'share', { keys: steps.keyring, logger }));
  if (pause.outcome !== 'paused') {
    steps.print({
      event: 'load.refused',
      reason: `hand-offs are ${pause.outcome}, not paused: pause them first (handoff-pause), so no request of the run can reach the bank`,
    });
    return 1;
  }
  const seeded = await seedRun({ database: steps.database, keyring: steps.keyring, runId });
  steps.print({ event: 'load.seeded', runId, agents: printed(seeded) });
  return steps.k6(1, seeded).finished ? 0 : 1;
}

/**
 * The clean-up of the run's organisations (cleanup.ts), and what it left
 * undone, printed. 0 when every organisation is inert.
 */
export async function cleanupJob(steps: JobSteps, agents: readonly PrintedAgent[]): Promise<number> {
  const orgIds = agents.map(({ orgId }) => orgId);
  let problems: string[];
  try {
    await cleanUpRun(steps.database, steps.keyring, orgIds);
    problems = await cleanUpFailures(steps.database, orgIds);
  } catch (error) {
    problems = [`The clean-up stopped: ${error instanceof Error ? error.message : String(error)}`];
  }
  steps.print({ event: 'load.cleaned', organizations: orgIds.length, problems });
  return problems.length === 0 ? 0 : 1;
}

/**
 * Phase 2: a new key for each agent, k6, then the database checks over both
 * phases' requests, and the clean-up whatever they found. 0 when k6 ran to
 * the end, every check held and every organisation is inert.
 */
export async function secondJob(
  steps: JobSteps,
  agents: readonly PrintedAgent[],
  createdFirst: number,
): Promise<number> {
  // The run's organisations are made inert whatever phase 2 does: on staging they stay.
  const held = await phaseTwo(steps, agents, createdFirst).catch(async (error: unknown) => {
    await cleanupJob(steps, agents);
    throw error;
  });
  const cleaned = (await cleanupJob(steps, agents)) === 0;
  return held && cleaned ? 0 : 1;
}

/** New keys, k6's phase 2 and the checks, printed: true when k6 ran to the end and every check held. */
async function phaseTwo(steps: JobSteps, agents: readonly PrintedAgent[], createdFirst: number): Promise<boolean> {
  const seeded = await rekeyed(steps.database, steps.keyring, {
    agents: agents.map((agent) => ({ ...agent, key: '' })),
  });
  const phase = steps.k6(2, seeded);
  const created = createdFirst + (phase.result?.created ?? 0);
  const checks = [];
  for (const check of LOAD_CHECKS) {
    checks.push({ name: check.name, problems: await check.run(steps.database, seeded.agents, created) });
  }
  steps.print({ event: 'load.checked', created, finished: phase.finished, checks });
  return phase.finished && checks.every(({ problems }) => problems.length === 0);
}

/** Where the k6 script is, in the image as in the repository. */
const K6_SCRIPT = fileURLToPath(new URL('./money-paths.k6.js', import.meta.url));

/** k6 answers 99 when a threshold failed: it ran to the end, and the report says which. */
const K6_THRESHOLD_FAILED = 99;

/**
 * Runs k6 for one phase against the API, the seed's keys in a file only this
 * user can read, in a folder removed after. Its summary line goes to stdout
 * as it prints it (`load.k6_summary`). `k6` is the command and its first
 * arguments: tests put a stand-in there.
 */
export function runK6(api: string, k6: readonly [string, ...string[]] = ['k6']) {
  const [command, ...first] = k6;
  return (phase: 1 | 2, seeded: Seeded): PhaseRun => {
    const dir = mkdtempSync(path.join(tmpdir(), 'agentx-load-'));
    try {
      const seed = path.join(dir, 'seed.json');
      writeFileSync(seed, JSON.stringify(seeded), { mode: 0o600 });
      const done = spawnSync(command, [...first, 'run', '--quiet', K6_SCRIPT], {
        env: { ...process.env, PHASE: String(phase), API: api, SEED: seed, OUT: dir },
        stdio: 'inherit',
        windowsHide: true,
      });
      const finished = done.error === undefined && (done.status === 0 || done.status === K6_THRESHOLD_FAILED);
      if (!finished) return { finished, result: undefined };
      return {
        finished,
        result: JSON.parse(readFileSync(path.join(dir, `k6-phase-${String(phase)}.json`), 'utf8')) as PhaseResult,
      };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

class JobRefused extends Error {}

/** A setting the job can't run without. */
function needed(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') throw new JobRefused(`${name} is not set.`);
  return value;
}

const STRING_FIELDS = ['orgId', 'agentId', 'sourceId', 'monthlyLimitMinor'] as const;

/** The run's agents as load.ts hands them on (`load.seeded`), or a refusal saying what is wrong with them. */
export function agentsOf(text: string): PrintedAgent[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new JobRefused('AGENTX_LOAD_SEEDED is not JSON.');
  }
  const agents = Array.isArray(parsed) ? (parsed as unknown[]) : [];
  const whole = (agent: unknown): agent is PrintedAgent => {
    if (typeof agent !== 'object' || agent === null) return false;
    const fields = agent as Record<string, unknown>;
    return (
      (fields.kind === 'ample' || fields.kind === 'capped') &&
      STRING_FIELDS.every((name) => typeof fields[name] === 'string' && fields[name] !== '') &&
      Array.isArray(fields.supplierIds) &&
      fields.supplierIds.length > 0 &&
      fields.supplierIds.every((id) => typeof id === 'string') &&
      !('key' in fields)
    );
  };
  if (agents.length === 0 || !agents.every(whole)) {
    throw new JobRefused("AGENTX_LOAD_SEEDED must be the run's agents as load.seeded printed them, without keys.");
  }
  return agents;
}

/** The job's command line and settings, run. */
export async function main(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const [job, ...rest] = argv;
  if ((job !== 'first' && job !== 'second' && job !== 'cleanup') || rest.length > 0) {
    throw new JobRefused('Run it as node tooling/load/job.ts <first|second|cleanup>.');
  }
  const connection = loadConnection({
    AGENTX_LOAD_DB_HOST: needed(env, 'AGENTX_LOAD_DB_HOST'),
    AGENTX_LOAD_DB_PASSWORD: readFileSync(needed(env, 'AGENTX_DB_PASSWORD_FILE'), 'utf8').trim(),
  });
  const database = createDatabase<LoadTables>(connection, testLogger());
  try {
    const steps: JobSteps = {
      database,
      keyring: loadKeys({ directory: needed(env, 'AGENTX_KEYS_DIR'), current: {} }),
      k6: runK6(needed(env, 'AGENTX_LOAD_API')),
      print: (line) => {
        console.log(JSON.stringify(line));
      },
    };
    if (job === 'first') return await firstJob(steps, needed(env, 'AGENTX_LOAD_RUN_ID'));
    const agents = agentsOf(needed(env, 'AGENTX_LOAD_SEEDED'));
    if (job === 'cleanup') return await cleanupJob(steps, agents);
    const createdFirst = Number(needed(env, 'AGENTX_LOAD_CREATED_FIRST'));
    if (!Number.isSafeInteger(createdFirst) || createdFirst < 0) {
      throw new JobRefused('AGENTX_LOAD_CREATED_FIRST must be phase 1’s count of new requests.');
    }
    return await secondJob(steps, agents, createdFirst);
  } finally {
    await database.destroy();
  }
}

if (import.meta.main) {
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (error) {
    if (!(error instanceof JobRefused)) throw error;
    console.log(JSON.stringify({ event: 'load.refused', reason: error.message }));
    process.exitCode = 1;
  }
}
