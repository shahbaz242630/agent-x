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
 * (`load.seeded_agent`, read back by load.ts), as no job can list the run's
 * organisations, each behind its own tenant wall. What it is given it checks
 * first: every organisation named for the run, every ID in it its own, so a
 * wrong line can never freeze anyone else's organisation (S153 review).
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
import { createDatabase, type Database, withTenant } from '../../packages/platform/src/db/index.ts';
import { type KeyProvider, loadKeys } from '../../packages/platform/src/keys/index.ts';
import { createStartupLogger } from '../../packages/platform/src/observability/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { LOAD_CHECKS } from './checks.ts';
import { cleanUpFailures, cleanUpRun } from './cleanup.ts';
import { loadConnection, loadOrgName, type Seeded, type SeededAgent } from './plan.ts';
import type { PhaseResult } from './report.ts';
import { rekeyed, seedRun } from './seed.ts';

export type LoadTables = MandateWorldTables & PlatformControlsTables;

/** One of the run's agents as a job may print it: everything the next job needs but its key. */
export type PrintedAgent = Omit<SeededAgent, 'key'>;

/** One line a job prints, for Log Analytics and load.ts. */
export type PrintedLine = { readonly event: string } & Record<string, unknown>;

/** k6's answer for one phase: whether it ran to the end (its thresholds are the report's to judge), and its numbers. */
export interface PhaseRun {
  readonly finished: boolean;
  readonly result: PhaseResult | undefined;
}

export interface JobSteps {
  readonly database: Database<LoadTables>;
  readonly keyring: KeyProvider;
  readonly k6: (phase: 1 | 2, seeded: Seeded) => PhaseRun | Promise<PhaseRun>;
  readonly print: (line: PrintedLine) => void;
}

/** A job's refusal, said in its own words: it has changed nothing. */
class JobRefused extends Error {}

const withoutKey = ({ key: _key, ...agent }: SeededAgent): PrintedAgent => agent;

/**
 * Whether every hand-off is paused, so no request of the run can reach the
 * bank (PL-46); when not, said. `tampered` counts as not: nothing is believed.
 */
async function handoffsPaused(steps: JobSteps, when: string): Promise<boolean> {
  const logger = createStartupLogger({ service: 'load' });
  const pause = await steps.database
    .transaction()
    .execute((tx) => handoffPauseOf(tx, 'share', { keys: steps.keyring, logger }));
  if (pause.outcome === 'paused') return true;
  steps.print({
    event: 'load.refused',
    reason: `hand-offs are ${pause.outcome} ${when}, not paused: pause them (handoff-pause), so no request of the run can reach the bank`,
  });
  return false;
}

/**
 * Phase 1: only while every hand-off is paused, then the seed, each agent
 * printed as it is made (a seed that stops half-way leaves them all
 * findable), then k6. 0 when k6 ran to the end.
 */
export async function firstJob(steps: JobSteps, runId: string): Promise<number> {
  if (!(await handoffsPaused(steps, 'before the seed'))) return 1;
  const seeded = await seedRun({
    database: steps.database,
    keyring: steps.keyring,
    runId,
    onSeeded: (agent) => {
      steps.print({ event: 'load.seeded_agent', runId, agent: withoutKey(agent) });
    },
  });
  steps.print({ event: 'load.seeded', runId, agents: seeded.agents.length });
  return (await steps.k6(1, seeded)).finished ? 0 : 1;
}

/**
 * Why the agents handed to a job aren't all the run's own, read through each
 * organisation's tenant wall: its name must be the run's, and the agent, the
 * funding source and every supplier must be in it. Nothing when they are.
 */
export async function notTheRuns(
  database: Database<LoadTables>,
  runId: string,
  agents: readonly PrintedAgent[],
): Promise<string[]> {
  const found: string[] = [];
  for (const agent of agents) {
    const wrong = await withTenant(database, agent.orgId, async (tx) => {
      const org = await tx.selectFrom('organizations.organizations').select('name').executeTakeFirst();
      if (org?.name !== loadOrgName(runId)) return `Organisation ${agent.orgId} is not one of run ${runId}'s.`;
      const count = async (table: 'agents.agents' | 'funding_sources.sources' | 'suppliers.suppliers', ids: string[]) =>
        Number(
          (
            await tx
              .selectFrom(table)
              .select((eb) => eb.fn.countAll<string>().as('n'))
              .where('id', 'in', ids)
              .executeTakeFirstOrThrow()
          ).n,
        );
      const owned =
        (await count('agents.agents', [agent.agentId])) === 1 &&
        (await count('funding_sources.sources', [agent.sourceId])) === 1 &&
        (await count('suppliers.suppliers', [...agent.supplierIds])) === new Set(agent.supplierIds).size;
      return owned
        ? undefined
        : `Agent ${agent.agentId}, its funding source or a supplier is not organisation ${agent.orgId}'s.`;
    });
    if (wrong !== undefined) found.push(wrong);
  }
  return found;
}

/** Refuses, changing nothing, unless every agent is the run's own. */
async function mustBeTheRuns(steps: JobSteps, runId: string, agents: readonly PrintedAgent[]): Promise<void> {
  const wrong = await notTheRuns(steps.database, runId, agents);
  if (wrong.length > 0) throw new JobRefused(`Nothing was changed: ${wrong.join(' ')}`);
}

/** The clean-up (cleanup.ts) of organisations already known to be the run's, and what it left undone, printed. */
async function cleanUp(steps: JobSteps, agents: readonly PrintedAgent[]): Promise<boolean> {
  const orgIds = agents.map(({ orgId }) => orgId);
  let problems: string[];
  try {
    await cleanUpRun(steps.database, steps.keyring, orgIds);
    problems = await cleanUpFailures(steps.database, orgIds);
  } catch (error) {
    problems = [`The clean-up stopped: ${error instanceof Error ? error.message : String(error)}`];
  }
  steps.print({ event: 'load.cleaned', organizations: orgIds.length, problems });
  return problems.length === 0;
}

/** The clean-up alone, of the run's own organisations only. 0 when every one is inert. */
export async function cleanupJob(steps: JobSteps, runId: string, agents: readonly PrintedAgent[]): Promise<number> {
  await mustBeTheRuns(steps, runId, agents);
  return (await cleanUp(steps, agents)) ? 0 : 1;
}

/**
 * Phase 2, on the run's own organisations only, while every hand-off is
 * paused: a new key for each agent, k6, then the database checks over both
 * phases' requests, and the clean-up whatever they found or threw. 0 when k6
 * ran to the end, hand-offs stayed paused, every check held and every
 * organisation is inert.
 */
export async function secondJob(
  steps: JobSteps,
  runId: string,
  agents: readonly PrintedAgent[],
  createdFirst: number,
): Promise<number> {
  if (agents.filter(({ kind }) => kind === 'capped').length !== 1) {
    throw new JobRefused("Nothing was changed: phase 2 needs the run's one capped agent, for its spike.");
  }
  await mustBeTheRuns(steps, runId, agents);
  // The run's organisations are made inert whatever phase 2 does: on staging they stay.
  const held = (await handoffsPaused(steps, 'before phase 2'))
    ? await phaseTwo(steps, agents, createdFirst).catch(async (error: unknown) => {
        await cleanUp(steps, agents);
        throw error;
      })
    : false;
  const cleaned = await cleanUp(steps, agents);
  return held && cleaned ? 0 : 1;
}

/** New keys, k6's phase 2 and the checks, printed: true when k6 ran to the end, hand-offs stayed paused and every check held. */
async function phaseTwo(steps: JobSteps, agents: readonly PrintedAgent[], createdFirst: number): Promise<boolean> {
  const seeded = await rekeyed(steps.database, steps.keyring, { agents });
  const phase = await steps.k6(2, seeded);
  const stillPaused = await handoffsPaused(steps, 'after phase 2');
  const created = createdFirst + (phase.result?.created ?? 0);
  const checks = [];
  for (const check of LOAD_CHECKS) {
    checks.push({ name: check.name, problems: await check.run(steps.database, seeded.agents, created) });
  }
  steps.print({ event: 'load.checked', created, finished: phase.finished, checks });
  return phase.finished && stillPaused && checks.every(({ problems }) => problems.length === 0);
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
export function runK6(
  api: string,
  k6: readonly [string, ...string[]] = ['k6'],
): (phase: 1 | 2, seeded: Seeded) => PhaseRun {
  const [command, ...first] = k6;
  return (phase, seeded) => {
    const dir = mkdtempSync(path.join(tmpdir(), 'agentx-load-'));
    try {
      const seed = path.join(dir, 'seed.json');
      writeFileSync(seed, JSON.stringify(seeded), { mode: 0o600 });
      const done = spawnSync(command, [...first, 'run', '--quiet', K6_SCRIPT], {
        env: { ...process.env, PHASE: String(phase), API: api, SEED: seed, OUT: dir },
        stdio: 'inherit',
        windowsHide: true,
      });
      if (done.error !== undefined || (done.status !== 0 && done.status !== K6_THRESHOLD_FAILED)) {
        return { finished: false, result: undefined };
      }
      const summary = path.join(dir, `k6-phase-${String(phase)}.json`);
      return { finished: true, result: JSON.parse(readFileSync(summary, 'utf8')) as PhaseResult };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

/** A setting the job can't run without. */
function needed(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') throw new JobRefused(`${name} is not set.`);
  return value;
}

const STRING_FIELDS = ['orgId', 'agentId', 'sourceId', 'monthlyLimitMinor'] as const;

/** One agent as load.seeded_agent printed it: all its IDs, and never a key. */
function isPrintedAgent(agent: unknown): agent is PrintedAgent {
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
}

/** The run's agents as load.ts hands them on, or a refusal saying what is wrong with them. */
export function agentsOf(text: string): PrintedAgent[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new JobRefused('AGENTX_LOAD_SEEDED is not JSON.');
  }
  const agents = Array.isArray(parsed) ? (parsed as unknown[]) : [];
  if (agents.length === 0 || !agents.every(isPrintedAgent)) {
    throw new JobRefused(
      "AGENTX_LOAD_SEEDED must be the run's agents as load.seeded_agent printed them, without keys.",
    );
  }
  if (new Set(agents.map(({ orgId }) => orgId)).size !== agents.length) {
    throw new JobRefused('AGENTX_LOAD_SEEDED names an organisation twice: each agent of the run has its own.');
  }
  return agents;
}

/** The job's command line and settings, run. */
export async function main(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const [job, ...rest] = argv;
  if ((job !== 'first' && job !== 'second' && job !== 'cleanup') || rest.length > 0) {
    throw new JobRefused('Run it as node tooling/load/job.ts <first|second|cleanup>.');
  }
  // Named, never left out: loadConnection takes a missing host for the laptop's loopback port.
  const connection = loadConnection({
    AGENTX_LOAD_DB_HOST: needed(env, 'AGENTX_LOAD_DB_HOST'),
    AGENTX_LOAD_DB_PASSWORD: readFileSync(needed(env, 'AGENTX_DB_PASSWORD_FILE'), 'utf8').trim(),
  });
  const runId = needed(env, 'AGENTX_LOAD_RUN_ID');
  const database = createDatabase<LoadTables>(connection, testLogger());
  try {
    const steps: JobSteps = {
      database,
      keyring: loadKeys({ directory: needed(env, 'AGENTX_KEYS_DIR'), current: {} }),
      // The clean-up sends no traffic, so it needs no API.
      k6: job === 'cleanup' ? () => ({ finished: false, result: undefined }) : runK6(needed(env, 'AGENTX_LOAD_API')),
      print: (line) => {
        console.log(JSON.stringify(line));
      },
    };
    if (job === 'first') return await firstJob(steps, runId);
    const agents = agentsOf(needed(env, 'AGENTX_LOAD_SEEDED'));
    if (job === 'cleanup') return await cleanupJob(steps, runId, agents);
    const createdFirst = Number(needed(env, 'AGENTX_LOAD_CREATED_FIRST'));
    if (!Number.isSafeInteger(createdFirst) || createdFirst < 0) {
      throw new JobRefused("AGENTX_LOAD_CREATED_FIRST must be phase 1's count of new requests.");
    }
    return await secondJob(steps, runId, agents, createdFirst);
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
