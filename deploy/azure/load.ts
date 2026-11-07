// The load test's run on Azure (Phase 4 D2c, PL-38), from the partner's own
// terminal once `apps --load-run --keep-running` has deployed its jobs:
//
//   node deploy/azure/load.ts run [--smoke]   one run, start to report (about 45 minutes; --smoke about 25)
//   node deploy/azure/load.ts status          what is up: the jobs, the API's size, the database's, a run left open
//   node deploy/azure/load.ts finish          the clean-up of a run left open, then the jobs removed
//
// A run does what the laptop's (tooling/load/run.ts) does, each step in
// staging's own network:
// 1. writes the run's request onto load-first (its ID, and the smoke flag),
//    runs it (the hand-off pause read, the seed, k6's phase 1), puts {} back,
//    and reads its lines from the workspace: the run's agents, without keys
//    (`load.seeded_agent`), and phase 1's numbers (`load.k6_summary`)
// 2. keeps the run's agents in tooling/load/.out/azure-run.json, so `finish`
//    can clean up a run that stopped half-way
// 3. restarts the API's revision, so its holdings check runs over phase 1's
//    requests at the start, and waits until it runs again
// 4. writes the agents and phase 1's count onto load-second and runs it (new
//    keys, k6's phases 2 to 5, the database checks, the clean-up)
// 5. reads the API's own lines over the run and writes the report, as the
//    laptop's run does, to tooling/load/reports/<day>-azure-<cpus>cpu.md
// Each request is written as the operator's is (held-request.ts): the jobs
// hold it as a secret, as a run started with settings of its own would lose
// its mounted login and keys. Nothing here holds a secret or a key: the
// agents' keys never leave the jobs. Every line a job prints reaches the
// workspace 4 to 9 minutes late, so each step waits for its run's lines.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { agentsOf, LATER_PHASES } from '../../tooling/load/job.ts';
import type { FreezeProbed } from '../../tooling/load/freeze-probe.ts';
import { apartOrgsOf, type LogSummary, logFailures, summariseLogs, troubleWindowOf } from '../../tooling/load/logs.ts';
import { LOAD_GATE, orgsOf, POLICY_P95_MS } from '../../tooling/load/plan.ts';
import { type PhaseResult, phaseFailures, renderReport } from '../../tooling/load/report.ts';
import { gatheredEnd, growthBetween } from '../../tooling/load/table-growth.ts';
import { ARM, type Az, realAz, RESOURCE_GROUP, signedIn, text } from './deploy.ts';
import {
  type Api,
  API_APP,
  apiUrl,
  endedAs,
  type JobRun,
  jobThere,
  lineOf,
  linesOf,
  limitOf,
  loadJobUrl,
  type Printed,
  readApi,
  readLoadJob,
  replicasOf,
  runLines,
  runWith,
  SETTLE_MS,
} from './load-jobs.ts';
import {
  askWorkspace,
  jobName,
  type JobSteps,
  LOAD_JOBS,
  type LoadJob,
  POLL_MS,
  STAGE_G_JOBS,
  type StageGJob,
  runCli,
  type Target,
  unfinishedRuns,
  UsageError,
  waitFor,
  workspaceId,
} from './jobs.ts';
import { get, record } from './release.ts';

const USAGE = `Usage, from your own terminal window, after apps --load-run --keep-running:
  node deploy/azure/load.ts run [--smoke]   one run, start to report; --smoke is the wiring run's short k6
  node deploy/azure/load.ts status          the load jobs, the API's size, the database's, any run left open
  node deploy/azure/load.ts finish          clean up a run left open, then remove the load jobs`;

export type Request = { readonly command: 'run'; readonly smoke: boolean } | { readonly command: 'status' | 'finish' };

export function parseArguments(argv: readonly string[]): Request {
  const [command, ...rest] = argv;
  if (command === 'run') {
    if (rest.length === 0) return { command, smoke: false };
    if (rest.length === 1 && rest[0] === '--smoke') return { command, smoke: true };
    throw new UsageError(`run takes only --smoke, not ${rest.join(' ')}`);
  }
  if (command === 'status' || command === 'finish') {
    if (rest.length > 0) throw new UsageError(`${command} takes nothing, not ${rest.join(' ')}`);
    return { command };
  }
  throw new UsageError(`say run, status or finish, not ${command ?? 'nothing'}`);
}

/**
 * The API's own lines over the run, read a minute apart: none taken as all of
 * them before 10 minutes past the run's end (they arrive 4 to 9 late), nor
 * waited for past 25.
 */
const API_LOG_POLL_MS = 60_000;
const API_LOG_SETTLED_MS = 10 * 60_000;
const API_LOG_READINGS = 25;

/** What a run needs from this machine, and where it keeps its notes; tests give their own. */
export interface LoadSteps extends JobSteps {
  /** Where a run left open keeps its agents (tooling/load/.out, kept out of git), and where reports go. */
  readonly stateFile: string;
  readonly reportsDir: string;
}

/**
 * The run left open, as `run` keeps it from before its first job starts: its
 * ID, whether it was the smoke run, load-first's run once started (whose lines
 * name the agents it seeded, should `run` stop before reading them), and the
 * agents once read (never their keys).
 */
interface OpenRun {
  readonly runId: string;
  readonly smoke: boolean;
  readonly firstRun?: string;
  readonly agents: readonly Printed[];
}

const keep = (steps: LoadSteps, open: OpenRun): void => {
  mkdirSync(path.dirname(steps.stateFile), { recursive: true });
  writeFileSync(steps.stateFile, JSON.stringify(open));
};

/** The agents load-first seeded, from its `load.seeded_agent` lines, checked as load-second will check them. */
function seededAgents(printed: readonly Printed[]): Readonly<Record<string, unknown>>[] {
  const agents = linesOf(printed, 'load.seeded_agent').map(({ agent }) => agent);
  return agents.length === 0 ? [] : agentsOf(JSON.stringify(agents)).map(record);
}

/** The line each load job prints last when it succeeds: its log is read until that line has arrived. */
const LAST_EVENT: Readonly<Record<LoadJob, string>> = {
  'load-first': 'load.k6_summary',
  'load-second': 'load.cleaned',
  'load-cleanup': 'load.cleaned',
};

/** A PL-38 job's run: its request, the line it prints last, and finish for a run that outlasts the wait. */
const loadRun = (request: Readonly<Record<string, string>>, job: LoadJob) => ({
  request,
  lastEvent: LAST_EVENT[job],
  ifStuck: 'wait for it, then load.ts finish.',
});

/**
 * Restarts the API's newest revision, so a new process starts and its
 * holdings check runs over phase 1's requests, as the laptop's restart does;
 * then waits until its replicas are new or restarted since, and every one
 * runs. A revision's own state can say Running throughout.
 */
async function restartApi(steps: JobSteps, subscription: string, revision: string): Promise<void> {
  const before = replicasOf(steps.az, subscription, revision).shape;
  const done = steps.az.run([
    'rest',
    '--method',
    'post',
    '--url',
    apiUrl(subscription, `/revisions/${revision}/restart`),
  ]);
  if (done.status !== 0) throw new Error(`Azure refused to restart the API's revision ${revision}.`);
  steps.say(`Restarted the API's revision ${revision}; waiting until it runs again...`);
  const deadline = steps.now().getTime() + SETTLE_MS;
  for (;;) {
    await steps.sleep(POLL_MS);
    const now = replicasOf(steps.az, subscription, revision);
    if (now.shape !== before && now.running) return;
    if (steps.now().getTime() >= deadline) {
      throw new Error(`The API's revision ${revision} wasn't running again 10 minutes after its restart.`);
    }
  }
}

/** The database server's size, as Azure gives it: `Standard_D2ads_v5 (GeneralPurpose)`. */
function databaseSize(steps: JobSteps, subscription: string): string {
  const listed = record(
    get(
      steps.az,
      `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2025-08-01`,
      'the database servers',
    ),
  ).value;
  const servers = Array.isArray(listed) ? listed.map(record) : [];
  if (servers.length !== 1)
    throw new Error(`Azure listed ${String(servers.length)} database servers, where staging has one.`);
  const sku = record(servers[0]?.sku);
  return `${text(sku.name)} (${text(sku.tier)})`;
}

/** The API's own lines over the run, once two readings a minute apart hold as many: its log as one text. */
async function apiLog(steps: JobSteps, subscription: string, began: string, ended: string): Promise<string> {
  const from = new Date(began).toISOString();
  const to = new Date(ended).toISOString();
  const workspace = workspaceId(steps, subscription);
  const query = [
    `ContainerAppConsoleLogs | where ContainerAppName == '${API_APP}'`,
    `| where TimeGenerated between (datetime('${from}') .. datetime('${to}'))`,
    '| order by TimeGenerated asc | project Log',
  ].join('\n');
  // The window and a margin past its end for the lines still arriving; a reading is of what has come so far.
  const timespan = `${from}/${new Date(Date.parse(to) + 30 * 60_000).toISOString()}`;
  let previous = -1;
  for (let reading = 0; ; reading += 1) {
    const table = record(
      (record(askWorkspace(steps, workspace, query, timespan)).tables as unknown[] | undefined)?.[0],
    );
    const rows = Array.isArray(table.rows) ? table.rows : [];
    const lines = rows.map((row) => (Array.isArray(row) ? text(row[0]) : ''));
    const late = steps.now().getTime() >= Date.parse(to) + API_LOG_SETTLED_MS;
    if ((late && lines.length > 0 && lines.length === previous) || reading >= API_LOG_READINGS) {
      return lines.join('\n');
    }
    previous = lines.length;
    await steps.sleep(API_LOG_POLL_MS);
  }
}

/** k6's summary of each phase that ran to the end, as the job printed them. */
const phasesOf = (printed: readonly Printed[]): PhaseResult[] =>
  linesOf(printed, 'load.k6_summary').flatMap(({ event: _event, ...result }) =>
    'phase' in result ? [result as unknown as PhaseResult] : [],
  );

/** The report's file for today, the API's size and the kind of run: a second run the same day gets its own. */
function reportFile(dir: string, at: string, cpus: number, smoke: boolean): string {
  mkdirSync(dir, { recursive: true });
  const name = `${at.slice(0, 10)}-azure-${String(cpus)}cpu${smoke ? '-smoke' : ''}`;
  for (let n = 1; ; n += 1) {
    const file = path.join(dir, n === 1 ? `${name}.md` : `${name}-${String(n)}.md`);
    if (!existsSync(file)) return file;
  }
}

/** Every load job is there and idle, the API keeps a copy running, and no run is left open: or why not. */
function preflight(steps: LoadSteps, subscription: string, smoke: boolean): Api {
  if (existsSync(steps.stateFile)) {
    throw new Error(`A run is still open (${steps.stateFile}): run load.ts finish first, which cleans it up.`);
  }
  for (const job of LOAD_JOBS) {
    readLoadJob(steps, subscription, job);
    const going = unfinishedRuns(steps, { subscription, job });
    if (going.length > 0) throw new Error(`${jobName(job)} has runs still going: ${going.join(', ')}.`);
  }
  const api = readApi(steps.az, subscription);
  if (api.fewest < 1) {
    throw new Error(
      'The API keeps no copy running, so phase 2 would start with a cold start in its numbers: run apps --load-run --keep-running first.',
    );
  }
  if (!smoke && api.cpus !== 2) {
    throw new Error(
      `The API runs at ${String(api.cpus)} CPUs, not the load run's 2: run apps --load-run --keep-running first.`,
    );
  }
  return api;
}

/** The problems a list in a job's line names, or `missing` when the line isn't there. */
const problemsIn = (line: Readonly<Record<string, unknown>> | undefined, missing: string): string[] =>
  Array.isArray(line?.problems) ? line.problems.map(String) : [missing];

/** Phase 1, in load-first: the run's agents (kept for `finish` as soon as there are any) and k6's numbers. */
async function phaseOne(
  steps: LoadSteps,
  subscription: string,
  open: OpenRun,
  flags: Readonly<Record<string, string>>,
) {
  steps.say('Phase 1: the seed and k6, in load-first...');
  keep(steps, open);
  const first = await runWith(steps, subscription, 'load-first', {
    ...loadRun({ AGENTX_LOAD_RUN_ID: open.runId, ...flags }, 'load-first'),
    started: (firstRun) => {
      keep(steps, { ...open, firstRun });
    },
  });
  const agents = seededAgents(first.printed);
  // Only a run that succeeded waits for its last line: a failed one's seed lines may be yet to come, for finish to read.
  const noneMade = agents.length === 0 && first.run.status === 'Succeeded';
  if (noneMade) rmSync(steps.stateFile, { force: true });
  else if (agents.length > 0) keep(steps, { ...open, agents });
  const [phase] = phasesOf(first.printed);
  const next = noneMade ? 'It made no organisation.' : 'Run load.ts finish to clean up its organisations.';
  if (first.run.status !== 'Succeeded' || phase === undefined) {
    throw new Error(`Phase 1 didn't finish (load-first ended ${endedAs(first.run, first.printed)}). ${next}`);
  }
  if (first.putBack !== undefined) throw new Error(`${first.putBack} ${next}`);
  return { run: first.run, agents, phase, printed: first.printed };
}

type Line = Readonly<Record<string, unknown>> | undefined;

/**
 * What the second job's lines (its database checks' and clean-up's among them)
 * say went wrong with the run's wiring, in plain words: none on a clean run.
 */
function wiringFailures(second: JobRun, checked: Line, cleanedLine: Line, logText: string): string[] {
  const cleaned = problemsIn(cleanedLine, 'The clean-up said nothing.');
  return [
    ...(second.run.status === 'Succeeded' ? [] : [`load-second ended ${endedAs(second.run, second.printed)}.`]),
    ...LATER_PHASES.filter((n) => !phasesOf(second.printed).some(({ phase }) => phase === n)).map(
      (n) => `Phase ${String(n)}'s k6 didn't run to the end.`,
    ),
    ...(checked === undefined ? ['The database checks said nothing.'] : checkProblems(checked)),
    ...(cleaned.length === 0 ? [] : [`The clean-up left work undone: ${cleaned.join(' ')} Run load.ts finish.`]),
    ...(logText === '' ? ["None of the API's lines reached the workspace."] : []),
    ...(second.putBack === undefined ? [] : [second.putBack]),
  ];
}

/** Each database check's problems, as `<check>: <problem>`. */
const checkProblems = (checked: Readonly<Record<string, unknown>>): string[] =>
  (Array.isArray(checked.checks) ? checked.checks.map(record) : []).flatMap((check) =>
    (Array.isArray(check.problems) ? check.problems : []).map((problem) => `${text(check.name)}: ${String(problem)}`),
  );

/** What an admin's freeze was answered in phase 5, as the job printed it; none when the phase ended first. */
const freezeProbeOf = (line: Line): FreezeProbed | undefined =>
  typeof line?.ms === 'number' && typeof line.answer === 'string' ? { ms: line.ms, answer: line.answer } : undefined;

async function runLoad(steps: LoadSteps, smoke: boolean): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  const api = preflight(steps, subscription, smoke);
  const database = databaseSize(steps, subscription);
  const at = steps.now().toISOString();
  const runId = `azure-${at.replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')}`;
  const kind = smoke ? ' (the wiring run: k6 for 20 seconds, measuring nothing)' : '';
  steps.say(`Run ${runId}${kind}: the API at ${String(api.cpus)} CPUs, the database ${database}.`);
  const flags: Readonly<Record<string, string>> = smoke ? { AGENTX_LOAD_SMOKE: '1' } : {};
  const first = await phaseOne(steps, subscription, { runId, smoke, agents: [] }, flags);
  await restartApi(steps, subscription, api.revision);
  steps.say('Phases 2 to 5: new keys, k6, the database checks and the clean-up, in load-second...');
  const second = await runWith(
    steps,
    subscription,
    'load-second',
    loadRun(
      {
        AGENTX_LOAD_RUN_ID: runId,
        AGENTX_LOAD_SEEDED: JSON.stringify(first.agents),
        AGENTX_LOAD_CREATED_FIRST: String(first.phase.created),
        ...flags,
      },
      'load-second',
    ),
  );
  const checked = lineOf(second.printed, 'load.checked');
  const cleanedLine = lineOf(second.printed, 'load.cleaned');
  if (cleanedLine !== undefined && problemsIn(cleanedLine, '').length === 0) rmSync(steps.stateFile, { force: true });
  steps.say("Reading the API's own lines over the run...");
  const logText = await apiLog(steps, subscription, first.run.began, second.run.ended);
  const phases = [first.phase, ...phasesOf(second.printed)];
  const logs: LogSummary = summariseLogs(logText, apartOrgsOf(first.agents), troubleWindowOf(phases));
  const created = phases.reduce((sum, phase) => sum + phase.created, 0);
  const wiring = wiringFailures(second, checked, cleanedLine, logText);
  // The wiring run is judged on its wiring alone: its numbers are a few seconds' of k6 on staging's own sizes.
  const failures = smoke
    ? wiring
    : [...wiring, ...phases.flatMap(phaseFailures), ...logFailures(logs, created, POLICY_P95_MS)];
  const freezeProbe = freezeProbeOf(lineOf(second.printed, 'load.freeze_probe'));
  const report = renderReport({
    at,
    commit: api.release.slice(0, 7),
    site: 'azure',
    apiCpus: api.cpus,
    database,
    smoke,
    phases,
    growth: growthBetween(gatheredEnd(first.printed, 'before'), gatheredEnd(second.printed, 'after')),
    logs,
    gate: LOAD_GATE,
    ...(freezeProbe === undefined ? {} : { freezeProbe }),
    databaseChecksPassed: checked !== undefined && checkProblems(checked).length === 0,
    failures,
  });
  const file = reportFile(steps.reportsDir, at, api.cpus, smoke);
  writeFileSync(file, report);
  steps.say(`\n${report}\nThe report: ${file}`);
  return failures.length === 0 ? 0 : 1;
}

/** PL-38's three jobs and Stage G's (4D2e), which load.ts reads and removes alike. */
const EVERY_LOAD_JOB: readonly (LoadJob | StageGJob)[] = [...LOAD_JOBS, ...STAGE_G_JOBS];

/** What is up for the load run, read only. */
function status(steps: LoadSteps): number {
  const subscription = signedIn(steps.az, steps.say);
  for (const job of EVERY_LOAD_JOB) {
    steps.say(`  ${jobName(job)}: ${jobThere(steps.az, subscription, job) ? 'there' : 'not there'}`);
  }
  const api = readApi(steps.az, subscription);
  steps.say(`  The API: ${String(api.cpus)} CPUs, ${api.fewest >= 1 ? 'a copy kept running' : 'scales to zero'}.`);
  steps.say(`  The database: ${databaseSize(steps, subscription)}.`);
  steps.say(
    existsSync(steps.stateFile) ? `  A run is still open: load.ts finish cleans it up.` : '  No run is left open.',
  );
  return 0;
}

/**
 * The open run's agents: as kept, or read from load-first's lines when `run`
 * stopped before reading them (waiting for that run to end first).
 */
async function openAgents(steps: LoadSteps, subscription: string, open: OpenRun) {
  if (open.agents.length > 0 || open.firstRun === undefined) return open.agents;
  const target: Target = { subscription, job: 'load-first' };
  const run = await waitFor(steps, target, open.firstRun, limitOf(steps.az, subscription, 'load-first'));
  if (run === undefined) throw new Error(`${open.firstRun} hasn't ended: run load.ts finish again once it has.`);
  return seededAgents(await runLines(steps, target, open.firstRun, run, LAST_EVENT['load-first']));
}

/** Cleans up the run left open, if any: its own organisations alone, in load-cleanup. */
async function cleanOpenRun(steps: LoadSteps, subscription: string): Promise<void> {
  const open = JSON.parse(readFileSync(steps.stateFile, 'utf8')) as OpenRun;
  const agents = await openAgents(steps, subscription, open);
  if (agents.length === 0) {
    steps.say(`Run ${open.runId} seeded no organisation: nothing to clean up.`);
    rmSync(steps.stateFile, { force: true });
    return;
  }
  steps.say(
    `Cleaning up run ${open.runId}'s ${String(orgsOf(agents.map((agent) => ({ orgId: text(agent.orgId) }))).length)} organisations, in load-cleanup...`,
  );
  const { run, printed, putBack } = await runWith(
    steps,
    subscription,
    'load-cleanup',
    loadRun({ AGENTX_LOAD_RUN_ID: open.runId, AGENTX_LOAD_SEEDED: JSON.stringify(agents) }, 'load-cleanup'),
  );
  const problems = problemsIn(lineOf(printed, 'load.cleaned'), 'the clean-up said nothing');
  if (run.status !== 'Succeeded' || problems.length > 0) {
    throw new Error(
      `The clean-up didn't finish (${endedAs(run, printed)}: ${problems.join(' ')}). The jobs are kept: run load.ts finish again.`,
    );
  }
  rmSync(steps.stateFile, { force: true });
  if (putBack !== undefined) steps.say(putBack);
}

/** Cleans up a run left open, then removes the load jobs (Stage G's too, where its run left them), never while a run of one goes; what to run next is said. */
async function finish(steps: LoadSteps): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  for (const job of EVERY_LOAD_JOB) {
    // A job already removed (an earlier finish), or Stage G's on a run without its copy, has nothing going.
    if (!jobThere(steps.az, subscription, job)) continue;
    const runs = unfinishedRuns(steps, { subscription, job });
    if (runs.length > 0) {
      throw new Error(
        `${jobName(job)} has runs still going (${runs.join(', ')}): wait for them, then load.ts finish again.`,
      );
    }
  }
  if (existsSync(steps.stateFile)) await cleanOpenRun(steps, subscription);
  for (const job of [...LOAD_JOBS, ...STAGE_G_JOBS.filter((each) => jobThere(steps.az, subscription, each))]) {
    const done = steps.az.run(['rest', '--method', 'delete', '--url', loadJobUrl(subscription, job)]);
    if (done.status !== 0) throw new Error(`Azure refused to remove ${jobName(job)}: run load.ts finish again.`);
    steps.say(`Removed ${jobName(job)}.`);
  }
  steps.say(
    'Next: apps (without --load-run) puts the API back and removes the jobs app, then foundation (without --load-size) the database.',
  );
  return 0;
}

export function load(request: Request, steps: LoadSteps): Promise<number> {
  switch (request.command) {
    case 'run':
      return runLoad(steps, request.smoke);
    case 'status':
      return Promise.resolve(status(steps));
    case 'finish':
      return finish(steps);
  }
}

const LOAD_DIR = fileURLToPath(new URL('../../tooling/load/', import.meta.url));

export function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => Az = realAz,
): Promise<number> {
  return runCli(
    USAGE,
    say,
    () => parseArguments(argv),
    (request) =>
      load(request, {
        az: az(),
        say,
        now: () => new Date(),
        sleep,
        stateFile: path.join(LOAD_DIR, '.out', 'azure-run.json'),
        reportsDir: path.join(LOAD_DIR, 'reports'),
      }),
  );
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
