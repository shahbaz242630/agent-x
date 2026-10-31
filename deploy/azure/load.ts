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
import { apartOrgsOf, type LogSummary, logFailures, summariseLogs, troubleWindowOf } from '../../tooling/load/logs.ts';
import { orgsOf, POLICY_P95_MS } from '../../tooling/load/plan.ts';
import { type PhaseResult, phaseFailures, renderReport } from '../../tooling/load/report.ts';
import { ARM, type Az, realAz, RESOURCE_GROUP, signedIn, text } from './deploy.ts';
import { asciiJson, lastModified, reason, sendPatch, type VaultReference, vaultReferences } from './held-request.ts';
import {
  askWorkspace,
  type Ended,
  jobName,
  type JobSteps,
  LOAD_JOBS,
  type LoadJob,
  type LogLine,
  POLL_MS,
  readLog,
  runCli,
  start,
  type Target,
  unfinishedRuns,
  UsageError,
  waitFor,
  workspaceId,
} from './jobs.ts';
import { get, record, resourceUrl } from './release.ts';

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

/** The secret each load job holds its run's request in (apps.bicep `loadRequest`; policy.ts `HELD`). */
const LOAD_REQUEST = 'load-request';

/** What a load job holds between runs: no request, which the jobs refuse. */
export const NO_REQUEST = '{}';

/** Where the load image is published (verify.ts `LOAD_SIGNER`), as a job names it, by digest. */
const LOAD_IMAGE = /^ghcr\.io\/shahbaz242630\/agent-x-load@sha256:[0-9a-f]{64}$/;

/** The API, as apps.bicep names it. */
const API_APP = 'ca-agentx-stg-api';

/** How long a change to a job, or the API's restart, may take to settle. */
const SETTLE_MS = 10 * 60_000;

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
  readonly agents: readonly Readonly<Record<string, unknown>>[];
}

const keep = (steps: LoadSteps, open: OpenRun): void => {
  mkdirSync(path.dirname(steps.stateFile), { recursive: true });
  writeFileSync(steps.stateFile, JSON.stringify(open));
};

/** The agents load-first seeded, from its `load.seeded_agent` lines, checked as load-second will check them. */
function seededAgents(printed: readonly Readonly<Record<string, unknown>>[]): Readonly<Record<string, unknown>>[] {
  const agents = linesOf(printed, 'load.seeded_agent').map(({ agent }) => agent);
  return agents.length === 0 ? [] : agentsOf(JSON.stringify(agents)).map(record);
}

/** A load job as Azure has it, checked: what a change sends back of it, and where it stands. */
interface LoadJobState {
  readonly references: readonly VaultReference[];
  readonly state: string;
  readonly modified: string;
}

const loadJobUrl = (subscription: string, job: LoadJob): string =>
  resourceUrl(subscription, { path: `jobs/${jobName(job)}`, container: job });

/** Whether the load job is there at all: an earlier finish may have removed it. */
const jobThere = (steps: JobSteps, subscription: string, job: LoadJob): boolean =>
  steps.az.run(['rest', '--method', 'get', '--url', loadJobUrl(subscription, job), '--output', 'json']).status === 0;

/**
 * A load job, read from Azure, or an error saying why it isn't one as
 * apps.bicep deploys it: one container on the load image by digest, running
 * `node tooling/load/job.ts <its part>`, its request held once.
 */
function readLoadJob(steps: JobSteps, subscription: string, job: LoadJob): LoadJobState {
  const refuse = (why: string): never => {
    throw new Error(`${jobName(job)} isn't a load job this tool knows (${why}): deploy apps --load-run again.`);
  };
  const found = get(steps.az, loadJobUrl(subscription, job), jobName(job));
  const properties = record(found.properties);
  const containers = record(properties.template).containers;
  if (!Array.isArray(containers) || containers.length !== 1) return refuse('it must run exactly one container');
  const container = record(containers[0]);
  if (!LOAD_IMAGE.test(text(container.image))) return refuse("it doesn't run the load image by digest");
  const part = job.replace(/^load-/, '');
  if (
    JSON.stringify([container.command, container.args]) !== JSON.stringify([['node', 'tooling/load/job.ts'], [part]])
  ) {
    refuse(`it must run node tooling/load/job.ts ${part}`);
  }
  const references = vaultReferences(record(properties.configuration).secrets, LOAD_REQUEST, refuse);
  const modified = lastModified(found);
  if (modified === '') return refuse("Azure gave no time of its last change, so one of ours can't be told apart");
  return { references, state: text(properties.provisioningState), modified };
}

/**
 * Writes `value` as the job's request, once no change to it is still going,
 * and waits until Azure has taken it: the secrets list whole, every vault
 * reference as it was read.
 */
async function writeRequest(steps: JobSteps, subscription: string, job: LoadJob, value: string): Promise<void> {
  const deadline = steps.now().getTime() + SETTLE_MS;
  let before = readLoadJob(steps, subscription, job);
  while (before.state === 'InProgress') {
    if (steps.now().getTime() >= deadline)
      throw new Error(`${jobName(job)} was still taking a change after 10 minutes.`);
    await steps.sleep(POLL_MS);
    before = readLoadJob(steps, subscription, job);
  }
  const what =
    value === NO_REQUEST ? `putting ${NO_REQUEST} back on ${jobName(job)}` : `the run's request on ${jobName(job)}`;
  const body = { properties: { configuration: { secrets: [...before.references, { name: LOAD_REQUEST, value }] } } };
  sendPatch(steps, loadJobUrl(subscription, job), asciiJson(JSON.stringify(body)), what);
  for (;;) {
    const now = readLoadJob(steps, subscription, job);
    if (now.modified !== before.modified && now.state === 'Succeeded') return;
    if (now.modified !== before.modified && (now.state === 'Failed' || now.state === 'Canceled')) {
      throw new Error(`Azure's change for ${what} ended ${now.state}.`);
    }
    if (steps.now().getTime() >= deadline) throw new Error(`Azure hadn't settled ${what} after 10 minutes.`);
    await steps.sleep(POLL_MS);
  }
}

/** A job's own JSON lines (what job.ts prints), from its run's log; the platform's lines and Node's own are skipped. */
export function printedLines(lines: readonly LogLine[]): Readonly<Record<string, unknown>>[] {
  return lines.flatMap((line) => {
    if (line.source === 'platform') return [];
    try {
      const parsed = record(JSON.parse(line.text));
      return typeof parsed.event === 'string' && parsed.event.startsWith('load.') ? [parsed] : [];
    } catch {
      return [];
    }
  });
}

/** One run of a load job: how it ended, its own lines, and why {} couldn't be put back, if it couldn't. */
interface JobRun {
  readonly run: Ended;
  readonly printed: Readonly<Record<string, unknown>>[];
  readonly putBack: string | undefined;
}

/**
 * One run of a load job with `request` written onto it first and {} put back
 * whatever happened, `started` told the run's name as soon as it has one. A
 * put-back that failed after a run that ended is said with its lines, never in
 * their place.
 */
async function runWith(
  steps: JobSteps,
  subscription: string,
  job: LoadJob,
  request: Readonly<Record<string, string>>,
  started: (execution: string) => void = () => undefined,
): Promise<JobRun> {
  const target: Target = { subscription, job };
  const limit = limitOf(steps, subscription, job);
  let execution: string | undefined;
  let run: Ended | undefined;
  let failure: unknown;
  try {
    await writeRequest(steps, subscription, job, JSON.stringify(request));
    execution = start(steps, target);
    started(execution);
    run = await waitFor(steps, target, execution, limit);
  } catch (error) {
    failure = error;
  }
  let putBack: string | undefined;
  try {
    await writeRequest(steps, subscription, job, NO_REQUEST);
  } catch (error) {
    putBack = `${NO_REQUEST} wasn't put back on ${jobName(job)} (${reason(error)}): apps --load-run deploys it back.`;
  }
  const also = putBack === undefined ? '' : ` ${putBack}`;
  if (failure !== undefined) throw new Error(`${reason(failure)}${also}`, { cause: failure });
  if (execution === undefined || run === undefined) {
    throw new Error(`${String(execution)} didn't end in time: wait for it, then load.ts finish.${also}`);
  }
  return { run, printed: printedLines(await readLog(steps, target, execution, run, LAST_EVENT[job])), putBack };
}

/** The line each load job prints last when it succeeds: its log is read until that line has arrived. */
const LAST_EVENT: Readonly<Record<LoadJob, string>> = {
  'load-first': 'load.k6_summary',
  'load-second': 'load.cleaned',
  'load-cleanup': 'load.cleaned',
};

/** A job's own time limit, in seconds. */
function limitOf(steps: JobSteps, subscription: string, job: LoadJob): number {
  const limit = record(
    record(get(steps.az, loadJobUrl(subscription, job), jobName(job)).properties).configuration,
  ).replicaTimeout;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit <= 0) {
    throw new Error(`Azure gave no time limit for ${jobName(job)}.`);
  }
  return limit;
}

/** The API as it now runs: its CPUs, whether it keeps a copy running, its newest revision and its build. */
interface Api {
  readonly cpus: number;
  readonly fewest: number;
  readonly revision: string;
  readonly release: string;
}

const apiUrl = (subscription: string, rest = ''): string =>
  resourceUrl(subscription, { path: `containerApps/${API_APP}${rest}`, container: 'api' });

function readApi(steps: JobSteps, subscription: string): Api {
  const properties = record(get(steps.az, apiUrl(subscription), 'the API').properties);
  const template = record(properties.template);
  const [container] = Array.isArray(template.containers) ? template.containers.map(record) : [];
  const settings = Array.isArray(container?.env) ? container.env.map(record) : [];
  return {
    cpus: Number(record(container?.resources).cpu),
    fewest: Number(record(template.scale).minReplicas),
    revision: text(properties.latestRevisionName),
    release: text(settings.find((setting) => setting.name === 'AGENTX_RELEASE')?.value),
  };
}

/** The revision's replicas as `name restarts` each, and whether every one runs. */
function replicasOf(steps: JobSteps, subscription: string, revision: string) {
  const listed = record(
    get(steps.az, apiUrl(subscription, `/revisions/${revision}/replicas`), "the API's replicas"),
  ).value;
  const replicas = Array.isArray(listed) ? listed.map(record) : [];
  const restarts = (replica: Readonly<Record<string, unknown>>): number => {
    const containers = record(replica.properties).containers;
    return Array.isArray(containers)
      ? containers.map(record).reduce((sum, container) => sum + Number(container.restartCount ?? 0), 0)
      : 0;
  };
  return {
    shape: replicas.map((replica) => `${text(replica.name)} ${String(restarts(replica))}`).join(','),
    running:
      replicas.length > 0 && replicas.every((replica) => text(record(replica.properties).runningState) === 'Running'),
  };
}

/**
 * Restarts the API's newest revision, so a new process starts and its
 * holdings check runs over phase 1's requests, as the laptop's restart does;
 * then waits until its replicas are new or restarted since, and every one
 * runs. A revision's own state can say Running throughout.
 */
async function restartApi(steps: JobSteps, subscription: string, revision: string): Promise<void> {
  const before = replicasOf(steps, subscription, revision).shape;
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
    const now = replicasOf(steps, subscription, revision);
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

/** One event's lines among a job's, by name, or its first. */
const linesOf = (printed: readonly Readonly<Record<string, unknown>>[], event: string) =>
  printed.filter((line) => line.event === event);
const lineOf = (printed: readonly Readonly<Record<string, unknown>>[], event: string) =>
  printed.find((line) => line.event === event);

/** k6's summary of each phase that ran to the end, as the job printed them. */
const phasesOf = (printed: readonly Readonly<Record<string, unknown>>[]): PhaseResult[] =>
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
  const api = readApi(steps, subscription);
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

/** How a job's run ended, with its own reason when it refused: `Failed: hand-offs are running`. */
const endedAs = (run: Ended, printed: readonly Readonly<Record<string, unknown>>[]): string => {
  const refused = lineOf(printed, 'load.refused');
  return refused === undefined ? run.status : `${run.status}: ${text(refused.reason)}`;
};

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
  const first = await runWith(
    steps,
    subscription,
    'load-first',
    { AGENTX_LOAD_RUN_ID: open.runId, ...flags },
    (firstRun) => {
      keep(steps, { ...open, firstRun });
    },
  );
  const agents = seededAgents(first.printed);
  if (agents.length === 0) rmSync(steps.stateFile, { force: true });
  else keep(steps, { ...open, agents });
  const [phase] = phasesOf(first.printed);
  const next = agents.length > 0 ? 'Run load.ts finish to clean up its organisations.' : 'It made no organisation.';
  if (first.run.status !== 'Succeeded' || phase === undefined) {
    throw new Error(`Phase 1 didn't finish (load-first ended ${endedAs(first.run, first.printed)}). ${next}`);
  }
  if (first.putBack !== undefined) throw new Error(`${first.putBack} ${next}`);
  return { run: first.run, agents, phase };
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
  const second = await runWith(steps, subscription, 'load-second', {
    AGENTX_LOAD_RUN_ID: runId,
    AGENTX_LOAD_SEEDED: JSON.stringify(first.agents),
    AGENTX_LOAD_CREATED_FIRST: String(first.phase.created),
    ...flags,
  });
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
  const report = renderReport({
    at,
    commit: api.release.slice(0, 7),
    site: 'azure',
    apiCpus: api.cpus,
    database,
    smoke,
    phases,
    logs,
    databaseChecksPassed: checked !== undefined && checkProblems(checked).length === 0,
    failures,
  });
  const file = reportFile(steps.reportsDir, at, api.cpus, smoke);
  writeFileSync(file, report);
  steps.say(`\n${report}\nThe report: ${file}`);
  return failures.length === 0 ? 0 : 1;
}

/** What is up for the load run, read only. */
function status(steps: LoadSteps): number {
  const subscription = signedIn(steps.az, steps.say);
  for (const job of LOAD_JOBS) {
    steps.say(`  ${jobName(job)}: ${jobThere(steps, subscription, job) ? 'there' : 'not there'}`);
  }
  const api = readApi(steps, subscription);
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
  const run = await waitFor(steps, target, open.firstRun, limitOf(steps, subscription, 'load-first'));
  if (run === undefined) throw new Error(`${open.firstRun} hasn't ended: run load.ts finish again once it has.`);
  return seededAgents(printedLines(await readLog(steps, target, open.firstRun, run, LAST_EVENT['load-first'])));
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
  const { run, printed, putBack } = await runWith(steps, subscription, 'load-cleanup', {
    AGENTX_LOAD_RUN_ID: open.runId,
    AGENTX_LOAD_SEEDED: JSON.stringify(agents),
  });
  const problems = problemsIn(lineOf(printed, 'load.cleaned'), 'the clean-up said nothing');
  if (run.status !== 'Succeeded' || problems.length > 0) {
    throw new Error(
      `The clean-up didn't finish (${endedAs(run, printed)}: ${problems.join(' ')}). The jobs are kept: run load.ts finish again.`,
    );
  }
  rmSync(steps.stateFile, { force: true });
  if (putBack !== undefined) steps.say(putBack);
}

/** Cleans up a run left open, then removes the load jobs, never while a run of one goes; what to run next is said. */
async function finish(steps: LoadSteps): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  for (const job of LOAD_JOBS) {
    // A job already removed (an earlier finish) has nothing going.
    if (!jobThere(steps, subscription, job)) continue;
    const runs = unfinishedRuns(steps, { subscription, job });
    if (runs.length > 0) {
      throw new Error(
        `${jobName(job)} has runs still going (${runs.join(', ')}): wait for them, then load.ts finish again.`,
      );
    }
  }
  if (existsSync(steps.stateFile)) await cleanOpenRun(steps, subscription);
  for (const job of LOAD_JOBS) {
    const done = steps.az.run(['rest', '--method', 'delete', '--url', loadJobUrl(subscription, job)]);
    if (done.status !== 0) throw new Error(`Azure refused to remove ${jobName(job)}: run load.ts finish again.`);
    steps.say(`Removed ${jobName(job)}.`);
  }
  steps.say('Next: apps (without --load-run) puts the API back, then foundation (without --load-size) the database.');
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

function main(
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
        sleep: (ms) => sleep(ms),
        stateFile: path.join(LOAD_DIR, '.out', 'azure-run.json'),
        reportsDir: path.join(LOAD_DIR, 'reports'),
      }),
  );
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
