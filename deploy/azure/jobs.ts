// Runs staging's jobs (0e G3a), one at a time, in the order a first deploy
// needs them:
//
//   node deploy/azure/jobs.ts run db-setup
//   node deploy/azure/jobs.ts run migrate
//   node deploy/azure/jobs.ts run zitadel-init
//   node deploy/azure/jobs.ts run zitadel-setup
//
// `run` starts a job, waits for that run to end, then reads the run's log from
// the workspace. `start` only starts it, and `wait <job> <run>` does the rest,
// so a run can be started in one place and watched from another; `wait` on a
// run that has ended reads its log at once. Nothing is asked and no secret
// passes through here: each job reads its own from the vault (apps.bicep).
//
// A job is never started while a run of it hasn't ended: Container Apps would
// run both side by side, and two set-up runs at once race on the same roles.
//
// `cleanup` is for a Zitadel setup that died part-way through a step (S19): it
// leaves the step marked as started, and every later setup run waits on it for
// ever ("migration already started"). Once that waiting run is stopped,
// `cleanup` runs the setup job once as `zitadel setup cleanup`, which cancels
// the marker; then `run zitadel-setup` goes again.
import { setTimeout as sleep } from 'node:timers/promises';

import { ARM, type Az, azJson, realAz, RESOURCE_GROUP, signedIn, text } from './deploy.ts';

/** The jobs, by the work each does, in the order a first deploy runs them (names.bicep); a test holds the two equal. */
export const JOBS = ['db-setup', 'migrate', 'zitadel-init', 'zitadel-setup'] as const;
export type Job = (typeof JOBS)[number];

/** A job's name in Azure (names.bicep `jobName`). */
export const jobName = (job: Job): string => `job-agentx-stg-${job}`;

/** How a run can end (Container Apps' execution states); any other state hasn't ended. */
export const ENDED: ReadonlySet<string> = new Set(['Succeeded', 'Failed', 'Stopped', 'Degraded']);

/** How often a run's state is read while it goes. */
export const POLL_MS = 15_000;

/**
 * How long past the job's own time limit a run is waited for: the limit counts
 * from the container's start, and before that the platform schedules the
 * replica and pulls the image.
 */
export const START_ALLOWANCE_SECONDS = 300;

/** The workspace the apps and jobs log to (names.bicep); a test holds the two equal. */
export const WORKSPACE = 'log-agentx-stg';

/** Log Analytics' query API, and the audience its token is for (the `.azure.com` one is refused, S19). */
const LOG_API = 'https://api.loganalytics.azure.com/v1/workspaces/';
const LOG_AUDIENCE = 'https://api.loganalytics.io';

/**
 * How long after a run's end its log may still be arriving: a container's
 * lines reach the workspace 5 to 10 minutes after they are written, the
 * platform's within a minute (S19).
 */
const LOG_DELAY_MS = 15 * 60_000;

/** How often the log is read while it arrives; two readings this far apart with the same lines settle it. */
const LOG_POLL_MS = 60_000;

/** How far either side of the run the log is searched, for clocks that disagree a little. */
const LOG_MARGIN_MS = 5 * 60_000;

export type Request =
  | { readonly command: 'start' | 'run'; readonly job: Job }
  | { readonly command: 'wait'; readonly job: Job; readonly execution: string }
  | { readonly command: 'cleanup'; readonly job: 'zitadel-setup' };

/** The Container Apps API version the stuck-step run is started with (Microsoft.App/jobs in apps.bicep); a test holds the two equal. */
export const JOBS_API = '2026-01-01';

/** What the setup job runs instead, once, to cancel a step a dead run left marked as started. */
const CLEANUP_ARGS = ['setup', 'cleanup'] as const;

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export const USAGE = `Usage:
  node deploy/azure/jobs.ts run <job>             start the job, wait for the run to end, read its log
  node deploy/azure/jobs.ts start <job>           start it only
  node deploy/azure/jobs.ts wait <job> <run>      wait for a run to end, read its log
  node deploy/azure/jobs.ts cleanup               clear a step a dead Zitadel setup run left started
The jobs, in the order a first deploy runs them: ${JOBS.join(', ')}`;

const isJob = (value: string | undefined): value is Job => JOBS.some((job) => job === value);

/** The part of a run's name Azure gives it, after the job's name and a hyphen. */
const RUN_SUFFIX = /^[a-z0-9]+$/;

/**
 * Whether a name is one of the job's runs. A fixed pattern and a prefix, never
 * a pattern built from what was typed (CodeQL js/regex-injection).
 */
export const isRunOf = (job: Job, execution: string): boolean => {
  const prefix = `${jobName(job)}-`;
  return execution.startsWith(prefix) && RUN_SUFFIX.test(execution.slice(prefix.length));
};

/** What the operator asked for, or a UsageError saying why it can't be done. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, job, ...rest] = argv;
  if (command === 'cleanup') {
    // Only Zitadel's setup marks its steps, so there is no job to name.
    if (job !== undefined) {
      throw new UsageError(`cleanup takes nothing: it is for zitadel-setup alone, not ${argv.slice(1).join(' ')}`);
    }
    return { command, job: 'zitadel-setup' };
  }
  if (command !== 'start' && command !== 'run' && command !== 'wait') {
    throw new UsageError(`say run, start, wait or cleanup, not ${command ?? 'nothing'}`);
  }
  if (!isJob(job)) throw new UsageError(`${job ?? 'nothing'} isn't a job: ${JOBS.join(', ')}`);
  if (command !== 'wait') {
    if (rest.length > 0) throw new UsageError(`${command} takes one job, not ${rest.join(' ')} as well`);
    return { command, job };
  }
  const [execution, ...extra] = rest;
  if (execution === undefined || extra.length > 0 || !isRunOf(job, execution)) {
    throw new UsageError(`wait takes the job and one of its runs, named ${jobName(job)}-<suffix>`);
  }
  return { command, job, execution };
}

export interface JobSteps {
  readonly az: Az;
  readonly say: (line: string) => void;
  readonly now: () => Date;
  readonly sleep: (ms: number) => Promise<void>;
}

/** A subscription's or a workspace's ID, as Azure writes it. */
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A job in the subscription the operator is signed in to. */
interface Target {
  readonly subscription: string;
  readonly job: Job;
}

/**
 * The arguments that name a job to the CLI, the subscription included, as
 * deploy.ts names it: the CLI's default could change under a long wait.
 */
const jobArgs = ({ subscription, job }: Target): string[] => [
  '--subscription',
  subscription,
  '--name',
  jobName(job),
  '--resource-group',
  RESOURCE_GROUP,
];

/** A job as Azure has it: its own time limit, in seconds, and the containers it runs. */
interface Deployed {
  readonly limit: number;
  readonly containers: unknown;
}

/** The job as deployed; reading it also proves it is. */
function readJob(steps: JobSteps, target: Target): Deployed {
  const shown = azJson(steps.az, ['containerapp', 'job', 'show', ...jobArgs(target)]) as {
    properties?: { configuration?: { replicaTimeout?: unknown }; template?: { containers?: unknown } };
  };
  const seconds = shown.properties?.configuration?.replicaTimeout;
  if (typeof seconds !== 'number' || !Number.isInteger(seconds) || seconds <= 0) {
    throw new Error(`Azure gave no time limit for ${jobName(target.job)}, so how long to wait is unknown.`);
  }
  return { limit: seconds, containers: shown.properties?.template?.containers };
}

/** One container of a run started with other arguments, in the fields a run's template takes (no mounts). */
interface RunContainer {
  readonly name: string;
  readonly image: string;
  readonly command: readonly string[];
  readonly args: readonly string[];
  readonly env: readonly (
    { readonly name: string; readonly value: string } | { readonly name: string; readonly secretRef: string }
  )[];
  readonly resources: { readonly cpu: number; readonly memory: string };
}

const isStrings = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string');

/**
 * The setup job's own container with `setup cleanup` as its arguments, and
 * nothing else changed: the same image, command, settings and size. The
 * settings are copied as names with values or with secret references only, so
 * no secret value is ever in hand. Anything that isn't the Zitadel setup this
 * tool knows is refused rather than guessed at.
 */
export function cleanupContainers(containers: unknown): RunContainer[] {
  const name = jobName('zitadel-setup');
  const refuse = (why: string): never => {
    throw new Error(`${name} isn't the Zitadel setup this tool knows (${why}), so it wasn't started to clean up.`);
  };
  if (!Array.isArray(containers) || containers.length !== 1) return refuse('it must run exactly one container');
  const container = (containers as readonly Record<string, unknown>[])[0] ?? {};
  const { image, command, args, env, resources } = container;
  if (container.name !== 'zitadel-setup') return refuse('its container is not named zitadel-setup');
  if (typeof image !== 'string' || !image.startsWith('ghcr.io/zitadel/zitadel:')) {
    return refuse("its image isn't Zitadel's");
  }
  if (!isStrings(command) || command.join(' ') !== '/app/zitadel') return refuse("its command isn't /app/zitadel");
  if (!isStrings(args) || args[0] !== 'setup') return refuse("its arguments don't start with setup");
  const size = resources as { cpu?: unknown; memory?: unknown } | undefined;
  if (typeof size?.cpu !== 'number' || typeof size.memory !== 'string') return refuse('its size is not given');
  if (!Array.isArray(env)) return refuse('its settings are not a list');
  const settings = (env as readonly ({ name?: unknown; value?: unknown; secretRef?: unknown } | null)[]).map(
    (entry) => {
      const setting = entry ?? {};
      if (typeof setting.name !== 'string') return refuse('a setting has no name');
      if (typeof setting.secretRef === 'string' && setting.value === undefined) {
        return { name: setting.name, secretRef: setting.secretRef };
      }
      if (typeof setting.value === 'string' && setting.secretRef === undefined) {
        return { name: setting.name, value: setting.value };
      }
      return refuse(`the setting ${setting.name} has neither a value nor a secret reference alone`);
    },
  );
  return [
    {
      name: container.name,
      image,
      command,
      args: [...CLEANUP_ARGS],
      env: settings,
      resources: { cpu: size.cpu, memory: size.memory },
    },
  ];
}

/**
 * Starts a run with other containers, through Resource Manager: the only way to
 * change a run's arguments, since CLI 2.90.0's `job start --args` sends a
 * container with no image and no settings (S19). The body is never repeated in
 * a message, though it holds no secret value.
 */
function startWith(steps: JobSteps, target: Target, containers: readonly RunContainer[]): unknown {
  const name = jobName(target.job);
  const done = steps.az.run([
    'rest',
    '--method',
    'post',
    '--url',
    `${ARM}subscriptions/${target.subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/jobs/${name}/start?api-version=${JOBS_API}`,
    '--body',
    JSON.stringify({ containers }),
  ]);
  if (done.status !== 0) throw new Error(`Azure refused to start ${name} to clean up:\n${done.stderr.trim()}`);
  if (done.stdout.trim() === '') {
    // The start is a long-running operation, which may answer 202 with no body.
    throw new Error(
      `Azure took the start of ${name} without naming the run. Find it with az containerapp job execution list --subscription ${target.subscription} --name ${name} --resource-group ${RESOURCE_GROUP}, and start nothing else until it has ended.`,
    );
  }
  return JSON.parse(done.stdout) as unknown;
}

/** The job's runs that haven't ended, with their states. */
function unfinishedRuns(steps: JobSteps, target: Target): string[] {
  const runs = azJson(steps.az, ['containerapp', 'job', 'execution', 'list', ...jobArgs(target)]);
  if (!Array.isArray(runs)) throw new Error(`Azure's list of ${jobName(target.job)}'s runs wasn't a list.`);
  return (runs as readonly { name?: unknown; properties?: { status?: unknown } }[])
    .filter((run) => !ENDED.has(text(run.properties?.status)))
    .map((run) => `${text(run.name)} (${text(run.properties?.status) || 'no state'})`);
}

/**
 * Starts the job, once nothing of it is still going, as it is deployed or with
 * the containers given: the new run's name.
 */
function start(steps: JobSteps, target: Target, containers?: readonly RunContainer[]): string {
  const name = jobName(target.job);
  const going = unfinishedRuns(steps, target);
  if (going.length > 0) {
    throw new Error(
      `${name} has runs that haven't ended, so it wasn't started: ${going.join(', ')}. Wait for them, or stop one with az containerapp job stop --subscription ${target.subscription} --name ${name} --resource-group ${RESOURCE_GROUP} --job-execution-name <run>.`,
    );
  }
  const started = (
    containers === undefined
      ? azJson(steps.az, ['containerapp', 'job', 'start', ...jobArgs(target)])
      : startWith(steps, target, containers)
  ) as { name?: unknown } | null;
  const execution = text(started?.name);
  if (!isRunOf(target.job, execution)) {
    throw new Error(`Azure started ${name} but named the run "${execution}", which isn't one of its runs.`);
  }
  steps.say(`Started ${execution}.`);
  return execution;
}

/** A time Azure gave, as HH:MM:SS UTC, or what it was when it isn't one. */
function clock(value: string): string {
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? `"${value}"` : `${at.toISOString().slice(11, 19)} UTC`;
}

/** What to run after a job that succeeded, in a first deploy. */
function after(job: Job): string {
  const next = JOBS[JOBS.indexOf(job) + 1];
  return next === undefined
    ? 'That is the last of the four a first deploy runs.'
    : `In a first deploy, the next is: node deploy/azure/jobs.ts run ${next}`;
}

/** How a run ended: its state, and its start and end as Azure gave them. */
interface Ended {
  readonly status: string;
  readonly began: string;
  readonly ended: string;
}

/** Waits for a run to end, `limit` being the job's time limit: how it ended, or nothing when it didn't in time. */
async function waitFor(steps: JobSteps, target: Target, execution: string, limit: number): Promise<Ended | undefined> {
  const deadline = steps.now().getTime() + (limit + START_ALLOWANCE_SECONDS) * 1000;
  steps.say(`Waiting for ${execution} to end (the job gives up after ${String(limit)} s)...`);
  let last: string | undefined;
  for (;;) {
    const run = azJson(steps.az, [
      'containerapp',
      'job',
      'execution',
      'show',
      ...jobArgs(target),
      '--job-execution-name',
      execution,
    ]) as { properties?: { status?: unknown; startTime?: unknown; endTime?: unknown } };
    const status = text(run.properties?.status);
    if (status !== last) {
      steps.say(`  ${steps.now().toISOString().slice(11, 19)} UTC  ${status || 'no state yet'}`);
      last = status;
    }
    if (ENDED.has(status)) {
      const began = text(run.properties?.startTime);
      const ended = text(run.properties?.endTime);
      const seconds = (new Date(ended).getTime() - new Date(began).getTime()) / 1000;
      const took = Number.isFinite(seconds) ? ` (${String(seconds)} s)` : '';
      steps.say(`${execution} ended ${status}: started ${clock(began)}, ended ${clock(ended)}${took}.`);
      return { status, began, ended };
    }
    if (steps.now().getTime() >= deadline) {
      steps.say(
        `${execution} hadn't ended ${String(limit + START_ALLOWANCE_SECONDS)} s after the wait began. To wait again: node deploy/azure/jobs.ts wait ${target.job} ${execution}`,
      );
      return undefined;
    }
    await steps.sleep(POLL_MS);
  }
}

/** The workspace's own ID, which the query API takes. */
function workspaceId(steps: JobSteps, subscription: string): string {
  const workspace = azJson(steps.az, [
    'rest',
    '--method',
    'get',
    '--url',
    `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE}?api-version=2025-02-01`,
  ]) as { properties?: { customerId?: unknown } };
  const id = text(workspace.properties?.customerId);
  if (!GUID.test(id)) throw new Error(`Azure gave no ID for ${WORKSPACE}, so the log can't be read.`);
  return id;
}

/**
 * Everything logged about one run, oldest first: the platform's lines (which
 * name the run in the replica's name, or in the text for the run's own events)
 * and the container's (whose group is named after the run). Both names are
 * held to `isRunOf` before they get here, so neither can end a string early.
 */
const logQuery = (job: Job, execution: string): string =>
  [
    'union',
    `(ContainerAppSystemLogs | where JobName == '${jobName(job)}' and (ReplicaName startswith_cs '${execution}-' or Log contains_cs "'${execution}'") | project TimeGenerated, Source = 'platform', Reason, Text = Log),`,
    `(ContainerAppConsoleLogs | where JobName == '${jobName(job)}' and ContainerGroupName startswith_cs '${execution}-' | project TimeGenerated, Source = Stream, Reason = '', Text = Log)`,
    '| order by TimeGenerated asc',
  ].join('\n');

interface LogLine {
  readonly time: string;
  readonly source: string;
  readonly reason: string;
  readonly text: string;
}

/** The query's rows, or an error when the answer isn't the table asked for. */
function logLines(answer: unknown): LogLine[] {
  const table = (answer as { tables?: readonly { columns?: readonly { name?: unknown }[]; rows?: unknown }[] })
    .tables?.[0];
  const columns = (table?.columns ?? []).map((column) => text(column.name));
  const wanted = ['TimeGenerated', 'Source', 'Reason', 'Text'];
  if (!Array.isArray(table?.rows) || !wanted.every((column) => columns.includes(column))) {
    throw new Error("Log Analytics' answer wasn't the table asked for.");
  }
  return (table.rows as readonly unknown[]).map((row) => {
    if (!Array.isArray(row)) throw new Error("Log Analytics' answer held a row that isn't one.");
    const cell = (column: string): string => text((row as readonly unknown[])[columns.indexOf(column)]);
    return { time: cell('TimeGenerated'), source: cell('Source'), reason: cell('Reason'), text: cell('Text') };
  });
}

/** The HH:MM:SS of a time the workspace gave. */
const TIME_OF_DAY = /T(\d{2}:\d{2}:\d{2})/;

/** A line as the operator reads it: the time, where it came from, what it says. */
function shown(line: LogLine): string {
  const time = TIME_OF_DAY.exec(line.time)?.[1] ?? line.time;
  return `  ${time}  ${line.source.padEnd(8)}  ${line.reason === '' ? '' : `${line.reason}: `}${line.text}`;
}

/**
 * Reads a run's log once it has all arrived, and shows it. It has arrived when
 * the platform has logged the container's end and two readings a minute apart
 * hold the same container lines, or when the run ended long enough ago that
 * nothing more will come.
 */
async function readLog(steps: JobSteps, target: Target, execution: string, run: Ended): Promise<void> {
  const began = Date.parse(run.began);
  const ended = Date.parse(run.ended);
  if (!Number.isFinite(began) || !Number.isFinite(ended)) {
    throw new Error(`Azure gave no start and end for ${execution}, so its log can't be looked for.`);
  }
  const workspace = workspaceId(steps, target.subscription);
  const query = logQuery(target.job, execution);
  let previous: number | undefined;
  for (let reading = 0; ; reading += 1) {
    const now = steps.now().getTime();
    const timespan = `${new Date(began - LOG_MARGIN_MS).toISOString()}/${new Date(Math.max(now, ended) + LOG_MARGIN_MS).toISOString()}`;
    const lines = logLines(
      azJson(steps.az, [
        'rest',
        '--method',
        'post',
        '--url',
        `${LOG_API}${workspace}/query`,
        '--resource',
        LOG_AUDIENCE,
        '--body',
        JSON.stringify({ query, timespan }),
      ]),
    );
    const fromContainer = lines.filter((line) => line.source !== 'platform').length;
    const terminated = lines.some((line) => line.reason === 'ContainerTerminated');
    const late = now >= ended + LOG_DELAY_MS;
    if (late || (terminated && fromContainer > 0 && fromContainer === previous)) {
      steps.say(
        `${execution}'s log, ${String(lines.length - fromContainer)} from the platform and ${String(fromContainer)} from the container:`,
      );
      for (const line of lines) steps.say(shown(line));
      if (!terminated) {
        steps.say("Azure logged no end for the container, so these may not be all the run's lines.");
      } else if (fromContainer === 0) {
        steps.say('No line from the container reached the workspace.');
      } else if (previous !== undefined && fromContainer !== previous) {
        // Late with the lines still changing: a run read long after it ended has had no earlier reading to differ from.
        steps.say("The container's lines were still arriving 15 minutes after the run ended, so more may be missing.");
      }
      return;
    }
    if (reading === 0) {
      steps.say(
        `Reading ${execution}'s log: Azure delivers a container's lines up to 10 minutes after they are written, so this can take that long...`,
      );
    }
    previous = fromContainer;
    await steps.sleep(LOG_POLL_MS);
  }
}

export async function jobs(request: Request, steps: JobSteps): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  if (!GUID.test(subscription)) throw new Error('Azure gave no subscription ID: is the CLI signed in?');
  const target = { subscription, job: request.job };
  // Read first, so a job that isn't deployed is refused before anything starts.
  const deployed = readJob(steps, target);
  switch (request.command) {
    case 'start': {
      const execution = start(steps, target);
      steps.say(`To wait for it: node deploy/azure/jobs.ts wait ${request.job} ${execution}`);
      return 0;
    }
    case 'run':
      return finish(steps, target, start(steps, target), deployed.limit, after(target.job));
    case 'wait':
      return finish(steps, target, request.execution, deployed.limit, after(target.job));
    case 'cleanup': {
      // The containers are checked before anything starts.
      const execution = start(steps, target, cleanupContainers(deployed.containers));
      return finish(
        steps,
        target,
        execution,
        deployed.limit,
        'The clean-up has run: the lines above say which step it cancelled, if any. Now run setup again: node deploy/azure/jobs.ts run zitadel-setup',
      );
    }
  }
}

/** Waits for a run, shows its log, and says what comes next: 0 only when it succeeded. */
async function finish(
  steps: JobSteps,
  target: Target,
  execution: string,
  limit: number,
  next: string,
): Promise<number> {
  const run = await waitFor(steps, target, execution, limit);
  if (run === undefined) return 1;
  await readLog(steps, target, execution, run);
  if (run.status !== 'Succeeded') {
    steps.say('Read the lines above before starting anything else.');
    return 1;
  }
  steps.say(next);
  return 0;
}

export async function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => Az = realAz,
): Promise<number> {
  let request: Request;
  try {
    request = parseArguments(argv);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    say(`${error.message}\n${USAGE}`);
    return 2;
  }
  try {
    return await jobs(request, { az: az(), say, now: () => new Date(), sleep: (ms) => sleep(ms) });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
