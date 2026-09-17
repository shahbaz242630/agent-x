// Runs staging's jobs (0e G3a), one at a time, in the order a first deploy
// needs them:
//
//   node deploy/azure/jobs.ts run db-setup
//   node deploy/azure/jobs.ts run migrate
//   node deploy/azure/jobs.ts run zitadel-init
//   node deploy/azure/jobs.ts run zitadel-setup
//
// `run` starts a job and waits for that run to end. `start` only starts it, and
// `wait <job> <run>` only waits, so a run can be started in one place and
// watched from another. Nothing is asked and no secret passes through here:
// each job reads its own from the vault (apps.bicep).
//
// A job is never started while a run of it hasn't ended: Container Apps would
// run both side by side, and two set-up runs at once race on the same roles.
import { setTimeout as sleep } from 'node:timers/promises';

import { type Az, azJson, realAz, RESOURCE_GROUP, signedIn, text } from './deploy.ts';

/** The jobs, by the work each does, in the order a first deploy runs them (names.bicep); a test holds the two equal. */
export const JOBS = ['db-setup', 'migrate', 'zitadel-init', 'zitadel-setup'] as const;
export type Job = (typeof JOBS)[number];

/** A job's name in Azure (names.bicep `jobName`). */
export const jobName = (job: Job): string => `job-agentx-stg-${job}`;

/** How a run can end (Container Apps' execution states); any other state hasn't ended. */
const ENDED: ReadonlySet<string> = new Set(['Succeeded', 'Failed', 'Stopped', 'Degraded']);

/** How often a run's state is read while it goes. */
const POLL_MS = 15_000;

/**
 * How long past the job's own time limit a run is waited for: the limit counts
 * from the container's start, and before that the platform schedules the
 * replica and pulls the image.
 */
const START_ALLOWANCE_SECONDS = 300;

export type Request =
  | { readonly command: 'start' | 'run'; readonly job: Job }
  | { readonly command: 'wait'; readonly job: Job; readonly execution: string };

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export const USAGE = `Usage:
  node deploy/azure/jobs.ts run <job>             start the job and wait for the run to end
  node deploy/azure/jobs.ts start <job>           start it only
  node deploy/azure/jobs.ts wait <job> <run>      wait for a run that has started
The jobs, in the order a first deploy runs them: ${JOBS.join(', ')}`;

const isJob = (value: string | undefined): value is Job => JOBS.some((job) => job === value);

/** What the operator asked for, or a UsageError saying why it can't be done. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, job, ...rest] = argv;
  if (command !== 'start' && command !== 'run' && command !== 'wait') {
    throw new UsageError(`say run, start or wait, not ${command ?? 'nothing'}`);
  }
  if (!isJob(job)) throw new UsageError(`${job ?? 'nothing'} isn't a job: ${JOBS.join(', ')}`);
  if (command !== 'wait') {
    if (rest.length > 0) throw new UsageError(`${command} takes one job, not ${rest.join(' ')} as well`);
    return { command, job };
  }
  const [execution, ...extra] = rest;
  // A run is named after its job, with a suffix Azure gives it.
  if (execution === undefined || extra.length > 0 || !new RegExp(`^${jobName(job)}-[a-z0-9]+$`).test(execution)) {
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

const SUBSCRIPTION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

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

/** The job's own time limit, in seconds; reading it also proves the job is deployed. */
function timeLimit(steps: JobSteps, target: Target): number {
  const shown = azJson(steps.az, ['containerapp', 'job', 'show', ...jobArgs(target)]) as {
    properties?: { configuration?: { replicaTimeout?: unknown } };
  };
  const seconds = shown.properties?.configuration?.replicaTimeout;
  if (typeof seconds !== 'number' || !Number.isInteger(seconds) || seconds <= 0) {
    throw new Error(`Azure gave no time limit for ${jobName(target.job)}, so how long to wait is unknown.`);
  }
  return seconds;
}

/** The job's runs that haven't ended, with their states. */
function unfinishedRuns(steps: JobSteps, target: Target): string[] {
  const runs = azJson(steps.az, ['containerapp', 'job', 'execution', 'list', ...jobArgs(target)]);
  if (!Array.isArray(runs)) throw new Error(`Azure's list of ${jobName(target.job)}'s runs wasn't a list.`);
  return (runs as readonly { name?: unknown; properties?: { status?: unknown } }[])
    .filter((run) => !ENDED.has(text(run.properties?.status)))
    .map((run) => `${text(run.name)} (${text(run.properties?.status) || 'no state'})`);
}

/** Starts the job, once nothing of it is still going: the new run's name. */
function start(steps: JobSteps, target: Target): string {
  const name = jobName(target.job);
  const going = unfinishedRuns(steps, target);
  if (going.length > 0) {
    throw new Error(
      `${name} has runs that haven't ended, so it wasn't started: ${going.join(', ')}. Wait for them, or stop one with az containerapp job stop --subscription ${target.subscription} --name ${name} --resource-group ${RESOURCE_GROUP} --job-execution-name <run>.`,
    );
  }
  const started = azJson(steps.az, ['containerapp', 'job', 'start', ...jobArgs(target)]) as { name?: unknown };
  const execution = text(started.name);
  if (!execution.startsWith(`${name}-`)) {
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

/** Waits for a run to end, `limit` being the job's time limit: 0 when it succeeded, 1 for any other end or none in time. */
async function waitFor(steps: JobSteps, target: Target, execution: string, limit: number): Promise<number> {
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
      if (status !== 'Succeeded') {
        steps.say('Read its logs before starting anything else.');
        return 1;
      }
      steps.say(after(target.job));
      return 0;
    }
    if (steps.now().getTime() >= deadline) {
      steps.say(
        `${execution} hadn't ended ${String(limit + START_ALLOWANCE_SECONDS)} s after the wait began. To wait again: node deploy/azure/jobs.ts wait ${target.job} ${execution}`,
      );
      return 1;
    }
    await steps.sleep(POLL_MS);
  }
}

export async function jobs(request: Request, steps: JobSteps): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  if (!SUBSCRIPTION_ID.test(subscription)) throw new Error('Azure gave no subscription ID: is the CLI signed in?');
  const target = { subscription, job: request.job };
  // Read first, so a job that isn't deployed is refused before anything starts.
  const limit = timeLimit(steps, target);
  switch (request.command) {
    case 'start': {
      const execution = start(steps, target);
      steps.say(`To wait for it: node deploy/azure/jobs.ts wait ${request.job} ${execution}`);
      return 0;
    }
    case 'run':
      return waitFor(steps, target, start(steps, target), limit);
    case 'wait':
      return waitFor(steps, target, request.execution, limit);
  }
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
