// The load jobs' shared steps (D2c, 4D2e Stage G): load.ts runs PL-38's jobs
// with them and stage-g.ts Stage G's, each the same way: the run's request
// written onto the job as a held secret (held-request.ts), the job started and
// waited for, {} put back whatever happened, and the job's own JSON lines read
// from the workspace; and the API as it runs, with its replicas and restarts.
import { type Az, text } from './deploy.ts';
import { asciiJson, lastModified, reason, sendPatch, type VaultReference, vaultReferences } from './held-request.ts';
import {
  type Ended,
  jobName,
  type JobSteps,
  type LoadJob,
  type LogLine,
  POLL_MS,
  readLog,
  STAGE_G_JOBS,
  type StageGJob,
  start,
  type Target,
  waitFor,
} from './jobs.ts';
import { get, record, resourceUrl } from './release.ts';

/** A job a load tool runs: PL-38's or Stage G's. */
export type RunnableJob = LoadJob | StageGJob;

/** The secret each load job holds its run's request in (apps.bicep `loadRequest`; policy.ts `HELD`). */
const LOAD_REQUEST = 'load-request';

/** What a load job holds between runs: no request, which the jobs refuse. */
export const NO_REQUEST = '{}';

/** Where the load image is published (verify.ts `LOAD_SIGNER`), as a job names it, by digest. */
const LOAD_IMAGE = /^ghcr\.io\/shahbaz242630\/agent-x-load@sha256:[0-9a-f]{64}$/;

/** The API, as apps.bicep names it. */
export const API_APP = 'ca-agentx-stg-api';

/** How long a change to a job, or the API's restart, may take to settle. */
export const SETTLE_MS = 10 * 60_000;

/** The script each job runs, in the load image: Stage G's its own. */
const scriptOf = (job: RunnableJob): string =>
  (STAGE_G_JOBS as readonly string[]).includes(job) ? 'tooling/load/stageg-job.ts' : 'tooling/load/job.ts';

/** A load job as Azure has it, checked: what a change sends back of it, and where it stands. */
interface LoadJobState {
  readonly references: readonly VaultReference[];
  readonly state: string;
  readonly modified: string;
}

export const loadJobUrl = (subscription: string, job: RunnableJob): string =>
  resourceUrl(subscription, { path: `jobs/${jobName(job)}`, container: job });

/** Whether the load job is there at all: an earlier finish may have removed it. */
export const jobThere = (az: Az, subscription: string, job: RunnableJob): boolean =>
  az.run(['rest', '--method', 'get', '--url', loadJobUrl(subscription, job), '--output', 'json']).status === 0;

/**
 * A load job, read from Azure, or an error saying why it isn't one as
 * apps.bicep deploys it: one container on the load image by digest, running
 * `node <its script> <its part>`, its request held once.
 */
export function readLoadJob(steps: JobSteps, subscription: string, job: RunnableJob): LoadJobState {
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
  const script = scriptOf(job);
  if (JSON.stringify([container.command, container.args]) !== JSON.stringify([['node', script], [part]])) {
    refuse(`it must run node ${script} ${part}`);
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
async function writeRequest(steps: JobSteps, subscription: string, job: RunnableJob, value: string): Promise<void> {
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

export type Printed = Readonly<Record<string, unknown>>;

/** A job's own JSON lines (what job.ts prints), from its run's log; the platform's lines and Node's own are skipped. */
export function printedLines(lines: readonly LogLine[]): Printed[] {
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
export interface JobRun {
  readonly run: Ended;
  readonly printed: Printed[];
  readonly putBack: string | undefined;
}

/**
 * A run's lines. One that didn't succeed and has no readable start never ran, as far as anything can tell, and has
 * none to look for: the report says it failed, where a refused read would lose every phase already measured.
 */
export const runLines = async (steps: JobSteps, target: Target, execution: string, run: Ended, lastEvent?: string) =>
  run.status !== 'Succeeded' && !Number.isFinite(Date.parse(run.began))
    ? []
    : printedLines(await readLog(steps, target, execution, run, lastEvent));

/** How a run of a load job goes: what it is told, the line it prints last, and what to do when it outlasts the wait. */
export interface RunOptions {
  /** Written onto the job first and {} put back after; undefined for a job that holds none (load-mark). */
  readonly request: Readonly<Record<string, unknown>> | undefined;
  /** The line the job prints last when it succeeds: its log is read until that line has arrived. */
  readonly lastEvent: string;
  /** What the partner does when the run outlasts the wait. */
  readonly ifStuck: string;
  /** Told the run's name as soon as it has one. */
  readonly started?: (execution: string) => void;
}

/**
 * One run of a load job with its request written onto it first and {} put
 * back whatever happened. A put-back that failed after a run that ended is
 * said with its lines, never in their place.
 */
export async function runWith(
  steps: JobSteps,
  subscription: string,
  job: RunnableJob,
  { request, lastEvent, ifStuck, started = () => undefined }: RunOptions,
): Promise<JobRun> {
  const target: Target = { subscription, job };
  const limit = limitOf(steps.az, subscription, job);
  let execution: string | undefined;
  let run: Ended | undefined;
  let failure: unknown;
  try {
    if (request !== undefined) await writeRequest(steps, subscription, job, JSON.stringify(request));
    execution = start(steps, target);
    started(execution);
    run = await waitFor(steps, target, execution, limit);
  } catch (error) {
    failure = error;
  }
  let putBack: string | undefined;
  try {
    if (request !== undefined) await writeRequest(steps, subscription, job, NO_REQUEST);
  } catch (error) {
    putBack = `${NO_REQUEST} wasn't put back on ${jobName(job)} (${reason(error)}): apps --load-run deploys it back.`;
  }
  const also = putBack === undefined ? '' : ` ${putBack}`;
  if (failure !== undefined) throw new Error(`${reason(failure)}${also}`, { cause: failure });
  if (execution === undefined || run === undefined) {
    throw new Error(`${String(execution)} didn't end in time: ${ifStuck}${also}`);
  }
  return { run, printed: await runLines(steps, target, execution, run, lastEvent), putBack };
}

/** A job's own time limit, in seconds. */
export function limitOf(az: Az, subscription: string, job: RunnableJob): number {
  const limit = record(
    record(get(az, loadJobUrl(subscription, job), jobName(job)).properties).configuration,
  ).replicaTimeout;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit <= 0) {
    throw new Error(`Azure gave no time limit for ${jobName(job)}.`);
  }
  return limit;
}

/** The API as it now runs: its CPUs, whether it keeps a copy running, its newest revision and its build. */
export interface Api {
  readonly cpus: number;
  readonly fewest: number;
  readonly revision: string;
  readonly release: string;
}

export const apiUrl = (subscription: string, rest = ''): string =>
  resourceUrl(subscription, { path: `containerApps/${API_APP}${rest}`, container: 'api' });

export function readApi(az: Az, subscription: string): Api {
  const properties = record(get(az, apiUrl(subscription), 'the API').properties);
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

/** One of the revision's replicas: its name and its containers' restarts summed. */
export interface Replica {
  readonly name: string;
  readonly restarts: number;
}

/** The revision's replicas, `shape` as `name restarts` each, and whether every one runs. */
export function replicasOf(az: Az, subscription: string, revision: string) {
  const listed = record(get(az, apiUrl(subscription, `/revisions/${revision}/replicas`), "the API's replicas")).value;
  const replicas = Array.isArray(listed) ? listed.map(record) : [];
  const restarts = (replica: Readonly<Record<string, unknown>>): number => {
    const containers = record(replica.properties).containers;
    return Array.isArray(containers)
      ? containers.map(record).reduce((sum, container) => sum + Number(container.restartCount ?? 0), 0)
      : 0;
  };
  const each: Replica[] = replicas.map((replica) => ({ name: text(replica.name), restarts: restarts(replica) }));
  return {
    each,
    shape: each.map(({ name, restarts: count }) => `${name} ${String(count)}`).join(','),
    running:
      replicas.length > 0 && replicas.every((replica) => text(record(replica.properties).runningState) === 'Running'),
  };
}

/** One event's lines among a job's, by name, or its first. */
export const linesOf = (printed: readonly Printed[], event: string) => printed.filter((line) => line.event === event);
export const lineOf = (printed: readonly Printed[], event: string) => printed.find((line) => line.event === event);

/** How a job's run ended, with its own reason when it refused: `Failed: hand-offs are running`. */
export const endedAs = (run: Ended, printed: readonly Printed[], refusal = 'load.refused'): string => {
  const refused = lineOf(printed, refusal);
  return refused === undefined ? run.status : `${run.status}: ${text(refused.reason)}`;
};
