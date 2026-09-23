// Runs the operator's command on its job (B1c-2b; ADR-011 §3, ADR-005 §6):
//
//   node deploy/azure/operator.ts create-organization --name <name> [--id <ID>]
//
// The job holds its request as a secret of its own (B1c-2a), since a run
// started with containers of its own loses every mounted file, its login and
// key among them. So this:
// 1. reads the job and the API, and refuses a job that isn't the operator's as
//    apps.bicep deploys it, one still settling an earlier change, or one with
//    a run still going
// 2. makes the new organisation's ID, or takes --id: the ID an earlier run
//    gave whose end was unclear, which can never make a second organisation
// 3. writes the request onto the job in one PATCH of its secrets, every vault
//    reference sent back as it was read, and in the same PATCH brings the
//    job's container to the image and build the API runs (CI's release moves
//    the API and migrate alone), then waits until Azure has taken it
// 4. starts the job as it is, never with containers of its own, and waits
// 5. puts [] back whatever happened, and waits until Azure has taken that
// 6. reads the run's log and says what the run did: created the
//    organisation, found it done already (nothing changed), or neither
// The request is never printed, nor put on a command line: it goes to Azure in
// a file only this user can read, removed straight after, with every character
// past ASCII escaped so the CLI can't misread its encoding. A read of the job
// never shows it back. Starting the job is the partner's (ADR-005 §6: the
// right to start it is the API's own authority), so this runs from their `!`.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import {
  createOrganizationRequest,
  NO_REQUEST_PROBLEM,
  REQUEST_LIMIT_BYTES,
  UUID_V7,
} from '../../apps/operator/src/request.ts';
import { uuidV7Ids } from '../../packages/core/src/shared-kernel/ids.ts';
import { realAz, signedIn, text } from './deploy.ts';
import {
  type Ended,
  jobName,
  type JobSteps,
  type LogLine,
  POLL_MS,
  readLog,
  start,
  type Target,
  unfinishedRuns,
  UsageError,
  waitFor,
} from './jobs.ts';
import {
  azureRefusal,
  changes,
  type Container,
  get,
  readWorkload,
  record,
  released,
  resourceUrl,
  type Running,
  runningAs,
  same,
  type WorkloadSpec,
} from './release.ts';

/** The operator's job, as apps.bicep deploys it; a test holds the two equal. */
export const OPERATOR_JOB: WorkloadSpec = { path: `jobs/${jobName('operator')}`, container: 'operator' };

/** The secret the job holds its request in (apps.bicep `operatorRequest`); a test holds the two equal. */
export const REQUEST_SECRET = 'operator-request';

/** What the job holds between runs: no request, which the command refuses (B1c-2a). */
export const NO_REQUEST = '[]';

/** What the job runs: the command, reading its request from the file the secret is mounted as (policy.ts `HELD`). */
const RUNS = ['node', 'apps/operator/src/main.ts', '--request', `/mnt/secrets/${REQUEST_SECRET}`];

/** How long a change to the job may take to settle. */
const SETTLE_MS = 5 * 60_000;

/** Any ID, for the size of a request before its own is made: every ID is as long. */
const SOME_ID = '00000000-0000-7000-8000-000000000000';

export const USAGE = `Usage:
  node deploy/azure/operator.ts create-organization --name <name> [--id <ID>]
The name is one argument: quote it if it holds a space. --id repeats the ID an earlier run gave when its end was unclear; the same ID can never make a second organisation.`;

/** What the partner asked for: a new organisation's name, and the ID of an earlier try if this is one. */
export interface Request {
  readonly name: string;
  readonly id: string | undefined;
}

/** What was asked for, or a UsageError saying why it can't be done. Nothing typed is repeated in one. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, flag, name, ...rest] = argv;
  const [idFlag, id, ...more] = rest;
  const ided = rest.length === 0 || (idFlag === '--id' && id !== undefined && more.length === 0);
  if (command !== 'create-organization' || flag !== '--name' || name === undefined || name === '' || !ided) {
    throw new UsageError(
      'say create-organization --name <name> [--id <ID>], the name as one argument, and nothing else',
    );
  }
  if (id !== undefined && !UUID_V7.test(id)) {
    throw new UsageError('--id takes the ID an earlier run gave: a UUIDv7, in lower case');
  }
  if (Buffer.byteLength(createOrganizationRequest(name, SOME_ID)) > REQUEST_LIMIT_BYTES) {
    throw new UsageError(
      `the name makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`,
    );
  }
  return { name, id };
}

/** One of the job's secrets that the vault holds, as Azure gives it back: sent back just so. */
interface VaultReference {
  readonly name: string;
  readonly keyVaultUrl: string;
  readonly identity: string;
}

/** The operator's job as Azure has it, checked: what a change sends back of it, and where it stands. */
interface OperatorJob {
  readonly running: Running;
  readonly references: readonly VaultReference[];
  /** How long one run may take, in seconds. */
  readonly limit: number;
  readonly state: string;
  /** When Azure last took a change to it: a change of ours has settled only once this moves on. */
  readonly modified: string;
}

/**
 * The job, read from Azure, or an error saying why it isn't the operator's job
 * as apps.bicep deploys it: its container as a release knows one, running the
 * command on its request's file and nothing else; its request held once, with
 * nothing shown of it; every other secret a reference to the vault; a time
 * limit; and the time of its last change, which tells a change of ours apart.
 */
function readOperatorJob(steps: JobSteps, target: Target): OperatorJob {
  const known = "the operator's job this tool knows";
  const refuse = (why: string): never => {
    throw new Error(`${OPERATOR_JOB.path} isn't ${known} (${why}): deploy it by hand.`);
  };
  const found = get(steps.az, resourceUrl(target.subscription, OPERATOR_JOB), "the operator's job");
  const properties = record(found.properties);
  const configuration = record(properties.configuration);
  const running = runningAs(OPERATOR_JOB, known, record(properties.template).containers);
  if (JSON.stringify([...running.container.command, ...running.container.args]) !== JSON.stringify(RUNS)) {
    refuse(`it must run ${RUNS.join(' ')}`);
  }
  if (!Array.isArray(configuration.secrets)) return refuse('its secrets are not a list');
  const secrets = configuration.secrets.map(record);
  const held = secrets.filter((secret) => secret.name === REQUEST_SECRET);
  if (held.length !== 1 || Object.keys(held[0] ?? {}).some((field) => field !== 'name')) {
    refuse(`it must hold ${REQUEST_SECRET} once, nothing of it shown`);
  }
  const references = secrets
    .filter((secret) => secret.name !== REQUEST_SECRET)
    .map(({ name, keyVaultUrl, identity, ...other }) =>
      typeof name === 'string' &&
      typeof keyVaultUrl === 'string' &&
      typeof identity === 'string' &&
      Object.keys(other).length === 0
        ? { name, keyVaultUrl, identity }
        : refuse('a secret other than its request is more than a reference to the vault'),
    );
  const limit = configuration.replicaTimeout;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit <= 0) return refuse('it has no time limit');
  const modified = text(record(found.systemData).lastModifiedAt);
  if (modified === '') return refuse("Azure gave no time of its last change, so one of ours can't be told apart");
  return { running, references, limit, state: text(properties.provisioningState), modified };
}

/**
 * JSON text with every character past ASCII written as its escape: the file
 * then reads the same in any encoding the CLI might take it to be in, and a
 * name is never kept misread for good.
 */
const asciiJson = (json: string): string =>
  json.replace(/[^ -~]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);

/**
 * The PATCH that sets the job's request to `value`: the secrets list whole,
 * since Azure's PATCH replaces a list whole, every vault reference as it was
 * read; and the container, when it is given.
 */
const patchBody = (job: OperatorJob, value: string, container?: Container): string =>
  asciiJson(
    JSON.stringify({
      properties: {
        configuration: { secrets: [...job.references, { name: REQUEST_SECRET, value }] },
        ...(container === undefined ? {} : { template: { containers: [container] } }),
      },
    }),
  );

/**
 * Sends a PATCH to the job from a file only this user can read, removed
 * straight after: the request stays off every command line. Azure's message
 * isn't shown, since it can quote what was sent.
 */
function patch(steps: JobSteps, target: Target, body: string, what: string): void {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-'));
  try {
    const file = path.join(folder, 'patch.json');
    writeFileSync(file, body, { mode: 0o600 });
    const done = steps.az.run([
      'rest',
      '--method',
      'patch',
      '--url',
      resourceUrl(target.subscription, OPERATOR_JOB),
      '--body',
      `@${file}`,
    ]);
    if (done.status !== 0) {
      throw new Error(
        `Azure refused ${what} (${azureRefusal(done.stderr)}). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it.`,
      );
    }
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
}

/**
 * Waits until Azure has taken a change sent after `before` (the time of the
 * job's last change then), holding `container`, marked Succeeded. Just after
 * the PATCH the job can still show the state its earlier change left, so only
 * a state after that time counts.
 */
async function settled(
  steps: JobSteps,
  target: Target,
  before: string,
  container: Container,
  what: string,
): Promise<OperatorJob> {
  const deadline = steps.now().getTime() + SETTLE_MS;
  for (;;) {
    const job = readOperatorJob(steps, target);
    const taken = job.modified !== before && same(job.running.container, container);
    if (taken && job.state === 'Succeeded') return job;
    if (taken && (job.state === 'Failed' || job.state === 'Canceled')) {
      throw new Error(`Azure's change to ${jobName('operator')} for ${what} ended ${job.state}.`);
    }
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `Azure hadn't settled ${what} on ${jobName('operator')} after ${String(SETTLE_MS / 60_000)} minutes (${job.state}${taken ? '' : ', not yet taken'}).`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/** Puts [] back as the job's request, every vault reference as it is now, and waits until Azure has taken it. */
async function clearRequest(steps: JobSteps, target: Target): Promise<void> {
  const job = readOperatorJob(steps, target);
  const what = `putting ${NO_REQUEST} back`;
  patch(steps, target, patchBody(job, NO_REQUEST), what);
  await settled(steps, target, job.modified, job.running.container, what);
  steps.say(`Put ${NO_REQUEST} back on ${jobName('operator')}: its next run holds no request until one is written.`);
}

/** The operator's command's own lines in a run: JSON, each naming its `event`. */
function commandLines(lines: readonly LogLine[]): Readonly<Record<string, unknown>>[] {
  return lines
    .filter((line) => line.source !== 'platform')
    .flatMap((line) => {
      try {
        const said = record(JSON.parse(line.text));
        return typeof said.event === 'string' ? [said] : [];
      } catch (error) {
        // A line that isn't the command's JSON (Node's own, say) is shown above and read as none of its own.
        if (error instanceof SyntaxError) return [];
        throw error;
      }
    });
}

/**
 * What the run did, from Azure's end of it and the command's own lines: 0 once
 * the organisation with this ID exists, made now or by an earlier run of the
 * same request, and 1 otherwise, saying what to do next.
 */
function outcome(steps: JobSteps, run: Ended, lines: readonly LogLine[], id: string): number {
  // The command ends 0 only once it has created the organisation.
  if (run.status === 'Succeeded') {
    steps.say(`Created the organisation ${id}.`);
    return 0;
  }
  const said = commandLines(lines);
  if (said.some((line) => line.event === 'operator.done_before')) {
    steps.say(`Already done: the organisation ${id} exists from an earlier run of this request, and nothing changed.`);
    return 0;
  }
  const refused = said.find((line) => line.event === 'operator.refused');
  if (Array.isArray(refused?.problems) && refused.problems.includes(NO_REQUEST_PROBLEM)) {
    steps.say(
      `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. Run the same command again with --id ${id}.`,
    );
    return 1;
  }
  steps.say(
    `The organisation may not have been created: read the lines above. If they leave it unclear, run the same command again with --id ${id}, which can't make a second one.`,
  );
  return 1;
}

/** Writes the request, runs it, puts [] back, and says what the run did: 0 once the organisation exists. */
export async function createOrganization(request: Request, steps: JobSteps): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  const target: Target = { subscription, job: 'operator' };
  const job = readOperatorJob(steps, target);
  const name = jobName('operator');
  if (job.state !== 'Succeeded') {
    throw new Error(`${name} is ${job.state} from an earlier change, so nothing was written: look at it first.`);
  }
  const api = readWorkload(steps.az, subscription, 'api').running;
  const going = unfinishedRuns(steps, target);
  if (going.length > 0) {
    throw new Error(`${name} has runs that haven't ended, so nothing was written: ${going.join(', ')}.`);
  }
  const synced = released(job.running, api.image, api.release);
  const moved = !same(job.running.container, synced);
  const id = request.id ?? uuidV7Ids.next();
  steps.say(
    `The new organisation's ID is ${id}. If this run's end is unclear, run the same command again with --id ${id}: it can't make a second organisation.`,
  );
  let execution: string;
  let run: Ended | undefined;
  try {
    const what = moved ? "writing the request and bringing the job to the API's build" : 'writing the request';
    if (moved) steps.say(`Bringing ${name} to the API's build: ${changes(job.running.container, synced).join('; ')}.`);
    patch(steps, target, patchBody(job, createOrganizationRequest(request.name, id), moved ? synced : undefined), what);
    await settled(steps, target, job.modified, synced, what);
    steps.say(`Wrote the request onto ${name}.`);
    execution = start(steps, target);
    run = await waitFor(steps, target, execution, job.limit);
  } catch (error) {
    // Whatever stopped it, the request comes off the job; a failure to take it off is said, and the first error stands.
    await clearRequest(steps, target).catch((failure: unknown) => {
      steps.say(
        `Putting ${NO_REQUEST} back failed too: ${failure instanceof Error ? failure.message : String(failure)}`,
      );
    });
    throw error;
  }
  await clearRequest(steps, target);
  if (run === undefined) return 1;
  const lines = await readLog(steps, target, execution, run);
  return outcome(steps, run, lines, id);
}

export async function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => ReturnType<typeof realAz> = realAz,
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
    return await createOrganization(request, { az: az(), say, now: () => new Date(), sleep: (ms) => sleep(ms) });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
