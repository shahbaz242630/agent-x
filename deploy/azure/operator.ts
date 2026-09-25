// Runs the operator's command on its job (B1c-2b; ADR-011 §3, ADR-005 §6):
//
//   node deploy/azure/operator.ts create-organization --name <name> [--id <ID>]
//   node deploy/azure/operator.ts invite-first-admin --org <organisation ID> --email <address> [--id <ID>]
//
// The second (B4-6b) invites a new organisation's first admin. Its link's
// token is made here, on the partner's own machine: the job is sent only the
// token's SHA-256, and the link is shown here once, after the run says the
// invitation exists, and kept nowhere. The link's address is the API's own
// public origin, read from Azure, so no domain is written in the repository.
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
// 5. puts [] back whatever happened, once no change to the job is still
//    going, and waits until Azure has taken that
// 6. reads the run's log and says what the run did for this request's ID:
//    created the organisation, found it done already (nothing changed), or
//    neither; a line about another ID is never taken for this one's
// One run at a time: Azure can't say whose change it took. A run stopped
// part-way (the terminal closed, say) leaves the request on the job, which
// can't make a second organisation, since it names its ID; the same command
// again with that --id takes it off at its end, as does deploy.ts apps.
// The request is never printed, nor put on a command line: it goes to Azure in
// a file in this user's own temporary folder, removed straight after, with
// every character past ASCII escaped so the CLI can't misread its encoding. A
// read of the job never shows it back. Starting the job is the partner's
// (ADR-005 §6: the right to start it is the API's own authority), so this runs
// from their `!`.
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import {
  createOrganizationRequest,
  firstAdminRequest,
  NO_REQUEST_PROBLEM,
  REQUEST_LIMIT_BYTES,
  UUID_V7,
} from '../../apps/operator/src/request.ts';
import { invitationEmail } from '../../packages/core/src/modules/identity/domain/invitation.ts';
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

/** How long a change to the job may take to settle: as long as a release gives one (release.ts). */
const SETTLE_MS = 10 * 60_000;

/** Any ID, for the size of a request before its own is made: every ID is as long. */
const SOME_ID = '00000000-0000-7000-8000-000000000000';

/** An error's message, or what was thrown when it isn't an Error. */
const reason = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** What may now hold the request when [] couldn't be put back, and what takes it off. */
const mayStillHold = (id: string, noun: string): string =>
  `The request may still be on ${jobName('operator')}. It names ${id}, so it can't make a second ${noun}. Take it off by running the same command again with --id ${id}, or by deploying the apps (deploy.ts apps).`;

/**
 * The last word on any failure once the ID is made: what the run did may be
 * unknown, and the same command with the same ID both finds out and finishes
 * it, making none twice.
 */
const tryAgain = (id: string, noun: string): string =>
  `To find out what happened, and finish it if it didn't: run the same command again with --id ${id}. If the ${noun} exists, that run ends "Already done"; none is made twice.`;

export const USAGE = `Usage:
  node deploy/azure/operator.ts create-organization --name <name> [--id <ID>]
  node deploy/azure/operator.ts invite-first-admin --org <organisation ID> --email <address> [--id <ID>]
The name is one argument: quote it if it holds a space. --id repeats the ID an earlier run gave when its end was unclear; the same ID can never make a second organisation, or invitation.`;

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

/** The first admin's invitation the partner asked for (B4-6b). */
export interface FirstAdminArguments {
  readonly orgId: string;
  /** In lower case, as the invitation keeps it. */
  readonly email: string;
  /** The ID of an earlier try, if this is one. */
  readonly id: string | undefined;
}

/** What was asked for, or a UsageError saying why it can't be done. The address is never repeated in one. */
export function parseFirstAdmin(argv: readonly string[]): FirstAdminArguments {
  const [command, orgFlag, orgId, emailFlag, email, ...rest] = argv;
  const [idFlag, id, ...more] = rest;
  const ided = rest.length === 0 || (idFlag === '--id' && id !== undefined && more.length === 0);
  if (
    command !== 'invite-first-admin' ||
    orgFlag !== '--org' ||
    emailFlag !== '--email' ||
    email === undefined ||
    !ided
  ) {
    throw new UsageError(
      'say invite-first-admin --org <organisation ID> --email <address> [--id <ID>], and nothing else',
    );
  }
  if (!UUID_V7.test(String(orgId))) throw new UsageError("--org takes the organisation's ID: a UUIDv7, in lower case");
  if (id !== undefined && !UUID_V7.test(id)) {
    throw new UsageError('--id takes the ID an earlier run gave: a UUIDv7, in lower case');
  }
  const address = invitationEmail(email);
  if (address === undefined) throw new UsageError("--email takes the address to invite, and this isn't one");
  if (Buffer.byteLength(firstAdminRequest(String(orgId), address, SOME_ID, '0'.repeat(64))) > REQUEST_LIMIT_BYTES) {
    throw new UsageError(
      `the address makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`,
    );
  }
  return { orgId: String(orgId), email: address, id };
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
        : refuse(
            'a secret other than its request must be exactly a reference to the vault: a name, a URL and an identity',
          ),
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
 * Sends a PATCH to the job from a file in a folder of its own in this user's
 * temporary folder (inside their profile on Windows, so theirs alone), removed
 * straight after: the request stays off every command line. Azure's message
 * isn't shown, since it can quote what was sent. A folder that can't be
 * removed (a scanner holding the file, say) is said, never taken for a PATCH
 * that failed.
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
    try {
      rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
    } catch (error) {
      steps.say(`Couldn't remove ${folder}, which holds what was sent: remove it by hand (${reason(error)}).`);
    }
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

/** Waits until no change to the job is still going, so the next is taken rather than refused: the job then. */
async function idle(steps: JobSteps, target: Target): Promise<OperatorJob> {
  const deadline = steps.now().getTime() + SETTLE_MS;
  for (;;) {
    const job = readOperatorJob(steps, target);
    if (job.state !== 'InProgress') return job;
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `${jobName('operator')} was still taking a change after ${String(SETTLE_MS / 60_000)} minutes, so nothing more was sent.`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/**
 * Puts [] back as the job's request, every vault reference as it is now, once
 * no change is still going (Azure may refuse one made during another), and
 * waits until Azure has taken it.
 */
async function clearRequest(steps: JobSteps, target: Target): Promise<void> {
  const job = await idle(steps, target);
  const what = `putting ${NO_REQUEST} back`;
  patch(steps, target, patchBody(job, NO_REQUEST), what);
  await settled(steps, target, job.modified, job.running.container, what);
  steps.say(`Put ${NO_REQUEST} back on ${jobName('operator')}: its next run holds no request until one is written.`);
}

/** The command's own lines in a run: its JSON ones, since neither Azure's lines nor Node's own are JSON. */
function commandLines(lines: readonly LogLine[]): Readonly<Record<string, unknown>>[] {
  return lines.flatMap((line) => {
    try {
      return [record(JSON.parse(line.text))];
    } catch (error) {
      // A line that isn't JSON is shown above and read as none of the command's own.
      if (error instanceof SyntaxError) return [];
      throw error;
    }
  });
}

/** A request for the job: what it makes, the ID that names it, and how the run's lines say so. */
interface JobRequest {
  readonly id: string;
  /** The request file's text. */
  readonly text: string;
  /** What it makes, as said: `organisation` or `invitation`. */
  readonly noun: string;
  /** The field the command's lines name it by. */
  readonly field: 'orgId' | 'invitationId';
  /** The command's line once it is made. */
  readonly made: string;
  /** Says it was made. */
  readonly sayMade: () => void;
  /** Said after "Already done", if anything. */
  readonly doneBeforeNote: string;
}

/**
 * What the run did, from the command's own lines about this request's ID and
 * Azure's end of the run: 0 once what it makes exists, made now or by an
 * earlier run of the same request, and 1 otherwise, saying what to do next. A
 * line about another ID (another request run in this one's place) is never
 * taken for this one's.
 */
function outcome(steps: JobSteps, run: Ended, lines: readonly LogLine[], asked: JobRequest): number {
  const { id, noun, field } = asked;
  const said = commandLines(lines);
  const about = (event: string): boolean => said.some((line) => line.event === event && line[field] === id);
  if (about(asked.made)) {
    asked.sayMade();
    return 0;
  }
  if (about('operator.done_before')) {
    steps.say(
      `Already done: the ${noun} ${id} exists from an earlier run of this request, and nothing changed.${asked.doneBeforeNote}`,
    );
    return 0;
  }
  const refused = said.find((line) => line.event === 'operator.refused');
  if (Array.isArray(refused?.problems) && refused.problems.includes(NO_REQUEST_PROBLEM)) {
    steps.say(
      `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. Run the same command again with --id ${id}.`,
    );
    return 1;
  }
  if (Array.isArray(refused?.problems) && refused[field] === id) {
    steps.say(`The operator's command refused it, and nothing changed: ${refused.problems.map(String).join('; ')}.`);
    return 1;
  }
  steps.say(
    run.status === 'Succeeded'
      ? `The run succeeded, but its lines don't show the ${noun} ${id} made: they may not all have arrived, or another request ran in this one's place. Run the same command again with --id ${id}, which can't make a second one.`
      : `The ${noun} may not have been created: read the lines above. If they leave it unclear, run the same command again with --id ${id}, which can't make a second one.`,
  );
  return 1;
}

/** Writes the request, runs it, puts [] back, and says what the run did: 0 once the organisation exists. */
export function createOrganization(request: Request, steps: JobSteps): Promise<number> {
  const id = request.id ?? uuidV7Ids.next();
  return runRequest(steps, () => ({
    id,
    text: createOrganizationRequest(request.name, id),
    noun: 'organisation',
    field: 'orgId',
    made: 'operator.organization_created',
    sayMade: () => {
      steps.say(`Created the organisation ${id}.`);
    },
    doneBeforeNote: '',
  }));
}

/**
 * Invites a new organisation's first admin (B4-6b): the token made here, only
 * its SHA-256 sent, and the link shown here once the run says the invitation
 * exists. 0 once it does.
 */
export function inviteFirstAdmin(request: FirstAdminArguments, steps: JobSteps): Promise<number> {
  const token = randomBytes(32).toString('base64url');
  const hash = createHash('sha256').update(token, 'ascii').digest('hex');
  const id = request.id ?? uuidV7Ids.next();
  return runRequest(steps, (api) => {
    const origin = api.container.env.find((setting) => setting.name === 'AGENTX_PUBLIC_ORIGIN');
    const value = origin !== undefined && 'value' in origin ? origin.value : '';
    if (!/^https:\/\/[a-z0-9.-]+$/.test(value)) {
      throw new Error('The API holds no https AGENTX_PUBLIC_ORIGIN, so no link could be made: nothing was written.');
    }
    return {
      id,
      text: firstAdminRequest(request.orgId, request.email, id, hash),
      noun: 'invitation',
      field: 'invitationId',
      made: 'operator.first_admin_invited',
      sayMade: () => {
        steps.say(
          `Invited the first admin of ${request.orgId} (invitation ${id}). Send them this link, shown this once and kept nowhere. It works for 72 hours, signed in with the invited address:\n${value}/invitations/accept#token=${token}`,
        );
      },
      doneBeforeNote:
        ' Its link was shown by that run alone. If it was lost, run the command again without --id: a new invitation, with a new link.',
    };
  });
}

/** Writes a request, runs it, puts [] back, and says what the run did: 0 once what it makes exists. */
async function runRequest(steps: JobSteps, prepare: (api: Running) => JobRequest): Promise<number> {
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
  const asked = prepare(api);
  const { id, noun } = asked;
  steps.say(
    `The new ${noun}'s ID is ${id}. If this run's end is unclear, run the same command again with --id ${id}: it can't make a second ${noun}, and it takes the request off the job at its end.`,
  );
  let execution: string;
  let run: Ended | undefined;
  try {
    const what = moved ? "writing the request and bringing the job to the API's build" : 'writing the request';
    if (moved) steps.say(`Bringing ${name} to the API's build: ${changes(job.running.container, synced).join('; ')}.`);
    patch(steps, target, patchBody(job, asked.text, moved ? synced : undefined), what);
    await settled(steps, target, job.modified, synced, what);
    steps.say(`Wrote the request onto ${name}.`);
    execution = start(steps, target);
    run = await waitFor(steps, target, execution, job.limit);
  } catch (error) {
    // Whatever stopped it, the request comes off the job; a failure to take it off is said, and the first error stands.
    await clearRequest(steps, target).catch((failure: unknown) => {
      steps.say(`Putting ${NO_REQUEST} back failed too: ${reason(failure)} ${mayStillHold(id, noun)}`);
    });
    steps.say(tryAgain(id, noun));
    throw error;
  }
  // The request comes off before the log is read; a failure to take it off still lets the run's outcome be said first.
  const left = await clearRequest(steps, target).then(
    () => undefined,
    (failure: unknown) => failure,
  );
  try {
    if (run === undefined) return 1;
    const said = outcome(steps, run, await readLog(steps, target, execution, run), asked);
    return left === undefined ? said : 1;
  } catch (error) {
    // The run ended, but what it did couldn't be read.
    steps.say(tryAgain(id, noun));
    throw error;
  } finally {
    if (left !== undefined) steps.say(`Putting ${NO_REQUEST} back failed: ${reason(left)} ${mayStillHold(id, noun)}`);
  }
}

export async function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => ReturnType<typeof realAz> = realAz,
): Promise<number> {
  let work: (steps: JobSteps) => Promise<number>;
  try {
    if (argv[0] === 'invite-first-admin') {
      const request = parseFirstAdmin(argv);
      work = (steps) => inviteFirstAdmin(request, steps);
    } else {
      const request = parseArguments(argv);
      work = (steps) => createOrganization(request, steps);
    }
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    say(`${error.message}\n${USAGE}`);
    return 2;
  }
  try {
    return await work({ az: az(), say, now: () => new Date(), sleep: (ms) => sleep(ms) });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
