// What CI does after a merge to main (0e G4-3; ADR-002 "Deploying"): puts the
// new image into the migration job, runs it, then puts it into the API. The
// partner set the limits (S23): CI changes only our image's version (its
// digest and AGENTX_RELEASE) in those two, and starts the migration; a merge
// that needs a hand deploy stops the release, red.
//
//   node deploy/azure/release.ts check <commit> <digest>
//   node deploy/azure/release.ts release <commit> <digest>
//
// `check` (G4-3a) reads what staging runs and says what a release of that
// commit would do, changing nothing: whether a person must deploy it instead,
// and what each update would change. `release` (G4-3b) does it: the image
// checked by verify.ts first; the migration job updated, then run, and waited
// for; only once that run has succeeded, the API updated, and waited for until
// its new revision takes all traffic and answers /health through its door.
// CI runs `release` after every merge to main (G4-4).
//
// - what staging runs is read from the API and the job themselves (their
//   AGENTX_RELEASE), never from the previous merge: a release that stopped red
//   stays red, however many merges follow, until a hand deploy stamps a later
//   commit. `apps` stamps one, and deploy.ts sends it only from a clean
//   checkout of that very commit, so the stamp says what Azure was built from.
//   The other hand deploys stamp nothing, so a red says what to run, and the
//   person runs all of it
// - an update carries the whole containers array, since Azure's PATCH replaces
//   an array whole, and nothing else: no environment and no identity, which
//   would ask for the linked actions CI's role doesn't hold (release.bicep).
//   Each container is Azure's own, with the image and AGENTX_RELEASE changed
//   and nothing else; a field this tool doesn't know is refused, not guessed at
// - only images, commits, file names and Azure's own names are printed: the
//   settings name the domain, and the subscription is Azure's, both kept out
//   of CI's public logs. An error Azure gives for a write is shown by its code
//   alone, since its message can quote what was sent
// - every wait has an end, and a release that stops says where it stopped and
//   what it left: the API is never updated unless the migration succeeded
import { readFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

import { IMAGE_REPOSITORY, type Outcome } from '../image/verify.ts';
import { ARM, type Az, azJson, realAz, realImages, RESOURCE_GROUP } from './deploy.ts';
import { type History, realHistory } from './git.ts';
import { ENDED, isRunOf, JOBS_API, POLL_MS, START_ALLOWANCE_SECONDS } from './jobs.ts';

/** Something only a person deploys, by the start of its path, and why. */
export interface HandDeployed {
  readonly prefix: string;
  /** An ending that doesn't count, under the prefix. */
  readonly except?: string;
  readonly why: string;
}

/** A list of HandDeployed, or an error saying why the file isn't one. */
export function handDeployedList(parsed: unknown): readonly HandDeployed[] {
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('hand-deployed.json must be a list of areas');
  return parsed.map((entry): HandDeployed => {
    const { prefix, except, why, ...other } = record(entry);
    if (typeof prefix !== 'string' || prefix === '' || typeof why !== 'string' || Object.keys(other).length > 0) {
      throw new Error('each area in hand-deployed.json is a prefix and a reason, and at most an ending it excepts');
    }
    if (except === undefined) return { prefix, why };
    if (typeof except !== 'string' || except === '') throw new Error(`${prefix}'s exception must be an ending`);
    return { prefix, except, why };
  });
}

/**
 * What only a person deploys (partner, S23), each with why and what to run: a
 * merge that changes any of it since what staging runs stops the release, red.
 * In deploy/azure that is what Azure is built from, the Bicep and the files it
 * reads, not the TypeScript there (the tools, this one among them). The list is
 * a data file beside the Bicep for that reason: changing it counts as changing
 * Azure's set-up, so a change to the gate itself goes red once. The set-up
 * job's own files count too, wherever they are: only a person runs it.
 */
export const HAND_DEPLOYED: readonly HandDeployed[] = handDeployedList(
  JSON.parse(readFileSync(new URL('./hand-deployed.json', import.meta.url), 'utf8')) as unknown,
);

/**
 * The hand-deployed area a file belongs to, if any. The start is compared
 * without case, since the partner's Windows checkout puts `Deploy/Azure/x`
 * where `deploy/azure/x` goes; the exception with it, so `.TS` still counts.
 */
const handDeployed = (file: string): HandDeployed | undefined =>
  HAND_DEPLOYED.find(
    ({ prefix, except }) =>
      file.toLowerCase().startsWith(prefix.toLowerCase()) && (except === undefined || !file.endsWith(except)),
  );

/** The two things a release changes, as Azure names them and the one container each runs (apps.bicep). */
export const WORKLOADS = {
  migrate: { path: 'jobs/job-agentx-stg-migrate', container: 'migrate' },
  api: { path: 'containerApps/ca-agentx-stg-api', container: 'api' },
} as const;
export type Workload = keyof typeof WORKLOADS;

/** The order a release updates them in: the migration first, and the API only once its run has succeeded (G4-3b). */
export const ORDER: readonly Workload[] = ['migrate', 'api'];

/** The setting that names the build on every log line. */
const RELEASE_SETTING = 'AGENTX_RELEASE';

/** A commit, as git writes it in full. */
const COMMIT = /^[0-9a-f]{40}$/;

/** An image digest, as ghcr.io gives it. */
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** A subscription's ID, as Azure writes it. */
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Our image by digest, the only form a deployment names it in (SEC-SC-02). */
const isOurImage = (image: string): boolean =>
  image.startsWith(`${IMAGE_REPOSITORY}@`) && DIGEST.test(image.slice(IMAGE_REPOSITORY.length + 1));

/** The fields of a container this tool copies; any other is refused. */
const CONTAINER_FIELDS: ReadonlySet<string> = new Set([
  'name',
  'image',
  'command',
  'args',
  'env',
  'resources',
  'volumeMounts',
]);

/** A container's size as Azure gives it: the two we set, and the disk it works out from them. */
const SIZE_FIELDS: ReadonlySet<string> = new Set(['cpu', 'memory', 'ephemeralStorage']);

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export const USAGE = `Usage:
  node deploy/azure/release.ts check <commit> <digest>     say what a release of that commit would do, changing nothing
  node deploy/azure/release.ts release <commit> <digest>   do it: run the migration, then update the API
<commit> is a full commit; <digest> is its image's, sha256:<64 hex>.`;

export interface Request {
  readonly command: 'check' | 'release';
  readonly commit: string;
  readonly digest: string;
}

/** What was asked for, or a UsageError saying why it can't be done. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, commit, digest, ...rest] = argv;
  if (command !== 'check' && command !== 'release') {
    throw new UsageError(`say check or release, not ${command ?? 'nothing'}`);
  }
  if (commit === undefined || !COMMIT.test(commit)) {
    throw new UsageError(`${commit ?? 'nothing'} isn't a full commit (40 lower-case hex)`);
  }
  if (digest === undefined || !DIGEST.test(digest)) {
    throw new UsageError(`${digest ?? 'nothing'} isn't an image digest (sha256: and 64 lower-case hex)`);
  }
  if (rest.length > 0) throw new UsageError(`${command} takes a commit and a digest, not ${rest.join(' ')} as well`);
  return { command, commit, digest };
}

/** One setting: a value, or a reference to one of the workload's secrets (never a value in hand). */
type Setting =
  { readonly name: string; readonly value: string } | { readonly name: string; readonly secretRef: string };

/** One container as a release sends it back: Azure's own fields, the ones this tool knows. */
export interface Container {
  readonly name: string;
  readonly image: string;
  readonly command: readonly string[];
  readonly args: readonly string[];
  readonly env: readonly Setting[];
  readonly resources: { readonly cpu: number; readonly memory: string };
  readonly volumeMounts: readonly { readonly volumeName: string; readonly mountPath: string }[];
}

/** What a workload runs: its one container, and the image and build in it. */
export interface Running {
  readonly container: Container;
  readonly image: string;
  readonly release: string;
}

const isStrings = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string');

function record(value: unknown): Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/**
 * What a workload runs, read from its containers as Azure gives them, or an
 * error saying why this isn't the workload a release knows: exactly one
 * container, named as apps.bicep names it, running our image by digest, with
 * one AGENTX_RELEASE naming a commit, and no field this tool doesn't copy, in
 * the container, its size, a setting or a mount.
 */
export function runningIn(workload: Workload, containers: unknown): Running {
  const { container: expected, path } = WORKLOADS[workload];
  const refuse = (why: string): never => {
    throw new Error(`${path} isn't the ${workload} a release knows (${why}): deploy it by hand.`);
  };
  if (!Array.isArray(containers) || containers.length !== 1) return refuse('it must run exactly one container');
  const found = record(containers[0]);
  const unknown = Object.keys(found).filter((field) => !CONTAINER_FIELDS.has(field));
  if (unknown.length > 0) return refuse(`its container has ${unknown.join(', ')}, which a release doesn't copy`);
  const { name, image, command, args, env, resources, volumeMounts } = found;
  if (name !== expected) return refuse(`its container isn't named ${expected}`);
  if (typeof image !== 'string' || !isOurImage(image)) return refuse(`it doesn't run ${IMAGE_REPOSITORY} by digest`);
  if (!isStrings(command) || !isStrings(args)) return refuse('its command or arguments are not lists of words');
  const size = record(resources);
  if (typeof size.cpu !== 'number' || typeof size.memory !== 'string') return refuse('its size is not given');
  const sized = Object.keys(size).filter((field) => !SIZE_FIELDS.has(field));
  if (sized.length > 0) return refuse(`its size has ${sized.join(', ')}, which a release doesn't copy`);
  if (!Array.isArray(env)) return refuse('its settings are not a list');
  const settings = env.map((entry): Setting => {
    const { name: setting, value, secretRef, ...other } = record(entry);
    if (typeof setting !== 'string') return refuse('a setting has no name');
    if (Object.keys(other).length > 0) return refuse(`the setting ${setting} has more than a name and its value`);
    if (typeof value === 'string' && secretRef === undefined) return { name: setting, value };
    if (typeof secretRef === 'string' && value === undefined) return { name: setting, secretRef };
    return refuse(`the setting ${setting} has neither a value nor a secret reference alone`);
  });
  // A reference to the vault has no value, which reads as "undefined": no commit.
  const releases = env.map(record).filter((entry) => entry.name === RELEASE_SETTING);
  const build = String(releases[0]?.value);
  if (releases.length !== 1 || !COMMIT.test(build)) {
    return refuse(`it doesn't name its build in one ${RELEASE_SETTING}`);
  }
  if (!Array.isArray(volumeMounts)) return refuse('its mounts are not a list');
  const mounts = volumeMounts.map((entry) => {
    const { volumeName, mountPath, ...other } = record(entry);
    if (typeof volumeName !== 'string' || typeof mountPath !== 'string' || Object.keys(other).length > 0) {
      return refuse('a mount is more than a volume and a path');
    }
    return { volumeName, mountPath };
  });
  return {
    container: {
      name: expected,
      image,
      command,
      args,
      env: settings,
      // The disk Azure gives the size (ephemeralStorage) is its to work out, not ours to send.
      resources: { cpu: size.cpu, memory: size.memory },
      volumeMounts: mounts,
    },
    image,
    release: build,
  };
}

/** The container with the new image and build, and nothing else changed. */
export const released = (running: Running, image: string, commit: string): Container => ({
  ...running.container,
  image,
  env: running.container.env.map((setting) =>
    setting.name === RELEASE_SETTING ? { name: RELEASE_SETTING, value: commit } : setting,
  ),
});

export type Decision =
  | { readonly kind: 'current' }
  | { readonly kind: 'past' }
  | { readonly kind: 'by-hand'; readonly reasons: readonly string[] }
  | { readonly kind: 'release'; readonly updates: ReadonlyMap<Workload, Container> };

/**
 * What a release of `commit` would do, given what each workload runs: nothing
 * when both already run it, or both run a later commit that has it (a release
 * run again after a newer one); a hand deploy when what either runs isn't in
 * the commit's history, or anything a person deploys changed since; otherwise
 * the update for each.
 */
export function decide(
  running: ReadonlyMap<Workload, Running>,
  commit: string,
  image: string,
  history: History,
): Decision {
  const all = ORDER.map((workload) => {
    const found = running.get(workload);
    if (found === undefined) throw new Error(`nothing was read for ${workload}`);
    return [workload, found] as const;
  });
  if (all.every(([, found]) => found.release === commit && found.image === image)) return { kind: 'current' };
  if (all.every(([, found]) => found.release !== commit && history.isAncestor(commit, found.release))) {
    return { kind: 'past' };
  }
  const reasons = new Set<string>();
  for (const release of new Set(all.map(([, found]) => found.release))) {
    if (!history.isAncestor(release, commit)) {
      reasons.add(`staging runs ${release}, which isn't in ${commit}'s history`);
      continue;
    }
    for (const file of history.changedFiles(release, commit)) {
      const area = handDeployed(file);
      if (area !== undefined) reasons.add(`${file} changed since ${release}: ${area.why}`);
    }
  }
  if (reasons.size > 0) return { kind: 'by-hand', reasons: [...reasons] };
  return {
    kind: 'release',
    updates: new Map(all.map(([workload, found]) => [workload, released(found, image, commit)])),
  };
}

/** A workload's URL in Resource Manager, at the version apps.bicep deploys it with. */
export const workloadUrl = (subscription: string, workload: Workload): string =>
  `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/${WORKLOADS[workload].path}?api-version=${JOBS_API}`;

/** The subscription the CLI is signed in to, said by its name alone: its ID stays out of CI's public logs. */
function signedIn(az: Az, say: (line: string) => void): string {
  const account = record(azJson(az, ['account', 'show']));
  const id = typeof account.id === 'string' ? account.id : '';
  if (!GUID.test(id)) throw new Error("The Azure CLI named no subscription it's signed in to.");
  say(`Signed in to the subscription "${String(account.name)}".`);
  return id;
}

/** A workload as Azure has it: its properties, and what it runs. */
interface Read {
  readonly properties: Readonly<Record<string, unknown>>;
  readonly running: Running;
}

/** A workload, read from Azure. */
function readWorkload(az: Az, subscription: string, workload: Workload): Read {
  const properties = record(
    record(azJson(az, ['rest', '--method', 'get', '--url', workloadUrl(subscription, workload)])).properties,
  );
  return { properties, running: runningIn(workload, record(properties.template).containers) };
}

/** The build a container names in AGENTX_RELEASE, or nothing. */
const buildOf = (container: Container): string => {
  const found = container.env.find((setting) => setting.name === RELEASE_SETTING);
  return found !== undefined && 'value' in found ? found.value : '';
};

/**
 * What changed in a container, in words: its image and its build, the two a
 * release changes. Nothing else is said: the settings name the domain, which
 * stays out of CI's public logs as it stays out of the repository.
 */
export function changes(before: Container, after: Container): string[] {
  const said: string[] = [];
  if (before.image !== after.image) said.push(`image ${before.image} → ${after.image}`);
  if (buildOf(before) !== buildOf(after)) said.push(`${RELEASE_SETTING} ${buildOf(before)} → ${buildOf(after)}`);
  return said;
}

export interface CheckSteps {
  readonly az: Az;
  readonly history: History;
  readonly say: (line: string) => void;
}

/** What a release of the commit would do, read from Azure and the history, with what each runs said. */
interface Plan {
  readonly subscription: string;
  readonly image: string;
  readonly reads: ReadonlyMap<Workload, Read>;
  readonly running: ReadonlyMap<Workload, Running>;
  readonly decision: Decision;
}

function plan(request: Request, steps: CheckSteps): Plan {
  const subscription = signedIn(steps.az, steps.say);
  const image = `${IMAGE_REPOSITORY}@${request.digest}`;
  const reads = new Map(ORDER.map((workload) => [workload, readWorkload(steps.az, subscription, workload)] as const));
  const running = new Map([...reads].map(([workload, read]) => [workload, read.running] as const));
  for (const [workload, found] of running) steps.say(`${workload} runs ${found.release} (${found.image}).`);
  return { subscription, image, reads, running, decision: decide(running, request.commit, image, steps.history) };
}

/**
 * A decision that leaves nothing to update, said: the status to end with, or
 * nothing when there are updates to make.
 */
function settled(decision: Decision, commit: string, say: (line: string) => void): number | undefined {
  if (decision.kind === 'current') {
    say(`Both already run ${commit}: a release has nothing to do.`);
    return 0;
  }
  if (decision.kind === 'past') {
    say(`Staging already runs a later commit than ${commit}: a release of it has nothing to do.`);
    return 0;
  }
  if (decision.kind === 'by-hand') {
    say(`A release of ${commit} stops here, red: this needs a hand deploy.`);
    for (const reason of decision.reasons) say(`  ${reason}`);
    return 1;
  }
  return undefined;
}

/** `check`: what a release would do, said; 0 when it could go ahead (or has nothing to do), 1 when it needs a hand deploy. */
export function check(request: Request, steps: CheckSteps): number {
  const { running, decision } = plan(request, steps);
  const stop = settled(decision, request.commit, steps.say);
  if (stop !== undefined || decision.kind !== 'release') return stop ?? 1;
  steps.say(`A release of ${request.commit} would update, in order:`);
  for (const [workload, after] of decision.updates) {
    const before = running.get(workload)?.container;
    const said = before === undefined ? [] : changes(before, after);
    steps.say(`  ${workload}: ${said.length > 0 ? said.join('; ') : 'nothing'}, and nothing else`);
  }
  return 0;
}

export interface ReleaseSteps extends CheckSteps {
  readonly now: () => Date;
  readonly sleep: (ms: number) => Promise<void>;
  /** verify.ts's answer for the image, by digest, at the commit. */
  readonly verify: (image: string, commit: string) => Outcome;
  /** The status a GET of the URL answers, or nothing when nothing answers. */
  readonly probe: (url: string) => Promise<number | undefined>;
}

/** How long an update of a workload may take to settle. */
const UPDATE_WAIT_MS = 10 * 60_000;

/** How long the API's new revision may take to be ready, and then to answer through its door (cold starts ~25 s, S22). */
const SERVE_WAIT_MS = 5 * 60_000;

/**
 * An error Azure gave, by its code alone: its message can quote what was sent,
 * the settings among them, and CI's log is public. The code says what kind.
 */
function azureCode(stderr: string): string {
  return /\(([A-Za-z][A-Za-z0-9]*)\)/.exec(stderr)?.[1] ?? 'no code given';
}

/**
 * Sends the update: the containers alone, as a PATCH (release.bicep), once the
 * workload is read again and found as it was when the release was decided.
 * Another deploy since then means stopping, not overwriting it.
 */
function update(steps: ReleaseSteps, subscription: string, workload: Workload, seen: Running, after: Container): Read {
  const now = readWorkload(steps.az, subscription, workload);
  if (now.running.release !== seen.release || now.running.image !== seen.image) {
    throw new Error(
      `${workload} changed while this release ran (it now runs ${now.running.release}): another deploy is going on, so nothing more was changed.`,
    );
  }
  const body = JSON.stringify({ properties: { template: { containers: [after] } } });
  const done = steps.az.run([
    'rest',
    '--method',
    'patch',
    '--url',
    workloadUrl(subscription, workload),
    '--body',
    body,
  ]);
  if (done.status !== 0) {
    throw new Error(
      `Azure refused the update of ${workload} (${azureCode(done.stderr)}). Its message isn't shown here, since it can quote the settings sent: run this release from your own terminal to read it.`,
    );
  }
  steps.say(`Updating ${workload}: ${changes(seen.container, after).join('; ')}.`);
  return now;
}

/** Waits for Azure to settle an update: the workload as it then is. */
async function settledUpdate(
  steps: ReleaseSteps,
  subscription: string,
  workload: Workload,
  after: Container,
): Promise<Read> {
  const deadline = steps.now().getTime() + UPDATE_WAIT_MS;
  for (;;) {
    const now = readWorkload(steps.az, subscription, workload);
    const state = String(now.properties.provisioningState);
    if (state === 'Failed' || state === 'Canceled') throw new Error(`Azure's update of ${workload} ended ${state}.`);
    // Settled is Azure holding what was sent: just after the PATCH it can still
    // show the old container, marked Succeeded, before it takes the update up.
    if (state === 'Succeeded' && JSON.stringify(now.running.container) === JSON.stringify(after)) {
      steps.say(`${workload} runs ${now.running.release}.`);
      return now;
    }
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `Azure hadn't settled the update of ${workload} after ${String(UPDATE_WAIT_MS / 60_000)} minutes (${state}).`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/** One run of the migration job, as Azure lists it. */
interface Run {
  readonly name: string;
  readonly status: string;
}

const jobUrl = (subscription: string, suffix: string): string =>
  workloadUrl(subscription, 'migrate').replace('?api-version=', `${suffix}?api-version=`);

/** migrate's runs, once none is still going (two would race, apps.bicep): `left` says what stopping leaves. */
function idle(steps: ReleaseSteps, subscription: string, left: string): Run[] {
  const listed = runs(steps, subscription);
  const going = listed.filter((run) => !ENDED.has(run.status));
  if (going.length > 0) {
    throw new Error(
      `migrate has runs that haven't ended (${going.map((run) => `${run.name} ${run.status}`).join(', ')}), so ${left}.`,
    );
  }
  return listed;
}

/** How long migrate's one run may take, in seconds (apps.bicep), or an error before anything is changed. */
function timeLimit(job: Read): number {
  const limit = record(job.properties.configuration).replicaTimeout;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit <= 0) {
    throw new Error(
      'Azure gave no time limit for migrate, so how long to wait for its run is unknown: nothing was changed.',
    );
  }
  return limit;
}

function runs(steps: ReleaseSteps, subscription: string): Run[] {
  const listed = record(azJson(steps.az, ['rest', '--method', 'get', '--url', jobUrl(subscription, '/executions')]));
  if (!Array.isArray(listed.value)) throw new Error("Azure's list of migrate's runs wasn't a list.");
  return listed.value.map((entry) => {
    const found = record(entry);
    return { name: String(found.name), status: String(record(found.properties).status) };
  });
}

/**
 * Starts the migration job as it is now deployed, with no template of its own
 * (a POST with no body), once none of its runs is still going: two would race
 * (apps.bicep). Azure may take the start without naming the run, so it is found
 * as the one run that wasn't there before.
 */
function startMigration(steps: ReleaseSteps, subscription: string): string {
  const before = idle(steps, subscription, 'none was started, and the API was left as it was');
  const done = steps.az.run(['rest', '--method', 'post', '--url', jobUrl(subscription, '/start')]);
  if (done.status !== 0) throw new Error(`Azure refused to start migrate (${azureCode(done.stderr)}).`);
  const known = new Set(before.map((run) => run.name));
  const fresh = runs(steps, subscription).filter((run) => !known.has(run.name));
  const [started] = fresh;
  if (fresh.length !== 1 || started === undefined) {
    throw new Error(
      `migrate was started, but ${String(fresh.length)} new runs are listed, so which is this release's is unknown: the API was left as it was.`,
    );
  }
  // Azure's own name for it, held to the job's runs before it goes into a URL.
  if (!isRunOf('migrate', started.name)) {
    throw new Error(
      `Azure named migrate's new run "${started.name}", which isn't one of its runs: the API was left as it was.`,
    );
  }
  steps.say(`Started ${started.name}.`);
  return started.name;
}

/** Waits for the run to end, within the job's own time limit and the start allowance: how it ended. */
async function ended(steps: ReleaseSteps, subscription: string, name: string, limit: number): Promise<string> {
  const deadline = steps.now().getTime() + (limit + START_ALLOWANCE_SECONDS) * 1000;
  let last = '';
  for (;;) {
    const run = record(
      azJson(steps.az, ['rest', '--method', 'get', '--url', jobUrl(subscription, `/executions/${name}`)]),
    );
    const status = String(record(run.properties).status);
    if (status !== last) {
      steps.say(`  ${name}: ${status}`);
      last = status;
    }
    if (ENDED.has(status)) return status;
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `${name} hadn't ended ${String(limit + START_ALLOWANCE_SECONDS)} s after it started, so the API was left as it was. To wait for it: node deploy/azure/jobs.ts wait migrate ${name}`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/** The address the API is served at, from its own setting (never printed: it names the domain). */
function publicOrigin(api: Running): string {
  const origin = api.container.env.find((setting) => setting.name === 'AGENTX_PUBLIC_ORIGIN');
  const value = origin !== undefined && 'value' in origin ? origin.value : '';
  if (!/^https:\/\/[a-z0-9.-]+$/.test(value)) {
    throw new Error(
      'The API names no https origin (AGENTX_PUBLIC_ORIGIN) to check it through once released: nothing was changed.',
    );
  }
  return value;
}

/**
 * Waits until the API serves the release: its new revision is the ready one,
 * provisioned, active and taking all traffic; its door answers `/health` with
 * 200 (which starts a replica of it, from zero); and the revision is then
 * healthy. Anything short of that within the wait is a failure.
 */
async function served(steps: ReleaseSteps, subscription: string, before: string, origin: string): Promise<string> {
  const deadline = steps.now().getTime() + SERVE_WAIT_MS;
  const late = (what: string): Error =>
    new Error(`The API's new revision wasn't ${what} ${String(SERVE_WAIT_MS / 60_000)} minutes after its update.`);
  const ready = async (): Promise<string> => {
    for (;;) {
      const { properties } = readWorkload(steps.az, subscription, 'api');
      const latest = String(properties.latestRevisionName);
      if (latest !== before && latest === properties.latestReadyRevisionName) return latest;
      if (steps.now().getTime() >= deadline) throw late('ready');
      await steps.sleep(POLL_MS);
    }
  };
  const revision = await ready();
  // Azure's own name for it, held to that shape before it goes into a URL.
  if (!/^ca-agentx-stg-api--[a-z0-9]+$/.test(revision)) {
    throw new Error(`Azure named the API's new revision "${revision}", which isn't one of its revisions.`);
  }
  const revisionUrl = workloadUrl(subscription, 'api').replace('?api-version=', `/revisions/${revision}?api-version=`);
  const readRevision = (): Readonly<Record<string, unknown>> =>
    record(record(azJson(steps.az, ['rest', '--method', 'get', '--url', revisionUrl])).properties);
  const shown = readRevision();
  if (shown.provisioningState !== 'Provisioned' || shown.active !== true || shown.trafficWeight !== 100) {
    throw new Error(
      `The API's new revision ${revision} isn't serving (${String(shown.provisioningState)}, active ${String(shown.active)}, ${String(shown.trafficWeight)}% of traffic).`,
    );
  }
  steps.say(`The API's new revision ${revision} takes all traffic; asking it for /health...`);
  for (;;) {
    const status = await steps.probe(`${origin}/health`);
    if (status === 200) break;
    if (steps.now().getTime() >= deadline) throw late('answering /health');
    await steps.sleep(POLL_MS);
  }
  const health = String(readRevision().healthState);
  if (health !== 'Healthy') {
    throw new Error(`The API's new revision ${revision} answered, but Azure calls it ${health}.`);
  }
  return revision;
}

/**
 * `release`: checks the image, then does what `check` says: the migration job
 * updated and run to success, then the API updated and serving. 0 when it is
 * released or had nothing to do, 1 when it stopped, saying where.
 */
export async function release(request: Request, steps: ReleaseSteps): Promise<number> {
  const image = `${IMAGE_REPOSITORY}@${request.digest}`;
  steps.say(`Checking ${image} was signed by CI on main at ${request.commit}, with its SBOM...`);
  const outcome = steps.verify(image, request.commit);
  if (!outcome.verified) {
    steps.say(`The image was refused (${outcome.reason}), so nothing was read or changed:\n${outcome.detail}`);
    return 1;
  }
  const { subscription, reads, decision } = plan(request, steps);
  const stop = settled(decision, request.commit, steps.say);
  if (stop !== undefined || decision.kind !== 'release') return stop ?? 1;
  const job = reads.get('migrate');
  const api = reads.get('api')?.running;
  const migrateAfter = decision.updates.get('migrate');
  const apiAfter = decision.updates.get('api');
  if (job === undefined || api === undefined || migrateAfter === undefined || apiAfter === undefined) {
    throw new Error('The release lost track of a workload.');
  }
  // Everything that could stop the release is settled before its first write.
  const origin = publicOrigin(api);
  const limit = timeLimit(job);
  idle(steps, subscription, 'nothing was changed');

  update(steps, subscription, 'migrate', job.running, migrateAfter);
  await settledUpdate(steps, subscription, 'migrate', migrateAfter);
  const name = startMigration(steps, subscription);
  const status = await ended(steps, subscription, name, limit);
  if (status !== 'Succeeded') {
    steps.say(
      `${name} ended ${status}, so the API was left on ${api.release}. Read its log: node deploy/azure/jobs.ts wait migrate ${name}`,
    );
    return 1;
  }

  const before = update(steps, subscription, 'api', api, apiAfter);
  await settledUpdate(steps, subscription, 'api', apiAfter);
  const revision = await served(steps, subscription, String(before.properties.latestRevisionName), origin);
  steps.say(`Released ${request.commit}: ${name} succeeded, and the API serves it from ${revision}.`);
  return 0;
}

/** What a release needs besides Azure and the history: time, the image check, and the door. */
export interface Extras {
  readonly now: () => Date;
  readonly sleep: (ms: number) => Promise<void>;
  readonly verify: (image: string, commit: string) => Outcome;
  readonly probe: (url: string) => Promise<number | undefined>;
}

/** The real ones: the clock, cosign through verify.ts, and a GET of the door. */
function realExtras(): Extras {
  return {
    now: () => new Date(),
    sleep: (ms) => sleep(ms),
    verify: (image, commit) => realImages().verify(image, commit),
    probe: async (url) => {
      try {
        const answer = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(30_000) });
        return answer.status;
      } catch (error) {
        // Nothing answered in time (a cold start, a reset): the caller asks again until its own deadline.
        if (error instanceof Error) return undefined;
        throw error;
      }
    },
  };
}

export async function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => Az = realAz,
  history: () => History = realHistory,
  extras: () => Extras = realExtras,
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
    const steps = { az: az(), history: history(), say };
    return request.command === 'check' ? check(request, steps) : await release(request, { ...steps, ...extras() });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
