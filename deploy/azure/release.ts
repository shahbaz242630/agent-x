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
// checked by verify.ts first; the migration job updated, then run (a run of
// this image), and waited for; only once that run has succeeded, the API
// updated, and waited for until a new revision of this image takes all
// traffic, the door answers /health, and Azure calls the revision healthy.
// CI runs `release` after every merge to main (G4-4), one release at a time.
//
// - what staging runs is read from the API and the job themselves (their
//   AGENTX_RELEASE), never from the previous merge: a release that stopped red
//   stays red, however many merges follow, until a hand deploy stamps a later
//   commit. `apps` stamps one, and deploy.ts sends it only from a clean
//   checkout of that very commit, so the stamp says what Azure was built from.
//   The other hand deploys stamp nothing on the workloads; foundation, secrets
//   and certificates each record the commit they sent in a tag on the
//   migration job (T1b, deploy.ts). A red says what to run: for a file a
//   deployment reads, which hand deploys read it, as the pinned Bicep says of
//   a clean checkout of the commit (T1a). A file that only recorded deploys
//   read, each recorded at a commit in this one's history with the file as it
//   is now, needs no hand deploy. Bicep is asked only once a release would be
//   red without it, and any doubt (Bicep unable to say, a record that isn't a
//   commit, or isn't in the history) leaves it red
// - an update carries the whole containers array, since Azure's PATCH replaces
//   an array whole, and nothing else: no environment and no identity, which
//   would ask for the linked actions CI's role doesn't hold (release.bicep).
//   Each container is Azure's own, with the image and AGENTX_RELEASE changed
//   and nothing else; a field this tool doesn't know is refused, not guessed at
// - only images, commits, file names and Azure's own names are printed: the
//   settings name the domain, and the subscription is Azure's, both kept out
//   of CI's public logs. An error Azure gives is shown by its HTTP reason and
//   code alone, and never with the URL asked (both can name the subscription;
//   its message can quote what was sent); the activity log has the rest
// - everything knowable before the first write is settled before it; every
//   wait has an end; a stop after the first write says what it left. The API
//   is updated only after a run of this release's image has succeeded
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import { fileReferences } from '../../tooling/bicep/references.ts';
import { IMAGE_REPOSITORY, type Outcome } from '../image/verify.ts';
import {
  ARM,
  type Az,
  type Deployment,
  DEPLOYMENTS,
  realAz,
  realImages,
  RECORDED,
  type Recorded,
  recordTag,
  RESOURCE_GROUP,
} from './deploy.ts';
import { type Checkout, type History, realCheckout, realHistory } from './git.ts';
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
 * job's own files count too, wherever they are: only a person runs it. A test
 * file never counts (TEST_FILE).
 */
export const HAND_DEPLOYED: readonly HandDeployed[] = handDeployedList(
  JSON.parse(readFileSync(new URL('./hand-deployed.json', import.meta.url), 'utf8')) as unknown,
);

/**
 * How a test file's name ends: in any area, a change to one needs no hand
 * deploy (partner, S41, narrowing S23), since it reaches nothing a person
 * deploys. The image leaves it out (.dockerignore's last rule for test files,
 * after everything it lets in) and no deployment reads it (what Bicep says,
 * pinned in release.test.ts). Compared with case, as the image build's
 * patterns are, so `main.Test.ts`, which the image would hold, still counts.
 */
export const TEST_FILE = '.test.ts';

/**
 * The hand-deployed area a file belongs to, if any. The start is compared
 * without case, since the partner's Windows checkout puts `Deploy/Azure/x`
 * where `deploy/azure/x` goes; the exception with it, so `.TS` still counts.
 */
const handDeployed = (file: string): HandDeployed | undefined =>
  file.endsWith(TEST_FILE)
    ? undefined
    : HAND_DEPLOYED.find(
        ({ prefix, except }) =>
          file.toLowerCase().startsWith(prefix.toLowerCase()) && (except === undefined || !file.endsWith(except)),
      );

/** The repository, whose paths git gives relative to it. */
const REPOSITORY = path.resolve(import.meta.dirname, '../..');

/**
 * The hand deploys that read each file, by its path in the repository in lower
 * case (a Windows checkout's case may differ from git's), in DEPLOYMENTS order.
 */
export type Readers = ReadonlyMap<string, readonly Deployment[]>;

/** Each deployment's parameters file, by its full path: what Bicep is asked about. */
export const PARAMS_PATHS: ReadonlyMap<Deployment, string> = new Map(
  (Object.entries(DEPLOYMENTS) as [Deployment, string][]).map(([deployment, file]) => [
    deployment,
    path.join(import.meta.dirname, file),
  ]),
);

/** A full path as git names it in the repository, or an error when it is outside. */
function inRepository(file: string): string {
  const relative = path.relative(REPOSITORY, file);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`Bicep says a deployment reads ${file}, which isn't in the repository`);
  }
  return relative.split(path.sep).join('/');
}

/** Readers from what Bicep says each parameters file's deployment reads, or an error when an answer is missing. */
export function readersFrom(answers: ReadonlyMap<string, readonly string[]>): Readers {
  const readers = new Map<string, Deployment[]>();
  for (const [deployment, params] of PARAMS_PATHS) {
    const read = answers.get(params);
    if (read === undefined) throw new Error(`Bicep said nothing of what ${deployment} reads`);
    for (const file of new Set(read.map((each) => inRepository(each).toLowerCase()))) {
      readers.set(file, [...(readers.get(file) ?? []), deployment]);
    }
  }
  return readers;
}

/** Two or more names, as a sentence says them. */
const listed = (names: readonly string[]): string => `${names.slice(0, -1).join(', ')} and ${String(names.at(-1))}`;

/**
 * What to run for a file the named hand deploys read and haven't recorded:
 * each of them, and then this release again, which each one's record lets
 * through; apps moves what staging runs itself, so nothing follows it.
 */
function toRun(readers: readonly Deployment[]): string {
  const then = readers.includes('apps') ? '' : ', then run this release again';
  if (readers.length === 1) {
    return `deploy.ts ${String(readers[0])} reads it, so run it by hand, its what-if read${then}`;
  }
  return `deploy.ts ${listed(readers)} read it, so run each by hand in that order, each what-if read${then}`;
}

/** The commit each recorded hand deploy last sent, as the migration job's tags hold them (T1b). */
export type Records = ReadonlyMap<Recorded, string>;

/** The records a workload's tags hold; a record that isn't a commit counts for nothing, and is said. */
export function recordsIn(tags: Readonly<Record<string, unknown>>, say: (line: string) => void): Records {
  const records = new Map<Recorded, string>();
  for (const deployment of RECORDED) {
    const value = tags[recordTag(deployment)];
    if (value === undefined) continue;
    if (typeof value === 'string' && COMMIT.test(value)) records.set(deployment, value);
    else say(`The migration job's ${recordTag(deployment)} isn't a commit, so it counts for nothing.`);
  }
  return records;
}

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
  | {
      readonly kind: 'release';
      readonly updates: ReadonlyMap<Workload, Container>;
      /** Each changed file a person deploys that the records show deployed, and by which. */
      readonly deployed: readonly string[];
    };

/**
 * What a release of `commit` would do, given what each workload runs: nothing
 * when both already run it, or both run a later commit that has it (a release
 * run again after a newer one); a hand deploy when what either runs isn't in
 * the commit's history, or anything a person deploys changed since; otherwise
 * the update for each. Given the readers, a changed file that a deployment
 * reads names the hand deploys to run, and one that only recorded deploys
 * read, each recorded at a commit in this one's history with the file
 * unchanged since, needs none.
 */
export function decide(
  running: ReadonlyMap<Workload, Running>,
  commit: string,
  image: string,
  history: History,
  readers?: Readers,
  records: Records = new Map(),
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
  // The files changed from each record's commit to this one, in lower case, read once each.
  const since = new Map<string, ReadonlySet<string>>();
  /** The commit a deploy's record says it sent this file as it is now, if one does. */
  const recordFor = (deployment: Deployment, file: string): string | undefined => {
    if (deployment === 'apps') return undefined;
    const sent = records.get(deployment);
    if (sent === undefined || !history.isAncestor(sent, commit)) return undefined;
    let changed = since.get(sent);
    if (changed === undefined) {
      changed = new Set(history.changedFiles(sent, commit).map((each) => each.toLowerCase()));
      since.set(sent, changed);
    }
    return changed.has(file.toLowerCase()) ? undefined : sent;
  };
  const reasons = new Set<string>();
  const deployed = new Set<string>();
  for (const release of new Set(all.map(([, found]) => found.release))) {
    if (!history.isAncestor(release, commit)) {
      reasons.add(`staging runs ${release}, which isn't in ${commit}'s history`);
      continue;
    }
    for (const file of history.changedFiles(release, commit)) {
      const area = handDeployed(file);
      if (area === undefined) continue;
      const deployments = readers?.get(file.toLowerCase());
      if (deployments === undefined) {
        reasons.add(`${file} changed since ${release}: ${area.why}`);
        continue;
      }
      const unrecorded = deployments.filter((deployment) => recordFor(deployment, file) === undefined);
      if (unrecorded.length > 0) {
        reasons.add(`${file} changed since ${release}: ${toRun(unrecorded)}`);
        continue;
      }
      const sent = deployments.map((deployment) => `${deployment} from ${String(recordFor(deployment, file))}`);
      deployed.add(`${file} changed since ${release}: deployed by hand, ${sent.join(', ')}`);
    }
  }
  if (reasons.size > 0) return { kind: 'by-hand', reasons: [...reasons] };
  return {
    kind: 'release',
    updates: new Map(all.map(([workload, found]) => [workload, released(found, image, commit)])),
    deployed: [...deployed],
  };
}

/** A workload's URL in Resource Manager, at the version apps.bicep deploys it with. */
export const workloadUrl = (subscription: string, workload: Workload): string =>
  `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/${WORKLOADS[workload].path}?api-version=${JOBS_API}`;

/**
 * Why Azure refused, from what `az rest` printed: the HTTP reason and the
 * error's code (`ERROR: Forbidden({"error":{"code":"AuthorizationFailed",…}})`).
 * Nothing else is shown: the message can quote what was sent, the settings
 * among them, and names the subscription, and CI's log is public. The
 * resource group's activity log holds the whole of it.
 */
function azureRefusal(stderr: string): string {
  const reason = /ERROR:\s*([A-Za-z][A-Za-z ]*?)\s*\(/.exec(stderr)?.[1];
  const code = /"code"\s*:\s*"([A-Za-z0-9.]+)"/.exec(stderr)?.[1];
  const said = [reason, code].filter((part) => part !== undefined);
  return said.length > 0 ? said.join(', ') : 'no reason given';
}

/** An answer the CLI printed, as JSON, or an error naming what it was for (never the answer itself). */
function parsed(stdout: string, what: string): Readonly<Record<string, unknown>> {
  try {
    return record(JSON.parse(stdout));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`Azure's answer for ${what} wasn't JSON.`, { cause: error });
    throw error;
  }
}

/**
 * What Azure answers a GET, or an error naming what was read and why it
 * failed: never the URL, which names the subscription, nor Azure's message.
 */
function get(az: Az, url: string, what: string): Readonly<Record<string, unknown>> {
  const done = az.run(['rest', '--method', 'get', '--url', url, '--output', 'json']);
  if (done.status !== 0) throw new Error(`Azure didn't answer the read of ${what} (${azureRefusal(done.stderr)}).`);
  return parsed(done.stdout, what);
}

/**
 * The subscription the CLI is signed in to, said by its name alone: its ID
 * stays out of CI's public logs. A sign-in to a tenant alone, whose "ID" is the
 * tenant's, is none.
 */
function signedIn(az: Az, say: (line: string) => void): string {
  const done = az.run(['account', 'show', '--output', 'json']);
  if (done.status !== 0) throw new Error(`The Azure CLI isn't signed in (${azureRefusal(done.stderr)}).`);
  const account = parsed(done.stdout, 'the account');
  const id = typeof account.id === 'string' ? account.id : '';
  if (!GUID.test(id) || id === account.tenantId)
    throw new Error("The Azure CLI named no subscription it's signed in to.");
  say(`Signed in to the subscription "${String(account.name)}".`);
  return id;
}

/** A workload as Azure has it: its properties, and what it runs. */
interface Read {
  readonly properties: Readonly<Record<string, unknown>>;
  /** Its tags: the migration job's hold the hand deploys' records (T1b). */
  readonly tags: Readonly<Record<string, unknown>>;
  readonly running: Running;
}

/** A workload, read from Azure. */
function readWorkload(az: Az, subscription: string, workload: Workload): Read {
  const found = get(az, workloadUrl(subscription, workload), workload);
  const properties = record(found.properties);
  return { properties, tags: record(found.tags), running: runningIn(workload, record(properties.template).containers) };
}

/** The build a container names in AGENTX_RELEASE, or nothing. */
const buildOf = (container: Container): string => {
  const found = container.env.find((setting) => setting.name === RELEASE_SETTING);
  return found !== undefined && 'value' in found ? found.value : '';
};

/** Whether two containers are the same, field for field. */
const same = (one: Container, other: Container): boolean => JSON.stringify(one) === JSON.stringify(other);

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

/** What a check reads from this folder: the commit it is at, and what Bicep says each deployment reads. */
export interface Folder {
  readonly checkout: () => Checkout;
  readonly references: (paramsFiles: readonly string[]) => Promise<ReadonlyMap<string, readonly string[]>>;
}

const realFolder = (): Folder => ({ checkout: () => realCheckout(), references: (files) => fileReferences(files) });

export interface CheckSteps {
  readonly az: Az;
  readonly history: History;
  readonly folder: Folder;
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

/**
 * Which hand deploys read each file, as Bicep says of this folder, which must
 * be a clean checkout of the commit; or nothing, with why said, when that
 * can't be known. It is asked only once a release is red, and only what the
 * red says rests on it.
 */
async function readersAt(commit: string, steps: CheckSteps): Promise<Readers | undefined> {
  const unsaid = (why: string): void => {
    steps.say(`Which hand deploy reads each file goes unsaid: ${why}.`);
  };
  try {
    const here = steps.folder.checkout();
    if (here.head !== commit || !here.clean) {
      unsaid(`this folder is at ${here.head}${here.clean ? '' : ' with changes'}, not ${commit}`);
      return undefined;
    }
    return readersFrom(await steps.folder.references([...PARAMS_PATHS.values()]));
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    unsaid(error.message);
    return undefined;
  }
}

async function plan(request: Request, steps: CheckSteps): Promise<Plan> {
  const subscription = signedIn(steps.az, steps.say);
  const image = `${IMAGE_REPOSITORY}@${request.digest}`;
  const reads = new Map(ORDER.map((workload) => [workload, readWorkload(steps.az, subscription, workload)] as const));
  const running = new Map([...reads].map(([workload, read]) => [workload, read.running] as const));
  for (const [workload, found] of running) steps.say(`${workload} runs ${found.release} (${found.image}).`);
  const first = decide(running, request.commit, image, steps.history);
  if (first.kind !== 'by-hand') return { subscription, image, reads, running, decision: first };
  const readers = await readersAt(request.commit, steps);
  const records = recordsIn(reads.get('migrate')?.tags ?? {}, steps.say);
  steps.say(
    records.size === 0
      ? 'The migration job holds no hand deploy records.'
      : `The migration job records: ${[...records].map(([deployment, sent]) => `${deployment} sent ${sent}`).join('; ')}.`,
  );
  const decision = decide(running, request.commit, image, steps.history, readers, records);
  return { subscription, image, reads, running, decision };
}

/** What the records show deployed by hand, said before a release goes ahead. */
function sayDeployed(decision: Decision, say: (line: string) => void): void {
  if (decision.kind !== 'release' || decision.deployed.length === 0) return;
  say('Deployed by hand already, as the migration job records:');
  for (const line of decision.deployed) say(`  ${line}`);
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
export async function check(request: Request, steps: CheckSteps): Promise<number> {
  const { running, decision } = await plan(request, steps);
  const stop = settled(decision, request.commit, steps.say);
  if (stop !== undefined || decision.kind !== 'release') return stop ?? 1;
  sayDeployed(decision, steps.say);
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

/** How long a started run may take to be listed. */
const LIST_WAIT_MS = 2 * 60_000;

/** How long the API's new revision may take to serve, and then to answer through its door (cold starts ~25 s, S22). */
const SERVE_WAIT_MS = 5 * 60_000;

/**
 * Where a release stopped leaves staging, said with its error: every stop
 * after the first write says what now holds what, and what still serves.
 */
async function leaving<T>(left: string, step: () => T | Promise<T>): Promise<T> {
  try {
    return await step();
  } catch (error) {
    if (error instanceof Error) throw new Error(`${error.message}\nLeft: ${left}`, { cause: error });
    throw error;
  }
}

/** What must hold of a workload before the release writes: settled, from no earlier change still going or failed. */
function settledBefore(workload: Workload, read: Read): void {
  const state = String(read.properties.provisioningState);
  if (state !== 'Succeeded') {
    throw new Error(`${workload} is ${state} from an earlier change, so nothing was sent: look at it first.`);
  }
}

/** The address the API is served at, from its own setting (never printed: it names the domain). */
function publicOrigin(api: Running): string {
  const origin = api.container.env.find((setting) => setting.name === 'AGENTX_PUBLIC_ORIGIN');
  const value = origin !== undefined && 'value' in origin ? origin.value : '';
  if (!/^https:\/\/[a-z0-9.-]+$/.test(value)) {
    throw new Error('The API names no https origin (AGENTX_PUBLIC_ORIGIN) to check it through once released.');
  }
  return value;
}

/**
 * A revision suffix set by hand would be sent again with CI's update and
 * refused as taken, after the migration had run: so none may be set.
 */
function noSuffix(api: Read): void {
  const suffix = record(api.properties.template).revisionSuffix;
  if (suffix !== undefined && suffix !== '') {
    throw new Error(`The API has the revision suffix ${JSON.stringify(suffix)} set, which a release would send again.`);
  }
}

/** How long migrate's one run may take, in seconds (apps.bicep). */
function timeLimit(job: Read): number {
  const limit = record(job.properties.configuration).replicaTimeout;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit <= 0) {
    throw new Error('Azure gave no time limit for migrate, so how long to wait for its run is unknown.');
  }
  return limit;
}

/**
 * Sends the update: the containers alone, as a PATCH (release.bicep), once
 * the workload is read again and found exactly as it was when the release was
 * decided: anything else there since means another deploy, not to be
 * overwritten. A workload already holding the update is sent nothing.
 */
function update(steps: ReleaseSteps, subscription: string, workload: Workload, seen: Running, after: Container): Read {
  const now = readWorkload(steps.az, subscription, workload);
  if (!same(now.running.container, seen.container)) {
    throw new Error(
      `${workload} changed while this release ran (it now runs ${now.running.release}, ${now.running.image}): another deploy is going on, so it wasn't updated.`,
    );
  }
  if (same(seen.container, after)) {
    steps.say(`${workload} already holds ${buildOf(after)}: nothing to send.`);
    return now;
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
      `Azure refused the update of ${workload} (${azureRefusal(done.stderr)}). Its message isn't shown, since it can quote the settings sent: the resource group's activity log has it.`,
    );
  }
  steps.say(`Updating ${workload}: ${changes(seen.container, after).join('; ')}.`);
  return now;
}

/**
 * Waits for Azure to settle an update. Settled is Azure holding what was sent,
 * marked Succeeded: just after the PATCH it can still show what was there
 * before, marked with the state that had, so a failure counts only once it is
 * this update's.
 */
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
    const taken = same(now.running.container, after);
    if (taken && state === 'Succeeded') {
      steps.say(`${workload} holds ${buildOf(after)}.`);
      return now;
    }
    if (taken && (state === 'Failed' || state === 'Canceled')) {
      throw new Error(`Azure's update of ${workload} ended ${state}.`);
    }
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `Azure hadn't settled the update of ${workload} after ${String(UPDATE_WAIT_MS / 60_000)} minutes (${state}${taken ? '' : ', not yet holding it'}).`,
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

function runs(steps: ReleaseSteps, subscription: string): Run[] {
  const listed = get(steps.az, jobUrl(subscription, '/executions'), "migrate's runs");
  if (!Array.isArray(listed.value)) throw new Error("Azure's list of migrate's runs wasn't a list.");
  return listed.value.map((entry) => {
    const found = record(entry);
    return { name: String(found.name), status: String(record(found.properties).status) };
  });
}

/** migrate's runs, once none is still going: two would race (apps.bicep). */
function idle(steps: ReleaseSteps, subscription: string): Run[] {
  const listed = runs(steps, subscription);
  const going = listed.filter((run) => !ENDED.has(run.status));
  if (going.length > 0) {
    throw new Error(
      `migrate has runs that haven't ended (${going.map((run) => `${run.name} ${run.status}`).join(', ')}).`,
    );
  }
  return listed;
}

/**
 * Starts the migration job as it is now deployed, with no template of its own
 * (a POST with no body), once none of its runs is still going. Azure may take
 * the start before it lists the run, or without naming it, so the run is the
 * one new run listed within LIST_WAIT_MS, and the one the start named if it
 * named one.
 */
async function startMigration(steps: ReleaseSteps, subscription: string): Promise<string> {
  const known = new Set(idle(steps, subscription).map((run) => run.name));
  const done = steps.az.run(['rest', '--method', 'post', '--url', jobUrl(subscription, '/start')]);
  if (done.status !== 0) throw new Error(`Azure refused to start migrate (${azureRefusal(done.stderr)}).`);
  const named = done.stdout.trim() === '' ? undefined : String(parsed(done.stdout, "migrate's start").name);
  const deadline = steps.now().getTime() + LIST_WAIT_MS;
  for (;;) {
    const fresh = runs(steps, subscription).filter((run) => !known.has(run.name));
    const [started] = fresh;
    if (fresh.length > 1) {
      throw new Error(
        `migrate was started, but ${String(fresh.length)} new runs are listed, so which is this release's is unknown.`,
      );
    }
    if (started !== undefined) {
      // Azure's own name for it, held to the job's runs before it goes into a URL.
      if (!isRunOf('migrate', started.name) || (named !== undefined && named !== started.name)) {
        throw new Error(
          `Azure listed migrate's new run as "${started.name}"${named === undefined ? '' : ` and started "${named}"`}, which isn't this release's run.`,
        );
      }
      steps.say(`Started ${started.name}.`);
      return started.name;
    }
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `migrate was started, but no new run was listed within ${String(LIST_WAIT_MS / 60_000)} minutes.`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/**
 * Waits for the run to end, within the job's own time limit and the start
 * allowance: how it ended. The run must be of this release's image, or it is
 * another release's.
 */
async function ended(
  steps: ReleaseSteps,
  subscription: string,
  name: string,
  image: string,
  limit: number,
): Promise<string> {
  const deadline = steps.now().getTime() + (limit + START_ALLOWANCE_SECONDS) * 1000;
  let last = '';
  for (;;) {
    const run = record(get(steps.az, jobUrl(subscription, `/executions/${name}`), name).properties);
    const [container] = Array.isArray(record(run.template).containers)
      ? (record(run.template).containers as unknown[])
      : [];
    const ran = String(record(container).image);
    if (ran !== image) throw new Error(`${name} runs ${ran}, not this release's image: another release started it.`);
    const status = String(run.status);
    if (status !== last) {
      steps.say(`  ${name}: ${status}`);
      last = status;
    }
    if (ENDED.has(status)) return status;
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `${name} hadn't ended ${String(limit + START_ALLOWANCE_SECONDS)} s after it started. To wait for it: node deploy/azure/jobs.ts wait migrate ${name}`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/** A revision of the API as Azure has it, and the image and build it runs. */
interface Revision {
  readonly properties: Readonly<Record<string, unknown>>;
  readonly running: { readonly image: string; readonly release: string };
}

/**
 * The image and build of a revision's one container, and nothing more: a
 * revision's template is Azure's own record, filled with its defaults (`probes:
 * []`, no `args`; the first real release, S24), and nothing is ever sent back
 * from it, so it isn't held to what runningIn holds a template to. A shape that
 * names neither reads as another release's, which is never served as this one.
 */
function revisionRuns(containers: unknown): Revision['running'] {
  const listed: readonly unknown[] = Array.isArray(containers) && containers.length === 1 ? containers : [];
  const container = record(listed[0]);
  if (container.name !== WORKLOADS.api.container) return { image: 'no container named api', release: 'none' };
  const builds = (Array.isArray(container.env) ? container.env : [])
    .map(record)
    .filter((setting) => setting.name === RELEASE_SETTING);
  const release = builds.length === 1 ? String(builds[0]?.value) : 'none';
  return { image: String(container.image), release };
}

function readRevision(steps: ReleaseSteps, subscription: string, name: string): Revision {
  const url = workloadUrl(subscription, 'api').replace('?api-version=', `/revisions/${name}?api-version=`);
  const properties = record(get(steps.az, url, name).properties);
  return { properties, running: revisionRuns(record(properties.template).containers) };
}

/**
 * Why a revision doesn't serve the release yet, or nothing when it does: this
 * image and build, provisioned, active, all traffic, and (once it has answered,
 * since a revision no replica has started yet may not say) healthy.
 */
function notServing(revision: Revision, image: string, commit: string, answered: boolean): string | undefined {
  const { properties, running } = revision;
  if (running.image !== image || running.release !== commit) {
    return `it runs ${running.release} (${running.image}), not this release`;
  }
  const state = [
    String(properties.provisioningState),
    `active ${String(properties.active)}`,
    `${String(properties.trafficWeight)}% of traffic`,
    String(properties.healthState),
  ].join(', ');
  const serving =
    properties.provisioningState === 'Provisioned' &&
    properties.active === true &&
    properties.trafficWeight === 100 &&
    (!answered || properties.healthState === 'Healthy');
  return serving ? undefined : state;
}

/** Azure's own name for one of the API's revisions, held to that shape before it goes into a URL. */
function revisionName(name: unknown): string {
  const revision = String(name);
  if (!/^ca-agentx-stg-api--[a-z0-9]+$/.test(revision)) {
    throw new Error(`Azure named the API's revision "${revision}", which isn't one of its revisions.`);
  }
  return revision;
}

/**
 * Waits until the API serves the release: a new revision is the ready one;
 * it holds this image and build, is provisioned, active, takes all traffic and
 * is healthy; and the door answers /health while it does (which starts a
 * replica, from zero). Each is waited for, not read once, within the wait.
 */
async function served(
  steps: ReleaseSteps,
  subscription: string,
  before: string,
  target: { readonly origin: string; readonly image: string; readonly commit: string },
): Promise<string> {
  const deadline = steps.now().getTime() + SERVE_WAIT_MS;
  const late = (what: string): Error =>
    new Error(`The API's new revision wasn't ${what} ${String(SERVE_WAIT_MS / 60_000)} minutes after its update.`);
  const wait = async (): Promise<void> => {
    await steps.sleep(POLL_MS);
  };
  const ready = async (): Promise<string> => {
    for (;;) {
      const { properties } = readWorkload(steps.az, subscription, 'api');
      const latest = properties.latestRevisionName;
      if (latest !== before && latest === properties.latestReadyRevisionName) return revisionName(latest);
      if (steps.now().getTime() >= deadline) throw late('ready');
      await wait();
    }
  };
  const revision = await ready();
  const serving = async (answered: boolean): Promise<void> => {
    const what = answered ? 'healthy once it answered' : 'serving';
    for (;;) {
      const found = readRevision(steps, subscription, revision);
      const why = notServing(found, target.image, target.commit, answered);
      if (why === undefined) return;
      // Another image or build is another deploy's revision, and a failed one won't recover: neither is waited for.
      const ours = found.running.image === target.image && found.running.release === target.commit;
      if (!ours || found.properties.provisioningState === 'Failed') {
        throw new Error(`The API's new revision ${revision} doesn't serve this release: ${why}.`);
      }
      if (steps.now().getTime() >= deadline) throw new Error(`${late(what).message} (${why})`);
      await wait();
    }
  };
  await serving(false);
  steps.say(`The API's new revision ${revision} takes all traffic; asking the door for /health...`);
  for (;;) {
    if ((await steps.probe(`${target.origin}/health`)) === 200) break;
    if (steps.now().getTime() >= deadline) throw late('answering /health');
    await wait();
  }
  await serving(true);
  return revision;
}

/**
 * When both already hold the commit: nothing to do only if the API's ready
 * revision serves it. A release that stopped after the API's update (its new
 * revision never ready) leaves the template holding the commit while the old
 * revision serves, and a run again must say so, red, not green.
 */
function alreadyServed(steps: ReleaseSteps, subscription: string, api: Read, image: string, commit: string): number {
  const latest = api.properties.latestRevisionName;
  const ready = api.properties.latestReadyRevisionName;
  const why =
    latest !== ready
      ? `its latest revision ${String(latest)} isn't the ready one (${String(ready)})`
      : notServing(readRevision(steps, subscription, revisionName(latest)), image, commit, true);
  if (why !== undefined) {
    steps.say(
      `Both hold ${commit}, but the API doesn't serve it: ${why}. Look at its revisions, then deploy by hand (apps).`,
    );
    return 1;
  }
  steps.say(`Both already run ${commit}, and the API serves it from ${String(latest)}: a release has nothing to do.`);
  return 0;
}

/**
 * `release`: checks the image, then does what `check` says: the migration job
 * updated and run to success, then the API updated and serving. 0 when it is
 * released or had nothing to do, 1 when it stopped, saying where and what it
 * left.
 */
export async function release(request: Request, steps: ReleaseSteps): Promise<number> {
  const { commit } = request;
  const image = `${IMAGE_REPOSITORY}@${request.digest}`;
  steps.say(`Checking ${image} was signed by CI on main at ${commit}, with its SBOM...`);
  const outcome = steps.verify(image, commit);
  if (!outcome.verified) {
    steps.say(`The image was refused (${outcome.reason}), so nothing was read or changed:\n${outcome.detail}`);
    return 1;
  }
  const { subscription, reads, decision } = await plan(request, steps);
  const job = reads.get('migrate');
  const api = reads.get('api');
  if (job === undefined || api === undefined) throw new Error('The release lost track of a workload.');
  if (decision.kind === 'current') return alreadyServed(steps, subscription, api, image, commit);
  const stop = settled(decision, commit, steps.say);
  if (stop !== undefined || decision.kind !== 'release') return stop ?? 1;
  sayDeployed(decision, steps.say);
  const migrateAfter = decision.updates.get('migrate');
  const apiAfter = decision.updates.get('api');
  if (migrateAfter === undefined || apiAfter === undefined) throw new Error('The release lost track of a workload.');
  const old = api.running.release;

  // Everything knowable before the first write is settled before it.
  const { origin, limit } = await leaving('nothing was changed.', () => {
    settledBefore('migrate', job);
    settledBefore('api', api);
    noSuffix(api);
    idle(steps, subscription);
    return { origin: publicOrigin(api.running), limit: timeLimit(job) };
  });

  await leaving(`migrate may hold ${commit}, not run; the API is on ${old}.`, async () => {
    update(steps, subscription, 'migrate', job.running, migrateAfter);
    await settledUpdate(steps, subscription, 'migrate', migrateAfter);
  });
  const name = await leaving(
    `migrate holds ${commit}, not run (a start that failed late may still have begun one: look at migrate's runs); the API is on ${old}.`,
    () => startMigration(steps, subscription),
  );
  const status = await leaving(`migrate holds ${commit}, its run ${name} not seen to end; the API is on ${old}.`, () =>
    ended(steps, subscription, name, image, limit),
  );
  if (status !== 'Succeeded') {
    steps.say(
      `${name} ended ${status}, so the API wasn't updated. Read its log: node deploy/azure/jobs.ts wait migrate ${name}\nLeft: migrate holds ${commit}; the API is on ${old}.`,
    );
    return 1;
  }

  const before = await leaving(`migrate ran ${commit}; the API is on ${old}.`, () =>
    update(steps, subscription, 'api', api.running, apiAfter),
  );
  const revision = await leaving(
    `migrate ran ${commit}; the API's template holds ${commit}, and until a new revision serves it the old one does.`,
    async () => {
      await settledUpdate(steps, subscription, 'api', apiAfter);
      return served(steps, subscription, String(before.properties.latestRevisionName), { origin, image, commit });
    },
  );
  steps.say(
    `Released ${commit}: ${name} succeeded, and the API's revision ${revision} holds it, takes all traffic and is healthy; its door answered /health.`,
  );
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
  folder: () => Folder = realFolder,
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
    const steps = { az: az(), history: history(), folder: folder(), say };
    return request.command === 'check'
      ? await check(request, steps)
      : await release(request, { ...steps, ...extras() });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
