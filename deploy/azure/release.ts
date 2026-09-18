// What CI does after a merge to main (0e G4-3; ADR-002 "Deploying"): puts the
// new image into the migration job, runs it, then puts it into the API. The
// partner set the limits (S23): CI changes only our image's version (its
// digest and AGENTX_RELEASE) in those two, and starts the migration; a merge
// that needs a hand deploy stops the release, red.
//
//   node deploy/azure/release.ts check <commit> <digest>
//
// `check` (G4-3a) reads what staging runs and says what a release of that
// commit would do, changing nothing: whether a person must deploy it instead,
// and what each update would change. The release itself follows (G4-3b).
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
// - only images, commits and file names are printed: the settings name the
//   domain, and the subscription is Azure's, both kept out of CI's public logs
import { readFileSync } from 'node:fs';

import { IMAGE_REPOSITORY } from '../image/verify.ts';
import { ARM, type Az, azJson, realAz, RESOURCE_GROUP } from './deploy.ts';
import { type History, realHistory } from './git.ts';
import { JOBS_API } from './jobs.ts';

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
  node deploy/azure/release.ts check <commit> <digest>   say what a release of that commit would do, changing nothing
<commit> is a full commit; <digest> is its image's, sha256:<64 hex>.`;

export interface Request {
  readonly command: 'check';
  readonly commit: string;
  readonly digest: string;
}

/** What was asked for, or a UsageError saying why it can't be done. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, commit, digest, ...rest] = argv;
  if (command !== 'check') throw new UsageError(`say check, not ${command ?? 'nothing'}`);
  if (commit === undefined || !COMMIT.test(commit)) {
    throw new UsageError(`${commit ?? 'nothing'} isn't a full commit (40 lower-case hex)`);
  }
  if (digest === undefined || !DIGEST.test(digest)) {
    throw new UsageError(`${digest ?? 'nothing'} isn't an image digest (sha256: and 64 lower-case hex)`);
  }
  if (rest.length > 0) throw new UsageError(`check takes a commit and a digest, not ${rest.join(' ')} as well`);
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

/** What a workload runs, read from Azure. */
function readRunning(az: Az, subscription: string, workload: Workload): Running {
  const shown = record(azJson(az, ['rest', '--method', 'get', '--url', workloadUrl(subscription, workload)]));
  return runningIn(workload, record(record(shown.properties).template).containers);
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

export interface ReleaseSteps {
  readonly az: Az;
  readonly history: History;
  readonly say: (line: string) => void;
}

/** `check`: what a release would do, said; 0 when it could go ahead (or has nothing to do), 1 when it needs a hand deploy. */
export function check(request: Request, steps: ReleaseSteps): number {
  const subscription = signedIn(steps.az, steps.say);
  const image = `${IMAGE_REPOSITORY}@${request.digest}`;
  const running = new Map(ORDER.map((workload) => [workload, readRunning(steps.az, subscription, workload)] as const));
  for (const [workload, found] of running) steps.say(`${workload} runs ${found.release} (${found.image}).`);
  const decision = decide(running, request.commit, image, steps.history);
  if (decision.kind === 'current') {
    steps.say(`Both already run ${request.commit}: a release has nothing to do.`);
    return 0;
  }
  if (decision.kind === 'past') {
    steps.say(`Staging already runs a later commit than ${request.commit}: a release of it has nothing to do.`);
    return 0;
  }
  if (decision.kind === 'by-hand') {
    steps.say(`A release of ${request.commit} would stop, red: this needs a hand deploy.`);
    for (const reason of decision.reasons) steps.say(`  ${reason}`);
    return 1;
  }
  steps.say(`A release of ${request.commit} would update, in order:`);
  for (const [workload, after] of decision.updates) {
    const before = running.get(workload)?.container;
    const said = before === undefined ? [] : changes(before, after);
    steps.say(`  ${workload}: ${said.length > 0 ? said.join('; ') : 'nothing'}, and nothing else`);
  }
  return 0;
}

export function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => Az = realAz,
  history: () => History = realHistory,
): number {
  let request: Request;
  try {
    request = parseArguments(argv);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    say(`${error.message}\n${USAGE}`);
    return 2;
  }
  try {
    return check(request, { az: az(), history: history(), say });
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  }
}

if (import.meta.main) process.exitCode = main(process.argv.slice(2));
