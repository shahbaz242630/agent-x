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
//   stays red, however many merges follow, until a hand deploy catches up
// - an update carries the whole containers array, since Azure's PATCH replaces
//   an array whole, and nothing else: no environment and no identity, which
//   would ask for the linked actions CI's role doesn't hold (release.bicep).
//   Each container is Azure's own, with the image and AGENTX_RELEASE changed
//   and nothing else; a field this tool doesn't know is refused, not guessed at
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { IMAGE_REPOSITORY } from '../image/verify.ts';
import { ARM, type Az, azJson, realAz, RESOURCE_GROUP, signedIn } from './deploy.ts';
import { JOBS_API } from './jobs.ts';

/**
 * What only a person deploys (partner, S23), each with why: a merge that
 * changes any of them since what staging runs stops the release, red. In
 * deploy/azure that is what Azure is built from, the Bicep and the files it
 * reads; the TypeScript there (this tool, the deploy tool, the rules) changes
 * how a deploy is done, not what Azure holds.
 */
export const HAND_DEPLOYED: readonly {
  readonly prefix: string;
  readonly except?: string;
  readonly why: string;
}[] = [
  {
    prefix: 'deploy/azure/',
    except: '.ts',
    why: "Azure's own set-up, Zitadel's images among it, deployed with a what-if read",
  },
  { prefix: 'db/bootstrap/', why: "the database's roles, which the set-up job sets with the server admin's login" },
  { prefix: 'apps/db-setup/', why: 'the set-up job, which only a person runs' },
];

/** The hand-deployed thing a file belongs to, if any. */
const handDeployed = (file: string): (typeof HAND_DEPLOYED)[number] | undefined =>
  HAND_DEPLOYED.find(
    ({ prefix, except }) => file.startsWith(prefix) && (except === undefined || !file.endsWith(except)),
  );

/** The two things a release changes, as Azure names them and the one container each runs (apps.bicep). */
export const WORKLOADS = {
  migrate: { path: 'jobs/job-agentx-stg-migrate', container: 'migrate' },
  api: { path: 'containerApps/ca-agentx-stg-api', container: 'api' },
} as const;
export type Workload = keyof typeof WORKLOADS;

/** The order a release updates them in: the migration first, so the API never runs ahead of its tables. */
export const ORDER: readonly Workload[] = ['migrate', 'api'];

/** The setting that names the build on every log line. */
const RELEASE_SETTING = 'AGENTX_RELEASE';

/** A commit on main, as git writes it in full. */
const COMMIT = /^[0-9a-f]{40}$/;

/** An image digest, as ghcr.io gives it. */
const DIGEST = /^sha256:[0-9a-f]{64}$/;

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

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export const USAGE = `Usage:
  node deploy/azure/release.ts check <commit> <digest>   say what a release of that commit would do, changing nothing
<commit> is a full commit on main; <digest> is its image's, sha256:<64 hex>.`;

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

const record = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};

/**
 * What a workload runs, read from its containers as Azure gives them, or an
 * error saying why this isn't the workload a release knows: exactly one
 * container, named as apps.bicep names it, running our image by digest, with
 * one AGENTX_RELEASE naming a commit, and no field this tool doesn't copy.
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
  if (!Array.isArray(env)) return refuse('its settings are not a list');
  const settings = env.map((entry): Setting => {
    const { name: setting, value, secretRef } = record(entry);
    if (typeof setting !== 'string') return refuse('a setting has no name');
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
      // Azure also reports the disk it gives the size (ephemeralStorage), which is its to work out, not ours to send.
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

/** Reading the repository's history, which CI checks out whole. */
export interface History {
  /** Whether `ancestor` is `commit` or in its history. */
  isAncestor(ancestor: string, commit: string): boolean;
  /** The files that differ between the two commits. */
  changedFiles(from: string, to: string): readonly string[];
}

export type Decision =
  | { readonly kind: 'current' }
  | { readonly kind: 'by-hand'; readonly reasons: readonly string[] }
  | { readonly kind: 'release'; readonly updates: ReadonlyMap<Workload, Container> };

/**
 * What a release of `commit` would do, given what each workload runs: nothing
 * when both already run it; a hand deploy when what either runs isn't in the
 * commit's history, or anything a person deploys changed since; otherwise
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
  const reasons = new Set<string>();
  for (const release of new Set(all.map(([, found]) => found.release))) {
    if (!history.isAncestor(release, commit)) {
      reasons.add(`staging runs ${release}, which isn't in ${commit}'s history`);
      continue;
    }
    for (const file of history.changedFiles(release, commit)) {
      const rule = handDeployed(file);
      if (rule !== undefined) reasons.add(`${file} changed since ${release}: ${rule.why}`);
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

/** The repository this file is in: git runs there, whatever the shell's folder. */
const REPOSITORY = fileURLToPath(new URL('../../', import.meta.url));

/** git itself, run with its arguments as a list, never through a shell. */
export function realHistory(repository = REPOSITORY): History {
  const git = (args: readonly string[]) =>
    spawnSync('git', args, { cwd: repository, encoding: 'utf8', windowsHide: true });
  return {
    isAncestor: (ancestor, commit) => {
      // A commit this clone doesn't have is in no history it can see: a hand deploy, not an error.
      if (git(['cat-file', '-e', `${ancestor}^{commit}`]).status !== 0) return false;
      const done = git(['merge-base', '--is-ancestor', ancestor, commit]);
      // 1 means "not an ancestor"; anything else (an unknown commit, 128) is an error, not an answer.
      if (done.status === 0 || done.status === 1) return done.status === 0;
      throw new Error(`git couldn't compare ${ancestor} and ${commit}:\n${done.stderr.trim()}`);
    },
    changedFiles: (from, to) => {
      const done = git(['diff', '--name-only', '--no-renames', from, to]);
      if (done.status !== 0)
        throw new Error(`git couldn't list the changes from ${from} to ${to}:\n${done.stderr.trim()}`);
      return done.stdout.split('\n').filter((file) => file !== '');
    },
  };
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
