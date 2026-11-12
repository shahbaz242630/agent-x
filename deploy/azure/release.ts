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
// - a new migration adding a trigger to a table already built, or a new body
//   to a guard function, is red unless the commit staging runs already carried
//   it as coming (decision 49, tooling/migration-order.ts): otherwise the image
//   running while it migrates raises a false tamper alarm
// - an update carries the whole containers array, since Azure's PATCH replaces
//   an array whole, and nothing else: no environment and no identity, which
//   would ask for the linked actions CI's role doesn't hold (release.bicep);
//   the API's also sends an empty revision suffix, so one set by hand is
//   cleared, never sent again and refused as taken (AZ7).
//   Each container is Azure's own, with the image and AGENTX_RELEASE changed
//   and nothing else; a field this tool doesn't know is refused, not guessed at.
//   The rest of each must first be what the commit's apps.bicep gives it (AZ2c,
//   drift.ts): a command or setting changed outside a deploy stops the release
//   red, before it could carry the change forward
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
import { fingerprintOf } from '../../tooling/git-hooks/private-names.ts';
import {
  COMING_FILE,
  MIGRATION_NAME,
  MIGRATIONS_FOLDER,
  parseComing,
  refusals,
} from '../../tooling/migration-order.ts';
import { IMAGE_REPOSITORY, type Outcome } from '../image/verify.ts';
import { type Anchor, anchorSaid, belowAnchor, forwardPast, lastRelease } from './anchor.ts';
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
  UsageError,
} from './deploy.ts';
import {
  type Bound,
  containersOf,
  deployable,
  differences,
  expectedOf,
  type LiveContainer,
  type Setting,
  shown,
  templatesIn,
  workloadDifferences,
} from './drift.ts';
import { atCommit, type Checkout, type History, realCheckout, realHistory } from './git.ts';
import {
  azureTime,
  ENDED,
  GUID,
  historyProblems,
  isRunOf,
  isStrings,
  JOBS_API,
  POLL_MS,
  runCli,
  START_ALLOWANCE_SECONDS,
} from './jobs.ts';

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
 * Kept here rather than in hand-deployed.json, so narrowing the gate didn't
 * turn a release red for nothing: like the rest of this tool, a change to it
 * is reviewed, not gated, and any other ending fails the .dockerignore test.
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

/** A workload as Azure names it, and the one container it runs (apps.bicep). */
export interface WorkloadSpec {
  readonly path: string;
  readonly container: string;
}

/** The two things a release changes, as Azure names them and the one container each runs (apps.bicep). */
export const WORKLOADS = {
  migrate: { path: 'jobs/job-agentx-stg-migrate', container: 'migrate' },
  api: { path: 'containerApps/ca-agentx-stg-api', container: 'api' },
} as const satisfies Readonly<Record<string, WorkloadSpec>>;
export type Workload = keyof typeof WORKLOADS;

/** The order a release updates them in: the migration first, and the API only once its run has succeeded (G4-3b). */
export const ORDER: readonly Workload[] = ['migrate', 'api'];

/**
 * What a folder's apps.bicep gives each release workload (its identity and
 * properties, as the snapshot has them), in the subscription.
 */
export type Templates = (subscription: string, commit: string) => ReadonlyMap<Workload, unknown>;

/** The pinned Bicep's snapshot of a deploy/azure folder's apps deployment (drift.ts): this checkout's unless given. */
export function templatesFrom(subscription: string, source?: string): ReadonlyMap<Workload, unknown> {
  const named = ORDER.map((workload) => {
    const [kind, name] = WORKLOADS[workload].path.split('/');
    return { type: `Microsoft.App/${String(kind)}`, name: String(name) };
  });
  const workloads = templatesIn(subscription, named, source);
  return new Map(ORDER.map((workload, index) => [workload, workloads[index]] as const));
}

/**
 * The real ones, of a commit's apps.bicep: this checkout's when it is a clean checkout of the commit, else the
 * commit's own, read in a temporary worktree (git.ts atCommit).
 */
export const realTemplates: Templates = (subscription, commit) => {
  const here = realCheckout();
  if (here.clean && here.head === commit) return templatesFrom(subscription);
  return atCommit(commit, 'deploy/azure', (dir) => templatesFrom(subscription, dir));
};

/** The setting that names the build on every log line. */
const RELEASE_SETTING = 'AGENTX_RELEASE';

/** A commit, as git writes it in full. */
export const COMMIT = /^[0-9a-f]{40}$/;

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

/** A container's size as Azure gives it: the two we set, and the disk it works out from them. */
const SIZE_FIELDS: ReadonlySet<string> = new Set(['cpu', 'memory', 'ephemeralStorage']);

export { UsageError } from './deploy.ts';

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

/** One container as a release sends it back: Azure's own fields, the ones this tool knows. */
export interface Container extends LiveContainer {
  readonly name: string;
  readonly image: string;
}

/** What a workload runs: its one container, and the image and build in it. */
export interface Running {
  readonly container: Container;
  readonly image: string;
  readonly release: string;
}

export function record(value: unknown): Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/** What a release workload runs (runningAs), refused as not "the <workload> a release knows". */
export const runningIn = (workload: Workload, containers: unknown): Running =>
  runningAs(WORKLOADS[workload], `the ${workload} a release knows`, containers);

/**
 * What a workload runs, read from its containers as Azure gives them, or an
 * error saying why this isn't `known`: exactly one container, named as
 * apps.bicep names it, running our image by digest, with one AGENTX_RELEASE
 * naming a commit, and no field this tool doesn't copy, in the container, its
 * size, a setting or a mount. The operator's job is read this way too, to be
 * kept on the API's build (operator.ts).
 */
export function runningAs(spec: WorkloadSpec, known: string, containers: unknown): Running {
  const { container: expected, path } = spec;
  const refuse = (why: string): never => {
    throw new Error(`${path} isn't ${known} (${why}): deploy it by hand.`);
  };
  if (!Array.isArray(containers) || containers.length !== 1) return refuse('it must run exactly one container');
  const found = record(containers[0]);
  const unknown = Object.keys(found).filter((field) => !CONTAINER_FIELDS.has(field));
  if (unknown.length > 0)
    return refuse(`its container has ${unknown.map(shown).join(', ')}, which this tool doesn't copy`);
  const { name, image, command, env, resources, volumeMounts } = found;
  // Azure leaves an empty argument list out of what it gives back (staging's API from 12 Nov 2026, after #626's
  // release): no arguments, as `[]`, which the release then sends back. Any other missing or odd list is refused.
  const args = 'args' in found ? found.args : [];
  if (name !== expected) return refuse(`its container isn't named ${expected}`);
  if (typeof image !== 'string' || !isOurImage(image)) return refuse(`it doesn't run ${IMAGE_REPOSITORY} by digest`);
  if (!isStrings(command) || !isStrings(args)) return refuse('its command or arguments are not lists of words');
  const size = record(resources);
  if (typeof size.cpu !== 'number' || typeof size.memory !== 'string') return refuse('its size is not given');
  const sized = Object.keys(size).filter((field) => !SIZE_FIELDS.has(field));
  if (sized.length > 0) return refuse(`its size has ${sized.map(shown).join(', ')}, which this tool doesn't copy`);
  if (!Array.isArray(env)) return refuse('its settings are not a list');
  const settings = env.map((entry): Setting => {
    const { name: setting, value, secretRef, ...other } = record(entry);
    if (typeof setting !== 'string') return refuse('a setting has no name');
    if (Object.keys(other).length > 0)
      return refuse(`the setting ${shown(setting)} has more than a name and its value`);
    if (typeof value === 'string' && secretRef === undefined) return { name: setting, value };
    if (typeof secretRef === 'string' && value === undefined) return { name: setting, secretRef };
    return refuse(`the setting ${shown(setting)} has neither a value nor a secret reference alone`);
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
  /** The API runs as `web` copies (a load run is up, 4D2e D13): a release would leave the jobs app behind. */
  | { readonly kind: 'load-run' }
  | { readonly kind: 'past' }
  | { readonly kind: 'by-hand'; readonly reasons: readonly string[] }
  /**
   * A migration staging's image wasn't told is coming (decision 49): a hand deploy is exactly what must not follow, as
   * it goes round this gate and the old image would raise a false tamper alarm as the migration runs.
   */
  | { readonly kind: 'coming-first'; readonly reasons: readonly string[] }
  /**
   * The API or the migration job isn't as the commit's apps.bicep has it beyond its image and build (AZ2c): changed
   * outside a deploy, which a release would carry forward, as it copies the rest of each container.
   */
  | { readonly kind: 'not-as-deployed'; readonly reasons: readonly string[] }
  | {
      readonly kind: 'release';
      readonly updates: ReadonlyMap<Workload, Container>;
      /** Each changed file a person deploys that the records show deployed, and by which. */
      readonly deployed: readonly string[];
    };

/**
 * What one file changed since a running release means: a reason for a hand
 * deploy, a line saying which recorded deploys sent it, or nothing when no
 * person deploys it.
 */
function changedFile(
  file: string,
  release: string,
  readers: Readers | undefined,
  recordFor: (deployment: Deployment, file: string) => string | undefined,
): { readonly kind: 'reason' | 'deployed'; readonly line: string } | undefined {
  const area = handDeployed(file);
  if (area === undefined) return undefined;
  const deployments = readers?.get(file.toLowerCase());
  if (deployments === undefined) return { kind: 'reason', line: `${file} changed since ${release}: ${area.why}` };
  const unrecorded = deployments.filter((deployment) => recordFor(deployment, file) === undefined);
  if (unrecorded.length > 0) return { kind: 'reason', line: `${file} changed since ${release}: ${toRun(unrecorded)}` };
  const sent = deployments.map((deployment) => `${deployment} from ${String(recordFor(deployment, file))}`);
  return { kind: 'deployed', line: `${file} changed since ${release}: deployed by hand, ${sent.join(', ')}` };
}

/**
 * Decision 49 (PL-66): each migration this release would run that adds a trigger to a table already built, or a new
 * body to a function already written, which the image staging runs (`release`) didn't carry as coming
 * (tooling/migration-order.ts). The check in CI holds a migration to the code before its merge, but GitHub may drop a
 * waiting release, so that code may never have run here: this holds it to what does run, before the first write.
 */
function notYetComing(release: string, commit: string, changed: readonly string[], history: History): string[] {
  const folder = `${MIGRATIONS_FOLDER}/`;
  const added = changed
    .filter((file) => file.startsWith(folder) && MIGRATION_NAME.test(file.slice(folder.length)))
    .filter((file) => history.fileAt(release, file) === undefined)
    .map((file) => file.slice(folder.length));
  if (added.length === 0) return [];
  const migrations = history
    .filesIn(commit, MIGRATIONS_FOLDER)
    .filter((name) => MIGRATION_NAME.test(name))
    .map((name) => ({ name, sql: history.fileAt(commit, `${folder}${name}`) ?? '' }));
  const coming = parseComing(history.fileAt(release, COMING_FILE));
  return refusals(migrations, added, () => coming).map((line) => `${line} (staging runs ${release})`);
}

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
  const notComing: string[] = [];
  for (const release of new Set(all.map(([, found]) => found.release))) {
    if (!history.isAncestor(release, commit)) {
      // Nothing can be read against it, decision 49 included: say so, so the hand deploy runs no unshipped trigger or body.
      reasons.add(`staging runs ${release}, which isn't in ${commit}'s history; ${OUTSIDE_HISTORY}`);
      continue;
    }
    const changed = history.changedFiles(release, commit);
    for (const file of changed) {
      const found = changedFile(file, release, readers, recordFor);
      if (found?.kind === 'reason') reasons.add(found.line);
      if (found?.kind === 'deployed') deployed.add(found.line);
    }
    notComing.push(...notYetComing(release, commit, changed, history));
  }
  // Before any hand deploy: once the coming entries are released, a rerun says what a person still has to deploy.
  if (notComing.length > 0) return { kind: 'coming-first', reasons: notComing };
  if (reasons.size > 0) return { kind: 'by-hand', reasons: [...reasons] };
  return {
    kind: 'release',
    updates: new Map(all.map(([workload, found]) => [workload, released(found, image, commit)])),
    deployed: [...deployed],
  };
}

/** A workload's URL in Resource Manager, at the version apps.bicep deploys it with. */
export const resourceUrl = (subscription: string, spec: WorkloadSpec): string =>
  `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/${spec.path}?api-version=${JOBS_API}`;

/** A release workload's URL in Resource Manager. */
export const workloadUrl = (subscription: string, workload: Workload): string =>
  resourceUrl(subscription, WORKLOADS[workload]);

/**
 * Why Azure refused, from what `az rest` printed: the HTTP reason and the
 * error's code (`ERROR: Forbidden({"error":{"code":"AuthorizationFailed",…}})`).
 * Nothing else is shown: the message can quote what was sent, the settings
 * among them, and names the subscription, and CI's log is public. The
 * resource group's activity log holds the whole of it.
 */
export function azureRefusal(stderr: string): string {
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
export function get(az: Az, url: string, what: string): Readonly<Record<string, unknown>> {
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
export interface Read {
  readonly properties: Readonly<Record<string, unknown>>;
  /** The identities it runs as, as Azure gives them. */
  readonly identity: unknown;
  /** Its tags: the migration job's hold the hand deploys' records (T1b). */
  readonly tags: Readonly<Record<string, unknown>>;
  readonly running: Running;
}

/** A workload, read from Azure. */
export function readWorkload(az: Az, subscription: string, workload: Workload): Read {
  const found = get(az, workloadUrl(subscription, workload), workload);
  const properties = record(found.properties);
  return {
    properties,
    identity: found.identity,
    tags: record(found.tags),
    running: runningIn(workload, record(properties.template).containers),
  };
}

/** The value a container's setting holds in the open, or nothing (none, or a secret reference). */
export const settingValue = (container: Container, name: string): string => {
  const found = container.env.find((setting) => setting.name === name);
  return found !== undefined && 'value' in found ? found.value : '';
};

/** The build a container names in AGENTX_RELEASE, or nothing. */
const buildOf = (container: Container): string => settingValue(container, RELEASE_SETTING);

/** Whether two containers are the same, field for field. */
export const same = (one: Container, other: Container): boolean => JSON.stringify(one) === JSON.stringify(other);

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

/**
 * What a check reads from this folder: the commit it is at, what Bicep says each deployment reads, and what its
 * apps.bicep gives the two workloads.
 */
export interface Folder {
  readonly checkout: () => Checkout;
  readonly references: (paramsFiles: readonly string[]) => Promise<ReadonlyMap<string, readonly string[]>>;
  readonly templates: Templates;
}

const realFolder = (): Folder => ({
  checkout: () => realCheckout(),
  references: (files) => fileReferences(files),
  templates: realTemplates,
});

export interface CheckSteps {
  readonly az: Az;
  readonly history: History;
  readonly folder: Folder;
  readonly say: (line: string) => void;
  /** verify.ts's answer for an image, by digest, at a commit. */
  readonly verify: (image: string, commit: string) => Outcome;
  /** The pins set for the release (PINS), from its environment: none set is an empty record. */
  readonly pins: Readonly<Record<string, string | undefined>>;
  /** The clock, which says how recent the oldest record is (recordedBuilds). */
  readonly now: () => Date;
  /** The last release GitHub recorded for staging (anchor.ts): read in CI, not outside it. */
  readonly anchor: () => Promise<Anchor>;
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

/** What to do when the templates can't be read: nothing was changed, and the release is run again from the commit. */
const UNCHECKED_GAP =
  'so whether the API or the migration job was changed outside a deploy (AZ2c) is unknown, and nothing was changed.';
const UNCHECKED_NEXT = `${UNCHECKED_GAP} Run this again from a clean checkout of the commit with the pinned Bicep (node tooling/bicep/install.ts).`;

/** The decisions held to what was deployed (AZ2c): a release about to write, and a re-run that has nothing to do. */
const HELD: ReadonlySet<Decision['kind']> = new Set(['release', 'current', 'past']);

/**
 * AZ2c: before anything is written, and on a re-run with nothing to do (read-only), each workload held to what the
 * apps.bicep of the build it runs gives it beyond its image and build, its build to its image's signature and to what
 * was deployed before it (rolledBack), and the shell's values to their pins; the decision unchanged when all hold.
 * The folder must be a clean checkout of the commit (CI's is). Nothing read is printed but names: the subscription is
 * masked out of Bicep's own words.
 */
async function heldToTemplates(
  decision: Decision,
  commit: string,
  subscription: string,
  reads: ReadonlyMap<Workload, Read>,
  steps: CheckSteps,
): Promise<Decision> {
  if (!HELD.has(decision.kind)) return decision;
  const here = steps.folder.checkout();
  if (here.head !== commit || !here.clean) {
    throw new Error(
      `This folder is at ${here.head}${here.clean ? '' : ' with changes'}, not ${commit}, so what apps.bicep gives the API and the migration job can't be read, ${UNCHECKED_NEXT}`,
    );
  }
  const bound: Bound = new Map();
  // Each build's templates read once, both workloads mostly running one build.
  const byBuild = new Map<string, ReadonlyMap<Workload, unknown>>();
  const reasons = ORDER.flatMap((workload) => heldWorkload(workload, reads, subscription, steps, { bound, byBuild }));
  const recorded = recordedBuilds(steps.az, subscription, steps.now());
  const anchor = await steps.anchor();
  const unanchored = anchorSaid(anchor);
  if (unanchored !== undefined) steps.say(unanchored);
  reasons.push(
    ...unsignedBuilds(reads, steps.verify),
    ...recorded.problems,
    ...rolledBack(reads, recorded, steps.history, anchor),
    ...unpinned(bound, steps.pins, steps.say),
  );
  return reasons.length === 0 ? decision : { kind: 'not-as-deployed', reasons };
}

/**
 * One workload held to the apps.bicep of the build it runs (drift.ts), as `workload: …` lines; an error in plain words
 * when that apps.bicep can't be read: this checkout's, or the build's own in a temporary worktree (git.ts atCommit).
 */
function heldWorkload(
  workload: Workload,
  reads: ReadonlyMap<Workload, Read>,
  subscription: string,
  steps: CheckSteps,
  held: { readonly bound: Bound; readonly byBuild: Map<string, ReadonlyMap<Workload, unknown>> },
): string[] {
  const read = reads.get(workload);
  if (read === undefined) throw new Error(`nothing was read for ${workload}`);
  const build = read.running.release;
  const bound = held.bound;
  let templates: ReadonlyMap<Workload, unknown>;
  try {
    templates = held.byBuild.get(build) ?? steps.folder.templates(subscription, build);
    held.byBuild.set(build, templates);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    const why = error.message.replaceAll(subscription, 'the subscription');
    const next = here(steps, build)
      ? UNCHECKED_NEXT
      : `${UNCHECKED_GAP} This checkout couldn't make a temporary worktree of ${build}, the build ${workload} runs: check git works here and the clone has the whole history (CI checks out with fetch-depth 0), then run this again.`;
    throw new Error(`What ${build}'s apps.bicep gives ${workload} couldn't be read (${why}), ${next}`, {
      cause: error,
    });
  }
  return workloadAgainst(workload, templates.get(workload), read, bound).map((line) => `${workload}: ${line}`);
}

/** Whether this folder is a clean checkout of the commit, whose apps.bicep is then read here. */
const here = (steps: CheckSteps, commit: string): boolean => {
  const at = steps.folder.checkout();
  return at.clean && at.head === commit;
};

/** The builds deploys have left on record, and why the record can't be trusted whole, if it can't. */
interface OnRecord {
  readonly api: readonly string[];
  readonly migrate: readonly string[];
  readonly problems: readonly string[];
}

/** Every item of a list Azure gives, page by page; a next page anywhere but Resource Manager is refused (the token goes where the URL points). */
export function listedAll(az: Az, url: string, what: string): unknown[] {
  const items: unknown[] = [];
  for (let next: string | undefined = url; next !== undefined;) {
    const page = get(az, next, what);
    if (!Array.isArray(page.value)) throw new Error(`Azure's list of ${what} wasn't a list.`);
    items.push(...(page.value as unknown[]));
    const link = page.nextLink;
    if (link !== undefined && link !== null && !(typeof link === 'string' && link.startsWith(ARM))) {
      throw new Error(
        `Azure's list of ${what} named its next page somewhere other than Resource Manager, so it wasn't read and nothing was changed. Run this again; if it repeats, look at it before any release.`,
      );
    }
    next = typeof link === 'string' ? link : undefined;
  }
  return items;
}

/** One revision or run on record: the build its workload's container's AGENTX_RELEASE names (any text, or none), and when it was made. */
interface Kept {
  readonly build: string | undefined;
  readonly startedAt: number | undefined;
}

/**
 * A revision or run as kept: the build of the container named as the workload's (apps.bicep), never whichever comes
 * first, and its creation (a revision) or start (a run). None of that name names no build: a record no deploy left.
 */
const keptOf =
  (workload: Workload) =>
  (item: unknown): Kept => {
    const properties = record(record(item).properties);
    const containers = record(properties.template).containers;
    const own = (Array.isArray(containers) ? (containers as unknown[]) : [])
      .map(record)
      .find((container) => container.name === WORKLOADS[workload].container);
    const env = own?.env;
    const found = (Array.isArray(env) ? env : []).map(record).find((setting) => setting.name === RELEASE_SETTING);
    return {
      build: typeof found?.value === 'string' ? found.value : undefined,
      startedAt: azureTime(properties.createdTime ?? properties.startTime),
    };
  };

/** How far back the record's own history is held to be whole: the job-start watch's window. */
const RECORD_HOURS = 6;

/**
 * What deploys have left on record (AZ2c): the builds of the API's revisions (Azure keeps each, a deploy can't take
 * one back; 100 inactive by default, which drift.ts holds) and of migrate's runs (its last 100). A list at that cap
 * whose oldest is still recent, or a flood of new ones, may have pushed an older record off its end: red, as the
 * job-start watch reads a job's runs (jobs.ts historyProblems). Read, never written.
 */
function recordedBuilds(az: Az, subscription: string, now: Date): OnRecord {
  const since = now.getTime() - RECORD_HOURS * 3_600_000;
  const revisionsUrl = workloadUrl(subscription, 'api').replace('?api-version=', '/revisions?api-version=');
  const revisions = listedAll(az, revisionsUrl, "the API's revisions").map(keptOf('api'));
  const runs = listedAll(az, jobUrl(subscription, '/executions'), "migrate's runs").map(keptOf('migrate'));
  const builds = (kept: readonly Kept[]): string[] => [...new Set(kept.map((each) => String(each.build)))];
  return {
    api: builds(revisions),
    migrate: builds(runs),
    problems: [
      ...historyProblems(revisions, since, RECORD_HOURS, 'revision').map(
        (problem) => `api: ${problem}, so a roll-back can't be ruled out: a suspected breach`,
      ),
      ...historyProblems(runs, since, RECORD_HOURS).map(
        (problem) => `migrate: ${problem}, so a roll-back can't be ruled out: a suspected breach`,
      ),
    ],
  };
}

/**
 * AZ2c: a workload rolled back, even to an older commit's own signed image, is a suspected breach. A release moves
 * both forward together, migrate first, so: neither may run a commit older than one deploys have left on record
 * (the API against its own revisions, since migrate alone may be ahead after --migrate-first or a stopped release;
 * migrate against both), and migrate may never be behind the API. A record naming a build that isn't a commit in this
 * history is one no deploy left: a suspected breach too.
 */
function rolledBack(
  reads: ReadonlyMap<Workload, Read>,
  recorded: OnRecord,
  history: History,
  anchor: Anchor,
): string[] {
  const api = reads.get('api')?.running.release ?? '';
  const migrate = reads.get('migrate')?.running.release ?? '';
  // One read of main's line places every build (git.ts mainline): newer is nearer the tip.
  const line = history.mainline();
  const place = (build: string): number | undefined => line.get(build);
  const said: string[] = [];
  for (const [workload, builds, kind] of [
    ['api', recorded.api, 'revision'],
    ['migrate', recorded.migrate, 'run'],
  ] as const) {
    const strange = builds.filter((build) => place(build) === undefined);
    if (strange.length > 0) {
      said.push(
        `${workload}: a ${kind} of it names a build that isn't in main's history (${strange.map(shown).join(', ')}): no deploy leaves one, a suspected breach (or this clone lacks main's newest commits: it reads origin/main, which git fetch origin main brings up to date)`,
      );
    }
  }
  /** The newest of the builds on record later than `build`, or nothing when none is. */
  const newestAfter = (build: string, among: readonly string[]): string | undefined => {
    let newest: string | undefined;
    let best = place(build);
    if (best === undefined) return undefined;
    for (const each of new Set(among)) {
      const at = place(each);
      if (at !== undefined && at < best) {
        best = at;
        newest = each;
      }
    }
    return newest;
  };
  for (const [workload, build] of [
    ['api', api],
    ['migrate', migrate],
  ] as const) {
    if (place(build) === undefined) {
      said.push(
        `${workload}: it runs ${shown(build)}, which isn't on main's line here, so how new it is can't be told: a suspected breach, unless this clone lacks main's newest commits (git fetch origin main; CI checks out with fetch-depth 0)`,
      );
    }
  }
  said.push(...belowAnchor(anchor, { api, migrate }, place));
  const apiLater = newestAfter(api, recorded.api);
  if (apiLater !== undefined) {
    said.push(
      `api: it runs ${api}, older than ${apiLater}, which one of its revisions ran: rolled back. ${forwardPast(apiLater)}`,
    );
  }
  const migrateLater = newestAfter(migrate, [...recorded.migrate, ...recorded.api]);
  if (migrateLater !== undefined) {
    said.push(
      `migrate: it runs ${migrate}, older than ${migrateLater}, which a run of it or an API revision ran: rolled back. ${forwardPast(migrateLater)}`,
    );
  }
  if ((place(migrate) ?? -1) > (place(api) ?? Number.POSITIVE_INFINITY)) {
    said.push(
      `migrate: it runs ${migrate}, behind the API's ${api}, which a release never leaves (it moves migrate first). If a hand apps run failed part way (it updates both at once), run apps again; otherwise a suspected breach`,
    );
  }
  return said;
}

/** The kind of workload, as Resource Manager names it. */
const kindOf = (workload: Workload): 'jobs' | 'containerApps' =>
  WORKLOADS[workload].path.startsWith('jobs/') ? 'jobs' : 'containerApps';

/** Every way a workload read from Azure differs from its template (drift.ts): its container, then the rest of it. */
function workloadAgainst(workload: Workload, template: unknown, read: Read, bound: Bound): string[] {
  return [
    ...differences(expectedOf(containersOf(template)), read.running.container, bound),
    ...workloadDifferences(kindOf(workload), template, { identity: read.identity, properties: read.properties }, bound),
  ];
}

/**
 * AZ2c H2: each workload's build, as its AGENTX_RELEASE names it, must be the commit its image's signature names:
 * CI signs each image for the one commit it was built from (verify.ts), and every deploy stamps that commit. A build
 * that isn't, an older commit's name on today's image say, would hide a change from the history the gate reads. Each
 * image and build is checked once.
 */
function unsignedBuilds(reads: ReadonlyMap<Workload, Read>, verify: CheckSteps['verify']): string[] {
  const checked = new Map<string, Outcome>();
  return ORDER.flatMap((workload) => {
    const running = reads.get(workload)?.running;
    if (running === undefined) return [];
    const key = `${running.image} ${running.release}`;
    const outcome = checked.get(key) ?? verify(running.image, running.release);
    checked.set(key, outcome);
    if (outcome.verified) return [];
    return [
      `${workload}: its image isn't CI's signed build of ${running.release}, the commit its ${RELEASE_SETTING} names (${outcome.reason}): a suspected breach`,
    ];
  });
}

/**
 * AZ2c H3: the staging secrets that pin what only the partner's shell gives `apps`, each the SHA-256 of the value in
 * lower case (as the domain guard keeps the domain, tooling/git-hooks/private-names.ts), by the marker it is matched
 * by (drift.ts SHELL_MARKERS). The values never reach CI or this repository; their hashes only confirm them.
 */
const PINS = [
  { variable: 'AGENTX_AUTH_HOST_SHA256', shell: 'AGENTX_AZURE_AUTH_HOST', what: 'auth host' },
  { variable: 'AGENTX_APP_HOST_SHA256', shell: 'AGENTX_AZURE_APP_HOST', what: 'app host' },
  { variable: 'AGENTX_OIDC_CLIENT_ID_SHA256', shell: 'AGENTX_AZURE_API_OIDC_CLIENT_ID', what: "API's client ID" },
] as const;

/**
 * Each pinned value the live settings carry, held to its pin exactly: a reason for each that isn't. A pin not set is
 * said in one line, not red: the value is then held to its shape alone. Neither the value nor its hash is printed.
 */
function unpinned(
  bound: ReadonlyMap<string, string>,
  pins: Readonly<Record<string, string | undefined>>,
  say: (line: string) => void,
): string[] {
  const unset = PINS.filter(({ variable }) => (pins[variable]?.trim() ?? '') === '');
  if (unset.length > 0) {
    say(
      `Not pinned (${unset.map(({ variable }) => variable).join(', ')} unset): the ${unset.map(({ what }) => what).join(', ')} held to shape alone. Nothing is wrong; set each as a staging secret to hold it exactly.`,
    );
  }
  return PINS.flatMap(({ variable, shell, what }) => {
    const pin = pins[variable]?.trim().toLowerCase() ?? '';
    if (pin === '') return [];
    if (!/^[0-9a-f]{64}$/.test(pin))
      return [`${variable} isn't a SHA-256 (64 hex), so the ${what} can't be checked: set it again`];
    const live = bound.get(`shell ${shell}`);
    if (live === undefined) return [`no setting carries the ${what}, which ${variable} pins`];
    return fingerprintOf(live.toLowerCase()) === pin
      ? []
      : [`api: the ${what} its settings carry isn't the one ${variable} pins`];
  });
}

async function plan(request: Request, steps: CheckSteps): Promise<Plan> {
  const subscription = signedIn(steps.az, steps.say);
  const image = `${IMAGE_REPOSITORY}@${request.digest}`;
  const reads = new Map(ORDER.map((workload) => [workload, readWorkload(steps.az, subscription, workload)] as const));
  const running = new Map([...reads].map(([workload, read]) => [workload, read.running] as const));
  for (const [workload, found] of running) steps.say(`${workload} runs ${found.release} (${found.image}).`);
  const api = running.get('api');
  if (api !== undefined && settingValue(api.container, 'AGENTX_ROLE') === 'web') {
    return { subscription, image, reads, running, decision: { kind: 'load-run' } };
  }
  const held = async (decided: Decision): Promise<Plan> => ({
    subscription,
    image,
    reads,
    running,
    decision: await heldToTemplates(decided, request.commit, subscription, reads, steps),
  });
  const first = decide(running, request.commit, image, steps.history);
  if (first.kind !== 'by-hand') return held(first);
  const readers = await readersAt(request.commit, steps);
  const records = recordsIn(reads.get('migrate')?.tags ?? {}, steps.say);
  steps.say(
    records.size === 0
      ? 'The migration job holds no hand deploy records.'
      : `The migration job records: ${[...records].map(([deployment, sent]) => deployment + ' sent ' + sent).join('; ')}.`,
  );
  return held(decide(running, request.commit, image, steps.history, readers, records));
}

/** What the records show deployed by hand, said before a release goes ahead. */
function sayDeployed(decision: Decision, say: (line: string) => void): void {
  if (decision.kind !== 'release' || decision.deployed.length === 0) return;
  say('Deployed by hand already, as the migration job records:');
  for (const line of decision.deployed) say(`  ${line}`);
}

/**
 * Why a release stops while the API runs as `web` copies (4D2e D13): that is a load run (apps --load-run), whose jobs
 * app a release can't move (CI's role is on the API and the migration job alone). Updating the copies would leave the
 * jobs on another build, and the prune could later remove the image they run. Read before anything is written.
 */
export const LOAD_RUN_UP =
  'A load run is up (the API runs as AGENTX_ROLE web, beside the jobs app): finish it (load.ts finish, then a plain apps), or run apps --load-run again after merging. This release changed nothing, red.';

/** A release outside the commit's history can't be checked against coming.json (decision 49), so the hand deploy is warned. */
export const OUTSIDE_HISTORY =
  'if this commit adds a migration with a trigger on a known table or a new guard function body, ship it in coming.json in a deploy first (decision 49)';

/** What to do when a migration wasn't shipped as coming first (decision 49): never the hand deploy a red usually asks. */
export const COMING_FIRST =
  "the image staging runs wasn't told what this release's migration adds. Release a commit carrying it in coming.json first, then this one; never a hand deploy, which goes round this check and raises the false tamper alarm it prevents (decision 49).";

/**
 * What a release says when a workload isn't as its commit's apps.bicep has it (AZ2c): what happened, what broke, what
 * next. A write with CI's sign-in leaves no request body in the activity log, so this is where such a change shows.
 */
export const NOT_AS_DEPLOYED =
  "the API or the migration job isn't as this commit's apps.bicep has it, beyond its image and build (what differs is below, by name, never by value). Someone changed it outside a deploy: with CI's sign-in, or by hand. What broke: nothing was released or changed, since a release copies each container and would carry that change forward, and run it. What next: find who changed it in the resource group's activity log and treat it as a suspected breach until shown otherwise (Incident-Response-Playbook section B); then deploy it by hand with apps after checking who changed it, which puts back what apps.bicep says.";

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
  if (decision.kind === 'load-run') {
    say(LOAD_RUN_UP);
    return 1;
  }
  if (decision.kind === 'coming-first') {
    say(`A release of ${commit} stops here, red: ${COMING_FIRST}`);
    for (const reason of decision.reasons) say(`  ${reason}`);
    return 1;
  }
  if (decision.kind === 'by-hand') {
    say(`A release of ${commit} stops here, red: this needs a hand deploy.`);
    for (const reason of decision.reasons) say(`  ${reason}`);
    return 1;
  }
  if (decision.kind === 'not-as-deployed') {
    say(`A release of ${commit} stops here, red: ${NOT_AS_DEPLOYED}`);
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

/** What running and waiting for the migration job needs: Azure, the clock, and somewhere to say what happens. */
type RunSteps = Pick<ReleaseSteps, 'az' | 'say' | 'now' | 'sleep'>;

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
  const value = settingValue(api.container, 'AGENTX_PUBLIC_ORIGIN');
  if (!/^https:\/\/[a-z0-9.-]+$/.test(value)) {
    throw new Error('The API names no https origin (AGENTX_PUBLIC_ORIGIN) to check it through once released.');
  }
  return value;
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
function update(steps: RunSteps, subscription: string, workload: Workload, seen: Running, after: Container): Read {
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
  // The API's update also sends an empty revision suffix (AZ7): a suffix set by hand would otherwise be sent again with
  // the containers and refused as taken, after the migration had run; empty lets Azure name the new revision itself.
  const template = workload === 'api' ? { revisionSuffix: '', containers: [after] } : { containers: [after] };
  const body = JSON.stringify({ properties: { template } });
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
  steps: RunSteps,
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

function runs(steps: RunSteps, subscription: string): Run[] {
  const listed = get(steps.az, jobUrl(subscription, '/executions'), "migrate's runs");
  if (!Array.isArray(listed.value)) throw new Error("Azure's list of migrate's runs wasn't a list.");
  return listed.value.map((entry) => {
    const found = record(entry);
    return { name: String(found.name), status: String(record(found.properties).status) };
  });
}

/** migrate's runs, once none is still going: two would race (apps.bicep). */
function idle(steps: RunSteps, subscription: string): Run[] {
  const listed = runs(steps, subscription);
  const going = listed.filter((run) => !ENDED.has(run.status));
  if (going.length > 0) {
    throw new Error(
      `migrate has runs that haven't ended (${going.map((run) => run.name + ' ' + run.status).join(', ')}).`,
    );
  }
  return listed;
}

/** Azure's own name for the new run, held to the job's runs (and to the name the start gave) before it goes into a URL. */
function checkStartedRun(listed: string, named: string | undefined): void {
  if (!isRunOf('migrate', listed) || (named !== undefined && named !== listed)) {
    const andStarted = named === undefined ? '' : ` and started "${named}"`;
    throw new Error(`Azure listed migrate's new run as "${listed}"${andStarted}, which isn't this release's run.`);
  }
}

/**
 * Starts the migration job as it is now deployed, with no template of its own
 * (a POST with no body), once none of its runs is still going. Azure may take
 * the start before it lists the run, or without naming it, so the run is the
 * one new run listed within LIST_WAIT_MS, and the one the start named if it
 * named one.
 */
async function startMigration(steps: RunSteps, subscription: string): Promise<string> {
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
      checkStartedRun(started.name, named);
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
  steps: RunSteps,
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
 * What a migration run ahead of a hand deploy needs (AZ6): a release's steps, less the image check and the door, and
 * what the hand deploy's checkout of the commit gives migrate (AZ2c).
 */
export type MigrateFirstSteps = RunSteps & Pick<ReleaseSteps, 'history'> & { readonly templates: Templates };

/**
 * The migration job's container as the hand deploy's commit gives it (AZ2c), with this image and build: never a copy
 * of the live one, which a write outside a deploy may have changed (its command, say), so a hand deploy never runs such
 * a change. Said when the live one differs beyond its image and build, by name alone: the hand deploy is the fix the
 * release asks for, and the difference is a suspected breach to look into.
 */
function templateMigrate(
  steps: MigrateFirstSteps,
  subscription: string,
  job: Read,
  image: string,
  commit: string,
): Container {
  const live = job.running;
  const template = steps.templates(subscription, commit).get('migrate');
  const containers = containersOf(template);
  const beyond = workloadDifferences(
    'jobs',
    template,
    { identity: job.identity, properties: job.properties },
    new Map(),
  );
  let after: Container | undefined;
  try {
    after = deployable(WORKLOADS.migrate.container, containers, image, commit);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    beyond.push(error.message);
  }
  // M3: --migrate-first sends the containers alone; anything else the commit's migrate needs only apps can send.
  if (beyond.length > 0 || after === undefined) {
    throw new Error(
      `migrate isn't as ${commit}'s apps.bicep has it beyond its containers (${beyond.join('; ')}), and --migrate-first sends its containers alone. If this commit adds a secret, mount or deploy-time setting to migrate: run apps --api-stopped first (Incident-Response-Playbook section L). If it doesn't, someone changed the job outside a deploy: treat it as a suspected breach (section B).`,
    );
  }
  const said = differences(expectedOf(containers), live.container, new Map());
  if (said.length > 0) {
    steps.say(
      `migrate isn't as ${commit}'s apps.bicep has it, beyond its image and build (${said.join('; ')}): it runs as apps.bicep says. If apps.bicep didn't change it since ${live.release}, someone changed it outside a deploy: treat it as a suspected breach (Incident-Response-Playbook section B).`,
    );
  }
  return after;
}

/**
 * `deploy.ts apps --migrate-first` (AZ6): a release's first half alone, for a hand deploy whose image brings
 * migrations the database lacks (S174: deployed together, the API started on the new image before them, refused at
 * start and raised a false tamper alarm). The migration job is updated to the image and run to success, as a release
 * does, but with its container as the commit's apps.bicep gives it (AZ2c), and the API is left as it is. Held, as a release is, to decision 49 against the build the API runs,
 * since it checks the database while the migration runs. The run's name once it has succeeded; otherwise an error
 * saying what it left, and the deployment isn't sent. The image was checked by the caller (verify.ts).
 */
export async function migrateFirst(
  steps: MigrateFirstSteps,
  subscription: string,
  commit: string,
  digest: string,
): Promise<string> {
  const image = `${IMAGE_REPOSITORY}@${digest}`;
  const job = readWorkload(steps.az, subscription, 'migrate');
  const apiRuns = readWorkload(steps.az, subscription, 'api').running.release;
  if (!steps.history.isAncestor(apiRuns, commit)) {
    throw new Error(
      `The API runs ${apiRuns}, which isn't in ${commit}'s history, so whether it knows what this image's migrations add can't be checked (decision 49): the migration wasn't run, and nothing was changed.`,
    );
  }
  const notComing = notYetComing(apiRuns, commit, steps.history.changedFiles(apiRuns, commit), steps.history);
  if (notComing.length > 0) {
    throw new Error(
      [
        `The migration wasn't run, and nothing was changed: ${COMING_FIRST}`,
        ...notComing.map((line) => `  ${line}`),
      ].join('\n'),
    );
  }
  const limit = await leaving('nothing was changed.', () => {
    settledBefore('migrate', job);
    idle(steps, subscription);
    return timeLimit(job);
  });
  const left = `the API is unchanged, on ${apiRuns}`;
  const after = await leaving('nothing was changed.', () => templateMigrate(steps, subscription, job, image, commit));
  await leaving(`migrate may hold ${commit}, not run; ${left}.`, async () => {
    update(steps, subscription, 'migrate', job.running, after);
    await settledUpdate(steps, subscription, 'migrate', after);
  });
  const name = await leaving(
    `migrate holds ${commit}, not run (a start that failed late may still have begun one: look at migrate's runs); ${left}.`,
    () => startMigration(steps, subscription),
  );
  const status = await leaving(`migrate holds ${commit}, its run ${name} not seen to end; ${left}.`, () =>
    ended(steps, subscription, name, image, limit),
  );
  if (status !== 'Succeeded') {
    throw new Error(
      `${name} ended ${status}, so nothing was deployed. Read its log: node deploy/azure/jobs.ts wait migrate ${name}\nLeft: migrate holds ${commit}; ${left}.`,
    );
  }
  steps.say(`${name} succeeded: the database holds every migration ${commit} brings.`);
  return name;
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

export function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => Az = realAz,
  history: () => History = realHistory,
  extras: () => Extras = realExtras,
  folder: () => Folder = realFolder,
  env: Readonly<Record<string, string | undefined>> = process.env,
): Promise<number> {
  return runCli(
    USAGE,
    say,
    () => parseArguments(argv),
    (request) => {
      const more = extras();
      const steps = {
        az: az(),
        history: history(),
        folder: folder(),
        say,
        verify: more.verify,
        pins: env,
        now: more.now,
        anchor: () => lastRelease(env),
      };
      return request.command === 'check' ? check(request, steps) : release(request, { ...steps, ...more });
    },
  );
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
