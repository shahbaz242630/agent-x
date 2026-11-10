// Watches every job's runs for containers other than the job's own (Carry-Forward
// S175). Whoever may start a Container Apps job may start it with its containers
// replaced: another command, arguments, image or settings, run with the job's
// secrets and identity (learn.microsoft.com/azure/container-apps/jobs,
// "Permissions"). Our own starts never do that but one: jobs.ts `cleanup` runs
// Zitadel's setup as `setup cleanup`, which is said here as the clean-up it is.
//
//   node deploy/azure/job-starts.ts [--hours 6]
//
// The activity log doesn't keep a start's body, but each run keeps the template
// it ran with. So this reads every job in staging's resource group and each run
// started in the last few hours, and compares the run's containers (and init
// containers) with the job's: image, command, arguments and settings (names and
// values; a secret by the name it refers to). Any difference is a finding: exit 1,
// which turns the scheduled workflow red and emails the repository's owner.
//
// **A known gap:** a run is compared with the job as it is now. A run started
// before the job last changed (every release, every operator run) that differs
// only as a release does (another digest of our own image, AGENTX_RELEASE's
// value) is listed NOT COMPARED, a warning on the workflow's page; any other
// difference stays a finding. So an override that changes only those, followed
// by a release, would pass as one: an older image of ours, and a release label.
// A start doesn't move the job's change time.
// Azure keeps a job's last 100 runs: a full list still inside the window, or a
// flood of runs, is a finding of its own. Nothing here stops a start: it only
// makes one seen.
//
// No setting's value is ever printed, nor a command or an argument: the
// workflow's log is public. Each finding names the run, and the partner reads
// the rest with `az containerapp job execution show`.
import { ARM, type Az, realAz, RESOURCE_GROUP, signedIn, text, UsageError } from './deploy.ts';
import { jobName, JOBS_API, runCli } from './jobs.ts';

/** How far back runs are read by default: twelve of the workflow's half-hourly runs, so a late cron or a short outage leaves no gap (a finding is then said more than once). */
export const DEFAULT_HOURS = 6;

/** The most hours asked for: a run older than Azure's own history isn't listed anyway. */
const MOST_HOURS = 24 * 7;

export const USAGE = `Usage:
  node deploy/azure/job-starts.ts [--hours <1-${String(MOST_HOURS)}>]
Reads every job's runs started in the last ${String(DEFAULT_HOURS)} hours (or as many as asked) and says any that ran other containers than its job's own.`;

/** One setting of a container: a name with a value or with a secret's name. */
interface Setting {
  readonly name: string;
  readonly value?: string;
  readonly secretRef?: string;
}

/** The fields of a container that a start may replace, and so are compared. */
interface Container {
  readonly name: string;
  readonly image: string;
  readonly command: readonly string[];
  readonly args: readonly string[];
  readonly env: readonly Setting[];
}

/** A template's containers and init containers, each by its name. */
interface Template {
  readonly containers: readonly Container[];
  readonly initContainers: readonly Container[];
}

export interface DeployedJob {
  readonly name: string;
  /** When the job last changed, in ms, or undefined when Azure didn't say. */
  readonly changedAt: number | undefined;
  readonly template: Template;
}

export interface Run {
  readonly name: string;
  readonly startedAt: number | undefined;
  readonly status: string;
  /** Undefined when Azure gave no template it can be read from. */
  readonly template: Template | undefined;
}

/** What one run turned out to be. */
export type Verdict =
  | { readonly kind: 'same' }
  | { readonly kind: 'clean-up' }
  | { readonly kind: 'not-comparable'; readonly differences: readonly string[] }
  | { readonly kind: 'changed'; readonly differences: readonly string[] };

/**
 * A time Azure gave, in ms. `systemData` writes UTC with no zone and seven
 * decimals (`2026-11-10T13:02:02.4268454`), which JavaScript would read as
 * local time, so a time with no zone is taken as UTC.
 */
export function azureTime(value: unknown): number | undefined {
  const written = text(value);
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.exec(written);
  if (match === null) return undefined;
  const [, seconds, fraction = '', zone = 'Z'] = match;
  const at = Date.parse(`${seconds ?? ''}${fraction.slice(0, 4)}${zone}`);
  return Number.isNaN(at) ? undefined : at;
}

const strings = (value: unknown): readonly string[] | undefined =>
  Array.isArray(value) && value.every((item) => typeof item === 'string') ? value : undefined;

/** A container as Azure gave it, or undefined for one that can't be read. A missing list is an empty one (a run omits empty `args`). */
function containerOf(value: unknown): Container | undefined {
  const found = (value ?? {}) as Record<string, unknown>;
  const command = strings(found.command ?? []);
  const args = strings(found.args ?? []);
  const env = found.env ?? [];
  if (typeof found.name !== 'string' || command === undefined || args === undefined || !Array.isArray(env)) {
    return undefined;
  }
  const settings = (env as readonly (Record<string, unknown> | null)[]).map((entry) => ({
    name: text(entry?.name),
    ...(typeof entry?.value === 'string' ? { value: entry.value } : {}),
    ...(typeof entry?.secretRef === 'string' ? { secretRef: entry.secretRef } : {}),
  }));
  return { name: found.name, image: text(found.image), command, args, env: settings };
}

/** A template's containers, or undefined when any of them can't be read. A job writes no init containers as null, a run as []. */
export function templateOf(value: unknown): Template | undefined {
  const found = (value ?? {}) as { containers?: unknown; initContainers?: unknown };
  const listOf = (part: unknown): readonly Container[] | undefined => {
    if (part === undefined || part === null) return [];
    if (!Array.isArray(part)) return undefined;
    const read = part.map(containerOf);
    return read.every((container) => container !== undefined) ? read : undefined;
  };
  const containers = listOf(found.containers);
  const initContainers = listOf(found.initContainers);
  if (containers === undefined || containers.length === 0 || initContainers === undefined) return undefined;
  return { containers, initContainers };
}

/**
 * A name from Azure as it is printed: anything but letters, digits, `_`, `.`
 * and `-` becomes `?`. A start's body chooses its containers' and settings'
 * names, and a line break in one could write a command into the workflow's log.
 */
const shown = (name: string): string => name.replace(/[^\w.-]/g, '?');

const sameList = (one: readonly string[], other: readonly string[]): boolean =>
  one.length === other.length && one.every((item, index) => item === other[index]);

/**
 * One way a run differs from its job, in plain words with no value. `routine`
 * when a release also makes it (RELEASE_SETTINGS' values, another digest of an
 * image of ours), so a run older than the job's last change may differ so
 * honestly; anything else no release does.
 */
export interface Difference {
  readonly text: string;
  readonly routine: boolean;
}

const unusual = (text: string): Difference => ({ text, routine: false });

/**
 * The settings whose values a release writes (apps.bicep `release`): every
 * other value is the same from one release to the next, so a run older than the
 * job's change that points the database, the keys or a URL elsewhere is a finding.
 */
const RELEASE_SETTINGS: ReadonlySet<string> = new Set(['AGENTX_RELEASE']);

/** Our own images, which a release moves to a new digest; a third party's (Zitadel's) changes only by hand. */
const OUR_REPOSITORIES: ReadonlySet<string> = new Set([
  'ghcr.io/shahbaz242630/agent-x',
  'ghcr.io/shahbaz242630/agent-x-load',
]);

/** An image named by digest, `<repository>@sha256:<64 hex>`: its repository, or undefined for any other form. */
const digestRepository = (image: string): string | undefined => /^([^@\s]+)@sha256:[0-9a-f]{64}$/.exec(image)?.[1];

/** Whether a run's other image is one a release makes: another digest of the same image of ours, nothing else. */
const releasedImage = (expected: string, ran: string): boolean => {
  const repository = digestRepository(expected);
  return repository !== undefined && OUR_REPOSITORIES.has(repository) && digestRepository(ran) === repository;
};

/** How one container's settings differ, by name alone: never a value. */
function settingDifferences(where: string, job: readonly Setting[], ran: readonly Setting[]): Difference[] {
  const found: Difference[] = [];
  const byName = (settings: readonly Setting[]): ReadonlyMap<string, Setting> =>
    new Map(settings.map((setting) => [setting.name, setting]));
  const own = byName(job);
  const run = byName(ran);
  for (const [name, setting] of run) {
    const expected = own.get(name);
    if (expected === undefined) found.push(unusual(`${where} had a setting the job doesn't: ${shown(name)}`));
    else if (
      expected.secretRef !== setting.secretRef ||
      (expected.value === undefined) !== (setting.value === undefined)
    ) {
      // Another secret, a value where the job reads a secret (or the other way), or neither: never a release's change.
      found.push(unusual(`${where}'s setting ${shown(name)} reads another secret, or none, than the job's`));
    } else if (expected.value !== setting.value) {
      const routine = RELEASE_SETTINGS.has(name);
      found.push({ text: `${where}'s setting ${shown(name)} differs from the job's`, routine });
    }
  }
  for (const name of own.keys()) {
    if (!run.has(name)) found.push(unusual(`${where} lacked the job's setting ${shown(name)}`));
  }
  // Two settings of one name: the later wins, so a repeat could hide a value.
  if (run.size !== ran.length) found.push(unusual(`${where} named a setting twice`));
  return found;
}

/** How one container a run ran differs from the job's container of its name. */
function sameNameDifferences(where: string, expected: Container, container: Container): Difference[] {
  const found: Difference[] = [];
  if (container.image !== expected.image) {
    const routine = releasedImage(expected.image, container.image);
    found.push({ text: `${where} ran another image${routine ? '' : ', not a release of the job’s own'}`, routine });
  }
  if (!sameList(container.command, expected.command)) found.push(unusual(`${where} ran another command`));
  if (!sameList(container.args, expected.args)) found.push(unusual(`${where} ran with other arguments`));
  return [...found, ...settingDifferences(where, expected.env, container.env)];
}

/** How one kind of container (`container` or `init container`) differs between the job and a run, in plain words, no values. */
function containerDifferences(kind: string, job: readonly Container[], ran: readonly Container[]): Difference[] {
  const found: Difference[] = [];
  const own = new Map(job.map((container) => [container.name, container]));
  for (const container of ran) {
    const where = `the ${kind} ${shown(container.name)}`;
    const expected = own.get(container.name);
    found.push(
      ...(expected === undefined
        ? [unusual(`it ran ${where}, which the job doesn't have`)]
        : sameNameDifferences(where, expected, container)),
    );
  }
  const names = new Set(ran.map((container) => container.name));
  for (const name of own.keys()) {
    if (!names.has(name)) found.push(unusual(`it didn't run the job's ${kind} ${shown(name)}`));
  }
  if (names.size !== ran.length) found.push(unusual(`it named a ${kind} twice`));
  return found;
}

/** Every way a run's template differs from its job's, or none. */
export function differences(job: Template, ran: Template): Difference[] {
  return [
    ...containerDifferences('container', job.containers, ran.containers),
    ...containerDifferences('init container', job.initContainers, ran.initContainers),
  ];
}

/** The arguments jobs.ts `cleanup` gives Zitadel's setup (its CLEANUP_ARGS): the one start of ours with other containers. */
const CLEANUP_ARGS = ['setup', 'cleanup'];

/** Whether a run is jobs.ts `cleanup`: Zitadel's setup job, its one container's arguments `setup cleanup`, nothing else changed. */
function isCleanUp(job: DeployedJob, run: Template): boolean {
  const [own] = job.template.containers;
  const [ran] = run.containers;
  if (job.name !== jobName('zitadel-setup') || own === undefined || ran === undefined) return false;
  return (
    run.containers.length === 1 &&
    sameList(ran.args, CLEANUP_ARGS) &&
    differences(job.template, { ...run, containers: [{ ...ran, args: own.args }] }).length === 0
  );
}

/** What one run was: as the job is, the clean-up, not comparable (started before the job changed), or changed. */
export function verdictOf(job: DeployedJob, run: Run): Verdict {
  if (run.template === undefined) {
    return {
      kind: 'changed',
      differences: ["Azure gave no containers for it that can be read, so it can't be checked"],
    };
  }
  const found = differences(job.template, run.template);
  if (found.length === 0) return { kind: 'same' };
  if (isCleanUp(job, run.template)) return { kind: 'clean-up' };
  // The job changes on every release and every operator run (its request is taken off), so a run older than that
  // change is let off only for what a deploy itself changes: an image of the same repository, a plain value. A
  // start doesn't move the job's own change time (read on staging, S183): an override shows in what it ran.
  const before = job.changedAt !== undefined && run.startedAt !== undefined && run.startedAt < job.changedAt;
  const texts = found.map((difference) => difference.text);
  const routine = found.every((difference) => difference.routine);
  return { kind: before && routine ? 'not-comparable' : 'changed', differences: texts };
}

/** A time as `YYYY-MM-DD HH:MM UTC`, or "an unknown time". */
const when = (ms: number | undefined): string =>
  ms === undefined ? 'an unknown time' : `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;

/** What the partner reads for each run that ran other containers. */
function findingLines(subscription: string, job: DeployedJob, run: Run, found: readonly string[]): string[] {
  return [
    `FOUND: ${run.name} (started ${when(run.startedAt)}, ${run.status || 'no state'}) did not run ${job.name} as it is deployed:`,
    ...found.map((difference) => `  - ${difference}`),
    '  What it means: someone who may start this job started it with its containers replaced, and so could have run anything with its secrets and its identity. Our own tools never do that.',
    `  What to do: treat it as a suspected breach (Incident-Response-Playbook section B; section T says how) until shown otherwise. See what ran: az containerapp job execution show --subscription ${subscription} --resource-group ${RESOURCE_GROUP} --name ${job.name} --job-execution-name ${run.name}`,
  ];
}

/** What the partner reads for a job whose run history can't be trusted whole. */
function historyLines(job: DeployedJob, problems: readonly string[]): string[] {
  return [
    `FOUND: ${job.name}'s runs can't all be checked:`,
    ...problems.map((problem) => `  - ${problem}`),
    '  What it means: a run with its containers changed could be among those not seen, or hidden by a flood of starts.',
    `  What to do: find who started it so often (the activity log, section T), then read its runs by hand (az containerapp job execution list --resource-group ${RESOURCE_GROUP} --name ${job.name}); treat it as section B until explained.`,
  ];
}

/** Azure's list, page by page: a page names the next with `nextLink`. */
function listAll(az: Az, what: string, url: string): unknown[] {
  const items: unknown[] = [];
  for (let next: string | undefined = url; next !== undefined && next !== '';) {
    const done = az.run(['rest', '--method', 'get', '--url', next, '--output', 'json']);
    if (done.status !== 0) {
      throw new Error(
        `Azure refused to list ${what}, so no run was checked and nothing is known about them. What to do: read Azure's words below; if it is the sign-in or the role, check the watch's repository secrets (AZURE_WATCH_CLIENT_ID and the other two) and its role on ${RESOURCE_GROUP}, then run the workflow again.\n${done.stderr.trim()}`,
      );
    }
    const page = JSON.parse(done.stdout) as { value?: unknown; nextLink?: unknown } | null;
    if (!Array.isArray(page?.value)) throw new Error(`Azure's list of ${what} wasn't a list, so no run was checked.`);
    items.push(...(page.value as unknown[]));
    // Only a link back to Resource Manager is followed: the token goes wherever the URL points.
    next = typeof page.nextLink === 'string' && page.nextLink.startsWith(ARM) ? page.nextLink : undefined;
  }
  return items;
}

const jobsUrl = (subscription: string): string =>
  `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.App/jobs`;

/** Every job in the resource group, with its template and when it last changed. */
export function deployedJobs(az: Az, subscription: string): DeployedJob[] {
  return listAll(az, `the jobs in ${RESOURCE_GROUP}`, `${jobsUrl(subscription)}?api-version=${JOBS_API}`).map(
    (item) => {
      const job = item as {
        name?: unknown;
        systemData?: { lastModifiedAt?: unknown };
        properties?: { template?: unknown };
      };
      const name = text(job.name);
      const template = templateOf(job.properties?.template);
      if (!/^[a-z0-9-]+$/.test(name) || template === undefined) {
        throw new Error(`Azure listed a job "${name}" whose containers can't be read, so no run of it can be checked.`);
      }
      return { name, changedAt: azureTime(job.systemData?.lastModifiedAt), template };
    },
  );
}

/** Every run of a job Azure lists, newest first as it gives them. */
export function listedRuns(az: Az, subscription: string, job: string): Run[] {
  return listAll(az, `${job}'s runs`, `${jobsUrl(subscription)}/${job}/executions?api-version=${JOBS_API}`).map(
    (item) => {
      const run = item as {
        name?: unknown;
        properties?: { startTime?: unknown; status?: unknown; template?: unknown };
      };
      return {
        name: shown(text(run.name)),
        startedAt: azureTime(run.properties?.startTime),
        status: text(run.properties?.status),
        template: templateOf(run.properties?.template),
      };
    },
  );
}

/** A run started at or after `since` (ms); one with no start time counts, since its age is unknown. */
const inWindow = (run: Run, since: number): boolean => run.startedAt === undefined || run.startedAt >= since;

/**
 * How many runs a job's history keeps: "the most recent 100" (learn.microsoft.com
 * /azure/container-apps/jobs, "Get job execution history"; staging's migration
 * job lists exactly 100). A list that full whose oldest run is still in the
 * window may have lost runs off its end, which are then never compared.
 */
export const HISTORY_KEPT = 100;

/** More runs of one job than this per three hours is a finding of its own: a flood could push an override off the history. */
const BUSY_PER_THREE_HOURS = 20;

/** Why a job's runs in the window can't be taken as all of them or as ordinary, a line each, or none. */
export function historyProblems(listed: readonly Run[], since: number, hours: number): string[] {
  const problems: string[] = [];
  const recent = listed.filter((run) => inWindow(run, since)).length;
  // The earliest start listed, in whatever order Azure lists them: before the window, and the window is whole.
  const reachesBack = listed.some((run) => run.startedAt !== undefined && run.startedAt < since);
  if (listed.length >= HISTORY_KEPT && !reachesBack) {
    problems.push(
      `the run history may be incomplete: Azure keeps ${String(HISTORY_KEPT)} runs, and all ${String(recent)} listed started in the window, so older runs in it may be gone unchecked`,
    );
  }
  const most = Math.ceil((hours * BUSY_PER_THREE_HOURS) / 3);
  if (recent > most) {
    problems.push(`it ran ${String(recent)} times in ${String(hours)} h, more than the ${String(most)} ever expected`);
  }
  return problems;
}

/** How many hours back to read, or a UsageError. */
export function parseArguments(argv: readonly string[]): number {
  if (argv.length === 0) return DEFAULT_HOURS;
  const [flag, value, ...rest] = argv;
  const hours = Number(value);
  if (flag !== '--hours' || rest.length > 0 || !/^\d+$/.test(value ?? '') || hours < 1 || hours > MOST_HOURS) {
    throw new UsageError(
      `say nothing, or --hours and a whole number from 1 to ${String(MOST_HOURS)}, not ${argv.join(' ')}`,
    );
  }
  return hours;
}

export interface WatchSteps {
  readonly az: Az;
  readonly say: (line: string) => void;
  readonly now: () => Date;
}

/** Reads every job's recent runs and says each that ran other containers: 1 when any did, else 0. */
export function watch(hours: number, steps: WatchSteps): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  const since = steps.now().getTime() - hours * 3_600_000;
  const jobs = deployedJobs(steps.az, subscription);
  steps.say(
    `Reading the runs of ${String(jobs.length)} jobs started since ${when(since)} (the last ${String(hours)} h).`,
  );
  const found: string[] = [];
  for (const job of jobs) {
    const listed = listedRuns(steps.az, subscription, job.name);
    const problems = historyProblems(listed, since, hours);
    if (problems.length > 0) found.push(...historyLines(job, problems));
    for (const run of listed.filter((each) => inWindow(each, since))) {
      const verdict = verdictOf(job, run);
      switch (verdict.kind) {
        case 'same':
          steps.say(`${run.name} (started ${when(run.startedAt)}): ran the job as it is deployed.`);
          break;
        case 'clean-up':
          steps.say(
            `${run.name} (started ${when(run.startedAt)}): Zitadel's stuck-step clean-up (node deploy/azure/jobs.ts cleanup), its one known change. If nobody ran it then, treat it as a finding.`,
          );
          break;
        case 'not-comparable':
          // A warning GitHub shows on the run's page, so it isn't lost in a green run's log.
          steps.say(
            `::warning::${run.name} (started ${when(run.startedAt)}): NOT COMPARED. It started before ${job.name} last changed (${when(job.changedAt)}), and differs from the job as it is now only as a release does (${verdict.differences.join('; ')}). Check it by hand if nothing was released then.`,
          );
          break;
        case 'changed':
          found.push(...findingLines(subscription, job, run, verdict.differences));
      }
    }
  }
  if (found.length === 0) {
    steps.say(`No run started since ${when(since)} ran other containers than its job's own.`);
    return Promise.resolve(0);
  }
  for (const line of found) steps.say(line);
  return Promise.resolve(1);
}

export function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => Az = realAz,
  now: () => Date = () => new Date(),
): Promise<number> {
  return runCli(
    USAGE,
    say,
    () => parseArguments(argv),
    (hours) => watch(hours, { az: az(), say, now }),
  );
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
