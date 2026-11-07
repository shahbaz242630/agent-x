/**
 * Stage G's jobs on Azure (4D2e, PL-62, PL-63), run by the load image inside
 * staging's network, only ever against the throwaway copy (throwaway.ts),
 * never staging's own database. Three parts, each its own job (apps.bicep):
 *
 *   node tooling/load/stageg-job.ts mark    load-mark, as the copy's owner: writes the copy's sentinel
 *   node tooling/load/stageg-job.ts step    load-step, as the app with its keys: `seed --to <orgs>` or `step <STEP json>`
 *   node tooling/load/stageg-job.ts check   load-check, as the app and the backup role: `check <STEP json> <CHECKED json>`
 *
 * The step and check parts read their command from the run's request, held as
 * the other load jobs' is (job.ts `requestOf`): `{"runId": "...", "command":
 * [words]}`. It never carries an agent: the cohort is read from the copy by
 * the seed's own IDs (stageg-seed.ts), and only its keys are made.
 *
 * Every part refuses before it changes anything unless its host is a throwaway
 * copy's by name; the step and check parts also unless that database carries
 * the sentinel naming the same copy, which only `mark` writes. Staging has none,
 * so a job pointed at it fails closed. A step also refuses unless every
 * hand-off is paused, as the PL-38 jobs do (job.ts), so no request reaches the bank.
 *
 * The checks read every organisation as the backup role (stageg-checks.ts),
 * which the API's identity can't read: so they are a job of their own, as the
 * set-up job's identity, given the app's and the backup role's logins alone.
 * Lines are JSON on stdout, for Log Analytics and the runner; never a key.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { createDatabase, type Database } from '../../packages/platform/src/db/index.ts';
import { API_PURPOSES, type KeyProvider, loadKeys, OPERATOR_ONLY } from '../../packages/platform/src/keys/index.ts';
import { createStartupLogger, type Logger } from '../../packages/platform/src/observability/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import { jobConnection, k6Ran, type LoadTables, pauseOutcome, type PrintedLine, withSeedFile } from './job.ts';
import { loadConnection, type Seeded } from './plan.ts';
import { rekeyed } from './seed.ts';
import { type StageGCheckedStep, stageGChecks } from './stageg-checks.ts';
import { stageGCohort, stageGSeed, stageGSeedWorkers } from './stageg-seed.ts';
import { STAGE_G_TESTS, type StepRun } from './stageg.ts';
import { whileStuck } from './stuck.ts';
import {
  markThrowaway,
  POSTGRES_HOST_SUFFIX,
  sentinelProblem,
  THROWAWAY_NAME_RULE,
  throwawayServerOfHost,
} from './throwaway.ts';

const STAGE_G_PARTS = ['mark', 'step', 'check'] as const;
export type StageGPart = (typeof STAGE_G_PARTS)[number];

/** A refusal in the job's own words: it has changed nothing. */
export class StageGRefused extends Error {}

/** The roles each part logs in as, fixed here: no setting can make the app's job the owner. */
const ROLES = { owner: 'agentx_owner', app: 'agentx_app', backup: 'agentx_backup' } as const;

/** Where each part finds the app's login: load-check holds the backup role's too, so it names the app's apart. */
const APP_LOGIN_FILE = { step: 'AGENTX_DB_PASSWORD_FILE', check: 'AGENTX_DB_APP_PASSWORD_FILE' } as const;

/** The most organisations a seed may ask for: three times past10k's, a typo's guard rather than a plan. */
const MOST_ORGS = 100_000;

/** A step's label as stageg.ts makes them: it names the step's orders (`G-<label>-...`), which the checks read back. */
const LABEL = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export type StageGCommand =
  | { readonly kind: 'seed'; readonly orgs: number }
  | { readonly kind: 'pause' }
  | { readonly kind: 'step'; readonly step: StepRun }
  | { readonly kind: 'check'; readonly step: StepRun; readonly checked: StageGCheckedStep };

/** What the run hands a part: its ID and the command's words. */
export interface StageGRequest {
  readonly runId: string;
  readonly command: readonly string[];
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function parsed(text: string, what: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new StageGRefused(`${what} is not JSON.`);
  }
}

/** The run's request, or a refusal saying what is wrong with it. */
export function stageGRequestOf(text: string): StageGRequest {
  const request = parsed(text, 'The run request');
  const fields = isObject(request) ? Object.keys(request).toSorted() : [];
  const { runId, command } = isObject(request) ? request : {};
  if (
    fields.join() !== 'command,runId' ||
    typeof runId !== 'string' ||
    runId === '' ||
    !Array.isArray(command) ||
    command.length === 0 ||
    !command.every((word) => typeof word === 'string')
  ) {
    throw new StageGRefused(
      'The run request must be {"runId": "<the run>", "command": [<its words>]} and nothing else: ask the runner (deploy/azure/stage-g.ts).',
    );
  }
  return { runId, command };
}

const wholeIn = (value: unknown, least: number, most: number): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= least && value <= most;

/** The step as the runner hands it (stageg.ts stepRun): the fields this job reads checked, the rest k6's (plain.k6.js readStep). */
export function stepOf(text: string): StepRun {
  const step = parsed(text, 'The step');
  if (
    !isObject(step) ||
    !(STAGE_G_TESTS as readonly unknown[]).includes(step.test) ||
    typeof step.label !== 'string' ||
    !LABEL.test(step.label) ||
    !wholeIn(step.orgs, 1, MOST_ORGS) ||
    (step.mix !== 'steady' && step.mix !== 'neighbours')
  ) {
    throw new StageGRefused(
      "The step must be one of stageg.ts's steps as stepRun makes it: a known test, a label of lower-case words, its organisations and its mix.",
    );
  }
  return step as unknown as StepRun;
}

const isTime = (value: unknown): value is string => typeof value === 'string' && !Number.isNaN(Date.parse(value));

/** What a step's summary and the run say about it, for the checks: its new requests, when it ran, when the run began. */
export function checkedOf(text: string, label: string): StageGCheckedStep {
  const checked = parsed(text, 'The step’s numbers');
  if (
    !isObject(checked) ||
    !wholeIn(checked.created, 0, Number.MAX_SAFE_INTEGER) ||
    !isTime(checked.startedAt) ||
    !isTime(checked.endedAt) ||
    !isTime(checked.since)
  ) {
    throw new StageGRefused(
      "The step's numbers must be {created, startedAt, endedAt, since}: its count of new requests, as load.stageg_summary gave them, and when the run's first step began.",
    );
  }
  return {
    label,
    created: checked.created,
    startedAt: checked.startedAt,
    endedAt: checked.endedAt,
    since: checked.since,
  };
}

/** The command a part's request asks, or a refusal: `step` takes seed and step, `check` takes check. */
export function commandOf(words: readonly string[], part: 'step' | 'check'): StageGCommand {
  const [first, ...rest] = words;
  if (part === 'step' && first === 'seed' && rest.length === 2 && rest[0] === '--to') {
    const orgs = Number(rest[1]);
    if (/^\d+$/.test(rest[1] ?? '') && wholeIn(orgs, 1, MOST_ORGS)) return { kind: 'seed', orgs };
  }
  if (part === 'step' && first === 'pause' && rest.length === 0) return { kind: 'pause' };
  if (part === 'step' && first === 'step' && rest.length === 1) return { kind: 'step', step: stepOf(rest[0] ?? '') };
  if (part === 'check' && first === 'check' && rest.length === 2) {
    const step = stepOf(rest[0] ?? '');
    return { kind: 'check', step, checked: checkedOf(rest[1] ?? '', step.label) };
  }
  throw new StageGRefused(
    part === 'step'
      ? `load-step takes pause, seed --to <1 to ${String(MOST_ORGS)} organisations> or step <STEP json>, not ${words.join(' ')}.`
      : `load-check takes check <STEP json> <CHECKED json>, not ${words.join(' ')}.`,
  );
}

/** The copy the job's host names, or a refusal before anything is reached: staging's own host is never one. */
export function copyOf(host: string): string {
  const server = throwawayServerOfHost(host);
  if (server === undefined) {
    throw new StageGRefused(
      `AGENTX_LOAD_DB_HOST is ${host}, not a throwaway copy's host (${THROWAWAY_NAME_RULE}${POSTGRES_HOST_SUFFIX}): Stage G never runs on staging's own database. Nothing was changed.`,
    );
  }
  return server;
}

/** Refuses, changing nothing, unless the database reached carries the sentinel naming this copy. */
async function onTheCopy(database: Database<LoadTables>, server: string): Promise<void> {
  const problem = await sentinelProblem(database, server);
  if (problem !== undefined) throw new StageGRefused(problem);
}

/** What a job reaches the world through: tests put stand-ins here. */
export interface StageGMakers {
  /** A connection to the job's host as `user`, at most the job's connections (job.ts JOB_CONNECTIONS). */
  readonly connect: (host: string, user: string, password: string) => Database<LoadTables>;
  readonly keyring: (directory: string) => KeyProvider;
  /** k6 for one step against the API, the cohort's keys in a file: true when it ran to the end. */
  readonly k6: (api: string) => (step: StepRun, seeded: Seeded) => Promise<boolean>;
  readonly print: (line: PrintedLine) => void;
  /** The long chain's refreshes: stageg-seed.ts's own unless a test asks for fewer. */
  readonly hugeChainEvents?: number;
}

/** Where the k6 script is, in the image as in the repository. */
const STAGE_G_SCRIPT = fileURLToPath(new URL('./stage-g.k6.js', import.meta.url));

/** k6 for one step: `k6` is the command and its first arguments, tests put a stand-in there. */
export const stageGK6 =
  (k6: readonly [string, ...string[]] = ['k6']) =>
  (api: string) =>
  (step: StepRun, seeded: Seeded): Promise<boolean> =>
    withSeedFile(
      seeded,
      (_dir, seed) => k6Ran(k6, STAGE_G_SCRIPT, { STEP: JSON.stringify(step), SEED: seed, API: api }),
      'agentx-stageg-k6-',
    );

const REAL: StageGMakers = {
  connect: (host, user, password) =>
    createDatabase<LoadTables>(
      jobConnection({ ...loadConnection({ AGENTX_LOAD_DB_HOST: host, AGENTX_LOAD_DB_PASSWORD: password }), user }),
      testLogger(),
    ),
  keyring: (directory) => loadKeys({ directory, current: {} }, API_PURPOSES, OPERATOR_ONLY),
  k6: stageGK6(),
  print: (line) => {
    console.log(JSON.stringify(line));
  },
};

/** A setting the job can't run without. */
function needed(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') throw new StageGRefused(`${name} is not set.`);
  return value;
}

const passwordIn = (env: NodeJS.ProcessEnv, name: string): string => readFileSync(needed(env, name), 'utf8').trim();

/** Opens a connection, runs `work` with it, and closes it whatever `work` does. */
async function using<T>(database: Database<LoadTables>, work: (database: Database<LoadTables>) => Promise<T>) {
  try {
    return await work(database);
  } finally {
    await database.destroy();
  }
}

/** load-mark: the sentinel written into the copy as its owner, then read back. */
function markPart(env: NodeJS.ProcessEnv, host: string, server: string, make: StageGMakers): Promise<number> {
  return using(make.connect(host, ROLES.owner, passwordIn(env, 'AGENTX_DB_PASSWORD_FILE')), async (owner) => {
    const problem = await markThrowaway(owner, server);
    if (problem !== undefined) throw new StageGRefused(problem);
    make.print({ event: 'load.stageg_marked', server });
    return 0;
  });
}

interface Context {
  readonly env: NodeJS.ProcessEnv;
  readonly runId: string;
  readonly make: StageGMakers;
}

/** load-step's seed: the run's organisations grown to `orgs`, those there found, timed by kind (stageg-seed.ts). */
async function seedCommand(app: Database<LoadTables>, { env, runId, make }: Context, orgs: number): Promise<number> {
  const keyring = make.keyring(needed(env, 'AGENTX_KEYS_DIR'));
  const workers = stageGSeedWorkers();
  const { hugeChainEvents } = make;
  const seeded = await stageGSeed({
    database: app,
    keyring,
    runId,
    orgs,
    workers,
    ...(hugeChainEvents === undefined ? {} : { hugeChainEvents }),
  });
  make.print({ event: 'load.stageg_seeded', runId, ...seeded });
  return 0;
}

/**
 * What to do about a copy whose hand-offs aren't paused: the copy is a restore,
 * so its pause is staging's at the moment it was made, and the operator's
 * handoff-pause moves staging's alone, never the copy's.
 */
const PAUSE_ON_STAGING_FIRST =
  'hand-offs must be paused on staging BEFORE stage-g.ts create, so the copy inherits the pause; a copy made unpaused must be deleted and made again';

/** Why the copy's hand-offs refuse a step, or undefined while they are paused. */
async function notPausedOnCopy(app: Database<LoadTables>, keyring: KeyProvider, when: string) {
  const outcome = await pauseOutcome(app, keyring);
  return outcome === 'paused'
    ? undefined
    : `the copy's hand-offs are ${outcome} ${when}, not paused: ${PAUSE_ON_STAGING_FIRST}`;
}

/**
 * load-step's pause: the copy's hand-off pause, read as the step reads it, for
 * the runner to check right after the copy is made, before any seed (a copy
 * holds staging's pause from its restore point, the one that counts). 0 when paused.
 */
async function pauseCommand(app: Database<LoadTables>, { env, runId, make }: Context): Promise<number> {
  const outcome = await pauseOutcome(app, make.keyring(needed(env, 'AGENTX_KEYS_DIR')));
  make.print({
    event: 'load.stageg_pause',
    runId,
    outcome,
    ...(outcome === 'paused' ? {} : { next: PAUSE_ON_STAGING_FIRST }),
  });
  return outcome === 'paused' ? 0 : 1;
}

/**
 * load-step's step, while every hand-off is paused: the cohort read from the
 * copy, new keys for its agents alone, k6 (the stuck organisation's suppliers
 * held locked for a neighbours step, stuck.ts). 0 when k6 ran to the end and
 * hand-offs stayed paused; its numbers are k6's own line, load.stageg_summary.
 */
async function stepCommand(app: Database<LoadTables>, { env, runId, make }: Context, step: StepRun): Promise<number> {
  const keyring = make.keyring(needed(env, 'AGENTX_KEYS_DIR'));
  const send = make.k6(needed(env, 'AGENTX_LOAD_API'));
  const before = await notPausedOnCopy(app, keyring, 'before the step');
  if (before !== undefined) throw new StageGRefused(`Nothing was changed: ${before}.`);
  const cohort = await stageGCohort({ database: app, runId, orgs: step.orgs, mix: step.mix });
  const keyed = await rekeyed(app, keyring, { agents: cohort });
  const run = () => send(step, keyed);
  const finished = step.mix === 'neighbours' ? await whileStuck(app, keyed.agents, run) : await run();
  const after = await notPausedOnCopy(app, keyring, 'after the step');
  make.print({
    event: 'load.stageg_stepped',
    runId,
    test: step.test,
    label: step.label,
    cohort: cohort.length,
    finished,
    ...(after === undefined ? {} : { notPaused: after }),
  });
  return finished && after === undefined ? 0 : 1;
}

/** load-check: every Stage G check of the step, the set-based ones as the backup role (stageg-checks.ts). 0 when all held. */
async function checkCommand(
  app: Database<LoadTables>,
  { env, runId, make }: Context,
  host: string,
  { step, checked }: Extract<StageGCommand, { kind: 'check' }>,
): Promise<number> {
  const cohort = await stageGCohort({ database: app, runId, orgs: step.orgs, mix: step.mix });
  const backup = make.connect(host, ROLES.backup, passwordIn(env, 'AGENTX_DB_BACKUP_PASSWORD_FILE'));
  const checks = await using(backup, (everyOrganisation) => stageGChecks({ everyOrganisation, app }, checked, cohort));
  make.print({ event: 'load.stageg_checked', runId, test: step.test, label: step.label, checks });
  return checks.every(({ failures }) => failures.length === 0) ? 0 : 1;
}

/** The part asked on the command line, or a refusal. */
export function partOf(argv: readonly string[]): StageGPart {
  const [part, ...rest] = argv;
  if (!(STAGE_G_PARTS as readonly unknown[]).includes(part) || rest.length > 0) {
    throw new StageGRefused(`Run it as node tooling/load/stageg-job.ts <${STAGE_G_PARTS.join('|')}>.`);
  }
  return part as StageGPart;
}

/** The job's command line and settings, run: the host and then the sentinel checked before anything else. */
export async function main(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  make: StageGMakers = REAL,
): Promise<number> {
  const part = partOf(argv);
  const host = needed(env, 'AGENTX_LOAD_DB_HOST');
  const server = copyOf(host);
  if (part === 'mark') return markPart(env, host, server, make);
  const request = stageGRequestOf(readFileSync(needed(env, 'AGENTX_LOAD_REQUEST_FILE'), 'utf8'));
  const command = commandOf(request.command, part);
  const context: Context = { env, runId: request.runId, make };
  return using(make.connect(host, ROLES.app, passwordIn(env, APP_LOGIN_FILE[part])), async (app) => {
    await onTheCopy(app, server);
    switch (command.kind) {
      case 'seed':
        return seedCommand(app, context, command.orgs);
      case 'pause':
        return pauseCommand(app, context);
      case 'step':
        return stepCommand(app, context, command.step);
      case 'check':
        return checkCommand(app, context, host, command);
    }
  });
}

/** Runs the job: a refusal logged in plain words (`load.stageg_refused`) and 1; anything else thrown as it is. */
export async function run(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  make: StageGMakers = REAL,
  logger: Logger = createStartupLogger({ service: 'load' }),
): Promise<number> {
  try {
    return await main(argv, env, make);
  } catch (error) {
    if (!(error instanceof StageGRefused)) throw error;
    logger.error('load.stageg_refused', { reason: error.message });
    return 1;
  }
}

if (import.meta.main) process.exitCode = await run(process.argv.slice(2));
