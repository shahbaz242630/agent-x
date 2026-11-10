// Stage G's runner (4D2e, PL-62, PL-63), from the partner's own terminal, as
// load.ts is for PL-38:
//
//   node deploy/azure/stage-g.ts create                    the throwaway copy of staging's database, then its mark
//   node deploy/azure/stage-g.ts run <test> [--from <step>] one test of stageg.ts, step by step, to its report
//   node deploy/azure/stage-g.ts status                    the copy, the jobs, the last step and its verdict
//   node deploy/azure/stage-g.ts delete [<copy>]           the copy removed, the load jobs with it
//   node deploy/azure/stage-g.ts delete --anchors          the copies' anchors containers, once their time is up
//
// `create` restores staging's server to psql-agentx-stg-g-<id> in its subnet
// and private zone (playbook L's drill, under Stage G's name), sizes it for the
// load run, tells the partner the apps line that points the API, its jobs app
// and the load jobs at it, and once those are deployed runs load-mark, which
// writes the copy's sentinel (tooling/load/throwaway.ts). A `create` stopped
// part-way is run again and carries on from where it was.
//
// `run` takes each step of the test's profile in turn: grows the seed to the
// step's organisations (load-step `seed --to N`, run again while a run ends
// before it is done), runs the step (load-step `step`), checks the copy
// (load-check), reads the step's lines from the workspace (4 to 9 minutes late)
// and judges it (stageg-report.ts). A step not judged yet is read again a while,
// then said so and left, never called failed; a failed step stops the climb
// (research S175: fix, re-run that step with --from). What each step found is
// kept in tooling/load/.out/stage-g.json with the copy, so a resumed climb's
// report still holds the steps before it, and the overload is sized from the
// breaking test's rate, the neighbours compared with the target's p95.
import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { backgroundHealth, type StepWindow } from '../../tooling/load/stageg-background.ts';
import type { StageGCheckResult } from '../../tooling/load/stageg-checks.ts';
import {
  renderStageG,
  judgeStageGStep,
  type StageGReportInput,
  type StageGStepResult,
  type StageGSummary,
  type StepJudgement,
} from '../../tooling/load/stageg-report.ts';
import { stageGKindAt, stageGOrgId } from '../../tooling/load/stageg-seed.ts';
import { baseHoldWindow } from '../../tooling/load/stageg-surge.ts';
import {
  breakingRate,
  type Profile,
  STAGE_G_TESTS,
  type StageGTest,
  stageGProfile,
  type StepRun,
  stepRun,
} from '../../tooling/load/stageg.ts';
import {
  throwawayAnchorsContainer,
  throwawayHost,
  throwawayIdOf,
  throwawayServerProblem,
} from '../../tooling/load/throwaway.ts';
import { type Az, realAz, text } from './deploy.ts';
import { reason } from './held-request.ts';
import { type JobSteps, POLL_MS, runCli, STAGE_G_JOBS, type StageGJob, UsageError } from './jobs.ts';
import { load } from './load.ts';
import { endedAs, type JobRun, lineOf, type Printed } from './load-jobs.ts';
import { evidenceAccountOf, LOAD_SKU, realStageGAzure, type StageGAzure } from './stage-g-azure.ts';
import { LOAD_SERVER_CONNECTIONS } from './policy.ts';
import { record } from './release.ts';

const USAGE = `Usage, from your own terminal window:
  node deploy/azure/stage-g.ts create                     make Stage G's copy of staging's database (pause staging's hand-offs first)
  node deploy/azure/stage-g.ts run <test> [--from <step>]  run one test step by step: ${STAGE_G_TESTS.join(', ')}
  node deploy/azure/stage-g.ts status                     the copy, the jobs, the last step and its verdict
  node deploy/azure/stage-g.ts delete [<copy>]            remove the copy and the load jobs
  node deploy/azure/stage-g.ts delete --anchors           remove old copies' anchors containers once their time is up`;

export type Request =
  | { readonly command: 'create' | 'status' }
  | { readonly command: 'run'; readonly test: StageGTest; readonly from?: string }
  | { readonly command: 'delete'; readonly name?: string }
  | { readonly command: 'anchors' };

function parseRun(rest: readonly string[]): Request {
  const [test, flag, label, ...extra] = rest;
  if (!(STAGE_G_TESTS as readonly (string | undefined)[]).includes(test)) {
    throw new UsageError(`run takes one of the tests (${STAGE_G_TESTS.join(', ')}), not ${test ?? 'nothing'}`);
  }
  if (flag === undefined) return { command: 'run', test: test as StageGTest };
  if (flag !== '--from' || label === undefined || extra.length > 0) {
    throw new UsageError(`run ${String(test)} takes only --from <step>, not ${rest.slice(1).join(' ')}`);
  }
  return { command: 'run', test: test as StageGTest, from: label };
}

function parseDelete(rest: readonly string[]): Request {
  const [named] = rest;
  if (named === undefined) return { command: 'delete' };
  if (rest.length === 1 && named === '--anchors') return { command: 'anchors' };
  if (rest.length === 1 && !named.startsWith('-')) return { command: 'delete', name: named };
  throw new UsageError(`delete takes the copy's name or --anchors, not ${rest.join(' ')}`);
}

export function parseArguments(argv: readonly string[]): Request {
  const [command, ...rest] = argv;
  if (command === 'create' || command === 'status') {
    if (rest.length > 0) throw new UsageError(`${command} takes nothing, not ${rest.join(' ')}`);
    return { command };
  }
  if (command === 'run') return parseRun(rest);
  if (command === 'delete') return parseDelete(rest);
  throw new UsageError(`say create, run, status or delete, not ${command ?? 'nothing'}`);
}

/** What the runner needs from this machine and the world; tests give their own. */
export interface StageGSteps extends JobSteps {
  readonly azure: StageGAzure;
  /** tooling/load/.out/stage-g.json: the copy and what its steps found. */
  readonly stateFile: string;
  readonly reportsDir: string;
  /** The Documents folder a report is copied to, only when it exists. */
  readonly copyDir: string;
  readonly randomId: () => string;
  /** load.ts finish: the load jobs (Stage G's among them) removed, any PL-38 run left open cleaned up first. */
  readonly finishLoad: () => Promise<number>;
}

/** One thing the runner itself found about a step (a job's end, a segment re-run), said in the report. */
interface Note {
  readonly label: string;
  readonly note: string;
}

interface TestRecord {
  readonly results: readonly StageGStepResult[];
  readonly notes: readonly Note[];
}

interface LastStep {
  readonly test: StageGTest;
  readonly label: string;
  readonly verdict: StepJudgement['state'] | 'stopped';
  readonly at: string;
}

/** The copy as the runner keeps it, from the restore's start to its removal. */
interface Copy {
  readonly server: string;
  readonly id: string;
  /** The seed's run ID: the same for every step on the copy, so the seed grows one set (stageg-seed.ts). */
  readonly runId: string;
  readonly createdAt: string;
  readonly sized: boolean;
  readonly marked: boolean;
  /** The copy's own hand-off pause read (load-step pause): a copy holds staging's from its restore point. */
  readonly paused: boolean;
  readonly seededTo: number;
  readonly incomplete: readonly number[];
  /** When the copy's first step began: an integrity hold since then fails any step's checks. */
  readonly since?: string;
  readonly breakingRate?: number;
  /** Zone-redundant high availability asked on the copy (the ha test), until a later test turns it off. */
  readonly ha?: boolean;
  readonly targetP95Ms?: number;
  readonly tests: Partial<Record<StageGTest, TestRecord>>;
  readonly last?: LastStep;
}

/** A copy's anchors container, kept until its files' time is up (apps.bicep: write-once, 3 days). */
interface Anchors {
  readonly container: string;
  readonly server: string;
  readonly lockedUntil: string;
}

interface State {
  readonly copy?: Copy;
  readonly anchors: readonly Anchors[];
}

const readState = (steps: StageGSteps): State =>
  existsSync(steps.stateFile) ? (JSON.parse(readFileSync(steps.stateFile, 'utf8')) as State) : { anchors: [] };

function keep(steps: StageGSteps, state: State): void {
  mkdirSync(path.dirname(steps.stateFile), { recursive: true });
  writeFileSync(steps.stateFile, `${JSON.stringify(state, null, 2)}\n`);
}

/** The copy kept, changed, and saved at once: a runner stopped any moment loses nothing it learned. */
function keepCopy(steps: StageGSteps, change: Partial<Copy>): Copy {
  const copy = { ...currentCopy(steps), ...change };
  keep(steps, { ...readState(steps), copy });
  return copy;
}

/** The copy kept, which the runner is working on: its loss mid-run is said, never guessed past. */
function currentCopy(steps: StageGSteps): Copy {
  const { copy } = readState(steps);
  if (copy === undefined) throw new Error(`${steps.stateFile} lost its copy while the runner worked.`);
  return copy;
}

/** A time as the partner reads it: UAE local (UTC+4). */
export const uae = (at: Date | string): string =>
  `${new Date(new Date(at).getTime() + 4 * 3_600_000).toISOString().slice(0, 16).replace('T', ' ')} UAE`;

const MINUTE_MS = 60_000;

/** A restore took 8 min 18 s on the first drill (playbook L); a larger copy longer. */
const RESTORE_WAIT_MS = 90 * MINUTE_MS;

/** The resize's restart and the connection limit's. */
const RESIZE_WAIT_MS = 20 * MINUTE_MS;

/** The partner's apps deploy, from their own terminal: a few minutes, given two hours. */
const APPS_WAIT_MS = 120 * MINUTE_MS;

/** How far back the restore point is: Azure takes none in the future, and the clocks may differ a little. */
const RESTORE_BEFORE_MS = 5 * MINUTE_MS;

/** A copy's anchors are kept 3 days (apps.bicep); an hour more for the last one written as it was removed. */
const ANCHORS_KEPT_MS = (3 * 24 + 1) * 60 * MINUTE_MS;

/**
 * Seed runs at most for one step's growth: each up to load-step's 75 minutes,
 * so twelve are 15 hours, past any growth measured so far (PL-62's 30,000).
 */
const SEED_RUNS = 12;

/** A step's lines re-read every 2 minutes for 30, then left as not judged yet. */
const JUDGE_POLL_MS = 2 * MINUTE_MS;
const JUDGE_READINGS = 15;

const ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** A new copy's ID: 8 lower-case letters or digits (throwaway.ts's rule). */
export const randomCopyId = (bytes: Buffer = randomBytes(8)): string =>
  Array.from(bytes, (byte) => ID_ALPHABET.charAt(byte % ID_ALPHABET.length)).join('');

const appsLine = (server: string): string =>
  `node deploy/azure/deploy.ts apps --load-run --keep-running --load-database ${server}`;
const PAUSE_LINE = 'node deploy/azure/operator.ts handoff-pause --reason <case reference>';
/** A stopped run's end, as Azure lists it: a few minutes, given ten. */
const STOP_WAIT_MS = 10 * MINUTE_MS;

const RESUME_LINE = 'node deploy/azure/operator.ts handoff-resume --reason <case reference>';

/** Waits until `done` gives a value, reading every `everyMs`, for `forMs` at most: undefined when it never did. */
async function waitUntil<T>(
  steps: StageGSteps,
  forMs: number,
  everyMs: number,
  done: () => T | undefined,
): Promise<T | undefined> {
  const deadline = steps.now().getTime() + forMs;
  for (;;) {
    const value = done();
    if (value !== undefined) return value;
    if (steps.now().getTime() >= deadline) return undefined;
    await steps.sleep(everyMs);
  }
}

/** The restore started, and the copy kept from that moment: refused while any copy is there. */
function startRestore(steps: StageGSteps): Copy {
  const { azure } = steps;
  const servers = azure.servers();
  const others = servers.filter((name) => throwawayIdOf(name) !== undefined);
  if (others.length > 0) {
    throw new Error(
      `A Stage G copy is already there (${others.join(', ')}), one this runner doesn't keep: remove it with node deploy/azure/stage-g.ts delete ${others[0] ?? ''} first. Nothing was made.`,
    );
  }
  const id = steps.randomId();
  const server = `psql-agentx-stg-g-${id}`;
  const problem = throwawayServerProblem(server);
  if (problem !== undefined) throw new Error(problem);
  const staging = azure.stagingServer();
  const at = new Date(steps.now().getTime() - RESTORE_BEFORE_MS);
  azure.restore(server, staging, at.toISOString());
  const copy: Copy = {
    server,
    id,
    runId: `stage-g-${id}`,
    createdAt: steps.now().toISOString(),
    sized: false,
    marked: false,
    paused: false,
    seededTo: 0,
    incomplete: [],
    tests: {},
  };
  keep(steps, { ...readState(steps), copy });
  steps.say(
    `Restoring ${staging.name} as it was at ${uae(at)} to ${server}, in its subnet and private zone. This takes about 10 minutes...`,
  );
  return copy;
}

/** Ready, sized for the load run, its connection limit taken: or an error saying to run create again. */
async function readyAndSized(steps: StageGSteps, copy: Copy): Promise<Copy> {
  const { azure } = steps;
  const ready = await waitUntil(steps, RESTORE_WAIT_MS, MINUTE_MS, () =>
    azure.serverState(copy.server) === 'Ready' ? true : undefined,
  );
  if (ready === undefined) {
    throw new Error(
      `${copy.server} wasn't ready 90 minutes after its restore began: run create again to keep waiting.`,
    );
  }
  if (copy.sized) return copy;
  steps.say(`${copy.server} is ready. Sizing it for the load run (${LOAD_SKU.name}): it restarts for a few minutes...`);
  azure.resize(copy.server);
  const sized = await waitUntil(steps, RESIZE_WAIT_MS, MINUTE_MS, () => {
    const live = azure.connectionLimit(copy.server);
    return live.limit >= LOAD_SERVER_CONNECTIONS && !live.waiting && azure.serverState(copy.server) === 'Ready'
      ? true
      : undefined;
  });
  if (sized === undefined) {
    throw new Error(
      `${copy.server}'s new size or connection limit hadn't taken 20 minutes on: run create again to keep waiting.`,
    );
  }
  return keepCopy(steps, { sized: true });
}

/** Whether every Stage G job is there and reaches the copy: apps --load-run --load-database has deployed them. */
const jobsOnCopy = (azure: StageGAzure, server: string): boolean =>
  STAGE_G_JOBS.every((job) => azure.jobHost(job) === throwawayHost(server));

/** load-mark, once the partner's apps deploy has put the jobs on the copy: the sentinel written and read back. */
async function mark(steps: StageGSteps, copy: Copy): Promise<Copy> {
  const { azure } = steps;
  steps.say(
    `Now deploy the apps onto the copy, in another terminal window:\n  ${appsLine(copy.server)}\nThis waits until it has (up to two hours), then marks the copy.`,
  );
  const deployed = await waitUntil(steps, APPS_WAIT_MS, MINUTE_MS, () =>
    jobsOnCopy(azure, copy.server) ? true : undefined,
  );
  if (deployed === undefined) {
    throw new Error(
      `The Stage G jobs weren't reaching ${copy.server} two hours on: run the apps line above, then create again.`,
    );
  }
  steps.say('The jobs reach the copy. Marking it (load-mark)...');
  const { run, printed } = await azure.runJob('load-mark', {
    request: undefined,
    lastEvent: 'load.stageg_marked',
    ifStuck: 'wait for it, then run node deploy/azure/stage-g.ts create again.',
  });
  const marked = lineOf(printed, 'load.stageg_marked');
  if (run.status !== 'Succeeded' || marked?.server !== copy.server) {
    throw new Error(
      `The copy wasn't marked (load-mark ended ${endedAs(run, printed, 'load.stageg_refused')}): read the lines above, then create again.`,
    );
  }
  return keepCopy(steps, { marked: true });
}

/**
 * load-step pause, right after the mark and before any seed: the copy's own
 * hand-off pause, which it holds from staging's at its restore point. Not
 * paused, the copy can never be used: the operator's pause moves staging's alone.
 */
async function confirmPaused(steps: StageGSteps, copy: Copy): Promise<Copy> {
  steps.say("Reading the copy's hand-off pause (load-step pause)...");
  const { run, printed } = await steps.azure.runJob('load-step', {
    request: { runId: copy.runId, command: ['pause'] },
    lastEvent: 'load.stageg_pause',
    ifStuck: 'wait for it, then run node deploy/azure/stage-g.ts create again.',
  });
  const outcome = text(lineOf(printed, 'load.stageg_pause')?.outcome);
  if (run.status !== 'Succeeded' || outcome !== 'paused') {
    const read = outcome === '' ? `unread (load-step ended ${endedAs(run, printed, 'load.stageg_refused')})` : outcome;
    throw new Error(
      `The copy's hand-offs are ${read}, not paused, so no step may run on it: staging wasn't paused when it was made. Remove it (node deploy/azure/stage-g.ts delete), pause staging:\n  ${PAUSE_LINE}\nthen create again.`,
    );
  }
  return keepCopy(steps, { paused: true });
}

async function create(steps: StageGSteps): Promise<number> {
  const kept = readState(steps).copy;
  if (kept?.marked === true && kept.paused) {
    throw new Error(
      `Stage G's copy ${kept.server} is already made, marked and paused: run a test on it (node deploy/azure/stage-g.ts run smoke), or delete it first.`,
    );
  }
  if (kept === undefined) {
    steps.say(
      `Staging's hand-offs must already be paused, run before create:\n  ${PAUSE_LINE}\nThe copy keeps staging's pause as it is at the restore, and no step runs on a copy unpaused: one made unpaused is refused once made, and must be removed and made again.`,
    );
  } else steps.say(`Carrying on with ${kept.server}, made ${uae(kept.createdAt)}.`);
  const sized = await readyAndSized(steps, kept ?? startRestore(steps));
  const marked = sized.marked ? sized : await mark(steps, sized);
  await confirmPaused(steps, marked);
  steps.say(
    `${sized.server} is ready, marked and paused. Next, the smoke test:\n  node deploy/azure/stage-g.ts run smoke`,
  );
  return 0;
}

/** The profile, sized from what earlier tests recorded where it must be: or why it can't run yet. */
function profileFor(test: StageGTest, copy: Copy): Profile {
  if (test === 'overload' && copy.breakingRate === undefined) {
    throw new Error(
      'The overload test is sized from the breaking test\'s measured rate, and none is recorded on this copy: run "breaking" first.',
    );
  }
  if (test === 'neighbours' && copy.targetP95Ms === undefined) {
    throw new Error(
      'The neighbours test compares the calm organisations with the target test\'s p95, and none is recorded on this copy: run "target" first.',
    );
  }
  return stageGProfile(test, copy.breakingRate);
}

/** The copy marked, its jobs on it and idle, the API keeping its copies running: or why not. */
function preflight(steps: StageGSteps): Copy {
  const copy = readState(steps).copy;
  if (copy?.marked !== true || !copy.paused) {
    throw new Error('No marked and paused Stage G copy is kept: run node deploy/azure/stage-g.ts create first.');
  }
  const { azure } = steps;
  if (!jobsOnCopy(azure, copy.server)) {
    throw new Error(
      `The Stage G jobs don't all reach ${copy.server}: run\n  ${appsLine(copy.server)}\nthen run again.`,
    );
  }
  for (const job of STAGE_G_JOBS) {
    const going = azure.runsGoing(job);
    if (going.length > 0) throw new Error(`${job} has runs still going: ${going.join(', ')}. Wait for them first.`);
  }
  if (azure.api().fewest < 1) {
    throw new Error(`The API keeps no copy running: run\n  ${appsLine(copy.server)}\nthen run again.`);
  }
  return copy;
}

/** Where the climb starts, and what the steps before it found: or why --from can't start there. */
function startOf(profile: Profile, record: TestRecord | undefined, from: string | undefined) {
  if (from === undefined) return { index: 0, results: [], notes: [] };
  const labels = profile.steps.map(({ label }) => label);
  const index = labels.indexOf(from);
  if (index < 0) throw new Error(`${profile.test} has no step ${from}: its steps are ${labels.join(', ')}.`);
  const results = (record?.results ?? []).slice(0, index);
  if (results.some(({ run }, at) => run.label !== labels[at]) || results.length < index) {
    throw new Error(
      `The steps before ${from} haven't all run on this copy: run node deploy/azure/stage-g.ts run ${profile.test} from its start.`,
    );
  }
  const before = new Set(labels.slice(0, index));
  return { index, results, notes: (record?.notes ?? []).filter(({ label }) => before.has(label)) };
}

/** Why a run of a job refused, if it did: its own words. */
const refusal = (printed: readonly Printed[]): string | undefined => {
  const refused = lineOf(printed, 'load.stageg_refused');
  return refused === undefined ? undefined : text(refused.reason);
};

/** A climb stopped by the runner, not by a step's verdict: said in plain words, the step to resume from named. */
class Stopped extends Error {}

/** How many organisations were found half-made, said after the count, if any. */
const halfMade = (incomplete: readonly number[]): string =>
  incomplete.length === 0 ? '' : ', ' + String(incomplete.length) + ' of them half-made and left out';

/** Grows the seed to `orgs`, a run at a time, while a run ends before it is done. */
async function growSeed(steps: StageGSteps, copy: Copy, orgs: number, label: string): Promise<Copy> {
  if (copy.seededTo >= orgs) return copy;
  for (let attempt = 1; attempt <= SEED_RUNS; attempt += 1) {
    steps.say(
      `Growing the seed to ${String(orgs)} organisations (run ${String(attempt)} of at most ${String(SEED_RUNS)})...`,
    );
    const { run, printed } = await steps.azure.runJob('load-step', {
      request: { runId: copy.runId, command: ['seed', '--to', String(orgs)] },
      lastEvent: 'load.stageg_seeded',
      ifStuck: `wait for it, then run again with --from ${label}.`,
    });
    const refused = refusal(printed);
    if (refused !== undefined) throw new Stopped(`The seed refused: ${refused}`);
    const seeded = lineOf(printed, 'load.stageg_seeded');
    if (seeded !== undefined) {
      const incomplete = Array.isArray(seeded.incomplete) ? seeded.incomplete.map(Number) : [];
      steps.say(`The seed holds ${String(orgs)} organisations${halfMade(incomplete)}.`);
      return keepCopy(steps, { seededTo: orgs, incomplete });
    }
    steps.say(`That seed run ended ${run.status} before it was done: it carries on where it stopped.`);
  }
  throw new Stopped(`The seed hadn't reached ${String(orgs)} organisations after ${String(SEED_RUNS)} runs.`);
}

/** The organisations a neighbours step means to be in trouble: the first two whole heavy ones (stageg-seed.ts). */
export function offendersOf(copy: Pick<Copy, 'runId' | 'incomplete'>, orgs: number): string[] {
  const offenders: string[] = [];
  for (let index = 0; index < orgs && offenders.length < 2; index += 1) {
    if (stageGKindAt(index) === 'heavy' && !copy.incomplete.includes(index)) {
      offenders.push(stageGOrgId(copy.runId, index));
    }
  }
  return offenders;
}

/** The API's replicas (`<revision>/<name>`) and their restarts summed; null when they couldn't be read. */
function replicasNow(azure: StageGAzure): { names: string[]; restarts: number } | null {
  try {
    const { revision } = azure.api();
    const replicas = azure.replicas(revision);
    return {
      names: replicas.map(({ name }) => `${revision}/${name}`),
      restarts: replicas.reduce((sum, { restarts }) => sum + restarts, 0),
    };
  } catch {
    return null;
  }
}

/** One step's traffic: its job's run and k6's summary, a soak segment cut off run again once. */
async function stepTraffic(steps: StageGSteps, copy: Copy, run: StepRun, notes: Note[]) {
  const tries = run.test === 'soak' ? 2 : 1;
  for (let attempt = 1; ; attempt += 1) {
    const before = replicasNow(steps.azure);
    steps.say(`Step ${run.label}: k6 on ${String(run.orgs)} organisations, in load-step...`);
    const ran = await steps.azure.runJob('load-step', {
      request: { runId: copy.runId, command: ['step', JSON.stringify(run)] },
      lastEvent: 'load.stageg_stepped',
      ifStuck: `wait for it, then run again with --from ${run.label}.`,
    });
    const refused = refusal(ran.printed);
    if (refused !== undefined) throw new Stopped(`Step ${run.label} refused: ${refused}`);
    const { event: _event, ...summary } = lineOf(ran.printed, 'load.stageg_summary') ?? {};
    if (typeof summary.startedAt === 'string' && typeof summary.endedAt === 'string') {
      return { ran, summary: summary as unknown as StageGSummary, before, after: replicasNow(steps.azure) };
    }
    if (attempt >= tries) {
      throw new Stopped(`Step ${run.label} gave no numbers (load-step ended ${ran.run.status}): k6 never finished.`);
    }
    notes.push({ label: run.label, note: `interrupted (load-step ended ${ran.run.status}) and run again once.` });
    steps.say(`Soak segment ${run.label} was cut off (load-step ended ${ran.run.status}): running it again, once.`);
  }
}

/** load-check over the step: each check's findings, none when the job said nothing. */
async function checkStep(steps: StageGSteps, copy: Copy, run: StepRun, summary: StageGSummary, since: string) {
  steps.say(`Checking the copy after ${run.label}, in load-check...`);
  const checked = {
    created: summary.created,
    startedAt: summary.startedAt,
    endedAt: summary.endedAt,
    since,
    // A climb that stopped itself cut off what was in flight: saved, never answered, at most one a VU.
    unansweredAtMost: summary.aborted ? run.vus.max : 0,
  };
  const done = await steps.azure.runJob('load-check', {
    request: { runId: copy.runId, command: ['check', JSON.stringify(run), JSON.stringify(checked)] },
    lastEvent: 'load.stageg_checked',
    ifStuck: `wait for it, then run again with --from ${run.label}.`,
  });
  const checks = lineOf(done.printed, 'load.stageg_checked')?.checks;
  return { done, checks: Array.isArray(checks) ? (checks.map(record) as unknown as StageGCheckResult[]) : [] };
}

/** What the runner found wrong with a step's jobs, beside its verdict. */
function jobNotes(run: StepRun, ran: JobRun, summary: StageGSummary, checked: JobRun): string[] {
  const stepped = lineOf(ran.printed, 'load.stageg_stepped');
  // A breaking climb stops itself on its threshold, so its k6, and its job, end failed by design.
  const meantToStop = run.abort !== null && summary.aborted;
  return [
    ...(ran.run.status === 'Succeeded' || meantToStop ? [] : [`load-step ended ${ran.run.status}.`]),
    ...(stepped?.notPaused === undefined
      ? []
      : [`Hand-offs weren't paused after the step: ${text(stepped.notPaused)}.`]),
    ...(checked.run.status === 'Succeeded'
      ? []
      : [`load-check ended ${endedAs(checked.run, checked.printed, 'load.stageg_refused')}.`]),
    ...[ran.putBack, checked.putBack].filter((said): said is string => said !== undefined),
  ];
}

/**
 * The step's lines from the workspace so far, or what is still missing from
 * them: an answer Log Analytics gave only in part, or no decision line yet from
 * a step that sent traffic. A missing read keeps the step not judged; a p95 of
 * nothing is never read as 0 ms.
 */
function readLines(azure: StageGAzure, window: StepWindow, offenders: readonly string[], sent: boolean) {
  try {
    const log = azure.stepLog(window, offenders);
    const decisionP95Ms = azure.decisionP95(window, offenders);
    const missing = decisionP95Ms === null && sent ? ['no decision lines read yet from the step'] : [];
    return { log, decisionP95Ms, missing };
  } catch (error) {
    return { log: [], decisionP95Ms: null, missing: [`a whole answer from the workspace: ${reason(error)}`] };
  }
}

/** The step's result as read from the workspace so far. */
function readResult(
  steps: StageGSteps,
  copy: Copy,
  traffic: Awaited<ReturnType<typeof stepTraffic>>,
  run: StepRun,
  checks: readonly StageGCheckResult[],
): StageGStepResult {
  const { azure } = steps;
  const { summary, before, after } = traffic;
  const window = { from: summary.startedAt, to: summary.endedAt };
  const offenders = run.mix === 'neighbours' ? offendersOf(copy, run.orgs) : [];
  const lines = readLines(azure, window, offenders, summary.requests > 0);
  const health = backgroundHealth(lines.log, window, {
    apiReplicas: after?.names ?? [],
    offenders: new Set(offenders),
    // The second offender is the stuck one (offendersOf, stageg-seed.ts's cohort order).
    stuck: offenders[1],
  });
  const surge = run.test === 'spike' || run.test === 'overload';
  return {
    run,
    summary,
    // Not a number only while the step can't be judged (`missing` says why), or when it sent nothing, which fails it.
    decisionP95Ms: lines.decisionP95Ms ?? Number.NaN,
    background: { ...health, missing: [...health.missing, ...lines.missing] },
    restarts: before === null || after === null ? null : { before: before.restarts, after: after.restarts },
    databaseChecks: checks,
    ...(surge ? { baseDecisionP95Ms: azure.decisionP95(baseHoldWindow(run, summary.startedAt)) } : {}),
    ...(run.test === 'soak'
      ? {
          resources: {
            memoryMb: azure.lastReading('memory', copy.server, window),
            connections: azure.lastReading('connections', copy.server, window),
          },
        }
      : {}),
  };
}

/** The report's input for the steps so far: the neighbours compared with the target's p95. */
const reportInput = (profile: Profile, copy: Copy, results: readonly StageGStepResult[]): StageGReportInput => ({
  site: 'azure',
  profile,
  steps: results,
  ...(profile.test === 'neighbours' && copy.targetP95Ms !== undefined ? { baselineP95Ms: copy.targetP95Ms } : {}),
});

/** A step judged, its lines read again while they arrive, for JUDGE_READINGS at most. */
async function judged(
  steps: StageGSteps,
  input: (result: StageGStepResult) => StageGReportInput,
  read: () => StageGStepResult,
) {
  for (let reading = 1; ; reading += 1) {
    const result = read();
    const asked = input(result);
    const baseline = asked.baselineP95Ms ?? asked.steps[0]?.summary.asksMs?.p95;
    const judgement = judgeStageGStep(asked, result, baseline);
    if (judgement.state !== 'not-judged-yet' || reading >= JUDGE_READINGS) return { result, judgement };
    if (reading === 1) {
      steps.say(
        `Step ${result.run.label}'s lines are still reaching the workspace (they come 4 to 9 minutes late): reading again every 2 minutes, for 30 at most...`,
      );
    }
    await steps.sleep(JUDGE_POLL_MS);
  }
}

/** The report's file for the day and the test: a second the same day gets its own. */
function reportFile(dir: string, at: Date, test: StageGTest): string {
  mkdirSync(dir, { recursive: true });
  const name = `${at.toISOString().slice(0, 10)}-stageg-${test}`;
  for (let n = 1; ; n += 1) {
    const file = path.join(dir, n === 1 ? `${name}.md` : `${name}-${String(n)}.md`);
    if (!existsSync(file)) return file;
  }
}

/** Writes the test's report as it stands, and a copy to the Documents folder where it exists. */
function writeReport(steps: StageGSteps, copy: Copy, profile: Profile, tested: TestRecord, stopped?: string): string {
  const now = steps.now();
  // The size Azure reports, not LOAD_SKU: day 2-4's copies were resized by hand and their headers said D2 (S177).
  const size = steps.azure.serverSize(copy.server) ?? `${LOAD_SKU.name}, not read back`;
  const notes = tested.notes.map(({ label, note }) => `- ${label}: ${note}`);
  const report = [
    `# Stage G on Azure: ${profile.test}`,
    '',
    `Written ${uae(now)}, on the throwaway copy ${copy.server} (${size}, high availability ${copy.ha === true ? 'on, zone-redundant' : 'off'}), the seed's run ${copy.runId}.`,
    '',
    renderStageG(reportInput(profile, copy, tested.results)).trimEnd(),
    ...(notes.length === 0 ? [] : ['', '### What the runner found', '', ...notes]),
    ...(stopped === undefined ? [] : ['', '### Why the climb stopped', '', stopped]),
    '',
  ].join('\n');
  const file = reportFile(steps.reportsDir, now, profile.test);
  writeFileSync(file, report);
  if (existsSync(steps.copyDir)) copyFileSync(file, path.join(steps.copyDir, path.basename(file)));
  steps.say(`\n${report}\nThe report: ${file}`);
  return file;
}

/** What one step's verdict records on the copy: the breaking rate and the target's p95, for the tests sized from them. */
function recorded(result: StageGStepResult, judgement: StepJudgement): Partial<Copy> {
  const { run, summary } = result;
  const rate =
    run.test === 'breaking' && run.abort !== null && summary.windows !== null
      ? breakingRate(run, run.abort, summary.windows)
      : null;
  const p95 = run.test === 'target' && judgement.state === 'passed' ? summary.asksMs?.p95 : undefined;
  return {
    ...(rate === null ? {} : { breakingRate: Math.round(rate) }),
    ...(p95 === undefined ? {} : { targetP95Ms: p95 }),
  };
}

/** One step, start to verdict: its seed, its traffic, its checks, its lines judged. */
async function oneStep(steps: StageGSteps, profile: Profile, run: StepRun, results: StageGStepResult[], notes: Note[]) {
  let copy = await growSeed(steps, currentCopy(steps), run.orgs, run.label);
  const traffic = await stepTraffic(steps, copy, run, notes);
  copy = copy.since === undefined ? keepCopy(steps, { since: traffic.summary.startedAt }) : copy;
  const { done, checks } = await checkStep(steps, copy, run, traffic.summary, copy.since ?? traffic.summary.startedAt);
  const problems = jobNotes(run, traffic.ran, traffic.summary, done);
  for (const note of problems) notes.push({ label: run.label, note });
  const { result, judgement } = await judged(
    steps,
    (current) => reportInput(profile, copy, [...results, current]),
    () => readResult(steps, copy, traffic, run, checks),
  );
  results.push(result);
  // A step its own rules pass still fails on what the runner found wrong with its jobs.
  const verdict: StepJudgement['state'] =
    problems.length > 0 && judgement.state === 'passed' ? 'failed' : judgement.state;
  const tested: TestRecord = { results: [...results], notes: [...notes] };
  keepCopy(steps, {
    ...recorded(result, judgement),
    tests: { ...copy.tests, [profile.test]: tested },
    last: { test: profile.test, label: run.label, verdict, at: steps.now().toISOString() },
  });
  return { verdict, judgement };
}

/** High availability coming up (a standby made and synced) or going: well past Azure's usual few minutes. */
const HA_WAIT_MS = 60 * MINUTE_MS;

/**
 * The copy's high availability as the test needs it: zone-redundant and
 * Healthy for the ha test (PL-64), off for every other, each waited for. The
 * ask is recorded before the wait, so a stopped run's next run waits again.
 */
async function haFor(steps: StageGSteps, kept: Copy, test: StageGTest): Promise<Copy> {
  const { azure } = steps;
  let copy = kept;
  const wanted = test === 'ha';
  if (!wanted && copy.ha !== true) return copy;
  const mode = wanted ? 'ZoneRedundant' : 'Disabled';
  if (copy.ha !== wanted) {
    azure.setHa(copy.server, mode);
    copy = keepCopy(steps, { ha: wanted });
  }
  steps.say(
    wanted
      ? `Turning on zone-redundant high availability on ${copy.server} for the ha test, and waiting until its standby is healthy (up to an hour)...`
      : `High availability is on from the ha test: turning it off on ${copy.server} first, and waiting until it is (up to an hour)...`,
  );
  const done = await waitUntil(steps, HA_WAIT_MS, MINUTE_MS, () => {
    const ha = azure.haOf(copy.server);
    const settled = wanted ? ha.mode === mode && ha.state === 'Healthy' : ha.mode === mode;
    return settled ? true : undefined;
  });
  if (done === undefined) {
    throw new Error(
      `${copy.server}'s high availability wasn't ${wanted ? 'on and healthy' : 'off'} an hour on: nothing ran. Run the same command again to keep waiting.`,
    );
  }
  if (!wanted) copy = keepCopy(steps, { ha: false });
  return copy;
}

async function runTest(steps: StageGSteps, test: StageGTest, from: string | undefined): Promise<number> {
  const ready = preflight(steps);
  const profile = profileFor(test, ready);
  const copy = await haFor(steps, ready, test);
  const start = startOf(profile, copy.tests[test], from);
  const results: StageGStepResult[] = [...start.results];
  const notes: Note[] = [...start.notes];
  steps.say(`Test ${test} on ${copy.server}: ${profile.steps.map(({ label }) => label).join(', ')}.`);
  for (const step of profile.steps.slice(start.index)) {
    const run = stepRun(profile, step);
    let outcome: Awaited<ReturnType<typeof oneStep>>;
    try {
      outcome = await oneStep(steps, profile, run, results, notes);
    } catch (error) {
      if (!(error instanceof Stopped)) throw error;
      const said = `${error.message} Once it's sorted, run: node deploy/azure/stage-g.ts run ${test} --from ${run.label}`;
      keepCopy(steps, { last: { test, label: run.label, verdict: 'stopped', at: steps.now().toISOString() } });
      writeReport(steps, copy, profile, { results, notes }, said);
      steps.say(said);
      return 1;
    }
    const current = currentCopy(steps);
    if (outcome.verdict === 'not-judged-yet') {
      writeReport(steps, current, profile, { results, notes });
      steps.say(
        `Step ${run.label} couldn't be judged: its lines hadn't all reached the workspace 30 minutes on. Nothing is called failed. Read the report, and when its lines are in, run the step again: node deploy/azure/stage-g.ts run ${test} --from ${run.label}`,
      );
      return 1;
    }
    if (outcome.verdict === 'failed') {
      writeReport(steps, current, profile, { results, notes });
      steps.say(
        `Step ${run.label} failed, so the climb stops here (the report says why). Fix it, then run that step again:\n  node deploy/azure/stage-g.ts run ${test} --from ${run.label}`,
      );
      return 1;
    }
    steps.say(`Step ${run.label} passed.`);
  }
  writeReport(steps, currentCopy(steps), profile, { results, notes });
  steps.say(`Test ${test} passed every step. When Stage G is done: node deploy/azure/stage-g.ts delete`);
  return 0;
}

/** Where a Stage G job stands: whether it reaches the copy, and any run of it going. */
function jobStatus(azure: StageGAzure, copy: Copy, job: StageGJob): string {
  const host = azure.jobHost(job);
  let said = 'not there';
  if (host === throwawayHost(copy.server)) said = 'reaching the copy';
  else if (host !== undefined) said = `reaching ${host}, not the copy`;
  const going = host === undefined ? [] : azure.runsGoing(job);
  const runs = going.length === 0 ? '' : ', runs going: ' + going.join(', ');
  return `  ${job}: ${said}${runs}.`;
}

/** The copy kept, as Azure and the runner know it. */
function copyStatus(steps: StageGSteps, copy: Copy): void {
  const { azure } = steps;
  const state = azure.serverState(copy.server) ?? 'it is not there';
  steps.say(`The copy: ${copy.server}, made ${uae(copy.createdAt)}; Azure says ${state}.`);
  const made = [
    copy.sized ? 'Sized for the load run' : 'Not sized yet',
    copy.marked ? 'marked' : 'not marked yet',
    copy.paused ? 'its hand-offs paused' : 'its hand-off pause not confirmed',
  ].join(', ');
  steps.say(`  ${made}; the seed holds ${String(copy.seededTo)} organisations.`);
  for (const job of STAGE_G_JOBS) steps.say(jobStatus(azure, copy, job));
  steps.say(`  The API: ${azure.api().fewest >= 1 ? 'its copies kept running' : 'scales to zero'}.`);
  const { last } = copy;
  steps.say(
    last === undefined
      ? '  No step has run yet.'
      : `  The last step: ${last.test} ${last.label}, ${last.verdict}, at ${uae(last.at)}.`,
  );
  if (copy.breakingRate !== undefined)
    steps.say(`  The breaking rate: ${String(copy.breakingRate)} requests a second.`);
}

function status(steps: StageGSteps): number {
  const { copy, anchors } = readState(steps);
  if (copy === undefined) steps.say('No Stage G copy is kept: node deploy/azure/stage-g.ts create makes one.');
  else copyStatus(steps, copy);
  for (const each of anchors) steps.say(`Anchors container ${each.container} kept until ${uae(each.lockedUntil)}.`);
  return 0;
}

/**
 * Stops every Stage G job's runs still going and waits until Azure has them
 * all ended (load.ts finish refuses a job with a run going), then removes the
 * load jobs (load.ts finish).
 */
async function stopJobs(steps: StageGSteps): Promise<void> {
  const { azure } = steps;
  for (const job of STAGE_G_JOBS) {
    for (const going of azure.runsGoing(job)) {
      const run = going.split(' ')[0] ?? going;
      azure.stopRun(job, run);
      steps.say(`Stopping ${run}...`);
    }
  }
  const ended = await waitUntil(steps, STOP_WAIT_MS, POLL_MS, () =>
    STAGE_G_JOBS.every((job) => azure.runsGoing(job).length === 0) ? true : undefined,
  );
  if (ended === undefined) {
    throw new Error('A Stage G run was still going 10 minutes after it was stopped: run delete again.');
  }
  if ((await steps.finishLoad()) !== 0) {
    throw new Error("The load jobs weren't all removed (the lines above say why): run delete again.");
  }
}

async function remove(steps: StageGSteps, named: string | undefined): Promise<number> {
  const state = readState(steps);
  const server = named ?? state.copy?.server;
  if (server === undefined) throw new Error('No Stage G copy is kept: name the copy to remove.');
  const problem = throwawayServerProblem(server);
  if (problem !== undefined) throw new Error(`${problem} Nothing was removed.`);
  const id = throwawayIdOf(server) ?? '';
  // The jobs reach the copy this runner keeps: removing another copy (one left from before) leaves them be.
  const kept = state.copy?.server === server;
  if (kept) await stopJobs(steps);
  const { azure } = steps;
  if (azure.servers().includes(server)) {
    steps.say(`Removing ${server}...`);
    azure.deleteServer(server);
    if (azure.servers().includes(server)) throw new Error(`Azure still lists ${server}: run delete again.`);
  }
  steps.say(`${server} is gone.`);
  const anchors: Anchors = {
    container: throwawayAnchorsContainer(id),
    server,
    lockedUntil: new Date(steps.now().getTime() + ANCHORS_KEPT_MS).toISOString(),
  };
  const others = state.anchors.filter(({ container }) => container !== anchors.container);
  const { copy } = state;
  keep(steps, { ...(copy === undefined || copy.server === server ? {} : { copy }), anchors: [...others, anchors] });
  steps.say(
    [
      ...(kept
        ? [
            `Next, put staging back:\n  node deploy/azure/deploy.ts apps`,
            `then resume staging's hand-offs:\n  ${RESUME_LINE}`,
          ]
        : []),
      `The copy's anchors container ${anchors.container} stays until its files' 3 days are up: after ${uae(anchors.lockedUntil)}, run node deploy/azure/stage-g.ts delete --anchors.`,
    ].join('\n'),
  );
  return 0;
}

const ANCHORS_CONTAINER = /^audit-anchors-g-[a-z0-9]{8}$/;

/** What happens to one recorded anchors container: what is said, and whether it stays on the list. */
function anchorsFate(
  steps: StageGSteps,
  each: Anchors,
  { account, servers, listed }: { account: string; servers: readonly string[]; listed: ReadonlySet<string> },
): { said: string; kept: boolean } {
  if (!ANCHORS_CONTAINER.test(each.container)) {
    return {
      said: `${each.container} isn't a copy's anchors container: left alone, and dropped from the list.`,
      kept: false,
    };
  }
  if (!listed.has(each.container)) return { said: `${each.container} is already gone.`, kept: false };
  if (servers.includes(each.server)) {
    return { said: `${each.container} kept: its copy ${each.server} is still there.`, kept: true };
  }
  if (steps.now().getTime() < Date.parse(each.lockedUntil)) {
    return { said: `${each.container} kept until ${uae(each.lockedUntil)}: its files' time isn't up.`, kept: true };
  }
  return steps.azure.deleteContainer(account, each.container)
    ? { said: `Removed ${each.container}.`, kept: false }
    : { said: `Azure refused to remove ${each.container}: run delete --anchors again later.`, kept: true };
}

/** Removes the anchors containers kept whose copy is gone and whose time is up; keeps and says the others. */
function removeAnchors(steps: StageGSteps): number {
  const state = readState(steps);
  const { azure } = steps;
  const account = evidenceAccountOf(azure.stagingServer().name);
  const known = { account, servers: azure.servers(), listed: new Set(azure.anchorContainers(account)) };
  const left = state.anchors.filter((each) => {
    const { said, kept } = anchorsFate(steps, each, known);
    steps.say(said);
    return kept;
  });
  keep(steps, { ...state, anchors: left });
  return left.length === 0 ? 0 : 1;
}

export function stageG(request: Request, steps: StageGSteps): Promise<number> {
  switch (request.command) {
    case 'create':
      return create(steps);
    case 'run':
      return runTest(steps, request.test, request.from);
    case 'status':
      return Promise.resolve(status(steps));
    case 'delete':
      return remove(steps, request.name);
    case 'anchors':
      return Promise.resolve(removeAnchors(steps));
  }
}

/** Whether a process with this ID is running: signal 0 tests it and sends nothing (EPERM: running, not ours). */
function running(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * One runner at a time on this laptop: on S178 a second, left running by mistake, fought the first over load-step's
 * request, each putting `{}` back on the other's run, so breaking's job read none and refused. The lock holds the
 * runner's process ID; one left by a runner no longer running is removed and made again, only-if-absent, so two
 * runners finding it together can't both take it. Windows reuses process IDs, so the refusal names the file too.
 * Gives back the release.
 */
export function holdRunnerLock(lockFile: string, pid: number = process.pid): () => void {
  mkdirSync(path.dirname(lockFile), { recursive: true });
  const take = (): void => {
    writeFileSync(lockFile, String(pid), { flag: 'wx' });
  };
  try {
    take();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    const holder = Number(readFileSync(lockFile, 'utf8').trim());
    const refused = new Error(
      `Another Stage G runner is going (process ${String(holder)}): let it finish or stop it, then run this again. Two at once overwrite each other's job requests. If no Stage G runner is open, delete ${lockFile} and run this again.`,
      { cause: error },
    );
    if (running(holder)) throw refused;
    rmSync(lockFile, { force: true });
    try {
      take();
    } catch {
      throw refused;
    }
  }
  // Read, not checked first (CodeQL js/file-system-race): a lock already gone has nothing to give back.
  return () => {
    let holder: string;
    try {
      holder = readFileSync(lockFile, 'utf8').trim();
    } catch {
      return;
    }
    if (holder === String(pid)) rmSync(lockFile, { force: true });
  };
}

const LOAD_DIR = fileURLToPath(new URL('../../tooling/load/', import.meta.url));

/** Where the partner keeps the Azure load reports (Documents, outside git). */
const DOCUMENTS_REPORTS = 'C:\\Users\\shahb\\OneDrive\\Agent X\\Documents\\Phase-4\\Slices\\Azure-Load-Reports';

/** The command line, run: `az` and `loadDir` (where the state and the reports go) are tests' to change. */
export function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => Az = realAz,
  loadDir: string = LOAD_DIR,
): Promise<number> {
  return runCli(
    USAGE,
    say,
    () => parseArguments(argv),
    async (request) => {
      // Reading the state changes nothing, so only the commands that do take the lock.
      const release =
        request.command === 'status' ? () => undefined : holdRunnerLock(path.join(loadDir, '.out', 'stage-g.lock'));
      // Ctrl+C or a closed window ends Node without running `finally`: the lock is given back there too.
      const stopped = () => {
        release();
        process.exit(130);
      };
      for (const signal of STOP_SIGNALS) process.once(signal, stopped);
      const base: JobSteps = { az: az(), say, now: () => new Date(), sleep };
      try {
        return await stageG(request, {
          ...base,
          azure: realStageGAzure(base),
          stateFile: path.join(loadDir, '.out', 'stage-g.json'),
          reportsDir: path.join(loadDir, 'reports'),
          copyDir: DOCUMENTS_REPORTS,
          randomId: randomCopyId,
          finishLoad: () =>
            load(
              { command: 'finish' },
              {
                ...base,
                stateFile: path.join(loadDir, '.out', 'azure-run.json'),
                reportsDir: path.join(loadDir, 'reports'),
              },
            ),
        });
      } finally {
        for (const signal of STOP_SIGNALS) process.off(signal, stopped);
        release();
      }
    },
  );
}

/** How a runner is stopped by hand: Ctrl+C, Ctrl+Break, a closed console window, or a kill. */
const STOP_SIGNALS = ['SIGINT', 'SIGBREAK', 'SIGHUP', 'SIGTERM'] as const;

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
