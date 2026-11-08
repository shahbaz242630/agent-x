// Stage G's runner (stage-g.ts) against a stand-in for what it asks of Azure
// (stage-g-azure.ts): the servers, the jobs' runs and lines, the API's
// replicas, a step's lines in the workspace. Nothing here reaches Azure.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { StepWindow } from '../../tooling/load/stageg-background.ts';
import { stagesSeconds, type StepRun } from '../../tooling/load/stageg.ts';
import { throwawayHost } from '../../tooling/load/throwaway.ts';
import type { Ended, StageGJob } from './jobs.ts';
import type { JobRun, RunOptions } from './load-jobs.ts';
import type { Metric, StageGAzure, StagingServer } from './stage-g-azure.ts';
import { holdRunnerLock, offendersOf, parseArguments, randomCopyId, stageG, type StageGSteps, uae } from './stage-g.ts';

const ID = 'abcd1234';
const COPY = `psql-agentx-stg-g-${ID}`;
const STAGING: StagingServer = {
  id: '/subscriptions/s/resourceGroups/rg-agentx-staging/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-agentx-stg-q1w2e3',
  name: 'psql-agentx-stg-q1w2e3',
  subnet: '/subscriptions/s/.../subnets/database',
  privateDnsZone: '/subscriptions/s/.../privateDnsZones/agentx.postgres.database.azure.com',
};

type Printed = Record<string, unknown>;

/** What a job's run prints and how it ends, for the request it was given. */
type Behaviour = (
  request: Readonly<Record<string, unknown>> | undefined,
  at: Date,
) => { status: string; printed: Printed[] };

/** k6's numbers for a step, as stage-g.k6.js prints them, timed from `at`. */
function summaryOf(run: StepRun, at: Date, p95 = 40, extra: Printed = {}): Printed {
  const kind = { requests: 1000, serverErrors: 0, rateLimited: 0, failedAnswers: 0, p95Ms: p95 };
  return {
    event: 'load.stageg_summary',
    test: run.test,
    step: run.label,
    orgs: run.orgs,
    requests: 1000,
    created: 900,
    serverErrors: 0,
    rateLimited: 0,
    checksFailed: 0,
    dropped: 0,
    asksMs: { p50: 10, p95, p99: p95 + 20, max: p95 + 50 },
    kinds: { steady: kind, calm: kind },
    aborted: false,
    windows: null,
    startedAt: at.toISOString(),
    endedAt: new Date(at.getTime() + stagesSeconds(run) * 1000).toISOString(),
    ...extra,
  };
}

const stepOf = (request: Readonly<Record<string, unknown>> | undefined): StepRun =>
  JSON.parse(String((request?.command as string[])[1])) as StepRun;

const SEEDED = (request: Readonly<Record<string, unknown>> | undefined) => ({
  status: 'Succeeded',
  printed: [{ event: 'load.stageg_seeded', orgs: Number((request?.command as string[])[2]), incomplete: [] }],
});

const DEFAULT_STEP: Behaviour = (request, at) => {
  const command = request?.command as string[];
  if (command[0] === 'seed') return SEEDED(request);
  if (command[0] === 'pause')
    return { status: 'Succeeded', printed: [{ event: 'load.stageg_pause', outcome: 'paused' }] };
  const run = stepOf(request);
  return {
    status: 'Succeeded',
    printed: [summaryOf(run, at), { event: 'load.stageg_stepped', label: run.label, finished: true }],
  };
};

const BEHAVIOUR: Record<StageGJob, Behaviour> = {
  'load-mark': () => ({ status: 'Succeeded', printed: [{ event: 'load.stageg_marked', server: COPY }] }),
  'load-step': DEFAULT_STEP,
  'load-check': () => ({
    status: 'Succeeded',
    printed: [{ event: 'load.stageg_checked', checks: [{ name: 'no duplicate', failures: [] }] }],
  }),
};

/** The background's lines over a window that kept up: a pulse a minute, an anchor check, a line after from the replica. */
function healthyLog(window: StepWindow) {
  const from = Date.parse(window.from);
  const to = Date.parse(window.to);
  const line = (at: number, fields: Printed) => JSON.stringify({ time: new Date(at).toISOString(), ...fields });
  const lines = [];
  for (let at = from; at <= to + 120_000; at += 60_000) {
    lines.push({ replica: 'jobs--r1/j1', log: line(at, { level: 'info', event: 'jobs.pulse' }) });
  }
  lines.push({
    replica: 'jobs--r1/j1',
    log: line(from + 1000, { level: 'info', event: 'audit.anchor_check_done', failed: 0, unchecked: 0, left: 0 }),
  });
  lines.push({ replica: 'api--r1/rep1', log: line(to + 60_000, { level: 'info', event: 'http.request' }) });
  return lines;
}

interface World {
  servers?: string[];
  /** Readings of the copy before Azure has it Ready. */
  restoreReadings?: number;
  /** Readings of the jobs before they reach the copy (the partner's apps deploy). */
  appsReadings?: number;
  behaviour?: Partial<Record<StageGJob, Behaviour>>;
  /** Readings of a step's lines before they are all in; Infinity: never. */
  lateReadings?: number;
  /** The p95 each step label's summary gives. */
  p95?: Readonly<Record<string, number>>;
  /** The requests each step label's summary says k6 never sent. */
  dropped?: Readonly<Record<string, number>>;
  going?: Partial<Record<StageGJob, string[]>>;
  finishResult?: number;
  containers?: string[];
  refusedContainers?: string[];
  fewest?: number;
  hostOverride?: string;
  /** Readings after an HA change before Azure shows it done; Infinity: never. */
  haReadings?: number;
  /** High availability as Azure has it before this run asks any change. */
  haNow?: { mode: string; state: string };
  /** Readings after a stop before the run shows ended. */
  stopReadings?: number;
  /** Readings of a step's lines that Log Analytics answers only in part. */
  partialReadings?: number;
  /** Readings of a step's decisions that find none yet; Infinity: never. */
  noDecisionReadings?: number;
}

/** Azure as stage-g.ts asks it, kept as a real one would keep it. */
class FakeAzure implements StageGAzure {
  readonly subscription = '6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b';
  readonly restores: { copy: string; source: StagingServer; at: string }[] = [];
  readonly resized: string[] = [];
  readonly deleted: string[] = [];
  readonly stopped: string[] = [];
  readonly runs: { job: StageGJob; request: Readonly<Record<string, unknown>> | undefined; options: RunOptions }[] = [];
  readonly removedContainers: string[] = [];
  readonly ha: { mode: string; readings: number }[] = [];
  readonly decisionOffenders: (readonly string[] | undefined)[] = [];
  servers_: string[];
  #decisionReadings = 0;
  #stopsLeft = 0;
  #stateReadings = 0;
  #appsReadings = 0;
  #logReadings = 0;
  readonly world: World;
  readonly now: () => Date;

  constructor(world: World, now: () => Date) {
    this.world = world;
    this.servers_ = [STAGING.name, ...(world.servers ?? [])];
    this.now = now;
  }

  servers() {
    return [...this.servers_];
  }
  stagingServer() {
    return STAGING;
  }
  restore(copy: string, source: StagingServer, at: string) {
    this.restores.push({ copy, source, at });
    this.servers_.push(copy);
  }
  serverState(name: string) {
    if (!this.servers_.includes(name)) return undefined;
    this.#stateReadings += 1;
    return this.#stateReadings > (this.world.restoreReadings ?? 0) ? 'Ready' : 'Restoring';
  }
  resize(name: string) {
    this.resized.push(name);
  }
  connectionLimit() {
    return { limit: this.resized.length > 0 ? 100 : 50, waiting: false };
  }
  deleteServer(name: string) {
    this.deleted.push(name);
    this.servers_ = this.servers_.filter((each) => each !== name);
  }
  jobHost() {
    if (this.world.hostOverride !== undefined) return this.world.hostOverride;
    this.#appsReadings += 1;
    return this.#appsReadings > (this.world.appsReadings ?? 0) ? throwawayHost(COPY) : undefined;
  }
  runsGoing(job: StageGJob) {
    if (this.stopped.length > 0 && this.#stopsLeft > 0) {
      this.#stopsLeft -= 1;
      return this.#stopsLeft === 0 ? [] : [`${this.stopped[0] ?? ''} (Stopping)`];
    }
    return this.stopped.length > 0 ? [] : (this.world.going?.[job] ?? []);
  }
  stopRun(_job: StageGJob, run: string) {
    this.stopped.push(run);
    this.#stopsLeft = this.world.stopReadings ?? 0;
  }
  setHa(_name: string, mode: string) {
    this.ha.push({ mode, readings: 0 });
  }
  haOf() {
    const asked = this.ha.at(-1);
    if (asked === undefined) return this.world.haNow ?? { mode: 'Disabled', state: 'NotEnabled' };
    asked.readings += 1;
    const done = asked.readings > (this.world.haReadings ?? 0);
    if (asked.mode === 'ZoneRedundant') {
      return { mode: 'ZoneRedundant', state: done ? 'Healthy' : 'CreatingStandby' };
    }
    return done ? { mode: 'Disabled', state: 'NotEnabled' } : { mode: 'ZoneRedundant', state: 'RemovingStandby' };
  }
  runJob(job: StageGJob, options: RunOptions): Promise<JobRun> {
    this.runs.push({ job, request: options.request, options });
    const at = this.now();
    const done = (this.world.behaviour?.[job] ?? BEHAVIOUR[job])(options.request, at);
    let { printed } = done;
    if (job === 'load-step' && (options.request?.command as string[])[0] === 'step') {
      const label = stepOf(options.request).label;
      const p95 = this.world.p95?.[label];
      const dropped = this.world.dropped?.[label];
      if (p95 !== undefined || dropped !== undefined) {
        printed = printed.map((line) =>
          line.event === 'load.stageg_summary'
            ? summaryOf(stepOf(options.request), at, p95, dropped === undefined ? {} : { dropped })
            : line,
        );
      }
    }
    const run: Ended = { status: done.status, began: at.toISOString(), ended: at.toISOString() };
    return Promise.resolve({ run, printed, putBack: undefined });
  }
  api() {
    return { cpus: 2, fewest: this.world.fewest ?? 3, revision: 'api--r1', release: 'd'.repeat(40) };
  }
  replicas() {
    return [{ name: 'rep1', restarts: 0 }];
  }
  stepLog(window: StepWindow) {
    this.#logReadings += 1;
    if (this.#logReadings <= (this.world.partialReadings ?? 0)) {
      throw new Error(
        'Log Analytics answered only in part (PartialError: query limits), so its lines can not be taken.',
      );
    }
    const lines = healthyLog(window);
    // Late: the replica's line after the step hasn't come in yet.
    return this.#logReadings <= (this.world.lateReadings ?? 0)
      ? lines.filter(({ replica }) => replica !== 'api--r1/rep1')
      : lines;
  }
  decisionP95(_window: StepWindow, offenders?: readonly string[]) {
    this.decisionOffenders.push(offenders);
    this.#decisionReadings += 1;
    return this.#decisionReadings <= (this.world.noDecisionReadings ?? 0) ? null : 50;
  }
  lastReading(metric: Metric) {
    return metric === 'memory' ? 900 : 40;
  }
  anchorContainers() {
    return this.world.containers ?? [];
  }
  deleteContainer(_account: string, container: string) {
    if (this.world.refusedContainers?.includes(container) === true) return false;
    this.removedContainers.push(container);
    return true;
  }
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'agentx-stage-g-test-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const stateFile = () => path.join(dir, '.out', 'stage-g.json');
/** The runner's state file, as much of it as the tests read. */
interface Kept {
  readonly copy?: {
    readonly server: string;
    readonly ha?: boolean;
    readonly marked: boolean;
    readonly paused: boolean;
    readonly seededTo: number;
    readonly since?: string;
    readonly last: { readonly test: string; readonly label: string; readonly verdict: string };
    readonly breakingRate?: number;
    readonly targetP95Ms?: number;
    readonly tests: Readonly<
      Record<string, { readonly results: readonly { readonly run: StepRun; readonly baseDecisionP95Ms?: number }[] }>
    >;
  };
  readonly anchors: readonly { readonly container: string }[];
}
const readStateFile = () => JSON.parse(readFileSync(stateFile(), 'utf8')) as Kept;
const keptCopy = () => {
  const { copy } = readStateFile();
  if (copy === undefined) throw new Error('no copy kept');
  return copy;
};

/** A copy made and marked, as create leaves it. */
function markedCopy(extra: Record<string, unknown> = {}) {
  mkdirSync(path.dirname(stateFile()), { recursive: true });
  writeFileSync(
    stateFile(),
    JSON.stringify({
      copy: {
        server: COPY,
        id: ID,
        runId: `stage-g-${ID}`,
        createdAt: '2026-11-06T08:00:00.000Z',
        sized: true,
        marked: true,
        paused: true,
        seededTo: 0,
        incomplete: [],
        tests: {},
        ...extra,
      },
      anchors: [],
    }),
  );
}

async function run(argv: readonly string[], world: World = {}, more: Partial<StageGSteps> = {}) {
  const said: string[] = [];
  let clock = Date.parse('2026-11-06T10:00:00Z');
  const now = () => {
    clock += 1000;
    return new Date(clock);
  };
  const azure = new FakeAzure(world, now);
  let finished = 0;
  const steps: StageGSteps = {
    az: { interactive: () => 0, run: () => ({ status: 0, stdout: '', stderr: '' }) },
    say: (line) => said.push(line),
    now,
    sleep: (ms) => {
      clock += ms;
      return Promise.resolve();
    },
    azure,
    stateFile: stateFile(),
    reportsDir: path.join(dir, 'reports'),
    copyDir: path.join(dir, 'documents'),
    randomId: () => ID,
    finishLoad: () => {
      finished += 1;
      return Promise.resolve(world.finishResult ?? 0);
    },
    ...more,
  };
  let code: number | undefined;
  let error: unknown;
  try {
    code = await stageG(parseArguments(argv), steps);
  } catch (caught) {
    error = caught;
  }
  return { code, error, said, text: said.join('\n'), azure, finished: () => finished };
}

const commands = (azure: FakeAzure) =>
  azure.runs.map(({ job, request }) => `${job} ${request === undefined ? '' : (request.command as string[])[0]}`);

describe('the command line', () => {
  it('takes each command and refuses anything else', () => {
    expect(parseArguments(['create'])).toEqual({ command: 'create' });
    expect(parseArguments(['status'])).toEqual({ command: 'status' });
    expect(parseArguments(['run', 'orgs'])).toEqual({ command: 'run', test: 'orgs' });
    expect(parseArguments(['run', 'orgs', '--from', 'orgs-1000'])).toEqual({
      command: 'run',
      test: 'orgs',
      from: 'orgs-1000',
    });
    expect(parseArguments(['delete'])).toEqual({ command: 'delete' });
    expect(parseArguments(['delete', COPY])).toEqual({ command: 'delete', name: COPY });
    expect(parseArguments(['delete', '--anchors'])).toEqual({ command: 'anchors' });
    for (const wrong of [
      [],
      ['make'],
      ['create', 'now'],
      ['run'],
      ['run', 'everything'],
      ['run', 'orgs', '--to', 'x'],
      ['run', 'orgs', '--from'],
      ['run', 'orgs', '--from', 'a', 'b'],
      ['delete', '--all'],
      ['delete', 'a', 'b'],
    ]) {
      expect(() => parseArguments(wrong)).toThrow(/./);
    }
  });

  it('makes IDs of 8 lower-case letters or digits, and says times in UAE', () => {
    expect(randomCopyId(Buffer.from([0, 25, 26, 35, 36, 61, 255, 7]))).toBe('az09azdh');
    expect(randomCopyId()).toMatch(/^[a-z0-9]{8}$/);
    expect(uae('2026-11-06T10:00:00Z')).toBe('2026-11-06 14:00 UAE');
  });

  it('names the neighbours offenders: the first two whole heavy organisations', () => {
    const all = offendersOf({ runId: 'r', incomplete: [] }, 1000);
    expect(all).toHaveLength(2);
    expect(offendersOf({ runId: 'r', incomplete: [1] }, 1000)[0]).toBe(all[1]);
  });
});

describe('create', () => {
  it('restores staging to a copy by name, sizes it, waits for the apps, then marks it', async () => {
    const done = await run(['create'], { restoreReadings: 2, appsReadings: 4 });
    expect(done.error).toBeUndefined();
    expect(done.code).toBe(0);
    expect(done.azure.restores).toEqual([
      { copy: COPY, source: STAGING, at: expect.stringMatching(/^2026-11-06T09:5\d:\d\d\.000Z$/) as unknown },
    ]);
    expect(done.azure.resized).toEqual([COPY]);
    expect(done.text).toContain(`node deploy/azure/deploy.ts apps --load-run --keep-running --load-database ${COPY}`);
    expect(commands(done.azure)).toEqual(['load-mark ', 'load-step pause']);
    expect(keptCopy()).toMatchObject({ server: COPY, runId: `stage-g-${ID}`, sized: true, marked: true, paused: true });
    expect(done.said[0]).toContain('node deploy/azure/operator.ts handoff-pause --reason <case reference>');
    expect(done.text).toContain('node deploy/azure/stage-g.ts run smoke');
  });

  it("refuses a copy made with staging's hand-offs running: remove it, pause staging, make it again", async () => {
    const unpaused: Behaviour = () => ({
      status: 'Failed',
      printed: [{ event: 'load.stageg_pause', outcome: 'running' }],
    });
    const done = await run(['create'], { behaviour: { 'load-step': unpaused } });
    expect(String(done.error)).toContain("The copy's hand-offs are running, not paused");
    expect(String(done.error)).toContain('node deploy/azure/stage-g.ts delete');
    expect(String(done.error)).toContain('node deploy/azure/operator.ts handoff-pause --reason <case reference>');
    expect(keptCopy()).toMatchObject({ marked: true, paused: false });
    expect(String((await run(['run', 'smoke'])).error)).toContain('No marked and paused Stage G copy');

    // Run again, it reads the pause again without marking twice; a refused read says the job's own words.
    const again = await run(['create'], {
      servers: [COPY],
      behaviour: {
        'load-step': () => ({ status: 'Failed', printed: [{ event: 'load.stageg_refused', reason: 'no sentinel' }] }),
      },
    });
    expect(commands(again.azure)).toEqual(['load-step pause']);
    expect(String(again.error)).toContain('unread (load-step ended Failed: no sentinel)');
  });

  it('refuses when a copy it does not keep is there already', async () => {
    const done = await run(['create'], { servers: ['psql-agentx-stg-g-zzzz9999'] });
    expect(String(done.error)).toContain('psql-agentx-stg-g-zzzz9999');
    expect(done.azure.restores).toEqual([]);
  });

  it('refuses an ID that would not fit the name rule', async () => {
    const done = await run(['create'], {}, { randomId: () => 'UPPER' });
    expect(String(done.error)).toContain("isn't a throwaway copy's name");
    expect(done.azure.restores).toEqual([]);
  });

  it('refuses a second copy once one is made and marked', async () => {
    markedCopy();
    const done = await run(['create']);
    expect(String(done.error)).toContain('already made, marked and paused');
  });

  it('carries on with a copy kept before it was marked, restoring nothing again', async () => {
    markedCopy({ marked: false, sized: false });
    const done = await run(['create'], { servers: [COPY] });
    expect(done.code).toBe(0);
    expect(done.azure.restores).toEqual([]);
    expect(done.text).toContain(`Carrying on with ${COPY}`);
  });

  it('says to run create again when the restore, the resize or the apps never come', async () => {
    const slow = await run(['create'], { restoreReadings: Number.POSITIVE_INFINITY });
    expect(String(slow.error)).toContain("wasn't ready 90 minutes");
    rmSync(stateFile());
    const noApps = await run(['create'], { appsReadings: Number.POSITIVE_INFINITY });
    expect(String(noApps.error)).toContain("weren't reaching");
  });

  it("stops when load-mark doesn't mark the copy, with the job's own reason", async () => {
    const done = await run(['create'], {
      behaviour: {
        'load-mark': () => ({ status: 'Failed', printed: [{ event: 'load.stageg_refused', reason: 'not a copy' }] }),
      },
    });
    expect(String(done.error)).toContain('load-mark ended Failed: not a copy');
    expect(keptCopy().marked).toBe(false);
  });
});

describe('run', () => {
  it('runs the smoke test: the seed, the step, the checks, the lines judged, and the report', async () => {
    markedCopy();
    mkdirSync(path.join(dir, 'documents'));
    const done = await run(['run', 'smoke']);
    expect(done.error).toBeUndefined();
    expect(done.code).toBe(0);
    expect(commands(done.azure)).toEqual(['load-step seed', 'load-step step', 'load-check check']);
    const seed = done.azure.runs[0]?.request;
    expect(seed).toEqual({ runId: `stage-g-${ID}`, command: ['seed', '--to', '100'] });
    const check = done.azure.runs[2]?.request?.command as string[];
    expect(JSON.parse(check[2] ?? '{}')).toMatchObject({ created: 900 });
    const state = keptCopy();
    expect(state.seededTo).toBe(100);
    expect(state.since).toEqual(expect.any(String));
    expect(state.last).toMatchObject({ test: 'smoke', label: 'smoke', verdict: 'passed' });
    const [report] = readdirSync(path.join(dir, 'reports'));
    expect(report).toBe('2026-11-06-stageg-smoke.md');
    expect(readdirSync(path.join(dir, 'documents'))).toEqual([report]);
    expect(readFileSync(path.join(dir, 'reports', report ?? ''), 'utf8')).toContain('**Passed: every step.**');
  });

  it('runs the seed again while a run ends before it is done, and stops when it refuses', async () => {
    markedCopy();
    let seeds = 0;
    const done = await run(['run', 'smoke'], {
      behaviour: {
        'load-step': (request, at) => {
          if ((request?.command as string[])[0] !== 'seed') return DEFAULT_STEP(request, at);
          seeds += 1;
          return seeds < 3 ? { status: 'Failed', printed: [] } : SEEDED(request);
        },
      },
    });
    expect(done.code).toBe(0);
    expect(commands(done.azure).filter((each) => each === 'load-step seed')).toHaveLength(3);

    rmSync(stateFile());
    markedCopy();
    const refused = await run(['run', 'smoke'], {
      behaviour: {
        'load-step': () => ({ status: 'Failed', printed: [{ event: 'load.stageg_refused', reason: 'no sentinel' }] }),
      },
    });
    expect(refused.code).toBe(1);
    expect(refused.text).toContain('The seed refused: no sentinel');
    expect(refused.text).toContain('run smoke --from smoke');
    expect(keptCopy().last.verdict).toBe('stopped');
  });

  it('gives up on a seed that never finishes, saying so', async () => {
    markedCopy();
    const done = await run(['run', 'smoke'], {
      behaviour: { 'load-step': () => ({ status: 'Failed', printed: [] }) },
    });
    expect(done.code).toBe(1);
    expect(done.text).toContain("hadn't reached 100 organisations after 12 runs");
  });

  it('skips a seed already grown, and stops the climb at its first failed step', async () => {
    markedCopy({ seededTo: 10_000 });
    const done = await run(['run', 'orgs'], { p95: { 'orgs-100': 40, 'orgs-1000': 80 }, dropped: { 'orgs-1000': 12 } });
    expect(done.code).toBe(1);
    expect(commands(done.azure)).toEqual(['load-step step', 'load-check check', 'load-step step', 'load-check check']);
    expect(done.text).toContain('node deploy/azure/stage-g.ts run orgs --from orgs-1000');
    expect(keptCopy().last).toMatchObject({ label: 'orgs-1000', verdict: 'failed' });
    const [report] = readdirSync(path.join(dir, 'reports'));
    expect(readFileSync(path.join(dir, 'reports', report ?? ''), 'utf8')).toContain('**Failed at step orgs-1000.**');

    // Fixed: --from resumes at that step, the earlier step's numbers still its baseline.
    const resumed = await run(['run', 'orgs', '--from', 'orgs-1000'], {
      p95: { 'orgs-1000': 42, 'orgs-3000': 43, 'orgs-10000': 44 },
    });
    expect(resumed.error).toBeUndefined();
    expect(resumed.code).toBe(0);
    expect(commands(resumed.azure)).toHaveLength(6);
    const reports = readdirSync(path.join(dir, 'reports'));
    expect(reports).toEqual(['2026-11-06-stageg-orgs-2.md', '2026-11-06-stageg-orgs.md']);
    const text = readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-orgs-2.md'), 'utf8');
    expect(text).toContain('Baseline: the first step, orgs-100, p95 40.0 ms');
    expect(text).toContain('**Passed: every step.**');
  });

  it('refuses --from a step that is not there, or whose earlier steps never ran', async () => {
    markedCopy({ seededTo: 10_000 });
    expect(String((await run(['run', 'orgs', '--from', 'orgs-7'])).error)).toContain('orgs has no step orgs-7');
    expect(String((await run(['run', 'orgs', '--from', 'orgs-3000'])).error)).toContain("haven't all run on this copy");
  });

  it('waits on a step not judged yet, then says so without calling it failed', async () => {
    markedCopy();
    const waited = await run(['run', 'smoke'], { lateReadings: 3 });
    expect(waited.code).toBe(0);
    expect(waited.text).toContain('still reaching the workspace');

    rmSync(stateFile());
    markedCopy();
    const never = await run(['run', 'smoke'], { lateReadings: Number.POSITIVE_INFINITY });
    expect(never.code).toBe(1);
    expect(never.text).toContain("couldn't be judged");
    expect(never.text).toContain('Nothing is called failed');
    expect(keptCopy().last.verdict).toBe('not-judged-yet');
  });

  it('keeps a step not judged while Log Analytics answers only in part, then judges it', async () => {
    markedCopy();
    const done = await run(['run', 'smoke'], { partialReadings: 2 });
    expect(done.code).toBe(0);
    expect(done.text).toContain('still reaching the workspace');

    rmSync(stateFile());
    markedCopy();
    const never = await run(['run', 'smoke'], { partialReadings: Number.POSITIVE_INFINITY });
    expect(never.code).toBe(1);
    const report = readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-smoke-2.md'), 'utf8');
    expect(report).toContain('a whole answer from the workspace: Log Analytics answered only in part');
  });

  it('never reads no decision line as 0 ms: the step stays not judged until they come', async () => {
    markedCopy();
    const late = await run(['run', 'smoke'], { noDecisionReadings: 2 });
    expect(late.code).toBe(0);

    rmSync(stateFile());
    markedCopy();
    const never = await run(['run', 'smoke'], { noDecisionReadings: Number.POSITIVE_INFINITY });
    expect(never.code).toBe(1);
    expect(keptCopy().last.verdict).toBe('not-judged-yet');
    const report = readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-smoke-2.md'), 'utf8');
    expect(report).toContain('smoke: no decision lines read yet from the step');
  });

  it('refuses the overload without a breaking rate, and the neighbours without the target', async () => {
    markedCopy();
    expect(String((await run(['run', 'overload'])).error)).toContain('run "breaking" first');
    expect(String((await run(['run', 'neighbours'])).error)).toContain('run "target" first');
  });

  it('records the breaking rate, then sizes the overload from it', async () => {
    markedCopy({ seededTo: 10_000 });
    const climbed = await run(['run', 'breaking'], {
      behaviour: {
        'load-step': (request, at) => {
          const step = stepOf(request);
          const windows = Array.from({ length: 80 }, (_, window) => ({
            window,
            p95Ms: window < 70 ? 50 : 600,
            failedShare: 0,
            refusedShare: 0,
            requests: 100,
          }));
          return {
            status: 'Failed',
            printed: [
              summaryOf(step, at, 40, { windows, aborted: true }),
              { event: 'load.stageg_stepped', finished: false },
            ],
          };
        },
      },
    });
    expect(climbed.error).toBeUndefined();
    const rate = keptCopy().breakingRate ?? 0;
    expect(rate).toBeGreaterThan(170);
    await run(['run', 'overload']);
    const sent = keptCopy().tests.overload?.results[0]?.run;
    expect(Math.max(...(sent?.stages ?? []).map(({ target }) => target))).toBe(Math.round(rate * 1.5));
  });

  it("fails a step its rules pass when its job didn't end well or hand-offs weren't paused", async () => {
    markedCopy();
    const done = await run(['run', 'smoke'], {
      behaviour: {
        'load-step': (request, at) =>
          (request?.command as string[])[0] === 'seed'
            ? SEEDED(request)
            : {
                status: 'Failed',
                printed: [summaryOf(stepOf(request), at), { event: 'load.stageg_stepped', notPaused: 'one org' }],
              },
        'load-check': () => ({ status: 'Failed', printed: [] }),
      },
    });
    expect(done.code).toBe(1);
    const report = readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-smoke.md'), 'utf8');
    expect(report).toContain('smoke: load-step ended Failed.');
    expect(report).toContain("Hand-offs weren't paused after the step: one org.");
    expect(report).toContain('smoke: load-check ended Failed.');
  });

  it('runs a soak segment cut off once more, and says so; a second cut stops the climb', async () => {
    markedCopy({ seededTo: 10_000 });
    let soak2 = 0;
    const done = await run(['run', 'soak'], {
      behaviour: {
        'load-step': (request, at) => {
          if (stepOf(request).label === 'soak-2' && (soak2 += 1) === 1) return { status: 'Failed', printed: [] };
          return DEFAULT_STEP(request, at);
        },
      },
    });
    expect(done.error).toBeUndefined();
    expect(done.code).toBe(0);
    const report = readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-soak.md'), 'utf8');
    expect(report).toContain('soak-2: interrupted (load-step ended Failed) and run again once.');
    expect(report).toContain("The API's memory (MB): 900");

    const twice = await run(['run', 'soak', '--from', 'soak-2'], {
      behaviour: {
        'load-step': (request, at) =>
          stepOf(request).label === 'soak-2' ? { status: 'Failed', printed: [] } : DEFAULT_STEP(request, at),
      },
    });
    expect(twice.code).toBe(1);
    expect(twice.text).toContain('Step soak-2 gave no numbers (load-step ended Failed)');
  });

  it('records the target p95, and runs the neighbours against it, offenders apart', async () => {
    markedCopy({ seededTo: 10_000 });
    const target = await run(['run', 'target']);
    expect(target.code).toBe(0);
    expect(keptCopy().targetP95Ms).toBe(40);
    expect(target.azure.decisionOffenders.every((given) => given?.length === 0)).toBe(true);
    const neighbours = await run(['run', 'neighbours']);
    expect(neighbours.code).toBe(0);
    // The decisions' p95 is the calm traffic's: the busy and stuck organisations' own are left out (S178).
    const offenders = offendersOf({ runId: `stage-g-${ID}`, incomplete: [] }, 10_000);
    expect(offenders).toHaveLength(2);
    expect(neighbours.azure.decisionOffenders.filter((given) => given !== undefined)).toContainEqual(offenders);
    expect(readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-neighbours.md'), 'utf8')).toContain(
      'Baseline: the target step, p95 40.0 ms',
    );
  });

  it('runs a spike with its base hold read apart', async () => {
    markedCopy({ seededTo: 10_000 });
    const done = await run(['run', 'spike']);
    expect(done.error).toBeUndefined();
    expect(keptCopy().tests.spike?.results[0]?.baseDecisionP95Ms).toBe(50);
  });

  it('refuses to run without a marked copy, with jobs elsewhere, runs going, or the API asleep', async () => {
    expect(String((await run(['run', 'smoke'])).error)).toContain('create first');
    markedCopy();
    expect(String((await run(['run', 'smoke'], { hostOverride: 'psql-agentx-stg-q1w2e3.x' })).error)).toContain(
      "don't all reach",
    );
    expect(String((await run(['run', 'smoke'], { going: { 'load-step': ['r1 (Running)'] } })).error)).toContain(
      'runs still going',
    );
    expect(String((await run(['run', 'smoke'], { fewest: 0 })).error)).toContain('keeps no copy running');
  });
});

describe('high availability for the ha test', () => {
  it('turns it on and waits until Healthy before the first step, and turns it off before any other test', async () => {
    markedCopy({ seededTo: 10_000 });
    const ha = await run(['run', 'ha'], { haReadings: 3 });
    expect(ha.error).toBeUndefined();
    expect(ha.azure.ha).toEqual([{ mode: 'ZoneRedundant', readings: 4 }]);
    expect(ha.text.indexOf('standby is healthy')).toBeLessThan(ha.text.indexOf('Step ha:'));
    expect(keptCopy().ha).toBe(true);
    expect(readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-ha.md'), 'utf8')).toContain(
      'high availability on, zone-redundant',
    );

    const target = await run(['run', 'target'], { haReadings: 2 });
    expect(target.error).toBeUndefined();
    expect(target.azure.ha).toEqual([{ mode: 'Disabled', readings: 3 }]);
    expect(target.text.indexOf('turning it off')).toBeLessThan(target.text.indexOf('Step target:'));
    expect(keptCopy().ha).toBe(false);
    expect(readFileSync(path.join(dir, 'reports', '2026-11-06-stageg-target.md'), 'utf8')).toContain(
      'high availability off',
    );
  });

  it('gives up honestly when HA never comes up, running nothing, and waits again on the next run', async () => {
    markedCopy({ seededTo: 10_000 });
    const never = await run(['run', 'ha'], { haReadings: Number.POSITIVE_INFINITY });
    expect(String(never.error)).toContain("high availability wasn't on and healthy an hour on: nothing ran");
    expect(never.azure.runs).toEqual([]);
    expect(keptCopy().ha).toBe(true);
    const again = await run(['run', 'ha'], { haNow: { mode: 'ZoneRedundant', state: 'Healthy' } });
    expect(again.azure.ha).toEqual([]);
    expect(again.code).toBe(0);
    const off = await run(['run', 'smoke'], { haReadings: Number.POSITIVE_INFINITY });
    expect(String(off.error)).toContain("high availability wasn't off an hour on");
  });
});

describe('status', () => {
  it('says the copy, its jobs, the last step and its verdict', async () => {
    markedCopy({
      last: { test: 'smoke', label: 'smoke', verdict: 'passed', at: '2026-11-06T09:00:00Z' },
      breakingRate: 400,
    });
    const done = await run(['status'], { servers: [COPY], going: { 'load-step': ['r9 (Running)'] } });
    expect(done.code).toBe(0);
    expect(done.text).toContain(`The copy: ${COPY}`);
    expect(done.text).toContain('load-step: reaching the copy, runs going: r9 (Running).');
    expect(done.text).toContain('The last step: smoke smoke, passed, at 2026-11-06 13:00 UAE.');
    expect(done.text).toContain('The breaking rate: 400');

    const elsewhere = await run(['status'], { hostOverride: 'other.host' });
    expect(elsewhere.text).toContain('reaching other.host, not the copy');
    expect(elsewhere.text).toContain('it is not there');
  });

  it('says when no copy is kept, and the anchors still waiting', async () => {
    mkdirSync(path.dirname(stateFile()), { recursive: true });
    writeFileSync(
      stateFile(),
      JSON.stringify({
        anchors: [{ container: 'audit-anchors-g-aaaa1111', server: 'x', lockedUntil: '2026-11-09T10:00:00Z' }],
      }),
    );
    const done = await run(['status']);
    expect(done.text).toContain('No Stage G copy is kept');
    expect(done.text).toContain('audit-anchors-g-aaaa1111 kept until 2026-11-09 14:00 UAE');
  });
});

describe('delete', () => {
  it("refuses any name but a copy's, staging's own above all, removing nothing", async () => {
    markedCopy();
    for (const name of [STAGING.name, 'psql-agentx-stg-drill', 'psql-agentx-stg-g-short']) {
      const done = await run(['delete', name], { servers: [COPY] });
      expect(String(done.error)).toContain("isn't a throwaway copy's name");
      expect(done.azure.deleted).toEqual([]);
      expect(done.finished()).toBe(0);
    }
  });

  it('stops the jobs, removes them and the copy, keeps its anchors for later and says the lines to run', async () => {
    markedCopy();
    const done = await run(['delete'], {
      servers: [COPY],
      going: { 'load-step': ['job-agentx-stg-load-step-x1 (Running)'] },
    });
    expect(done.error).toBeUndefined();
    expect(done.azure.stopped).toEqual(['job-agentx-stg-load-step-x1']);
    expect(done.finished()).toBe(1);
    expect(done.azure.deleted).toEqual([COPY]);
    const state = readStateFile();
    expect(state.copy).toBeUndefined();
    expect(state.anchors).toEqual([
      {
        container: `audit-anchors-g-${ID}`,
        server: COPY,
        lockedUntil: expect.stringMatching(/^2026-11-09T11:/) as unknown,
      },
    ]);
    expect(done.text).toContain('node deploy/azure/deploy.ts apps\n');
    expect(done.text).toContain('node deploy/azure/operator.ts handoff-resume --reason <case reference>');
    expect(done.text).toContain('delete --anchors');
  });

  it('waits for a stopped run to end before removing the jobs, and gives up after 10 minutes', async () => {
    markedCopy();
    const going = { 'load-step': ['job-agentx-stg-load-step-x1 (Running)'] };
    const done = await run(['delete'], { servers: [COPY], going, stopReadings: 3 });
    expect(done.error).toBeUndefined();
    expect(done.finished()).toBe(1);
    expect(done.azure.deleted).toEqual([COPY]);

    markedCopy();
    const stuck = await run(['delete'], { servers: [COPY], going, stopReadings: Number.POSITIVE_INFINITY });
    expect(String(stuck.error)).toContain('still going 10 minutes after it was stopped');
    expect(stuck.finished()).toBe(0);
    expect(stuck.azure.deleted).toEqual([]);
  });

  it('removes another copy by name without touching the load jobs of the one kept', async () => {
    markedCopy();
    const other = 'psql-agentx-stg-g-zzzz9999';
    const done = await run(['delete', other], { servers: [COPY, other] });
    expect(done.code).toBe(0);
    expect(done.finished()).toBe(0);
    expect(done.azure.deleted).toEqual([other]);
    expect(keptCopy().server).toBe(COPY);
    expect(done.text).not.toContain('put staging back');
  });

  it('stops when the load jobs are not removed, and needs a name with no copy kept', async () => {
    markedCopy();
    const done = await run(['delete'], { servers: [COPY], finishResult: 1 });
    expect(String(done.error)).toContain("weren't all removed");
    expect(done.azure.deleted).toEqual([]);
    rmSync(stateFile());
    expect(String((await run(['delete'])).error)).toContain('name the copy');
    const named = await run(['delete', 'psql-agentx-stg-g-zzzz9999']);
    expect(named.code).toBe(0);
    expect(named.azure.deleted).toEqual([]);
  });

  it('removes only the anchors containers whose copy is gone and whose time is up', async () => {
    mkdirSync(path.dirname(stateFile()), { recursive: true });
    const anchors = [
      {
        container: 'audit-anchors-g-aaaa1111',
        server: 'psql-agentx-stg-g-aaaa1111',
        lockedUntil: '2026-11-01T00:00:00Z',
      },
      {
        container: 'audit-anchors-g-bbbb2222',
        server: 'psql-agentx-stg-g-bbbb2222',
        lockedUntil: '2026-12-01T00:00:00Z',
      },
      {
        container: 'audit-anchors-g-cccc3333',
        server: 'psql-agentx-stg-g-cccc3333',
        lockedUntil: '2026-11-01T00:00:00Z',
      },
      {
        container: 'audit-anchors-g-dddd4444',
        server: 'psql-agentx-stg-g-dddd4444',
        lockedUntil: '2026-11-01T00:00:00Z',
      },
      {
        container: 'audit-anchors-g-eeee5555',
        server: 'psql-agentx-stg-g-eeee5555',
        lockedUntil: '2026-11-01T00:00:00Z',
      },
      { container: 'audit-anchors', server: STAGING.name, lockedUntil: '2026-11-01T00:00:00Z' },
    ];
    writeFileSync(stateFile(), JSON.stringify({ anchors }));
    const done = await run(['delete', '--anchors'], {
      servers: ['psql-agentx-stg-g-cccc3333'],
      containers: ['audit-anchors', ...anchors.slice(0, 4).map(({ container }) => container)],
      refusedContainers: ['audit-anchors-g-dddd4444'],
    });
    expect(done.azure.removedContainers).toEqual(['audit-anchors-g-aaaa1111']);
    expect(done.code).toBe(1);
    expect(readStateFile().anchors.map(({ container }: { container: string }) => container)).toEqual([
      'audit-anchors-g-bbbb2222',
      'audit-anchors-g-cccc3333',
      'audit-anchors-g-dddd4444',
    ]);
    expect(done.text).toContain('audit-anchors-g-eeee5555 is already gone');
    expect(done.text).toContain("audit-anchors isn't a copy's anchors container");
  });
});

describe('one runner at a time', () => {
  it('refuses while another runner holds the lock, takes over a dead one’s, and gives it back (S178)', () => {
    const lock = path.join(mkdtempSync(path.join(tmpdir(), 'stage-g-lock-')), '.out', 'stage-g.lock');
    // This test's own process is running, so a lock naming it is held.
    mkdirSync(path.dirname(lock), { recursive: true });
    writeFileSync(lock, String(process.pid));
    expect(() => holdRunnerLock(lock, 4_000_000_001)).toThrow(
      `Another Stage G runner is going (process ${String(process.pid)})`,
    );
    // Windows reuses process IDs: the refusal names the file, to delete when no runner is open.
    expect(() => holdRunnerLock(lock, 4_000_000_001)).toThrow(`If no Stage G runner is open, delete ${lock}`);
    // A runner no longer running: its lock is taken over, and given back by this one alone.
    writeFileSync(lock, '0');
    const release = holdRunnerLock(lock, 4_000_000_001);
    expect(readFileSync(lock, 'utf8')).toBe('4000000001');
    release();
    expect(existsSync(lock)).toBe(false);
    const mine = holdRunnerLock(lock, 4_000_000_002);
    writeFileSync(lock, '4000000003');
    mine();
    expect(readFileSync(lock, 'utf8')).toBe('4000000003');
  });
});
