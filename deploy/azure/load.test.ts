// The load test's run on Azure (D2c, load.ts), against a stand-in for Azure
// that keeps what a real one would: each load job's request, its runs and
// their lines in the workspace, the API's revision and its restart, the
// database's size, and which jobs are left. Nothing here reaches Azure.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import { jobName, LOAD_JOBS, type LoadJob, type LogLine } from './jobs.ts';
import { load, type LoadSteps, NO_REQUEST, parseArguments, printedLines } from './load.ts';

const SUBSCRIPTION = '6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b';
const WORKSPACE_ID = '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d';
const LOAD_IMAGE = `ghcr.io/shahbaz242630/agent-x-load@sha256:${'c'.repeat(64)}`;
const RELEASE = 'd'.repeat(40);

const AMPLE = {
  kind: 'ample',
  orgId: 'org-a',
  agentId: 'agent-a',
  sourceId: 's-a',
  supplierIds: ['p-a'],
  monthlyLimitMinor: '2000000',
};
const CAPPED = { ...AMPLE, kind: 'capped', orgId: 'org-c', agentId: 'agent-c', monthlyLimitMinor: '10000' };

/** k6's summary of a phase, as money-paths.k6.js prints it. */
const summary = (phase: number, created: number) => ({
  event: 'load.k6_summary',
  phase,
  requests: created + 2,
  created,
  serverErrors: 0,
  rateLimited: 0,
  checksFailed: 0,
  dropped: 0,
  asksMs: { p50: 20, p95: 80, p99: 120, max: 300 },
  spikeMs: phase === 2 ? { p50: 200, p95: 400, max: 500 } : null,
  thresholds: { 'checks rate==1': true },
});

/** One agent as job.ts prints it once seeded: under `agent`, without its key. */
const seededLine = (agent: Readonly<Record<string, unknown>>) => ({ event: 'load.seeded_agent', runId: 'r', agent });

/** What a job prints for the request it was started with: its lines, and how its run ends. */
type Behaviour = (request: Readonly<Record<string, string>>) => { status: string; lines: unknown[] };

const DEFAULTS: Readonly<Record<LoadJob, Behaviour>> = {
  'load-first': () => ({
    status: 'Succeeded',
    lines: [seededLine(AMPLE), seededLine(CAPPED), summary(1, 2)],
  }),
  'load-second': () => ({
    status: 'Succeeded',
    lines: [
      summary(2, 1),
      { event: 'load.checked', created: 3, finished: true, checks: [{ name: 'recorded', problems: [] }] },
      { event: 'load.cleaned', organizations: 2, problems: [] },
    ],
  }),
  'load-cleanup': () => ({ status: 'Succeeded', lines: [{ event: 'load.cleaned', organizations: 2, problems: [] }] }),
};

/** The API's own lines over a clean run: three decisions and the holdings check at the restart. */
const API_LINES = [
  { level: 'info', event: 'holdings_check.passed', requests: 2, mismatched: 0, tampered: 0 },
  ...[30, 40, 50].map((durationMs) => ({ level: 'info', event: 'spend_request.decided', durationMs, orgId: 'org-a' })),
];

interface World {
  cpus?: number;
  fewest?: number;
  image?: string;
  behaviour?: Partial<Record<LoadJob, Behaviour>>;
  apiLines?: readonly unknown[];
  /** A run of this job still going when the run starts. */
  going?: LoadJob;
  startRefused?: LoadJob;
  /** This job's runs never end, while it says so. */
  timesOut?: LoadJob | undefined;
  /** Azure refuses {} put back on this job. */
  putBackRefused?: LoadJob;
  /** The API's replicas never change after a restart. */
  restartIgnored?: boolean;
  /** How many readings of the API's lines find none yet: they arrive late. */
  apiLinesLate?: number;
}

const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

/** Azure as load.ts sees it, kept as a real one would keep it. */
class FakeAzure implements Az {
  readonly calls: string[] = [];
  /** Each job's request as it now holds it, and every request it was given in turn. */
  readonly requests = new Map<LoadJob, string>(LOAD_JOBS.map((job) => [job, NO_REQUEST]));
  readonly written: { job: LoadJob; value: string }[] = [];
  /** Each run: its job, the request it started with, and what it printed. */
  readonly runs: { name: string; job: LoadJob; request: Record<string, string>; status: string; lines: unknown[] }[] =
    [];
  readonly restarted: string[] = [];
  readonly deleted: LoadJob[] = [];
  apiReadings = 0;
  readonly #modified = new Map<LoadJob, number>(LOAD_JOBS.map((job) => [job, 0]));
  readonly #world: World;

  constructor(world: World = {}) {
    this.#world = world;
  }

  /** The world changed mid-test: a run that had gone on ends, say. */
  set(change: World): void {
    Object.assign(this.#world, change);
  }

  interactive(): number | null {
    throw new Error('load.ts never runs the CLI interactively');
  }

  run(args: readonly string[]): AzResult {
    this.calls.push(args.join(' '));
    if (args[0] === 'account') return json({ name: 'Azure subscription 1', id: SUBSCRIPTION });
    if (args[0] === 'rest') return this.#rest(args);
    const name = args[args.indexOf('--name') + 1] ?? '';
    const job = LOAD_JOBS.find((each) => jobName(each) === name);
    if (job === undefined) throw new Error(`unexpected az ${args.join(' ')}`);
    switch (args.slice(0, 4).join(' ')) {
      case 'containerapp job execution list':
        return json(this.#world.going === job ? [{ name: `${name}-old1`, properties: { status: 'Running' } }] : []);
      case `containerapp job start --subscription`:
        return this.#start(job, name);
      case 'containerapp job execution show': {
        const run = this.runs.find((each) => each.name === args[args.indexOf('--job-execution-name') + 1]);
        const going = run?.job === this.#world.timesOut;
        return json({
          properties: {
            status: going ? 'Running' : run?.status,
            startTime: '2026-10-27T10:00:00+00:00',
            endTime: going ? null : '2026-10-27T10:05:00+00:00',
          },
        });
      }
      default:
        throw new Error(`unexpected az ${args.join(' ')}`);
    }
  }

  #start(job: LoadJob, name: string): AzResult {
    if (this.#world.startRefused === job) return { status: 1, stdout: '', stderr: 'ERROR: Bad Request' };
    const request = JSON.parse(this.requests.get(job) ?? NO_REQUEST) as Record<string, string>;
    const { status, lines } = (this.#world.behaviour?.[job] ?? DEFAULTS[job])(request);
    const run = { name: `${name}-r${String(this.runs.length + 1)}`, job, request, status, lines };
    this.runs.push(run);
    return json({ name: run.name });
  }

  #rest(args: readonly string[]): AzResult {
    const method = args[args.indexOf('--method') + 1];
    const url = args[args.indexOf('--url') + 1] ?? '';
    const job = LOAD_JOBS.find((each) => url.includes(`/Microsoft.App/jobs/${jobName(each)}?`));
    if (job !== undefined) return this.#jobRest(job, method, args);
    if (url.includes('/containerApps/ca-agentx-stg-api/revisions/api--r7/restart')) {
      this.restarted.push('api--r7');
      return json({});
    }
    if (url.includes('/containerApps/ca-agentx-stg-api/revisions/api--r7/replicas?')) {
      // A restart restarts the replica's container: its count moves on, unless the world says it never does.
      const restarts = this.#world.restartIgnored === true ? 0 : this.restarted.length;
      return json({
        value: [
          { name: 'api--r7-6f9c', properties: { runningState: 'Running', containers: [{ restartCount: restarts }] } },
        ],
      });
    }
    if (url.includes('/containerApps/ca-agentx-stg-api?')) return json(this.#api());
    if (url.includes('/flexibleServers?')) {
      return json({ value: [{ sku: { name: 'Standard_B1ms', tier: 'Burstable' } }] });
    }
    if (url.includes('/workspaces/log-agentx-stg?')) return json({ properties: { customerId: WORKSPACE_ID } });
    if (url.endsWith(`/workspaces/${WORKSPACE_ID}/query`)) return json(this.#query(args));
    throw new Error(`unexpected az ${args.join(' ')}`);
  }

  /** A load job read, its request written, or the job removed, by Resource Manager. */
  #jobRest(job: LoadJob, method: string | undefined, args: readonly string[]): AzResult {
    if (method === 'delete') {
      this.deleted.push(job);
      return json({});
    }
    if (method !== 'patch') {
      if (this.deleted.includes(job)) return { status: 3, stdout: '', stderr: 'ERROR: Not Found' };
      return json(this.#job(job));
    }
    const body = readFileSync((args[args.indexOf('--body') + 1] ?? '').slice(1), 'utf8');
    const secrets = (
      JSON.parse(body) as { properties: { configuration: { secrets: { name: string; value?: string }[] } } }
    ).properties.configuration.secrets;
    expect(secrets.filter((secret) => secret.name !== 'load-request')).toEqual(this.#references(job));
    const value = secrets.find((secret) => secret.name === 'load-request')?.value ?? '';
    if (value === NO_REQUEST && this.#world.putBackRefused === job) {
      return {
        status: 1,
        stdout: '',
        stderr: 'ERROR: Conflict({"error":{"code":"ContainerAppOperationInProgress"}})',
      };
    }
    this.requests.set(job, value);
    this.written.push({ job, value });
    this.#modified.set(job, (this.#modified.get(job) ?? 0) + 1);
    return json({});
  }

  #references(job: LoadJob) {
    return [
      {
        name: 'db-app-password',
        keyVaultUrl: 'https://kv.vault.azure.net/secrets/db-app-password',
        identity: `id-${job}`,
      },
    ];
  }

  #job(job: LoadJob) {
    return {
      properties: {
        provisioningState: 'Succeeded',
        configuration: { replicaTimeout: 1800, secrets: [...this.#references(job), { name: 'load-request' }] },
        template: {
          containers: [
            {
              name: job,
              image: this.#world.image ?? LOAD_IMAGE,
              command: ['node', 'tooling/load/job.ts'],
              args: [job.replace(/^load-/, '')],
            },
          ],
        },
      },
      systemData: { lastModifiedAt: `2026-10-27T09:00:0${String(this.#modified.get(job) ?? 0)}Z` },
    };
  }

  #api() {
    return {
      properties: {
        latestRevisionName: 'api--r7',
        template: {
          scale: { minReplicas: this.#world.fewest ?? 1 },
          containers: [
            { resources: { cpu: this.#world.cpus ?? 2 }, env: [{ name: 'AGENTX_RELEASE', value: RELEASE }] },
          ],
        },
      },
    };
  }

  /** A run's lines (the container's, and the platform's end), or the API's over the run. */
  #query(args: readonly string[]) {
    const { query } = JSON.parse(args[args.indexOf('--body') + 1] ?? '{}') as { query: string };
    if (query.includes("ContainerAppName == 'ca-agentx-stg-api'")) {
      this.apiReadings += 1;
      const late = this.apiReadings <= (this.#world.apiLinesLate ?? 0);
      return {
        tables: [
          {
            columns: [{ name: 'Log' }],
            rows: late ? [] : (this.#world.apiLines ?? API_LINES).map((line) => [JSON.stringify(line)]),
          },
        ],
      };
    }
    const run = this.runs.find((each) => query.includes(`'${each.name}-'`));
    const rows: LogLine[] = [
      ...(run?.lines ?? []).map((line) => ({
        time: '2026-10-27T10:01:00Z',
        source: 'stdout',
        reason: '',
        text: JSON.stringify(line),
      })),
      { time: '2026-10-27T10:00:30Z', source: 'stdout', reason: '', text: 'k6 progress, not JSON' },
      { time: '2026-10-27T10:05:00Z', source: 'platform', reason: 'ContainerTerminated', text: 'ended' },
    ];
    return {
      tables: [
        {
          columns: ['TimeGenerated', 'Source', 'Reason', 'Text'].map((name) => ({ name })),
          rows: rows.map((row) => [row.time, row.source, row.reason, row.text]),
        },
      ],
    };
  }
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'agentx-azure-load-test-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** load.ts against `az`, every wait instant but moving the clock on as long, and each reading a second. */
async function run(argv: readonly string[], az: FakeAzure) {
  const said: string[] = [];
  let clock = Date.parse('2026-10-27T10:00:00Z');
  const steps: LoadSteps = {
    az,
    say: (line) => said.push(line),
    now: () => {
      clock += 1000;
      return new Date(clock);
    },
    sleep: (ms) => {
      clock += ms;
      return Promise.resolve();
    },
    stateFile: path.join(dir, '.out', 'azure-run.json'),
    reportsDir: path.join(dir, 'reports'),
  };
  let error: unknown;
  let status: number | undefined;
  try {
    status = await load(parseArguments(argv), steps);
  } catch (caught) {
    error = caught;
  }
  const reports = existsSync(steps.reportsDir) ? readdirSync(steps.reportsDir) : [];
  return { status, error, said, steps, reports };
}

describe('the command line', () => {
  it('takes run, run --smoke, status and finish, and nothing else', () => {
    expect(parseArguments(['run'])).toEqual({ command: 'run', smoke: false });
    expect(parseArguments(['run', '--smoke'])).toEqual({ command: 'run', smoke: true });
    expect(parseArguments(['status'])).toEqual({ command: 'status' });
    expect(parseArguments(['finish'])).toEqual({ command: 'finish' });
    for (const argv of [
      [],
      ['go'],
      ['run', '--fast'],
      ['run', '--smoke', '--smoke'],
      ['status', 'now'],
      ['finish', 'x'],
    ]) {
      expect(() => parseArguments(argv)).toThrow(/say run, status or finish|takes only --smoke|takes nothing/);
    }
  });
});

describe('a run', () => {
  it('runs both phases with the restart between, each request written first and {} put back, and writes the report', async () => {
    const az = new FakeAzure();
    const done = await run(['run'], az);
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    const [first, second] = az.runs;
    expect(first?.job).toBe('load-first');
    expect(first?.request).toEqual({ AGENTX_LOAD_RUN_ID: expect.stringMatching(/^azure-20261027T\d{6}Z$/) as unknown });
    // The second job is handed the agents as the first printed them, never a key, and phase 1's count.
    expect(second?.request).toEqual({
      AGENTX_LOAD_RUN_ID: first?.request.AGENTX_LOAD_RUN_ID,
      AGENTX_LOAD_SEEDED: JSON.stringify([AMPLE, CAPPED]),
      AGENTX_LOAD_CREATED_FIRST: '2',
    });
    expect(az.written.map(({ job, value }) => `${job} ${value === NO_REQUEST ? '{}' : 'request'}`)).toEqual([
      'load-first request',
      'load-first {}',
      'load-second request',
      'load-second {}',
    ]);
    expect([...az.requests.values()]).toEqual([NO_REQUEST, NO_REQUEST, NO_REQUEST]);
    // The restart comes after the first run's lines are read and before the second job starts.
    const restart = az.calls.findIndex((call) => call.includes('/revisions/api--r7/restart'));
    const secondStart = az.calls.findIndex(
      (call) => call.startsWith('containerapp job start') && call.includes('load-second'),
    );
    expect(restart).toBeGreaterThan(az.calls.findIndex((call) => call.includes('/query')));
    expect(restart).toBeLessThan(secondStart);
    expect(done.reports).toEqual(['2026-10-27-azure-2cpu.md']);
    const report = readFileSync(path.join(done.steps.reportsDir, done.reports[0] ?? ''), 'utf8');
    expect(report).toContain('**Passed.**');
    expect(report).toContain(`Commit \`${RELEASE.slice(0, 7)}\``);
    expect(report).toContain('the database Standard_B1ms (Burstable)');
    // Cleaned up, so no run is left open.
    expect(existsSync(done.steps.stateFile)).toBe(false);
  });

  it("asks the jobs for the wiring run's short k6 with --smoke, and judges it on its wiring alone", async () => {
    // At staging's own size, with a slow decision that would fail a real run.
    const slow = [
      ...API_LINES.slice(0, 3),
      { level: 'info', event: 'spend_request.decided', durationMs: 900, orgId: 'org-a' },
    ];
    const az = new FakeAzure({ cpus: 0.5, apiLines: slow });
    const done = await run(['run', '--smoke'], az);
    expect(done.status).toBe(0);
    expect(az.runs.map((each) => each.request.AGENTX_LOAD_SMOKE)).toEqual(['1', '1']);
    expect(done.reports).toEqual(['2026-10-27-azure-0.5cpu-smoke.md']);
    const report = readFileSync(path.join(done.steps.reportsDir, done.reports[0] ?? ''), 'utf8');
    expect(report).toContain('its numbers measure nothing');
    expect(report).toContain('**Passed.**');
  });

  it("fails a real run on its numbers: a slow decision, a warning in the API's log", async () => {
    const lines = [
      ...API_LINES.slice(0, 3),
      { level: 'warn', event: 'db.transaction_retried' },
      { level: 'info', event: 'spend_request.decided', durationMs: 900, orgId: 'org-a' },
    ];
    const done = await run(['run'], new FakeAzure({ apiLines: lines }));
    expect(done.status).toBe(1);
    const report = readFileSync(path.join(done.steps.reportsDir, done.reports[0] ?? ''), 'utf8');
    expect(report).toContain('The API logged db.transaction_retried 1 time(s)');
    expect(report).toContain("A decision's p95 was 900 ms");
  });

  it("names what the database checks and the clean-up found, and keeps the run open when the clean-up didn't finish", async () => {
    const az = new FakeAzure({
      behaviour: {
        'load-second': () => ({
          status: 'Failed',
          lines: [
            summary(2, 1),
            { event: 'load.checked', checks: [{ name: 'one claim an order', problems: ['Order X has two.'] }] },
            { event: 'load.cleaned', problems: ['Org org-c still has a key.'] },
          ],
        }),
      },
    });
    const done = await run(['run'], az);
    expect(done.status).toBe(1);
    const report = readFileSync(path.join(done.steps.reportsDir, done.reports[0] ?? ''), 'utf8');
    expect(report).toContain('- load-second ended Failed.');
    expect(report).toContain('- one claim an order: Order X has two.');
    expect(report).toContain('The clean-up left work undone: Org org-c still has a key. Run load.ts finish.');
    expect(report).toContain('The database after the run: failed');
    expect(JSON.parse(readFileSync(done.steps.stateFile, 'utf8'))).toMatchObject({ agents: [AMPLE, CAPPED] });
  });

  it('stops after a first job that refused, saying why, keeps what it seeded to clean up, and never restarts the API', async () => {
    const az = new FakeAzure({
      behaviour: {
        'load-first': () => ({
          status: 'Failed',
          lines: [seededLine(AMPLE), { event: 'load.refused', reason: 'hand-offs are running' }],
        }),
      },
    });
    const done = await run(['run'], az);
    expect(done.error).toMatchObject({
      message:
        "Phase 1 didn't finish (load-first ended Failed: hand-offs are running). Run load.ts finish to clean up its organisations.",
    });
    expect(az.restarted).toEqual([]);
    expect(az.runs).toHaveLength(1);
    expect(JSON.parse(readFileSync(done.steps.stateFile, 'utf8'))).toMatchObject({ agents: [AMPLE] });
    expect(az.requests.get('load-first')).toBe(NO_REQUEST);
  });

  it("waits for the API's lines that arrive late, and counts them all", async () => {
    const az = new FakeAzure({ apiLinesLate: 3 });
    const done = await run(['run'], az);
    expect(done.status).toBe(0);
    expect(az.apiReadings).toBeGreaterThan(4);
  });

  it("stops before phase 2 when the API's replicas haven't restarted 10 minutes after the restart", async () => {
    const az = new FakeAzure({ restartIgnored: true });
    const done = await run(['run'], az);
    expect(done.error).toMatchObject({
      message: "The API's revision api--r7 wasn't running again 10 minutes after its restart.",
    });
    expect(az.runs.map(({ job }) => job)).toEqual(['load-first']);
  });

  it("keeps the run open with load-first's run named when it doesn't end in time, for finish to read and clean up", async () => {
    const az = new FakeAzure({ timesOut: 'load-first' });
    const done = await run(['run'], az);
    expect(done.error).toMatchObject({ message: expect.stringMatching(/r1 didn't end in time/) as unknown });
    expect(az.requests.get('load-first')).toBe(NO_REQUEST);
    const open = JSON.parse(readFileSync(done.steps.stateFile, 'utf8')) as Record<string, unknown>;
    expect(open).toMatchObject({ firstRun: 'job-agentx-stg-load-first-r1', agents: [] });
    // Once it has ended, finish reads what it seeded and cleans that up.
    az.set({ timesOut: undefined });
    const finished = await run(['finish'], az);
    expect(finished.status).toBe(0);
    expect(az.runs.at(-1)).toMatchObject({
      job: 'load-cleanup',
      request: { AGENTX_LOAD_SEEDED: JSON.stringify([AMPLE, CAPPED]) },
    });
    expect(az.deleted).toEqual([...LOAD_JOBS]);
  });

  it('says {} could not be put back after a good phase 1, and keeps its agents to clean up', async () => {
    const az = new FakeAzure({ putBackRefused: 'load-first' });
    const done = await run(['run'], az);
    expect(done.error).toMatchObject({
      message:
        "{} wasn't put back on job-agentx-stg-load-first (Azure refused putting {} back on job-agentx-stg-load-first (Conflict, ContainerAppOperationInProgress). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it.): apps --load-run deploys it back. Run load.ts finish to clean up its organisations.",
    });
    expect(az.restarted).toEqual([]);
    expect(JSON.parse(readFileSync(done.steps.stateFile, 'utf8'))).toMatchObject({ agents: [AMPLE, CAPPED] });
  });

  it('says a first job that made nothing left nothing to clean up', async () => {
    const az = new FakeAzure({ behaviour: { 'load-first': () => ({ status: 'Failed', lines: [] }) } });
    const done = await run(['run'], az);
    expect(done.error).toMatchObject({
      message: "Phase 1 didn't finish (load-first ended Failed). It made no organisation.",
    });
    expect(existsSync(done.steps.stateFile)).toBe(false);
  });

  it('puts {} back on the job when its start is refused', async () => {
    const az = new FakeAzure({ startRefused: 'load-first' });
    const done = await run(['run'], az);
    expect(done.error).toBeInstanceOf(Error);
    expect(az.written.map(({ value }) => value === NO_REQUEST)).toEqual([false, true]);
  });

  it('starts nothing unless the API keeps a copy running at the load size, every job is idle, and no run is left open', async () => {
    const refusals: [World, RegExp][] = [
      [{ fewest: 0 }, /keeps no copy running.*--keep-running/],
      [{ cpus: 0.5 }, /runs at 0.5 CPUs, not the load run's 2/],
      [{ going: 'load-second' }, /job-agentx-stg-load-second has runs still going/],
      [{ image: `ghcr.io/shahbaz242630/agent-x@sha256:${'c'.repeat(64)}` }, /doesn't run the load image by digest/],
    ];
    for (const [world, message] of refusals) {
      const az = new FakeAzure(world);
      const done = await run(['run'], az);
      expect(done.error).toMatchObject({ message: expect.stringMatching(message) as unknown });
      expect(az.written).toEqual([]);
      expect(az.runs).toEqual([]);
    }
    mkdirSync(path.join(dir, '.out'), { recursive: true });
    writeFileSync(path.join(dir, '.out', 'azure-run.json'), '{}');
    const open = await run(['run'], new FakeAzure());
    expect(open.error).toMatchObject({
      message: expect.stringMatching(/A run is still open.*load.ts finish first/) as unknown,
    });
  });
});

describe('finish', () => {
  it('cleans up a run left open with its own agents, then removes the three jobs', async () => {
    mkdirSync(path.join(dir, '.out'), { recursive: true });
    writeFileSync(
      path.join(dir, '.out', 'azure-run.json'),
      JSON.stringify({ runId: 'azure-x', smoke: false, agents: [AMPLE] }),
    );
    const az = new FakeAzure();
    const done = await run(['finish'], az);
    expect(done.status).toBe(0);
    expect(az.runs.map(({ job, request }) => [job, request])).toEqual([
      ['load-cleanup', { AGENTX_LOAD_RUN_ID: 'azure-x', AGENTX_LOAD_SEEDED: JSON.stringify([AMPLE]) }],
    ]);
    expect(az.deleted).toEqual([...LOAD_JOBS]);
    expect(existsSync(done.steps.stateFile)).toBe(false);
    expect(done.said.at(-1)).toMatch(/^Next: apps \(without --load-run\)/);
  });

  it('does nothing while a run of a load job is still going', async () => {
    mkdirSync(path.join(dir, '.out'), { recursive: true });
    writeFileSync(
      path.join(dir, '.out', 'azure-run.json'),
      JSON.stringify({ runId: 'azure-x', smoke: false, agents: [AMPLE] }),
    );
    const az = new FakeAzure({ going: 'load-second' });
    const done = await run(['finish'], az);
    expect(done.error).toMatchObject({
      message: expect.stringMatching(/^job-agentx-stg-load-second has runs still going .*wait for them/) as unknown,
    });
    expect(az.runs).toEqual([]);
    expect(az.deleted).toEqual([]);
  });

  it('removes an open run that seeded nothing, then the jobs', async () => {
    mkdirSync(path.join(dir, '.out'), { recursive: true });
    writeFileSync(
      path.join(dir, '.out', 'azure-run.json'),
      JSON.stringify({ runId: 'azure-x', smoke: false, agents: [] }),
    );
    const az = new FakeAzure();
    const done = await run(['finish'], az);
    expect(done.status).toBe(0);
    expect(done.said).toContain('Run azure-x seeded no organisation: nothing to clean up.');
    expect(az.runs).toEqual([]);
    expect(existsSync(done.steps.stateFile)).toBe(false);
    expect(az.deleted).toEqual([...LOAD_JOBS]);
  });

  it('removes the jobs straight away when no run is left open', async () => {
    const az = new FakeAzure();
    expect((await run(['finish'], az)).status).toBe(0);
    expect(az.runs).toEqual([]);
    expect(az.deleted).toEqual([...LOAD_JOBS]);
  });

  it('keeps the jobs and the open run when the clean-up leaves work undone', async () => {
    mkdirSync(path.join(dir, '.out'), { recursive: true });
    writeFileSync(
      path.join(dir, '.out', 'azure-run.json'),
      JSON.stringify({ runId: 'azure-x', smoke: false, agents: [AMPLE] }),
    );
    const az = new FakeAzure({
      behaviour: {
        'load-cleanup': () => ({ status: 'Succeeded', lines: [{ event: 'load.cleaned', problems: ['a key left'] }] }),
      },
    });
    const done = await run(['finish'], az);
    expect(done.error).toMatchObject({
      message: expect.stringMatching(/didn't finish.*a key left.*The jobs are kept/) as unknown,
    });
    expect(az.deleted).toEqual([]);
    expect(existsSync(done.steps.stateFile)).toBe(true);
  });
});

describe('status', () => {
  it('says which jobs are there, the API and database sizes, and whether a run is open, changing nothing', async () => {
    const az = new FakeAzure({ fewest: 0, cpus: 0.5 });
    az.deleted.push('load-cleanup');
    const done = await run(['status'], az);
    expect(done.said.slice(1)).toEqual([
      '  job-agentx-stg-load-first: there',
      '  job-agentx-stg-load-second: there',
      '  job-agentx-stg-load-cleanup: not there',
      '  The API: 0.5 CPUs, scales to zero.',
      '  The database: Standard_B1ms (Burstable).',
      '  No run is left open.',
    ]);
    expect(az.written).toEqual([]);
  });
});

describe("a job's own lines", () => {
  it("takes the load test's JSON lines from the container, never the platform's or another program's", () => {
    const line = (source: string, text: string): LogLine => ({ time: '', source, reason: '', text });
    expect(
      printedLines([
        line('stdout', '{"event":"load.seeded","agents":2}'),
        line('platform', '{"event":"load.refused"}'),
        line('stdout', '{"event":"http.request_completed"}'),
        line('stderr', 'not JSON'),
        line('stdout', '[1,2]'),
      ]),
    ).toEqual([{ event: 'load.seeded', agents: 2 }]);
  });
});
