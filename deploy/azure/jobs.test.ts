// The job runner (G3a). Nothing here reaches Azure: the CLI is a stand-in that
// answers from a script and records each call, and time moves only when the
// runner sleeps, so a wait of many minutes runs at once.
import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import {
  cleanupContainers,
  type Job,
  jobName,
  JOBS,
  JOBS_API,
  jobs,
  main,
  parseArguments,
  type Request,
  USAGE,
  UsageError,
  WORKSPACE,
} from './jobs.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000b';
const WORKSPACE_ID = '00000000-0000-0000-0000-00000000000c';
const START = new Date('2026-09-17T05:46:30Z');

/** A row of the log query: when, where from, the platform's reason, the text. */
type Row = readonly [string, string, string, string];

const TERMINATED: Row = [
  '2026-09-17T05:47:12.6002662Z',
  'platform',
  'ContainerTerminated',
  "Container 'db-setup' was terminated with exit code '0' and reason 'ProcessExited'",
];
const CREATED: Row = [
  '2026-09-17T05:46:43.8217382Z',
  'platform',
  'SuccessfulCreate',
  "Successfully created pod for Job Execution 'job-agentx-stg-db-setup-o2jp673'",
];
const line = (event: string): Row => ['2026-09-17T05:47:12.4133012Z', 'stdout', '', `{"event":"${event}"}`];

/** What a finished run's log holds once it has all arrived. */
const WHOLE_LOG: readonly Row[] = [CREATED, line('db-setup.done'), TERMINATED];

/**
 * Names assembled from their words, so no test line pairs a secret's name with
 * a quoted value: the shape GitGuardian reads as a password (PRs #27 and #28).
 */
const setting = (...words: readonly string[]): string => words.join('_');
const secret = (...words: readonly string[]): string => words.join('-');

/** The setup job's container as `job show` gives it (S20), with made-up values. */
const SETUP_CONTAINER = {
  name: 'zitadel-setup',
  image: `ghcr.io/zitadel/zitadel:v4.17.3@sha256:${'d'.repeat(64)}`,
  command: ['/app/zitadel'],
  args: ['setup', '--masterkeyFile', '/mnt/secrets/zitadel-masterkey'],
  env: [
    { name: 'ZITADEL_DATABASE_POSTGRES_HOST', value: 'db.example.invalid' },
    {
      name: setting('ZITADEL', 'DATABASE', 'POSTGRES', 'USER', 'PASSWORD'),
      secretRef: secret('db', 'zitadel', 'password'),
    },
    { name: 'ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_ADDRESS', value: 'admin@example.invalid' },
    {
      name: setting('ZITADEL', 'FIRSTINSTANCE', 'ORG', 'HUMAN', 'PASSWORD'),
      secretRef: secret('zitadel', 'admin', 'password'),
    },
  ],
  resources: { cpu: 0.5, memory: '1Gi', ephemeralStorage: '' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
  probes: [],
};

/** What the clean-up run is started with: the same container, `setup cleanup` its arguments, nothing it can't take. */
const CLEANUP_CONTAINER = {
  name: 'zitadel-setup',
  image: SETUP_CONTAINER.image,
  command: ['/app/zitadel'],
  args: ['setup', 'cleanup'],
  env: SETUP_CONTAINER.env,
  resources: { cpu: 0.5, memory: '1Gi' },
};

const CLEANUP_URL = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/jobs/job-agentx-stg-zitadel-setup/start?api-version=2026-01-01`;

interface Script {
  /** The subscription ID `account show` gives. */
  readonly subscription?: unknown;
  /** What `job show` gives as the time limit, or the whole answer's failure. */
  readonly limit?: unknown;
  readonly notDeployed?: boolean;
  /** The job's runs, as `execution list` gives them. */
  readonly runs?: unknown;
  /** The name `job start` gives the new run. */
  readonly started?: string;
  /** The states `execution show` gives, one per reading, the last one repeated. */
  readonly states?: readonly string[];
  readonly startTime?: string;
  readonly endTime?: string;
  /** The workspace's ID, as Resource Manager gives it. */
  readonly workspace?: unknown;
  /** The log query's rows, one list per reading, the last one repeated; or a whole answer of another shape. */
  readonly logs?: readonly (readonly Row[])[];
  readonly logAnswer?: unknown;
  /** The containers `job show` gives; the setup job's by default. */
  readonly containers?: unknown;
  /** How Resource Manager answers a start with other containers: its status, and what it prints. */
  readonly startStatus?: number;
  readonly startAnswer?: string;
}

/** An Azure CLI that answers from the script and records every call. */
class ScriptedAz implements Az {
  readonly calls: (readonly string[])[] = [];
  readonly #script: Script;
  #readings = 0;
  #logReadings = 0;

  constructor(script: Script = {}) {
    this.#script = script;
  }

  interactive(): number | null {
    throw new Error('the job runner never runs the CLI interactively');
  }

  run(args: readonly string[]): AzResult {
    this.calls.push(args);
    const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
    const script = this.#script;
    if (args[0] === 'rest' && args[args.indexOf('--url') + 1]?.includes('/Microsoft.App/jobs/') === true) {
      expect(args.slice(0, 5)).toEqual(['rest', '--method', 'post', '--url', CLEANUP_URL]);
      if (script.startStatus !== undefined && script.startStatus !== 0) {
        return {
          status: script.startStatus,
          stdout: '',
          stderr: 'ERROR: Bad Request({"error":{"code":"InvalidParameter"}})',
        };
      }
      return {
        status: 0,
        stdout:
          script.startAnswer ??
          JSON.stringify({ id: '/subscriptions/x', name: 'job-agentx-stg-zitadel-setup-c1e2a3n' }),
        stderr: '',
      };
    }
    if (args[0] === 'rest') return json(this.#rest(args));
    const words = args.filter((arg) => !arg.startsWith('-')).slice(0, 4);
    switch (words.join(' ')) {
      case 'account show json':
        return json({
          name: 'Azure subscription 1',
          id: 'subscription' in script ? script.subscription : SUBSCRIPTION,
        });
      case `containerapp job show ${words[3] ?? ''}`:
        if (script.notDeployed === true) {
          return { status: 3, stdout: '', stderr: "ERROR: (ResourceNotFound) The Resource 'x' was not found." };
        }
        return json({
          name: args[args.indexOf('--name') + 1],
          properties: {
            configuration: { replicaTimeout: 'limit' in script ? script.limit : 900 },
            template: { containers: 'containers' in script ? script.containers : [SETUP_CONTAINER] },
          },
        });
      case 'containerapp job execution list':
        return json('runs' in script ? script.runs : [{ name: 'old', properties: { status: 'Succeeded' } }]);
      case `containerapp job start ${words[3] ?? ''}`:
        return json({ id: '/subscriptions/x', name: script.started ?? 'job-agentx-stg-db-setup-o2jp673' });
      case 'containerapp job execution show': {
        const states = script.states ?? ['Succeeded'];
        const state = states[Math.min(this.#readings, states.length - 1)];
        this.#readings += 1;
        return json({
          name: args[args.indexOf('--job-execution-name') + 1],
          properties: {
            status: state,
            startTime: script.startTime ?? '2026-09-17T05:46:43+00:00',
            endTime: script.endTime ?? '2026-09-17T05:47:21+00:00',
          },
        });
      }
      default:
        throw new Error(`unexpected az ${args.join(' ')}`);
    }
  }

  /** The workspace, by Resource Manager, and the log query. */
  #rest(args: readonly string[]): unknown {
    const script = this.#script;
    const url = args[args.indexOf('--url') + 1];
    if (args[2] === 'get') {
      expect(url).toBe(
        `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.OperationalInsights/workspaces/log-agentx-stg?api-version=2025-02-01`,
      );
      return { properties: { customerId: 'workspace' in script ? script.workspace : WORKSPACE_ID } };
    }
    expect(args.slice(0, 3)).toEqual(['rest', '--method', 'post']);
    expect(url).toBe(`https://api.loganalytics.azure.com/v1/workspaces/${WORKSPACE_ID}/query`);
    expect(args[args.indexOf('--resource') + 1]).toBe('https://api.loganalytics.io');
    if ('logAnswer' in script) return script.logAnswer;
    const readings = script.logs ?? [WHOLE_LOG];
    const rows = readings[Math.min(this.#logReadings, readings.length - 1)];
    this.#logReadings += 1;
    return {
      tables: [
        {
          name: 'PrimaryResult',
          columns: [
            { name: 'TimeGenerated', type: 'datetime' },
            { name: 'Source', type: 'string' },
            { name: 'Reason', type: 'string' },
            { name: 'Text', type: 'string' },
          ],
          rows,
        },
      ],
    };
  }

  /** The commands, by their first words, in the order they ran. */
  get sequence(): string[] {
    return this.calls.map((call) => call.slice(0, call[2] === 'execution' ? 4 : 3).join(' '));
  }

  /** What each log query asked for. */
  get queries(): { query: string; timespan: string }[] {
    return this.#bodies('/query') as { query: string; timespan: string }[];
  }

  /** What each start through Resource Manager sent. */
  get starts(): unknown[] {
    return this.#bodies('/start?');
  }

  #bodies(urlPart: string): unknown[] {
    return this.calls
      .filter((call) => call[2] === 'post' && call[4]?.includes(urlPart) === true)
      .map((call) => JSON.parse(call[call.indexOf('--body') + 1] ?? '') as unknown);
  }
}

/** One run of the runner, with a clock that moves only when it sleeps. */
async function run(argv: readonly string[], script: Script = {}) {
  const az = new ScriptedAz(script);
  const said: string[] = [];
  const slept: number[] = [];
  let now = START.getTime();
  const status = await jobs(parseArguments(argv), {
    az,
    say: (line) => said.push(line),
    now: () => new Date(now),
    sleep: (ms) => {
      slept.push(ms);
      now += ms;
      return Promise.resolve();
    },
  }).then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error }),
  );
  return { status: status.value, error: status.error, az, said, slept };
}

/** The lines a run's state was reported on. */
const stateLines = (said: readonly string[]): string[] => said.filter((line) => / UTC {2}/.test(line));

describe('parseArguments', () => {
  it('reads cleanup as being for the setup job alone', () => {
    expect(parseArguments(['cleanup'])).toEqual({ command: 'cleanup', job: 'zitadel-setup' });
  });

  it("reads the three ways the runner is used, for every job, and only waits for the operator's", () => {
    for (const job of JOBS) {
      if (job === 'operator') {
        // Started as deployed, it holds no request and refuses (B1c-2a).
        expect(() => parseArguments(['run', job])).toThrow(
          new UsageError(
            "the operator's job isn't run as it is deployed: it holds no request, and refuses; node deploy/azure/operator.ts writes one and runs it",
          ),
        );
        expect(() => parseArguments(['start', job])).toThrow(
          new UsageError(
            "the operator's job isn't started as it is deployed: it holds no request, and refuses; node deploy/azure/operator.ts writes one and runs it",
          ),
        );
      } else {
        expect(parseArguments(['run', job])).toEqual({ command: 'run', job });
        expect(parseArguments(['start', job])).toEqual({ command: 'start', job });
      }
      expect(parseArguments(['wait', job, `${jobName(job)}-o2jp673`])).toEqual({
        command: 'wait',
        job,
        execution: `${jobName(job)}-o2jp673`,
      });
    }
  });

  it('refuses anything else, saying why', () => {
    for (const [argv, reason] of [
      [[], /say run, start, wait or cleanup, not nothing/],
      [['stop', 'db-setup'], /say run, start, wait or cleanup, not stop/],
      [['cleanup', 'zitadel-setup'], /cleanup takes nothing: it is for zitadel-setup alone, not zitadel-setup$/],
      [['cleanup', 'db-setup', 'x'], /cleanup takes nothing: .* not db-setup x$/],
      [['run'], /nothing isn't a job: db-setup, migrate, zitadel-init, zitadel-setup/],
      [['run', 'setup'], /setup isn't a job/],
      [['run', 'job-agentx-stg-db-setup'], /isn't a job/],
      [['run', 'db-setup', 'migrate'], /run takes one job, not migrate as well/],
      [['start', 'db-setup', '--args'], /start takes one job/],
      [['wait', 'db-setup'], /wait takes the job and one of its runs, named job-agentx-stg-db-setup-<suffix>/],
      [['wait', 'db-setup', 'job-agentx-stg-migrate-o2jp673'], /one of its runs/],
      [['wait', 'db-setup', 'job-agentx-stg-db-setup-'], /one of its runs/],
      [['wait', 'db-setup', 'job-agentx-stg-db-setup-O2JP673'], /one of its runs/],
      [['wait', 'db-setup', 'job-agentx-stg-db-setup-o2jp673 --args'], /one of its runs/],
      [['wait', 'db-setup', "job-agentx-stg-db-setup-o2jp673'"], /one of its runs/],
      [['wait', 'db-setup', 'xjob-agentx-stg-db-setup-o2jp673'], /one of its runs/],
      [['wait', 'db-setup', 'job-agentx-stg-db-setup-o2jp673', 'more'], /one of its runs/],
    ] as const) {
      expect(() => parseArguments(argv)).toThrow(UsageError);
      expect(() => parseArguments(argv)).toThrow(reason);
    }
  });
});

describe('run', () => {
  it('checks the job is deployed and idle, starts it, waits for the run to succeed, and shows its log', async () => {
    const done = await run(['run', 'db-setup'], { states: ['Running', 'Running', 'Succeeded'] });
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'containerapp job show',
      'containerapp job execution list',
      'containerapp job start',
      'containerapp job execution show',
      'containerapp job execution show',
      'containerapp job execution show',
      'rest --method get',
      'rest --method post',
      'rest --method post',
    ]);
    // The subscription signed in to, named on every call.
    const naming = [
      '--subscription',
      SUBSCRIPTION,
      '--name',
      'job-agentx-stg-db-setup',
      '--resource-group',
      'rg-agentx-staging',
    ];
    for (const call of done.az.calls.slice(1, 7)) expect(call.join(' ')).toContain(naming.join(' '));
    expect(done.az.calls[6]).toEqual([
      'containerapp',
      'job',
      'execution',
      'show',
      ...naming,
      '--job-execution-name',
      'job-agentx-stg-db-setup-o2jp673',
      '--output',
      'json',
    ]);
    // A plain start: the job's own container, never arguments that would replace it.
    expect(done.az.calls[3]).toEqual(['containerapp', 'job', 'start', ...naming, '--output', 'json']);
    // The run's state every 15 s; its log again a minute later, when the first reading can't be the last.
    expect(done.slept).toEqual([15_000, 15_000, 60_000]);
    expect(done.said).toEqual([
      `Signed in to the subscription "Azure subscription 1" (${SUBSCRIPTION}).`,
      'Started job-agentx-stg-db-setup-o2jp673.',
      'Waiting for job-agentx-stg-db-setup-o2jp673 to end (the job gives up after 900 s)...',
      '  05:46:30 UTC  Running',
      '  05:47:00 UTC  Succeeded',
      'job-agentx-stg-db-setup-o2jp673 ended Succeeded: started 05:46:43 UTC, ended 05:47:21 UTC (38 s).',
      "Reading job-agentx-stg-db-setup-o2jp673's log: Azure delivers a container's lines up to 10 minutes after they are written, so this can take that long...",
      "job-agentx-stg-db-setup-o2jp673's log, 2 from the platform and 1 from the container:",
      "  05:46:43  platform  SuccessfulCreate: Successfully created pod for Job Execution 'job-agentx-stg-db-setup-o2jp673'",
      '  05:47:12  stdout    {"event":"db-setup.done"}',
      "  05:47:12  platform  ContainerTerminated: Container 'db-setup' was terminated with exit code '0' and reason 'ProcessExited'",
      'In a first deploy, the next is: node deploy/azure/jobs.ts run migrate',
    ]);
  });

  it("asks the workspace for this run's lines alone, from just before it started until just after now", async () => {
    const done = await run(['run', 'db-setup']);
    expect(done.az.queries).toEqual([
      {
        query: [
          'union',
          `(ContainerAppSystemLogs | where JobName == 'job-agentx-stg-db-setup' and (ReplicaName startswith_cs 'job-agentx-stg-db-setup-o2jp673-' or Log contains_cs "'job-agentx-stg-db-setup-o2jp673'") | project TimeGenerated, Source = 'platform', Reason, Text = Log),`,
          `(ContainerAppConsoleLogs | where JobName == 'job-agentx-stg-db-setup' and ContainerGroupName startswith_cs 'job-agentx-stg-db-setup-o2jp673-' | project TimeGenerated, Source = Stream, Reason = '', Text = Log)`,
          '| order by TimeGenerated asc',
        ].join('\n'),
        // Five minutes either side: of the start, and of the run's end or now, whichever is later.
        timespan: '2026-09-17T05:41:43.000Z/2026-09-17T05:52:21.000Z',
      },
      { query: expect.any(String) as unknown, timespan: '2026-09-17T05:41:43.000Z/2026-09-17T05:52:30.000Z' },
    ]);
  });

  it('names the next job in the order a first deploy runs them, and says when there is none', async () => {
    const next: string[] = [];
    for (const job of JOBS.filter((each) => each !== 'operator')) {
      const done = await run(['run', job], { started: `${jobName(job)}-abc1234` });
      expect(done.status).toBe(0);
      next.push(done.said.at(-1) ?? '');
    }
    // The operator's is no part of a first deploy.
    const operator = await run(['wait', 'operator', `${jobName('operator')}-abc1234`]);
    expect(operator.status).toBe(0);
    next.push(operator.said.at(-1) ?? '');
    expect(next).toEqual([
      'In a first deploy, the next is: node deploy/azure/jobs.ts run migrate',
      'In a first deploy, the next is: node deploy/azure/jobs.ts run zitadel-init',
      'In a first deploy, the next is: node deploy/azure/jobs.ts run zitadel-setup',
      'That is the last of the four a first deploy runs.',
      "The operator's request has run: the lines above say what it did.",
    ]);
  });

  it('ends with failure for every end but success, after showing the log', async () => {
    for (const state of ['Failed', 'Stopped', 'Degraded']) {
      const done = await run(['run', 'zitadel-init'], {
        started: 'job-agentx-stg-zitadel-init-k2m9x1q',
        states: ['Processing', state],
      });
      expect({ state, status: done.status }).toEqual({ state, status: 1 });
      expect(done.said).toContain(
        `job-agentx-stg-zitadel-init-k2m9x1q ended ${state}: started 05:46:43 UTC, ended 05:47:21 UTC (38 s).`,
      );
      expect(done.said.slice(-2)).toEqual([
        "  05:47:12  platform  ContainerTerminated: Container 'db-setup' was terminated with exit code '0' and reason 'ProcessExited'",
        'Read the lines above before starting anything else.',
      ]);
    }
  });

  it('keeps waiting through states that are not an end, a missing one included', async () => {
    const done = await run(['run', 'db-setup'], { states: ['', 'Unknown', 'Processing', 'Running', 'Succeeded'] });
    expect(done.status).toBe(0);
    expect(done.slept.filter((ms) => ms === 15_000)).toHaveLength(4);
    expect(stateLines(done.said)).toEqual([
      '  05:46:30 UTC  no state yet',
      '  05:46:45 UTC  Unknown',
      '  05:47:00 UTC  Processing',
      '  05:47:15 UTC  Running',
      '  05:47:30 UTC  Succeeded',
    ]);
  });

  it('gives up once the job has had its time limit and the start allowance, saying how to wait again, and reads no log', async () => {
    const done = await run(['run', 'db-setup'], { limit: 60, states: ['Running'] });
    expect(done.status).toBe(1);
    // 60 s of the job's limit and 300 s to start: 24 readings 15 s apart, then one at the deadline.
    expect(done.slept).toHaveLength(24);
    expect(done.said.at(-1)).toBe(
      "job-agentx-stg-db-setup-o2jp673 hadn't ended 360 s after the wait began. To wait again: node deploy/azure/jobs.ts wait db-setup job-agentx-stg-db-setup-o2jp673",
    );
    expect(done.az.sequence).not.toContain('rest --method get');
  });

  it('says the times as Azure gave them when they are not times, and then looks for no log', async () => {
    for (const [startTime, endTime] of [
      ['soon', ''],
      ['2026-09-17T05:46:43+00:00', 'later'],
    ] as const) {
      const done = await run(['run', 'db-setup'], { startTime, endTime });
      expect(done.said.at(-1)).toMatch(/^job-agentx-stg-db-setup-o2jp673 ended Succeeded: started .*, ended .*\.$/);
      expect(done.said.at(-1)).not.toMatch(/ s\)\.$/);
      expect(done.error).toMatchObject({
        message: "Azure gave no start and end for job-agentx-stg-db-setup-o2jp673, so its log can't be looked for.",
      });
      expect(done.az.sequence).not.toContain('rest --method get');
    }
    const odd = await run(['run', 'db-setup'], { startTime: 'soon', endTime: '' });
    expect(odd.said.at(-1)).toBe('job-agentx-stg-db-setup-o2jp673 ended Succeeded: started "soon", ended "".');
  });
});

describe("a run's log", () => {
  it('is shown once the container has ended and two readings a minute apart hold the same lines', async () => {
    const done = await run(['run', 'db-setup'], {
      logs: [
        [CREATED],
        [CREATED, TERMINATED],
        [CREATED, line('db-setup.starting'), TERMINATED],
        [CREATED, line('db-setup.starting'), line('db-setup.done'), TERMINATED],
        [CREATED, line('db-setup.starting'), line('db-setup.done'), TERMINATED],
      ],
    });
    expect(done.status).toBe(0);
    expect(done.az.queries).toHaveLength(5);
    expect(done.slept.filter((ms) => ms === 60_000)).toHaveLength(4);
    expect(done.said.filter((said) => said.startsWith('Reading '))).toHaveLength(1);
    expect(done.said).toContain("job-agentx-stg-db-setup-o2jp673's log, 2 from the platform and 2 from the container:");
  });

  it('is waited for until 15 minutes after the run ended, then shown as it is, saying what is missing', async () => {
    const neverEnded = await run(['run', 'db-setup'], { logs: [[CREATED, line('db-setup.starting')]] });
    expect(neverEnded.status).toBe(0);
    // The run ended at 05:47:21; readings from 05:46:30 a minute apart, the last at or after 06:02:21.
    expect(neverEnded.az.queries).toHaveLength(17);
    expect(neverEnded.az.queries.at(-1)?.timespan).toBe('2026-09-17T05:41:43.000Z/2026-09-17T06:07:30.000Z');
    // Azure's own word that the run succeeded still stands.
    expect(neverEnded.said.slice(-5)).toEqual([
      "job-agentx-stg-db-setup-o2jp673's log, 1 from the platform and 1 from the container:",
      "  05:46:43  platform  SuccessfulCreate: Successfully created pod for Job Execution 'job-agentx-stg-db-setup-o2jp673'",
      '  05:47:12  stdout    {"event":"db-setup.starting"}',
      "Azure logged no end for the container, so these may not be all the run's lines.",
      'In a first deploy, the next is: node deploy/azure/jobs.ts run migrate',
    ]);
    const silent = await run(['run', 'db-setup'], { logs: [[CREATED, TERMINATED]] });
    expect(silent.az.queries).toHaveLength(17);
    expect(silent.said).toContain('No line from the container reached the workspace.');
    // A line more on every reading, the container's end logged from the first.
    const growing = Array.from({ length: 17 }, (_, count) => [
      CREATED,
      ...Array.from({ length: count + 1 }, (__, index) => line(`step.${String(index)}`)),
      TERMINATED,
    ]);
    const stillArriving = await run(['run', 'db-setup'], { logs: growing });
    expect(stillArriving.status).toBe(0);
    expect(stillArriving.az.queries).toHaveLength(17);
    expect(stillArriving.said).toContain(
      "job-agentx-stg-db-setup-o2jp673's log, 2 from the platform and 17 from the container:",
    );
    expect(stillArriving.said.at(-2)).toBe(
      "The container's lines were still arriving 15 minutes after the run ended, so more may be missing.",
    );
    // The same lines on the last two readings, just inside the 15 minutes: nothing is said to be missing.
    const settledLate = await run(['run', 'db-setup'], { logs: [...growing.slice(0, 15), growing[14] ?? []] });
    expect(settledLate.az.queries).toHaveLength(16);
    expect(settledLate.said.filter((said) => said.includes('may be missing'))).toEqual([]);
  });

  it("of a run that ended long ago is read once, and nothing is said to be missing when it isn't", async () => {
    const earlier = { startTime: '2026-09-17T05:00:00+00:00', endTime: '2026-09-17T05:31:30+00:00' };
    const done = await run(['wait', 'db-setup', 'job-agentx-stg-db-setup-o2jp673'], earlier);
    expect(done.status).toBe(0);
    expect(done.az.queries).toHaveLength(1);
    expect(done.said.filter((said) => said.startsWith('Reading '))).toEqual([]);
    expect(done.said.slice(-2)).toEqual([
      "  05:47:12  platform  ContainerTerminated: Container 'db-setup' was terminated with exit code '0' and reason 'ProcessExited'",
      'In a first deploy, the next is: node deploy/azure/jobs.ts run migrate',
    ]);
  });

  it('shows a time the workspace gave that is not one as it came', async () => {
    const done = await run(['run', 'db-setup'], { logs: [[['yesterday', 'stderr', '', 'boom'], TERMINATED]] });
    expect(done.said).toContain('  yesterday  stderr    boom');
    // A line on stderr is the container's too, so the second reading settles it.
    expect(done.az.queries).toHaveLength(2);
    expect(done.said).toContain("job-agentx-stg-db-setup-o2jp673's log, 1 from the platform and 1 from the container:");
  });

  it("is refused when the workspace has no ID, or the answer isn't the table asked for", async () => {
    for (const workspace of [undefined, '', 'log-agentx-stg', `${WORKSPACE_ID} `]) {
      const done = await run(['run', 'db-setup'], { workspace });
      expect(done.error).toMatchObject({ message: "Azure gave no ID for log-agentx-stg, so the log can't be read." });
      expect(done.az.sequence).not.toContain('rest --method post');
    }
    const table = (rows: unknown, columns = ['TimeGenerated', 'Source', 'Reason', 'Text']) => ({
      tables: [{ columns: columns.map((name) => ({ name })), rows }],
    });
    for (const [logAnswer, message] of [
      [{}, "Log Analytics' answer wasn't the table asked for."],
      [{ tables: [] }, "Log Analytics' answer wasn't the table asked for."],
      [table(undefined), "Log Analytics' answer wasn't the table asked for."],
      [table({}), "Log Analytics' answer wasn't the table asked for."],
      [table([], ['TimeGenerated', 'Source', 'Text']), "Log Analytics' answer wasn't the table asked for."],
      [table(['not a row']), "Log Analytics' answer held a row that isn't one."],
    ] as const) {
      const done = await run(['run', 'db-setup'], { logAnswer });
      expect(done.error).toMatchObject({ message });
    }
  });

  it('reads the columns by name, whatever order they come in', async () => {
    const done = await run(['run', 'db-setup'], {
      logAnswer: {
        tables: [
          {
            columns: [{ name: 'Text' }, { name: 'Reason' }, { name: 'TimeGenerated' }, { name: 'Source' }],
            rows: [["Container 'db-setup' was terminated", 'ContainerTerminated', '2026-09-17T05:47:12Z', 'platform']],
          },
        ],
      },
      endTime: '2026-09-17T05:00:00+00:00',
    });
    expect(done.said).toContain("  05:47:12  platform  ContainerTerminated: Container 'db-setup' was terminated");
  });
});

describe('start', () => {
  it('starts the job and says how to wait for it, without waiting', async () => {
    const done = await run(['start', 'migrate'], { started: 'job-agentx-stg-migrate-p0q1r2s' });
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'containerapp job show',
      'containerapp job execution list',
      'containerapp job start',
    ]);
    expect(done.slept).toEqual([]);
    expect(done.said.slice(-2)).toEqual([
      'Started job-agentx-stg-migrate-p0q1r2s.',
      'To wait for it: node deploy/azure/jobs.ts wait migrate job-agentx-stg-migrate-p0q1r2s',
    ]);
  });

  it('refuses while a run of the job has not ended, whatever its state says, and starts nothing', async () => {
    const done = await run(['start', 'zitadel-setup'], {
      runs: [
        { name: 'job-agentx-stg-zitadel-setup-a1', properties: { status: 'Succeeded' } },
        { name: 'job-agentx-stg-zitadel-setup-b2', properties: { status: 'Running' } },
        { name: 'job-agentx-stg-zitadel-setup-c3', properties: { status: 'Unknown' } },
        { name: 'job-agentx-stg-zitadel-setup-d4', properties: {} },
        { name: 'job-agentx-stg-zitadel-setup-e5', properties: { status: 'Failed' } },
        { name: 'job-agentx-stg-zitadel-setup-f6', properties: { status: 'Stopped' } },
        { name: 'job-agentx-stg-zitadel-setup-g7', properties: { status: 'Degraded' } },
      ],
    });
    expect(done.error).toMatchObject({
      message:
        "job-agentx-stg-zitadel-setup has runs that haven't ended, so it wasn't started: job-agentx-stg-zitadel-setup-b2 (Running), job-agentx-stg-zitadel-setup-c3 (Unknown), job-agentx-stg-zitadel-setup-d4 (no state). Wait for them, or stop one with az containerapp job stop --subscription 00000000-0000-0000-0000-00000000000b --name job-agentx-stg-zitadel-setup --resource-group rg-agentx-staging --job-execution-name <run>.",
    });
    expect(done.az.sequence).not.toContain('containerapp job start');
  });

  it('starts a job that has never run', async () => {
    const done = await run(['start', 'db-setup'], { runs: [] });
    expect(done.status).toBe(0);
  });

  it("refuses a list of runs that isn't one, and a started run named for another job", async () => {
    const notList = await run(['start', 'db-setup'], { runs: { value: [] } });
    expect(notList.error).toMatchObject({ message: "Azure's list of job-agentx-stg-db-setup's runs wasn't a list." });
    expect(notList.az.sequence).not.toContain('containerapp job start');
    // Held to the same shape as a run typed on the command line, since the log query quotes it.
    for (const started of [
      'job-agentx-stg-migrate-o2jp673',
      'job-agentx-stg-db-setup',
      'job-agentx-stg-db-setup-',
      'job-agentx-stg-db-setup-o2jp673 x',
      "job-agentx-stg-db-setup-o2jp673'",
      '',
    ]) {
      const odd = await run(['run', 'db-setup'], { started });
      expect(odd.error).toMatchObject({
        message: `Azure started job-agentx-stg-db-setup but named the run "${started}", which isn't one of its runs.`,
      });
      expect(odd.az.sequence).not.toContain('containerapp job execution show');
    }
  });
});

describe('wait', () => {
  it('waits for a run that has started, starting nothing, then shows its log', async () => {
    const done = await run(['wait', 'migrate', 'job-agentx-stg-migrate-p0q1r2s'], { states: ['Running', 'Succeeded'] });
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'containerapp job show',
      'containerapp job execution show',
      'containerapp job execution show',
      'rest --method get',
      'rest --method post',
      'rest --method post',
    ]);
    expect(done.az.queries[0]?.query).toContain("ContainerGroupName startswith_cs 'job-agentx-stg-migrate-p0q1r2s-'");
  });
});

describe('cleanup', () => {
  it("starts the setup job once as setup cleanup, through Resource Manager, with the job's own container", async () => {
    const done = await run(['cleanup']);
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'containerapp job show',
      'containerapp job execution list',
      'rest --method post',
      'containerapp job execution show',
      'rest --method get',
      'rest --method post',
      'rest --method post',
    ]);
    expect(done.az.calls[1]).toContain('job-agentx-stg-zitadel-setup');
    expect(done.az.starts).toEqual([{ containers: [CLEANUP_CONTAINER] }]);
    // Settings that read a secret still name it alone, with no value beside it.
    expect(JSON.stringify(done.az.starts)).not.toMatch(/"secretRef":"[^"]+","value"|"value":"[^"]*","secretRef"/);
    expect(done.said).toContain('Started job-agentx-stg-zitadel-setup-c1e2a3n.');
    expect(done.az.queries[0]?.query).toContain("startswith_cs 'job-agentx-stg-zitadel-setup-c1e2a3n-'");
    expect(done.said.at(-1)).toBe(
      'The clean-up has run: the lines above say which step it cancelled, if any. Now run setup again: node deploy/azure/jobs.ts run zitadel-setup',
    );
    // The body is never repeated where it could be read.
    expect(done.said.join('\n')).not.toContain('admin@example.invalid');
  });

  it('waits, like any run, and ends with failure when the clean-up fails', async () => {
    const done = await run(['cleanup'], { states: ['Running', 'Failed'] });
    expect(done.status).toBe(1);
    expect(done.said.at(-1)).toBe('Read the lines above before starting anything else.');
  });

  it('refuses while a setup run is still waiting, saying how to stop it, and starts nothing', async () => {
    const done = await run(['cleanup'], {
      runs: [{ name: 'job-agentx-stg-zitadel-setup-w4it1ng', properties: { status: 'Running' } }],
    });
    expect(done.error).toMatchObject({
      message: expect.stringContaining(
        "job-agentx-stg-zitadel-setup has runs that haven't ended, so it wasn't started: job-agentx-stg-zitadel-setup-w4it1ng (Running). Wait for them, or stop one with az containerapp job stop",
      ) as unknown,
    });
    expect(done.az.starts).toEqual([]);
  });

  it('refuses when Resource Manager refuses, or answers without naming a run of the job, never repeating what was sent', async () => {
    const refused = await run(['cleanup'], { startStatus: 1 });
    expect(refused.error).toMatchObject({
      message:
        'Azure refused to start job-agentx-stg-zitadel-setup to clean up:\nERROR: Bad Request({"error":{"code":"InvalidParameter"}})',
    });
    const silent = await run(['cleanup'], { startAnswer: '  \n' });
    expect(silent.error).toMatchObject({
      message: `Azure took the start of job-agentx-stg-zitadel-setup without naming the run. Find it with az containerapp job execution list --subscription ${SUBSCRIPTION} --name job-agentx-stg-zitadel-setup --resource-group rg-agentx-staging, and start nothing else until it has ended.`,
    });
    for (const startAnswer of ['null', '{}', JSON.stringify({ name: 'job-agentx-stg-zitadel-init-c1e2a3n' })]) {
      const odd = await run(['cleanup'], { startAnswer });
      expect(odd.error).toMatchObject({
        message: expect.stringMatching(/^Azure started job-agentx-stg-zitadel-setup but named the run/) as unknown,
      });
      expect(odd.az.sequence).not.toContain('containerapp job execution show');
    }
    for (const done of [refused, silent]) {
      expect((done.error as Error).message).not.toContain('admin@example.invalid');
      expect(done.az.sequence).not.toContain('containerapp job execution show');
    }
  });

  it('refuses a job that is not the Zitadel setup it knows, before anything starts', async () => {
    const done = await run(['cleanup'], {
      containers: [{ ...SETUP_CONTAINER, image: 'ghcr.io/shahbaz242630/agent-x@sha256:x' }],
    });
    expect(done.error).toMatchObject({
      message:
        "job-agentx-stg-zitadel-setup isn't the Zitadel setup this tool knows (its image isn't Zitadel's), so it wasn't started to clean up.",
    });
    expect(done.az.sequence).toEqual(['account show --output', 'containerapp job show']);
  });
});

describe('cleanupContainers', () => {
  const refusal = (why: string): string =>
    `job-agentx-stg-zitadel-setup isn't the Zitadel setup this tool knows (${why}), so it wasn't started to clean up.`;
  const withSetting = (entry: unknown) => [{ ...SETUP_CONTAINER, env: [...SETUP_CONTAINER.env, entry] }];

  it("keeps the job's image, command, settings and size, and only those, with setup cleanup as its arguments", () => {
    expect(cleanupContainers([SETUP_CONTAINER])).toEqual([CLEANUP_CONTAINER]);
    // Whatever else a setting carries is left behind.
    expect(
      cleanupContainers(withSetting({ name: 'ZITADEL_TLS_ENABLED', value: 'false', extra: 'x' }))[0]?.env.at(-1),
    ).toEqual({ name: 'ZITADEL_TLS_ENABLED', value: 'false' });
    // A value may be empty.
    expect(cleanupContainers(withSetting({ name: 'ZITADEL_EXTERNALPORT', value: '' }))[0]?.env.at(-1)).toEqual({
      name: 'ZITADEL_EXTERNALPORT',
      value: '',
    });
  });

  it('refuses anything else, saying what', () => {
    for (const [containers, why] of [
      [undefined, 'it must run exactly one container'],
      [{}, 'it must run exactly one container'],
      [[], 'it must run exactly one container'],
      [[SETUP_CONTAINER, SETUP_CONTAINER], 'it must run exactly one container'],
      [[{ ...SETUP_CONTAINER, name: 'zitadel-init' }], 'its container is not named zitadel-setup'],
      [[{ ...SETUP_CONTAINER, image: undefined }], "its image isn't Zitadel's"],
      [[{ ...SETUP_CONTAINER, image: 'ghcr.io/zitadel/zitadel-login:v4.17.3' }], "its image isn't Zitadel's"],
      [[{ ...SETUP_CONTAINER, image: 'evil.example/ghcr.io/zitadel/zitadel:v4' }], "its image isn't Zitadel's"],
      [[{ ...SETUP_CONTAINER, command: ['/app/zitadel', 'start'] }], "its command isn't /app/zitadel"],
      [[{ ...SETUP_CONTAINER, command: '/app/zitadel' }], "its command isn't /app/zitadel"],
      [[{ ...SETUP_CONTAINER, command: [7] }], "its command isn't /app/zitadel"],
      // A list inside the list joins to the same words.
      [[{ ...SETUP_CONTAINER, command: [['/app/zitadel']] }], "its command isn't /app/zitadel"],
      [[{ ...SETUP_CONTAINER, args: ['start-from-init'] }], "its arguments don't start with setup"],
      [[{ ...SETUP_CONTAINER, args: [] }], "its arguments don't start with setup"],
      [[{ ...SETUP_CONTAINER, args: 'setup' }], "its arguments don't start with setup"],
      [[{ ...SETUP_CONTAINER, resources: undefined }], 'its size is not given'],
      [[{ ...SETUP_CONTAINER, resources: { cpu: '0.5', memory: '1Gi' } }], 'its size is not given'],
      [[{ ...SETUP_CONTAINER, resources: { cpu: 0.5 } }], 'its size is not given'],
      [[{ ...SETUP_CONTAINER, env: undefined }], 'its settings are not a list'],
      [withSetting({ value: 'x' }), 'a setting has no name'],
      [withSetting(null), 'a setting has no name'],
      [
        withSetting({ name: 'A', value: 'x', secretRef: secret('a', 'b') }),
        'the setting A has neither a value nor a secret reference alone',
      ],
      [withSetting({ name: 'A' }), 'the setting A has neither a value nor a secret reference alone'],
      [withSetting({ name: 'A', value: 5 }), 'the setting A has neither a value nor a secret reference alone'],
      [withSetting({ name: 'A', secretRef: 5 }), 'the setting A has neither a value nor a secret reference alone'],
    ] as const) {
      expect(() => cleanupContainers(containers)).toThrow(refusal(why));
    }
  });
});

describe('before anything starts', () => {
  const each: readonly Request[] = [
    { command: 'run', job: 'db-setup' },
    { command: 'start', job: 'db-setup' },
    { command: 'wait', job: 'db-setup', execution: 'job-agentx-stg-db-setup-o2jp673' },
  ];

  it('refuses when the CLI gives no subscription ID, and asks Azure nothing more', async () => {
    for (const subscription of [
      undefined,
      '',
      'Azure subscription 1',
      `${SUBSCRIPTION} `,
      SUBSCRIPTION.toUpperCase(),
    ]) {
      for (const request of each) {
        const az = new ScriptedAz({ subscription });
        await expect(
          jobs(request, { az, say: () => undefined, now: () => START, sleep: () => Promise.resolve() }),
        ).rejects.toThrow('Azure gave no subscription ID: is the CLI signed in?');
        expect(az.sequence).toEqual(['account show --output']);
      }
    }
  });

  it('refuses a job that is not deployed, or has no usable time limit', async () => {
    for (const [script, message] of [
      [{ notDeployed: true }, /az containerapp job show .* failed:\nERROR: \(ResourceNotFound\)/],
      [{ limit: undefined }, /Azure gave no time limit for job-agentx-stg-db-setup/],
      [{ limit: '900' }, /no time limit/],
      [{ limit: 0 }, /no time limit/],
      [{ limit: -5 }, /no time limit/],
      [{ limit: 1.5 }, /no time limit/],
    ] as const) {
      for (const request of each) {
        const az = new ScriptedAz(script);
        await expect(
          jobs(request, { az, say: () => undefined, now: () => START, sleep: () => Promise.resolve() }),
        ).rejects.toThrow(message);
        expect(az.sequence).toEqual(['account show --output', 'containerapp job show']);
      }
    }
  });
});

describe('main', () => {
  it('prints the usage for arguments it cannot read', async () => {
    const said: string[] = [];
    await expect(main(['run', 'nothing'], (line) => said.push(line))).resolves.toBe(2);
    expect(said.join('\n')).toContain(USAGE);
  });

  it('says what went wrong, and ends with 1, when Azure refuses', async () => {
    const said: string[] = [];
    await expect(
      main(
        ['start', 'db-setup'],
        (line) => said.push(line),
        () => new ScriptedAz({ notDeployed: true }),
      ),
    ).resolves.toBe(1);
    expect(said.at(-1)).toMatch(/ResourceNotFound/);
  });

  it('ends with what the run ended with', async () => {
    await expect(
      main(
        ['start', 'db-setup'],
        () => undefined,
        () => new ScriptedAz(),
      ),
    ).resolves.toBe(0);
  });
});

describe('the runner and the deployment agree', () => {
  it('names every job the deployment creates, in the order it lists them, and the workspace they log to', () => {
    const created = inCopy((dir) => environmentSnapshot(dir, 'staging').together).predictedResources;
    expect(
      created.filter((resource) => resource.type === 'Microsoft.App/jobs').map((resource) => resource.name),
    ).toEqual(JOBS.map((job: Job) => jobName(job)));
    expect(
      created
        .filter((resource) => resource.type === 'Microsoft.OperationalInsights/workspaces')
        .map((resource) => resource.name),
    ).toEqual([WORKSPACE]);
    // The clean-up run is started with the API version the jobs are deployed with.
    expect(
      new Set(
        created.filter((resource) => resource.type === 'Microsoft.App/jobs').map((resource) => resource.apiVersion),
      ),
    ).toEqual(new Set([JOBS_API]));
  });
});
