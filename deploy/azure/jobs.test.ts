// The job runner (G3a). Nothing here reaches Azure: the CLI is a stand-in that
// answers from a script and records each call, and time moves only when the
// runner sleeps, so a wait of many minutes runs at once.
import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import { type Job, jobName, JOBS, jobs, main, parseArguments, type Request, USAGE, UsageError } from './jobs.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000b';
const START = new Date('2026-09-17T05:46:30Z');

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
}

/** An Azure CLI that answers from the script and records every call. */
class ScriptedAz implements Az {
  readonly calls: (readonly string[])[] = [];
  readonly #script: Script;
  #readings = 0;

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
          properties: { configuration: { replicaTimeout: 'limit' in script ? script.limit : 900 } },
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

  /** The commands, by their first words, in the order they ran. */
  get sequence(): string[] {
    return this.calls.map((call) => call.slice(0, call[2] === 'execution' ? 4 : 3).join(' '));
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

describe('parseArguments', () => {
  it('reads the three ways the runner is used, for every job', () => {
    for (const job of JOBS) {
      expect(parseArguments(['run', job])).toEqual({ command: 'run', job });
      expect(parseArguments(['start', job])).toEqual({ command: 'start', job });
      expect(parseArguments(['wait', job, `${jobName(job)}-o2jp673`])).toEqual({
        command: 'wait',
        job,
        execution: `${jobName(job)}-o2jp673`,
      });
    }
  });

  it('refuses anything else, saying why', () => {
    for (const [argv, reason] of [
      [[], /say run, start or wait, not nothing/],
      [['stop', 'db-setup'], /say run, start or wait, not stop/],
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
      [['wait', 'db-setup', 'xjob-agentx-stg-db-setup-o2jp673'], /one of its runs/],
      [['wait', 'db-setup', 'job-agentx-stg-db-setup-o2jp673', 'more'], /one of its runs/],
    ] as const) {
      expect(() => parseArguments(argv)).toThrow(UsageError);
      expect(() => parseArguments(argv)).toThrow(reason);
    }
  });
});

describe('run', () => {
  it('checks the job is deployed and idle, starts it, and waits for the run to succeed', async () => {
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
    for (const call of done.az.calls.slice(1)) expect(call.join(' ')).toContain(naming.join(' '));
    expect(done.az.calls.at(-1)).toEqual([
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
    expect(done.slept).toEqual([15_000, 15_000]);
    expect(done.said).toEqual([
      `Signed in to the subscription "Azure subscription 1" (${SUBSCRIPTION}).`,
      'Started job-agentx-stg-db-setup-o2jp673.',
      'Waiting for job-agentx-stg-db-setup-o2jp673 to end (the job gives up after 900 s)...',
      '  05:46:30 UTC  Running',
      '  05:47:00 UTC  Succeeded',
      'job-agentx-stg-db-setup-o2jp673 ended Succeeded: started 05:46:43 UTC, ended 05:47:21 UTC (38 s).',
      'In a first deploy, the next is: node deploy/azure/jobs.ts run migrate',
    ]);
  });

  it('names the next job in the order a first deploy runs them, and says when there is none', async () => {
    const next: string[] = [];
    for (const job of JOBS) {
      const done = await run(['run', job], { started: `${jobName(job)}-abc1234` });
      expect(done.status).toBe(0);
      next.push(done.said.at(-1) ?? '');
    }
    expect(next).toEqual([
      'In a first deploy, the next is: node deploy/azure/jobs.ts run migrate',
      'In a first deploy, the next is: node deploy/azure/jobs.ts run zitadel-init',
      'In a first deploy, the next is: node deploy/azure/jobs.ts run zitadel-setup',
      'That is the last of the four a first deploy runs.',
    ]);
  });

  it('ends with failure, and says to read the logs, for every end but success', async () => {
    for (const state of ['Failed', 'Stopped', 'Degraded']) {
      const done = await run(['run', 'zitadel-init'], {
        started: 'job-agentx-stg-zitadel-init-k2m9x1q',
        states: ['Processing', state],
      });
      expect({ state, status: done.status }).toEqual({ state, status: 1 });
      expect(done.said.slice(-2)).toEqual([
        `job-agentx-stg-zitadel-init-k2m9x1q ended ${state}: started 05:46:43 UTC, ended 05:47:21 UTC (38 s).`,
        'Read its logs before starting anything else.',
      ]);
    }
  });

  it('keeps waiting through states that are not an end, a missing one included', async () => {
    const done = await run(['run', 'db-setup'], { states: ['', 'Unknown', 'Processing', 'Running', 'Succeeded'] });
    expect(done.status).toBe(0);
    expect(done.slept).toHaveLength(4);
    expect(done.said.filter((line) => line.startsWith('  '))).toEqual([
      '  05:46:30 UTC  no state yet',
      '  05:46:45 UTC  Unknown',
      '  05:47:00 UTC  Processing',
      '  05:47:15 UTC  Running',
      '  05:47:30 UTC  Succeeded',
    ]);
  });

  it('gives up once the job has had its time limit and the start allowance, saying how to wait again', async () => {
    const done = await run(['run', 'db-setup'], { limit: 60, states: ['Running'] });
    expect(done.status).toBe(1);
    // 60 s of the job's limit and 300 s to start: 24 readings 15 s apart, then one at the deadline.
    expect(done.slept).toHaveLength(24);
    expect(done.said.at(-1)).toBe(
      "job-agentx-stg-db-setup-o2jp673 hadn't ended 360 s after the wait began. To wait again: node deploy/azure/jobs.ts wait db-setup job-agentx-stg-db-setup-o2jp673",
    );
  });

  it('says the times as Azure gave them when they are not times, with no duration', async () => {
    const done = await run(['run', 'db-setup'], { startTime: 'soon', endTime: '' });
    expect(done.said).toContain('job-agentx-stg-db-setup-o2jp673 ended Succeeded: started "soon", ended "".');
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
    // Held to the same shape as a run typed on the command line.
    for (const started of [
      'job-agentx-stg-migrate-o2jp673',
      'job-agentx-stg-db-setup',
      'job-agentx-stg-db-setup-',
      'job-agentx-stg-db-setup-o2jp673 x',
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
  it('waits for a run that has started, starting nothing', async () => {
    const done = await run(['wait', 'migrate', 'job-agentx-stg-migrate-p0q1r2s'], { states: ['Running', 'Succeeded'] });
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'containerapp job show',
      'containerapp job execution show',
      'containerapp job execution show',
    ]);
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
        const said: string[] = [];
        await expect(
          jobs(request, {
            az,
            say: (line) => said.push(line),
            now: () => START,
            sleep: () => Promise.resolve(),
          }),
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
    const said: string[] = [];
    await expect(
      main(
        ['start', 'db-setup'],
        (line) => said.push(line),
        () => new ScriptedAz(),
      ),
    ).resolves.toBe(0);
  });
});

describe('the runner and the deployment agree', () => {
  it('names every job the deployment creates, in the order it lists them', () => {
    const created = inCopy((dir) => environmentSnapshot(dir, 'staging').together)
      .predictedResources.filter((resource) => resource.type === 'Microsoft.App/jobs')
      .map((resource) => resource.name);
    expect(created).toEqual(JOBS.map((job: Job) => jobName(job)));
  });
});
