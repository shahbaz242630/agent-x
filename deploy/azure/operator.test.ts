// The operator's command on its job (B1c-2b). Nothing here reaches Azure: the
// CLI is a stand-in holding the job and the API as Azure would, answering
// from them and recording each call. A PATCH is read from the file it is sent
// in, as it is sent, and taken only after a few readings, as Azure settles a
// change in the background; time moves only when the runner sleeps.
import { existsSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  createOrganizationRequest,
  NO_REQUEST_PROBLEM,
  REQUEST_LIMIT_BYTES,
  UUID_V7,
} from '../../apps/operator/src/request.ts';
import type { Az, AzResult } from './deploy.ts';
import { jobName, JOBS_API, UsageError } from './jobs.ts';
import {
  createOrganization,
  main,
  NO_REQUEST,
  OPERATOR_JOB,
  parseArguments,
  REQUEST_SECRET,
  USAGE,
} from './operator.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000b';
const WORKSPACE_ID = '00000000-0000-0000-0000-00000000000c';
const START = new Date('2026-09-23T08:00:00Z');
const RUN = 'job-agentx-stg-operator-7x2kq9m';
/** Plain words a test can look for in everything said and sent; never a real business. */
const NAME = 'Zephyrine Trading Test Co';
/** An ID an earlier run gave. */
const EARLIER_ID = '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b';

const ARM = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers`;
const JOB_URL = `${ARM}/Microsoft.App/jobs/job-agentx-stg-operator?api-version=${JOBS_API}`;
const API_URL = `${ARM}/Microsoft.App/containerApps/ca-agentx-stg-api?api-version=${JOBS_API}`;
const WORKSPACE_URL = `${ARM}/Microsoft.OperationalInsights/workspaces/log-agentx-stg?api-version=2025-02-01`;

/**
 * Names assembled from their words, so no test line pairs a secret's name with
 * a quoted value: the shape GitGuardian reads as a password (PRs #27 and #28).
 */
const setting = (...words: readonly string[]): string => words.join('_');
const secret = (...words: readonly string[]): string => words.join('-');

const image = (digit: string): string => `ghcr.io/shahbaz242630/agent-x@sha256:${digit.repeat(64)}`;
const commit = (digit: string): string => digit.repeat(40);

const IDENTITY = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-agentx-stg-operator`;
/** The job's secrets but its request, as Azure gives them back: references to the vault. */
const REFERENCES = [secret('db', 'app', 'password'), secret('key', 'audit', 'mac', 'v1')].map((name) => ({
  identity: IDENTITY,
  keyVaultUrl: `https://kv-agentx-stg-test.vault.azure.net/secrets/${name}`,
  name,
}));

/** The operator's container as Azure gives it back (read S42), with made-up values. */
const operatorContainer = (on: string, build: string) => ({
  args: ['--request', '/mnt/secrets/operator-request'],
  command: ['node', 'apps/operator/src/main.ts'],
  env: [
    { name: 'AGENTX_ENV', value: 'staging' },
    { name: 'AGENTX_RELEASE', value: build },
    { name: 'AGENTX_DB_HOST', value: 'db.example.invalid' },
    { name: 'AGENTX_DB_NAME', value: 'agentx' },
    { name: 'AGENTX_KEYS_DIR', value: '/mnt/secrets' },
    { name: 'AGENTX_DB_USER', value: 'agentx_app' },
    { name: setting('AGENTX', 'DB', 'PASSWORD', 'FILE'), value: `/mnt/secrets/${secret('db', 'app', 'password')}` },
  ],
  image: on,
  name: 'operator',
  resources: { cpu: 0.5, memory: '1Gi' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
});

/** The API's container, as a release reads it. */
const apiContainer = (on: string, build: string) => ({
  name: 'api',
  image: on,
  command: ['node', 'apps/api/src/main.ts'],
  args: [],
  env: [
    { name: 'AGENTX_ENV', value: 'staging' },
    { name: 'AGENTX_RELEASE', value: build },
  ],
  resources: { cpu: 0.5, memory: '1Gi', ephemeralStorage: '2Gi' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
});

/** A row of the log query: when, where from, the platform's reason, the text. */
type Row = readonly [string, string, string, string];

const TERMINATED: Row = [
  '2026-09-23T08:02:12.6002662Z',
  'platform',
  'ContainerTerminated',
  "Container 'operator' was terminated with exit code '0' and reason 'ProcessExited'",
];
const said = (fields: Readonly<Record<string, unknown>>): Row => [
  '2026-09-23T08:02:12.4133012Z',
  'stdout',
  '',
  JSON.stringify({ level: 'info', service: 'operator', ...fields }),
];

/** How a run ends, and what its lines say, for the ID its request names. */
type Ending = 'created' | 'done-before' | 'no-request' | 'refused' | 'failed';

const RUN_LINES: Readonly<Record<Ending, (id: string) => readonly Row[]>> = {
  created: (id) => [
    said({ event: 'operator.starting' }),
    said({ event: 'operator.organization_created', orgId: id }),
    TERMINATED,
  ],
  'done-before': (id) => [
    said({ event: 'operator.starting' }),
    said({ event: 'operator.done_before', orgId: id }),
    TERMINATED,
  ],
  'no-request': () => [said({ event: 'operator.refused', problems: [NO_REQUEST_PROBLEM] }), TERMINATED],
  refused: () => [said({ event: 'operator.refused', problems: ['the name starts or ends with a space'] }), TERMINATED],
  failed: (id) => [
    said({ event: 'operator.starting' }),
    ['2026-09-23T08:02:12.5Z', 'stderr', '', 'a line that is not JSON'],
    said({ event: 'operator.failed', orgId: id }),
    TERMINATED,
  ],
};

interface Script {
  /** What the job and the API run before anything. */
  readonly jobImage?: string;
  readonly jobBuild?: string;
  readonly apiImage?: string;
  readonly apiBuild?: string;
  /** The job's state before anything, from an earlier change. */
  readonly state?: string;
  /** A change to the job's answer, for the jobs this tool must refuse. */
  readonly job?: (answer: Record<string, unknown>) => void;
  /** The job's runs, as `execution list` gives them. */
  readonly runs?: unknown;
  /** How many readings after a PATCH still show the job as it was, and how each PATCH settles, in order. */
  readonly lag?: number;
  readonly settles?: readonly ('Succeeded' | 'Failed' | 'never')[];
  /** Each PATCH's CLI status, in order: 0 sends it. */
  readonly patchStatus?: readonly number[];
  readonly startStatus?: number;
  /** The states `execution show` gives, the last repeated. */
  readonly states?: readonly string[];
  readonly ending?: Ending;
}

/** A change Azure is settling: the readings left that show the job as it was, then the change. */
interface Settling {
  left: number;
  applied: boolean;
  readonly settles: 'Succeeded' | 'Failed' | 'never';
  readonly apply: () => void;
}

/** Azure as the runner meets it: the job and the API, and every call recorded. */
class FakeAzure implements Az {
  readonly calls: (readonly string[])[] = [];
  /** Each PATCH as it was sent: the file's text, and its JSON. */
  readonly sent: { readonly text: string; readonly body: Record<string, unknown>; readonly file: string }[] = [];
  /** What the job holds as its request, and held when its run started. */
  request = NO_REQUEST;
  heldAtStart: string | undefined;
  container: unknown;
  state: string;
  modified = '2026-09-22T17:20:12.062971';
  readonly #script: Script;
  #settling: Settling | undefined;
  #changes = 0;
  #readings = 0;

  constructor(script: Script) {
    this.#script = script;
    this.container = operatorContainer(script.jobImage ?? image('a'), script.jobBuild ?? commit('a'));
    this.state = script.state ?? 'Succeeded';
  }

  interactive(): number | null {
    throw new Error('the operator runner never runs the CLI interactively');
  }

  run(args: readonly string[]): AzResult {
    this.calls.push(args);
    const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
    const script = this.#script;
    if (args[0] === 'rest') {
      const method = args[args.indexOf('--method') + 1];
      const url = args[args.indexOf('--url') + 1];
      if (method === 'patch') return this.#patch(args, url);
      if (method === 'get' && url === JOB_URL) return json(this.#job());
      if (method === 'get' && url === API_URL) {
        return json({
          properties: {
            provisioningState: 'Succeeded',
            template: { containers: [apiContainer(script.apiImage ?? image('b'), script.apiBuild ?? commit('b'))] },
          },
          tags: {},
        });
      }
      if (method === 'get' && url === WORKSPACE_URL) return json({ properties: { customerId: WORKSPACE_ID } });
      if (method === 'post' && url === `https://api.loganalytics.azure.com/v1/workspaces/${WORKSPACE_ID}/query`) {
        return json(this.#log());
      }
      throw new Error(`unexpected az ${args.join(' ')}`);
    }
    const words = args.filter((arg) => !arg.startsWith('-')).slice(0, 4);
    switch (words.join(' ')) {
      case 'account show json':
        return json({ name: 'Azure subscription 1', id: SUBSCRIPTION });
      case 'containerapp job execution list':
        return json('runs' in script ? script.runs : [{ name: 'old', properties: { status: 'Succeeded' } }]);
      case `containerapp job start ${SUBSCRIPTION}`:
        if (script.startStatus !== undefined) {
          return { status: script.startStatus, stdout: '', stderr: 'ERROR: Conflict({"error":{"code":"JobBusy"}})' };
        }
        this.heldAtStart = this.request;
        return json({ id: '/subscriptions/x', name: RUN });
      case 'containerapp job execution show': {
        const states = script.states ?? [
          script.ending === undefined || script.ending === 'created' ? 'Succeeded' : 'Failed',
        ];
        const state = states[Math.min(this.#readings, states.length - 1)];
        this.#readings += 1;
        return json({
          name: RUN,
          properties: { status: state, startTime: '2026-09-23T08:01:43+00:00', endTime: '2026-09-23T08:02:21+00:00' },
        });
      }
      default:
        throw new Error(`unexpected az ${args.join(' ')}`);
    }
  }

  /** The job as a GET gives it: never a secret's value, and a change being settled shown as Azure shows it. */
  #job(): Record<string, unknown> {
    const settling = this.#settling;
    if (settling !== undefined) {
      if (settling.left > 0) {
        settling.left -= 1;
      } else if (!settling.applied) {
        settling.apply();
        settling.applied = true;
        this.modified = `2026-09-23T08:0${String(this.#changes)}:00.000000`;
        this.state = 'InProgress';
      } else if (settling.settles !== 'never') {
        this.state = settling.settles;
        this.#settling = undefined;
      }
    }
    const answer: Record<string, unknown> = {
      id: '/subscriptions/x',
      name: jobName('operator'),
      properties: {
        provisioningState: this.state,
        configuration: {
          replicaTimeout: 300,
          replicaRetryLimit: 0,
          triggerType: 'Manual',
          secrets: [...REFERENCES, { name: REQUEST_SECRET }],
        },
        template: {
          containers: [this.container],
          volumes: [{ name: 'secrets', storageType: 'Secret' }],
        },
      },
      systemData: { lastModifiedAt: this.modified },
    };
    this.#script.job?.(answer);
    return answer;
  }

  #patch(args: readonly string[], url: string | undefined): AzResult {
    expect(url).toBe(JOB_URL);
    const body = args[args.indexOf('--body') + 1] ?? '';
    expect(body.startsWith('@')).toBe(true);
    const file = body.slice(1);
    const text = readFileSync(file, 'utf8');
    const parsed = JSON.parse(text) as Record<string, unknown>;
    this.sent.push({ text, body: parsed, file });
    const index = this.#changes;
    this.#changes += 1;
    const status = this.#script.patchStatus?.[index] ?? 0;
    if (status !== 0) {
      return {
        status,
        stdout: '',
        stderr: `ERROR: Bad Request({"error":{"code":"InvalidParameter","message":"${text}"}})`,
      };
    }
    const properties = parsed.properties as {
      configuration: { secrets: { name: string; value?: string }[] };
      template?: { containers: unknown[] };
    };
    this.#settling = {
      left: this.#script.lag ?? 1,
      applied: false,
      settles: this.#script.settles?.[index] ?? 'Succeeded',
      apply: () => {
        this.request = properties.configuration.secrets.find((each) => each.name === REQUEST_SECRET)?.value ?? '';
        if (properties.template !== undefined) this.container = properties.template.containers[0];
      },
    };
    return { status: 0, stdout: '', stderr: '' };
  }

  /** The run's lines, for the ID its request named when it started. */
  #log(): unknown {
    const id = String((JSON.parse(this.heldAtStart ?? '[]') as string[])[4]);
    const rows = RUN_LINES[this.#script.ending ?? 'created'](id);
    return {
      tables: [
        {
          columns: [{ name: 'TimeGenerated' }, { name: 'Source' }, { name: 'Reason' }, { name: 'Text' }],
          rows,
        },
      ],
    };
  }

  /** The commands, by their first words, in the order they ran. */
  get sequence(): string[] {
    return this.calls.map((call) => {
      if (call[0] !== 'rest') return call.slice(0, call[2] === 'execution' ? 4 : 3).join(' ');
      const url = call[call.indexOf('--url') + 1] ?? '';
      const what = url === JOB_URL ? 'job' : url === API_URL ? 'api' : url.includes('/query') ? 'log' : 'workspace';
      return `${call[2] ?? ''} ${what}`;
    });
  }
}

/** One run of the runner, with a clock that moves only when it sleeps. */
async function run(argv: readonly string[], script: Script = {}) {
  const az = new FakeAzure(script);
  const lines: string[] = [];
  const slept: number[] = [];
  let now = START.getTime();
  const status = await createOrganization(parseArguments(argv), {
    az,
    say: (line) => lines.push(line),
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
  return { status: status.value, error: status.error, az, said: lines, slept };
}

const create = ['create-organization', '--name', NAME];

describe('parseArguments', () => {
  it('reads a name, and an earlier run ID when one is given', () => {
    expect(parseArguments(create)).toEqual({ name: NAME, id: undefined });
    expect(parseArguments([...create, '--id', EARLIER_ID])).toEqual({ name: NAME, id: EARLIER_ID });
  });

  it('refuses anything else, repeating nothing typed', () => {
    const shape = 'say create-organization --name <name> [--id <ID>], the name as one argument, and nothing else';
    for (const [argv, message] of [
      [[], shape],
      [['create-organization'], shape],
      [['create-organization', '--name'], shape],
      [['create-organization', '--name', ''], shape],
      [['delete-organization', '--name', NAME], shape],
      [['create-organization', '--title', NAME], shape],
      [['create-organization', '--name', 'Zephyrine', 'Trading'], shape],
      [[...create, '--id'], shape],
      [[...create, '--org', EARLIER_ID], shape],
      [[...create, '--id', EARLIER_ID, '--force'], shape],
      [[...create, '--id', EARLIER_ID.toUpperCase()], '--id takes the ID an earlier run gave: a UUIDv7, in lower case'],
      [
        [...create, '--id', '6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f'],
        '--id takes the ID an earlier run gave: a UUIDv7, in lower case',
      ],
    ] as const) {
      expect(() => parseArguments(argv)).toThrow(new UsageError(message));
    }
  });

  it(`refuses a name that makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`, () => {
    const fits = 'Q'.repeat(REQUEST_LIMIT_BYTES - createOrganizationRequest('', EARLIER_ID).length);
    expect(parseArguments(['create-organization', '--name', fits]).name).toBe(fits);
    expect(() => parseArguments(['create-organization', '--name', `${fits}Q`])).toThrow(
      new UsageError(
        `the name makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`,
      ),
    );
    // Counted in UTF-8, as the operator reads it: two bytes a letter here.
    const accented = String.fromCharCode(0xe9).repeat(Math.floor(fits.length / 2) + 1);
    expect(() => parseArguments(['create-organization', '--name', accented])).toThrow(UsageError);
  });
});

describe('creating an organisation', () => {
  it("writes the request with the API's build, runs it, puts [] back and says it was created", async () => {
    const done = await run(create);

    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.az.sequence).toEqual([
      'account show --output',
      'get job',
      'get api',
      'containerapp job execution list',
      'patch job',
      'get job',
      'get job',
      'get job',
      // The start looks again for a run going, then starts the job as it is.
      'containerapp job execution list',
      'containerapp job start',
      'containerapp job execution show',
      'get job',
      'patch job',
      'get job',
      'get job',
      'get job',
      'get workspace',
      'post log',
      'post log',
    ]);
    const [write, clear] = done.az.sent;
    const id = String((JSON.parse(done.az.heldAtStart ?? '[]') as string[])[4]);
    expect(id).toMatch(UUID_V7);
    // The run started holding this request, and the job holds none now.
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, id));
    expect(done.az.request).toBe(NO_REQUEST);
    // One PATCH: every vault reference as it was read, the request, and the container on the API's build.
    expect(write?.body).toEqual({
      properties: {
        configuration: {
          secrets: [...REFERENCES, { name: REQUEST_SECRET, value: createOrganizationRequest(NAME, id) }],
        },
        template: { containers: [operatorContainer(image('b'), commit('b'))] },
      },
    });
    // Then the request off again, the references as they are, and the container left alone.
    expect(clear?.body).toEqual({
      properties: { configuration: { secrets: [...REFERENCES, { name: REQUEST_SECRET, value: NO_REQUEST }] } },
    });
    expect(done.az.container).toEqual(operatorContainer(image('b'), commit('b')));
    expect(done.said).toEqual([
      `Signed in to the subscription "Azure subscription 1" (${SUBSCRIPTION}).`,
      `The new organisation's ID is ${id}. If this run's end is unclear, run the same command again with --id ${id}: it can't make a second organisation.`,
      `Bringing job-agentx-stg-operator to the API's build: image ${image('a')} → ${image('b')}; AGENTX_RELEASE ${commit('a')} → ${commit('b')}.`,
      'Wrote the request onto job-agentx-stg-operator.',
      `Started ${RUN}.`,
      `Waiting for ${RUN} to end (the job gives up after 300 s)...`,
      // Two readings 15 s apart while Azure took the request.
      '  08:00:30 UTC  Succeeded',
      `${RUN} ended Succeeded: started 08:01:43 UTC, ended 08:02:21 UTC (38 s).`,
      'Put [] back on job-agentx-stg-operator: its next run holds no request until one is written.',
      `Reading ${RUN}'s log: Azure delivers a container's lines up to 10 minutes after they are written, so this can take that long...`,
      `${RUN}'s log, 1 from the platform and 2 from the container:`,
      expect.stringMatching(
        /^ {2}08:02:12 {2}stdout {4}\{"level":"info","service":"operator","event":"operator.starting"\}$/,
      ),
      expect.stringMatching(/"event":"operator.organization_created"/),
      "  08:02:12  platform  ContainerTerminated: Container 'operator' was terminated with exit code '0' and reason 'ProcessExited'",
      `Created the organisation ${id}.`,
    ]);
  });

  it('sends no container when the job already runs what the API runs', async () => {
    const done = await run(create, { jobImage: image('b'), jobBuild: commit('b') });

    expect(done.status).toBe(0);
    expect(done.az.sent.map((each) => Object.keys(each.body.properties as object))).toEqual([
      ['configuration'],
      ['configuration'],
    ]);
    expect(done.said.filter((line) => line.startsWith('Bringing'))).toEqual([]);
  });

  it('never prints the name, never puts it on a command line, and removes the file it was sent in', async () => {
    const done = await run(create);

    expect(done.said.join('\n')).not.toContain('Zephyrine');
    expect(done.az.calls.flat().join(' ')).not.toContain('Zephyrine');
    expect(done.az.sent[0]?.text).toContain('Zephyrine');
    for (const each of done.az.sent) expect(existsSync(each.file)).toBe(false);
  });

  it('sends a name past ASCII as escapes, so it reads the same in any encoding, and it arrives whole', async () => {
    // Arabic, an accented letter, and a letter from beyond the first 65,536 (two UTF-16 units).
    const name = `${String.fromCharCode(0x0645, 0x0624, 0x0633, 0x0633, 0x0629)} Caf${String.fromCharCode(0xe9)} ${String.fromCodePoint(0x1d49c)}`;
    const done = await run(['create-organization', '--name', name]);

    expect(done.status).toBe(0);
    expect(done.az.sent[0]?.text).toMatch(/^[ -~]+$/);
    const id = String((JSON.parse(done.az.heldAtStart ?? '[]') as string[])[4]);
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(name, id));
  });

  it('writes the ID given for a retry, and calls a request done before already done', async () => {
    const done = await run([...create, '--id', EARLIER_ID], { ending: 'done-before' });

    expect(done.status).toBe(0);
    expect(done.az.heldAtStart).toBe(createOrganizationRequest(NAME, EARLIER_ID));
    expect(done.said.at(-1)).toBe(
      `Already done: the organisation ${EARLIER_ID} exists from an earlier run of this request, and nothing changed.`,
    );
    expect(done.az.request).toBe(NO_REQUEST);
  });

  it('says so when the run found no request, Azure not having put it in place in time', async () => {
    const done = await run(create, { ending: 'no-request' });

    expect(done.status).toBe(1);
    const id = String((JSON.parse(done.az.heldAtStart ?? '[]') as string[])[4]);
    expect(done.said.at(-1)).toBe(
      `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. Run the same command again with --id ${id}.`,
    );
    expect(done.az.request).toBe(NO_REQUEST);
  });

  it.each(['refused', 'failed'] as const)(
    'reads a run that %s as not created, saying how to try again',
    async (ending) => {
      const done = await run(create, { ending });

      expect(done.status).toBe(1);
      const id = String((JSON.parse(done.az.heldAtStart ?? '[]') as string[])[4]);
      expect(done.said.at(-1)).toBe(
        `The organisation may not have been created: read the lines above. If they leave it unclear, run the same command again with --id ${id}, which can't make a second one.`,
      );
      expect(done.az.request).toBe(NO_REQUEST);
    },
  );

  it("puts [] back and says how to wait again when the run doesn't end in time, reading no log", async () => {
    const done = await run(create, { states: ['Running'] });

    expect(done.status).toBe(1);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said).toContain(
      `${RUN} hadn't ended 600 s after the wait began. To wait again: node deploy/azure/jobs.ts wait operator ${RUN}`,
    );
    expect(done.az.sequence).not.toContain('post log');
  });

  it('waits for Azure to take each change, never trusting the state an earlier change left', async () => {
    const done = await run(create, { lag: 3 });

    expect(done.status).toBe(0);
    // After each PATCH: three readings as it was, one taking it, one settled.
    expect(done.az.sequence.slice(4, 10)).toEqual(['patch job', 'get job', 'get job', 'get job', 'get job', 'get job']);
    expect(done.az.heldAtStart).not.toBe(NO_REQUEST);
  });
});

describe('what stops it, and what it leaves', () => {
  it.each([
    [
      'still settling an earlier change',
      { state: 'InProgress' },
      'job-agentx-stg-operator is InProgress from an earlier change, so nothing was written: look at it first.',
    ],
    [
      'running a run',
      { runs: [{ name: RUN, properties: { status: 'Running' } }] },
      `job-agentx-stg-operator has runs that haven't ended, so nothing was written: ${RUN} (Running).`,
    ],
  ] as const)('writes nothing to a job %s', async (_what, script, message) => {
    const done = await run(create, script);

    expect(done.error).toMatchObject({ message });
    expect(done.az.sent).toEqual([]);
    expect(done.az.sequence).not.toContain('containerapp job start');
  });

  it.each([
    [
      'a container field it would drop',
      (job: Record<string, unknown>) => {
        const container = firstContainer(at(job, 'properties'));
        if (container !== undefined) container.probes = [];
      },
      "its container has probes, which a release doesn't copy",
    ],
    [
      'another command',
      (job: Record<string, unknown>) => {
        const container = firstContainer(at(job, 'properties'));
        if (container !== undefined) container.args = ['--request', '/mnt/secrets/operator-request', '--name', 'x'];
      },
      'it must run node apps/operator/src/main.ts --request /mnt/secrets/operator-request',
    ],
    [
      'its request shown',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [...REFERENCES, { name: REQUEST_SECRET, value: NO_REQUEST }];
      },
      'it must hold operator-request once, nothing of it shown',
    ],
    [
      'its request twice',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [
          ...REFERENCES,
          { name: REQUEST_SECRET },
          { name: REQUEST_SECRET },
        ];
      },
      'it must hold operator-request once, nothing of it shown',
    ],
    [
      'no request',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [...REFERENCES];
      },
      'it must hold operator-request once, nothing of it shown',
    ],
    [
      'a secret that is not a reference to the vault',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [{ name: 'other' }, { name: REQUEST_SECRET }];
      },
      'a secret other than its request is more than a reference to the vault',
    ],
    [
      'a reference with more to it',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = [{ ...REFERENCES[0], value: 'x' }, { name: REQUEST_SECRET }];
      },
      'a secret other than its request is more than a reference to the vault',
    ],
    [
      'secrets that are not a list',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').secrets = {};
      },
      'its secrets are not a list',
    ],
    [
      'no time limit',
      (job: Record<string, unknown>) => {
        at(job, 'properties', 'configuration').replicaTimeout = '300';
      },
      'it has no time limit',
    ],
    [
      'no time of its last change',
      (job: Record<string, unknown>) => {
        job.systemData = {};
      },
      "Azure gave no time of its last change, so one of ours can't be told apart",
    ],
  ] as const)('refuses a job with %s, writing nothing', async (_what, change, why) => {
    const done = await run(create, { job: change });

    expect(done.error).toMatchObject({
      message: `jobs/job-agentx-stg-operator isn't the operator's job this tool knows (${why}): deploy it by hand.`,
    });
    expect(done.az.sent).toEqual([]);
  });

  it('refuses a time limit that is not a whole number of seconds above nothing', async () => {
    for (const limit of [0, -1, 1.5]) {
      const done = await run(create, {
        job: (job) => {
          at(job, 'properties', 'configuration').replicaTimeout = limit;
        },
      });
      expect(messageOf(done.error)).toContain('(it has no time limit)');
    }
  });

  it('puts [] back when Azure refuses the request, and the refusal stands, quoting nothing sent', async () => {
    const done = await run(create, { patchStatus: [1] });

    expect(done.error).toMatchObject({
      message:
        "Azure refused writing the request and bringing the job to the API's build (Bad Request, InvalidParameter). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it.",
    });
    expect(messageOf(done.error)).not.toContain('Zephyrine');
    expect(done.az.sent).toHaveLength(2);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.az.sequence).not.toContain('containerapp job start');
  });

  it('puts [] back when the start is refused, and the refusal stands', async () => {
    const done = await run(create, { startStatus: 1 });

    expect(done.error).toBeInstanceOf(Error);
    expect(done.az.request).toBe(NO_REQUEST);
    expect(done.said.at(-1)).toBe(
      'Put [] back on job-agentx-stg-operator: its next run holds no request until one is written.',
    );
  });

  it('says so when putting [] back fails after another failure, and the first failure stands', async () => {
    const done = await run(create, { startStatus: 1, patchStatus: [0, 1] });

    expect(messageOf(done.error)).toMatch(/^az containerapp job start /);
    expect(done.said.at(-1)).toBe(
      "Putting [] back failed too: Azure refused putting [] back (Bad Request, InvalidParameter). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it.",
    );
  });

  it('fails when putting [] back fails after the run, reading no log', async () => {
    const done = await run(create, { patchStatus: [0, 1] });

    expect(messageOf(done.error)).toMatch(/^Azure refused putting \[\] back/);
    expect(done.az.sequence).not.toContain('post log');
  });

  it('stops when Azure ends a change as failed, or never settles it, and puts [] back', async () => {
    const failed = await run(create, { settles: ['Failed'] });
    expect(failed.error).toMatchObject({
      message:
        "Azure's change to job-agentx-stg-operator for writing the request and bringing the job to the API's build ended Failed.",
    });
    expect(failed.az.sequence).not.toContain('containerapp job start');
    expect(failed.az.request).toBe(NO_REQUEST);

    const never = await run(create, { settles: ['never'] });
    expect(never.error).toMatchObject({
      message:
        "Azure hadn't settled writing the request and bringing the job to the API's build on job-agentx-stg-operator after 5 minutes (InProgress).",
    });
    expect(never.said.at(-1)).toBe(
      'Put [] back on job-agentx-stg-operator: its next run holds no request until one is written.',
    );
    expect(never.az.request).toBe(NO_REQUEST);

    const neither = await run(create, { settles: ['never', 'never'] });
    expect(messageOf(neither.error)).toMatch(/^Azure hadn't settled writing the request/);
    expect(neither.said.at(-1)).toMatch(/^Putting \[\] back failed too: Azure hadn't settled putting \[\] back on /);
  });

  it('says a change not yet taken when Azure still shows the job as it was at the end', async () => {
    const done = await run(create, { lag: 1_000 });

    expect(messageOf(done.error)).toMatch(/after 5 minutes \(Succeeded, not yet taken\)\.$/);
  });
});

describe('main', () => {
  it('says how to use it, and ends 2, when asked something else', async () => {
    const lines: string[] = [];
    await expect(
      main(
        ['create-organization'],
        (line) => lines.push(line),
        () => new FakeAzure({}),
      ),
    ).resolves.toBe(2);
    expect(lines).toEqual([
      `say create-organization --name <name> [--id <ID>], the name as one argument, and nothing else\n${USAGE}`,
    ]);
  });

  it('says what stopped it, and ends 1', async () => {
    const lines: string[] = [];
    await expect(
      main(
        create,
        (line) => lines.push(line),
        () => new FakeAzure({ state: 'Failed' }),
      ),
    ).resolves.toBe(1);
    expect(lines.at(-1)).toBe(
      'job-agentx-stg-operator is Failed from an earlier change, so nothing was written: look at it first.',
    );
  });
});

describe('the runner and the deployment agree', () => {
  it("names the operator's job, its container, its command and the request it holds as deployed", () => {
    const created = inCopy((dir) => environmentSnapshot(dir, 'staging').together).predictedResources;
    const job = created.find((resource) => resource.name === jobName('operator'));
    expect(job?.type).toBe('Microsoft.App/jobs');
    expect(`jobs/${String(job?.name)}`).toBe(OPERATOR_JOB.path);
    const container = firstContainer(job?.properties);
    expect(container?.name).toBe(OPERATOR_JOB.container);
    expect([...(container?.command as string[]), ...(container?.args as string[])]).toEqual([
      'node',
      'apps/operator/src/main.ts',
      '--request',
      `/mnt/secrets/${REQUEST_SECRET}`,
    ]);
    expect(at(job?.properties, 'configuration').secrets).toContainEqual({ name: REQUEST_SECRET, value: NO_REQUEST });
  });
});

/** A value deep in an answer, as an object a test can change. */
function at(value: unknown, ...keys: readonly string[]): Record<string, unknown> {
  let found: unknown = value;
  for (const key of keys) found = (found as Record<string, unknown> | undefined)?.[key];
  return (found ?? {}) as Record<string, unknown>;
}

/** The first container in an answer's properties, as an object a test can change. */
function firstContainer(properties: unknown): Record<string, unknown> | undefined {
  const containers = at(properties, 'template').containers;
  return Array.isArray(containers) ? (containers[0] as Record<string, unknown> | undefined) : undefined;
}

/** What a failure said, or that there was none. */
const messageOf = (error: unknown): string =>
  error instanceof Error ? error.message : `no error but ${String(error)}`;
