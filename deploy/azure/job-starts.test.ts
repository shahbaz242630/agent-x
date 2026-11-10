// The watch on job runs with their containers changed (Carry-Forward S175).
// Nothing here reaches Azure: the CLI is a stand-in that answers each list from
// the jobs and runs a test gives it, the way `az rest` gives them.
import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import {
  azureTime,
  DEFAULT_HOURS,
  type DeployedJob,
  differences,
  main,
  parseArguments,
  type Run,
  templateOf,
  USAGE,
  verdictOf,
} from './job-starts.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000d';
const NOW = new Date('2026-11-10T14:00:00Z');
const GROUP_URL = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/jobs`;

/** Names assembled from their words, so no line pairs a secret-like name with a quoted value (GitGuardian, PRs #27 and #28). */
const setting = (...words: readonly string[]): string => words.join('_');

/** The operator's container as a job lists it, with made-up values. */
const OPERATOR = {
  name: 'operator',
  image: `ghcr.io/shahbaz242630/agent-x@sha256:${'a'.repeat(64)}`,
  command: ['node', 'apps/operator/src/main.ts'],
  args: ['--request', '/mnt/secrets/operator-request'],
  env: [
    { name: 'AGENTX_ENV', value: 'staging' },
    { name: setting('AGENTX', 'DB', 'PASSWORD', 'FILE'), value: '/mnt/secrets/db-operator-password' },
    { name: setting('AGENTX', 'HELD', 'REF'), secretRef: 'held-ref' },
  ],
  resources: { cpu: 0.5, memory: '1Gi' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
};

/** The same container as a run records it: no mounts, a type and a storage size of its own. */
const RAN = (changes: Partial<typeof OPERATOR> = {}): Record<string, unknown> => {
  const { volumeMounts: _mounts, ...rest } = OPERATOR;
  return {
    ...rest,
    imageType: 'ContainerImage',
    resources: { ...OPERATOR.resources, ephemeralStorage: '' },
    ...changes,
  };
};

/** A job as the resource group's list gives it: `lastModifiedAt` in UTC with no zone, as Azure writes it. */
const JOB = (name: string, containers: readonly unknown[], lastModifiedAt = '2026-11-10T02:18:42.2731403') => ({
  name,
  systemData: { lastModifiedAt },
  properties: { template: { containers, initContainers: null, volumes: [] } },
});

const EXECUTION = (
  name: string,
  startTime: string,
  containers: readonly unknown[],
  initContainers: unknown[] = [],
) => ({
  name,
  type: 'Microsoft.App/jobs/executions',
  properties: { startTime, status: 'Succeeded', template: { containers, initContainers } },
});

interface World {
  readonly jobs: readonly unknown[];
  readonly runs: Readonly<Record<string, readonly unknown[]>>;
  /** The URL Azure refuses, and with what. */
  readonly refuse?: { readonly url: string; readonly stderr: string };
  /** A second page for the jobs' list. */
  readonly nextPage?: { readonly link: string; readonly jobs: readonly unknown[] };
}

/** The CLI, answering from a world and recording every call. */
class FakeAz implements Az {
  readonly calls: string[][] = [];
  private readonly world: World;
  constructor(world: World) {
    this.world = world;
  }
  interactive(): number {
    throw new Error('the watch asks nothing');
  }
  run(args: readonly string[]): AzResult {
    this.calls.push([...args]);
    const ok = (body: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(body), stderr: '' });
    if (args[0] === 'account') return ok({ name: 'Pay-As-You-Go', id: SUBSCRIPTION });
    const url = args[args.indexOf('--url') + 1] ?? '';
    if (this.world.refuse !== undefined && url.startsWith(this.world.refuse.url)) {
      return { status: 1, stdout: '', stderr: this.world.refuse.stderr };
    }
    if (url === this.world.nextPage?.link) return ok({ value: this.world.nextPage.jobs });
    if (url === `${GROUP_URL}?api-version=2026-01-01`) {
      return ok({ value: this.world.jobs, ...(this.world.nextPage ? { nextLink: this.world.nextPage.link } : {}) });
    }
    const job = /\/jobs\/([^/]+)\/executions\?api-version=2026-01-01$/.exec(url)?.[1];
    if (job !== undefined) return ok({ value: this.world.runs[job] ?? [] });
    return { status: 1, stdout: '', stderr: `unexpected call: ${args.join(' ')}` };
  }
}

async function run(
  world: World,
  argv: readonly string[] = [],
): Promise<{ status: number; lines: string[]; az: FakeAz }> {
  const lines: string[] = [];
  const az = new FakeAz(world);
  const status = await main(
    argv,
    (line) => lines.push(line),
    () => az,
    () => NOW,
  );
  return { status, lines, az };
}

const OPERATOR_JOB = 'job-agentx-stg-operator';
const RUN_NAME = 'job-agentx-stg-operator-bvf2opt';
/** After the job's last change, inside the last six hours. */
const LATELY = '2026-11-10T12:16:55+00:00';

const oneRun = (containers: readonly unknown[], startTime = LATELY, initContainers: unknown[] = []): World => ({
  jobs: [JOB(OPERATOR_JOB, [OPERATOR])],
  runs: { [OPERATOR_JOB]: [EXECUTION(RUN_NAME, startTime, containers, initContainers)] },
});

describe('the job-start watch', () => {
  it('passes a run that ran its job as deployed, and reads no run older than the window', async () => {
    const world: World = {
      jobs: [
        JOB(OPERATOR_JOB, [OPERATOR]),
        JOB('job-agentx-stg-migrate', [{ ...OPERATOR, name: 'migrate', args: [] }]),
      ],
      runs: {
        [OPERATOR_JOB]: [
          EXECUTION(RUN_NAME, LATELY, [RAN()]),
          // Older than six hours, and changed: outside the window, so never read.
          EXECUTION('job-agentx-stg-operator-old', '2026-11-10T07:59:59+00:00', [RAN({ command: ['sh'] })]),
        ],
        // A run omits empty arguments; the job lists them as [].
        'job-agentx-stg-migrate': [
          EXECUTION('job-agentx-stg-migrate-x1', LATELY, [{ ...RAN({ name: 'migrate' }), args: undefined }]),
        ],
      },
    };
    const done = await run(world);
    expect(done.status).toBe(0);
    expect(done.lines).toEqual([
      `Signed in to the subscription "Pay-As-You-Go" (${SUBSCRIPTION}).`,
      'Reading the runs of 2 jobs started since 2026-11-10 08:00 UTC (the last 6 h).',
      `${RUN_NAME} (started 2026-11-10 12:16 UTC): ran the job as it is deployed.`,
      'job-agentx-stg-migrate-x1 (started 2026-11-10 12:16 UTC): ran the job as it is deployed.',
      "No run started since 2026-11-10 08:00 UTC ran other containers than its job's own.",
    ]);
    // Reads only: every call a GET or the account.
    for (const call of done.az.calls)
      expect(call[0] === 'account' || call.slice(0, 3).join(' ') === 'rest --method get').toBe(true);
  });

  it.each([
    ['a changed command', RAN({ command: ['sh', '-c'] }), 'the container operator ran another command'],
    ['changed arguments', RAN({ args: ['--other'] }), 'the container operator ran with other arguments'],
    [
      'another image',
      RAN({ image: 'ghcr.io/elsewhere/tool:1' }),
      'the container operator ran another image, from another repository',
    ],
    [
      'a changed setting value',
      RAN({ env: [{ name: 'AGENTX_ENV', value: 'hidden-value-xyz' }, ...OPERATOR.env.slice(1)] }),
      "the container operator's setting AGENTX_ENV differs from the job's",
    ],
    [
      'an added setting',
      RAN({ env: [...OPERATOR.env, { name: 'NODE_OPTIONS', value: 'hidden-value-xyz' }] }),
      "the container operator had a setting the job doesn't: NODE_OPTIONS",
    ],
    [
      'a setting pointed at another secret',
      RAN({ env: [...OPERATOR.env.slice(0, 2), { name: setting('AGENTX', 'HELD', 'REF'), secretRef: 'other-ref' }] }),
      `the container operator's setting ${setting('AGENTX', 'HELD', 'REF')} reads another secret, or none, than the job's`,
    ],
    [
      'a dropped setting',
      RAN({ env: OPERATOR.env.slice(0, 2) }),
      `the container operator lacked the job's setting ${setting('AGENTX', 'HELD', 'REF')}`,
    ],
  ])('finds %s, says what to do, and prints no value', async (_what, container, difference) => {
    const done = await run(oneRun([container]));
    expect(done.status).toBe(1);
    const said = done.lines.join('\n');
    expect(done.lines).toContain(`  - ${difference}`);
    expect(said).toContain(
      `FOUND: ${RUN_NAME} (started 2026-11-10 12:16 UTC, Succeeded) did not run ${OPERATOR_JOB} as it is deployed:`,
    );
    expect(said).toContain('treat it as a suspected breach (Incident-Response-Playbook section B; section T says how)');
    expect(said).toContain(
      `az containerapp job execution show --subscription ${SUBSCRIPTION} --resource-group rg-agentx-staging --name ${OPERATOR_JOB} --job-execution-name ${RUN_NAME}`,
    );
    for (const value of [
      'hidden-value-xyz',
      'sh',
      '--other',
      'other-ref',
      'ghcr.io/elsewhere',
      '/mnt/secrets/db-operator-password',
    ]) {
      expect(said.split(/[\s,:;()]+/)).not.toContain(value);
      expect(said).not.toContain(` ${value} `);
    }
    expect(said).not.toMatch(/hidden-value|elsewhere|other-ref|\/mnt\//);
  });

  it('finds an added container or init container, a missing one, and a name given twice', async () => {
    const extra = { ...RAN(), name: 'sidecar' };
    const done = await run(oneRun([RAN(), extra, extra], LATELY, [{ ...RAN(), name: 'first' }]));
    expect(done.status).toBe(1);
    expect(done.lines.filter((line) => line.startsWith('  - '))).toEqual([
      "  - it ran the container sidecar, which the job doesn't have",
      "  - it ran the container sidecar, which the job doesn't have",
      '  - it named a container twice',
      "  - it ran the init container first, which the job doesn't have",
    ]);
    const missing = await run(oneRun([{ ...RAN(), name: 'renamed' }]));
    expect(missing.lines).toContain("  - it didn't run the job's container operator");
    // A name with a line break can't write a workflow command into the log.
    const injected = await run(
      oneRun([RAN({ env: [...OPERATOR.env, { name: `X${String.fromCharCode(10)}::error::forged`, value: '' }] })]),
    );
    expect(injected.lines).toContain("  - the container operator had a setting the job doesn't: X???error??forged");
    const twice = await run(oneRun([RAN({ env: [...OPERATOR.env, { name: 'AGENTX_ENV', value: 'staging' }] })]));
    expect(twice.lines).toContain('  - the container operator named a setting twice');
  });

  it("lists a run older than its job's last change as not compared only when it differs as a deploy does", async () => {
    // The job changed at 13:02:02 UTC (written with no zone, as Azure does); the run started at 12:16.
    const world: World = {
      jobs: [JOB(OPERATOR_JOB, [OPERATOR], '2026-11-10T13:02:02.4268454')],
      runs: {
        [OPERATOR_JOB]: [
          EXECUTION(RUN_NAME, LATELY, [
            RAN({
              image: 'ghcr.io/shahbaz242630/agent-x@sha256:old',
              env: [{ name: 'AGENTX_ENV', value: 'before-the-release' }, ...OPERATOR.env.slice(1)],
            }),
          ]),
        ],
      },
    };
    const done = await run(world);
    expect(done.status).toBe(0);
    expect(done.lines).toContain(
      `::warning::${RUN_NAME} (started 2026-11-10 12:16 UTC): NOT COMPARED. It started before ${OPERATOR_JOB} last changed (2026-11-10 13:02 UTC), and differs from the job as it is now only as a deploy does (the container operator ran another image; the container operator's setting AGENTX_ENV differs from the job's). Check it by hand if nobody deployed then.`,
    );
    // The same run, unchanged, is simply clean: the job's change is no reason to doubt a run that matches it.
    const same = await run({ ...world, runs: { [OPERATOR_JOB]: [EXECUTION(RUN_NAME, LATELY, [RAN()])] } });
    expect(same.lines).toContain(`${RUN_NAME} (started 2026-11-10 12:16 UTC): ran the job as it is deployed.`);
    // Anything a deploy doesn't change stays a finding, however old the run: a routine write after an override
    // (a release, the operator's request taken off) must not hide it.
    const notRoutine: readonly (readonly [Record<string, unknown>, string])[] = [
      [RAN({ command: ['sh'] }), 'the container operator ran another command'],
      [RAN({ args: ['--other'] }), 'the container operator ran with other arguments'],
      [
        RAN({ image: 'ghcr.io/elsewhere/tool@sha256:old' }),
        'the container operator ran another image, from another repository',
      ],
      [
        RAN({ env: [...OPERATOR.env, { name: 'NODE_OPTIONS', value: 'x' }] }),
        "the container operator had a setting the job doesn't: NODE_OPTIONS",
      ],
      [RAN({ env: OPERATOR.env.slice(1) }), "the container operator lacked the job's setting AGENTX_ENV"],
      [
        RAN({ env: [{ name: 'AGENTX_ENV', secretRef: 'held-ref' }, ...OPERATOR.env.slice(1)] }),
        "the container operator's setting AGENTX_ENV reads another secret, or none, than the job's",
      ],
      [{ ...RAN(), name: 'sidecar' }, "it ran the container sidecar, which the job doesn't have"],
    ];
    for (const [container, difference] of notRoutine) {
      const old = await run({ ...world, runs: { [OPERATOR_JOB]: [EXECUTION(RUN_NAME, LATELY, [container])] } });
      expect(old.status).toBe(1);
      expect(old.lines).toContain(`  - ${difference}`);
    }
  });

  it("finds a job's run history that may be cut short, or a flood of runs of one job", async () => {
    const runsOf = (count: number, startOf: (index: number) => string): unknown[] =>
      Array.from({ length: count }, (_, index) =>
        EXECUTION(`${OPERATOR_JOB}-r${String(index)}`, startOf(index), [RAN()]),
      );
    const inside = (index: number): string => new Date(NOW.getTime() - (index + 1) * 60_000).toISOString();
    const world = (runs: unknown[]): World => ({
      jobs: [JOB(OPERATOR_JOB, [OPERATOR])],
      runs: { [OPERATOR_JOB]: runs },
    });
    // A hundred kept, every one inside the window: older ones in it may have fallen off.
    const full = await run(world(runsOf(100, inside)));
    expect(full.status).toBe(1);
    expect(full.lines).toContain(`FOUND: ${OPERATOR_JOB}'s runs can't all be checked:`);
    expect(full.lines).toContain(
      '  - the run history may be incomplete: Azure keeps 100 runs, and all 100 listed started in the window, so older runs in it may be gone unchecked',
    );
    expect(full.lines).toContain('  - it ran 100 times in 6 h, more than the 40 ever expected');
    // A hundred kept, the oldest outside the window: the window is whole, and 40 runs in it are not a flood.
    const whole = await run(world(runsOf(100, (index) => (index < 40 ? inside(index) : '2026-11-09T12:00:00+00:00'))));
    expect(whole.status).toBe(0);
    // 41 in six hours is.
    const busy = await run(world(runsOf(41, inside)));
    expect(busy.status).toBe(1);
    expect(busy.lines).toContain('  - it ran 41 times in 6 h, more than the 40 ever expected');
    expect(busy.lines.some((line) => line.includes('may be incomplete'))).toBe(false);
  });

  it("says Zitadel's stuck-step clean-up as itself, and anything more on that job as a finding", async () => {
    const SETUP = {
      ...OPERATOR,
      name: 'zitadel-setup',
      args: ['setup', '--masterkeyFile', '/mnt/secrets/zitadel-masterkey'],
    };
    const ran = { ...SETUP, args: ['setup', 'cleanup'] };
    const job = 'job-agentx-stg-zitadel-setup';
    const world = (containers: readonly unknown[]): World => ({
      jobs: [JOB(job, [SETUP])],
      runs: { [job]: [EXECUTION(`${job}-c1`, LATELY, containers)] },
    });
    const cleanUp = await run(world([ran]));
    expect(cleanUp.status).toBe(0);
    expect(cleanUp.lines).toContain(
      `${job}-c1 (started 2026-11-10 12:16 UTC): Zitadel's stuck-step clean-up (node deploy/azure/jobs.ts cleanup), its one known change. If nobody ran it then, treat it as a finding.`,
    );
    expect((await run(world([{ ...ran, command: ['sh'] }]))).status).toBe(1);
    expect((await run(world([ran, { ...ran, name: 'second' }]))).status).toBe(1);
    // The same arguments on another job are no clean-up.
    expect((await run(oneRun([RAN({ args: ['setup', 'cleanup'] })]))).status).toBe(1);
  });

  it('fails closed on a run or a job whose containers can not be read', async () => {
    const unreadable = await run({
      jobs: [JOB(OPERATOR_JOB, [OPERATOR])],
      runs: { [OPERATOR_JOB]: [{ name: RUN_NAME, properties: { startTime: LATELY, status: 'Running' } }] },
    });
    expect(unreadable.status).toBe(1);
    expect(unreadable.lines).toContain("  - Azure gave no containers for it that can be read, so it can't be checked");
    const badJob = await run({ jobs: [JOB(OPERATOR_JOB, [{ name: 'operator', command: 'node' }])], runs: {} });
    expect(badJob.status).toBe(1);
    expect(badJob.lines.at(-1)).toBe(
      `Azure listed a job "${OPERATOR_JOB}" whose containers can't be read, so no run of it can be checked.`,
    );
  });

  it('says plainly when Azure refuses, and that nothing was checked', async () => {
    const done = await run({
      jobs: [JOB(OPERATOR_JOB, [OPERATOR])],
      runs: {},
      refuse: { url: `${GROUP_URL}/${OPERATOR_JOB}/executions`, stderr: 'ERROR: (AuthorizationFailed) not allowed\n' },
    });
    expect(done.status).toBe(1);
    expect(done.lines.at(-1)).toBe(
      `Azure refused to list ${OPERATOR_JOB}'s runs, so no run was checked and nothing is known about them. What to do: read Azure's words below; if it is the sign-in or the role, check the watch's repository secrets (AZURE_WATCH_CLIENT_ID and the other two) and its role on rg-agentx-staging, then run the workflow again.\nERROR: (AuthorizationFailed) not allowed`,
    );
  });

  it("reads every page of a list, following only Resource Manager's own links", async () => {
    const link = `${GROUP_URL}?api-version=2026-01-01&$skiptoken=two`;
    const done = await run({
      jobs: [JOB(OPERATOR_JOB, [OPERATOR])],
      runs: { 'job-agentx-stg-second': [EXECUTION('job-agentx-stg-second-r1', LATELY, [RAN()])] },
      nextPage: { link, jobs: [JOB('job-agentx-stg-second', [OPERATOR])] },
    });
    expect(done.status).toBe(0);
    expect(done.lines[1]).toBe('Reading the runs of 2 jobs started since 2026-11-10 08:00 UTC (the last 6 h).');
    const elsewhere = await run({
      jobs: [JOB(OPERATOR_JOB, [OPERATOR])],
      runs: {},
      nextPage: { link: 'https://example.invalid/jobs?page=2', jobs: [] },
    });
    expect(elsewhere.az.calls.some((call) => call.includes('https://example.invalid/jobs?page=2'))).toBe(false);
  });

  it('refuses a list that is no list', async () => {
    const az: Az = {
      interactive: () => 0,
      run: (args) =>
        args[0] === 'account'
          ? { status: 0, stdout: JSON.stringify({ name: 'x', id: SUBSCRIPTION }), stderr: '' }
          : { status: 0, stdout: '{"error":"odd"}', stderr: '' },
    };
    const lines: string[] = [];
    expect(
      await main(
        [],
        (line) => lines.push(line),
        () => az,
      ),
    ).toBe(1);
    expect(lines.at(-1)).toBe("Azure's list of the jobs in rg-agentx-staging wasn't a list, so no run was checked.");
  });

  it('takes --hours, and refuses anything else with the usage', async () => {
    expect(parseArguments([])).toBe(DEFAULT_HOURS);
    expect(parseArguments(['--hours', '24'])).toBe(24);
    for (const argv of [
      ['--hours'],
      ['--hours', '0'],
      ['--hours', '1.5'],
      ['--hours', '999'],
      ['--days', '1'],
      ['--hours', '2', 'x'],
    ]) {
      expect(() => parseArguments(argv)).toThrow(/say nothing, or --hours/);
    }
    const lines: string[] = [];
    expect(
      await main(
        ['--days'],
        (line) => lines.push(line),
        () => new FakeAz({ jobs: [], runs: {} }),
      ),
    ).toBe(2);
    expect(lines.at(-1)).toContain(USAGE);
    // A run started a day ago is read only when asked for 24 hours.
    const dayOld = oneRun([RAN({ command: ['sh'] })], '2026-11-09T15:00:00+00:00');
    expect((await run(dayOld)).lines.some((line) => line.startsWith(RUN_NAME))).toBe(false);
    const asked = await run(dayOld, ['--hours', '24']);
    expect(asked.status).toBe(1);
    expect(asked.lines).toContain('  - the container operator ran another command');
  });
});

describe('reading what Azure gives', () => {
  it('reads a time with no zone as UTC, keeps a zone given, and refuses anything else', () => {
    expect(azureTime('2026-11-10T13:02:02.4268454')).toBe(Date.parse('2026-11-10T13:02:02.426Z'));
    expect(azureTime('2026-11-10T02:16:55+00:00')).toBe(Date.parse('2026-11-10T02:16:55Z'));
    expect(azureTime('2026-11-10T06:16:55+04:00')).toBe(Date.parse('2026-11-10T02:16:55Z'));
    for (const value of [undefined, 42, '', 'yesterday', '2026-13-45T99:99:99Z'])
      expect(azureTime(value)).toBeUndefined();
  });

  it('takes a missing list as empty, and anything unreadable as no template', () => {
    expect(templateOf({ containers: [{ name: 'a' }] })).toEqual({
      containers: [{ name: 'a', image: '', command: [], args: [], env: [] }],
      initContainers: [],
    });
    for (const value of [
      undefined,
      { containers: [] },
      { containers: 'x' },
      { containers: [{ name: 'a' }], initContainers: 'x' },
      { containers: [{ name: 'a', args: [1] }] },
      { containers: [{ name: 'a', env: {} }] },
      { containers: [null] },
    ]) {
      expect(templateOf(value)).toBeUndefined();
    }
    // A setting with neither a value nor a reference is compared as itself.
    expect(templateOf({ containers: [{ name: 'a', env: [null, { name: 'B' }] }] })?.containers[0]?.env).toEqual([
      { name: '' },
      { name: 'B' },
    ]);
  });

  it('compares a run with no start time, and one of a job that never said when it changed', () => {
    const template = templateOf({ containers: [OPERATOR] });
    const changed = templateOf({ containers: [RAN({ args: [] })] });
    if (template === undefined || changed === undefined) throw new Error('unreadable stand-in');
    const job: DeployedJob = { name: OPERATOR_JOB, changedAt: undefined, template };
    const ran: Run = { name: RUN_NAME, startedAt: undefined, status: '', template: changed };
    expect(verdictOf(job, ran).kind).toBe('changed');
    expect(verdictOf({ ...job, changedAt: NOW.getTime() }, ran).kind).toBe('changed');
    expect(differences(template, template)).toEqual([]);
  });
});
