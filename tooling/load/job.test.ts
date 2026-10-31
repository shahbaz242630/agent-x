// The load test's jobs (D2c, job.ts): what they accept, and how k6 is run.
// The jobs' work against a database is job.db.test.ts.
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, afterEach, describe, expect, it } from 'vitest';

import { agentsOf, main, type PrintedAgent, requestOf, runK6 } from './job.ts';

const AGENT: PrintedAgent = {
  kind: 'ample',
  orgId: '01a17c20-0000-7000-8000-000000000001',
  agentId: '01a17c20-0000-7000-8000-000000000002',
  sourceId: '01a17c20-0000-7000-8000-000000000003',
  supplierIds: ['01a17c20-0000-7000-8000-000000000004'],
  monthlyLimitMinor: '2000000',
};

describe("the run's agents, as load.ts hands them to the second job", () => {
  it('takes them as load.seeded_agent printed them', () => {
    const agents = [
      AGENT,
      { ...AGENT, kind: 'capped', agentId: 'capped', orgId: '01a17c20-0000-7000-8000-000000000009' },
    ];
    expect(agentsOf(JSON.stringify(agents))).toEqual(agents);
  });

  it.each([
    ['not JSON', '{agents'],
    ['not a list', JSON.stringify({ agents: [AGENT] })],
    ['no agents', '[]'],
    ['a key among them', JSON.stringify([{ ...AGENT, key: 'agx_live_secret' }])],
    ['another kind', JSON.stringify([{ ...AGENT, kind: 'spike' }])],
    ['an empty ID', JSON.stringify([{ ...AGENT, orgId: '' }])],
    ['an ID missing', JSON.stringify([{ ...AGENT, sourceId: undefined }])],
    ['no suppliers', JSON.stringify([{ ...AGENT, supplierIds: [] }])],
    ['a supplier not named', JSON.stringify([{ ...AGENT, supplierIds: [7] }])],
    ['one good and one not', JSON.stringify([AGENT, null])],
    ['the same organisation twice', JSON.stringify([AGENT, { ...AGENT, agentId: 'another', kind: 'capped' }])],
    [
      'a crowd in an ample agent’s organisation',
      JSON.stringify([AGENT, { ...AGENT, agentId: 'b', kind: 'crowd-own' }]),
    ],
    [
      'the same agent twice',
      JSON.stringify([
        { ...AGENT, kind: 'crowd-own' },
        { ...AGENT, kind: 'crowd-own' },
      ]),
    ],
  ])('refuses %s', (_case, text) => {
    expect(() => agentsOf(text)).toThrow(/AGENTX_LOAD_SEEDED/);
  });

  it('lets the neighbours’ crowds share an organisation, but never the calm ones', () => {
    for (const kind of ['neighbour-busy', 'neighbour-stuck']) {
      const crowd = [
        { ...AGENT, kind, agentId: 'a' },
        { ...AGENT, kind, agentId: 'b' },
      ];
      expect(agentsOf(JSON.stringify(crowd))).toEqual(crowd);
    }
    const calm = [
      { ...AGENT, kind: 'neighbour-calm', agentId: 'a' },
      { ...AGENT, kind: 'neighbour-calm', agentId: 'b' },
    ];
    expect(() => agentsOf(JSON.stringify(calm))).toThrow('names an organisation twice');
    expect(agentsOf(JSON.stringify(calm.slice(0, 1)))).toEqual(calm.slice(0, 1));
  });

  it('lets a crowd’s agents share their organisation', () => {
    const crowd = [
      { ...AGENT, kind: 'crowd-shared', agentId: 'a' },
      { ...AGENT, kind: 'crowd-shared', agentId: 'b' },
    ];
    expect(agentsOf(JSON.stringify(crowd))).toEqual(crowd);
  });
});

describe('the command line and settings', () => {
  it.each([[[]], [['third']], [['first', 'extra']]])('refuses %j before reading any setting', async (argv) => {
    await expect(main(argv, {})).rejects.toThrow('Run it as node tooling/load/job.ts <first|second|cleanup>.');
  });

  it('refuses a missing setting by name, before it reaches the database', async () => {
    await expect(main(['first'], {})).rejects.toThrow('AGENTX_LOAD_DB_HOST is not set.');
    await expect(main(['first'], { AGENTX_LOAD_DB_HOST: 'db.example.invalid' })).rejects.toThrow(
      'AGENTX_DB_PASSWORD_FILE is not set.',
    );
  });

  it("reads the run's values from its request file alone, never from its own settings", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'agentx-load-request-'));
    try {
      const loginFile = path.join(dir, 'db-app-login');
      const request = path.join(dir, 'load-request');
      writeFileSync(loginFile, 'stand-in');
      writeFileSync(request, '{}');
      const settings = { AGENTX_LOAD_DB_HOST: 'db.example.invalid', AGENTX_DB_PASSWORD_FILE: loginFile };
      await expect(main(['first'], settings)).rejects.toThrow('AGENTX_LOAD_REQUEST_FILE is not set.');
      // As deployed, the request is {}: a run started without one changes nothing, whatever its settings say.
      await expect(
        main(['first'], { ...settings, AGENTX_LOAD_REQUEST_FILE: request, AGENTX_LOAD_RUN_ID: 'r1' }),
      ).rejects.toThrow('AGENTX_LOAD_RUN_ID is not set.');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("the run's request, as load.ts writes it onto the job", () => {
  it('takes the run values and the smoke flag, each as text', () => {
    const request = { AGENTX_LOAD_RUN_ID: 'r1', AGENTX_LOAD_SEEDED: '[]', AGENTX_LOAD_CREATED_FIRST: '12' };
    expect(requestOf(JSON.stringify(request))).toEqual(request);
    expect(requestOf('{}')).toEqual({});
    expect(requestOf(JSON.stringify({ AGENTX_LOAD_RUN_ID: 'r1', AGENTX_LOAD_SMOKE: '1' }))).toEqual({
      AGENTX_LOAD_RUN_ID: 'r1',
      AGENTX_LOAD_SMOKE: '1',
    });
  });

  it.each([
    ['not JSON', '{run'],
    ['not an object', '"r1"'],
    ['a list', '[]'],
    ['nothing', 'null'],
    ['another setting', JSON.stringify({ AGENTX_LOAD_RUN_ID: 'r1', AGENTX_LOAD_DB_HOST: 'elsewhere' })],
    ['a value not text', JSON.stringify({ AGENTX_LOAD_CREATED_FIRST: 12 })],
  ])('refuses %s', (_case, text) => {
    expect(() => requestOf(text)).toThrow(/run request/);
  });
});

describe('k6, for one phase', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentx-fake-k6-'));
  // A stand-in for k6: it writes the summary file k6's handleSummary writes, from what it was given, and exits as told.
  const fake = path.join(dir, 'fake-k6.mjs');
  writeFileSync(
    fake,
    [
      "import { readFileSync, writeFileSync } from 'node:fs';",
      "const seed = JSON.parse(readFileSync(process.env.SEED, 'utf8'));",
      'const summary = { phase: Number(process.env.PHASE), created: seed.agents.length, api: process.env.API, smoke: process.env.SMOKE, args: process.argv.slice(2) };',
      "if (process.env.FAKE_K6_EXIT !== '2') writeFileSync(`${process.env.OUT}/k6-phase-${process.env.PHASE}.json`, JSON.stringify(summary));",
      "process.exit(Number(process.env.FAKE_K6_EXIT ?? '0'));",
    ].join('\n'),
  );
  const seeded = { agents: [{ ...AGENT, key: 'agx_test_key' }] };
  const k6 = runK6('http://api.internal', [process.execPath, fake]);
  const left = () => readdirSync(tmpdir()).filter((name) => name.startsWith('agentx-load-'));
  const before = left();

  afterEach(() => {
    delete process.env.FAKE_K6_EXIT;
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("runs the script against the API with the seed's file, reads its summary, and leaves no file behind", () => {
    expect(k6(2, seeded)).toEqual({
      finished: true,
      result: {
        phase: 2,
        created: 1,
        api: 'http://api.internal',
        smoke: '0',
        args: ['run', '--quiet', expect.stringMatching(/money-paths\.k6\.js$/) as unknown],
      },
    });
    expect(left()).toEqual(before);
  });

  it("tells the script it is the wiring run's short k6 only when asked (load.ts run --smoke)", () => {
    expect(runK6('http://api.internal', [process.execPath, fake], true)(1, seeded).result).toMatchObject({
      smoke: '1',
    });
  });

  it('counts a failed threshold (99) as run to the end: the report says which', () => {
    process.env.FAKE_K6_EXIT = '99';
    expect(k6(1, seeded).finished).toBe(true);
  });

  it('counts any other exit, or a k6 that never started, as not finished, with no numbers', () => {
    process.env.FAKE_K6_EXIT = '2';
    expect(k6(1, seeded)).toEqual({ finished: false, result: undefined });
    expect(runK6('http://api.internal', ['agentx-no-such-k6'])(1, seeded)).toEqual({
      finished: false,
      result: undefined,
    });
    expect(left()).toEqual(before);
  });
});
