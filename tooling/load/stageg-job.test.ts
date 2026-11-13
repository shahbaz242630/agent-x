// Stage G's jobs (stageg-job.ts): what each part accepts, the host guard that
// refuses before anything is reached, the plain-words refusal, and how k6 is
// run. The parts' work against a database is stageg-job.db.test.ts.
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { LogCapture, testLogger } from '../../packages/testing/src/index.ts';
import { afterAll, afterEach, describe, expect, it } from 'vitest';

import {
  checkedOf,
  commandOf,
  copyOf,
  main,
  partOf,
  run,
  type StageGMakers,
  stageGK6,
  StageGRefused,
  stageGRequestOf,
  stepOf,
} from './stageg-job.ts';
import { stageGProfile, stepRun } from './stageg.ts';

const COPY = 'psql-agentx-stg-g-a1b2c3d4';
const HOST = `${COPY}.postgres.database.azure.com`;
const SMOKE = stageGProfile('smoke');
const STEP = stepRun(SMOKE, SMOKE.steps[0] ?? SMOKE.steps.at(-1) ?? ({} as never));
const CHECKED = {
  created: 12,
  startedAt: '2026-11-06T10:00:00.000Z',
  endedAt: '2026-11-06T10:02:00.000Z',
  since: '2026-11-06T09:00:00.000Z',
};

/** Makers that fail the test if the job reaches for anything: every refusal here comes before a connection. */
const untouched: StageGMakers = {
  connect: () => {
    throw new Error('reached the database');
  },
  keyring: () => {
    throw new Error('read the keys');
  },
  k6: () => () => Promise.reject(new Error('ran k6')),
  print: () => {
    throw new Error('printed');
  },
};

describe('the part asked on the command line', () => {
  it('is one of mark, step or check, alone', () => {
    expect(partOf(['mark'])).toBe('mark');
    expect(partOf(['step'])).toBe('step');
    expect(partOf(['check'])).toBe('check');
    for (const argv of [[], ['first'], ['step', 'seed'], ['mark', 'mark']]) {
      expect(() => partOf(argv)).toThrow('Run it as node tooling/load/stageg-job.ts <mark|step|check>.');
    }
  });
});

describe('the host guard', () => {
  it('takes a throwaway copy’s host, and names its server', () => {
    expect(copyOf(HOST)).toBe(COPY);
  });

  it.each([
    ["staging's own server", 'psql-agentx-stg-abc123.postgres.database.azure.com'],
    ["the restore drill's copy", 'psql-agentx-stg-drill.postgres.database.azure.com'],
    ['a name alone', COPY],
    ['the laptop', '127.0.0.1'],
  ])('refuses %s, changing nothing', (_case, host) => {
    expect(() => copyOf(host)).toThrow(
      `AGENTX_LOAD_DB_HOST is ${host}, not a throwaway copy's host (psql-agentx-stg-g-<8 lower-case letters or digits>.postgres.database.azure.com): Stage G never runs on staging's own database. Nothing was changed.`,
    );
  });

  it.each(['mark', 'step', 'check'])(
    '%s refuses a host that is not a copy’s, or none, before reaching anything',
    async (part) => {
      await expect(main([part], {}, untouched)).rejects.toThrow('AGENTX_LOAD_DB_HOST is not set.');
      await expect(
        main([part], { AGENTX_LOAD_DB_HOST: 'psql-agentx-stg-abc123.postgres.database.azure.com' }, untouched),
      ).rejects.toThrow(/Stage G never runs on staging's own database/);
    },
  );
});

describe("the run's request", () => {
  it('takes its run and its words, and nothing else', () => {
    expect(stageGRequestOf(JSON.stringify({ runId: 'g1', command: ['seed', '--to', '100'] }))).toEqual({
      runId: 'g1',
      command: ['seed', '--to', '100'],
    });
  });

  it.each([
    ['not JSON', '{run'],
    ['as deployed', '{}'],
    ['a list', '[]'],
    ['no run', JSON.stringify({ command: ['seed'] })],
    ['an empty run', JSON.stringify({ runId: '', command: ['seed'] })],
    ['a run not text', JSON.stringify({ runId: 7, command: ['seed'] })],
    ['no words', JSON.stringify({ runId: 'g1', command: [] })],
    ['words not a list', JSON.stringify({ runId: 'g1', command: 'seed --to 100' })],
    ['a word not text', JSON.stringify({ runId: 'g1', command: ['seed', '--to', 100] })],
    ['agents beside it', JSON.stringify({ runId: 'g1', command: ['seed'], agents: [] })],
  ])('refuses %s', (_case, text) => {
    expect(() => stageGRequestOf(text)).toThrow(/run request/);
  });
});

describe('the commands each part takes', () => {
  it('load-step: seed --to <organisations>, or step <STEP json>', () => {
    expect(commandOf(['seed', '--to', '1000'], 'step')).toEqual({ kind: 'seed', orgs: 1000 });
    expect(commandOf(['pause'], 'step')).toEqual({ kind: 'pause' });
    expect(commandOf(['step', JSON.stringify(STEP)], 'step')).toEqual({ kind: 'step', step: STEP });
  });

  it('load-check: check <STEP json> <CHECKED json>, the label the step’s own', () => {
    expect(commandOf(['check', JSON.stringify(STEP), JSON.stringify(CHECKED)], 'check')).toEqual({
      kind: 'check',
      step: STEP,
      checked: { label: 'smoke', ...CHECKED, unansweredAtMost: 0 },
    });
  });

  it.each([
    [['seed', '--to', '0']],
    [['seed', '--to', '100001']],
    [['seed', '--to', '1e3']],
    [['seed', '--to', '-5']],
    [['seed', '--to']],
    [['seed', '1000']],
    [['seed', '--to', '100', 'more']],
    [['step']],
    [['check', JSON.stringify(STEP), JSON.stringify(CHECKED)]],
    [['mark']],
    [['pause', 'now']],
  ])('load-step refuses %j', (words) => {
    expect(() => commandOf(words, 'step')).toThrow(
      `load-step takes pause, seed --to <1 to 100000 organisations> or step <STEP json>, not ${words.join(' ')}.`,
    );
  });

  it.each([
    [['seed', '--to', '100']],
    [['step', JSON.stringify(STEP)]],
    [['check', JSON.stringify(STEP)]],
    [['pause']],
  ])('load-check refuses %j', (words) => {
    expect(() => commandOf(words, 'check')).toThrow(
      `load-check takes check <STEP json> <CHECKED json>, not ${words.join(' ')}.`,
    );
  });

  it.each([
    ['not JSON', '{step'],
    ['not an object', '[]'],
    ['an unknown test', JSON.stringify({ ...STEP, test: 'warmup' })],
    ['a label of another shape', JSON.stringify({ ...STEP, label: "smoke'; drop" })],
    ['a label of capitals', JSON.stringify({ ...STEP, label: 'Smoke' })],
    ['a label ending in a dash', JSON.stringify({ ...STEP, label: 'smoke-' })],
    ['no organisations', JSON.stringify({ ...STEP, orgs: 0 })],
    ['too many organisations', JSON.stringify({ ...STEP, orgs: 100_001 })],
    ['part of an organisation', JSON.stringify({ ...STEP, orgs: 1.5 })],
    ['another mix', JSON.stringify({ ...STEP, mix: 'crowd' })],
  ])('refuses a step with %s', (_case, text) => {
    expect(() => stepOf(text)).toThrow(/The step/);
  });

  it('takes the largest seed, and a step of one organisation', () => {
    expect(commandOf(['seed', '--to', '100000'], 'step')).toEqual({ kind: 'seed', orgs: 100_000 });
    expect(stepOf(JSON.stringify({ ...STEP, orgs: 1, label: 'rate-43' }))).toMatchObject({ orgs: 1 });
  });

  it.each([
    ['not JSON', '{n'],
    ['no count', JSON.stringify({ ...CHECKED, created: undefined })],
    ['a negative count', JSON.stringify({ ...CHECKED, created: -1 })],
    ['a start that is no time', JSON.stringify({ ...CHECKED, startedAt: 'soon' })],
    ['an end that is no time', JSON.stringify({ ...CHECKED, endedAt: 7 })],
    ['no first step', JSON.stringify({ ...CHECKED, since: undefined })],
    ['a negative allowance in flight', JSON.stringify({ ...CHECKED, unansweredAtMost: -1 })],
    ['part of a request in flight', JSON.stringify({ ...CHECKED, unansweredAtMost: 1.5 })],
  ])('refuses the step’s numbers with %s', (_case, text) => {
    expect(() => checkedOf(text, 'smoke')).toThrow(/The step['’]s numbers/);
  });

  it('takes how many a stopped climb cut off in flight, none when not given (S178)', () => {
    expect(checkedOf(JSON.stringify(CHECKED), 'smoke').unansweredAtMost).toBe(0);
    expect(checkedOf(JSON.stringify({ ...CHECKED, unansweredAtMost: 850 }), 'breaking').unansweredAtMost).toBe(850);
  });
});

describe('a refusal, run', () => {
  it('is logged in plain words as load.stageg_refused, and the job ends 1', async () => {
    const capture = new LogCapture();
    expect(await run(['mark'], { AGENTX_LOAD_DB_HOST: 'db.example.invalid' }, untouched, testLogger(capture))).toBe(1);
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        level: 'error',
        event: 'load.stageg_refused',
        reason: expect.stringMatching(
          /^AGENTX_LOAD_DB_HOST is db\.example\.invalid, not a throwaway copy's host/,
        ) as unknown,
        says: expect.stringMatching(/^A load test job refused to start/) as unknown,
      }),
    ]);
  });

  it('is never what anything else is: an unexpected failure is thrown as it is', async () => {
    const failing: StageGMakers = {
      ...untouched,
      connect: () => {
        throw new Error('the network is down');
      },
    };
    const dir = mkdtempSync(path.join(tmpdir(), 'agentx-stageg-test-'));
    try {
      const login = path.join(dir, 'login');
      writeFileSync(login, 'stand-in');
      await expect(
        run(['mark'], { AGENTX_LOAD_DB_HOST: HOST, AGENTX_DB_PASSWORD_FILE: login }, failing, testLogger()),
      ).rejects.toThrow('the network is down');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    expect(new StageGRefused('x')).toBeInstanceOf(Error);
  });

  it('reads the request from its file alone, and refuses one as deployed ({})', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'agentx-stageg-test-'));
    try {
      const request = path.join(dir, 'load-request');
      writeFileSync(request, '{}');
      await expect(main(['step'], { AGENTX_LOAD_DB_HOST: HOST }, untouched)).rejects.toThrow(
        'AGENTX_LOAD_REQUEST_FILE is not set.',
      );
      await expect(
        main(['check'], { AGENTX_LOAD_DB_HOST: HOST, AGENTX_LOAD_REQUEST_FILE: request }, untouched),
      ).rejects.toThrow(/The run request must be/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('k6, for one step', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentx-fake-k6-'));
  // A stand-in for k6: it says what it was given on its exit code, and exits as told.
  const fake = path.join(dir, 'fake-k6.mjs');
  const said = path.join(dir, 'said.json');
  writeFileSync(
    fake,
    [
      "import { readFileSync, writeFileSync } from 'node:fs';",
      "const seed = JSON.parse(readFileSync(process.env.SEED, 'utf8'));",
      `writeFileSync(${JSON.stringify(said)}, JSON.stringify({ step: JSON.parse(process.env.STEP), agents: seed.agents.length, api: process.env.API, args: process.argv.slice(2) }));`,
      "process.exit(Number(process.env.FAKE_K6_EXIT ?? '0'));",
    ].join('\n'),
  );
  const seeded = {
    agents: [
      {
        kind: 'ample' as const,
        orgId: 'o',
        agentId: 'a',
        sourceId: 's',
        supplierIds: ['p'],
        monthlyLimitMinor: '1',
        key: 'agx_test_key',
      },
    ],
  };
  const k6 = stageGK6([process.execPath, fake])('http://api.internal');
  const left = () => readdirSync(tmpdir()).filter((name) => name.startsWith('agentx-stageg-k6-'));
  const before = left();

  afterEach(() => {
    delete process.env.FAKE_K6_EXIT;
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("runs stage-g.k6.js with the step, the cohort's keys in a file and the API, leaving no file behind", async () => {
    expect(await k6(STEP, seeded)).toBe(true);
    expect(JSON.parse(readFileSync(said, 'utf8'))).toEqual({
      step: STEP,
      agents: 1,
      api: 'http://api.internal',
      args: ['run', '--quiet', '--no-usage-report', expect.stringMatching(/stage-g\.k6\.js$/) as unknown],
    });
    expect(left()).toEqual(before);
  });

  it('counts a failed threshold (99) as run to the end, and any other exit as not', async () => {
    process.env.FAKE_K6_EXIT = '99';
    expect(await k6(STEP, seeded)).toBe(true);
    process.env.FAKE_K6_EXIT = '2';
    expect(await k6(STEP, seeded)).toBe(false);
    expect(left()).toEqual(before);
  });
});
