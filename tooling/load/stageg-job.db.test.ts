// Stage G's jobs (stageg-job.ts) against a migrated database, its connections
// handed out by role and k6 stood in for (stageg-job.test.ts runs the real
// command): a step or check refused on a database with no sentinel, as
// staging's has none, changing nothing; the mark as the owner; then the seed,
// a step while hand-offs are paused (refused while they aren't), and the checks
// as the backup role.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { changeHandoffPause, createPlatformChain } from '../../packages/core/src/modules/platform-controls/index.ts';
import { createDatabase, type Database } from '../../packages/platform/src/db/index.ts';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { keys } from '../../apps/api/src/mandate-world.helper.test.ts';
import type { LoadTables, PrintedLine } from './job.ts';
import type { Seeded } from './plan.ts';
import { main, type StageGMakers } from './stageg-job.ts';
import { stageGOrgId } from './stageg-seed.ts';
import { stageGProfile, type StepRun, stepRun } from './stageg.ts';

const server = inject('postgres');
const COPY = 'psql-agentx-stg-g-a1b2c3d4';
const HOST = `${COPY}.postgres.database.azure.com`;
const RUN = 'g-db';
let database: TestDatabase;
let operator: Database<LoadTables>;
let dir: string;
const chain = createPlatformChain({ keys, ids: new SequentialIds(0x56e0_0000_0000) });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  operator = createDatabase<LoadTables>({ ...database.connection('operator'), maxConnections: 2 }, testLogger());
  dir = mkdtempSync(path.join(tmpdir(), 'agentx-stageg-db-'));
  writeFileSync(path.join(dir, 'login'), 'unused: the test hands out its own connections');
});

afterAll(async () => {
  await operator.destroy();
  await database.drop();
  rmSync(dir, { recursive: true, force: true });
});

const ROLE_OF: Readonly<Record<string, 'owner' | 'app' | 'backup'>> = {
  agentx_owner: 'owner',
  agentx_app: 'app',
  agentx_backup: 'backup',
};

/** The test database's connections by the role a part asks for, k6 answering `finished`; what each was asked kept. */
function makers(finished = true) {
  const printed: PrintedLine[] = [];
  const asked: { host: string; user: string }[] = [];
  const sent: { step: StepRun; seeded: Seeded }[] = [];
  const make: StageGMakers = {
    connect: (host, user) => {
      asked.push({ host, user });
      const role = ROLE_OF[user];
      if (role === undefined) throw new Error(`asked for ${user}`);
      return createDatabase<LoadTables>({ ...database.connection(role), maxConnections: 6 }, testLogger());
    },
    keyring: () => keys,
    k6: (api) => (step, seeded) => {
      expect(api).toBe('https://api.internal.example');
      sent.push({ step, seeded });
      return Promise.resolve(finished);
    },
    print: (line) => printed.push(line),
    hugeChainEvents: 3,
  };
  return { make, printed, asked, sent };
}

/** A part's settings, its request written to a file as the runner writes it onto the job. */
function settings(command: readonly string[]): NodeJS.ProcessEnv {
  const request = path.join(dir, `request-${String(Math.random()).slice(2)}`);
  writeFileSync(request, JSON.stringify({ runId: RUN, command }));
  const login = path.join(dir, 'login');
  return {
    AGENTX_LOAD_DB_HOST: HOST,
    AGENTX_LOAD_REQUEST_FILE: request,
    AGENTX_DB_PASSWORD_FILE: login,
    AGENTX_DB_APP_PASSWORD_FILE: login,
    AGENTX_DB_BACKUP_PASSWORD_FILE: login,
    AGENTX_KEYS_DIR: dir,
    AGENTX_LOAD_API: 'https://api.internal.example',
  };
}

const pauseMoved = (paused: boolean) =>
  operator
    .transaction()
    .execute((tx) =>
      changeHandoffPause(
        tx,
        { chain, keys, logger: testLogger() },
        { paused, reason: 'TEST-STAGE-G', actor: { type: 'system', id: 'operator' }, release: 'r-test', run: null },
      ),
    );

const organisations = async (): Promise<number> => {
  const backup = createDatabase<LoadTables>(database.connection('backup'), testLogger());
  try {
    const { n } = await backup
      .selectFrom('organizations.organizations')
      .select((eb) => eb.fn.countAll<string>().as('n'))
      .executeTakeFirstOrThrow();
    return Number(n);
  } finally {
    await backup.destroy();
  }
};

/** The app role's transactions left open now: the stuck organisation's, holding its suppliers, while a neighbours step runs. */
async function openTransactions(): Promise<number> {
  const app = createDatabase<{ 'pg_catalog.pg_stat_activity': { state: string | null; datname: string } }>(
    database.connection('app'),
    testLogger(),
  );
  try {
    const open = await app
      .selectFrom('pg_catalog.pg_stat_activity')
      .select('state')
      .where('state', '=', 'idle in transaction')
      .where('datname', '=', database.connection('app').database)
      .execute();
    return open.length;
  } finally {
    await app.destroy();
  }
}

const SMOKE = stageGProfile('smoke');
const STEP: StepRun = { ...stepRun(SMOKE, SMOKE.steps[0]!), orgs: 3 };

describe("Stage G's jobs on a database", () => {
  it('refuses a seed, a step or a check on a database with no sentinel, as staging’s, changing nothing', async () => {
    for (const command of [
      ['seed', '--to', '3'],
      ['step', JSON.stringify(STEP)],
    ]) {
      const { make, sent } = makers();
      await expect(main(['step'], settings(command), make)).rejects.toThrow(
        `The database at ${COPY} carries no Stage G sentinel, so it may be staging's own: nothing was changed. Run the load-mark job on the copy first.`,
      );
      expect(sent).toEqual([]);
    }
    const { make, asked } = makers();
    const checked = {
      created: 1,
      startedAt: '2026-11-06T10:00:00Z',
      endedAt: '2026-11-06T10:01:00Z',
      since: '2026-11-06T10:00:00Z',
    };
    await expect(
      main(['check'], settings(['check', JSON.stringify(STEP), JSON.stringify(checked)]), make),
    ).rejects.toThrow(/carries no Stage G sentinel/);
    // Refused on the app's connection: the backup role is never reached.
    expect(asked).toEqual([{ host: HOST, user: 'agentx_app' }]);
    expect(await organisations()).toBe(0);
  });

  it('marks the copy as its owner, on its own host', async () => {
    const { make, printed, asked } = makers();
    expect(await main(['mark'], settings([]), make)).toBe(0);
    expect(asked).toEqual([{ host: HOST, user: 'agentx_owner' }]);
    expect(printed).toEqual([{ event: 'load.stageg_marked', server: COPY }]);
  });

  it('then seeds the run’s organisations as the app, printing what it made', async () => {
    const { make, printed } = makers();
    expect(await main(['step'], settings(['seed', '--to', '3']), make)).toBe(0);
    expect(printed).toEqual([
      expect.objectContaining({
        event: 'load.stageg_seeded',
        runId: RUN,
        orgs: 3,
        found: 0,
        made: { idle: 0, light: 1, heavy: 1, 'huge-chain': 1 },
        incomplete: [],
      }),
    ]);
    expect(await organisations()).toBe(3);
  });

  it('refuses a step while hand-offs are not paused, sending nothing', async () => {
    await pauseMoved(false);
    const { make, sent } = makers();
    await expect(main(['step'], settings(['step', JSON.stringify(STEP)]), make)).rejects.toThrow(
      /^Nothing was changed: hand-offs are .* before the step, not paused/,
    );
    expect(sent).toEqual([]);
    await pauseMoved(true);
  });

  it("sends the step as the cohort's agents, each newly keyed, and says k6 ran to the end", async () => {
    const { make, printed, sent } = makers();
    expect(await main(['step'], settings(['step', JSON.stringify(STEP)]), make)).toBe(0);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.step).toEqual(STEP);
    // The steady cohort of three organisations: the light one's agent alone, with a key.
    expect(sent[0]?.seeded.agents.map(({ kind, orgId }) => ({ kind, orgId }))).toEqual([
      { kind: 'ample', orgId: stageGOrgId(RUN, 2) },
    ]);
    expect(sent[0]?.seeded.agents[0]?.key).toMatch(/^axk_/);
    expect(printed).toEqual([
      { event: 'load.stageg_stepped', runId: RUN, test: 'smoke', label: 'smoke', cohort: 1, finished: true },
    ]);
    expect(JSON.stringify(printed)).not.toContain('axk_');
  });

  it('ends 1 when k6 stopped short', async () => {
    const { make, printed } = makers(false);
    expect(await main(['step'], settings(['step', JSON.stringify(STEP)]), make)).toBe(1);
    expect(printed).toEqual([expect.objectContaining({ event: 'load.stageg_stepped', finished: false })]);
  });

  it(
    'holds the stuck organisation for a neighbours step, its cohort the calm, busy and stuck agents',
    { timeout: 600_000 },
    async () => {
      const NEIGHBOURS = stageGProfile('neighbours');
      const step: StepRun = { ...stepRun(NEIGHBOURS, NEIGHBOURS.steps[0]!), orgs: 3 };
      const few = makers();
      // One heavy organisation of three: no stuck one, so no cohort can be made and nothing is sent.
      await expect(main(['step'], settings(['step', JSON.stringify(step)]), few.make)).rejects.toThrow(
        /has no neighbour-stuck agent/,
      );
      expect(few.sent).toEqual([]);
      // Grown to the second heavy organisation, the stuck one: its suppliers are held while k6 runs.
      const grow = makers();
      expect(await main(['step'], settings(['seed', '--to', '202']), grow.make)).toBe(0);
      const { make, sent } = makers();
      let stuckWhileSent = false;
      const held: StageGMakers = {
        ...make,
        k6: (api) => async (sentStep, seeded) => {
          stuckWhileSent = (await openTransactions()) === 1;
          return make.k6(api)(sentStep, seeded);
        },
      };
      expect(await main(['step'], settings(['step', JSON.stringify({ ...step, orgs: 202 })]), held)).toBe(0);
      expect(stuckWhileSent).toBe(true);
      expect(new Set(sent[0]?.seeded.agents.map(({ kind }) => kind))).toEqual(
        new Set(['neighbour-calm', 'neighbour-busy', 'neighbour-stuck']),
      );
      expect(await openTransactions()).toBe(0);
    },
  );

  it('checks the step as the backup role and the app, and ends 1 when a check finds something', async () => {
    const { make, printed, asked } = makers();
    const checked = {
      created: 1,
      startedAt: new Date(Date.now() - 60_000).toISOString(),
      endedAt: new Date().toISOString(),
      since: new Date(Date.now() - 60_000).toISOString(),
    };
    expect(await main(['check'], settings(['check', JSON.stringify(STEP), JSON.stringify(checked)]), make)).toBe(1);
    expect(asked).toEqual([
      { host: HOST, user: 'agentx_app' },
      { host: HOST, user: 'agentx_backup' },
    ]);
    const [line] = printed;
    expect(line).toMatchObject({ event: 'load.stageg_checked', runId: RUN, test: 'smoke', label: 'smoke' });
    // k6 was stood in for: the one request it says it made isn't there, and no request holds money to compare.
    const checks = (line?.checks ?? []) as { name: string; failures: string[] }[];
    expect(checks.filter(({ failures }) => failures.length > 0).map(({ name }) => name)).toEqual([
      'lost no request: the step’s own requests are as many as k6 was answered 201 for',
      'the active cohort: holds exactly one reservation and one open claim for each request holding money, and none for the rest',
    ]);
  });
});
