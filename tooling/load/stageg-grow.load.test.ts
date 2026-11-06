// Stage G's seed on the laptop's load stack (4D2e, PL-62): 100 organisations,
// then grown to 300 by the same call, proving a re-run makes only what is
// missing and never an organisation twice; the cohort's agents, keyed, written
// where stage-g.k6.js reads them; and the API's first anchor check after a
// restart reading every chain, the seeded ones among them, with nothing failed.
// Each seed's numbers are printed (seconds per organisation by kind). Run with
// the load stack up (run.ts's compose files):
//   AGENTX_LOAD_DB_PASSWORD=... node node_modules/vitest/vitest.mjs run --config vitest.load.config.ts stageg-grow
// AGENTX_STAGE_G_WORKERS and AGENTX_STAGE_G_HUGE_CHAIN set the workers and the long chain's length.
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { createDatabase } from '../../packages/platform/src/db/index.ts';
import { API_PURPOSES, loadKeys, OPERATOR_ONLY } from '../../packages/platform/src/keys/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import {
  APP_KEYS_DIR,
  loadConnection,
  loadOrgName,
  OUT_DIR,
  SEED_FILE,
  STAGE_G_HUGE_CHAIN_EVENTS,
  STAGE_G_SEED_WORKERS,
} from './plan.ts';
import { asAdmin, COMPOSE } from './run.ts';
import { rekeyed } from './seed.ts';
import { stageGCohort, stageGSeed, type StageGSeeded } from './stageg-seed.ts';

const workers = Number(process.env.AGENTX_STAGE_G_WORKERS ?? STAGE_G_SEED_WORKERS);
const hugeChainEvents = Number(process.env.AGENTX_STAGE_G_HUGE_CHAIN ?? STAGE_G_HUGE_CHAIN_EVENTS);
const runId = process.env.AGENTX_LOAD_RUN_ID ?? `stage-g ${new Date().toISOString()}`;
const database = createDatabase<MandateWorldTables>({ ...loadConnection(), maxConnections: workers + 2 }, testLogger());
const keyring = loadKeys({ directory: APP_KEYS_DIR, current: {} }, API_PURPOSES, OPERATOR_ONLY);
const seeded = (orgs: number) => stageGSeed({ database, keyring, runId, orgs, workers, hugeChainEvents });

afterAll(() => database.destroy());

/** Where each step's numbers go, one JSON line each: Vitest keeps a passing test's output to itself. */
const NUMBERS_FILE = path.join(OUT_DIR, 'stageg-seed.jsonl');

const noted = (line: Record<string, unknown>): void => {
  mkdirSync(OUT_DIR, { recursive: true });
  appendFileSync(
    NUMBERS_FILE,
    `${JSON.stringify(line)}
`,
  );
};

/** One seed's numbers, each kind's seconds an organisation, for the report. */
function printed(seed: StageGSeeded): void {
  const each = Object.fromEntries(
    Object.entries(seed.made).map(([kind, made]) => [
      kind,
      made === 0 ? null : seed.seconds[kind as keyof typeof seed.seconds] / made,
    ]),
  );
  noted({ event: 'load.stageg_seeded', runId, workers, hugeChainEvents, ...seed, secondsEach: each });
}

const total = (seed: StageGSeeded): number => Object.values(seed.made).reduce((sum, n) => sum + n, 0);

/** The run's organisations as the database's admin counts them past every tenant wall: all, and distinct IDs. */
function counted(): { all: number; distinct: number } {
  const name = loadOrgName(runId).replaceAll("'", "''");
  const [all, distinct] = asAdmin(
    `select count(*) || ' ' || count(distinct id) from organizations.organizations where name = '${name}'`,
    'agentx',
  )
    .split(' ')
    .map(Number);
  return { all: all ?? 0, distinct: distinct ?? 0 };
}

describe('Stage G seed (4D2e, PL-62)', () => {
  it('seeds 100 organisations', { timeout: 3_600_000 }, async () => {
    const first = await seeded(100);
    printed(first);
    expect({ found: first.found, made: total(first), incomplete: first.incomplete }).toEqual({
      found: 0,
      made: 100,
      incomplete: [],
    });
    expect(first.made).toEqual({ idle: 96, light: 2, heavy: 1, 'huge-chain': 1 });
  });

  it('grows the same set to 300, making only the 200 missing', { timeout: 3_600_000 }, async () => {
    const grown = await seeded(300);
    printed(grown);
    expect({ found: grown.found, made: total(grown), incomplete: grown.incomplete }).toEqual({
      found: 100,
      made: 200,
      incomplete: [],
    });
    expect(counted()).toEqual({ all: 300, distinct: 300 });
  });

  it("writes the neighbours cohort's agents, keyed, where stage-g.k6.js reads them", async () => {
    const steady = await stageGCohort({ database, runId, orgs: 300, mix: 'steady' });
    expect(steady.map(({ kind }) => kind)).toEqual(Array.from({ length: 6 }, () => 'ample'));
    const cohort = await stageGCohort({ database, runId, orgs: 300, mix: 'neighbours' });
    const kinds = cohort.reduce<Record<string, number>>((n, { kind }) => ({ ...n, [kind]: (n[kind] ?? 0) + 1 }), {});
    expect(kinds).toEqual({ 'neighbour-calm': 6, 'neighbour-busy': 10, 'neighbour-stuck': 10 });
    const keyed = await rekeyed(database, keyring, { agents: cohort });
    mkdirSync(OUT_DIR, { recursive: true });
    // The agents' keys: readable by this user alone, never printed.
    writeFileSync(SEED_FILE, JSON.stringify(keyed), { mode: 0o600 });
    expect(new Set(keyed.agents.map(({ key }) => key)).size).toBe(cohort.length);
  });

  it(
    "the API's first anchor check after a restart reads every chain and finds none failed",
    { timeout: 900_000 },
    async () => {
      const since = new Date().toISOString();
      const docker = (...args: string[]) =>
        spawnSync('docker', [...COMPOSE, ...args], { encoding: 'utf8', windowsHide: true, maxBuffer: 256 * 1024 ** 2 });
      expect(docker('restart', 'api').status).toBe(0);
      expect(docker('up', '--wait', '--no-deps', 'api').status).toBe(0);
      let done: Record<string, unknown> | undefined;
      for (let tries = 0; done === undefined && tries < 160; tries += 1) {
        await new Promise((resolve) => setTimeout(resolve, 5000));
        done = docker('logs', '--since', since, '--no-log-prefix', '--no-color', 'api')
          .stdout.split('\n')
          .filter((line) => line.includes('"audit.anchor_check_done"'))
          .map((line) => JSON.parse(line) as Record<string, unknown>)
          .at(0);
      }
      expect(done).toBeDefined();
      noted({ ...done, runId });
      expect(Number(done?.chains)).toBeGreaterThanOrEqual(300);
      expect({ failed: done?.failed, unchecked: done?.unchecked, left: done?.left }).toEqual({
        failed: 0,
        unchecked: 0,
        left: 0,
      });
    },
  );
});
