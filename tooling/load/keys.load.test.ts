// The load test's keys step on the laptop (D2c), between the phases: a new
// key for each of the run's agents (seed.ts, rekeyed), written over the
// seed's file for phase 2, as Azure's second job makes its own. Run by
// `corepack pnpm load` (run.ts), never by the ordinary test run.
import { writeFileSync } from 'node:fs';

import { afterAll, expect, it } from 'vitest';

import { createDatabase } from '../../packages/platform/src/db/index.ts';
import { loadKeys } from '../../packages/platform/src/keys/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { APP_KEYS_DIR, loadConnection, readSeeded, SEED_FILE } from './plan.ts';
import { rekeyed } from './seed.ts';

const database = createDatabase<MandateWorldTables>(loadConnection(), testLogger());

afterAll(() => database.destroy());

it('gives each agent a new key for phase 2', { timeout: 120_000 }, async () => {
  const before = readSeeded();
  const after = await rekeyed(database, loadKeys({ directory: APP_KEYS_DIR, current: {} }), before);
  // The agents' keys: readable by this user alone.
  writeFileSync(SEED_FILE, JSON.stringify(after), { mode: 0o600 });
  expect(after.agents.map(({ agentId }) => agentId)).toEqual(before.agents.map(({ agentId }) => agentId));
  const unchanged = after.agents.filter(({ key }, n) => key === before.agents[n]?.key);
  expect(unchanged).toEqual([]);
});
