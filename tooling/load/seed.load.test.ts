// The load test's seed step on the laptop (D2): through the load stack's
// loopback port, as the app's own role, the run's organisations and agents
// (seed.ts). Its agents' keys go to the run's gitignored folder for k6. Run by
// `corepack pnpm load` (run.ts), never by the ordinary test run.
import { mkdirSync, writeFileSync } from 'node:fs';

import { afterAll, expect, it } from 'vitest';

import { createDatabase } from '../../packages/platform/src/db/index.ts';
import { loadKeys } from '../../packages/platform/src/keys/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { AMPLE_AGENTS, APP_KEYS_DIR, loadConnection, OUT_DIR, SEED_FILE } from './plan.ts';
import { seedRun } from './seed.ts';

const database = createDatabase<MandateWorldTables>(loadConnection(), testLogger());

afterAll(() => database.destroy());

it('seeds the ample agents and the capped one', { timeout: 600_000 }, async () => {
  const seeded = await seedRun({
    database,
    keyring: loadKeys({ directory: APP_KEYS_DIR, current: {} }),
    runId: process.env.AGENTX_LOAD_RUN_ID ?? 'local',
  });
  mkdirSync(OUT_DIR, { recursive: true });
  // The agents' keys: readable by this user alone.
  writeFileSync(SEED_FILE, JSON.stringify(seeded), { mode: 0o600 });
  expect(seeded.agents).toHaveLength(AMPLE_AGENTS + 1);
});
