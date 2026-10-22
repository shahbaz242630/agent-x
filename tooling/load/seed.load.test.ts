// The load test's seed (D2): through the load stack's loopback port, as the
// app's own role, the organisations and agents the k6 script asks as, built by
// the database tests' own world and signed with the keys the stack's API
// reads. Its agents' keys go to the run's gitignored folder for k6. Run by
// `corepack pnpm load` (run.ts), never by the ordinary test run.
import { mkdirSync, writeFileSync } from 'node:fs';

import { afterAll, expect, it } from 'vitest';

import { uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import { createDatabase } from '../../packages/platform/src/db/index.ts';
import { loadKeys } from '../../packages/platform/src/keys/index.ts';
import { FixedClock, testLogger } from '../../packages/testing/src/index.ts';

import { createMandateRegistry } from '../../apps/api/src/mandate-registry.ts';
import { AED, mandateWorld, type MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import {
  AMPLE_AGENTS,
  APP_KEYS_DIR,
  APPROVAL_THRESHOLD_MINOR,
  CAPPED_MONTHLY_MINOR,
  loadConnection,
  OUT_DIR,
  SEED_FILE,
  type Seeded,
  type SeededAgent,
} from './plan.ts';

const database = createDatabase<MandateWorldTables>(loadConnection(), testLogger());
// The stack's clock is the real one, and sealed times are Postgres's: the seed's starts now.
const clock = new FixedClock(new Date());
const keyring = loadKeys({ directory: APP_KEYS_DIR, current: {} });
const shared = mandateWorld({ app: () => database, clock: () => clock, ids: uuidV7Ids, name: 'load', keyring });
const registry = createMandateRegistry({ database, keys: keyring, ids: uuidV7Ids, clock, logger: testLogger() });

afterAll(() => database.destroy());

/** An organisation with three verified suppliers and an agent with a mandate in force and a key. */
async function seeded(kind: SeededAgent['kind']): Promise<SeededAgent> {
  const w = await shared.world({ suppliers: 3 });
  for (const id of w.suppliers) await shared.verified(w, id);
  const capped = kind === 'capped' ? AED(CAPPED_MONTHLY_MINOR) : undefined;
  const terms = {
    approvalThreshold: AED(APPROVAL_THRESHOLD_MINOR),
    ...(capped === undefined ? {} : { perOrderLimit: capped, monthlyLimit: capped }),
  };
  await shared.inForce(registry, w, terms);
  const acting = await shared.agentKey(w);
  return {
    kind,
    orgId: w.org,
    agentId: w.agent,
    key: acting.text,
    sourceId: w.source,
    supplierIds: w.suppliers,
    monthlyLimitMinor: String(shared.termsOf(w, terms).monthlyLimit.minor),
  };
}

it('seeds the ample agents and the capped one', { timeout: 600_000 }, async () => {
  const agents: SeededAgent[] = [];
  for (let n = 0; n < AMPLE_AGENTS; n += 1) agents.push(await seeded('ample'));
  agents.push(await seeded('capped'));
  mkdirSync(OUT_DIR, { recursive: true });
  // The agents' keys: readable by this user alone.
  writeFileSync(SEED_FILE, JSON.stringify({ agents } satisfies Seeded), { mode: 0o600 });
  expect(agents).toHaveLength(AMPLE_AGENTS + 1);
});
