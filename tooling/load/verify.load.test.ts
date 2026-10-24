// The load test's database checks on the laptop (D2, checks.ts), each its own
// test so the run's output names the one that failed. Run by `corepack pnpm
// load` (run.ts), which gives it k6's count of new requests.
import { afterAll, describe, expect, it } from 'vitest';

import { createDatabase } from '../../packages/platform/src/db/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { LOAD_CHECKS } from './checks.ts';
import { loadConnection, readSeeded } from './plan.ts';

const database = createDatabase<MandateWorldTables>(loadConnection(), testLogger());
const { agents } = readSeeded();

afterAll(() => database.destroy());

describe('after the load (D2, PL-38)', () => {
  it.each(LOAD_CHECKS)('$name', async ({ run }) => {
    expect(await run(database, agents, Number(process.env.AGENTX_LOAD_CREATED))).toEqual([]);
  });
});
