// The load test's clean-up step on the laptop (D2c, cleanup.ts), once the
// checks are done: every organisation of the run made inert, and a second
// clean-up changing nothing, as Azure's job will do it on staging. Run by
// `corepack pnpm load` (run.ts), never by the ordinary test run.
import { afterAll, expect, it } from 'vitest';

import { createDatabase, withTenant } from '../../packages/platform/src/db/index.ts';
import { loadKeys } from '../../packages/platform/src/keys/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { cleanUpFailures, cleanUpRun } from './cleanup.ts';
import { APP_KEYS_DIR, loadConnection, readSeeded } from './plan.ts';

const database = createDatabase<MandateWorldTables>(loadConnection(), testLogger());
const orgIds = readSeeded().agents.map(({ orgId }) => orgId);
const keyring = loadKeys({ directory: APP_KEYS_DIR, current: {} });

afterAll(() => database.destroy());

/** How many audit events each organisation's chain holds. */
const chainLengths = () =>
  Promise.all(
    orgIds.map((orgId) =>
      withTenant(database, orgId, (tx) =>
        tx
          .selectFrom('audit.events')
          .select((eb) => eb.fn.countAll<string>().as('n'))
          .executeTakeFirstOrThrow(),
      ),
    ),
  );

// ~6,800 requests voided, four organisations at once: under 3 minutes on the laptop; room for a slower database.
it(
  'leaves every organisation of the run frozen, holding nothing, with no live key or member',
  { timeout: 1_800_000 },
  async () => {
    await cleanUpRun(database, keyring, orgIds);
    expect(await cleanUpFailures(database, orgIds)).toEqual([]);
  },
);

it('changes nothing when run again', { timeout: 1_800_000 }, async () => {
  const before = await chainLengths();
  await cleanUpRun(database, keyring, orgIds);
  expect(await chainLengths()).toEqual(before);
});
