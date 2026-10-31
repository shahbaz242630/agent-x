// What makes phase 5's stuck organisation stuck (4D2d, PL-63): two of its three
// suppliers' rows held locked for the phase, in one open transaction through
// its own tenant wall, as an unfinished piece of its own work would hold them.
// Its requests to them wait on the lock, each up to its limit; to the third
// they go on, so it still holds money for the database checks to compare. The
// laptop's run (run.ts) and, on Azure, the second job (job.ts) both call this.
import { type Database, withTenant } from '../../packages/platform/src/db/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import type { SeededAgent } from './plan.ts';

/** Of the stuck organisation's three suppliers, the two held. */
const SUPPLIERS_HELD = 2;

/** Runs `phase` with the stuck organisation's suppliers held locked, and lets them go after it, whatever it does. */
export function whileStuck<T>(
  database: Database<MandateWorldTables>,
  agents: readonly Pick<SeededAgent, 'kind' | 'orgId' | 'supplierIds'>[],
  phase: () => T | Promise<T>,
): Promise<T> {
  const stuck = agents.find(({ kind }) => kind === 'neighbour-stuck');
  if (stuck === undefined) throw new Error('The neighbours phase needs the run’s stuck organisation.');
  return withTenant(database, stuck.orgId, async (tx) => {
    await tx
      .selectFrom('suppliers.suppliers')
      .select('id')
      .where('id', 'in', [...stuck.supplierIds.slice(0, SUPPLIERS_HELD)])
      .forUpdate()
      .execute();
    return phase();
  });
}
