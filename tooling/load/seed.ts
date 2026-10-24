// The load test's seed (D2), as a module: the organisations and agents the k6
// script asks as, built by the database tests' own world and signed with the
// keys the API reads, so the API believes them. The laptop's step
// (seed.load.test.ts) and, on Azure, the run's job (D2c) both call it; neither
// copy of the code can drift from the other.
import { uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import type { Database } from '../../packages/platform/src/db/index.ts';
import type { KeyProvider } from '../../packages/platform/src/keys/index.ts';
import { FixedClock, testLogger } from '../../packages/testing/src/index.ts';

import { createMandateRegistry } from '../../apps/api/src/mandate-registry.ts';
import { AED, mandateWorld, type MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import {
  AMPLE_AGENTS,
  APPROVAL_THRESHOLD_MINOR,
  CAPPED_MONTHLY_MINOR,
  loadOrgName,
  type Seeded,
  type SeededAgent,
} from './plan.ts';

/** The seeded world's helpers for one run's seed or keys: the API's clock is the real one, and sealed times are Postgres's. */
function worldOf(database: Database<MandateWorldTables>, keyring: KeyProvider) {
  const clock = new FixedClock(new Date());
  return {
    clock,
    shared: mandateWorld({ app: () => database, clock: () => clock, ids: uuidV7Ids, name: 'load', keyring }),
  };
}

/**
 * Seeds one run: the ample agents and the capped one, each in an organisation
 * of its own named for the run, with three verified suppliers, a mandate in
 * force and a key.
 */
export async function seedRun({
  database,
  keyring,
  runId,
}: {
  readonly database: Database<MandateWorldTables>;
  readonly keyring: KeyProvider;
  readonly runId: string;
}): Promise<Seeded> {
  const { clock, shared } = worldOf(database, keyring);
  const registry = createMandateRegistry({ database, keys: keyring, ids: uuidV7Ids, clock, logger: testLogger() });

  async function seeded(kind: SeededAgent['kind']): Promise<SeededAgent> {
    const w = await shared.world({ suppliers: 3, orgName: loadOrgName(runId) });
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

  const agents: SeededAgent[] = [];
  for (let n = 0; n < AMPLE_AGENTS; n += 1) agents.push(await seeded('ample'));
  agents.push(await seeded('capped'));
  return { agents };
}

/**
 * A new key for each of the run's agents, in place of the seed's: on Azure
 * the second phase runs in a job of its own, and keys never leave the job
 * that made them, so it is given the run's IDs alone and makes its own. The
 * laptop's run does the same between its phases, so Azure runs nothing the
 * laptop hasn't. The old keys stay live until the clean-up revokes them all.
 */
export async function rekeyed(
  database: Database<MandateWorldTables>,
  keyring: KeyProvider,
  seeded: Seeded,
): Promise<Seeded> {
  const { shared } = worldOf(database, keyring);
  const agents: SeededAgent[] = [];
  for (const agent of seeded.agents) {
    const { text } = await shared.agentKey({ org: agent.orgId, agent: agent.agentId });
    agents.push({ ...agent, key: text });
  }
  return { agents };
}
