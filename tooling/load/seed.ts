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
  CROWD_AGENTS,
  type CrowdKind,
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
 * force and a key; then the two crowds, ten agents an organisation. `onSeeded`
 * hears of each agent as it is made, so a seed that stops half-way still leaves
 * every organisation it made findable.
 */
export async function seedRun({
  database,
  keyring,
  runId,
  onSeeded = () => undefined,
}: {
  readonly database: Database<MandateWorldTables>;
  readonly keyring: KeyProvider;
  readonly runId: string;
  readonly onSeeded?: (agent: SeededAgent) => void;
}): Promise<Seeded> {
  const { clock, shared } = worldOf(database, keyring);
  const registry = createMandateRegistry({ database, keys: keyring, ids: uuidV7Ids, clock, logger: testLogger() });
  // The split check off: on, it adds up an agent's AED 1 to 9 to one supplier and past AED 5 sends nearly every
  // request to a person (S164: 24 of 6,777 allowed). Off, about half are allowed and half wait, as the traffic means.
  const ampleTerms = { approvalThreshold: AED(APPROVAL_THRESHOLD_MINOR), splitCheck: false };

  async function seeded(kind: SeededAgent['kind']): Promise<SeededAgent> {
    const w = await shared.world({ suppliers: 3, orgName: loadOrgName(runId) });
    for (const id of w.suppliers) await shared.verified(w, id);
    const capped = kind === 'capped' ? AED(CAPPED_MONTHLY_MINOR) : undefined;
    const terms =
      capped === undefined
        ? ampleTerms
        : { approvalThreshold: AED(APPROVAL_THRESHOLD_MINOR), perOrderLimit: capped, monthlyLimit: capped };
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

  /** One organisation's ten agents, on the same terms as the ample ones: suppliers three each, or the same three. */
  async function crowded(kind: CrowdKind): Promise<SeededAgent[]> {
    const own = kind === 'crowd-own';
    const w = await shared.world({ suppliers: own ? 3 * CROWD_AGENTS : 3, orgName: loadOrgName(runId) });
    for (const id of w.suppliers) await shared.verified(w, id);
    const made: SeededAgent[] = [];
    for (let at = 0; at < CROWD_AGENTS; at += 1) {
      const theirs = at === 0 ? w : await shared.anotherAgent(w);
      await shared.inForce(registry, theirs, ampleTerms);
      const acting = await shared.agentKey(theirs);
      const agent: SeededAgent = {
        kind,
        orgId: w.org,
        agentId: theirs.agent,
        key: acting.text,
        sourceId: w.source,
        supplierIds: own ? w.suppliers.slice(at * 3, at * 3 + 3) : w.suppliers,
        monthlyLimitMinor: String(shared.termsOf(w, ampleTerms).monthlyLimit.minor),
      };
      onSeeded(agent);
      made.push(agent);
    }
    return made;
  }

  const agents: SeededAgent[] = [];
  for (const kind of [...Array<'ample'>(AMPLE_AGENTS).fill('ample'), 'capped' as const]) {
    const agent = await seeded(kind);
    onSeeded(agent);
    agents.push(agent);
  }
  agents.push(...(await crowded('crowd-own')), ...(await crowded('crowd-shared')));
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
  seeded: { readonly agents: readonly Omit<SeededAgent, 'key'>[] },
): Promise<Seeded> {
  const { shared } = worldOf(database, keyring);
  const agents: SeededAgent[] = [];
  for (const agent of seeded.agents) {
    const { text } = await shared.agentKey({ org: agent.orgId, agent: agent.agentId });
    agents.push({ ...agent, key: text });
  }
  return { agents };
}
