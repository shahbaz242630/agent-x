// Stage G's seed (4D2e, PL-62, PL-63): thousands of organisations made through
// the app's own path, as seed.ts makes PL-38's, never rows written past it
// (design item 4): each organisation's records come from the same functions the
// use cases call, signed by withSignedStates with the keys the API reads. N
// workers side by side, each one connection, so a run fits a job's time.
//
// Resumable: an organisation's ID comes from the run and its index alone, so a
// re-run, or the next job execution after one stopped, finds what is made and
// makes only what is missing; growing a seeded set (100, then 1,000, 3,000...)
// is the same call with a larger count. An idle organisation is made in one
// transaction, so it is there whole or not at all; an active one takes several,
// and one found half-made is reported (`incomplete`), never made twice.
//
// The active cohort (stageGCohort) is read back from the database by the same
// IDs, never sent in a request: only its agents get keys (seed.ts's rekeyed).
import { createHash } from 'node:crypto';

import { withSignedStates } from '../../packages/core/src/modules/audit/index.ts';
import { addMembership, userForSubject } from '../../packages/core/src/modules/identity/index.ts';
import { setPolicy } from '../../packages/core/src/modules/mandates/index.ts';
import { createOrganization } from '../../packages/core/src/modules/organizations/index.ts';
import { addSupplier, supplierOf, verifySupplier } from '../../packages/core/src/modules/suppliers/index.ts';
import { type IdGenerator, uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import { type Database, withTenant } from '../../packages/platform/src/db/index.ts';
import type { KeyProvider } from '../../packages/platform/src/keys/index.ts';
import { FixedClock, testLogger } from '../../packages/testing/src/index.ts';

import { createMandateRegistry } from '../../apps/api/src/mandate-registry.ts';
import { AED, mandateWorld, type MandateWorldTables, OPERATOR } from '../../apps/api/src/mandate-world.helper.test.ts';
import { capChoiceDetails, SUGGESTED_MONTHLY_CAP_MINOR } from '../../apps/api/src/monthly-cap-choice.ts';
import {
  CROWD_AGENTS,
  loadOrgName,
  type SeededAgent,
  STAGE_G_HEAVY_EVERY,
  STAGE_G_HUGE_CHAIN_EVENTS,
  STAGE_G_LIGHT_EVERY,
} from './plan.ts';
import { AMPLE_TERMS } from './seed.ts';

/** What an organisation of the seed is: most idle; a few light-active, fewer heavy; the first has the long chain. */
export type StageGOrgKind = 'idle' | 'light' | 'heavy' | 'huge-chain';

const ACTIVE_KINDS: ReadonlySet<StageGOrgKind> = new Set(['light', 'heavy', 'huge-chain']);

/** The kind of the organisation at `index`, from the index alone, so a grown set keeps every earlier one's. */
export function stageGKindAt(index: number): StageGOrgKind {
  if (index === 0) return 'huge-chain';
  if (index % STAGE_G_HEAVY_EVERY === 1) return 'heavy';
  if (index % STAGE_G_LIGHT_EVERY === 2) return 'light';
  return 'idle';
}

/** Each active organisation's agents with a mandate in force: a heavy one's are PL-38's crowd, sharing three suppliers. */
const agentsOfKind = (kind: StageGOrgKind): number => (kind === 'heavy' ? CROWD_AGENTS : 1);

/**
 * The organisation's ID for a run and index: a version 8 UUID (RFC 9562) of a
 * SHA-256, the same on every execution, so what one made the next finds.
 */
export function stageGOrgId(runId: string, index: number): string {
  const hex = createHash('sha256')
    .update(`agentx-stage-g\0${runId}\0${String(index)}`)
    .digest('hex');
  const variant = ((Number.parseInt(hex.charAt(16), 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-8${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/** IDs whose first is `first`: mandateWorld's world() names its organisation with its first ID. */
const firstThen = (first: string): IdGenerator => {
  let given = false;
  return {
    next: () => {
      if (given) return uuidV7Ids.next();
      given = true;
      return first;
    },
  };
};

export interface StageGSeedOptions {
  readonly database: Database<MandateWorldTables>;
  readonly keyring: KeyProvider;
  readonly runId: string;
  /** How many organisations the run's set should hold when done: indexes 0 to orgs - 1. */
  readonly orgs: number;
  /** Organisations made at once, each worker one connection at a time. */
  readonly workers: number;
  /** The long chain's partner refreshes: STAGE_G_HUGE_CHAIN_EVENTS unless a test asks for fewer. */
  readonly hugeChainEvents?: number;
}

export interface StageGSeeded {
  readonly orgs: number;
  /** Organisations already there, whole, from an earlier execution. */
  readonly found: number;
  /** Made now, by kind. */
  readonly made: Readonly<Record<StageGOrgKind, number>>;
  /** Seconds spent making each kind, summed over its organisations (divide by `made` for one's). */
  readonly seconds: Readonly<Record<StageGOrgKind, number>>;
  /** Active organisations found half-made (an execution stopped inside one): left out of the cohort. */
  readonly incomplete: readonly number[];
  readonly elapsedSeconds: number;
}

const byKind = (): Record<StageGOrgKind, number> => ({ idle: 0, light: 0, heavy: 0, 'huge-chain': 0 });

/** Postgres's unique violation: another execution made the same organisation at the same moment. */
const isUniqueViolation = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && (error as { code?: unknown }).code === '23505';

/**
 * Runs `work` for every item, `workers` at a time. The first failure stops
 * new items being taken; the rest finish what they began, then it is thrown.
 */
export async function pooled<T>(items: readonly T[], workers: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  let failure: { readonly error: unknown } | undefined;
  const worker = async (): Promise<void> => {
    while (failure === undefined && next < items.length) {
      const item = items[next] as T;
      next += 1;
      try {
        await work(item);
      } catch (error) {
        failure ??= { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(workers, items.length)) }, worker));
  if (failure !== undefined) throw failure.error;
}

/** The seed's makers for one run: one registry and clock, each organisation its own world (its people's names its own). */
function makers(options: StageGSeedOptions) {
  const { database, keyring, runId } = options;
  const clock = new FixedClock(new Date());
  const registry = createMandateRegistry({ database, keys: keyring, ids: uuidV7Ids, clock, logger: testLogger() });
  const services = { keys: keyring, ids: uuidV7Ids, logger: testLogger() };
  const orgName = loadOrgName(runId);
  const hugeChainEvents = options.hugeChainEvents ?? STAGE_G_HUGE_CHAIN_EVENTS;

  /**
   * An idle organisation as the operator founds one: made, its admin joined, its
   * monthly cap chosen (E2), and the history the measured time allowed (S175: an
   * idle one took 0.05 s serial): one supplier entered and verified by its admin.
   * All in one transaction, so it is whole or absent.
   */
  async function idle(orgId: string): Promise<void> {
    const now = clock.now();
    const userId = await userForSubject(
      database,
      { issuer: 'https://auth.example.test', subject: `stage-g-${orgId}` },
      { ids: uuidV7Ids, clock },
    );
    const membershipId = uuidV7Ids.next();
    await withSignedStates(database, orgId, services, async (tx, states) => {
      await createOrganization(tx, states, { id: orgId, name: orgName, actor: OPERATOR });
      await addMembership(tx, states, {
        orgId,
        id: membershipId,
        userId,
        role: 'admin',
        joinedAt: now,
        actor: OPERATOR,
      });
      await setPolicy(tx, states, {
        orgId,
        existing: null,
        scope: 'organization',
        mandateId: null,
        versionId: uuidV7Ids.next(),
        rules: {
          currency: 'AED',
          perOrderCap: null,
          monthlyCap: AED(BigInt(SUGGESTED_MONTHLY_CAP_MINOR)),
          approvalThreshold: null,
          supplierIds: null,
        },
        madeBy: membershipId,
        madeAt: now,
        actor: { type: 'user', id: userId },
        details: capChoiceDetails('amount'),
      });
      const supplier = { orgId, id: uuidV7Ids.next() };
      await addSupplier(tx, states, keyring, {
        ...supplier,
        versionId: uuidV7Ids.next(),
        supplier: {
          displayName: 'Gulf Office Supplies LLC',
          contacts: { phone: '+971501234567', email: null, tradeLicence: null },
          source: { kind: 'registry', ref: 'DED-123456' },
        },
        enteredBy: membershipId,
        remittanceEmail: 'on',
        createdAt: now,
        actor: { type: 'user', id: userId },
      });
      const entered = await supplierOf(tx, states, supplier, 'change');
      if (entered.outcome !== 'found') throw new Error(`The supplier just entered was ${entered.outcome}.`);
      await verifySupplier(tx, states, supplier, entered, {
        verifiedBy: membershipId,
        actor: { type: 'user', id: userId },
      });
    });
  }

  /**
   * An active organisation as seed.ts makes PL-38's: three verified suppliers and
   * an agent with a mandate in force, on the steady traffic's terms; a heavy one's
   * nine more agents share them; the long chain's source then refreshed from the
   * partner `hugeChainEvents` times, as its daily refresh would over years, each a
   * signed change of its own.
   */
  async function active(orgId: string, kind: StageGOrgKind): Promise<void> {
    const shared = mandateWorld({
      app: () => database,
      clock: () => clock,
      ids: firstThen(orgId),
      name: `stage-g-${orgId}`,
      keyring,
    });
    const w = await shared.world({ suppliers: 3, orgName });
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry, w, AMPLE_TERMS);
    for (let at = 1; at < agentsOfKind(kind); at += 1) {
      await shared.inForce(registry, await shared.anotherAgent(w), AMPLE_TERMS);
    }
    if (kind !== 'huge-chain') return;
    // After the link's own time, a millisecond apart: each answer newer than the last, so each is kept.
    const linked = w.state.statusChangedAt.getTime();
    for (let at = 1; at <= hugeChainEvents; at += 1) {
      await shared.partnerSays(w, { statusChangedAt: new Date(linked + at) });
    }
  }

  return { idle, active };
}

/** Whether the organisation is there: read through its own tenant wall, as only it can be. */
const exists = (database: Database<MandateWorldTables>, orgId: string): Promise<boolean> =>
  withTenant(
    database,
    orgId,
    async (tx) => (await tx.selectFrom('organizations.organizations').select('id').executeTakeFirst()) !== undefined,
  );

/** The organisation's agents with a mandate in force, and each one's source, suppliers and month, oldest first. */
const agentsInForce = (database: Database<MandateWorldTables>, orgId: string) =>
  withTenant(database, orgId, (tx) =>
    tx
      .selectFrom('mandates.mandates as m')
      .innerJoin('mandates.versions as v', (join) =>
        join.onRef('v.org_id', '=', 'm.org_id').onRef('v.id', '=', 'm.current_version_id'),
      )
      .select(['m.agent_id', 'v.funding_source_id', 'v.supplier_ids', 'v.monthly_limit_minor'])
      .where('m.status', '=', 'ACTIVE')
      .orderBy('m.created_at')
      .orderBy('m.agent_id')
      .execute(),
  );

/**
 * Seeds the run's set up to `orgs` organisations, `workers` at a time: those
 * already there are found, not made again; each kind's making timed.
 */
export async function stageGSeed(options: StageGSeedOptions): Promise<StageGSeeded> {
  const started = performance.now();
  const { database, runId } = options;
  const make = makers(options);
  const made = byKind();
  const seconds = byKind();
  const incomplete: number[] = [];
  let found = 0;
  const indexes = Array.from({ length: options.orgs }, (_, index) => index);
  await pooled(indexes, options.workers, async (index) => {
    const orgId = stageGOrgId(runId, index);
    const kind = stageGKindAt(index);
    if (await exists(database, orgId)) {
      const whole = !ACTIVE_KINDS.has(kind) || (await agentsInForce(database, orgId)).length === agentsOfKind(kind);
      if (whole) found += 1;
      else incomplete.push(index);
      return;
    }
    const at = performance.now();
    try {
      await (kind === 'idle' ? make.idle(orgId) : make.active(orgId, kind));
    } catch (error) {
      // Made by another execution at the same moment: its, not a failure. Anything else is.
      if (!isUniqueViolation(error) || !(await exists(database, orgId))) throw error;
      found += 1;
      return;
    }
    made[kind] += 1;
    seconds[kind] += (performance.now() - at) / 1000;
  });
  return {
    orgs: options.orgs,
    found,
    made,
    seconds,
    incomplete: incomplete.toSorted((a, b) => a - b),
    elapsedSeconds: (performance.now() - started) / 1000,
  };
}

/** Which traffic a Stage G step sends (stageg.ts's Profile mix): what the cohort's agents are named for in the seed file. */
export type StageGMix = 'steady' | 'neighbours';

/**
 * The kind stage-g.k6.js knows an active organisation's agents by, for the mix,
 * or undefined for one k6 doesn't send as: the steady traffic is one agent an
 * organisation, the light ones; beside the calm ones the first heavy
 * organisation is the busy one and the second the stuck one. The other heavy
 * organisations and the long chain are there as data: k6 has no traffic for them.
 */
export function cohortKindOf(kind: StageGOrgKind, mix: StageGMix, heavyAt: number): SeededAgent['kind'] | undefined {
  if (kind === 'light') return mix === 'steady' ? 'ample' : 'neighbour-calm';
  if (kind !== 'heavy' || mix === 'steady') return undefined;
  return heavyAt === 0 ? 'neighbour-busy' : heavyAt === 1 ? 'neighbour-stuck' : undefined;
}

/** One cohort agent as a job may print it: everything but its key. */
export type CohortAgent = Omit<SeededAgent, 'key'>;

/**
 * The agents k6 sends as for a step over the run's first `orgs` organisations,
 * read from the database by their IDs (never from a request); a half-made
 * organisation's are left out. Thrown when the mix has no agent to send as.
 */
export async function stageGCohort({
  database,
  runId,
  orgs,
  mix,
}: {
  readonly database: Database<MandateWorldTables>;
  readonly runId: string;
  readonly orgs: number;
  readonly mix: StageGMix;
}): Promise<CohortAgent[]> {
  const agents: CohortAgent[] = [];
  let heavyAt = 0;
  for (let index = 0; index < orgs; index += 1) {
    const kind = stageGKindAt(index);
    const cohortKind = cohortKindOf(kind, mix, heavyAt);
    if (kind === 'heavy') heavyAt += 1;
    if (cohortKind === undefined) continue;
    const orgId = stageGOrgId(runId, index);
    const rows = await agentsInForce(database, orgId);
    if (rows.length !== agentsOfKind(kind)) continue;
    for (const row of rows) {
      agents.push({
        kind: cohortKind,
        orgId,
        agentId: row.agent_id,
        sourceId: row.funding_source_id,
        supplierIds: row.supplier_ids.split(' '),
        monthlyLimitMinor: String(row.monthly_limit_minor),
      });
    }
  }
  const sends = (kind: SeededAgent['kind']) => agents.some((agent) => agent.kind === kind);
  const needed = mix === 'steady' ? ['ample'] : ['neighbour-calm', 'neighbour-busy', 'neighbour-stuck'];
  const missing = needed.filter((kind) => !sends(kind as SeededAgent['kind']));
  if (missing.length > 0) {
    throw new Error(
      `The ${mix} cohort of run ${runId}'s first ${String(orgs)} organisations has no ${missing.join(', ')} agent: seed more organisations first.`,
    );
  }
  return agents;
}
