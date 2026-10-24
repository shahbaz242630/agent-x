// The load test's checks of what the database holds once k6 is done (D2), as
// a module: every request k6 had recorded is there once, no agent's month went
// past its limit, every request holding money holds exactly its reservation
// and order claim, one open claim an order, and no organisation on an
// integrity hold. Read as the app's own role, through each organisation's
// tenant wall. The laptop's step (verify.load.test.ts) and, on Azure, the
// run's job (D2c) both run them; each says what it found wrong in plain
// words, so the job can print it where the report reads it.
import { type Database, withTenant } from '../../packages/platform/src/db/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import type { SeededAgent } from './plan.ts';

/** The statuses that hold money before a hand-off: a reservation HELD and an order claim open. */
const HOLDING = ['APPROVED', 'APPROVAL_REQUIRED'] as const;

export interface LoadCheck {
  readonly name: string;
  /** What it found wrong, in plain words: none when the check holds. */
  readonly run: (
    database: Database<MandateWorldTables>,
    agents: readonly SeededAgent[],
    created: number,
  ) => Promise<string[]>;
}

/** Runs `read` in each agent's organisation and keeps what each says was wrong. */
async function eachOrg(
  agents: readonly SeededAgent[],
  read: (agent: SeededAgent) => Promise<string | undefined>,
): Promise<string[]> {
  const found: string[] = [];
  for (const agent of agents) {
    const wrong = await read(agent);
    if (wrong !== undefined) found.push(wrong);
  }
  return found;
}

export const LOAD_CHECKS: readonly LoadCheck[] = [
  {
    name: 'recorded each request k6 was answered 201 for, once',
    async run(database, agents, created) {
      const counts = await Promise.all(
        agents.map(({ orgId }) =>
          withTenant(database, orgId, (tx) =>
            tx
              .selectFrom('spend_requests.requests')
              .select((eb) => eb.fn.countAll<string>().as('n'))
              .executeTakeFirstOrThrow(),
          ),
        ),
      );
      const recorded = counts.reduce((sum, { n }) => sum + Number(n), 0);
      // NaN too: a runner that passed no count must fail, never compare.
      if (!Number.isFinite(created) || created <= 0)
        return ['k6 recorded no new request, so nothing could be checked.'];
      return recorded === created
        ? []
        : [`The database holds ${String(recorded)} requests, but k6 was answered 201 for ${String(created)} new ones.`];
    },
  },
  {
    name: 'kept every agent’s month within its limit, and stopped the capped one at it',
    run: (database, agents) =>
      eachOrg(agents, async (agent) => {
        const { held, denied } = await withTenant(database, agent.orgId, async (tx) => ({
          held: await tx
            .selectFrom('limit_reservations.reservations')
            .select((eb) => eb.fn.coalesce(eb.fn.sum<string>('amount_minor'), eb.lit(0)).as('minor'))
            .where('agent_id', '=', agent.agentId)
            .where('state', '!=', 'RELEASED')
            .executeTakeFirstOrThrow(),
          denied: await tx
            .selectFrom('spend_requests.requests')
            .select((eb) => eb.fn.countAll<string>().as('n'))
            .where('agent_id', '=', agent.agentId)
            .where('status', '=', 'DENIED')
            .executeTakeFirstOrThrow(),
        }));
        const limit = BigInt(agent.monthlyLimitMinor);
        if (BigInt(held.minor) > limit) {
          return `Agent ${agent.agentId} holds ${held.minor} fils this month, over its limit of ${agent.monthlyLimitMinor}.`;
        }
        // The spike asks for twice its month at once: the load reached the limit, so the line above meant something.
        if (agent.kind === 'capped' && (BigInt(held.minor) !== limit || Number(denied.n) === 0)) {
          return `The capped agent holds ${held.minor} fils with ${denied.n} denied: the spike should have filled its month exactly and been refused past it.`;
        }
        return undefined;
      }),
  },
  {
    name: 'handed nothing off: the hand-off is paused, as staging’s is, so the check below holds',
    run: (database, agents) =>
      eachOrg(agents, async ({ orgId }) => {
        const moved = await withTenant(database, orgId, (tx) =>
          tx
            .selectFrom('spend_requests.requests')
            .select('id')
            .where('status', 'in', ['INSTRUCTION_READY', 'HANDED_OFF'])
            .execute(),
        );
        return moved.length === 0
          ? undefined
          : `Organisation ${orgId} handed off ${String(moved.length)} request(s): the hand-off should be paused.`;
      }),
  },
  {
    name: 'holds exactly one reservation and one open claim for each request holding money, and none for the rest',
    run: (database, agents) =>
      eachOrg(agents, async ({ orgId }) => {
        const found = await withTenant(database, orgId, async (tx) => {
          const holding = await tx
            .selectFrom('spend_requests.requests')
            .select('id')
            .where('status', 'in', HOLDING)
            .execute();
          const reservations = await tx
            .selectFrom('limit_reservations.reservations')
            .select('request_id')
            .where('state', '=', 'HELD')
            .execute();
          const claims = await tx
            .selectFrom('spend_requests.order_claims')
            .select('request_id')
            .where('released_at', 'is', null)
            .execute();
          return {
            holding: holding.map(({ id }) => id).sort(),
            reservations: reservations.map(({ request_id }) => request_id).sort(),
            claims: claims.map(({ request_id }) => request_id).sort(),
          };
        });
        const same = (ids: readonly (string | null)[]) => ids.join(',') === found.holding.join(',');
        if (found.holding.length === 0) return `Organisation ${orgId} has no request holding money to compare.`;
        return same(found.reservations) && same(found.claims)
          ? undefined
          : `Organisation ${orgId}: ${String(found.holding.length)} requests hold money, but ${String(found.reservations.length)} reservations are held and ${String(found.claims.length)} claims open, or they name other requests.`;
      }),
  },
  {
    name: 'left one open claim an order',
    run: (database, agents) =>
      eachOrg(agents, async ({ orgId }) => {
        const twice = await withTenant(database, orgId, (tx) =>
          tx
            .selectFrom('spend_requests.order_claims')
            .select(['supplier_id', 'order_reference'])
            .where('released_at', 'is', null)
            .groupBy(['supplier_id', 'order_reference'])
            .having((eb) => eb.fn.countAll(), '>', 1)
            .execute(),
        );
        return twice.length === 0
          ? undefined
          : `Organisation ${orgId} has ${String(twice.length)} order(s) with more than one open claim.`;
      }),
  },
  {
    name: 'put no organisation on an integrity hold',
    run: (database, agents) =>
      eachOrg(agents, async ({ orgId }) => {
        const holds = await withTenant(database, orgId, (tx) =>
          tx.selectFrom('audit.events').select('seq').where('action', '=', 'integrity_hold.set').execute(),
        );
        return holds.length === 0 ? undefined : `Organisation ${orgId} was put on an integrity hold.`;
      }),
  },
];
