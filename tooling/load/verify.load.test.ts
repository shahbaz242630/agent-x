// The load test's checks of what the database holds once k6 is done (D2):
// every request k6 had recorded is there once, no agent's month went past its
// limit, every request holding money holds exactly its reservation and order
// claim, one open claim an order, and no organisation on an integrity hold.
// Read as the app's own role, through each organisation's tenant wall. Run by
// `corepack pnpm load` (run.ts), which gives it k6's count of new requests.
import { afterAll, describe, expect, it } from 'vitest';

import { createDatabase, withTenant } from '../../packages/platform/src/db/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { loadConnection, readSeeded } from './plan.ts';

const database = createDatabase<MandateWorldTables>(loadConnection(), testLogger());
const { agents } = readSeeded();

afterAll(() => database.destroy());

/** The statuses that hold money before a hand-off: a reservation HELD and an order claim open. */
const HOLDING = ['APPROVED', 'APPROVAL_REQUIRED'] as const;

describe('after the load (D2, PL-38)', () => {
  it('recorded each request k6 was answered 201 for, once', async () => {
    const created = Number(process.env.AGENTX_LOAD_CREATED);
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
    expect(created).toBeGreaterThan(0);
    expect(counts.reduce((sum, { n }) => sum + Number(n), 0)).toBe(created);
  });

  it('kept every agent’s month within its limit, and stopped the capped one at it', async () => {
    for (const agent of agents) {
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
      expect(BigInt(held.minor)).toBeLessThanOrEqual(BigInt(agent.monthlyLimitMinor));
      // The spike asks for twice its month at once: the load reached the limit, so the line above meant something.
      if (agent.kind === 'capped') {
        expect(BigInt(held.minor)).toBe(BigInt(agent.monthlyLimitMinor));
        expect(Number(denied.n)).toBeGreaterThan(0);
      }
    }
  });

  it('handed nothing off: the stack’s hand-off is paused from birth, as staging’s is, so the check below holds', async () => {
    for (const { orgId } of agents) {
      const moved = await withTenant(database, orgId, (tx) =>
        tx
          .selectFrom('spend_requests.requests')
          .select('id')
          .where('status', 'in', ['INSTRUCTION_READY', 'HANDED_OFF'])
          .execute(),
      );
      expect(moved).toEqual([]);
    }
  });

  it('holds exactly one reservation and one open claim for each request holding money, and none for the rest', async () => {
    for (const { orgId } of agents) {
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
      expect(found.holding.length).toBeGreaterThan(0);
      expect(found.reservations).toEqual(found.holding);
      expect(found.claims).toEqual(found.holding);
    }
  });

  it('left one open claim an order', async () => {
    for (const { orgId } of agents) {
      const twice = await withTenant(database, orgId, (tx) =>
        tx
          .selectFrom('spend_requests.order_claims')
          .select(['supplier_id', 'order_reference'])
          .where('released_at', 'is', null)
          .groupBy(['supplier_id', 'order_reference'])
          .having((eb) => eb.fn.countAll(), '>', 1)
          .execute(),
      );
      expect(twice).toEqual([]);
    }
  });

  it('put no organisation on an integrity hold', async () => {
    for (const { orgId } of agents) {
      const holds = await withTenant(database, orgId, (tx) =>
        tx.selectFrom('audit.events').select('seq').where('action', '=', 'integrity_hold.set').execute(),
      );
      expect(holds).toEqual([]);
    }
  });
});
