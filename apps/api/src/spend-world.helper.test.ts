// The world the tests of ending a spend request share (Phase 2 D7, D8): the
// mandate test world, whose agent has a key and a mandate in force (approval
// above AED 1,000) and both suppliers verified; the agent's requests decided
// through decideAndReserve; and reads of where a request stands, what it
// holds and the agent's month.
import type { FixedClock, SequentialIds, TestDatabase } from '@agentx/testing';
import { withSignedStates } from '@agentx/core/modules/audit';
import { type LimitReservationsTables, monthSpent } from '@agentx/core/modules/limit-reservations';
import { requestOf, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { type Database, withTenant } from '@agentx/platform/db';

import type { MandateRegistry } from './mandate-registry.ts';
import { AED, mandateWorld, type MandateWorldTables, type World } from './mandate-world.helper.test.ts';
import {
  type AgentActing,
  DECIDE_OPERATION,
  type SpendAskedByAgent,
  type SpendRequestDecisions,
} from './spend-request-decisions.ts';

export type SpendWorldTables = MandateWorldTables & SpendRequestsTables & LimitReservationsTables;

/**
 * The request's claim or reservation released, or its reservation's amount
 * halved, by the tables' owner with their guards off: as only something past
 * the app could (G2).
 */
export async function changedPastTheApp(
  database: TestDatabase,
  org: string,
  requestId: string,
  what: 'claim released' | 'reservation released' | 'amount halved',
): Promise<void> {
  const owner = await database.connect('owner');
  try {
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [org]);
    await owner.query('begin');
    await owner.query('alter table limit_reservations.reservations disable trigger user');
    await owner.query('alter table spend_requests.order_claims disable trigger user');
    if (what === 'claim released') {
      await owner.query('update spend_requests.order_claims set released_at = now() where request_id = $1', [
        requestId,
      ]);
    } else if (what === 'reservation released') {
      await owner.query(
        "update limit_reservations.reservations set state = 'RELEASED', settled_at = now() where request_id = $1",
        [requestId],
      );
    } else {
      await owner.query(
        'update limit_reservations.reservations set amount_minor = amount_minor / 2 where request_id = $1',
        [requestId],
      );
    }
    await owner.query('alter table limit_reservations.reservations enable trigger user');
    await owner.query('alter table spend_requests.order_claims enable trigger user');
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

const CORRELATION = '0199a0f0-0000-7000-8000-0000000000d7';

export function spendWorld({
  app,
  clock,
  ids,
  name,
  registry,
  decisions,
}: {
  readonly app: () => Database<SpendWorldTables>;
  readonly clock: () => FixedClock;
  readonly ids: SequentialIds;
  readonly name: string;
  readonly registry: () => MandateRegistry;
  readonly decisions: () => SpendRequestDecisions;
}) {
  const shared = mandateWorld({ app, clock, ids, name });

  /** A world whose agent has a key and a mandate in force (approval above AED 1,000), both suppliers verified. */
  async function ready() {
    const w = await shared.world();
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry(), w, { approvalThreshold: AED(100_000n) });
    return { w, acting: await shared.agentKey(w) };
  }

  let keysUsed = 0;
  /** The agent's request, decided: AED 2,000 to the first supplier by default, so it waits for approval. */
  const ask = async (acting: AgentActing, w: World, overrides: Partial<SpendAskedByAgent> = {}) => {
    keysUsed += 1;
    const asked: SpendAskedByAgent = {
      amount: AED(200_000n),
      supplierId: w.suppliers[0] ?? '',
      fundingSourceId: w.source,
      orderReference: `INV-${String(keysUsed)}`,
      purpose: 'Printer paper',
      ...overrides,
    };
    const answer = await decisions().decideAndReserve(
      acting,
      {
        orgId: acting.orgId,
        client: { kind: 'agent', id: acting.agentId },
        operation: DECIDE_OPERATION,
        key: `${name}-${String(keysUsed)}`,
        payload: JSON.stringify({ ...asked, amount: String(asked.amount.minor) }),
      },
      asked,
      CORRELATION,
    );
    if (answer.outcome !== 'decided') throw new Error(`not decided: ${JSON.stringify(answer)}`);
    return answer.request;
  };

  /** The request's status, as its signed state says. */
  const statusOf = (w: World, id: string) =>
    withSignedStates(app(), w.org, shared.quiet(), async (tx, states) => {
      const read = await requestOf(tx, states, { orgId: w.org, id });
      return read.outcome === 'found' ? read.request.status : read.outcome;
    });

  /** What the request holds: its reservation's state and whether its claim is released. */
  const holdingsOf = (w: World, id: string) =>
    withTenant(app(), w.org, async (tx) => {
      const reservation = await tx
        .selectFrom('limit_reservations.reservations')
        .select('state')
        .where('request_id', '=', id)
        .executeTakeFirstOrThrow();
      const claim = await tx
        .selectFrom('spend_requests.order_claims')
        .select('released_at')
        .where('request_id', '=', id)
        .executeTakeFirstOrThrow();
      return { reservation: reservation.state, released: claim.released_at !== null };
    });

  /** What the agent's month holds: every reservation but a released one. */
  const spentOf = (w: World, acting: AgentActing) =>
    withTenant(app(), w.org, async (tx) => {
      const { month } = await tx
        .selectFrom('limit_reservations.reservations')
        .select('month')
        .where('agent_id', '=', acting.agentId)
        .executeTakeFirstOrThrow();
      return monthSpent(tx, { agentId: acting.agentId, month });
    });

  return { ...shared, ready, ask, statusOf, holdingsOf, spentOf };
}
