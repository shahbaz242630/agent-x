// The agent's month and its reservations (0040; ADR-006 §6–§8; partner
// decision 4; Phase 2 D4): what a decision locks to serialise an agent's
// monthly check, the total it checks, and the capacity it holds.
//
// The caller (D4's decideAndReserve) has taken ADR-006's locks 2–6 first, then:
// - `lockAgentMonth`: the agent's zone (added from the mandate in force on its
//   first decision, then kept for good: D2's review), its month at `at` in that
//   zone, and that month's period row locked FOR NO KEY UPDATE (level 7);
// - `monthSpent`: the agent's month, every reservation but a released one, in
//   a statement of its own after the lock, so READ COMMITTED's fresh snapshot
//   sees every reservation the transaction it waited for committed (§7.2);
// - `reserve`: the request's reservation, HELD, while the request is still
//   VALIDATING (level 11; 0039's `held_for_its_request`), at the very instant
//   the month was worked out from.
import { sql, type Transaction } from 'kysely';

import { periodOf } from '../../../shared-kernel/index.ts';
import { RESERVATION } from '../domain/reservation.ts';
import type { LimitReservationsTables } from './tables.ts';

type ReservationsTransaction = Transaction<LimitReservationsTables>;

/** The agent's month a decision weighs: the zone it is named in, and its name. */
export interface AgentMonth {
  readonly timeZone: string;
  readonly month: string;
}

/**
 * The agent's month at `at`, its period row locked FOR NO KEY UPDATE: two
 * decisions for one agent's month run one after the other. The zone is the
 * agent's kept one; `zoneIfNew` (the mandate in force's) only for an agent
 * with none yet.
 */
export async function lockAgentMonth(
  tx: ReservationsTransaction,
  { orgId, agentId, zoneIfNew, at }: { orgId: string; agentId: string; zoneIfNew: string; at: Date },
): Promise<AgentMonth> {
  await tx
    .insertInto('limit_reservations.agent_zones')
    .values({ org_id: orgId, agent_id: agentId, time_zone: zoneIfNew, created_at: at })
    .onConflict((conflict) => conflict.doNothing())
    .execute();
  const { time_zone: timeZone } = await tx
    .selectFrom('limit_reservations.agent_zones')
    .select('time_zone')
    .where('agent_id', '=', agentId)
    .executeTakeFirstOrThrow();
  const { month } = periodOf(at, timeZone);
  await tx
    .insertInto('limit_reservations.agent_periods')
    .values({ org_id: orgId, agent_id: agentId, month, created_at: at })
    .onConflict((conflict) => conflict.doNothing())
    .execute();
  await tx
    .selectFrom('limit_reservations.agent_periods')
    .select('month')
    .where('agent_id', '=', agentId)
    .where('month', '=', month)
    .forNoKeyUpdate()
    .executeTakeFirstOrThrow();
  return { timeZone, month };
}

/** The agent's month's total in minor units: every reservation but a released one, under any of its mandates. */
export async function monthSpent(
  tx: ReservationsTransaction,
  { agentId, month }: { agentId: string; month: string },
): Promise<bigint> {
  const { spent } = await tx
    .selectFrom('limit_reservations.reservations')
    .select(sql<string>`coalesce(pg_catalog.sum(amount_minor), 0)::text`.as('spent'))
    .where('agent_id', '=', agentId)
    .where('month', '=', month)
    .where('state', '<>', 'RELEASED')
    .executeTakeFirstOrThrow();
  return BigInt(spent);
}

/** A request's reservation, as a decision holds it. */
export interface NewReservation {
  readonly orgId: string;
  readonly id: string;
  readonly requestId: string;
  readonly agentId: string;
  readonly mandateId: string;
  /** The month lockAgentMonth gave for `reservedAt`. */
  readonly month: string;
  readonly supplierId: string;
  readonly payeeKey: string | null;
  readonly amountMinor: bigint;
  readonly currency: string;
  readonly reservedAt: Date;
}

/** Holds the request's capacity: HELD, in the agent's month. */
export async function reserve(tx: ReservationsTransaction, reservation: NewReservation): Promise<void> {
  await tx
    .insertInto('limit_reservations.reservations')
    .values({
      org_id: reservation.orgId,
      id: reservation.id,
      request_id: reservation.requestId,
      agent_id: reservation.agentId,
      mandate_id: reservation.mandateId,
      month: reservation.month,
      supplier_id: reservation.supplierId,
      payee_key: reservation.payeeKey,
      amount_minor: reservation.amountMinor,
      currency: reservation.currency,
      state: RESERVATION.initial,
      reserved_at: reservation.reservedAt,
      settled_at: null,
    })
    .execute();
}
