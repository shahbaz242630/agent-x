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
// - `splitHeld`: with the mandate's split check on, the payee's reservations
//   in its rolling window, across agents, as a statement of its own too (D5);
// - `reserve`: the request's reservation, HELD, while the request is still
//   VALIDATING (level 11; 0039's `held_for_its_request`), at the very instant
//   the month was worked out from.
//
// A request that ends before hand-off (expired or cancelled: D7, D8) gives
// its capacity back: `lockReservationsOf` takes its reservation FOR NO KEY
// UPDATE at level 11, after the request (8) and before the audit head (12),
// and `releaseReservationsOf` releases it once the request has ended (0040's
// `held_for_its_request` refuses it before).
import { sql, type Transaction } from 'kysely';

import { periodOf } from '../../../shared-kernel/index.ts';
import { RESERVATION } from '../domain/reservation.ts';
import type { LimitReservationsTables } from './tables.ts';

type ReservationsTransaction = Transaction<LimitReservationsTables>;

/**
 * The agent's month at `at` (`YYYY-MM`), its period row locked FOR NO KEY
 * UPDATE: two decisions for one agent's month run one after the other. Named
 * in the agent's kept zone; `zoneIfNew` (the mandate in force's) only for an
 * agent with none yet.
 */
export async function lockAgentMonth(
  tx: ReservationsTransaction,
  { orgId, agentId, zoneIfNew, at }: { orgId: string; agentId: string; zoneIfNew: string; at: Date },
): Promise<string> {
  await tx
    .insertInto('limit_reservations.agent_zones')
    .values({ org_id: orgId, agent_id: agentId, time_zone: zoneIfNew, created_at: at })
    .onConflict((conflict) => conflict.doNothing())
    .execute();
  const month = await agentMonth(tx, { agentId, zoneIfNew, at });
  await tx
    .insertInto('limit_reservations.agent_periods')
    .values({ org_id: orgId, agent_id: agentId, month, created_at: at })
    .onConflict((conflict) => conflict.doNothing())
    .execute();
  return lockAgentPeriod(tx, { agentId, month });
}

/**
 * The agent's `month`, a period it already has, locked FOR NO KEY UPDATE
 * (level 7): an approval's, weighed in the month its request's capacity is
 * held in (Phase 3 B4b), whatever month it is now. Throws for a month the
 * agent has no period in (a reservation is only ever made in one).
 */
export async function lockAgentPeriod(
  tx: ReservationsTransaction,
  { agentId, month }: { agentId: string; month: string },
): Promise<string> {
  await tx
    .selectFrom('limit_reservations.agent_periods')
    .select('month')
    .where('agent_id', '=', agentId)
    .where('month', '=', month)
    .forNoKeyUpdate()
    .executeTakeFirstOrThrow();
  return month;
}

/**
 * The agent's month at `at` (`YYYY-MM`), writing and locking nothing: named
 * in its kept zone, or `zoneIfNew` for an agent with none yet, as its first
 * decision would keep it. The simulator's (C4); a decision locks it instead.
 */
export async function agentMonth(
  tx: ReservationsTransaction,
  { agentId, zoneIfNew, at }: { agentId: string; zoneIfNew: string; at: Date },
): Promise<string> {
  const kept = await tx
    .selectFrom('limit_reservations.agent_zones')
    .select('time_zone')
    .where('agent_id', '=', agentId)
    .executeTakeFirst();
  return periodOf(at, kept?.time_zone ?? zoneIfNew).month;
}

/**
 * The agent's month's total in minor units of `currency`: every reservation
 * but a released one, under any of its mandates. One currency's alone, as a
 * cap is in one (G4: another's minor units would be counted as its own).
 * `except` leaves one request's out: an approval weighs its request against
 * the others, as its own amount is added by the engine (Phase 3 B4b).
 */
export async function monthSpent(
  tx: ReservationsTransaction,
  {
    agentId,
    month,
    currency,
    except,
  }: { agentId: string; month: string; currency: string; except?: string | undefined },
): Promise<bigint> {
  const { spent } = await tx
    .selectFrom('limit_reservations.reservations')
    .select(sql<string>`coalesce(pg_catalog.sum(amount_minor), 0)::text`.as('spent'))
    .where('agent_id', '=', agentId)
    .where('month', '=', month)
    .where('currency', '=', currency)
    .where('state', '<>', 'RELEASED')
    .where((where) => (except === undefined ? where.lit(true) : where('request_id', '<>', except)))
    .executeTakeFirstOrThrow();
  return BigInt(spent);
}

/**
 * The split total in minor units (ADR-006 §9, ADR-014 §3 and §5; D5): what the
 * payee's reservations still hold (every state but RELEASED) that were
 * reserved since `since`, under any agent of the organisation. The payee is
 * its supplier, and its payee key where it has one: both are read, so a
 * reservation made under another supplier record with the same payee key
 * counts, and so does one the supplier made before it had a key (0041's
 * indexes). A statement of its own after the supplier's lock, which
 * serialises the payee's decisions (§7.2). In `currency` alone, as the
 * threshold is (G4).
 */
export async function splitHeld(
  tx: ReservationsTransaction,
  {
    supplierId,
    payeeKey,
    since,
    currency,
  }: { supplierId: string; payeeKey: string | null; since: Date; currency: string },
): Promise<bigint> {
  const { held } = await tx
    .selectFrom('limit_reservations.reservations')
    .select(sql<string>`coalesce(pg_catalog.sum(amount_minor), 0)::text`.as('held'))
    .where('state', '<>', 'RELEASED')
    .where('reserved_at', '>=', since)
    .where('currency', '=', currency)
    .where((where) =>
      payeeKey === null
        ? where('supplier_id', '=', supplierId)
        : where.or([where('supplier_id', '=', supplierId), where('payee_key', '=', payeeKey)]),
    )
    .executeTakeFirstOrThrow();
  return BigInt(held);
}

/** A reservation as the holdings check (E1) compares it with its request. */
export interface ReservationSeen {
  readonly requestId: string;
  readonly agentId: string;
  readonly mandateId: string;
  readonly supplierId: string;
  readonly amountMinor: bigint;
  readonly currency: string;
  readonly state: string;
  readonly month: string;
  readonly reservedAt: Date;
  readonly payeeKey: string | null;
}

/** The reservations of the requests named, in one statement: none, one, or (past the app) more for each. */
export async function reservationsFor(
  tx: ReservationsTransaction,
  requestIds: readonly string[],
): Promise<ReservationSeen[]> {
  if (requestIds.length === 0) return [];
  const rows = await tx
    .selectFrom('limit_reservations.reservations')
    .select([
      'request_id',
      'agent_id',
      'mandate_id',
      'supplier_id',
      'amount_minor',
      'currency',
      'state',
      'month',
      'reserved_at',
      'payee_key',
    ])
    .where('request_id', 'in', requestIds)
    .execute();
  return rows.map((row) => ({
    requestId: row.request_id,
    agentId: row.agent_id,
    mandateId: row.mandate_id,
    supplierId: row.supplier_id,
    amountMinor: BigInt(row.amount_minor),
    currency: row.currency,
    state: row.state,
    month: row.month,
    reservedAt: row.reserved_at,
    payeeKey: row.payee_key,
  }));
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

/**
 * Locks the requests' reservations FOR NO KEY UPDATE (level 11), in one
 * statement in order of ID (at least one asked), before their moves take the audit head.
 */
export async function lockReservationsOf(tx: ReservationsTransaction, requestIds: readonly string[]): Promise<void> {
  await tx
    .selectFrom('limit_reservations.reservations')
    .select('id')
    .where('request_id', 'in', requestIds)
    .orderBy('id')
    .forNoKeyUpdate()
    .execute();
}

/**
 * Releases the request's HELD reservations, once the request has ended
 * before hand-off: how many were released. (BLOCKED_UNKNOWN comes only after
 * hand-off, settled by the payment's outcome, Phase 4.)
 */
export async function releaseReservationsOf(
  tx: ReservationsTransaction,
  { requestId, at }: { readonly requestId: string; readonly at: Date },
): Promise<number> {
  const released = await tx
    .updateTable('limit_reservations.reservations')
    .set({ state: 'RELEASED', settled_at: at })
    .where('request_id', '=', requestId)
    .where('state', '=', RESERVATION.initial)
    .executeTakeFirst();
  return Number(released.numUpdatedRows);
}
