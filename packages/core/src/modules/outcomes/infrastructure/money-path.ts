// One organisation's money path in counts (GA4, PRD §9.3): what the money-path
// snapshot (apps/api's money-path-snapshot.ts) reads of each organisation, a
// page of organisations a trip, each under its own wall (readEachTenant).
//
// Counts and sums only, never a row: nothing is decided or moved from them, so
// none is read through its signed state (a tampered row is the anchor check's
// and the holdings check's to find, not a dashboard's). One statement, each
// part a range of an index the jobs already keep:
//
// - approvals waiting: requests APPROVAL_REQUIRED (0074's requests_waiting_until);
// - approvals expired in the window: requests EXPIRED whose wait ended in it, by
//   `waits_until` (0073, filled for every waiting request by 0086), so within the
//   request expiry's five minutes of when it expired; read from the ID the
//   oldest such request could have (the window and the longest wait before it,
//   on the primary key: IDs are UUIDv7, so by when the request was made);
// - payments UNKNOWN, and when the oldest of them was made (as the bank check's
//   `payment_check.still_unknown` ages one), and payments still under way
//   (SUBMISSION_PENDING, SUBMITTED, PROCESSING) made before `stuckBefore`
//   (0063's transactions_under_way);
// - money held: the organisation's reservations HELD or BLOCKED_UNKNOWN (0120's
//   reservations_holding, read from the index alone), each split two ways and
//   counted and summed by currency:
//   - held: one in its agent's month now, or whose request is still live
//     (waiting, approved, ready, or handed off with its payment not yet settled:
//     settling moves the reservation in the same transaction, 0040). What the
//     limits engine holds against the agents' months now, and what a payment may
//     still take.
//   - kept past months: one of an earlier month whose request has ended. An
//     ending that kept its capacity (`capacityKept`, AT13d) leaves its reservation
//     HELD for good, counting in its own month alone (month-totals.ts), so once
//     that month is past it holds nothing more; it is said apart, never dropped.
//   The month now is the agent's, in its zone (agent_zones), as the database
//   names a reservation's month as it is made (0040's guard: to_char in that
//   zone, which periodOf's month must equal for the insert to pass); an agent
//   with no zone row reads in the default zone. Each reservation reaches its
//   zone and its request by their primary keys.
import { sql } from 'kysely';

import { DEFAULT_TIME_ZONE } from '../../../shared-kernel/index.ts';

/** A request whose reservation may still be taken by its payment, or given back by its own move. */
const LIVE = ['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF'] as const;

/** The times one pass reads every organisation's counts at, the same for each. */
export interface MoneyPathWindow {
  /** The pass's time. */
  readonly now: Date;
  /** Approvals whose wait ended after this, up to `now`, are counted as expired. */
  readonly expiredSince: Date;
  /** The lowest ID a request whose wait ended after `expiredSince` can have. */
  readonly idFloor: string;
  /** A payment under way made before this counts as stuck. */
  readonly stuckBefore: Date;
}

/** Money held in one currency: how many reservations, and their amount in minor units, as a decimal string. */
export interface HeldMoney {
  readonly currency: string;
  readonly reservations: number;
  readonly amountMinor: string;
}

/** One organisation's money path, as one read counts it. */
export interface MoneyPath {
  readonly approvalsWaiting: number;
  readonly approvalsExpired: number;
  readonly unknownPayments: number;
  /** When the oldest payment UNKNOWN was made; null where none is. */
  readonly oldestUnknownAt: Date | null;
  readonly stuckPayments: number;
  /** Held in its agent's month now, or for a request still live: by currency, in its order. */
  readonly held: readonly HeldMoney[];
  /** Kept HELD by an ending in a month now past, holding nothing more: by currency, in its order. */
  readonly keptPastMonths: readonly HeldMoney[];
}

/** The read's one row, as Postgres answers it. */
export interface MoneyPathRow {
  readonly approvals_waiting: number;
  readonly approvals_expired: number;
  readonly unknown_payments: number;
  readonly oldest_unknown_at: Date | null;
  readonly stuck_payments: number;
  readonly held: readonly HeldMoney[];
  readonly kept_past_months: readonly HeldMoney[];
}

/** The money held now (`true`) or kept past its month (`false`), by currency, as a JSON list: empty where none. */
const heldWhere = (nowHeld: boolean) => sql`coalesce(
  (select pg_catalog.json_agg(
    pg_catalog.json_build_object('currency', currency, 'reservations', reservations, 'amountMinor', amount_minor)
    order by currency
  ) from by_currency where now_held = ${nowHeld}::boolean),
  '[]'::json
)`;

/**
 * The organisation's money path as of `at`: one statement, not run, for readEachTenant's trip (each under the
 * organisation's own wall; the organisation is named too, so every part reads its index from the organisation).
 */
export function moneyPathRead(orgId: string, at: MoneyPathWindow) {
  const org = orgId.toLowerCase();
  // eslint-disable-next-line agentx/authority-tables-through-signed-state -- counts and sums alone, for the workbook; nothing is decided or moved from them
  return sql<MoneyPathRow>`
    with under_way as (
      select t.status, t.created_at
      from transactions.transactions t
      where t.org_id = ${org}::uuid and t.status in ('SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN')
    ),
    holding as (
      select h.currency, h.amount_minor,
        coalesce(
          h.month = pg_catalog.to_char(${at.now}::timestamptz at time zone coalesce(z.time_zone, ${DEFAULT_TIME_ZONE}), 'YYYY-MM')
            or r.status in (${sql.join(LIVE)}),
          false
        ) as now_held
      from limit_reservations.reservations h
      left join limit_reservations.agent_zones z on z.org_id = h.org_id and z.agent_id = h.agent_id
      left join spend_requests.requests r on r.org_id = h.org_id and r.id = h.request_id
      where h.org_id = ${org}::uuid and h.state in ('HELD', 'BLOCKED_UNKNOWN')
    ),
    by_currency as (
      select now_held, currency, pg_catalog.count(*)::int as reservations,
        pg_catalog.sum(amount_minor)::text as amount_minor
      from holding
      group by now_held, currency
    )
    select
      (select pg_catalog.count(*)::int from spend_requests.requests
        where org_id = ${org}::uuid and status = 'APPROVAL_REQUIRED') as approvals_waiting,
      (select pg_catalog.count(*)::int from spend_requests.requests
        where org_id = ${org}::uuid and id >= ${at.idFloor}::uuid and status = 'EXPIRED'
          and waits_until > ${at.expiredSince}::timestamptz and waits_until <= ${at.now}::timestamptz) as approvals_expired,
      (select pg_catalog.count(*)::int from under_way where status = 'UNKNOWN') as unknown_payments,
      (select pg_catalog.min(created_at) from under_way where status = 'UNKNOWN') as oldest_unknown_at,
      (select pg_catalog.count(*)::int from under_way
        where status <> 'UNKNOWN' and created_at < ${at.stuckBefore}::timestamptz) as stuck_payments,
      ${heldWhere(true)} as held,
      ${heldWhere(false)} as kept_past_months
  `;
}

/** The read's row as a money path. */
export const moneyPathOf = (row: MoneyPathRow): MoneyPath => ({
  approvalsWaiting: row.approvals_waiting,
  approvalsExpired: row.approvals_expired,
  unknownPayments: row.unknown_payments,
  oldestUnknownAt: row.oldest_unknown_at,
  stuckPayments: row.stuck_payments,
  held: row.held,
  keptPastMonths: row.kept_past_months,
});
