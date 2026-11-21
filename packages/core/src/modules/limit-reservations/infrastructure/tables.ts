import type { Generated } from 'kysely';

/** The limit_reservations schema's tables (db/migrations/0040_limit_reservations.sql), as Kysely sees them. */
export interface LimitReservationsTables {
  'limit_reservations.agent_zones': AgentZonesTable;
  'limit_reservations.agent_periods': AgentPeriodsTable;
  'limit_reservations.reservations': ReservationsTable;
  'limit_reservations.month_totals': MonthTotalsTable;
  'limit_reservations.payee_windows': PayeeWindowsTable;
}

/** The time zone an agent's months are named in: its first reservation's mandate's, kept for good. */
interface AgentZonesTable {
  org_id: string;
  /** Its agent's ID: the row's own, as a signed record is addressed (0054's `id_is_its_agent`). */
  id: string;
  agent_id: string;
  time_zone: string;
  created_at: Date;
  state_version: Generated<number>;
  state_event_id: string | null;
}

/** Only a lock target: one row an agent a month, never changed (partner decision 4). */
interface AgentPeriodsTable {
  org_id: string;
  agent_id: string;
  /** `YYYY-MM`, as `periodOf` names it in the agent's zone. */
  month: string;
  created_at: Date;
}

interface ReservationsTable {
  org_id: string;
  id: string;
  /** Its spend request, by ID alone (ADR-004 §4). */
  request_id: string;
  agent_id: string;
  /** The lineage it was reserved under. */
  mandate_id: string;
  /** The agent's month it counts in. */
  month: string;
  supplier_id: string;
  /** The supplier's payee key when it has one (ADR-014 §3). */
  payee_key: string | null;
  /** Minor units: read back as text or a bigint, never a float. */
  amount_minor: string | bigint;
  currency: string;
  /** HELD, FINALISED, RELEASED or BLOCKED_UNKNOWN. */
  state: string;
  reserved_at: Date;
  /** When it reached FINALISED or RELEASED; none before. */
  settled_at: Date | null;
}

/** An agent's month's total in one currency, signed (0110, GM-1a): what its reservations hold, kept as they change. */
interface MonthTotalsTable {
  org_id: string;
  /** Named by its organisation, agent, month and currency (namedId), so a deleted one reads as deleted. */
  id: string;
  agent_id: string;
  /** `YYYY-MM`, as `periodOf` names it in the agent's zone. */
  month: string;
  currency: string;
  /** Minor units held: read back as text or a bigint, never a float. */
  held_minor: string | bigint;
  created_at: Date;
  state_version: Generated<number>;
  state_event_id: string | null;
}

/** A payee's split window in one currency, signed (0112, GM-1b): what its reservations hold, hour by hour. */
interface PayeeWindowsTable {
  org_id: string;
  /** Named by its organisation, supplier, payee key and currency (namedId), so a deleted one reads as deleted. */
  id: string;
  /** Its supplier's reservations, under any key; null for a key's own row. */
  supplier_id: string | null;
  /** Its payee key's reservations, under any supplier; null for a supplier's own row. */
  payee_key: string | null;
  currency: string;
  /** `hour:amount`, comma between, in order: each hour since 1970 holding anything, in minor units. */
  held_by_hour: string;
  created_at: Date;
  state_version: Generated<number>;
  state_event_id: string | null;
}
