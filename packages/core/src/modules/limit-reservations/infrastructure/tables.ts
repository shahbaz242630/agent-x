/** The limit_reservations schema's tables (db/migrations/0040_limit_reservations.sql), as Kysely sees them. */
export interface LimitReservationsTables {
  'limit_reservations.agent_zones': AgentZonesTable;
  'limit_reservations.agent_periods': AgentPeriodsTable;
  'limit_reservations.reservations': ReservationsTable;
}

/** The time zone an agent's months are named in: its first reservation's mandate's, kept for good. */
interface AgentZonesTable {
  org_id: string;
  agent_id: string;
  time_zone: string;
  created_at: Date;
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
