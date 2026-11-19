/** The security schema's tables (db/migrations/0012_security_events.sql, 0091_security_org_events.sql), as Kysely sees them. */
export interface SecurityEventsTables {
  'security.events': EventsTable;
  'security.org_events': OrgEventsTable;
}

interface EventsTable {
  id: string;
  kind: string;
  reason: string;
  /** Postgres `inet`, as text; null when the API could read no address. */
  ip: string | null;
  user_id: string | null;
  window_start: Date;
  count: number;
  created_at: Date;
  /** 0106: the row's MAC with `session-mac` (event-seals.ts), and its key's version; null on a row from before. */
  mac: Buffer | null;
  mac_key_version: number | null;
}

/** An organisation's own events (0091): a tenant table, walled by row-level security. */
interface OrgEventsTable {
  org_id: string;
  id: string;
  kind: string;
  reason: string;
  /** Postgres `inet`, as text; null when the API could read no address. */
  ip: string | null;
  user_id: string | null;
  agent_id: string | null;
  window_start: Date;
  count: number;
  created_at: Date;
  /** 0106: the row's MAC with `session-mac` (event-seals.ts), and its key's version; null on a row from before. */
  mac: Buffer | null;
  mac_key_version: number | null;
}
