/** The security schema's table (db/migrations/0012_security_events.sql), as Kysely sees it. */
export interface SecurityEventsTables {
  'security.events': EventsTable;
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
}
