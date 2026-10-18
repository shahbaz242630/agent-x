/** The activity log's tables (db/migrations/0052_activity_log.sql), as Kysely sees them. */
export interface ActivityTables {
  'access.requests': RequestsTable;
  'access.person_requests': PersonRequestsTable;
}

/** What both tables hold of a request. */
interface RequestColumns {
  id: string;
  recorded_at: Date;
  method: string;
  route: string;
  path_ids: string[];
  status: number;
  reason: string | null;
  correlation_id: string;
  duration_ms: number;
  /** Postgres `inet`, as text. */
  ip: string | null;
  country: string | null;
  city: string | null;
  time_zone: string | null;
  time_zone_from: string | null;
}

interface RequestsTable extends RequestColumns {
  org_id: string;
  actor_type: string;
  actor_id: string;
}

interface PersonRequestsTable extends RequestColumns {
  user_id: string;
  claimed_org: string | null;
}
