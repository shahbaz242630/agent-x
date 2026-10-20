import type { Generated } from 'kysely';

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

/** The activity log's background downloads (db/migrations/0053_activity_exports.sql), as Kysely sees them. */
export interface ActivityExportTables {
  'activity_exports.exports': ExportsTable;
  'activity_exports.files': FilesTable;
}

interface ExportsTable {
  org_id: string;
  id: string;
  requested_by: string;
  requested_at: Generated<Date>;
  range_from: Date;
  range_to: Date;
  actor_type: string | null;
  actor_id: string | null;
  format: string;
  written_up_to: string | null;
}

interface FilesTable {
  org_id: string;
  export_id: string;
  /** Postgres `date`, the month's first day: always read as `month::text` (YYYY-MM-DD), as pg would make it a local Date. */
  month: string;
  state: string;
  attempts: number;
  building_until: Date | null;
  requests: number | null;
  /** Postgres `bigint`, which the pool reads as a bigint. */
  bytes: bigint | null;
  sha256: string | null;
  ready_at: Date | null;
  failure: string | null;
}
