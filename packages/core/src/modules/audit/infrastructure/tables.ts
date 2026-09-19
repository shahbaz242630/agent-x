/** The audit schema's tables (db/migrations/0002_audit.sql), as Kysely sees them. */
export interface AuditTables {
  'audit.events': EventsTable;
  'audit.heads': HeadsTable;
}

interface EventsTable {
  org_id: string;
  seq: bigint;
  id: string;
  recorded_at: Date;
  actor_type: string;
  actor_id: string;
  action: string;
  subject_type: string;
  subject_id: string;
  subject_version: number;
  /** The canonical JSON text that was sealed, kept exactly. */
  details: string;
  prev_hash: Buffer;
  hash: Buffer;
  mac: Buffer;
  mac_key_version: number;
}

interface HeadsTable {
  org_id: string;
  seq: bigint;
  hash: Buffer;
  mac: Buffer;
  mac_key_version: number;
}
