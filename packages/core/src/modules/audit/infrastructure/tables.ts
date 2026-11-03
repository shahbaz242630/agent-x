/**
 * The audit schema's tables (db/migrations/0002_audit.sql), as Kysely sees them,
 * and the holds waiting (0069): the directory's schema, read and written only here,
 * as the hold is the audit module's and it imports no other.
 */
export interface AuditTables {
  'audit.events': EventsTable;
  'audit.heads': HeadsTable;
  'directory.holds_waiting': HoldsWaitingTable;
}

interface HoldsWaitingTable {
  org_id: string;
  subject_type: string;
  object_id: string;
  reason: string;
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
