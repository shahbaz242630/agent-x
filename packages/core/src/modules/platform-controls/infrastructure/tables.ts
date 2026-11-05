import type { Generated } from 'kysely';

/** The platform-controls schema's tables (db/migrations/0003_platform_controls.sql, 0057_handoff_pause.sql, 0068_job_lease.sql, 0079_operator_role.sql), as Kysely sees them. */
export interface PlatformControlsTables {
  'platform_controls.audit_events': EventsTable;
  'platform_controls.audit_head': HeadTable;
  'platform_controls.handoff_pause': HandoffPauseTable;
  'platform_controls.job_lease': JobLeaseTable;
  'platform_controls.operator_signatures': OperatorSignaturesTable;
  'platform_controls.operator_signing': OperatorSigningTable;
}

/** Where the operator's signatures start (0079, PL-57): one row, the owner's, read only. */
interface OperatorSigningTable {
  only_row: Generated<boolean>;
  signed_from: bigint;
}

/** The operator's signature on one of its platform events (0079, PL-57), by the event's place and ID. */
interface OperatorSignaturesTable {
  seq: bigint;
  id: string;
  /** Ed25519: 64 bytes. */
  signature: Buffer;
  key_version: number;
}

interface EventsTable {
  seq: bigint;
  id: string;
  recorded_at: Date;
  actor_type: string;
  actor_id: string;
  action: string;
  /** The canonical JSON text that was sealed, kept exactly. */
  details: string;
  prev_hash: Buffer;
  hash: Buffer;
  mac: Buffer;
  mac_key_version: number;
}

interface HeadTable {
  /** Always true, which makes the row the table's only one; the database fills it in. */
  only_row: Generated<boolean>;
  seq: bigint;
  hash: Buffer;
  mac: Buffer;
  mac_key_version: number;
}

interface JobLeaseTable {
  name: string;
  /** The process that leads; null when free. */
  holder: string | null;
  until: Date;
  renewed_at: Date | null;
  /** Moved only while the hand-off and the payment checks beat. */
  beating_at: Date | null;
}

interface HandoffPauseTable {
  /** Always true, which makes the row the table's only one; the database fills it in. */
  only_row: Generated<boolean>;
  paused: boolean;
  /** The platform event that set it; null with `event_id` only for the row as born, paused. */
  event_seq: bigint | null;
  event_id: string | null;
}
