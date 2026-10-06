import type { Generated } from 'kysely';

/** The mandates schema's tables (db/migrations/0035_mandates.sql), as Kysely sees them. */
export interface MandatesTables {
  'mandates.allowed_currencies': AllowedCurrenciesTable;
  'mandates.mandates': MandatesTable;
  'mandates.versions': MandateVersionsTable;
}

interface AllowedCurrenciesTable {
  /** An ISO 4217 code: AED in the Pilot. */
  code: string;
}

interface MandatesTable {
  org_id: string;
  id: string;
  agent_id: string;
  /** The IANA zone its months are counted in, as the runtime names it. */
  time_zone: string;
  split_window_hours: number;
  status: string;
  /** The version in force. */
  current_version_id: string | null;
  /** A draft waiting for acceptance. */
  pending_version_id: string | null;
  /** The membership of the admin who accepted the version in force. */
  accepted_by: string | null;
  accepted_at: Date | null;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface MandateVersionsTable {
  org_id: string;
  id: string;
  mandate_id: string;
  version: number;
  purpose: string;
  currency: string;
  /** Minor units: read back as text or a bigint, never a float. */
  per_order_limit_minor: string | bigint;
  monthly_limit_minor: string | bigint;
  approval_threshold_minor: string | bigint;
  /** Lower-case supplier IDs, sorted, each once, one space apart. */
  supplier_ids: string;
  funding_source_id: string;
  /** `on` or `off`. */
  split_check: string;
  /** `strict` or `flexible`. */
  consent_limits: string;
  ends_at: Date | null;
  /** SHA-256 of the canonical terms, in lower-case hex: what an acceptance is bound to. */
  terms_hash: string;
  /** The membership of the member who drafted it. */
  drafted_by: string;
  drafted_at: Date;
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}
