import type { Generated } from 'kysely';

/** The funding_sources schema's tables (db/migrations/0029_funding_sources.sql), as Kysely sees them. */
export interface FundingSourcesTables {
  'funding_sources.links': LinksTable;
  'funding_sources.sources': SourcesTable;
}

interface LinksTable {
  org_id: string;
  /** Our link ID: the partner's idempotency key for it. */
  id: string;
  /** The membership of the member who started it. */
  started_by: string;
  partner: string;
  session_ref: string;
  expires_at: Date;
  created_at: Date;
  outcome: string | null;
  source_id: string | null;
  settled_at: Date | null;
}

interface SourcesTable {
  org_id: string;
  id: string;
  link_id: string;
  partner: string;
  external_ref: string;
  status: string;
  availability: string;
  consent_status: string;
  account_consent_id: string;
  replaces_consent_id: string | null;
  consent_expires_at: Date;
  currency: string;
  limit_period: string;
  /** Minor units: pg gives a bigint back as text. */
  max_payment_minor: string | bigint;
  max_period_minor: string | bigint;
  max_period_payments: number;
  holder_name: string;
  account_type: string;
  hint: string;
  partner_changed_at: Date;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}
