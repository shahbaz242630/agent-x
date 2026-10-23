// The provider-events tables (db/migrations/0063_provider_events.sql), as Kysely sees them.

export interface ProviderEventsTables {
  'provider_events.inbox': {
    id: string;
    partner: string;
    dedupe_key: string;
    event_type: string;
    reference_kind: 'instruction' | 'consent';
    reference: string;
    org_id: string | null;
    received_at: Date;
    taken_at: Date | null;
    attempts: number;
    body_ciphertext: Buffer | null;
    body_key_version: number | null;
  };
  'security.partner_event_evidence': {
    id: string;
    reason: 'signature' | 'stale' | 'malformed';
    ip: string | null;
    body_ciphertext: Buffer;
    body_key_version: number;
    body_bytes: number;
    received_at: Date;
  };
}
