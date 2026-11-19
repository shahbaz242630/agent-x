import type { Generated } from 'kysely';

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
    /** 0105 (S206 V6): its MAC with `session-mac`, and the key's version; null on a row from before. */
    mac: Buffer | null;
    mac_key_version: number | null;
    /** 0105: a row from before it, which alone may have no MAC (and is never believed without one). */
    before_macs: Generated<boolean>;
  };
}
