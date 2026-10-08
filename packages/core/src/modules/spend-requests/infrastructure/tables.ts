import type { Generated } from 'kysely';

/** The spend_requests schema's tables (db/migrations/0039_spend_requests.sql), as Kysely sees them. */
export interface SpendRequestsTables {
  'spend_requests.requests': RequestsTable;
  'spend_requests.order_claims': OrderClaimsTable;
}

interface RequestsTable {
  org_id: string;
  id: string;
  agent_id: string;
  /** The agent key the request came with. */
  agent_key_id: string;
  /** The agent's mandate and its version in force when decided; none when it had none. */
  mandate_id: string | null;
  mandate_version_id: string | null;
  /** The policy versions weighed; none where none is set (the default applied). */
  organization_policy_version_id: string | null;
  mandate_policy_version_id: string | null;
  /** As the agent named it, the organisation's or not. */
  supplier_id: string;
  /** The supplier's version weighed; none when it isn't the organisation's. */
  supplier_version_id: string | null;
  /** As the agent named it, the organisation's or not. */
  funding_source_id: string;
  /** Minor units: read back as text or a bigint, never a float. */
  amount_minor: string | bigint;
  currency: string;
  purpose: string;
  /** As the agent wrote it; the claim keeps its canonical form. */
  order_reference: string;
  idempotency_key: string;
  /** The keyed hash of everything weighed, in lower-case hex, and its key's version. */
  input_hash: string;
  input_hash_key_version: number;
  /** ALLOW, DENY, REQUIRE_APPROVAL or REQUIRE_NEW_MANDATE. */
  decision: string;
  /** Reason codes in the order checked, one space apart; none for ALLOW. */
  reason_codes: string | null;
  status: string;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface OrderClaimsTable {
  org_id: string;
  id: string;
  request_id: string;
  supplier_id: string;
  /** The supplier's payee key when it has one (ADR-014 §3). */
  payee_key: string | null;
  /** Canonical: lower case, words one space apart (ADR-006 §5). */
  order_reference: string;
  claimed_at: Date;
  /** When its request or payment ended so the order may be asked for again; open until then. */
  released_at: Date | null;
}
