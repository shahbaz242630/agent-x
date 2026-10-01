import type { Generated } from 'kysely';

/** The suppliers schema's tables (db/migrations/0032_suppliers.sql, 0033_beneficiary_registrations.sql), as Kysely sees them. */
export interface SuppliersTables {
  'suppliers.suppliers': SuppliersTable;
  'suppliers.supplier_versions': SupplierVersionsTable;
  'suppliers.beneficiary_registrations': BeneficiaryRegistrationsTable;
}

interface SuppliersTable {
  org_id: string;
  id: string;
  status: string;
  current_version_id: string;
  pending_version_id: string | null;
  cooling_off_until: Date | null;
  /** The verifier's membership. */
  verified_by: string | null;
  /** The version that was verified. */
  verified_version_id: string | null;
  payee_key: string | null;
  payee_key_version: number | null;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface SupplierVersionsTable {
  org_id: string;
  id: string;
  supplier_id: string;
  version: number;
  display_name: string;
  /** Which contacts it holds: `phone`, then `email` and `licence` when given. */
  contacts: string;
  phone_ciphertext: Buffer;
  email_ciphertext: Buffer | null;
  licence_ciphertext: Buffer | null;
  contacts_key_version: number;
  /** Since when its phone is the supplier's. */
  phone_since: Date;
  source_kind: string;
  source_ref: string;
  /** The membership of the member who entered it. */
  entered_by: string;
  entered_at: Date;
  registration_id: string | null;
  beneficiary_ref: string | null;
  payee_hint: string | null;
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface BeneficiaryRegistrationsTable {
  org_id: string;
  /** Ours: the partner's idempotency key for it. */
  id: string;
  supplier_id: string;
  /** The version Tx 2 makes with its reference. */
  version_id: string;
  partner: string;
  route: string;
  /** The membership of the member who started it. */
  started_by: string;
  status: string;
  beneficiary_ref: string | null;
  payee_key: string | null;
  payee_key_version: number | null;
  name_check: string | null;
  masked_name: string | null;
  payee_hint: string | null;
  registered_at: Date | null;
  failure: string | null;
  created_at: Date;
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}
