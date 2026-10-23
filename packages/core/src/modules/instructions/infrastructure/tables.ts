import type { Generated } from 'kysely';

/** The instructions schema's table and its directory entry (db/migrations/0058_instructions_transactions.sql), as Kysely sees them. */
export interface InstructionsTables {
  'instructions.instructions': InstructionsTable;
  'directory.instructions': DirectoryInstructionsTable;
}

interface InstructionsTable {
  org_id: string;
  id: string;
  spend_request_id: string;
  route: string;
  route_reason: string;
  funding_source_id: string;
  partner: string;
  partner_legal_entity_id: string;
  partner_licence_ref: string;
  account_consent_id: string;
  beneficiary_ref: string;
  supplier_version_id: string;
  /** Minor units, as Postgres's bigint comes back: text. */
  amount_minor: string;
  currency: string;
  payment_reference: string;
  intent_hash: string;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

/** An instruction's ID and its organisation (ADR-005): a global table, of no organisation. */
interface DirectoryInstructionsTable {
  instruction_id: string;
  org_id: string;
  /** The consent it pays under (0063); null for one entered before. */
  account_consent_id: string | null;
}
