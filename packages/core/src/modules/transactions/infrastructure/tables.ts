import type { Generated } from 'kysely';

/** The transactions schema's table (db/migrations/0057_instructions_transactions.sql), as Kysely sees it. */
export interface TransactionsTables {
  'transactions.transactions': TransactionsTable;
}

interface TransactionsTable {
  org_id: string;
  id: string;
  instruction_id: string;
  status: string;
  provider_status: Generated<string | null>;
  payment_instruction_ref: Generated<string | null>;
  reject_code: Generated<string | null>;
  provider_changed_at: Generated<Date | null>;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}
