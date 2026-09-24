/** The identity schema's tables (db/migrations/0010_identity.sql), as Kysely sees them. */
export interface IdentityTables {
  'identity.users': UsersTable;
  'identity.sessions': SessionsTable;
}

interface UsersTable {
  id: string;
  issuer: string;
  subject: string;
  created_at: Date;
}

interface SessionsTable {
  /** The stable record: step-up challenges bind to it (ADR-003 §7). */
  id: string;
  user_id: string;
  /** SHA-256 of the cookie ID the browser holds; never the cookie ID itself. */
  cookie_hash: Buffer;
  idp_session_id: string | null;
  auth_time: Date;
  amr: string[];
  created_at: Date;
  last_seen_at: Date;
  /** The absolute end, set when it opens; the idle end moves with last_seen_at. */
  ends_at: Date;
}
