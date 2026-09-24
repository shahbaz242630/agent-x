/** The identity schema's tables (db/migrations/0010_identity.sql, 0011_login_flows.sql, 0013_step_up_challenges.sql), as Kysely sees them. */
export interface IdentityTables {
  'identity.users': UsersTable;
  'identity.sessions': SessionsTable;
  'identity.login_flows': LoginFlowsTable;
  'identity.step_up_challenges': StepUpChallengesTable;
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

interface LoginFlowsTable {
  /** SHA-256 of the flow ID the browser holds; never the flow ID itself. */
  cookie_hash: Buffer;
  state: string;
  nonce: string;
  verifier: string;
  /** The same-origin path to send the browser back to (SEC-WEB-04). */
  return_to: string;
  created_at: Date;
  ends_at: Date;
}

interface StepUpChallengesTable {
  id: string;
  /** The stable session record the challenge binds to; it goes with the session. */
  session_id: string;
  /** Taken from the session as the challenge is made. */
  user_id: string;
  /** What the change is, in the same form as a write's operation. */
  action: string;
  /** SHA-256 of the pending change, which its own module keeps. */
  change_hash: Buffer;
  nonce: string;
  created_at: Date;
  ends_at: Date;
  /** The step-up's evidence: all set together, once, or none. */
  verified_at: Date | null;
  auth_time: Date | null;
  amr: string[] | null;
  idp_session_id: string | null;
  id_token_hash: Buffer | null;
}
