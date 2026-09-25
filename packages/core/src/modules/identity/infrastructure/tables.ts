import type { Generated } from 'kysely';

/** The identity schema's tables (db/migrations/0010_identity.sql, 0011_login_flows.sql, 0013_step_up_challenges.sql, 0014_step_up_flows.sql, 0015_memberships.sql, 0016_invitations.sql, 0017_session_emails.sql, 0018_invitation_acceptance.sql, 0019_membership_reactivation.sql, 0020_first_admin_invitation.sql), as Kysely sees them. */
export interface IdentityTables {
  'identity.users': UsersTable;
  'identity.sessions': SessionsTable;
  'identity.login_flows': LoginFlowsTable;
  'identity.step_up_challenges': StepUpChallengesTable;
  'identity.memberships': MembershipsTable;
  'identity.invitations': InvitationsTable;
  'identity.session_emails': SessionEmailsTable;
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
  /** The step-up challenge the flow was started for (0014); null for an ordinary sign-in. */
  step_up_challenge_id: string | null;
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

interface MembershipsTable {
  org_id: string;
  id: string;
  user_id: string;
  role: string;
  status: string;
  joined_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface InvitationsTable {
  org_id: string;
  id: string;
  role: string;
  status: string;
  invited_by: string | null;
  expires_at: Date;
  created_at: Date;
  email_ciphertext: Buffer;
  email_key_version: number;
  step_up_challenge_id: string | null;
  accepted_by: string | null;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface SessionEmailsTable {
  session_id: string;
  email_ciphertext: Buffer;
  email_key_version: number;
}
