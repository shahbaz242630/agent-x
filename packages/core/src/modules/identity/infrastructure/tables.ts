import type { Generated } from 'kysely';

import type { TamperSign } from '../../audit/index.ts';

/** The identity schema's tables (db/migrations/0010_identity.sql, 0011_login_flows.sql, 0013_step_up_challenges.sql, 0014_step_up_flows.sql, 0015_memberships.sql, 0016_invitations.sql, 0017_session_emails.sql, 0018_invitation_acceptance.sql, 0019_membership_reactivation.sql, 0020_first_admin_invitation.sql, 0022_registered_contacts.sql, 0025_factor_resets.sql, 0049_user_contacts.sql, 0085_membership_grants.sql, 0106_login_flow_caps.sql, 0120_passkey_additions.sql), as Kysely sees them. */
export interface IdentityTables {
  'identity.users': UsersTable;
  'identity.sessions': SessionsTable;
  'identity.login_flows': LoginFlowsTable;
  'identity.step_up_challenges': StepUpChallengesTable;
  'identity.passkey_additions': PasskeyAdditionsTable;
  'identity.memberships': MembershipsTable;
  'identity.membership_grants': MembershipGrantsTable;
  'identity.invitations': InvitationsTable;
  'identity.session_emails': SessionEmailsTable;
  'identity.user_contacts': UserContactsTable;
  'identity.registered_contacts': RegisteredContactsTable;
  'identity.factor_resets': FactorResetsTable;
  'identity.factor_reset_confirmations': FactorResetConfirmationsTable;
}

interface UsersTable {
  id: string;
  issuer: string;
  subject: string;
  created_at: Date;
  /** When their sessions were last all ended (0098, AG10); null if never. */
  sessions_ended_at: Date | null;
  /** `session-mac` over id, issuer, subject and created_at (row-macs.ts, 0100); null only for a person made before it. */
  mac: Buffer | null;
  mac_key_version: number | null;
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
  /** `session-mac` over every column but last_seen_at (row-macs.ts, 0100), and its key's version. */
  mac: Buffer;
  mac_key_version: number;
  /** `session-mac` over the cookie hash and last_seen_at (row-macs.ts, 0111), and its key's version; none on a session from before. */
  last_use_mac: Buffer | null;
  last_use_mac_key_version: number | null;
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
  /** The network a sign-in's flow was started from (0106), counted against its cap; null for a step-up's, or one before. */
  network_key: string | null;
}

/** A passkey added inside Agent X under way (SA6, 0120): from the step-up's return to the key confirmed. */
interface PasskeyAdditionsTable {
  /** The step-up challenge's own ID. */
  id: string;
  /** The session the step-up was made in; the addition goes with it. */
  session_id: string;
  user_id: string;
  state: 'stepped_up' | 'ticketed' | 'redeemed' | 'registering' | 'confirming' | 'confirmed';
  /** The person's own access token to the login service's API, sealed with the row's ID, person and session; gone once sent to be confirmed. */
  token_ciphertext: Buffer | null;
  token_key_version: number | null;
  /** SHA-256 of the one-time ticket for the add-a-key page, from `ticketed` on. */
  ticket_hash: Buffer | null;
  /** The login service's ID for the new passkey, once registering. */
  passkey_id: string | null;
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
  /** `session-mac` over the challenge as it stands, opened or verified (row-macs.ts, 0100), and its key's version. */
  mac: Buffer;
  mac_key_version: number;
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

/** A membership's grant summary (0085, OR1): its row's ID is its membership's. */
interface MembershipGrantsTable {
  org_id: string;
  id: string;
  /** Lower-case user IDs, sorted, comma-joined; empty for none. */
  granted_by: string;
  verifier_changed_at: Date | null;
  membership_version: number;
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

interface UserContactsTable {
  user_id: string;
  name_ciphertext: Buffer | null;
  name_key_version: number | null;
  email_ciphertext: Buffer | null;
  email_key_version: number | null;
  updated_at: Date;
}

interface RegisteredContactsTable {
  org_id: string;
  id: string;
  status: string;
  added_by: string;
  /** Null for a DRAFT. */
  counts_from: Date | null;
  step_up_challenge_id: string;
  created_at: Date;
  email_ciphertext: Buffer;
  email_key_version: number;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface FactorResetsTable {
  org_id: string;
  id: string;
  status: string;
  person: string;
  requested_by: string;
  step_up_challenge_id: string;
  expires_at: Date;
  /** Null until a contact confirms, with the cooling-off's end. */
  confirmed_by: string | null;
  cooling_off_until: Date | null;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface FactorResetConfirmationsTable {
  org_id: string;
  reset_id: string;
  contact_id: string;
  secret_ciphertext: Buffer;
  secret_key_version: number;
  created_at: Date;
}

/** A record read through its signed state: found as `T`, missing, or tampered with. */
export type Found<T> =
  T | { readonly outcome: 'missing' } | { readonly outcome: 'tampered'; readonly sign: TamperSign };
