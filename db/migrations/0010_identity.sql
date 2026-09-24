-- The identity module's tables (ADR-003 §5, ADR-005 §6): the people who sign
-- in, and their console sessions. Both are global tables: a person can belong
-- to several organisations (memberships join at B4), and a session is opened
-- before any organisation is known. Each is on the CI-06 list with its reason,
-- its exact columns and the app's rights on it.
--
-- A person is known by the login service's issuer and subject, never by an
-- email or a name: Zitadel keeps those (ADR-009). The row is made at their
-- first sign-in; Zitadel is the gate, with self-registration off.
--
-- A session's own ID is its stable record, which step-up challenges bind to
-- (ADR-003 §7). The browser holds a different, random cookie ID, stored here
-- only as its SHA-256: it is rotated at step-up while the record stays, and a
-- copy of this table signs no one in. Zitadel's access and refresh tokens are
-- never stored. Its session ID (`sid`), the authentication time and methods
-- are kept as the evidence the login gave.
--
-- The app adds people and reads them, never changes or deletes one: a user's
-- ID is what every membership and audit event will point at. It adds sessions,
-- reads them, rotates a session's cookie ID and moves its last-seen time, and
-- deletes a session to end it; it never moves one to another person, nor
-- changes when it began, what it proved or when it must end. The backup role
-- reads everything, as it must for a logical backup.

CREATE SCHEMA identity;
GRANT USAGE ON SCHEMA identity TO agentx_app, agentx_backup;

CREATE TABLE identity.users (
  id uuid PRIMARY KEY,
  issuer text NOT NULL CHECK (pg_catalog.char_length(issuer) BETWEEN 1 AND 255),
  subject text NOT NULL CHECK (pg_catalog.char_length(subject) BETWEEN 1 AND 255),
  created_at timestamptz NOT NULL,
  CONSTRAINT one_user_per_subject UNIQUE (issuer, subject)
);

GRANT SELECT, INSERT ON identity.users TO agentx_app;
GRANT SELECT ON identity.users TO agentx_backup;

CREATE TABLE identity.sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES identity.users (id),
  cookie_hash bytea NOT NULL CHECK (pg_catalog.octet_length(cookie_hash) = 32),
  idp_session_id text CHECK (pg_catalog.char_length(idp_session_id) BETWEEN 1 AND 255),
  auth_time timestamptz NOT NULL,
  amr text[] NOT NULL CHECK (pg_catalog.cardinality(amr) BETWEEN 1 AND 16),
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  CONSTRAINT one_session_per_cookie UNIQUE (cookie_hash),
  CONSTRAINT ends_after_it_begins CHECK (ends_at > created_at)
);

-- A person's sessions, found together to end them all (B4: a role change or a
-- deactivation ends every one of them in the same transaction).
CREATE INDEX sessions_by_user ON identity.sessions (user_id);

GRANT SELECT, INSERT, DELETE ON identity.sessions TO agentx_app;
GRANT UPDATE (cookie_hash, last_seen_at) ON identity.sessions TO agentx_app;
GRANT SELECT ON identity.sessions TO agentx_backup;
