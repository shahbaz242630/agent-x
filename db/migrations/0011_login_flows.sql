-- The sign-in flows under way (ADR-003 §5-§6, B2-3a): what the API sent a
-- browser to the login service with (state, nonce, PKCE verifier) and where
-- to send it back after, kept here until the browser returns. The browser
-- holds only a random flow ID in a short-lived cookie, stored here as its
-- SHA-256, like a session's cookie ID (0010).
--
-- Kept server-side rather than sealed in the cookie, so no key is needed and
-- a flow is used once: the callback takes it (deletes it and reads it in one
-- statement) before it calls the login service, so a replayed callback finds
-- nothing. A flow lives ten minutes.
--
-- A global table, on the CI-06 list: a flow belongs to no organisation, and
-- to no one yet. The app adds a flow, and takes it (DELETE ... RETURNING,
-- which needs SELECT); it never changes one. The backup role reads it, as it
-- reads everything.

CREATE TABLE identity.login_flows (
  cookie_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(cookie_hash) = 32),
  state text NOT NULL CHECK (pg_catalog.char_length(state) BETWEEN 1 AND 255),
  nonce text NOT NULL CHECK (pg_catalog.char_length(nonce) BETWEEN 1 AND 255),
  verifier text NOT NULL CHECK (pg_catalog.char_length(verifier) BETWEEN 43 AND 128),
  return_to text NOT NULL CHECK (pg_catalog.char_length(return_to) BETWEEN 1 AND 512),
  created_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  CONSTRAINT flow_ends_after_it_begins CHECK (ends_at > created_at)
);

GRANT SELECT, INSERT, DELETE ON identity.login_flows TO agentx_app;
GRANT SELECT ON identity.login_flows TO agentx_backup;
