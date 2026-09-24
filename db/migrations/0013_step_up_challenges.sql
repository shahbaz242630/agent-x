-- Step-up challenges (ADR-003 §8-§9, B3-1): before a sensitive change, the
-- person signs in again, and that sign-in stands for that one change alone.
-- A challenge binds the stable session record (0010), the action and the
-- SHA-256 of the pending change, which its own module keeps; it holds the
-- nonce the login service must echo, and lives five minutes.
--
-- Once the person has signed in again, the step-up's evidence is recorded on
-- it, once: when, how (`amr`), Zitadel's session ID and the ID token's hash.
-- The change then consumes it inside the change's own transaction (deletes
-- and reads it in one statement), only for the same session, action and
-- change hash, so it is used once and for nothing else (SEC-HA-03, 04).
--
-- A global table, on the CI-06 list: a person's step-up belongs to their
-- session, not to an organisation. The person is taken from the session as
-- the challenge is made, never given. It goes with its session (ON DELETE
-- CASCADE): sessions end by being deleted, and a challenge outliving its
-- session could be used by no one. The app adds challenges, reads them,
-- records the evidence once and deletes them; it never changes what a
-- challenge is for. The backup role reads it, as it reads everything.

CREATE TABLE identity.step_up_challenges (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES identity.sessions (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES identity.users (id),
  action text NOT NULL CHECK (
    pg_catalog.char_length(action) <= 64 AND action ~ '^[a-z][a-z0-9]*([.-][a-z0-9]+)*$'
  ),
  change_hash bytea NOT NULL CHECK (pg_catalog.octet_length(change_hash) = 32),
  nonce text NOT NULL CHECK (pg_catalog.char_length(nonce) BETWEEN 1 AND 255),
  created_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  verified_at timestamptz,
  auth_time timestamptz,
  amr text[] CHECK (pg_catalog.cardinality(amr) BETWEEN 1 AND 16),
  idp_session_id text CHECK (pg_catalog.char_length(idp_session_id) BETWEEN 1 AND 255),
  id_token_hash bytea CHECK (pg_catalog.octet_length(id_token_hash) = 32),
  CONSTRAINT challenge_ends_after_it_begins CHECK (ends_at > created_at),
  -- The evidence is recorded whole, or not at all; Zitadel's session ID may be absent.
  CONSTRAINT evidence_whole CHECK (
    (verified_at IS NULL AND auth_time IS NULL AND amr IS NULL AND idp_session_id IS NULL AND id_token_hash IS NULL)
    OR (verified_at IS NOT NULL AND auth_time IS NOT NULL AND amr IS NOT NULL AND id_token_hash IS NOT NULL)
  )
);

-- A session's challenges, found by the cascade as the session ends.
CREATE INDEX step_up_challenges_by_session ON identity.step_up_challenges (session_id);

GRANT SELECT, INSERT, DELETE ON identity.step_up_challenges TO agentx_app;
GRANT UPDATE (verified_at, auth_time, amr, idp_session_id, id_token_hash) ON identity.step_up_challenges TO agentx_app;
GRANT SELECT ON identity.step_up_challenges TO agentx_backup;
