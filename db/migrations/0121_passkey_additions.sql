-- A passkey added inside Agent X (SA6; ADR-012 §8, SEC-OPS-04, B6-3d): a person,
-- signed in again with a passkey they already hold, adds another without the
-- 7 days' restriction a key added at the login service directly starts.
--
-- One row is one addition under way, from the step-up's return to the key
-- confirmed, minutes at most:
-- - `stepped_up`: the step-up came back with the person's own access token to
--   the login service's API, kept sealed (ADR-011 §2, `field-encryption`)
--   with the row's ID, its person and its session as associated data, so it
--   opens for this addition alone; never shown to anyone, never logged;
-- - `ticketed`: the console was given a one-time ticket for the add-a-key
--   page, kept only as its SHA-256;
-- - `redeemed`: the page redeemed the ticket, once; the login service is asked
--   for a passkey as the person;
-- - `registering`: the login service named the new passkey's ID, recorded on
--   the platform chain before the page was given anything to make the key with.
-- - `confirming`: the page sent the key made, once; the token is taken out of
--   the row as the key goes to the login service;
-- - `confirmed`: the login service took the key; the row is kept a few
--   minutes only for the console to say so.
-- Refused, or past its time, the row is deleted, and the token with it.
--
-- A global table, on the CI-06 list: a person's own sign-in methods belong
-- to no organisation. It goes with its session (ON DELETE CASCADE): the
-- step-up was that session's. The app adds a row, moves it on, and deletes
-- it; it never changes whose it is or which session's. The backup role reads
-- it, as it reads everything (the token sealed).

CREATE TABLE identity.passkey_additions (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES identity.sessions (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES identity.users (id),
  state text NOT NULL CHECK (state IN ('stepped_up', 'ticketed', 'redeemed', 'registering', 'confirming', 'confirmed')),
  token_ciphertext bytea CHECK (pg_catalog.octet_length(token_ciphertext) BETWEEN 1 AND 8192),
  token_key_version integer CHECK (token_key_version >= 1),
  ticket_hash bytea UNIQUE CHECK (pg_catalog.octet_length(ticket_hash) = 32),
  passkey_id text CHECK (passkey_id ~ '^[0-9A-Za-z_-]{1,200}$'),
  created_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  CONSTRAINT addition_ends_after_it_begins CHECK (ends_at > created_at),
  -- Each state holds exactly what it has reached: a ticket from `ticketed` on, a passkey only once registering.
  CONSTRAINT addition_state_whole CHECK (
    (state = 'stepped_up' AND ticket_hash IS NULL AND passkey_id IS NULL)
    OR (state IN ('ticketed', 'redeemed') AND ticket_hash IS NOT NULL AND passkey_id IS NULL)
    OR (state IN ('registering', 'confirming', 'confirmed') AND ticket_hash IS NOT NULL AND passkey_id IS NOT NULL)
  ),
  -- The token is held until the key is sent to be confirmed, and never after.
  CONSTRAINT addition_token_until_confirming CHECK (
    (state IN ('confirming', 'confirmed') AND token_ciphertext IS NULL AND token_key_version IS NULL)
    OR (state NOT IN ('confirming', 'confirmed') AND token_ciphertext IS NOT NULL AND token_key_version IS NOT NULL)
  )
);

-- A session's additions, found by the cascade as the session ends.
CREATE INDEX passkey_additions_by_session ON identity.passkey_additions (session_id);
-- The sweep's: additions past their time.
CREATE INDEX passkey_additions_by_end ON identity.passkey_additions (ends_at);

GRANT SELECT, INSERT, DELETE ON identity.passkey_additions TO agentx_app;
GRANT UPDATE (state, token_ciphertext, token_key_version, ticket_hash, passkey_id, ends_at) ON identity.passkey_additions TO agentx_app;
GRANT SELECT ON identity.passkey_additions TO agentx_backup;
