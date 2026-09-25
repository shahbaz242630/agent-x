-- A session's verified email address (ADR-003 §5, ADR-005 §6; B4-4a): what
-- the login service vouched for as the person signed in, kept so an
-- invitation can be matched against it (B4-4c: the token and a match with
-- the accepting account's verified email).
--
-- Only an address the login service says is verified is kept, in lower
-- case, encrypted (ADR-011 §2, `field-encryption`) with the session's ID as
-- its associated data, so a value copied to another session won't open.
-- Zitadel stays the address's home (0010): this copy lives exactly as long
-- as its session, going with it (ON DELETE CASCADE), and a session signed in
-- before B4-4a has none, so its person signs in again to accept.
--
-- A global table, on the CI-06 list: a session belongs to a person, not to
-- an organisation. The app adds an address as the session opens and reads it;
-- it never changes one. The backup role reads it, as it reads everything.

CREATE TABLE identity.session_emails (
  session_id uuid PRIMARY KEY REFERENCES identity.sessions (id) ON DELETE CASCADE,
  email_ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(email_ciphertext) BETWEEN 29 AND 1024),
  email_key_version integer NOT NULL CHECK (email_key_version >= 1)
);

GRANT SELECT, INSERT ON identity.session_emails TO agentx_app;
GRANT SELECT ON identity.session_emails TO agentx_backup;
