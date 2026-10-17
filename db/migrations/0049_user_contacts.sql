-- A person's name and verified email address, kept so the audit log can always
-- say who did what (Phase 3 E10d, partner decision 25; ADR-009 §1a as
-- amended; ADR-011 §2). The login service stays their home and is asked first
-- when the log is read; this copy names the person when it can't answer, or no
-- longer has them (an account deleted). Kept even then, for as long as the log
-- must be kept (partner, S122): the app may not delete a row, and a formal
-- erasure request is handled by hand under the privacy policy (PL-42).
--
-- Refreshed at each sign-in, from what the login service vouched for then: the
-- name as the person's profile gives it, and an email address only when the
-- login service says it is verified. Either may be missing; a row holds at
-- least one. Each is encrypted (`field-encryption`) with the person's ID and
-- the field's name as its associated data, so a value copied to another row,
-- or from one field to the other, won't open.
--
-- It is for showing alone: never sealed into an event, never what an
-- invitation is matched against (that is a session's own address, 0017), and
-- never what grants or decides anything, so it is not an authority table.
--
-- A global table, on the CI-06 list: a person belongs to no one organisation,
-- and is shown by the same name in each of theirs. The app adds a row and
-- changes only its values and when they were last confirmed, never whose it
-- is. The backup role reads everything, as it must for a logical backup.

CREATE TABLE identity.user_contacts (
  user_id uuid PRIMARY KEY REFERENCES identity.users (id),
  name_ciphertext bytea CHECK (pg_catalog.octet_length(name_ciphertext) BETWEEN 29 AND 1024),
  name_key_version integer CHECK (name_key_version >= 1),
  email_ciphertext bytea CHECK (pg_catalog.octet_length(email_ciphertext) BETWEEN 29 AND 1024),
  email_key_version integer CHECK (email_key_version >= 1),
  updated_at timestamptz NOT NULL,
  CONSTRAINT name_with_its_key CHECK ((name_ciphertext IS NULL) = (name_key_version IS NULL)),
  CONSTRAINT email_with_its_key CHECK ((email_ciphertext IS NULL) = (email_key_version IS NULL)),
  CONSTRAINT holds_a_name_or_an_email CHECK (name_ciphertext IS NOT NULL OR email_ciphertext IS NOT NULL)
);

GRANT SELECT, INSERT ON identity.user_contacts TO agentx_app;
GRANT UPDATE (name_ciphertext, name_key_version, email_ciphertext, email_key_version, updated_at)
  ON identity.user_contacts TO agentx_app;
GRANT SELECT ON identity.user_contacts TO agentx_backup;
