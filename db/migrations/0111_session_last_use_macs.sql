-- A console session's last use sealed by a key the database never holds
-- (S207 GM-4; Threat-Model R-15, ADR-012 §2).
--
-- A session lives while its idle timeout holds, from its last use
-- (last_seen_at), which 0100's MAC leaves out: it moves on every request. So
-- the database's owner, holding a cookie stolen while its session was live,
-- could move that session's last use forward after it went idle and sign in
-- with it again, up to its absolute end.
--
-- Now each session keeps a second MAC with the app's `session-mac` key, over
-- its cookie's hash and its last use (identity/infrastructure/row-macs.ts),
-- and that key's version. The request that uses a session writes both with
-- the new last use, in the statement that already writes it, and checks the
-- pair it replaced: one the app didn't write ends the session and raises the
-- integrity alarm. A step-up's new cookie ID writes it again with the new hash.
--
-- The sessions already here have none, and none can be made here: the key
-- isn't the database's. Such a session is ended at its next use, so everyone
-- signs in again once after this release. Nullable, not deleted and required
-- as 0100 did: the release before this one goes on opening sessions while
-- this one rolls out, and those are ended the same way.

ALTER TABLE identity.sessions
  ADD COLUMN last_use_mac bytea CHECK (pg_catalog.octet_length(last_use_mac) = 32),
  ADD COLUMN last_use_mac_key_version integer CHECK (last_use_mac_key_version >= 1),
  ADD CONSTRAINT last_use_mac_with_its_version CHECK ((last_use_mac IS NULL) = (last_use_mac_key_version IS NULL));

-- Written only with the last use (a request's use, a step-up's new cookie ID: sessions.ts).
GRANT UPDATE (last_use_mac, last_use_mac_key_version) ON identity.sessions TO agentx_app;
