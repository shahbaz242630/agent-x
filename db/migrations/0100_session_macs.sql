-- A MAC on every console session and step-up challenge (Phase 6 6F1 gate,
-- S205 tamper pass; ADR-012 §2, Threat-Model row 13).
--
-- Both tables are global: no row wall stands between them and the database's
-- owner, who holds none of the app's keys. A session was found by its cookie's
-- hash alone, so a row the owner planted, for a real admin and a cookie of its
-- own choosing, signed it in as that admin; a challenge the owner moved to
-- verified, with a passkey, was used by the app itself to sign an admin's
-- change. Now each row carries a MAC with the app's `session-mac` key over
-- what it says (identity/infrastructure/row-macs.ts) and that key's version.
-- The app believes only a row whose MAC holds; any other is no session or no
-- challenge, and raises the integrity alarm.
--
-- The rows already here have no MAC, and none can be made for them here: the
-- key isn't the database's. They are deleted (a challenge goes with its
-- session, as does its verified address), so everyone signs in again once
-- after this release. Then both columns are required: a session gets its MAC
-- as it opens, a challenge as it opens and again as it is verified.
--
-- The app may write the MAC where it may already write what it covers: a
-- session's at its new cookie ID (a step-up's rotation), a challenge's with
-- its evidence.

DELETE FROM identity.sessions;

ALTER TABLE identity.sessions
  ADD COLUMN mac bytea NOT NULL CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer NOT NULL CHECK (mac_key_version >= 1);

ALTER TABLE identity.step_up_challenges
  ADD COLUMN mac bytea NOT NULL CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer NOT NULL CHECK (mac_key_version >= 1);

GRANT UPDATE (mac, mac_key_version) ON identity.sessions TO agentx_app;
GRANT UPDATE (mac, mac_key_version) ON identity.step_up_challenges TO agentx_app;
