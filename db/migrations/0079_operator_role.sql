-- PL-57 (Phase 4 gate, partner decision 37d): the operator's command connects as
-- its own role, agentx_operator (db/bootstrap/operator-role.sql), not the app's,
-- and holds a signing key of its own. So "operator only" is the database's rule
-- as well as the code's: the API's role loses the one write only the operator's
-- commands make, and the operator's role holds exactly what its commands do,
-- under the same forced row security as the API's (no BYPASSRLS, no SECURITY
-- DEFINER). The schema guard and CI-06 hold it to the same list
-- (OPERATOR_RIGHTS in schema-policy.ts), every right on its own.
--
-- What each command needs:
-- - create-organization: the directory's list and the new organisation's row,
--   its own audit chain started (with its hold, CLEAR) and the platform chain's
--   event; the hold history marked due (org_work, 4D2e D10).
-- - invite-first-admin: the invitation and its token, the organisation's
--   members read, both chains.
-- - audit-export, activity-export: the organisation's audit log and activity
--   log read, the names they show read, a record on both chains, every admin
--   told (the outbox).
-- - handoff-pause, handoff-resume: the pause's row moved, the platform chain's
--   event, every admin of every organisation told.
-- - restore-check: reads only, on the drill's copy and the live server.
--
-- The hand-off pause's row moves for the operator alone from here: the API
-- reads it, never moves it, so a foothold in the API can't resume hand-offs.
--
-- platform_controls.operator_signatures: the operator's signature on each of
-- its events on the platform chain, by its own Ed25519 key (`operator-signing`,
-- held by the operator's job alone; the API holds only its public half). The
-- API's role may read the table, never add to it, and no role may change or
-- delete a row. A global table, of no organisation, as the platform chain is.
--
-- platform_controls.operator_signing: where signing starts, written here, by
-- the owner, once: the platform chain's next place as this migration runs.
-- Every operator's event from it on is believed only with a signature that
-- checks against the operator's key; one before it was recorded before PL-57,
-- as all were, and needs none. No running role may write it, so a foothold in
-- the API can't move the start, nor slip an unsigned event in before the first
-- signed run. A read that finds no row believes no unsigned operator's event.

GRANT USAGE ON SCHEMA access, audit, directory, identity, notifications, organizations, platform_controls TO agentx_operator;

-- Both audit chains: events added and read, each head moved in its four columns.
GRANT SELECT, INSERT ON audit.events TO agentx_operator;
GRANT SELECT, INSERT ON audit.heads TO agentx_operator;
GRANT UPDATE (seq, hash, mac, mac_key_version) ON audit.heads TO agentx_operator;
GRANT SELECT, INSERT ON platform_controls.audit_events TO agentx_operator;
GRANT SELECT, INSERT ON platform_controls.audit_head TO agentx_operator;
GRANT UPDATE (seq, hash, mac, mac_key_version) ON platform_controls.audit_head TO agentx_operator;

-- The hand-off pause: the operator's alone to move. A hand-off still locks the
-- row FOR SHARE (ADR-006 §6 level 1), which Postgres allows only to a role that
-- may UPDATE some column of it: the API's role keeps UPDATE on only_row alone,
-- which its CHECK and key hold true, so the lock is all it can do with it.
GRANT SELECT ON platform_controls.handoff_pause TO agentx_operator;
GRANT UPDATE (paused, event_seq, event_id) ON platform_controls.handoff_pause TO agentx_operator;
REVOKE UPDATE (paused, event_seq, event_id) ON platform_controls.handoff_pause FROM agentx_app;
GRANT UPDATE (only_row) ON platform_controls.handoff_pause TO agentx_app;

-- An organisation made: listed, its row, its hold history due. A signed row is
-- added, then moved to its first status with its signed event, as the API's
-- record writes do: the same columns the app may move, and no other.
GRANT SELECT, INSERT ON directory.orgs TO agentx_operator;
GRANT SELECT, INSERT ON organizations.organizations TO agentx_operator;
GRANT UPDATE (status, state_version, state_event_id) ON organizations.organizations TO agentx_operator;
GRANT SELECT, INSERT ON directory.org_work TO agentx_operator;
-- A mark already there is counted on (directory.mark_org_work's ON CONFLICT).
GRANT UPDATE (due_at, marks) ON directory.org_work TO agentx_operator;

-- A first admin invited: the invitation added and moved to its first state with
-- its signed event, as the organisation's row is.
GRANT SELECT ON directory.members TO agentx_operator;
GRANT INSERT ON directory.invites TO agentx_operator;
GRANT SELECT, INSERT ON identity.invitations TO agentx_operator;
GRANT UPDATE (role, status, invited_by, expires_at, step_up_challenge_id, accepted_by, state_version, state_event_id)
  ON identity.invitations TO agentx_operator;

-- An export: the organisation's activity log read, and each person it names by
-- the copy Agent X keeps (decision 27).
GRANT SELECT ON access.requests TO agentx_operator;
GRANT SELECT ON identity.users TO agentx_operator;
GRANT SELECT ON identity.user_contacts TO agentx_operator;

-- A tamper sign found by a command's read holds the organisation, as the API's
-- reads do (4D2e D5): the hold waiting listed, then taken off once recorded.
GRANT SELECT, INSERT, DELETE ON directory.holds_waiting TO agentx_operator;

-- Every admin told.
GRANT INSERT ON notifications.outbox TO agentx_operator;

CREATE TABLE platform_controls.operator_signatures (
  seq bigint NOT NULL PRIMARY KEY CHECK (seq >= 1),
  id uuid NOT NULL UNIQUE,
  signature bytea NOT NULL CHECK (pg_catalog.octet_length(signature) = 64),
  key_version integer NOT NULL CHECK (key_version >= 1)
);

GRANT SELECT, INSERT ON platform_controls.operator_signatures TO agentx_operator;
GRANT SELECT ON platform_controls.operator_signatures TO agentx_app;
GRANT SELECT ON platform_controls.operator_signatures TO agentx_backup;

CREATE TABLE platform_controls.operator_signing (
  only_row boolean NOT NULL PRIMARY KEY DEFAULT true CHECK (only_row),
  signed_from bigint NOT NULL CHECK (signed_from >= 1)
);

INSERT INTO platform_controls.operator_signing (signed_from)
SELECT COALESCE((SELECT h.seq FROM platform_controls.audit_head h), 0) + 1;

GRANT SELECT ON platform_controls.operator_signing TO agentx_app, agentx_operator, agentx_backup;

-- The same on every organisation's chain: the operator's events there (its
-- creation, its first admin's invitation, an export's record) are signed as on
-- the platform chain, the signature in audit.operator_signatures, behind the
-- tenant wall, which only the operator's role adds to. Where signing starts is
-- per chain, as each chain counts its own places (a place, not a time: an event's
-- place is fixed by the head it was sealed on, its time is the writer's clock):
-- written here, by the owner, for every chain there is (its next place), into
-- audit.operator_signing_starts, which no running role may write. A chain started after this has no row, and
-- its start is its first place: every operator's event on it is signed.
CREATE TABLE audit.operator_signatures (
  org_id uuid NOT NULL,
  seq bigint NOT NULL CHECK (seq >= 1),
  signature bytea NOT NULL CHECK (pg_catalog.octet_length(signature) = 64),
  key_version integer NOT NULL CHECK (key_version >= 1),
  PRIMARY KEY (org_id, seq)
);

ALTER TABLE audit.operator_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.operator_signatures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.operator_signatures
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON audit.operator_signatures TO agentx_operator;
GRANT SELECT ON audit.operator_signatures TO agentx_app, agentx_backup;

CREATE TABLE audit.operator_signing_starts (
  org_id uuid NOT NULL PRIMARY KEY,
  signed_from bigint NOT NULL CHECK (signed_from >= 1)
);

-- Filled before its own wall goes up, and from every chain's head: the wall
-- binds the owner too (FORCE), so it stands aside for this one read, in this
-- transaction, as 0054 did.
SET LOCAL lock_timeout = '5s';
ALTER TABLE audit.heads NO FORCE ROW LEVEL SECURITY;
INSERT INTO audit.operator_signing_starts (org_id, signed_from)
SELECT h.org_id, h.seq + 1 FROM audit.heads h;
ALTER TABLE audit.heads FORCE ROW LEVEL SECURITY;

ALTER TABLE audit.operator_signing_starts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.operator_signing_starts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.operator_signing_starts
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT ON audit.operator_signing_starts TO agentx_app, agentx_operator, agentx_backup;
