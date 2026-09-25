-- Invitations (ADR-003 §8-§9, ADR-005 §6, PRD §7.1 `POST /v1/members/invitations`;
-- B4-3): an admin asks for a person to join the organisation with a role,
-- signs in again for that one invitation, and is shown its link once. The
-- identity module owns them (ADR-004).
--
-- identity.invitations is the invitation: a tenant table, behind the tenant
-- policy, and an authority table (ADR-012 §2), since accepting one grants a
-- role. Its role, its status, the admin who asked for it (by their
-- membership) and when it ends must equal its latest signed event, so an
-- owner who raises an invitation's role, reopens one or moves its end is
-- caught at the next read. It is on the product's authority-table list
-- (packages/core/src/authority-tables.ts), which CI, the lint rules and the
-- live schema guard all read.
--
-- It starts as a DRAFT: the immutable pending change a step-up binds to
-- (ADR-003 §9 step 1), with the step-up challenge opened for it. Confirmed
-- with that challenge consumed, it moves to OPEN (DRAFT>OPEN) and its token is
-- listed in the directory, in the same transaction. B4-4 adds acceptance.
--
-- The invited person's email address is kept encrypted (ADR-011 §2), with the
-- organisation and the invitation as its associated data, so a value copied
-- to another row or organisation won't open. It is written once, with the
-- row, and never changed: the app may update only the signed fields and the
-- two signed-state columns (the signing step writes every signed field). The
-- step-up challenge's ID is signed with the rest, so an answer that repeats
-- the draft's can point the admin at their own challenge again; it grants
-- nothing, as the challenge is bound to the session and the change's hash.
--
-- The admin who asked is a membership of the same organisation (a composite
-- key, so it can't point at another organisation's).
--
-- directory.invites is the directory's lookup from a token to its
-- invitation (ADR-005 §6): the token's SHA-256 alone, never the token, with
-- the organisation and the invitation's ID, so accepting can find the
-- organisation before any is known. It grants nothing: the invitation is then
-- read and verified inside the organisation's own withTenant, and accepting
-- needs the invited email too. One token per invitation. On the CI-06 list
-- with exactly its columns (SEC-TEN-08). The app adds an entry and reads
-- them; it never changes or deletes one.
-- The backup role reads everything, as it must for a logical backup.

CREATE TABLE identity.invitations (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'approver', 'developer', 'viewer')),
  -- Held to the machine's states and moves by its status guard, below.
  status text NOT NULL,
  invited_by uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  email_ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(email_ciphertext) BETWEEN 29 AND 1024),
  email_key_version integer NOT NULL CHECK (email_key_version >= 1),
  step_up_challenge_id uuid NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT invitation_ends_after_it_begins CHECK (expires_at > created_at),
  CONSTRAINT asked_by_a_member FOREIGN KEY (org_id, invited_by) REFERENCES identity.memberships (org_id, id)
);

ALTER TABLE identity.invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity.invitations
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON identity.invitations
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('DRAFT', 'DRAFT>OPEN');

GRANT SELECT, INSERT ON identity.invitations TO agentx_app;
GRANT UPDATE (role, status, invited_by, expires_at, step_up_challenge_id, state_version, state_event_id) ON identity.invitations TO agentx_app;
GRANT SELECT ON identity.invitations TO agentx_backup;

CREATE TABLE directory.invites (
  token_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(token_hash) = 32),
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id),
  invitation_id uuid NOT NULL,
  CONSTRAINT one_token_per_invitation UNIQUE (org_id, invitation_id)
);

GRANT SELECT, INSERT ON directory.invites TO agentx_app;
GRANT SELECT ON directory.invites TO agentx_backup;
