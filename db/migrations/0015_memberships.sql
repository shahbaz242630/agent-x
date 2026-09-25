-- Memberships (ADR-003, ADR-005 §6, PRD §3 `User` / `Membership`; B4-1): who
-- belongs to which organisation, with which role. The identity module owns
-- them (ADR-004).
--
-- directory.members is the directory's lookup from a person to the
-- organisations they belong to, and to their membership in each: IDs only,
-- in a global table, so a signed-in person's organisations can be found
-- before any one is known (ADR-005 §6: "showing a user their
-- organisations"). It is never what grants anything: the membership it names,
-- with its role and status, is read inside the organisation's own withTenant,
-- verified against its signed state, which must name the same person. So the
-- membership is found by its key, never by reading the authority table for
-- a person, and an entry pointed at someone else's membership, with no
-- membership behind it, or with one deactivated, finds nothing. On the CI-06 list with exactly its
-- columns (SEC-TEN-08). The app adds an entry and reads them; it never
-- changes or deletes one, so an entry stays after its membership is
-- deactivated, as the membership row does.
--
-- identity.memberships is the membership: a tenant table, behind the tenant
-- policy, and an authority table (ADR-012 §2): whose it is, its role, its
-- status and when it began must equal the membership's latest signed event,
-- so an owner who moves an admin's row to another person, raises a role,
-- reactivates a member or makes a membership look older than it is (the
-- two-person rule's "established" verifier, ADR-012 §1) is caught at the next
-- read. It is on the product's authority-table list
-- (packages/core/src/authority-tables.ts), which CI, the lint rules and the
-- live schema guard all read.
--
-- One membership per person in an organisation. It points at its directory
-- entry, made in the same transaction, by person, organisation and its own
-- ID, so a membership can't exist that the person's list of organisations
-- leaves out or names by another ID; and at the person.
--
-- The roles are the organisation's four (PRD §7.1, access.ts): admin,
-- approver (the finance approver), developer, viewer. A person invited as an
-- admin or approver waits for an existing admin's confirmation on the
-- invitation, before any membership exists (ADR-005 §6; B4-4), so a
-- membership starts ACTIVE, and moves only by deactivate (ACTIVE>DEACTIVATED).
--
-- The app adds a row and reads it, and changes only its authority fields and
-- the two signed-state columns, which the audit module's record writes and
-- seals together (a new row's included, so whose it is and when it began are
-- among them); never its key, and never deletes (a row deleted and inserted
-- again would be born ACTIVE). The module never moves a membership to
-- another person or changes when it began; a write past record is unsigned,
-- and denied at the next read.
-- The backup role reads everything, as it must for a logical backup.

CREATE TABLE directory.members (
  user_id uuid NOT NULL REFERENCES identity.users (id),
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id),
  membership_id uuid NOT NULL,
  PRIMARY KEY (user_id, org_id),
  CONSTRAINT names_one_membership UNIQUE (user_id, org_id, membership_id)
);

GRANT SELECT, INSERT ON directory.members TO agentx_app;
GRANT SELECT ON directory.members TO agentx_backup;

CREATE TABLE identity.memberships (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES identity.users (id),
  role text NOT NULL CHECK (role IN ('admin', 'approver', 'developer', 'viewer')),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'DEACTIVATED')),
  joined_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_membership_per_person UNIQUE (org_id, user_id),
  CONSTRAINT listed_in_the_directory FOREIGN KEY (user_id, org_id, id)
    REFERENCES directory.members (user_id, org_id, membership_id)
);

ALTER TABLE identity.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity.memberships
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON identity.memberships
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('ACTIVE', 'ACTIVE>DEACTIVATED');

GRANT SELECT, INSERT ON identity.memberships TO agentx_app;
GRANT UPDATE (user_id, role, status, joined_at, state_version, state_event_id) ON identity.memberships TO agentx_app;
GRANT SELECT ON identity.memberships TO agentx_backup;
