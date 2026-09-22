-- The organizations module's table (ADR-005 §1, PRD §3 `Organization`): one
-- row per organisation, its tenant boundary, holding what limits it. Today
-- that is its status: ACTIVE, or FROZEN, which stops every new hand-off
-- (PRD §5.3; the freeze and unfreeze routes are Phase 3's). A freeze is a
-- status on a row that always exists, never a row whose absence lifts it.
--
-- An authority table (ADR-012 §2): its status must equal the organisation's
-- latest signed event, so the row carries state_version and state_event_id
-- and is read for any decision through the audit module's verifiedState. It is
-- on the product's authority-table list (packages/core/src/authority-tables.ts),
-- which CI, the lint rules and the live schema guard all read.
--
-- A tenant table, behind the tenant policy. The row's id is its own org_id:
-- an organisation is its own tenant, so it has exactly one row. It points at
-- the organisation's directory entry, which it is created with in the same
-- transaction, so no organisation can exist that the directory's list leaves
-- out.
--
-- The status guard (0004) holds the organization machine
-- (packages/core/src/modules/organizations/domain/organization.ts), in its own
-- order: a new row starts ACTIVE, and the status moves only by freeze
-- (ACTIVE>FROZEN) and unfreeze (FROZEN>ACTIVE).
--
-- The app adds a row and reads it, and changes only the status and the two
-- signed-state columns; never the name, never a key, and never deletes (a row
-- deleted and inserted again would be born ACTIVE). The backup role reads
-- everything, as it must for a logical backup.

CREATE SCHEMA organizations;
GRANT USAGE ON SCHEMA organizations TO agentx_app, agentx_backup;

CREATE TABLE organizations.organizations (
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id),
  id uuid NOT NULL,
  name text NOT NULL CHECK (pg_catalog.char_length(name) BETWEEN 1 AND 200),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'FROZEN')),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_row_per_organization CHECK (id = org_id)
);

ALTER TABLE organizations.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations.organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations.organizations
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON organizations.organizations
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('ACTIVE', 'ACTIVE>FROZEN', 'FROZEN>ACTIVE');

GRANT SELECT, INSERT ON organizations.organizations TO agentx_app;
GRANT UPDATE (status, state_version, state_event_id) ON organizations.organizations TO agentx_app;
GRANT SELECT ON organizations.organizations TO agentx_backup;
