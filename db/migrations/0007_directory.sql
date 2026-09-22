-- The directory module's first table (ADR-005 §6): which organisations exist.
-- Work that runs across organisations (the anchor check of every chain, the
-- retention sweeps) reads this list and then works on one organisation at a
-- time, each inside its own withTenant, so no query ever reads across tenants.
--
-- A global table, with no row-level security and no org_id wall, on the
-- CI-06 list with exactly its columns: it holds IDs only, never a name, a
-- secret or anything personal (SEC-TEN-08). An organisation's own row, with
-- its status, lives in the organizations module's tenant table, which points
-- here (0008).
--
-- The app adds an organisation and reads the list; it never changes or
-- deletes one: an organisation missing from the list would be one no sweep
-- or anchor check reaches. The lifecycle (active, closed) joins when closing
-- an organisation does. The backup role reads everything, as it must for a
-- logical backup.

CREATE SCHEMA directory;
GRANT USAGE ON SCHEMA directory TO agentx_app, agentx_backup;

CREATE TABLE directory.orgs (
  org_id uuid PRIMARY KEY
);

GRANT SELECT, INSERT ON directory.orgs TO agentx_app;
GRANT SELECT ON directory.orgs TO agentx_backup;
