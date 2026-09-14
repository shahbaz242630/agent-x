-- Baseline privileges, before any module creates a table (ADR-005). Runs as
-- agentx_owner, like every migration.
--
-- Each module gets its own schema and grants only the rights its code needs.
-- Postgres gives some rights to every role (PUBLIC) by default, and they would
-- reach the app too, so they are taken back here:
-- - USAGE on the public schema. No module uses it.
-- - EXECUTE on functions the owner creates from now on. A module grants EXECUTE
--   on a function explicitly, when its code needs it.

REVOKE ALL ON SCHEMA public FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE agentx_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
