-- The app's database (ADR-002: one per environment). Run once, by the server
-- admin, after roles.sql, naming the database:
--
--   psql -v ON_ERROR_STOP=1 -v db=agentx -f db/bootstrap/database.sql
--
-- agentx_owner owns it, so the migrations (run as agentx_owner) can create the
-- module schemas. By default every role may connect to a new database and
-- create temporary tables in it; both are taken back from PUBLIC, and only the
-- app and backup roles may connect.

CREATE DATABASE :"db" OWNER agentx_owner;

REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO agentx_app, agentx_backup;
