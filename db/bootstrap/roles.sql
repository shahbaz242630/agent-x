-- The three database roles (ADR-005 §3). Run once per Postgres server, by the
-- server admin, before anything else:
--
--   psql -v ON_ERROR_STOP=1 -f db/bootstrap/roles.sql
--
-- The roles get no passwords here, so this file never handles a secret. The
-- admin sets each one separately, from the secret store.
--
-- None of them is a member of another role, and none can create roles or
-- databases. Only agentx_backup can bypass row-level security: a logical
-- backup must see every organisation. The app never logs in as it, and it
-- refuses to start as any role that could bypass the tenant walls
-- (assertRuntimeRole in @agentx/platform/db).

-- Owns the database and the tables, and runs the migrations. Never used by the
-- running app. It keeps INHERIT: Postgres gives a database's owner the rights
-- over the `public` schema through a built-in role (pg_database_owner), and
-- without INHERIT the baseline migration couldn't take them back from PUBLIC.
CREATE ROLE agentx_owner
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;

-- The API and the worker. Gets only the table rights each module's migration grants.
CREATE ROLE agentx_app
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

-- The backup job only. It will be granted read access to every table, and nothing else.
CREATE ROLE agentx_backup
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
