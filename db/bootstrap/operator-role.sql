-- The operator's command's own role (ADR-005 §3; PL-57, partner decision 37d).
-- Run once per Postgres server, by the server admin, after roles.sql: the
-- set-up job (apps/db-setup) runs both. A file of its own, so a server made
-- before it gets the role without roles.sql's three being made again.
--
-- No password here, so this file never handles a secret: the set-up job gives
-- the role its login from the secret store. It gets only the table rights the
-- operator's commands need, from the migrations (0079), under the same forced
-- row security as the app: no BYPASSRLS, never a member of another role.
CREATE ROLE agentx_operator
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
