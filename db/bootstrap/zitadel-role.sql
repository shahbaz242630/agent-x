-- The login service's own role (ADR-002: each database with its own roles and
-- no cross-access; ADR-003). Run once per Postgres server, by the server
-- admin, like roles.sql, which it follows: the set-up job (apps/db-setup)
-- runs both.
--
-- No password here, so this file never handles a secret: the set-up job gives
-- the role its login from the secret store. It owns only its own database
-- (zitadel-database.sql), where Zitadel creates its schemas itself
-- (`zitadel init zitadel`), so Zitadel never needs the server admin.

CREATE ROLE zitadel
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
