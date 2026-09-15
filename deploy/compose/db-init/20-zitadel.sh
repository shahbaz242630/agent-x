#!/bin/bash
# The login service's own role and database on the same server (ADR-002: each
# with its own roles and no cross-access). Zitadel then creates its schemas
# itself, as the owner (`zitadel init zitadel` in compose.yaml), so it never
# needs the server admin. Nothing else may connect to its database, and it can't
# connect to Agent X's: db/bootstrap/database.sql took that right from PUBLIC.
set -euo pipefail

# psql reads the password from the environment (\getenv) and quotes it, so it
# never meets the SQL as text and never appears in a command line. The server
# would log a failing statement in full, so statement logging is off here.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
SET log_min_error_statement = panic;
SET log_statement = 'none';
\getenv login AGENTX_LOCAL_ZITADEL_DB_PASSWORD
CREATE ROLE zitadel
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
  PASSWORD :'login';
CREATE DATABASE zitadel OWNER zitadel;
REVOKE ALL ON DATABASE zitadel FROM PUBLIC;
SQL
