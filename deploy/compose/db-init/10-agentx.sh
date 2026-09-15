#!/bin/bash
# The Agent X roles and database, set up the way an admin sets up a real server
# (Product-Documentation/Database.md): the roles from db/bootstrap, each role's
# password from this run's generated logins, then the database. The Postgres
# image runs this folder once, on an empty data directory, as the server admin.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres --file /agentx/bootstrap/roles.sql

# psql reads each password straight from the environment (\getenv) and quotes
# it (:'name'), so it never meets the SQL as text and never appears in a
# command line that `ps` could show. The server would log a failing statement
# in full, password included, so statement logging is off for this session.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
SET log_min_error_statement = panic;
SET log_statement = 'none';
\getenv owner_login AGENTX_LOCAL_DB_OWNER_PASSWORD
\getenv app_login AGENTX_LOCAL_DB_APP_PASSWORD
\getenv backup_login AGENTX_LOCAL_DB_BACKUP_PASSWORD
ALTER ROLE agentx_owner PASSWORD :'owner_login';
ALTER ROLE agentx_app PASSWORD :'app_login';
ALTER ROLE agentx_backup PASSWORD :'backup_login';
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres --set db=agentx \
  --file /agentx/bootstrap/database.sql
