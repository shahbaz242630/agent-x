#!/bin/bash
# The Agent X roles and database, set up the way an admin sets up a real server
# (Product-Documentation/Database.md): the roles from db/bootstrap, each role's
# password from this run's generated logins, then the database. The Postgres
# image runs this folder once, on an empty data directory, as the server admin.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres --file /agentx/bootstrap/roles.sql

# psql quotes the values (:'name'), so they never meet the SQL as text.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  --set owner_login="$AGENTX_LOCAL_DB_OWNER_PASSWORD" \
  --set app_login="$AGENTX_LOCAL_DB_APP_PASSWORD" \
  --set backup_login="$AGENTX_LOCAL_DB_BACKUP_PASSWORD" <<'SQL'
ALTER ROLE agentx_owner PASSWORD :'owner_login';
ALTER ROLE agentx_app PASSWORD :'app_login';
ALTER ROLE agentx_backup PASSWORD :'backup_login';
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres --set db=agentx \
  --file /agentx/bootstrap/database.sql
