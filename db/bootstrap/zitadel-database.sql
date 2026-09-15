-- The login service's database, owned by its role (zitadel-role.sql). Run
-- once per server by the server admin, after the role exists.
--
-- Nothing else may connect to it: the right every role has to connect to a
-- new database is taken back from PUBLIC. The app's database takes the same
-- right back (database.sql), so neither side can reach the other's.

CREATE DATABASE zitadel OWNER zitadel;

REVOKE ALL ON DATABASE zitadel FROM PUBLIC;
