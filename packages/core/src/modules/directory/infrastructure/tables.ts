/** The directory schema's tables (db/migrations/0007_directory.sql, 0015_memberships.sql), as Kysely sees them. */
export interface DirectoryTables {
  'directory.orgs': OrgsTable;
  'directory.members': MembersTable;
}

interface OrgsTable {
  org_id: string;
}

interface MembersTable {
  user_id: string;
  org_id: string;
  membership_id: string;
}
