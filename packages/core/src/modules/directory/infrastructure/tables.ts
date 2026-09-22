/** The directory schema's tables (db/migrations/0007_directory.sql), as Kysely sees them. */
export interface DirectoryTables {
  'directory.orgs': OrgsTable;
}

interface OrgsTable {
  org_id: string;
}
