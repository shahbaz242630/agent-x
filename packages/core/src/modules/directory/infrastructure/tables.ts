/** The directory schema's tables (db/migrations/0007_directory.sql, 0015_memberships.sql, 0016_invitations.sql, 0027_agents.sql), as Kysely sees them. */
export interface DirectoryTables {
  'directory.orgs': OrgsTable;
  'directory.members': MembersTable;
  'directory.invites': InvitesTable;
  'directory.agent_keys': AgentKeysTable;
}

interface OrgsTable {
  org_id: string;
}

interface MembersTable {
  user_id: string;
  org_id: string;
  membership_id: string;
}

interface InvitesTable {
  token_hash: Buffer;
  org_id: string;
  invitation_id: string;
}

interface AgentKeysTable {
  key_id: string;
  org_id: string;
}
