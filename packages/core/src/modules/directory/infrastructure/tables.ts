import type { Generated } from 'kysely';

/** The directory schema's tables (db/migrations/0007_directory.sql, 0015_memberships.sql, 0016_invitations.sql, 0027_agents.sql, 0072_org_work.sql, 0073_expiry_marks.sql), as Kysely sees them. */
export interface DirectoryTables {
  'directory.orgs': OrgsTable;
  'directory.members': MembersTable;
  'directory.invites': InvitesTable;
  'directory.agent_keys': AgentKeysTable;
  'directory.org_work': OrgWorkTable;
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

/** The work the marks follow so far. */
export type OrgWorkJob = 'hand_off' | 'hand_off_sweep' | 'payment_check' | 'request_expiry' | 'mandate_expiry';

interface OrgWorkTable {
  org_id: string;
  job: OrgWorkJob;
  due_at: Date;
  marks: Generated<string>;
}
