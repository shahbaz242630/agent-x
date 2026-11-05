import type { Generated } from 'kysely';

/** The directory schema's tables (db/migrations/0007_directory.sql, 0015_memberships.sql, 0016_invitations.sql, 0027_agents.sql, 0072_org_work.sql, 0073_expiry_marks.sql, 0075_void_marks.sql, 0077_reset_download_hold_marks.sql), as Kysely sees them. */
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

/** The work the marks follow so far: 0077's CHECK on `job`, held to it by org-work.db.test.ts. */
export const ORG_WORK_JOBS = [
  'hand_off',
  'hand_off_sweep',
  'payment_check',
  'request_expiry',
  'mandate_expiry',
  'request_voids',
  'waiting_rejections',
  'carry_rest',
  'factor_removals',
  'background_downloads',
  'hold_history',
] as const;

export type OrgWorkJob = (typeof ORG_WORK_JOBS)[number];

interface OrgWorkTable {
  org_id: string;
  job: OrgWorkJob;
  due_at: Date;
  marks: Generated<string>;
}
