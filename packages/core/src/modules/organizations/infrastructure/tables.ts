import type { Generated } from 'kysely';

/** The organizations schema's table (db/migrations/0008_organizations.sql), as Kysely sees it. */
export interface OrganizationsTables {
  'organizations.organizations': OrganizationsTable;
}

interface OrganizationsTable {
  org_id: string;
  /** The organisation's own ID, always its org_id. */
  id: string;
  name: string;
  status: string;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}
