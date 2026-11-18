/** The oauth schema's tables (db/migrations/0093_connections.sql, 0094), as Kysely sees them. */
export interface OauthTables {
  'oauth.clients': ClientsTable;
  'oauth.flows': FlowsTable;
}

interface ClientsTable {
  client_id: string;
  name: string;
  redirect_uris: string[];
  application_type: string;
  grant_types: string[];
  software_id: string | null;
  software_version: string | null;
  created_at: Date;
  first_connected_at: Date | null;
  last_connected_at: Date | null;
}

interface FlowsTable {
  id: string;
  kind: string;
  client_id: string;
  redirect_uri: string | null;
  state: string | null;
  code_challenge: string | null;
  scopes_asked: string;
  resource: string;
  browser_hash: string | null;
  device_hash: string | null;
  user_code_hash: string | null;
  interval_s: number | null;
  created_at: Date;
  ends_at: Date;
  decided_at: Date | null;
  outcome: string | null;
  org_id: string | null;
  key_id: string | null;
  code_hash: string | null;
  code_ends_at: Date | null;
  used_at: Date | null;
  polled_at: Date | null;
}
