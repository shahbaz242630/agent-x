import type { Generated } from 'kysely';

/** The agents schema's tables (db/migrations/0027_agents.sql, 0093, 0102), as Kysely sees them. */
export interface AgentsTables {
  'agents.agents': AgentsTable;
  'agents.agent_keys': AgentKeysTable;
  'agents.connections': ConnectionsTable;
  'agents.connection_tokens': ConnectionTokensTable;
  'agents.connection_heads': ConnectionHeadsTable;
}

/** A connection's refresh head (0102): the refresh token that may be used now, its signed state's. */
interface ConnectionHeadsTable {
  org_id: string;
  /** Its connection's (its key's) ID. */
  id: string;
  refresh_id: string;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface AgentsTable {
  org_id: string;
  id: string;
  name: string;
  owner: string;
  status: string;
  scopes: string;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

interface AgentKeysTable {
  org_id: string;
  /** The key's ID, the one in the key an agent sends. */
  id: string;
  agent_id: string;
  status: string;
  scopes: string;
  /** HMAC-SHA-256 of the key's secret with the agent-key pepper, in lower-case hex. */
  secret_mac: string;
  secret_key_version: number;
  expires_at: Date;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

/** An MCP connection (0093): its ID is its key's. */
interface ConnectionsTable {
  org_id: string;
  id: string;
  agent_id: string;
  client_id: string;
  resource: string;
  redirect_uri: string | null;
  client_name: string;
  via: string;
  made_by: string;
  created_at: Date;
  /** These two are written by the signed state's steps alone (the audit module's record). */
  state_version: Generated<number>;
  state_event_id: Generated<string | null>;
}

/** A connection's access or refresh token (0093): its secret's MAC alone. */
interface ConnectionTokensTable {
  org_id: string;
  id: string;
  key_id: string;
  kind: string;
  scopes: string;
  secret_mac: string;
  secret_key_version: number;
  expires_at: Date;
  created_at: Date;
  parent_id: string | null;
  used_at: Date | null;
}
