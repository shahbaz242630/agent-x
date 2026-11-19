import type { Generated } from 'kysely';

/** The agents schema's tables (db/migrations/0027_agents.sql), as Kysely sees them. */
export interface AgentsTables {
  'agents.agents': AgentsTable;
  'agents.agent_keys': AgentKeysTable;
  'agents.connections': ConnectionsTable;
  'agents.connection_tokens': ConnectionTokensTable;
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
  /** How its MAC was taken (0102): 1 before, 2 its parent covered. */
  mac_version: Generated<number>;
}
