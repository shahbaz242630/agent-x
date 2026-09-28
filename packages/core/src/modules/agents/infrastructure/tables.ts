import type { Generated } from 'kysely';

/** The agents schema's tables (db/migrations/0027_agents.sql), as Kysely sees them. */
export interface AgentsTables {
  'agents.agents': AgentsTable;
  'agents.agent_keys': AgentKeysTable;
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
