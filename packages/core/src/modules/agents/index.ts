// The agents module (ADR-004, ADR-011 §1): an organisation's AI agents and
// their keys (C1-1), both authority tables read through their signed states.
// A key's ID is listed in the directory, so a request carrying the key can be
// placed in its organisation before any is known. Registering an agent, with
// its first key, is composed with the step-up in the API (C1-2, ADR-004 §7).
// The key check (C1-4a) says whether a key an agent sends may act.
export {
  AGENT,
  AGENT_KEY,
  agentKeyText,
  AgentNameRefused,
  isAgentName,
  KEY_SECRET_BYTES,
  keyExpiresAt,
  keySecretMessage,
  MOST_AGENTS_ADDED_A_DAY,
  parseAgentKey,
  type PresentedKey,
  type Scope,
  SCOPES,
  ScopesRefused,
  scopesText,
} from './domain/agent.ts';
export {
  AGENT_KEYS,
  type AgentKeyRecord,
  agentKeysOf,
  addAgentKey,
  TooManyAgentKeys,
} from './infrastructure/agent-keys.ts';
export {
  addAgent,
  agentOf,
  AGENTS,
  agentsAddedSince,
  type AgentShown,
  agentsPage,
  agentsShown,
  type AgentsTransaction,
  MOST_AGENTS_A_PAGE,
  oneAgentAddAtATime,
} from './infrastructure/agents.ts';
export {
  type AcceptedKey,
  agentKeyAt,
  type AgentKeyChecker,
  createAgentKeyCheck,
  type KeyAtCheck,
  type KeyChecked,
  type KeyRefusal,
} from './infrastructure/key-check.ts';
export type { AgentsTables } from './infrastructure/tables.ts';
