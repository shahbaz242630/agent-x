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
  isLiveKey,
  KEY_DAYS,
  KEY_PREFIX,
  KEY_SECRET_BYTES,
  keyExpiresAt,
  keySecretMessage,
  MOST_AGENTS_ADDED_A_DAY,
  MOST_KEYS_ISSUED_A_DAY,
  MOST_LIVE_KEYS,
  parseAgentKey,
  type PresentedKey,
  type Scope,
  SCOPES,
  rotatedKeyExpiresAt,
  ScopesRefused,
  scopesOf,
  scopesText,
} from './domain/agent.ts';
export {
  AGENT_KEYS,
  type AgentKeyCheck,
  agentKeyOf,
  type AgentKeyRecord,
  agentKeysOf,
  addAgentKey,
  type IssuedAgentKey,
  bringKeyExpiryForward,
  keysIssuedSince,
  keysOnceIssued,
  MOST_KEYS_LISTED,
  oneKeyIssueAtATime,
  revokeKey,
  roomForAKey,
  TooManyAgentKeys,
} from './infrastructure/agent-keys.ts';
export {
  addAgent,
  agentOf,
  AGENTS,
  agentsAddedSince,
  agentsNamed,
  type AgentRecord,
  type AgentShown,
  agentsPage,
  agentsShown,
  type AgentsTransaction,
  handAgentOver,
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
// MCP connections by OAuth (6E3a, ADR-016): a key whose secret was thrown away, its connection, and its tokens.
export {
  ACCESS_TOKEN_SECONDS,
  type ConnectionTokenKind,
  MOST_CONNECTIONS_MADE_A_DAY,
  MOST_LIVE_CONNECTIONS,
  parseConnectionToken,
  type PresentedToken,
  REFRESH_IDLE_DAYS,
} from './domain/connection.ts';
export {
  CLOSED_HEAD,
  CONNECTION_HEADS,
  type HeadCheck,
  headClosed,
  headMoved,
  headOf,
} from './infrastructure/connection-heads.ts';
export {
  addConnection,
  agentsOfLiveConnectionsMadeBy,
  type ConnectionListed,
  connectionOf,
  type ConnectionRecord,
  CONNECTIONS,
  connectionsCounted,
  connectionsListed,
  connectionsMadeSince,
  type ConnectionVia,
  ENDED_CONNECTIONS_SHOWN_DAYS,
  isConnectionKey,
  liveConnectionsMadeBy,
  MOST_CONNECTIONS_LISTED,
} from './infrastructure/connections.ts';
export {
  type IssuedTokens,
  issueTokens,
  tokenGenuine,
  type TokenProof,
  tokenProven,
  type TokenRow,
  sweepConnectionTokens,
  tokenRowLocked,
  usedNow,
} from './infrastructure/connection-tokens.ts';
export {
  type ConnectionTokenChecker,
  createConnectionTokenCheck,
  tokenAtTheDoor,
} from './infrastructure/connection-check.ts';
export { credentialAt, pepperHeld } from './infrastructure/key-check.ts';
