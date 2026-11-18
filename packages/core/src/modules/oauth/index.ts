// The oauth module (6E3a, ADR-016; MCP-Guide M5): Agent X's own OAuth 2.1
// authorization server's rules and records, for MCP connections. What it
// checks (PKCE, redirect addresses, scopes, a client's registration) and what
// it keeps before any organisation is known (the clients that registered
// themselves, the flows under way). A connection itself, and its tokens, are
// the agents module's: a connection is a key of an agent's.
export {
  checkRegistration,
  type ClientRegistration,
  DEVICE_CODE_GRANT,
  GRANT_TYPES,
  type GrantType,
  MOST_REDIRECTS,
  type RegistrationAsked,
  type RegistrationChecked,
} from './infrastructure/client-metadata.ts';
export {
  hashOf,
  isCodeText,
  isDeviceCodeText,
  isFlowCookie,
  newCode,
  newDeviceCode,
  newFlowCookie,
  newUserCode,
  userCodeOf,
} from './infrastructure/codes.ts';
export {
  checkClientMetadataDocument,
  type ClientMetadataDocument,
  type DocumentChecked,
  isTrustedMetadataClientId,
} from './infrastructure/client-metadata-document.ts';
export {
  CLIENT_METADATA_KEPT_MS,
  CLIENT_METADATA_STALE_MS,
  keepClientMetadata,
  type KeptDocument,
  keptClientMetadata,
  retireClientMetadata,
  sweepClientMetadata,
} from './infrastructure/client-metadata-cache.ts';
export { challengeOf, isCodeChallenge, PKCE_METHOD, pkceMatches } from './infrastructure/pkce.ts';
export { isLoopback, isRegisteredRedirect, redirectMatches, redirectProblems } from './domain/redirects.ts';
export {
  OFFLINE_ACCESS,
  scopeParameter,
  scopesAsked,
  scopesNarrowed,
  SCOPES_SUPPORTED,
} from './infrastructure/scopes.ts';
export {
  type Client,
  CLIENT_KEPT_DAYS,
  clientOf,
  clientSeen,
  MOST_REGISTRATIONS_A_DAY,
  MOST_REGISTRATIONS_A_NETWORK_A_DAY,
  type Registered,
  registerClient,
  sweepClients,
} from './infrastructure/clients.ts';
export {
  type AnyFlowRead,
  CODE_SECONDS,
  type CodeFlow,
  codeHeld,
  codeUsed,
  deviceClaimed,
  type DeviceFlow,
  type DeviceFlowOpened,
  deviceFlowOfCode,
  type DeviceFlowRead,
  deviceHeld,
  devicePolled,
  openDeviceFlow,
  flowOfCode,
  FLOW_SECONDS,
  flowById,
  type FlowOpened,
  MOST_OPEN_FLOWS,
  MOST_OPEN_FLOWS_A_BROWSER,
  MOST_OPEN_FLOWS_A_SOURCE,
  flowDecided,
  type FlowDecision,
  type FlowRead,
  openCodeFlow,
  sweepFlows,
} from './infrastructure/flows.ts';
export type { OauthTables } from './infrastructure/tables.ts';
