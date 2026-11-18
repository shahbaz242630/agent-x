// The oauth module (6E3a, ADR-016; MCP-Guide M5): Agent X's own OAuth 2.1
// authorization server's rules and records, for MCP connections. What it
// checks (PKCE, redirect addresses, scopes, a client's registration) and what
// it keeps before any organisation is known (the clients that registered
// themselves, the flows under way). A connection itself, and its tokens, are
// the agents module's: a connection is a key of an agent's.
export {
  checkRegistration,
  type ClientRegistration,
  GRANT_TYPES,
  MOST_REDIRECTS,
  type RegistrationAsked,
  type RegistrationChecked,
} from './infrastructure/client-metadata.ts';
export { hashOf, isCodeText, isFlowCookie, newCode, newFlowCookie } from './infrastructure/codes.ts';
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
  clientConnected,
  clientOf,
  MOST_REGISTRATIONS_A_DAY,
  type Registered,
  registerClient,
  sweepClients,
} from './infrastructure/clients.ts';
export {
  CODE_SECONDS,
  type CodeFlow,
  codeTaken,
  codeUsedBefore,
  FLOW_SECONDS,
  flowById,
  type FlowOpened,
  MOST_OPEN_FLOWS,
  MOST_OPEN_FLOWS_A_BROWSER,
  flowDecided,
  type FlowDecision,
  type FlowRead,
  openCodeFlow,
  sweepFlows,
} from './infrastructure/flows.ts';
export type { OauthTables } from './infrastructure/tables.ts';
