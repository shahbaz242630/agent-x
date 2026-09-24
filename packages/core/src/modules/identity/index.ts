// The identity module (ADR-003, ADR-004): the people who sign in, their
// console sessions and the sign-in flows under way, in global tables (0010,
// 0011); the OIDC client that checks a sign-in (B2-2); and the sign-in from
// end to end (B2-3a). The routes come at B2-3a-2, memberships and roles at
// B4, step-up challenges at B3.
export { HOME_PATH, isReturnPath, type SignInEvidence, SignInRefused, type Subject } from './domain/sign-in.ts';
export { createLoginFlows, LOGIN_FLOW_SECONDS, type LoginFlows } from './infrastructure/login-flows.ts';
export {
  createSessions,
  type LiveSession,
  type OpenedSession,
  type Sessions,
  type SessionTimeouts,
} from './infrastructure/sessions.ts';
export {
  createOidcClient,
  type LoginFlow,
  type OidcClient,
  type OidcClientSettings,
  SignInFailed,
  type SignInFailure,
  type SignInStart,
  type VerifiedSignIn,
} from './infrastructure/oidc-client.ts';
export {
  type CallbackInput,
  createSignIn,
  type SignIn,
  type SignInBegun,
  type SignInCompleted,
} from './infrastructure/sign-in-flow.ts';
export type { IdentityTables } from './infrastructure/tables.ts';
export { userForSubject } from './infrastructure/users.ts';
