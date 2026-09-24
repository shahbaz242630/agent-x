// The identity module (ADR-003, ADR-004): the people who sign in and their
// console sessions, in two global tables (0010). The OIDC client that checks
// a sign-in (B2-2), and the routes that open and use a session (B2-3, B2-4),
// build on these. Memberships and roles join at B4, step-up challenges at B3.
export { type SignInEvidence, SignInRefused, type Subject } from './domain/sign-in.ts';
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
export type { IdentityTables } from './infrastructure/tables.ts';
export { userForSubject } from './infrastructure/users.ts';
