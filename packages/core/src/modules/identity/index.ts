// The identity module (ADR-003, ADR-004): the people who sign in, their
// console sessions and the sign-in flows under way, in global tables (0010,
// 0011); the OIDC client that checks a sign-in (B2-2); and the sign-in from
// end to end (B2-3a). The routes come at B2-3a-2. Step-up challenges (B3-1),
// bound to one pending change in a session. Memberships and roles (B4-1): a
// person in an organisation, an authority table read through its signed state.
// Invitations (B4-3a): the pending change an admin's step-up binds to, then
// opened with a token shown once.
export {
  CONFIRMED_ROLES,
  EMAIL_MAX,
  INVITATION,
  INVITATION_HOURS,
  invitationEmail,
  needsConfirmation,
} from './domain/invitation.ts';
export { isRole, MEMBERSHIP, type Role, ROLES } from './domain/membership.ts';
export { HOME_PATH, isReturnPath, type SignInEvidence, SignInRefused, type Subject } from './domain/sign-in.ts';
export {
  AUTH_TIME_TOLERANCE_SECONDS,
  type ChallengeFacts,
  type FreshSignIn,
  type StepUpRefusal,
  stepUpRefusal,
} from './domain/step-up.ts';
export { createLoginFlows, LOGIN_FLOW_SECONDS, type LoginFlows } from './infrastructure/login-flows.ts';
export {
  createSessions,
  LONGEST_IDLE_SECONDS,
  type LiveSession,
  type OpenedSession,
  type Sessions,
  type SessionTimeouts,
} from './infrastructure/sessions.ts';
export {
  CONFIRM_OPERATION,
  createInvitationWrites,
  INVITE_OPERATION,
  type InvitationWrite,
  type InvitationWrites,
  type InvitingAdmin,
} from './infrastructure/inviting.ts';
export {
  acceptInvitation,
  draftInvitation,
  type InvitationChange,
  invitationChange,
  type InvitationRecord,
  invitationRecord,
  type InvitationRequest,
  INVITATIONS,
  type InvitationsTransaction,
  invitationToOpen,
  InvitationNotAccepted,
  InvitationNotOpened,
  InvitationUnreadable,
  openInvitation,
} from './infrastructure/invitations.ts';
export {
  addMembership,
  type MemberRecord,
  membersFor,
  membersOf,
  type MembersList,
  type MembershipCheck,
  membershipFor,
  membershipOf,
  MEMBERSHIPS,
  type MembershipsTransaction,
  MOST_MEMBERS,
  type NewMembership,
  TooManyMembers,
} from './infrastructure/memberships.ts';
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
  StepUpFailed,
  type StepUpFailure,
} from './infrastructure/sign-in-flow.ts';
export {
  type ConsumedStepUp,
  createStepUpChallenges,
  type PendingChallenge,
  STEP_UP_SECONDS,
  type StepUpBinding,
  type StepUpChallenges,
  type StepUpEvidence,
} from './infrastructure/step-up-challenges.ts';
export type { IdentityTables } from './infrastructure/tables.ts';
export { userForSubject } from './infrastructure/users.ts';
