// The identity module (ADR-003, ADR-004): the people who sign in, their
// console sessions and the sign-in flows under way, in global tables (0010,
// 0011); the OIDC client that checks a sign-in (B2-2); and the sign-in from
// end to end (B2-3a). The routes come at B2-3a-2. Step-up challenges (B3-1),
// bound to one pending change in a session. Memberships and roles (B4-1): a
// person in an organisation, an authority table read through its signed state.
// Invitations (B4-3a): the pending change an admin's step-up binds to, then
// opened with a token shown once. Registered contacts (B6-1a): an
// organisation's trust anchor, added and removed with step-up.
export {
  CONFIRMED_ROLES,
  EMAIL_MAX,
  INVITATION,
  INVITATION_HOURS,
  invitationEmail,
  needsConfirmation,
} from './domain/invitation.ts';
export { isRole, MEMBERSHIP, type Role, ROLES } from './domain/membership.ts';
export { classOfIdpEvent, type IdpEventClass, WATCHED_IDP_EVENTS } from './domain/idp-event.ts';
export { CONTACT_COOLING_OFF_DAYS, countsNow, MOST_CONTACTS, REGISTERED_CONTACT } from './domain/registered-contact.ts';
export {
  FACTOR_RESET,
  type FactorResetStatus,
  RESET_CONFIRM_HOURS,
  RESET_COOLING_OFF_HOURS,
} from './domain/factor-reset.ts';
export { HOME_PATH, isReturnPath, type SignInEvidence, SignInRefused, type Subject } from './domain/sign-in.ts';
export {
  AUTH_TIME_TOLERANCE_SECONDS,
  type ChallengeFacts,
  type FreshSignIn,
  PASSKEY_METHOD,
  type StepUpRefusal,
  stepUpRefusal,
} from './domain/step-up.ts';
export { AddressBookUnavailable, createAddressBook } from './infrastructure/address-book.ts';
export {
  createIdpEventCopier,
  IDP_EVENT_COPIED,
  type IdpEventCopier,
  SIGN_IN_CHANGED,
} from './infrastructure/idp-copier.ts';
export {
  createIdpEventFeed,
  type IdpEvent,
  type IdpEventFeed,
  IdpFeedUnavailable,
  MOST_EVENTS_A_PAGE,
} from './infrastructure/idp-feed.ts';
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
  ACCEPT_OPERATION,
  type Acceptance,
  type AcceptingPerson,
  createInvitationAcceptance,
  type InvitationAcceptance,
} from './infrastructure/accepting.ts';
export {
  type AcceptanceConfirmations,
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  type ConfirmationWrite,
  createAcceptanceConfirmations,
  DECLINE_OPERATION,
} from './infrastructure/confirming.ts';
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
  type FirstAdminInvitation,
  inviteFirstAdmin,
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
  createMembershipChanges,
  DEACTIVATE_CONFIRM_OPERATION,
  DEACTIVATE_OPERATION,
  type MembershipChange,
  type MembershipChanges,
  type MembershipChangeWrite,
  ROLE_CONFIRM_OPERATION,
  ROLE_OPERATION,
} from './infrastructure/membership-changes.ts';
export {
  addMembership,
  type MemberCheck,
  memberOf,
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
  createHoldInvestigations,
  type HoldAdmin,
  type HoldInvestigations,
  type HoldShown,
  INVESTIGATE_OPERATION,
  type InvestigationWrite,
} from './infrastructure/hold-investigations.ts';
export {
  CLEAR_CONFIRM_OPERATION,
  CLEAR_OPERATION,
  type ClearingAdmin,
  type ClearingWrite,
  createHoldClearings,
  type HoldClearings,
} from './infrastructure/hold-clearing.ts';
export {
  activeContactsFor,
  contactAddressFor,
  ContactsTampered,
  type ContactWithAddress,
  REGISTERED_CONTACTS,
  registeredContactsFor,
} from './infrastructure/registered-contacts.ts';
export { FACTOR_RESETS, resetLinkFor } from './infrastructure/factor-resets.ts';
export {
  CONTACT_ADD_CONFIRM_OPERATION,
  CONTACT_ADD_OPERATION,
  CONTACT_REMOVE_CONFIRM_OPERATION,
  CONTACT_REMOVE_OPERATION,
  type ContactChanges,
  type ContactChangeWrite,
  createContactChanges,
} from './infrastructure/contact-changes.ts';
export {
  createResetChanges,
  RESET_ASK_CONFIRM_OPERATION,
  RESET_ASK_OPERATION,
  RESET_CANCEL_OPERATION,
  type ResetChanges,
  type ResetChangeWrite,
  type ResetsList,
} from './infrastructure/reset-changes.ts';
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
export { subjectOfUser, userForSubject, userOfSubject } from './infrastructure/users.ts';
