// What a notice says (B5-1b, B6-1b, B6-2a): plain text, from the notice's own
// constants and IDs alone. It tells, and does nothing: no link that acts, no
// token, no approval power (PRD §4.4, SEC-HA-11), and nothing of the person
// or contact it is about beyond the IDs an admin can look up once signed in.
import { type ClaimedNotice, type NoticeKind, SIGN_IN_NOTICE_KINDS } from './notice.ts';

/** An email as the notifier sends it. */
export interface NoticeMessage {
  /** The notice's own ID: the provider's key for telling a repeated send (B5-3). */
  readonly id: string;
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}

const ROLE_NAMES: Readonly<Record<NonNullable<ClaimedNotice['role']>, string>> = {
  admin: 'admin',
  approver: 'finance approver',
  developer: 'developer',
  viewer: 'viewer',
};

/** A notice's subject and first line, from its role's name (a membership notice's) or nothing. */
interface Wording {
  readonly subject: (role: string) => string;
  readonly firstLine: (role: string) => string;
  /** What to check if it wasn't expected. */
  readonly check: string;
}

const MEMBERS_CHECK = "If you didn't expect this, sign in to Agent X and check the organisation's members.";
const CONTACTS_CHECK =
  "If you didn't expect this, tell the organisation's admins at once: an admin can sign in to Agent X and check its registered contacts.";
const SIGN_IN_CHECK =
  "If you didn't expect this, tell the organisation's admins at once, and the person if it wasn't you: someone may be trying to take over this login.";

const WORDING: Readonly<Record<NoticeKind, Wording>> = {
  role_granted: {
    subject: (role) => `Agent X: a member of your organisation is now ${article(role)} ${role}`,
    firstLine: (role) => `A member of one of your Agent X organisations was given the ${role} role.`,
    check: MEMBERS_CHECK,
  },
  member_rejoined: {
    subject: (role) => `Agent X: a member rejoined your organisation as ${article(role)} ${role}`,
    firstLine: (role) =>
      `Someone removed from one of your Agent X organisations rejoined it, as ${article(role)} ${role}.`,
    check: MEMBERS_CHECK,
  },
  contact_added: {
    subject: () => 'Agent X: a registered contact was added to your organisation',
    firstLine: () =>
      'A registered contact was added to one of your Agent X organisations. It counts for confirming sensitive changes only 7 days from now.',
    check: CONTACTS_CHECK,
  },
  contact_removed: {
    subject: () => 'Agent X: a registered contact was removed from your organisation',
    firstLine: () => 'A registered contact was removed from one of your Agent X organisations.',
    check: CONTACTS_CHECK,
  },
  second_factor_removed: {
    subject: () => "Agent X: a second factor was removed from a person's login",
    firstLine: () =>
      'An authenticator app, a security key or a passkey was removed from the login of a person in one of your Agent X organisations.',
    check: SIGN_IN_CHECK,
  },
  password_changed: {
    subject: () => "Agent X: a person's password was changed or a reset was asked for",
    firstLine: () =>
      'The password of a person in one of your Agent X organisations was changed, or a reset of it was asked for.',
    check: SIGN_IN_CHECK,
  },
  sign_in_email_changed: {
    subject: () => "Agent X: the email address of a person's login was changed",
    firstLine: () => 'The email address of the login of a person in one of your Agent X organisations was changed.',
    check: SIGN_IN_CHECK,
  },
  sign_in_blocked: {
    subject: () => "Agent X: a person's login was locked, deactivated or removed",
    firstLine: () =>
      'The login of a person in one of your Agent X organisations was locked, deactivated or removed: they can no longer sign in.',
    check: SIGN_IN_CHECK,
  },
  sign_in_restored: {
    subject: () => "Agent X: a person's login was unlocked or reactivated",
    firstLine: () =>
      'The login of a person in one of your Agent X organisations was unlocked or reactivated: they can sign in again.',
    check: SIGN_IN_CHECK,
  },
};

/** Whether the notice is about a person's sign-in (B6-2a). */
const isAboutASignIn = (kind: NoticeKind): boolean => SIGN_IN_NOTICE_KINDS.some((each) => each === kind);

function article(word: string): string {
  return /^[aeiou]/.test(word) ? 'an' : 'a';
}

/** The email telling `to` of the notice. */
export function messageFor(notice: ClaimedNotice, to: string): NoticeMessage {
  const role = notice.role === null ? '' : ROLE_NAMES[notice.role];
  const wording = WORDING[notice.kind];
  const about =
    notice.membershipId !== null
      ? `Membership: ${notice.membershipId}`
      : `${isAboutASignIn(notice.kind) ? 'Person' : 'Registered contact'}: ${notice.aboutId ?? ''}`;
  const why =
    notice.recipientContactId !== null
      ? "You're told because this address is one of the organisation's registered contacts."
      : isAboutASignIn(notice.kind) && notice.recipientUserId === notice.aboutId
        ? "You're told because this is your own login."
        : "You're told because you're an admin of this organisation.";
  return {
    id: notice.id,
    to,
    subject: wording.subject(role),
    text: [
      wording.firstLine(role),
      '',
      wording.check,
      '',
      `Organisation: ${notice.orgId}`,
      about,
      '',
      `${why} This email can't approve or change anything.`,
    ].join('\n'),
  };
}
