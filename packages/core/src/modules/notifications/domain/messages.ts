// What a notice says (B5-1b, B6-1b): plain text, from the notice's own
// constants and IDs alone. It tells, and does nothing: no link that acts, no
// token, no approval power (PRD §4.4, SEC-HA-11), and nothing of the person
// or contact it is about beyond the IDs an admin can look up once signed in.
import type { ClaimedNotice, NoticeKind } from './notice.ts';

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
};

function article(word: string): string {
  return /^[aeiou]/.test(word) ? 'an' : 'a';
}

/** The email telling `to` of the notice. */
export function messageFor(notice: ClaimedNotice, to: string): NoticeMessage {
  const role = notice.role === null ? '' : ROLE_NAMES[notice.role];
  const wording = WORDING[notice.kind];
  const about =
    notice.membershipId === null ? `Registered contact: ${notice.aboutId ?? ''}` : `Membership: ${notice.membershipId}`;
  const why =
    notice.recipientContactId === null
      ? "You're told because you're an admin of this organisation."
      : "You're told because this address is one of the organisation's registered contacts.";
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
