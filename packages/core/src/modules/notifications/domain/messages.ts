// What a notice says (B5-1b): plain text, from the notice's own constants and
// IDs alone. It tells, and does nothing: no link that acts, no token, no
// approval power (PRD §4.4, SEC-HA-11), and nothing of the person it is about
// beyond the IDs the admin can look up once signed in.
import type { ClaimedNotice, NoticeKind } from './notice.ts';

/** An email as the notifier sends it. */
export interface NoticeMessage {
  /** The notice's own ID: the provider's key for telling a repeated send (B5-3). */
  readonly id: string;
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}

const ROLE_NAMES: Readonly<Record<ClaimedNotice['role'], string>> = {
  admin: 'admin',
  approver: 'finance approver',
  developer: 'developer',
  viewer: 'viewer',
};

const SUBJECTS: Readonly<Record<NoticeKind, (role: string) => string>> = {
  role_granted: (role) => `Agent X: a member of your organisation is now ${article(role)} ${role}`,
  member_rejoined: (role) => `Agent X: a member rejoined your organisation as ${article(role)} ${role}`,
};

const FIRST_LINES: Readonly<Record<NoticeKind, (role: string) => string>> = {
  role_granted: (role) => `A member of one of your Agent X organisations was given the ${role} role.`,
  member_rejoined: (role) =>
    `Someone removed from one of your Agent X organisations rejoined it, as ${article(role)} ${role}.`,
};

function article(word: string): string {
  return /^[aeiou]/.test(word) ? 'an' : 'a';
}

/** The email telling `to` of the notice. */
export function messageFor(notice: ClaimedNotice, to: string): NoticeMessage {
  const role = ROLE_NAMES[notice.role];
  return {
    id: notice.id,
    to,
    subject: SUBJECTS[notice.kind](role),
    text: [
      FIRST_LINES[notice.kind](role),
      '',
      "If you didn't expect this, sign in to Agent X and check the organisation's members.",
      '',
      `Organisation: ${notice.orgId}`,
      `Membership: ${notice.membershipId}`,
      '',
      "You're told because you're an admin of this organisation. This email can't approve or change anything.",
    ].join('\n'),
  };
}
