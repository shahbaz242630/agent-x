// What a notice says (B5-1b, B6-1b, B6-2a, B6-3b): plain text, from the
// notice's own constants and IDs alone. It tells, and does nothing: no link
// that acts, no token, no approval power (PRD §4.4, SEC-HA-11), and nothing of
// the person or contact it is about beyond the IDs an admin can look up once
// signed in.
//
// The one exception (B6-3b, 0026): the notice asking a registered contact to
// confirm a reset of a person's lost second factor carries that contact's
// link, read at send time, to a page where confirming takes a press. It
// confirms that one reset only, and says so; nothing it holds approves a
// payment (SEC-HA-11 is untouched).
import {
  type ClaimedNotice,
  isAboutAnAgent,
  isAboutAPerson,
  isAboutASupplier,
  type NoticeKind,
  RESET_LINK_KIND,
} from './notice.ts';

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

/** A contact's link to confirm a reset, and when the reset lapses: what the sender reads at send time (B6-3b). */
export interface ResetLink {
  readonly url: string;
  readonly expiresAt: Date;
}

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
const RESET_CHECK =
  "If you didn't expect this, tell the organisation's admins at once: any admin can sign in to Agent X and cancel it until the second factor is removed. Someone may be trying to take over this login.";
const RESET_CLOSED_CHECK =
  "If you didn't expect this, sign in to Agent X, or ask the organisation's admins, and check the organisation's resets.";
const SUPPLIERS_CHECK =
  "If you didn't expect this, sign in to Agent X and check the organisation's suppliers, and tell its admins at once: someone may be trying to redirect its payments.";
const AGENTS_CHECK =
  "If you didn't expect this, sign in to Agent X and check the organisation's AI agents, and tell its admins at once: someone may be trying to take control of an agent.";
/** What a person's second factor is, as the emails name it. */
const SECOND_FACTOR = 'second factor (an authenticator app, a security key or a passkey)';

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
  member_removed: {
    subject: (role) => `Agent X: ${article(role)} ${role} was removed from your organisation`,
    firstLine: (role) =>
      `A member of one of your Agent X organisations, ${article(role)} ${role}, was removed: their sessions ended. Any AI agents they own keep running until an admin hands them to someone else or suspends them.`,
    check: MEMBERS_CHECK,
  },
  role_removed: {
    subject: (role) => `Agent X: a member of your organisation is no longer ${article(role)} ${role}`,
    firstLine: (role) =>
      `A member of one of your Agent X organisations had the ${role} role taken away: their sessions ended.`,
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
  second_factor_added: {
    subject: () => "Agent X: a second factor was added to a person's login",
    firstLine: () =>
      'A second factor (an authenticator app, a security key, a passkey, or a code sent by SMS or email) was added to the login of a person in one of your Agent X organisations.',
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
  // Its own email, with the contact's link (linkMessage below); kept here so every kind has its words.
  factor_reset_link: {
    subject: () => "Agent X: please confirm a reset of a person's second factor",
    firstLine: () => `An admin asked to reset the ${SECOND_FACTOR} of a person who says they lost theirs.`,
    check: RESET_CHECK,
  },
  factor_reset_asked: {
    subject: () => "Agent X: a reset of a person's second factor was asked for",
    firstLine: () =>
      `An admin of one of your Agent X organisations asked to reset the ${SECOND_FACTOR} of a person who says they lost theirs. The organisation's registered contacts are asked to confirm it.`,
    check: RESET_CHECK,
  },
  factor_reset_confirmed: {
    subject: () => "Agent X: a reset of a person's second factor was confirmed",
    firstLine: () =>
      `A registered contact confirmed a reset of the ${SECOND_FACTOR} of a person in one of your Agent X organisations. It will be removed in 24 hours, unless an admin cancels the reset first.`,
    check: RESET_CHECK,
  },
  factor_reset_cancelled: {
    subject: () => "Agent X: a reset of a person's second factor was cancelled",
    firstLine: () =>
      `An admin cancelled a reset of the ${SECOND_FACTOR} of a person in one of your Agent X organisations. Nothing was removed.`,
    check: RESET_CLOSED_CHECK,
  },
  factor_reset_expired: {
    subject: () => "Agent X: a reset of a person's second factor lapsed",
    firstLine: () =>
      `A reset of the ${SECOND_FACTOR} of a person in one of your Agent X organisations lapsed: no registered contact confirmed it within 72 hours. Nothing was removed.`,
    check: RESET_CLOSED_CHECK,
  },
  factor_reset_completed: {
    subject: () => "Agent X: a person's second factor was removed, as a reset asked",
    firstLine: () =>
      `The ${SECOND_FACTOR} of a person in one of your Agent X organisations was removed, as a reset a registered contact confirmed asked. They sign in with their password, and set up a new one.`,
    check: SIGN_IN_CHECK,
  },
  // About a supplier (0033), sent by E2-2 and E3-2.
  supplier_reactivated: {
    subject: () => 'Agent X: a suspended supplier was reactivated',
    firstLine: () =>
      'An admin reactivated a suspended supplier of one of your Agent X organisations. It is verified again only if nothing about it changed while it was suspended.',
    check: SUPPLIERS_CHECK,
  },
  supplier_payee_changed: {
    subject: () => "Agent X: a supplier's bank details are being changed",
    firstLine: () =>
      'New bank details were registered for a supplier of one of your Agent X organisations. Nothing is paid to them until a second person has called the supplier back and verified the change.',
    check: SUPPLIERS_CHECK,
  },
  supplier_details_changed: {
    subject: () => "Agent X: a supplier's details were changed",
    firstLine: () =>
      'The details of a supplier of one of your Agent X organisations were changed. Nothing is paid to it until a second person verifies it again.',
    check: SUPPLIERS_CHECK,
  },
  supplier_verified: {
    subject: () => 'Agent X: a supplier was verified',
    firstLine: () =>
      "A second person verified a supplier of one of your Agent X organisations: the organisation's AI agents may now ask to pay it.",
    check: SUPPLIERS_CHECK,
  },
  supplier_suspended: {
    subject: () => 'Agent X: a supplier was suspended',
    firstLine: () =>
      'A supplier of one of your Agent X organisations was suspended: nothing is paid to it until an admin reactivates it.',
    check: SUPPLIERS_CHECK,
  },
  // About an agent (0034): its handover, to the admins and to its new owner.
  agent_handed_over: {
    subject: () => 'Agent X: an AI agent was handed to another owner',
    firstLine: () =>
      'An admin handed an AI agent of one of your Agent X organisations to another member. Its old keys stopped working at once, and the admin was given its one new key.',
    check: AGENTS_CHECK,
  },
  agent_handed_to_you: {
    subject: () => 'Agent X: an AI agent was handed to you',
    firstLine: () =>
      'An admin of one of your Agent X organisations made you the owner of an AI agent. Its old keys stopped working at once; the admin was given its one new key, to pass to you by a way you already trust.',
    check: AGENTS_CHECK,
  },
};

const NEWLINE = '\n';

/** What a notice is about, by its ID alone: a membership, a person, a supplier, or a registered contact. */
function aboutLine(notice: ClaimedNotice): string {
  if (notice.membershipId !== null) return `Membership: ${notice.membershipId}`;
  const id = notice.aboutId ?? '';
  if (isAboutAPerson(notice.kind)) return `Person: ${id}`;
  if (isAboutAnAgent(notice.kind)) return `Agent: ${id}`;
  return isAboutASupplier(notice.kind) ? `Supplier: ${id}` : `Registered contact: ${id}`;
}

function article(word: string): string {
  return /^[aeiou]/.test(word) ? 'an' : 'a';
}

/** The email asking a registered contact to confirm a reset, with its link (B6-3b). */
function linkMessage(notice: ClaimedNotice, to: string, link: ResetLink): NoticeMessage {
  return {
    id: notice.id,
    to,
    subject: WORDING[RESET_LINK_KIND].subject(''),
    text: [
      `An admin of one of your Agent X organisations asked to reset the ${SECOND_FACTOR} of a person who says they lost theirs. As one of the organisation's registered contacts, you're asked to confirm it.`,
      '',
      "Confirm only once you've checked with the admin and the person, by a way you already trust (a call to a number you already know, never one in an email), that the request is real. Once confirmed, the second factor is removed 24 hours later, unless an admin cancels the reset first.",
      '',
      'To confirm, open this link and press Confirm:',
      link.url,
      '',
      `The link works until ${link.expiresAt.toISOString()}. If you didn't expect this, don't open it, and tell the organisation's admins at once.`,
      '',
      `Organisation: ${notice.orgId}`,
      `Reset: ${notice.aboutId ?? ''}`,
      '',
      "You're told because this address is one of the organisation's registered contacts. This link confirms this one reset only: it can't approve a payment or change anything else, and Agent X never asks for a password or a code by email.",
    ].join(NEWLINE),
  };
}

/**
 * The email telling `to` of the notice. The notice asking a contact to
 * confirm a reset takes its link, and no other notice takes one: either
 * mismatch is a bug, and throws.
 */
export function messageFor(notice: ClaimedNotice, to: string, link?: ResetLink): NoticeMessage {
  if (notice.kind === RESET_LINK_KIND) {
    if (link === undefined) throw new RangeError("a reset's link notice is sent with its link");
    return linkMessage(notice, to, link);
  }
  if (link !== undefined) throw new RangeError("only a reset's link notice carries a link");
  const role = notice.role === null ? '' : ROLE_NAMES[notice.role];
  const wording = WORDING[notice.kind];
  const why =
    notice.recipientContactId !== null
      ? "You're told because this address is one of the organisation's registered contacts."
      : // The kind check keeps a notice with neither (both null) from reading as one's own login.
        isAboutAPerson(notice.kind) && notice.recipientUserId === notice.aboutId
        ? "You're told because this is your own login."
        : notice.kind === 'agent_handed_to_you'
          ? "You're told because you're the agent's new owner."
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
      aboutLine(notice),
      '',
      `${why} This email can't approve or change anything.`,
    ].join(NEWLINE),
  };
}
