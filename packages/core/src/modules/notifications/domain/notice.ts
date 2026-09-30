// A notice (B5, B6-1b): whom to tell, in which organisation, of what, and
// about what. IDs and constants only (0021, 0023).
//
// A notice about a membership (a role granted, a member rejoining) names the
// membership and its role; a notice about a registered contact (one added or
// removed) names the contact in `aboutId`, and one about a person's sign-in
// changed at the login service (B6-2a), or about a reset of their second
// factor (B6-3b), names the person, by their user ID. The one notice that
// asks a contact to confirm a reset names the reset (0026).

/** The kinds about a membership. */
/** The kinds about a membership: a role given, a rejoin, and since the S68 audit a removal and a role taken away (0031). */
const MEMBERSHIP_NOTICE_KINDS = ['role_granted', 'member_rejoined', 'member_removed', 'role_removed'] as const;
/** The kinds about a registered contact (B6-1b). */
const CONTACT_NOTICE_KINDS = ['contact_added', 'contact_removed'] as const;
/** The kinds about a person's sign-in, changed at the login service (B6-2a, 0024; a factor added since the S68 audit, 0030). */
export const SIGN_IN_NOTICE_KINDS = [
  'second_factor_removed',
  'second_factor_added',
  'password_changed',
  'sign_in_email_changed',
  'sign_in_blocked',
  'sign_in_restored',
] as const;
export type SignInNoticeKind = (typeof SIGN_IN_NOTICE_KINDS)[number];

/**
 * The kind that asks one registered contact to confirm a reset, about the
 * reset (B6-3b, 0026): its email carries the contact's link, read at send
 * time, the one notice that does.
 */
export const RESET_LINK_KIND = 'factor_reset_link';
/** The kinds about a reset of a person's second factor, told to them, their admins and its contacts (B6-3b, 0026). */
const RESET_NOTICE_KINDS = [
  'factor_reset_asked',
  'factor_reset_confirmed',
  'factor_reset_cancelled',
  'factor_reset_expired',
  'factor_reset_completed',
] as const;

export const NOTICE_KINDS = [
  ...MEMBERSHIP_NOTICE_KINDS,
  ...CONTACT_NOTICE_KINDS,
  ...SIGN_IN_NOTICE_KINDS,
  RESET_LINK_KIND,
  ...RESET_NOTICE_KINDS,
] as const;
export type NoticeKind = (typeof NOTICE_KINDS)[number];

const NOTICE_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;
export type NoticeRole = (typeof NOTICE_ROLES)[number];

export const isNoticeKind = (value: unknown): value is NoticeKind => NOTICE_KINDS.some((kind) => kind === value);
export const isNoticeRole = (value: unknown): value is NoticeRole => NOTICE_ROLES.some((role) => role === value);

/** Whether a kind is about a person's sign-in, `aboutId` their user ID (B6-2a). */
const isAboutASignIn = (kind: NoticeKind): boolean => SIGN_IN_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about a reset of a person's second factor, `aboutId` their user ID (B6-3b). */
const isAboutAReset = (kind: NoticeKind): boolean => RESET_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about a person, `aboutId` their user ID: their sign-in, or a reset of their second factor. */
export const isAboutAPerson = (kind: NoticeKind): boolean => isAboutASignIn(kind) || isAboutAReset(kind);

/** Whether a kind is about a membership, with its role; any other is about `aboutId`. */
export const isAboutAMembership = (kind: NoticeKind): boolean => MEMBERSHIP_NOTICE_KINDS.some((each) => each === kind);

/** A notice to one person, or to a group found as it is sent, as the change writes it. */
export interface Notice {
  readonly orgId: string;
  /**
   * The person to tell, by their user ID; the sender finds their address.
   * Null, with no contact named and `toContacts` not set: the organisation's
   * active admins but the member the notice is about, found as it is sent
   * (`fanOut`).
   */
  readonly recipientUserId: string | null;
  /** A registered contact to tell (B6-1b), by its ID; the sender reads its address. */
  readonly recipientContactId?: string | null;
  /** The organisation's ACTIVE registered contacts, found as it is sent (B6-1b). */
  readonly toContacts?: boolean;
  readonly kind: NoticeKind;
  /** The membership a membership notice is about; null for any other. */
  readonly membershipId: string | null;
  /** The role that membership holds now; null for any other. */
  readonly role: NoticeRole | null;
  /** What any other notice is about (B6-1b): a registered contact, a person, or a reset (the link's). */
  readonly aboutId?: string | null;
}

/** A notice the sender has taken, to send. */
export interface ClaimedNotice extends Notice {
  readonly recipientContactId: string | null;
  readonly toContacts: boolean;
  readonly aboutId: string | null;
  readonly id: string;
  readonly createdAt: Date;
  /** Tries before this one. */
  readonly attempts: number;
}
