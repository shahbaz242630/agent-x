// A notice (B5, B6-1b): whom to tell, in which organisation, of what, and
// about what. IDs and constants only (0021, 0023).
//
// A notice about a membership (a role granted, a member rejoining) names the
// membership and its role; a notice about a registered contact (one added or
// removed) names the contact in `aboutId`.

/** The kinds about a membership. */
const MEMBERSHIP_NOTICE_KINDS = ['role_granted', 'member_rejoined'] as const;
/** The kinds about a registered contact (B6-1b). */
const CONTACT_NOTICE_KINDS = ['contact_added', 'contact_removed'] as const;

export const NOTICE_KINDS = [...MEMBERSHIP_NOTICE_KINDS, ...CONTACT_NOTICE_KINDS] as const;
export type NoticeKind = (typeof NOTICE_KINDS)[number];

const NOTICE_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;
export type NoticeRole = (typeof NOTICE_ROLES)[number];

export const isNoticeKind = (value: unknown): value is NoticeKind => NOTICE_KINDS.some((kind) => kind === value);
export const isNoticeRole = (value: unknown): value is NoticeRole => NOTICE_ROLES.some((role) => role === value);

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
  /** What any other notice is about (B6-1b): a registered contact. */
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
