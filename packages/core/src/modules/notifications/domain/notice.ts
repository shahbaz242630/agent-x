// A notice (B5): whom to tell, in which organisation, of what, and about which
// membership and role. IDs and constants only (0021).

export const NOTICE_KINDS = ['role_granted', 'member_rejoined'] as const;
export type NoticeKind = (typeof NOTICE_KINDS)[number];

const NOTICE_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;
export type NoticeRole = (typeof NOTICE_ROLES)[number];

export const isNoticeKind = (value: unknown): value is NoticeKind => NOTICE_KINDS.some((kind) => kind === value);
export const isNoticeRole = (value: unknown): value is NoticeRole => NOTICE_ROLES.some((role) => role === value);

/** A notice to one person, as the change writes it. */
export interface Notice {
  readonly orgId: string;
  /** The person to tell, by their user ID; the sender finds their address. */
  readonly recipientUserId: string;
  readonly kind: NoticeKind;
  /** The membership the notice is about. */
  readonly membershipId: string;
  /** The role it holds now. */
  readonly role: NoticeRole;
}

/** A notice the sender has taken, to send. */
export interface ClaimedNotice extends Notice {
  readonly id: string;
  readonly createdAt: Date;
  /** Tries before this one. */
  readonly attempts: number;
}
