// A notice (B5, B6-1b): whom to tell, in which organisation, of what, and
// about what. IDs and constants only (0021, 0023).
//
// A notice about a membership (a role granted, a member rejoining) names the
// membership and its role; a notice about a registered contact (one added or
// removed) names the contact in `aboutId`, and one about a person's sign-in
// changed at the login service (B6-2a), or about a reset of their second
// factor (B6-3b), names the person, by their user ID. The one notice that
// asks a contact to confirm a reset names the reset (0026), one about a
// supplier (E2-1, 0033) names the supplier, and one about an agent (0034)
// names the agent.

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

/** The kinds about a supplier, `aboutId` its ID (0033): sent by E2-2 and E3-2; its remittance email changed by Phase 4 C2a (0061). */
export const SUPPLIER_NOTICE_KINDS = [
  'supplier_reactivated',
  'supplier_payee_changed',
  'supplier_details_changed',
  'supplier_verified',
  'supplier_suspended',
  'supplier_remittance_changed',
] as const;

/** The kinds about an agent, `aboutId` its ID (0034): its handover, told to the admins and to its new owner. */
export const AGENT_NOTICE_KINDS = ['agent_handed_over', 'agent_handed_to_you'] as const;

/**
 * The kinds about a mandate, `aboutId` its ID: its moves (0036), and a change
 * of its own policy (0038), told to every admin and approver (partner, S86, S91).
 */
export const MANDATE_NOTICE_KINDS = [
  'mandate_accepted',
  'mandate_suspended',
  'mandate_resumed',
  'mandate_revoked',
  'mandate_expired',
  'mandate_policy_changed',
] as const;

/**
 * The kinds about the organisation as a whole, `aboutId` its ID: a change of
 * its own policy (0038), its freeze and unfreeze (0045), told to every admin
 * and approver.
 */
const ORGANIZATION_NOTICE_KINDS = [
  'organization_policy_changed',
  'organization_frozen',
  'organization_unfrozen',
] as const;

/** The kinds about a spend request, `aboutId` its ID (0045): one waiting for approval, told to every admin and approver (partner decision 2, S104). */
const SPEND_REQUEST_NOTICE_KINDS = ['spend_request_waiting'] as const;

/**
 * The kinds about a spend request told to every admin alone, `aboutId` its ID
 * (0059, Phase 4 B4b): an approved one stopped by the hand-off's last check
 * before it reached the bank (partner decision 3, S135).
 */
const SPEND_REQUEST_ADMIN_NOTICE_KINDS = ['spend_request_stopped'] as const;

/**
 * The kinds about an entry of the organisation's audit log, `aboutId` the
 * entry's event ID: Agent X's own team exported the audit log (0050) or the
 * activity log (0053, L7) for a case, told to every admin (ADR-005 §6,
 * partner decision 24); an admin's background download of the activity log
 * ready, or given up on, told to them (0053, decision 31); Agent X's own team
 * paused or resumed every hand-off to the bank, for every organisation, told
 * to every admin (0057, Phase 4 B1, partner decision 4).
 */
const AUDIT_LOG_NOTICE_KINDS = [
  'audit_log_exported',
  'access_log_export_ready',
  'access_log_export_failed',
  'access_log_exported',
  'handoff_paused',
  'handoff_resumed',
] as const;

/**
 * The kind that tells a supplier it was paid (0062, Phase 4 C2b; partner
 * decision 34a): `aboutId` the payment's transaction, to no person or
 * contact; the sender reads the supplier's address, the setting and what the
 * email carries at send time. One a payment.
 */
export const REMITTANCE_KIND = 'payment_remittance';
/** The kind that tells every admin a paid supplier had no email to tell (0062, decision 34c), `aboutId` the transaction. */
export const REMITTANCE_NO_EMAIL_KIND = 'payment_remittance_no_email';
/**
 * The kind that tells every admin one of them marked a payment failed on
 * their bank's written word (0064; gate H10), `aboutId` the transaction.
 */
const MARKED_FAILED_KIND = 'payment_marked_failed';
/**
 * The kinds that tell every admin a payment the bank left unclear (0065,
 * partner decisions 37b, 38), `aboutId` the transaction: the bank went back on its
 * word, rejected it without proof the money stayed, or left it unresolved past
 * a day.
 */
const PAYMENT_ALERT_KINDS = ['payment_contradicted', 'payment_unproven', 'payment_still_unknown'] as const;
/**
 * The kinds that tell every admin an admin proposed marking a payment failed,
 * a second admin to confirm it, or withdrew that (0066, gate H10), `aboutId`
 * the transaction.
 */
const MARK_PROPOSAL_KINDS = ['payment_mark_proposed', 'payment_mark_withdrawn'] as const;

export const NOTICE_KINDS = [
  ...MEMBERSHIP_NOTICE_KINDS,
  ...CONTACT_NOTICE_KINDS,
  ...SIGN_IN_NOTICE_KINDS,
  RESET_LINK_KIND,
  ...RESET_NOTICE_KINDS,
  ...SUPPLIER_NOTICE_KINDS,
  ...AGENT_NOTICE_KINDS,
  ...MANDATE_NOTICE_KINDS,
  ...ORGANIZATION_NOTICE_KINDS,
  ...SPEND_REQUEST_NOTICE_KINDS,
  ...SPEND_REQUEST_ADMIN_NOTICE_KINDS,
  ...AUDIT_LOG_NOTICE_KINDS,
  REMITTANCE_KIND,
  REMITTANCE_NO_EMAIL_KIND,
  MARKED_FAILED_KIND,
  ...PAYMENT_ALERT_KINDS,
  ...MARK_PROPOSAL_KINDS,
] as const;
export type NoticeKind = (typeof NOTICE_KINDS)[number];

const NOTICE_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;
export type NoticeRole = (typeof NOTICE_ROLES)[number];

export const isNoticeKind = (value: unknown): value is NoticeKind => NOTICE_KINDS.some((kind) => kind === value);
export const isNoticeRole = (value: unknown): value is NoticeRole => NOTICE_ROLES.some((role) => role === value);

/** Whether a kind is about a person, `aboutId` their user ID: their sign-in (B6-2a), or a reset of their second factor (B6-3b). */
export const isAboutAPerson = (kind: NoticeKind): boolean =>
  SIGN_IN_NOTICE_KINDS.some((each) => each === kind) || RESET_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about a supplier, `aboutId` its ID (0033). */
export const isAboutASupplier = (kind: NoticeKind): boolean => SUPPLIER_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about an agent, `aboutId` its ID (0034). */
export const isAboutAnAgent = (kind: NoticeKind): boolean => AGENT_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about a mandate, `aboutId` its ID (0036, 0038). */
export const isAboutAMandate = (kind: NoticeKind): boolean => MANDATE_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about the organisation as a whole, `aboutId` its ID (0038). */
export const isAboutTheOrganization = (kind: NoticeKind): boolean =>
  ORGANIZATION_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about a spend request, `aboutId` its ID (0045, 0059). */
export const isAboutASpendRequest = (kind: NoticeKind): boolean =>
  SPEND_REQUEST_NOTICE_KINDS.some((each) => each === kind) ||
  SPEND_REQUEST_ADMIN_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about an entry of the audit log, `aboutId` its event ID (0050). */
export const isAboutAnAuditEntry = (kind: NoticeKind): boolean => AUDIT_LOG_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about a payment, `aboutId` its transaction's ID (0062, 0064, 0065). */
export const isAboutAPayment = (kind: NoticeKind): boolean =>
  kind === REMITTANCE_KIND ||
  kind === REMITTANCE_NO_EMAIL_KIND ||
  kind === MARKED_FAILED_KIND ||
  PAYMENT_ALERT_KINDS.some((each) => each === kind) ||
  MARK_PROPOSAL_KINDS.some((each) => each === kind);

/** Whether a kind is told to every admin and approver: what lets an agent spend, and what waits on them (0036, 0038, 0045). */
export const isToAdminsAndApprovers = (kind: NoticeKind): boolean =>
  isAboutAMandate(kind) || isAboutTheOrganization(kind) || SPEND_REQUEST_NOTICE_KINDS.some((each) => each === kind);

/** Whether a kind is about a membership, with its role; any other is about `aboutId`. */
export const isAboutAMembership = (kind: NoticeKind): boolean => MEMBERSHIP_NOTICE_KINDS.some((each) => each === kind);

/** A notice to one person, or to a group found as it is sent, as the change writes it. */
export interface Notice {
  readonly orgId: string;
  /**
   * The person to tell, by their user ID; the sender finds their address.
   * Null, with no contact named and `toContacts` not set: the organisation's
   * active admins but the member the notice is about, found as it is sent
   * (`fanOut`); for a notice about a mandate, its admins and approvers; for
   * a remittance (0062), the paid supplier itself.
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
  /** What any other notice is about (B6-1b): a registered contact, a person, a reset (the link's), a supplier, an agent, an audit log entry or a payment. */
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
