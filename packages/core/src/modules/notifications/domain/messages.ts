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
//
// The other (Phase 4 C2b, 0062): the email telling a paid supplier, someone
// outside the organisation, carries the payment's own facts, read at send
// time: who paid, the invoice number, the bank reference and the amount
// (partner decisions 8 and 34a). Nothing else, and no ID of ours.
import {
  type ClaimedNotice,
  isAboutAMandate,
  isAboutAnAgent,
  isAboutAnAuditEntry,
  isAboutAPayment,
  isAboutAPerson,
  isAboutASupplier,
  isAboutASpendRequest,
  isAboutTheOrganization,
  isToAdminsAndApprovers,
  type NoticeKind,
  REMITTANCE_KIND,
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

/**
 * A spend request waiting for approval, as the sender reads it at send time
 * from its verified records (Phase 3 B2, partner decision 2): what it asks
 * and who asked, and the console's address. Never the agent's own words (its
 * purpose), and nothing that decides (SEC-HA-11).
 */
export interface WaitingRequest {
  readonly amountMinor: bigint;
  readonly currency: string;
  readonly supplierName: string;
  readonly agentName: string;
  readonly agentId: string;
  readonly consoleUrl: string;
  /** When it expires, unless a person decides first: its decision's time and its wait (E6, partner S119). */
  readonly expiresAt: Date;
}

/**
 * A payment that succeeded, as the sender reads it at send time for its
 * supplier's email (Phase 4 C2b; partner decisions 8 and 34a): who paid, the
 * invoice it pays, the reference the supplier's bank shows and the amount.
 * Nothing else of the organisation, the agent or the request goes to someone
 * outside it.
 */
export interface PaidRemittance {
  readonly payerName: string;
  readonly invoiceNumber: string;
  readonly bankReference: string;
  readonly amountMinor: bigint;
  readonly currency: string;
}

/** Minor units as an amount reads in an email: AED 12,500.00 (two decimals, ADR-006 §1's currencies). */
export function amountText(minor: bigint, currency: string): string {
  const whole = new Intl.NumberFormat('en-US').format(minor / 100n);
  return `${currency} ${whole}.${(minor % 100n).toString().padStart(2, '0')}`;
}

/** A notice's subject and first line, from its role's name (a membership notice's) or nothing. */
interface Wording {
  readonly subject: (role: string) => string;
  readonly firstLine: (role: string) => string;
  /** What to check if it wasn't expected, or what to do. */
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
const MANDATES_CHECK =
  "If you didn't expect this, sign in to Agent X and check the organisation's mandates, and tell its admins at once: a mandate is what lets an AI agent spend.";
const POLICIES_CHECK =
  "If you didn't expect this, sign in to Agent X and check the organisation's policies, and tell its admins at once: a policy sets how much, and whom, its AI agents may pay.";
const FREEZE_CHECK =
  "If you didn't expect this, sign in to Agent X and check the organisation's state, and tell its admins at once: a freeze is the organisation's emergency brake on its AI agents' spending.";
/** What an admin can check of a pause or resume of every hand-off to the bank (0057): its entry, with its reason. */
const HANDOFF_CHECK =
  "Sign in to Agent X and open the audit log to see this entry and its reason. If you have questions about it, tell the organisation's other admins and contact us.";
/** A payment the bank left unclear: what Agent X does by itself (partner decision 38). */
const KEEPS_CHECKING =
  "Agent X keeps checking it with the bank automatically and updates the payment if the bank's answer changes.";
/** What the admin takes to their own bank about it (decision 38: never our team's check). */
const WITH_YOUR_BANK =
  "Sign in to Agent X to see the payment, its reference and the bank's answers in your audit log, where you can download them. Check your bank statement and, if you need to, contact your bank quoting that payment reference. Don't pay its invoice again until your bank confirms the money didn't leave your account.";
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
  supplier_remittance_changed: {
    subject: () => "Agent X: a supplier's payment emails were switched on or off",
    firstLine: () =>
      'An admin of one of your Agent X organisations changed whether a supplier is emailed when a payment to it succeeds. Who is paid, and how much, did not change.',
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
  // About a mandate (0036): its moves, to every admin and approver.
  mandate_accepted: {
    subject: () => 'Agent X: a mandate was accepted',
    firstLine: () =>
      'An admin of one of your Agent X organisations accepted a mandate, signing in again with a passkey: its terms are now in force, and the AI agent it names may spend within them. Where the organisation’s policies hold the agent to a lower monthly cap (AED 20,000 unless set), the lower cap applies: the mandate shows it.',
    check: MANDATES_CHECK,
  },
  mandate_suspended: {
    subject: () => 'Agent X: a mandate was suspended',
    firstLine: () =>
      'An admin of one of your Agent X organisations suspended a mandate: the AI agent it names can spend nothing under it until it is resumed.',
    check: MANDATES_CHECK,
  },
  mandate_resumed: {
    subject: () => 'Agent X: a mandate was resumed',
    firstLine: () =>
      'An admin of one of your Agent X organisations resumed a suspended mandate: the AI agent it names may spend within its terms again.',
    check: MANDATES_CHECK,
  },
  mandate_revoked: {
    subject: () => 'Agent X: a mandate was revoked',
    firstLine: () =>
      'An admin of one of your Agent X organisations revoked a mandate for good: the AI agent it names can spend nothing under it again.',
    check: MANDATES_CHECK,
  },
  mandate_expired: {
    subject: () => 'Agent X: a mandate expired',
    firstLine: () =>
      'A mandate of one of your Agent X organisations reached its end date: the AI agent it names can spend nothing under it again.',
    check: MANDATES_CHECK,
  },
  // About a policy (0038): a change, in force at once, to every admin and approver.
  mandate_policy_changed: {
    subject: () => "Agent X: a mandate's policy was changed",
    firstLine: () =>
      "An admin of one of your Agent X organisations changed a mandate's own policy, signing in again with a passkey: its rules are in force now for the AI agent the mandate names.",
    check: POLICIES_CHECK,
  },
  organization_policy_changed: {
    subject: () => "Agent X: the organisation's policy was changed",
    firstLine: () =>
      "An admin of one of your Agent X organisations changed its policy, signing in again with a passkey: its rules are in force now for the organisation's AI agents.",
    check: POLICIES_CHECK,
  },
  // About the organisation's freeze (0045): its brake, to every admin and approver.
  organization_frozen: {
    subject: () => 'Agent X: the organisation was frozen',
    firstLine: () =>
      "An admin or approver of one of your Agent X organisations froze it: its AI agents can't make new spend requests, and none waiting can be approved, until an admin unfreezes it.",
    check: FREEZE_CHECK,
  },
  organization_unfrozen: {
    subject: () => 'Agent X: the organisation was unfrozen',
    firstLine: () =>
      'An admin of one of your Agent X organisations unfroze it, signing in again with a passkey and giving a reason: its AI agents can make spend requests again under their mandates.',
    check: FREEZE_CHECK,
  },
  // About a spend request (0045): one waiting for a person's decision. B2 adds its amount, supplier and agent and the
  // console's address (partner decision 2): never a token or anything that decides (SEC-HA-11).
  spend_request_waiting: {
    subject: () => "Agent X: an AI agent's spend request is waiting for approval",
    firstLine: () =>
      "An AI agent of one of your Agent X organisations asked to pay a supplier, and its organisation's rules need a person to approve it. Nothing is paid unless an admin or approver approves it in Agent X, signing in again with a passkey (only an admin, when it is over its mandate's own limits); it expires at the time shown below.",
    check:
      "Sign in to Agent X to see the request in full and approve or reject it. If you didn't expect it, reject it and tell the organisation's admins.",
  },
  // About a spend request (0059, Phase 4 B4b): an approved one stopped by the hand-off's last check, to every admin
  // (partner decision 3). Never its amount or supplier: the console shows those to whoever signs in.
  spend_request_stopped: {
    subject: () => 'Agent X: an approved payment was stopped before it reached the bank',
    firstLine: () =>
      "An approved spend request in one of your Agent X organisations was stopped by Agent X's last check before it was handed to the bank, because something it was approved under had changed: for example its agent's key was ended, its supplier's payee changed, or its mandate was replaced or stopped. Nothing was paid, and the money held for it was freed.",
    check:
      "Sign in to Agent X to see the request and why it was stopped. Once whatever stopped it is put right, the agent can ask again if the payment is still needed. If you didn't expect this, tell the organisation's other admins.",
  },
  // About an audit log entry (0050): Agent X's own team read the log for a case, to every admin (ADR-005 §6).
  audit_log_exported: {
    subject: () => "Agent X: our team exported your organisation's audit log",
    firstLine: () =>
      "Agent X's own team exported the audit log of one of your Agent X organisations for a case: a dispute, or a regulator's request. The export only reads the log; it changed nothing.",
    check:
      "Sign in to Agent X and open the audit log to see this entry: its case reference, the dates it covers and how many events it held. If you didn't expect it, tell the organisation's other admins.",
  },
  // About an admin's background download of the activity log (0053, decision 31): to the admin who asked, in words
  // alone, never a range, a count or a file (decision 30).
  access_log_export_ready: {
    subject: () => 'Agent X: your activity log download is ready',
    firstLine: () =>
      'The activity log download you asked for in one of your Agent X organisations is ready. It is kept for 7 days, then deleted.',
    check: "Sign in to Agent X as an admin to save it. If you didn't ask for it, tell the organisation's other admins.",
  },
  access_log_export_failed: {
    subject: () => "Agent X: your activity log download couldn't be made",
    firstLine: () =>
      "The activity log download you asked for in one of your Agent X organisations couldn't be made: it failed several times, or was still not made six days after you asked. Nothing was changed.",
    check: 'Sign in to Agent X to ask for it again. If it fails again, tell us the entry named below.',
  },
  // About an activity log entry (0053, L7): Agent X's own team read the activity log for a case, to every admin.
  access_log_exported: {
    subject: () => "Agent X: our team exported your organisation's activity log",
    firstLine: () =>
      "Agent X's own team exported the activity log of one of your Agent X organisations for a case: a dispute, or a regulator's request. The export only reads the log; it changed nothing.",
    check:
      "Sign in to Agent X and open the audit log to see this entry: its case reference, the dates it covers and how many requests it held. If you didn't expect it, tell the organisation's other admins.",
  },
  // About an audit log entry (0057, Phase 4 B1): Agent X's own team paused or resumed every hand-off to the bank, for
  // every organisation at once, to every admin (partner decision 4). Its reason is on the entry, never in the email.
  handoff_paused: {
    subject: () => 'Agent X: payments to the bank are paused',
    firstLine: () =>
      "Agent X's own team paused every hand-off of approved payments to the bank, for every organisation, one of yours among them. Spend requests are still decided and approved; approved ones wait, and nothing is sent to the bank until we resume.",
    check: HANDOFF_CHECK,
  },
  handoff_resumed: {
    subject: () => 'Agent X: payments to the bank are resumed',
    firstLine: () =>
      "Agent X's own team resumed the hand-off of approved payments to the bank, for every organisation, one of yours among them. Each approved payment that waited is checked again before it goes.",
    check: HANDOFF_CHECK,
  },
  // To a paid supplier (0062, Phase 4 C2b, partner decision 34a): its own email (remittanceMessage); only the subject here.
  payment_remittance: {
    subject: () => 'Payment sent to you',
    firstLine: () => '',
    check: '',
  },
  // About a payment (0062, decision 34c): its supplier had no email to tell, to every admin.
  payment_remittance_no_email: {
    subject: () => 'Agent X: a supplier was paid but not emailed',
    firstLine: () =>
      "A payment from one of your Agent X organisations to a supplier succeeded. The supplier is set to be emailed when it is paid, but it has no email address on file, so it wasn't told. The payment itself is not affected.",
    check:
      'Sign in to Agent X to see the payment, and let the supplier know it was paid if they need to. To have it emailed next time, add its email address in its details.',
  },
  // About a payment (0064, Phase 4 E1c): Agent X's own team marked it failed on the bank's written word, to every admin.
  payment_marked_failed: {
    subject: () => 'Agent X: a payment was marked failed',
    firstLine: () =>
      "Agent X's own team marked a payment from one of your organisations as failed: the bank confirmed in writing that it never accepted it, so no money left your account. The amount it held against your limits is free again, and its invoice can be paid again.",
    check:
      "Sign in to Agent X to see the payment, and the bank's reference our team recorded in your audit log. If you think this is wrong, contact Agent X support before paying the invoice again.",
  },
  // About a payment (0065, partner decision 37b), to every admin: between them and their bank (decision 38).
  payment_contradicted: {
    subject: () => "Agent X: the bank's answer on a payment changed",
    firstLine: () =>
      `The bank's answer about a payment from one of your organisations went back on what it said before. Agent X keeps the payment as it was. ${KEEPS_CHECKING}`,
    check: WITH_YOUR_BANK,
  },
  payment_unproven: {
    subject: () => 'Agent X: a payment was rejected without proof',
    firstLine: () =>
      `The bank rejected a payment from one of your organisations but didn't confirm the money stayed in your account. Its amount stays held against your limits. ${KEEPS_CHECKING}`,
    check: WITH_YOUR_BANK,
  },
  payment_still_unknown: {
    subject: () => 'Agent X: a payment still has no final answer',
    firstLine: () =>
      `A payment from one of your organisations has had no final answer from the bank for over a day. Its amount stays held against your limits. ${KEEPS_CHECKING}`,
    check: WITH_YOUR_BANK,
  },
};

const NEWLINE = '\n';

/** What a notice is about, by its ID alone: a membership, a person, an agent, a mandate, the organisation, a spend request, an audit log entry, a payment, a supplier, or a registered contact. */
function aboutLine(notice: ClaimedNotice): string {
  if (notice.membershipId !== null) return `Membership: ${notice.membershipId}`;
  const id = notice.aboutId ?? '';
  if (isAboutAPerson(notice.kind)) return `Person: ${id}`;
  if (isAboutAnAgent(notice.kind)) return `Agent: ${id}`;
  if (isAboutAMandate(notice.kind)) return `Mandate: ${id}`;
  if (isAboutTheOrganization(notice.kind)) return `Organisation: ${id}`;
  if (isAboutASpendRequest(notice.kind)) return `Spend request: ${id}`;
  if (isAboutAnAuditEntry(notice.kind)) return `Audit log entry: ${id}`;
  if (isAboutAPayment(notice.kind)) return `Payment: ${id}`;
  return isAboutASupplier(notice.kind) ? `Supplier: ${id}` : `Registered contact: ${id}`;
}

function article(word: string): string {
  return /^[aeiou]/.test(word) ? 'an' : 'a';
}

/** A time as the Pilot's people read it: 17 Oct 2026, 16:05 in the UAE (UTC+4, no daylight saving). */
const UAE_TIME = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'Asia/Dubai',
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
});

const uaeTime = (at: Date): string => UAE_TIME.format(at);

/** The waiting request's own lines, between the email's first line and what to do. */
function requestLines(request: WaitingRequest): string[] {
  return [
    `Amount: ${amountText(request.amountMinor, request.currency)}`,
    `Supplier: ${request.supplierName}`,
    `AI agent: ${request.agentName} (ID ${request.agentId})`,
    `Expires: ${uaeTime(request.expiresAt)} UAE time (${request.expiresAt.toISOString()})`,
    `Agent X: ${request.consoleUrl}`,
  ];
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
 * The email telling a supplier it was paid (Phase 4 C2b): the payment's four
 * facts alone, plain text, no link; never the organisation's or anyone's ID.
 */
function remittanceMessage(notice: ClaimedNotice, to: string, paid: PaidRemittance): NoticeMessage {
  return {
    id: notice.id,
    to,
    subject: `${WORDING[REMITTANCE_KIND].subject('')} by ${paid.payerName}`,
    text: [
      `${paid.payerName} sent you a payment through Agent X.`,
      '',
      `Amount: ${amountText(paid.amountMinor, paid.currency)}`,
      `Invoice number: ${paid.invoiceNumber}`,
      `Bank reference: ${paid.bankReference} (as your bank shows it)`,
      '',
      `If you didn't expect this payment, contact ${paid.payerName} by a way you already trust, never by replying to this email.`,
      '',
      "You're told because they chose to email you when they pay you. This email is for your records: it can't change anything, and Agent X never asks for a password, a code or bank details by email.",
    ].join(NEWLINE),
  };
}

/** Why the recipient is told: as a contact, as the person the login is, as an agent's new owner, as an admin or approver (a mandate, a policy, the organisation's freeze or a request waiting), or as an admin. */
function whyTold(notice: ClaimedNotice): string {
  if (notice.recipientContactId !== null) {
    return "You're told because this address is one of the organisation's registered contacts.";
  }
  // The kind check keeps a notice with neither (both null) from reading as one's own login.
  if (isAboutAPerson(notice.kind) && notice.recipientUserId === notice.aboutId) {
    return "You're told because this is your own login.";
  }
  if (notice.kind === 'agent_handed_to_you') return "You're told because you're the agent's new owner.";
  if (isToAdminsAndApprovers(notice.kind))
    return "You're told because you're an admin or approver of this organisation.";
  return "You're told because you're an admin of this organisation.";
}

/**
 * The email telling `to` of the notice. The notice asking a contact to
 * confirm a reset takes its link, and a remittance the payment it tells of,
 * and no other notice takes either: any mismatch is a bug, and throws.
 */
export function messageFor(
  notice: ClaimedNotice,
  to: string,
  link?: ResetLink,
  request?: WaitingRequest,
  paid?: PaidRemittance,
): NoticeMessage {
  const remittance = notice.kind === REMITTANCE_KIND;
  if (remittance !== (paid !== undefined)) {
    throw new RangeError('a remittance, and only it, is sent with the payment it tells of');
  }
  if (paid !== undefined) {
    if (link !== undefined || request !== undefined) throw new RangeError('a remittance carries its payment alone');
    return remittanceMessage(notice, to, paid);
  }
  if (notice.kind === RESET_LINK_KIND) {
    if (link === undefined) throw new RangeError("a reset's link notice is sent with its link");
    return linkMessage(notice, to, link);
  }
  if (link !== undefined) throw new RangeError("only a reset's link notice carries a link");
  const waiting = notice.kind === 'spend_request_waiting';
  if (waiting !== (request !== undefined)) {
    throw new RangeError("a waiting request's notice, and only it, is sent with the request");
  }
  const role = notice.role === null ? '' : ROLE_NAMES[notice.role];
  const wording = WORDING[notice.kind];
  const why = whyTold(notice);
  return {
    id: notice.id,
    to,
    subject: wording.subject(role),
    text: [
      wording.firstLine(role),
      '',
      ...(request === undefined ? [] : [...requestLines(request), '']),
      wording.check,
      '',
      `Organisation: ${notice.orgId}`,
      aboutLine(notice),
      '',
      `${why} This email can't approve or change anything.`,
    ].join(NEWLINE),
  };
}
