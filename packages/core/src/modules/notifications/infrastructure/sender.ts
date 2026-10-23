// The notice sender (ADR-003 §10; B5-1b): takes the outbox's due notices a
// batch at a time and sends each through the notifier, to the address the
// address book gives for its recipient at send time, from the login service
// (the copy Agent X keeps names people in the audit log only, decision 25).
//
// - A notice to the organisation's admins is turned into one to each active
//   admin the audience finds, but the member it is about (`fanOut`), and
//   those are sent in the same run; a notice to its registered contacts
//   (B6-1b) into one to each ACTIVE contact the audience finds. A notice
//   about a supplier (E2-2b, ADR-012 §1: "every member plus its registered
//   contacts") goes to every active member, whatever their role, and to the
//   contacts that count now (7 days after they are confirmed), as a reset's
//   confirmation does. An audience that can't be read leaves it to be tried
//   again (`audience_unavailable`).
// - A contact's address is its own row's, decrypted at send time (B6-1b); a
//   person's is the login service's.
// - A notice asking a contact to confirm a reset (B6-3b) is sent with that
//   contact's link, read at send time from the reset's own verified row and
//   the secret written for the contact; a reset no longer waiting for a
//   contact gives the notice up at once (`reset_closed`), as its link would do
//   nothing; links that can't be read leave it to be tried again
//   (`link_unavailable`).
// - A remittance (Phase 4 C2b, 0062: a payment to a supplier SUCCEEDED) goes
//   to the supplier itself: what it carries, its address and the setting are
//   read at send time from the payment's verified records (`Remittances`). The
//   setting `off` (decision 34b), or the payment no longer SUCCEEDED, gives it
//   up at once, logged with why (`remittance_off`, `payment_not_succeeded`); a
//   supplier version with no email (decision 34c) passes it on to the
//   organisation's admins (`no_address`), who are told instead; records that
//   can't be read or believed leave it to be tried again
//   (`payment_unavailable`).
// - A notice sent is marked sent. A failed send is counted as the notifier
//   says: tried again later, or given up at once when no retry can mend it.
// - A recipient with no address gives the notice up at once (`no_address`);
//   an address book that can't be reached leaves it to be tried again
//   (`address_unavailable`).
// - Anything else thrown by the notifier, or a failure it names in anything
//   but a short constant, or by the outbox's own LEASE_EXPIRED, is counted as
//   a failed try (`send_error`, `send_failed`), never lost: the next notice
//   is still sent (review).
// - A run stops between notices once its signal is aborted; a notice it had
//   claimed and not reached is taken again once its lease runs out.
// - A run never throws (review): the outbox away, or a statement past its
//   limit, is logged (`notification.run_failed`) and the run ends, so the
//   API's timer takes the next one as usual; the notices it held wait for
//   their lease.
//
// Its log lines name the notice, its kind and how it went: never the
// address, never a link, and never the provider's own words.
import type { Logger } from '@agentx/platform/observability';
import type { Kysely } from 'kysely';

import {
  messageFor,
  type NoticeMessage,
  type PaidRemittance,
  type ResetLink,
  type WaitingRequest,
} from '../domain/messages.ts';
import {
  type ClaimedNotice,
  isAboutAPerson,
  isAboutASupplier,
  isToAdminsAndApprovers,
  REMITTANCE_KIND,
  REMITTANCE_NO_EMAIL_KIND,
  RESET_LINK_KIND,
} from '../domain/notice.ts';
import { LEASE_EXPIRED, type Outbox } from './outbox.ts';
import type { NotificationsTables } from './tables.ts';

/** How a send went, as the notifier tells it. */
export type SendOutcome =
  | { readonly outcome: 'sent' }
  /** `failure` a short constant; `lasting` when no retry can mend it (an address refused). */
  | { readonly outcome: 'failed'; readonly failure: string; readonly lasting: boolean };

/** Sends an email: Azure Communication Services on staging (B5-3), a fake in tests. */
export interface Notifier {
  send(message: NoticeMessage): Promise<SendOutcome>;
}

/** Finds a person's email address at send time, by their user ID: the login service's (B5-3). */
export interface AddressBook {
  /** Their verified address; undefined if they have none. Throws if it can't be asked. */
  addressOf(userId: string): Promise<string | undefined>;
}

/** Finds a registered contact's address at send time, from its own row (B6-1b): identity's, which the API wires. */
export interface ContactAddresses {
  /**
   * The contact's address, from its verified row, removed ones included (a
   * contact is told of its own removal); undefined for a draft or none.
   * Throws if it can't be read, or can't be believed.
   */
  addressOf(orgId: string, contactId: string): Promise<string | undefined>;
}

/** Finds a registered contact's link to confirm a reset, at send time (B6-3b): identity's, which the API wires. */
export interface ResetLinks {
  /**
   * The contact's link for the reset, and when the reset lapses; undefined
   * when the reset no longer waits for a contact, or no link was written for
   * the contact. Throws if it can't be read, or can't be believed.
   */
  linkFor(orgId: string, resetId: string, contactId: string): Promise<ResetLink | undefined>;
}

/** Finds a spend request waiting for approval, at send time (Phase 3 B2): the spend-requests', which the API wires. */
export interface WaitingRequests {
  /**
   * The request as the email shows it; undefined when it no longer waits
   * (approved, rejected, expired or cancelled since) or can't be believed.
   * Throws if it can't be read.
   */
  waitingOf(orgId: string, requestId: string): Promise<WaitingRequest | undefined>;
}

/** A paid supplier's email, as read at send time (Phase 4 C2b). */
export type RemittanceRead =
  | { readonly outcome: 'send'; readonly to: string; readonly paid: PaidRemittance }
  /** Its setting is `off` (partner decision 34b): nothing is sent. */
  | { readonly outcome: 'off' }
  /** The version its instruction names holds no email (decision 34c): the admins are told instead. */
  | { readonly outcome: 'no_email' }
  /** The payment is no longer SUCCEEDED: nothing is sent. */
  | { readonly outcome: 'not_succeeded' };

/** Finds a payment's remittance at send time (Phase 4 C2b): from its verified records, which the API wires. */
export interface Remittances {
  /** The supplier's email for the payment, or why there is none. Throws if its records can't be read, or can't be believed. */
  remittanceOf(orgId: string, transactionId: string): Promise<RemittanceRead>;
}

/** Why a remittance is given up at once, as the outbox keeps it. */
const REMITTANCE_SKIPPED = { off: 'remittance_off', not_succeeded: 'payment_not_succeeded' } as const;

/** An organisation's active admin, as their verified membership says. */
export interface Admin {
  readonly userId: string;
  readonly membershipId: string;
}

/** Finds an organisation's groups at send time: identity's verified memberships and contacts, which the API wires. */
export interface Audience {
  /** Its active admins, each verified. Throws if they can't be read, or can't be believed. */
  adminsOf(orgId: string): Promise<readonly Admin[]>;
  /** Its active admins' and approvers' user IDs, each verified (0036). Throws if they can't be read, or can't be believed. */
  adminsAndApproversOf(orgId: string): Promise<readonly string[]>;
  /** Its active members' user IDs, every role, each verified (E2-2b). Throws if they can't be read, or can't be believed. */
  membersOf(orgId: string): Promise<readonly string[]>;
  /** Its ACTIVE registered contacts' IDs, each verified (B6-1b). Throws if they can't be read, or can't be believed. */
  contactsOf(orgId: string): Promise<readonly string[]>;
  /** Those of them that count now (E2-2b), each verified. Throws if they can't be read, or can't be believed. */
  countingContactsOf(orgId: string): Promise<readonly string[]>;
}

/** How many notices a run takes at a time. */
export const NOTICES_A_RUN = 20;

const FAILURE = /^[a-z][a-z_]{0,63}$/;

export interface NoticeSender {
  /** Sends the due notices, a batch at a time, until none is due or the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createNoticeSender({
  db,
  outbox,
  notifier,
  addresses,
  contactAddresses,
  resetLinks,
  waitingRequests,
  remittances,
  audience,
  logger,
}: {
  readonly db: Kysely<NotificationsTables>;
  readonly outbox: Outbox;
  readonly notifier: Notifier;
  readonly addresses: AddressBook;
  readonly contactAddresses: ContactAddresses;
  readonly resetLinks: ResetLinks;
  readonly waitingRequests: WaitingRequests;
  readonly remittances: Remittances;
  readonly audience: Audience;
  readonly logger: Logger;
}): NoticeSender {
  /** Counts the try as failed, and logs how it went. */
  const failed = async (notice: ClaimedNotice, failure: string, lasting: boolean): Promise<void> => {
    const became = await outbox.failed(db, notice.id, failure, lasting);
    logger.warn('notification.failed', {
      noticeId: notice.id,
      kind: notice.kind,
      attempt: notice.attempts + 1,
      failure,
      outcome: became,
    });
  };

  /**
   * The group's members a notice to it goes to: the ACTIVE contacts, or the
   * admins but the member it is about, by their membership, or, for a notice
   * about a person (their sign-in, or a reset of their second factor), by
   * their user ID (B6-2a review): that person is told apart, as themselves,
   * once. A notice about a supplier: the contacts that count now, or every
   * active member (E2-2b). A notice about a mandate, the organisation's
   * policy or freeze, or a spend request waiting: every admin and approver
   * (0036, 0038, 0045).
   */
  const groupOf = async (notice: ClaimedNotice): Promise<readonly string[]> => {
    if (isAboutASupplier(notice.kind)) {
      return notice.toContacts ? audience.countingContactsOf(notice.orgId) : audience.membersOf(notice.orgId);
    }
    if (isToAdminsAndApprovers(notice.kind)) return audience.adminsAndApproversOf(notice.orgId);
    if (notice.toContacts) return audience.contactsOf(notice.orgId);
    const aboutPerson = isAboutAPerson(notice.kind) ? notice.aboutId : null;
    const admins = await audience.adminsOf(notice.orgId);
    return admins
      .filter(
        ({ membershipId, userId }) => membershipId !== notice.membershipId && userId.toLowerCase() !== aboutPerson,
      )
      .map(({ userId }) => userId);
  };

  /** Turns a notice to a group into one to each of its members. */
  const fanOut = async (notice: ClaimedNotice): Promise<void> => {
    let recipients: readonly string[];
    try {
      recipients = await groupOf(notice);
    } catch {
      await failed(notice, 'audience_unavailable', false);
      return;
    }
    const written = await outbox.fanOut(db, notice.id, recipients);
    // Not open: another sender turned it first, or it was given up for good meanwhile.
    if (written === 'not_open') return;
    logger.info('notification.fanned_out', { noticeId: notice.id, kind: notice.kind, notices: written });
  };

  /**
   * What a notice is sent with, read at send time: a reset's link (B6-3b) or
   * a waiting spend request (Phase 3 B2); undefined once that read has failed
   * and the try is recorded as failed.
   */
  const extrasOf = async (
    notice: ClaimedNotice,
  ): Promise<{ readonly link?: ResetLink; readonly request?: WaitingRequest } | undefined> => {
    if (notice.kind === RESET_LINK_KIND) {
      let link: ResetLink | undefined;
      try {
        // The outbox writes a link notice to one contact, and about the reset, only.
        link = await resetLinks.linkFor(notice.orgId, notice.aboutId ?? '', notice.recipientContactId ?? '');
      } catch {
        await failed(notice, 'link_unavailable', false);
        return undefined;
      }
      if (link === undefined) {
        await failed(notice, 'reset_closed', true);
        return undefined;
      }
      return { link };
    }
    if (notice.kind === 'spend_request_waiting') {
      let request: WaitingRequest | undefined;
      try {
        request = await waitingRequests.waitingOf(notice.orgId, notice.aboutId ?? '');
      } catch {
        await failed(notice, 'request_unavailable', false);
        return undefined;
      }
      // Decided, expired or cancelled before its email went: nothing waits for anyone now.
      if (request === undefined) {
        await failed(notice, 'request_not_waiting', true);
        return undefined;
      }
      return { request };
    }
    return {};
  };

  /** Sends one notice to its recipient and records how it went. */
  const sendOne = async (notice: ClaimedNotice): Promise<void> => {
    let address: string | undefined;
    try {
      address =
        notice.recipientContactId === null
          ? await addresses.addressOf(notice.recipientUserId ?? '')
          : await contactAddresses.addressOf(notice.orgId, notice.recipientContactId);
    } catch {
      await failed(notice, 'address_unavailable', false);
      return;
    }
    if (address === undefined) {
      await failed(notice, 'no_address', true);
      return;
    }
    const extras = await extrasOf(notice);
    if (extras === undefined) return;
    await sendAndRecord(notice, messageFor(notice, address, extras.link, extras.request));
  };

  /** Sends the notice's email and records how it went. */
  const sendAndRecord = async (notice: ClaimedNotice, message: NoticeMessage): Promise<void> => {
    let sent: SendOutcome;
    try {
      sent = await notifier.send(message);
    } catch {
      await failed(notice, 'send_error', false);
      return;
    }
    if (sent.outcome === 'failed') {
      const keptAs = FAILURE.test(sent.failure) && sent.failure !== LEASE_EXPIRED ? sent.failure : 'send_failed';
      await failed(notice, keptAs, sent.lasting);
      return;
    }
    await outbox.sent(db, notice.id);
    logger.info('notification.sent', { noticeId: notice.id, kind: notice.kind, attempt: notice.attempts + 1 });
  };

  /**
   * Sends a remittance to its paid supplier, as its records say at send time;
   * or gives it up, or passes it on to the admins, logged with why. Says
   * whether it wrote a notice in its place.
   */
  const sendRemittance = async (notice: ClaimedNotice): Promise<boolean> => {
    let read: RemittanceRead;
    try {
      // The outbox writes a remittance about its transaction only.
      read = await remittances.remittanceOf(notice.orgId, notice.aboutId ?? '');
    } catch {
      await failed(notice, 'payment_unavailable', false);
      return false;
    }
    if (read.outcome === 'send') {
      await sendAndRecord(notice, messageFor(notice, read.to, undefined, undefined, read.paid));
      return false;
    }
    if (read.outcome === 'no_email') {
      const passed = await outbox.passOn(db, notice.id, REMITTANCE_NO_EMAIL_KIND, 'no_address');
      if (passed) logger.info('notification.remittance_skipped', { noticeId: notice.id, why: 'no_email' });
      return passed;
    }
    const became = await outbox.failed(db, notice.id, REMITTANCE_SKIPPED[read.outcome], true);
    logger.info('notification.remittance_skipped', { noticeId: notice.id, why: read.outcome, outcome: became });
    return false;
  };

  /** Fans out a notice to no one in particular, or sends one to its recipient; says whether it wrote notices due now. */
  const deliver = async (notice: ClaimedNotice): Promise<boolean> => {
    if (notice.kind === REMITTANCE_KIND) return sendRemittance(notice);
    if (notice.recipientUserId === null && notice.recipientContactId === null) {
      await fanOut(notice);
      return true;
    }
    await sendOne(notice);
    return false;
  };

  return {
    async run(signal) {
      try {
        await runBatches(signal);
      } catch (error) {
        logger.warn('notification.run_failed', { err: error });
      }
    },
  };

  /** Claims and sends batches until none is due or the signal is aborted. */
  async function runBatches(signal: AbortSignal | undefined): Promise<void> {
    const stopped = (): boolean => signal?.aborted === true;
    for (;;) {
      if (stopped()) return;
      const due = await outbox.claimDue(db, NOTICES_A_RUN);
      let wroteMore = false;
      for (const notice of due) {
        if (stopped()) return;
        if (await deliver(notice)) wroteMore = true;
      }
      // A full batch may have left more due, and a fan-out or a notice passed on has just made some.
      if (due.length < NOTICES_A_RUN && !wroteMore) return;
    }
  }
}
