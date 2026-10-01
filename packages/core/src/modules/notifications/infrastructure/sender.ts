// The notice sender (ADR-003 §10; B5-1b): takes the outbox's due notices a
// batch at a time and sends each through the notifier, to the address the
// address book gives for its recipient at send time (Agent X keeps none).
//
// - A notice to the organisation's admins is turned into one to each active
//   admin the audience finds, but the member it is about (`fanOut`), and
//   those are sent in the same run; a notice to its registered contacts
//   (B6-1b) into one to each ACTIVE contact the audience finds. An audience
//   that can't be read leaves it to be tried again (`audience_unavailable`).
// - A contact's address is its own row's, decrypted at send time (B6-1b); a
//   person's is the login service's.
// - A notice asking a contact to confirm a reset (B6-3b) is sent with that
//   contact's link, read at send time from the reset's own verified row and
//   the secret written for the contact; a reset no longer waiting for a
//   contact gives the notice up at once (`reset_closed`), as its link would do
//   nothing; links that can't be read leave it to be tried again
//   (`link_unavailable`).
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

import { messageFor, type NoticeMessage, type ResetLink } from '../domain/messages.ts';
import { type ClaimedNotice, isAboutAPerson, RESET_LINK_KIND } from '../domain/notice.ts';
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

/** An organisation's active admin, as their verified membership says. */
export interface Admin {
  readonly userId: string;
  readonly membershipId: string;
}

/** Finds an organisation's groups at send time: identity's verified memberships and contacts, which the API wires. */
export interface Audience {
  /** Its active admins, each verified. Throws if they can't be read, or can't be believed. */
  adminsOf(orgId: string): Promise<readonly Admin[]>;
  /** Its ACTIVE registered contacts' IDs, each verified (B6-1b). Throws if they can't be read, or can't be believed. */
  contactsOf(orgId: string): Promise<readonly string[]>;
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
  audience,
  logger,
}: {
  readonly db: Kysely<NotificationsTables>;
  readonly outbox: Outbox;
  readonly notifier: Notifier;
  readonly addresses: AddressBook;
  readonly contactAddresses: ContactAddresses;
  readonly resetLinks: ResetLinks;
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
   * once.
   */
  const groupOf = async (notice: ClaimedNotice): Promise<readonly string[]> => {
    if (notice.toContacts) return audience.contactsOf(notice.orgId);
    const aboutPerson = isAboutAPerson(notice.kind) ? notice.aboutId : null;
    const admins = await audience.adminsOf(notice.orgId);
    return admins
      .filter(
        ({ membershipId, userId }) =>
          membershipId.toLowerCase() !== notice.membershipId && userId.toLowerCase() !== aboutPerson,
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
    let link: ResetLink | undefined;
    if (notice.kind === RESET_LINK_KIND) {
      try {
        // The outbox writes a link notice to one contact, and about the reset, only.
        link = await resetLinks.linkFor(notice.orgId, notice.aboutId ?? '', notice.recipientContactId ?? '');
      } catch {
        await failed(notice, 'link_unavailable', false);
        return;
      }
      if (link === undefined) {
        await failed(notice, 'reset_closed', true);
        return;
      }
    }
    let sent: SendOutcome;
    try {
      sent = await notifier.send(messageFor(notice, address, link));
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

  /** Fans out a notice to no one in particular, or sends one to its recipient; says whether it fanned out. */
  const deliver = async (notice: ClaimedNotice): Promise<boolean> => {
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
      let fannedOut = false;
      for (const notice of due) {
        if (stopped()) return;
        if (await deliver(notice)) fannedOut = true;
      }
      // A full batch may have left more due, and a fan-out has just made some.
      if (due.length < NOTICES_A_RUN && !fannedOut) return;
    }
  }
}
