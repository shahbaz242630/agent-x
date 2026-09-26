// The notice sender (ADR-003 §10; B5-1b): takes the outbox's due notices a
// batch at a time and sends each through the notifier, to the address the
// address book gives for its recipient at send time (Agent X keeps none).
//
// - A notice to the organisation's admins is turned into one to each active
//   admin the audience finds, but the member it is about (`fanOut`), and
//   those are sent in the same run. An audience that can't be read leaves it
//   to be tried again (`audience_unavailable`).
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
//
// Its log lines name the notice, its kind and how it went: never the
// address, and never the provider's own words.
import type { Logger } from '@agentx/platform/observability';
import type { Kysely } from 'kysely';

import { messageFor, type NoticeMessage } from '../domain/messages.ts';
import type { ClaimedNotice } from '../domain/notice.ts';
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

/** An organisation's active admin, as their verified membership says. */
export interface Admin {
  readonly userId: string;
  readonly membershipId: string;
}

/** Finds an organisation's active admins at send time: identity's verified memberships, which the API wires. */
export interface Audience {
  /** Its active admins, each verified. Throws if they can't be read, or can't be believed. */
  adminsOf(orgId: string): Promise<readonly Admin[]>;
}

/** How many notices a run takes at a time. */
export const NOTICES_A_RUN = 20;

const FAILURE = /^[a-z][a-z_]{0,63}$/;

export interface NoticeSender {
  /** Sends the due notices, a batch at a time, until none is due or the signal is aborted. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createNoticeSender({
  db,
  outbox,
  notifier,
  addresses,
  audience,
  logger,
}: {
  readonly db: Kysely<NotificationsTables>;
  readonly outbox: Outbox;
  readonly notifier: Notifier;
  readonly addresses: AddressBook;
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

  /** Turns a notice to the admins into one to each, but the member it is about. */
  const fanOut = async (notice: ClaimedNotice): Promise<void> => {
    let admins: readonly Admin[];
    try {
      admins = await audience.adminsOf(notice.orgId);
    } catch {
      await failed(notice, 'audience_unavailable', false);
      return;
    }
    const others = admins.filter(({ membershipId }) => membershipId.toLowerCase() !== notice.membershipId);
    const written = await outbox.fanOut(
      db,
      notice.id,
      others.map(({ userId }) => userId),
    );
    // Not open: another sender turned it first, or it was given up for good meanwhile.
    if (written === 'not_open') return;
    logger.info('notification.fanned_out', { noticeId: notice.id, kind: notice.kind, notices: written });
  };

  /** Sends one notice to its recipient and records how it went. */
  const sendOne = async (notice: ClaimedNotice, recipientUserId: string): Promise<void> => {
    let address: string | undefined;
    try {
      address = await addresses.addressOf(recipientUserId);
    } catch {
      await failed(notice, 'address_unavailable', false);
      return;
    }
    if (address === undefined) {
      await failed(notice, 'no_address', true);
      return;
    }
    let sent: SendOutcome;
    try {
      sent = await notifier.send(messageFor(notice, address));
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

  return {
    async run(signal) {
      const stopped = (): boolean => signal?.aborted === true;
      for (;;) {
        if (stopped()) return;
        const due = await outbox.claimDue(db, NOTICES_A_RUN);
        let fannedOut = false;
        for (const notice of due) {
          if (stopped()) return;
          if (notice.recipientUserId === null) {
            await fanOut(notice);
            fannedOut = true;
          } else {
            await sendOne(notice, notice.recipientUserId);
          }
        }
        // A full batch may have left more due, and a fan-out has just made some.
        if (due.length < NOTICES_A_RUN && !fannedOut) return;
      }
    },
  };
}
