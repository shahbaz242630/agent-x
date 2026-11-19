// A notice sealed as it is queued and as it ends (S206 V4, Threat-Model R-15;
// 0105): notifications.outbox is global and holds no signed state, and the
// sender reads whom to tell from the row, so a notice is believed only with
// the MACs the app made of it, with a key the database never holds.
//
// - Queued (`notice-v1`): its ID, organisation, recipient (a person, a
//   contact, or a group: the contacts or the admins, found as it is sent),
//   kind, membership, role, what it is about and when it was queued. A notice
//   moved to another person or contact, or planted whole, no longer matches; a
//   MAC copied to another notice names the first.
// - Ended (`notice-end-v1`): its ID, sent or given up, and why it was given
//   up. A notice marked sent or given up by anyone else has none that holds.
//
// The key is `audit-mac`: both processes that queue notices hold it (the API
// and the operator's command, which holds no other MAC key), and a notice's
// seal is evidence beside its `notice.queued` record on the same chain. The
// labels keep its messages apart from the chain's own (`audit-event`,
// `audit-head`, a state's).
import { KeyError, type KeyProvider, type Message } from '@agentx/platform/keys';

const QUEUED_LABEL = 'notice-v1';
const ENDED_LABEL = 'notice-end-v1';
const KEY = 'audit-mac';

/** An absent field: never a value, as every kept one is a UUID or a word. */
const NONE = '';

/** A notice's columns its queued seal binds, as the outbox keeps them. */
export interface QueuedColumns {
  readonly id: string;
  readonly org_id: string;
  readonly recipient_user_id: string | null;
  readonly recipient_contact_id: string | null;
  readonly to_contacts: boolean;
  readonly kind: string;
  readonly membership_id: string | null;
  readonly role: string | null;
  readonly about_id: string | null;
  readonly created_at: Date;
}

/** A seal as the outbox's columns keep it. */
export interface NoticeSeal {
  readonly mac: Buffer;
  readonly keyVersion: number;
}

/**
 * How a notice's seal reads: as the app made it, or not its own. One with none is not its own either: the notices
 * queued before seals were sealed once, as the first release with them started (apps/api/src/notice-legacy.ts).
 */
export type SealJudged = 'sound' | 'tampered';

const queuedMessage = (row: QueuedColumns): Message => [
  QUEUED_LABEL,
  row.id.toLowerCase(),
  row.org_id.toLowerCase(),
  row.recipient_user_id?.toLowerCase() ?? NONE,
  row.recipient_contact_id?.toLowerCase() ?? NONE,
  row.to_contacts ? 'contacts' : NONE,
  row.kind,
  row.membership_id?.toLowerCase() ?? NONE,
  row.role ?? NONE,
  row.about_id?.toLowerCase() ?? NONE,
  row.created_at.toISOString(),
];

/** How a notice ended, as its end seal binds it: sent, or given up and why. */
export type NoticeEnd = { readonly outcome: 'sent' } | { readonly outcome: 'given_up'; readonly failure: string };

const endedMessage = (id: string, end: NoticeEnd): Message => [
  ENDED_LABEL,
  id.toLowerCase(),
  end.outcome,
  end.outcome === 'given_up' ? end.failure : NONE,
];

const sealOf = (keys: KeyProvider, message: Message): NoticeSeal => {
  const { mac, keyVersion } = keys.mac(KEY, message);
  return { mac, keyVersion };
};

/** The seal of a notice as it is queued, with the current key. */
export const queuedSeal = (keys: KeyProvider, row: QueuedColumns): NoticeSeal => sealOf(keys, queuedMessage(row));

/** The seal of a notice's end, with the current key. */
export const endSeal = (keys: KeyProvider, id: string, end: NoticeEnd): NoticeSeal =>
  sealOf(keys, endedMessage(id, end));

/** Whether a MAC, as read, holds for the message: one taken out, cut short or of a version not held holds for nothing. */
function holds(keys: KeyProvider, message: Message, mac: unknown, version: unknown): boolean {
  if (!Buffer.isBuffer(mac) || typeof version !== 'number' || !Number.isSafeInteger(version)) return false;
  try {
    return keys.verifyMac(KEY, version, message, mac);
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/** Whether a notice, as read, is the one the app queued. */
export const queuedJudged = (
  keys: KeyProvider,
  row: QueuedColumns & { readonly mac: unknown; readonly mac_key_version: unknown },
): SealJudged => (holds(keys, queuedMessage(row), row.mac, row.mac_key_version) ? 'sound' : 'tampered');

/** A notice's end as read: its outcome's columns and its end seal. */
export interface EndColumns {
  readonly id: string;
  readonly sent_at: Date | null;
  readonly given_up_at: Date | null;
  readonly last_failure: string | null;
  readonly end_mac: unknown;
  readonly end_key_version: unknown;
}

/** Whether a notice ended, as read, ended as the app sealed it: `open` for one not ended. */
export function endJudged(keys: KeyProvider, row: EndColumns): 'open' | 'sound' | 'tampered' {
  if (row.sent_at === null && row.given_up_at === null) return 'open';
  const end: NoticeEnd =
    row.sent_at === null ? { outcome: 'given_up', failure: row.last_failure ?? NONE } : { outcome: 'sent' };
  return holds(keys, endedMessage(row.id, end), row.end_mac, row.end_key_version) ? 'sound' : 'tampered';
}
