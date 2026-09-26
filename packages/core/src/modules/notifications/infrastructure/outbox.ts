// The notifications outbox (ADR-003 §10, ADR-007; Phase 1 B5-1a): notices to
// one person each, written in the change's own transaction, then sent by the
// API's sender (B5-1b).
//
// - `add` writes notices on the handle it is given: the change's transaction,
//   so a notice commits or rolls back with what it tells of. Everything must
//   be well formed, or nothing is written: a bug, never a partial write.
// - `claimDue` takes up to a batch of due notices, soonest first, and moves
//   each one's next try on by the lease, in one statement: a sender that dies
//   mid-send leaves the notice to be tried again once the lease runs out, and
//   two senders never take the same notice (`SKIP LOCKED`). A notice may so be
//   sent twice after a crash; the provider is given its ID to tell (B5-3).
// - `sent` marks a notice sent; `failed` counts a failed try and sets the next
//   one further off each time, or gives the notice up after MOST_ATTEMPTS, or
//   at once for a failure no retry can mend. Neither touches a notice already
//   sent or given up.
// - `sweep` deletes notices sent or given up past the retention, oldest first.
//
// Each but `add` runs in a transaction of its own whose statements give up
// after 10 seconds, a wait for a lock included. The times are the Clock's.
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import type { NotificationsTables } from './tables.ts';

export const NOTICE_KINDS = ['role_granted', 'member_rejoined'] as const;
export type NoticeKind = (typeof NOTICE_KINDS)[number];

const ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;
type NoticeRole = (typeof ROLES)[number];

/** How many times a notice is tried before it is given up. */
export const MOST_ATTEMPTS = 8;

/** How long a claimed notice is left to its sender before it is due again. */
export const CLAIM_LEASE_MS = 10 * 60_000;

/** The waits before each try after a failed one: a minute, then longer, to six hours. */
const BACKOFF_MS = [60_000, 5 * 60_000, 15 * 60_000, 60 * 60_000, 2 * 3_600_000, 4 * 3_600_000, 6 * 3_600_000];

/** How long a notice sent or given up is kept. */
export const OUTBOX_RETENTION_DAYS = 30;

/** The most notices one `add` writes, or one `claimDue` takes. */
export const MOST_NOTICES_A_BATCH = 100;

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

export interface Outbox {
  /** Writes these notices on the change's own transaction, at most MOST_NOTICES_A_BATCH. Throws RangeError for anything malformed, writing nothing. */
  add(tx: Kysely<NotificationsTables>, notices: readonly Notice[]): Promise<void>;
  /** Takes up to `most` due notices, soonest first, each held for the lease. */
  claimDue(db: Kysely<NotificationsTables>, most: number): Promise<ClaimedNotice[]>;
  /** Marks the notice sent; false if it was already sent or given up. */
  sent(db: Kysely<NotificationsTables>, id: string): Promise<boolean>;
  /**
   * Counts a failed try, `failure` a short constant saying why: the next is set
   * further off, or the notice given up once it has had MOST_ATTEMPTS, or at
   * once when `lasting`. Says what became of it; `done` if it was already sent
   * or given up.
   */
  failed(
    db: Kysely<NotificationsTables>,
    id: string,
    failure: string,
    lasting: boolean,
  ): Promise<'retry' | 'given_up' | 'done'>;
  /** Deletes up to `most` notices sent or given up past the retention, oldest first, and says how many. */
  sweep(db: Kysely<NotificationsTables>, most: number): Promise<number>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FAILURE = /^[a-z][a-z_]{0,63}$/;
const DAY_MS = 86_400_000;

const isKind = (value: unknown): value is NoticeKind => NOTICE_KINDS.some((kind) => kind === value);
const isRole = (value: unknown): value is NoticeRole => ROLES.some((role) => role === value);
const isId = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);

/** Why a notice can't be written, if it can't. */
function problemWith(notice: Notice): string | undefined {
  if (!isId(notice.orgId)) return 'its organisation is not a UUID';
  if (!isId(notice.recipientUserId)) return 'its recipient is not a UUID';
  if (!isKind(notice.kind)) return 'its kind is not one we send';
  if (!isId(notice.membershipId)) return 'its membership is not a UUID';
  if (!isRole(notice.role)) return 'its role is not one of the four';
  return undefined;
}

/** The wait before the try after `attempts` failed ones. */
const backoffAfter = (attempts: number): number => BACKOFF_MS[Math.min(attempts, BACKOFF_MS.length) - 1] ?? 0;

export function createOutbox({ ids, clock }: { readonly ids: IdGenerator; readonly clock: Clock }): Outbox {
  /** Runs the work in a transaction of its own, each statement limited to 10 seconds, a wait for a lock included. */
  const limited = <T>(db: Kysely<NotificationsTables>, work: (tx: Kysely<NotificationsTables>) => Promise<T>) =>
    db.transaction().execute(async (tx) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return work(tx);
    });

  const atLeastOne = (most: number, what: string): void => {
    if (!Number.isSafeInteger(most) || most < 1 || most > MOST_NOTICES_A_BATCH) {
      throw new RangeError(`${what} 1 to ${String(MOST_NOTICES_A_BATCH)} notices at a time`);
    }
  };

  return {
    async add(tx, notices) {
      if (notices.length === 0) return;
      if (notices.length > MOST_NOTICES_A_BATCH) {
        throw new RangeError(`at most ${String(MOST_NOTICES_A_BATCH)} notices are written at a time`);
      }
      for (const notice of notices) {
        const problem = problemWith(notice);
        if (problem !== undefined) throw new RangeError(`a notice can't be written: ${problem}`);
      }
      const now = clock.now();
      await tx
        .insertInto('notifications.outbox')
        .values(
          notices.map((notice) => ({
            id: ids.next(),
            org_id: notice.orgId.toLowerCase(),
            recipient_user_id: notice.recipientUserId.toLowerCase(),
            kind: notice.kind,
            membership_id: notice.membershipId.toLowerCase(),
            role: notice.role,
            created_at: now,
            attempts: 0,
            next_attempt_at: now,
          })),
        )
        .execute();
    },

    async claimDue(db, most) {
      atLeastOne(most, 'a claim takes');
      const now = clock.now();
      return limited(db, async (tx) => {
        const due = tx
          .selectFrom('notifications.outbox')
          .select('id')
          .where('sent_at', 'is', null)
          .where('given_up_at', 'is', null)
          .where('next_attempt_at', '<=', now)
          .orderBy('next_attempt_at')
          .orderBy('id')
          .limit(most)
          .forUpdate()
          .skipLocked();
        const rows = await tx
          .updateTable('notifications.outbox')
          .set({ next_attempt_at: new Date(now.getTime() + CLAIM_LEASE_MS) })
          .where('id', 'in', due)
          .returning(['id', 'org_id', 'recipient_user_id', 'kind', 'membership_id', 'role', 'created_at', 'attempts'])
          .execute();
        return rows
          .map((row) => {
            if (!isKind(row.kind) || !isRole(row.role)) {
              throw new Error("a notice's kind or role is not one the table allows");
            }
            return {
              id: row.id,
              orgId: row.org_id,
              recipientUserId: row.recipient_user_id,
              kind: row.kind,
              membershipId: row.membership_id,
              role: row.role,
              createdAt: row.created_at,
              attempts: row.attempts,
            };
          })
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id));
      });
    },

    async sent(db, id) {
      if (!isId(id)) return false;
      const now = clock.now();
      return limited(db, async (tx) => {
        const row = await tx
          .updateTable('notifications.outbox')
          .set({ sent_at: now })
          .where('id', '=', id)
          .where('sent_at', 'is', null)
          .where('given_up_at', 'is', null)
          .returning('id')
          .executeTakeFirst();
        return row !== undefined;
      });
    },

    async failed(db, id, failure, lasting) {
      if (!FAILURE.test(failure)) throw new RangeError("a notice's failure is not a short lowercase name");
      if (!isId(id)) return 'done';
      const now = clock.now();
      return limited(db, async (tx) => {
        const row = await tx
          .selectFrom('notifications.outbox')
          .select('attempts')
          .where('id', '=', id)
          .where('sent_at', 'is', null)
          .where('given_up_at', 'is', null)
          .forUpdate()
          .executeTakeFirst();
        if (row === undefined) return 'done';
        const attempts = row.attempts + 1;
        const givenUp = lasting || attempts >= MOST_ATTEMPTS;
        await tx
          .updateTable('notifications.outbox')
          .set({
            attempts,
            last_failure: failure,
            ...(givenUp ? { given_up_at: now } : { next_attempt_at: new Date(now.getTime() + backoffAfter(attempts)) }),
          })
          .where('id', '=', id)
          .execute();
        return givenUp ? 'given_up' : 'retry';
      });
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1)
        throw new RangeError('a sweep deletes at least one notice at a time');
      const past = new Date(clock.now().getTime() - OUTBOX_RETENTION_DAYS * DAY_MS);
      return limited(db, async (tx) => {
        const oldest = tx
          .selectFrom('notifications.outbox')
          .select('id')
          .where((eb) => eb.or([eb('sent_at', 'is not', null), eb('given_up_at', 'is not', null)]))
          .where('created_at', '<=', past)
          .orderBy('created_at')
          .limit(most);
        // A notice done is never changed again, so the rows found are still done when deleted.
        const rows = await tx.deleteFrom('notifications.outbox').where('id', 'in', oldest).returning('id').execute();
        return rows.length;
      });
    },
  };
}
