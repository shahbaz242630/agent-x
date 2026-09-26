// The notifications outbox (ADR-003 §10, ADR-007; Phase 1 B5-1a): notices to
// one person each, written in the change's own transaction, then sent by the
// API's sender (B5-1b).
//
// - `add` writes notices in the transaction it is given, the change's own,
//   so a notice commits or rolls back with what it tells of: it takes a
//   transaction and nothing else (review). Everything must be well formed, or
//   nothing is written: a bug, never a partial write.
// - `claimDue` takes up to a batch of due notices, soonest due first, and
//   starts a try of each: it counts the try and moves the next one on by the
//   lease, in one statement. A sender that dies mid-send leaves the notice to
//   be tried again once the lease runs out, and two senders never take the
//   same notice (`SKIP LOCKED`). A notice whose last try's lease ran out is
//   given up (`lease_expired`) rather than taken again, so one that brings its
//   sender down every time is still tried MOST_ATTEMPTS times at most
//   (review). A notice may so be sent twice after a crash; the provider is
//   given its ID to tell (B5-3).
// - `sent` marks a notice sent; `failed` records why a try failed and sets the
//   next one further off each time, or gives the notice up after its
//   MOST_ATTEMPTS-th try, or at once for a failure no retry can mend. Neither
//   touches a notice already sent or given up.
// - `sweep` deletes notices sent or given up past the retention, oldest first.
//
// Each but `add` runs in a transaction of its own whose statements give up
// after 10 seconds, a wait for a lock included. The times are the Clock's.
import { type Kysely, sql, type Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { type ClaimedNotice, isNoticeKind, isNoticeRole, type Notice } from '../domain/notice.ts';
import type { NotificationsTables } from './tables.ts';

/** How many times a notice is tried before it is given up. */
export const MOST_ATTEMPTS = 8;

/** How long a claimed notice is left to its sender before it is due again. */
export const CLAIM_LEASE_MS = 10 * 60_000;

/** The waits after each failed try but the last: a minute, then longer, to six hours. */
const BACKOFF_MS = [60_000, 5 * 60_000, 15 * 60_000, 60 * 60_000, 2 * 3_600_000, 4 * 3_600_000, 6 * 3_600_000];

/** How long a notice sent or given up is kept. */
export const OUTBOX_RETENTION_DAYS = 30;

/** The most notices one `add` writes, or one `claimDue` takes. */
export const MOST_NOTICES_A_BATCH = 100;

export interface Outbox {
  /** Writes these notices in the change's own transaction, at most MOST_NOTICES_A_BATCH. Throws RangeError for anything malformed, writing nothing. */
  add(tx: Transaction<NotificationsTables>, notices: readonly Notice[]): Promise<void>;
  /** Starts a try of up to `most` due notices, soonest due first, each held for the lease; gives up any whose last try's lease ran out. */
  claimDue(db: Kysely<NotificationsTables>, most: number): Promise<ClaimedNotice[]>;
  /** Marks the notice sent; false if it was already sent or given up. */
  sent(db: Kysely<NotificationsTables>, id: string): Promise<boolean>;
  /**
   * Records why the notice's try failed, `failure` a short constant: the next
   * try is set further off, or the notice given up after its MOST_ATTEMPTS-th
   * try, or at once when `lasting`. Says what became of it; `done` if it was
   * already sent or given up.
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

const isId = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);

/** Why a notice can't be written, if it can't. */
function problemWith(notice: Notice): string | undefined {
  if (!isId(notice.orgId)) return 'its organisation is not a UUID';
  if (!isId(notice.recipientUserId)) return 'its recipient is not a UUID';
  if (!isNoticeKind(notice.kind)) return 'its kind is not one we send';
  if (!isId(notice.membershipId)) return 'its membership is not a UUID';
  if (!isNoticeRole(notice.role)) return 'its role is not one of the four';
  return undefined;
}

/** The wait after the `tries`-th try failed, `tries` from 1 to MOST_ATTEMPTS - 1. */
const backoffAfter = (tries: number): number => BACKOFF_MS[Math.min(tries, BACKOFF_MS.length) - 1] ?? 0;

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
        // A notice due again after its last try: that try's lease ran out, its sender gone.
        await tx
          .updateTable('notifications.outbox')
          .set({ given_up_at: now, last_failure: 'lease_expired' })
          .where('sent_at', 'is', null)
          .where('given_up_at', 'is', null)
          .where('next_attempt_at', '<=', now)
          .where('attempts', '>=', MOST_ATTEMPTS)
          .execute();
        const due = tx
          .selectFrom('notifications.outbox')
          .select('id')
          .where('sent_at', 'is', null)
          .where('given_up_at', 'is', null)
          .where('next_attempt_at', '<=', now)
          .where('attempts', '<', MOST_ATTEMPTS)
          .orderBy('next_attempt_at')
          .orderBy('id')
          .limit(most)
          .forUpdate()
          .skipLocked();
        const rows = await tx
          .updateTable('notifications.outbox')
          .set((eb) => ({
            attempts: eb('attempts', '+', 1),
            next_attempt_at: new Date(now.getTime() + CLAIM_LEASE_MS),
          }))
          .where('id', 'in', due)
          .returning(['id', 'org_id', 'recipient_user_id', 'kind', 'membership_id', 'role', 'created_at', 'attempts'])
          .execute();
        // Every row taken now has the same next try, the lease's end, so they go in the order they were written.
        return rows
          .map((row) => {
            if (!isNoticeKind(row.kind) || !isNoticeRole(row.role)) {
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
              attempts: row.attempts - 1,
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
        // The try that failed was counted as it was taken.
        const givenUp = lasting || row.attempts >= MOST_ATTEMPTS;
        await tx
          .updateTable('notifications.outbox')
          .set({
            last_failure: failure,
            ...(givenUp
              ? { given_up_at: now }
              : { next_attempt_at: new Date(now.getTime() + backoffAfter(row.attempts)) }),
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
