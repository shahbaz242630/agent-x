// The console's server-side sessions (ADR-003 §5-§7; 0010).
//
// A session has two IDs. Its record ID is stable: step-up challenges bind to
// it, and it outlives every rotation. The browser holds the other, the cookie
// ID: 32 random bytes, sent as base64url, stored only as its SHA-256. A new
// one is issued at step-up (`rotate`), and a sign-in always opens a new
// session, never reusing one the browser brought (SEC-HA-07). The cookie ID
// carries 256 bits, so a plain hash of it can't be guessed back from a copy of
// the table, and no key is needed.
//
// A session lives while both its timeouts hold: the idle one, from its last
// use, and the absolute one, from when it opened. `use` finds a live session
// by its cookie ID and moves its last use on, in one statement, so a session
// past either timeout is never found again, however it is asked for. The
// times are the Clock's (ADR-006 §3), so tests can move them.
//
// Every function but `sweep` runs one statement on the handle it is given, so
// the caller decides the transaction, and its statement timeout. A session
// past either timeout is never found again, but its row stays until it is
// ended; `sweep` deletes such rows a batch at a time, in a transaction of its
// own with a statement timeout (B2-4a: hourly, from the API).
import { createHash, randomBytes } from 'node:crypto';

import { type ExpressionBuilder, type Kysely, sql, type Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { checkEvidence, type SignInEvidence } from '../domain/sign-in.ts';
import type { IdentityTables } from './tables.ts';

/** How long a session lives. */
export interface SessionTimeouts {
  /** Seconds from its last use. */
  readonly idleSeconds: number;
  /** Seconds from when it opened, however much it is used. */
  readonly absoluteSeconds: number;
}

/** A session just opened: its record, and the cookie ID to send the browser, which is never kept. */
export interface OpenedSession {
  readonly sessionId: string;
  readonly cookie: string;
}

/** A live session, as a request finds it. */
export interface LiveSession extends SignInEvidence {
  readonly sessionId: string;
  readonly userId: string;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  /** Its absolute end. */
  readonly endsAt: Date;
  /** When it ends if it goes unused from now: its idle timeout from its last use, or its absolute end if that is sooner. */
  readonly idleEndsAt: Date;
}

export interface Sessions {
  /** Opens a new session for the user, with what their sign-in proved. Throws SignInRefused for evidence that can't be stored. */
  open(db: Kysely<IdentityTables>, userId: string, evidence: SignInEvidence): Promise<OpenedSession>;
  /** The live session this cookie ID belongs to, its last use moved on; undefined for any other cookie ID. */
  use(db: Kysely<IdentityTables>, cookie: string): Promise<LiveSession | undefined>;
  /**
   * Gives a live session a new cookie ID, keeping its record (step-up,
   * SEC-HA-07): the old one finds nothing from then on. Undefined if the
   * session isn't live.
   */
  rotate(db: Kysely<IdentityTables>, sessionId: string): Promise<string | undefined>;
  /** Ends the session this cookie ID belongs to, live or not; false if there is none. */
  end(db: Kysely<IdentityTables>, cookie: string): Promise<boolean>;
  /**
   * Deletes up to `most` sessions no process could use again: past their
   * absolute end, or unused past the longest idle timeout there can be
   * (LONGEST_IDLE_SECONDS). Says how many.
   */
  sweep(db: Kysely<IdentityTables>, most: number): Promise<number>;
}

/** The cookie ID's size: 256 bits. */
const COOKIE_BYTES = 32;
/** Its text: 32 bytes in base64url, unpadded. */
const COOKIE = /^[A-Za-z0-9_-]{43}$/;

/** The shortest idle timeout: shorter would sign people out mid-task. The config's own minimums come with it (B2-4). */
const LEAST_SECONDS = 60;

/**
 * The longest idle timeout there can be: AGENTX_SESSION_IDLE_MINUTES's
 * maximum, 480 minutes. The sweep deletes by it rather than by this process's
 * own setting, so no setting, on this replica or another, or after a release
 * that lengthens it, could make a deleted session live again.
 */
export const LONGEST_IDLE_SECONDS = 8 * 60 * 60;

const newCookie = (): string => randomBytes(COOKIE_BYTES).toString('base64url');
const hashOf = (cookie: string): Buffer => createHash('sha256').update(cookie, 'ascii').digest();
/** Only text a cookie ID could be is looked up: anything else is no session, and no query. */
const isCookie = (value: unknown): value is string => typeof value === 'string' && COOKIE.test(value);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const isWholeSeconds = (value: number): boolean => Number.isSafeInteger(value) && value >= LEAST_SECONDS;

/**
 * Locks the people's sessions, in order of ID, in the caller's transaction:
 * a demotion's or deactivation's level 0b (ADR-006 §6), before any
 * membership. `FOR NO KEY UPDATE`, not `FOR UPDATE`: a challenge opened for
 * one of them meanwhile (its key check takes a key-share lock on the session)
 * goes ahead rather than waiting while it holds a membership's lock this
 * transaction waits for. A sign-out, or a step-up's new cookie ID, waits.
 */
export async function lockSessionsOf(tx: Transaction<IdentityTables>, userIds: readonly string[]): Promise<void> {
  await tx
    .selectFrom('identity.sessions')
    .select('id')
    .where('user_id', 'in', userIds)
    .orderBy('id')
    .forNoKeyUpdate()
    .execute();
}

/**
 * Ends every session the person has, live or not, in the caller's
 * transaction, which locked them first (lockSessionsOf): a role change or
 * deactivation ends them in its own transaction (ADR-003 §7, SEC-HA-10). Their
 * challenges and verified addresses go with them. Says how many.
 */
export async function endSessionsOf(tx: Transaction<IdentityTables>, userId: string): Promise<number> {
  const rows = await tx.deleteFrom('identity.sessions').where('user_id', '=', userId).returning('id').execute();
  return rows.length;
}

export function createSessions({
  ids,
  clock,
  timeouts,
}: {
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly timeouts: SessionTimeouts;
}): Sessions {
  const { idleSeconds, absoluteSeconds } = timeouts;
  if (!isWholeSeconds(idleSeconds) || !isWholeSeconds(absoluteSeconds)) {
    throw new RangeError(`session timeouts must be whole numbers of seconds, at least ${LEAST_SECONDS}`);
  }
  if (idleSeconds > LONGEST_IDLE_SECONDS) {
    throw new RangeError(
      `the idle timeout must not be longer than ${LONGEST_IDLE_SECONDS} seconds, which the sweep relies on`,
    );
  }
  if (idleSeconds > absoluteSeconds) {
    throw new RangeError('the idle timeout must not be longer than the absolute one');
  }

  /** The last use a session must have had after, to be live now. */
  const idleSince = (now: Date): Date => new Date(now.getTime() - idleSeconds * 1000);

  return {
    async open(db, userId, evidence) {
      checkEvidence(evidence);
      const now = clock.now();
      const cookie = newCookie();
      const sessionId = ids.next();
      await db
        .insertInto('identity.sessions')
        .values({
          id: sessionId,
          user_id: userId,
          cookie_hash: hashOf(cookie),
          idp_session_id: evidence.idpSessionId ?? null,
          auth_time: evidence.authTime,
          amr: [...evidence.amr],
          created_at: now,
          last_seen_at: now,
          ends_at: new Date(now.getTime() + absoluteSeconds * 1000),
        })
        .execute();
      return { sessionId, cookie };
    },

    async use(db, cookie) {
      if (!isCookie(cookie)) return undefined;
      const now = clock.now();
      const row = await db
        .updateTable('identity.sessions')
        // Never backwards: a request timed a moment earlier can't shorten the session.
        .set((eb) => ({ last_seen_at: eb.fn('greatest', [eb.ref('last_seen_at'), eb.val(now)]) }))
        .where('cookie_hash', '=', hashOf(cookie))
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .returning(['id', 'user_id', 'idp_session_id', 'auth_time', 'amr', 'created_at', 'last_seen_at', 'ends_at'])
        .executeTakeFirst();
      if (row === undefined) return undefined;
      const idleEnd = row.last_seen_at.getTime() + idleSeconds * 1000;
      return {
        sessionId: row.id,
        userId: row.user_id,
        idpSessionId: row.idp_session_id ?? undefined,
        authTime: row.auth_time,
        amr: row.amr,
        createdAt: row.created_at,
        lastSeenAt: row.last_seen_at,
        endsAt: row.ends_at,
        idleEndsAt: new Date(Math.min(idleEnd, row.ends_at.getTime())),
      };
    },

    async rotate(db, sessionId) {
      if (typeof sessionId !== 'string' || !UUID.test(sessionId)) return undefined;
      const now = clock.now();
      const cookie = newCookie();
      const row = await db
        .updateTable('identity.sessions')
        .set({ cookie_hash: hashOf(cookie) })
        .where('id', '=', sessionId)
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .returning('id')
        .executeTakeFirst();
      return row === undefined ? undefined : cookie;
    },

    async end(db, cookie) {
      if (!isCookie(cookie)) return false;
      const row = await db
        .deleteFrom('identity.sessions')
        .where('cookie_hash', '=', hashOf(cookie))
        .returning('id')
        .executeTakeFirst();
      return row !== undefined;
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) {
        throw new RangeError('a sweep deletes at least one session at a time');
      }
      const now = clock.now();
      return db.transaction().execute(async (tx) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        // Only sessions no process could find again, whatever its idle
        // timeout: past their stored end, or unused past the longest idle
        // timeout there can be. A session between that and this process's own
        // timeout is refused by `use` already, and goes in a later sweep.
        const past = (eb: ExpressionBuilder<IdentityTables, 'identity.sessions'>) =>
          eb.or([
            eb('last_seen_at', '<=', new Date(now.getTime() - LONGEST_IDLE_SECONDS * 1000)),
            eb('ends_at', '<=', now),
          ]);
        const ended = tx.selectFrom('identity.sessions').select('id').where(past).limit(most);
        // Asked again of each row as it is deleted: a session a request used
        // while the sweep waited for its lock is live again, and the id alone
        // would be all Postgres checks a second time.
        const rows = await tx
          .deleteFrom('identity.sessions')
          .where('id', 'in', ended)
          .where(past)
          .returning('id')
          .execute();
        return rows.length;
      });
    },
  };
}
