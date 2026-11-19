// The console's server-side sessions (ADR-003 §5-§7; 0010).
//
// A session has two IDs. Its record ID is stable: step-up challenges bind to
// it, and it outlives every rotation. The browser holds the other, the cookie
// ID: 32 random bytes, sent as base64url, stored only as its SHA-256. A new
// one is issued at step-up (`rotate`), and a sign-in always opens a new
// session, never reusing one the browser brought (SEC-HA-07). The cookie ID
// carries 256 bits, so a plain hash of it can't be guessed back from a copy of
// the table.
//
// Each row carries a MAC with `session-mac` (row-macs.ts, S205): over its
// person, cookie hash, evidence and times, all but its last use. A row whose
// MAC doesn't hold, planted or edited by something without the app's key such
// as the database's owner, is no session and raises the integrity alarm. A
// rotation writes the MAC again with the new cookie hash, and only over a row
// whose MAC held.
//
// A session lives while both its timeouts hold: the idle one, from its last
// use, and the absolute one, from when it opened. `use` finds a live session
// by its cookie ID and moves its last use on, in one statement, so a session
// past either timeout is never found again, however it is asked for. The
// times are the Clock's (ADR-006 §3), so tests can move them.
//
// Every function but `sweep` runs on the handle it is given, so the caller
// decides the transaction, and its statement timeout: one statement each, but
// `rotate`'s two, which read the row to check its MAC and then write it only
// as it was read. A session past either timeout is never found again, but its
// row stays until it is ended; `sweep` deletes such rows a batch at a time, in a transaction of its
// own with a statement timeout (B2-4a: hourly, from the API).
import { createHash, randomBytes } from 'node:crypto';

import { limitStatements } from '@agentx/platform/db';
import { type ExpressionBuilder, type Kysely, sql, type Transaction } from 'kysely';

import { type Clock, type IdGenerator, UUID } from '../../../shared-kernel/index.ts';
import {
  type CheckedPlatformEvent,
  latestPlatformTimeOfRead,
  type PlatformEvent,
  type PlatformTransaction,
  recentPlatformEvents,
} from '../../platform-controls/index.ts';
import { checkEvidence, type SignInEvidence } from '../domain/sign-in.ts';
import { macHolds, macOf, type RowMacs, rowForged, sessionMessage } from './row-macs.ts';
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
   * Who holds the live session this cookie ID belongs to, its last use left
   * as it was: a browser's error report (6A2) is no use of it, and mustn't
   * keep an idle session alive. Undefined for any other cookie ID.
   */
  holder(db: Kysely<IdentityTables>, cookie: string): Promise<string | undefined>;
  /**
   * Gives a live session a new cookie ID, keeping its record (step-up,
   * SEC-HA-07): the old one finds nothing from then on. Undefined if the
   * session isn't live.
   */
  rotate(db: Kysely<IdentityTables>, sessionId: string): Promise<string | undefined>;
  /**
   * Ends the session this cookie ID belongs to, live or not; its user's ID,
   * undefined if there is none, or if its MAC doesn't hold (deleted all the same).
   */
  end(db: Kysely<IdentityTables>, cookie: string): Promise<string | undefined>;
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
 * challenges and verified addresses go with them. Keeps `endedAt` as when
 * they were last all ended (0098, AG10), never moved back, so a sign-in made
 * before it opens no session (sessionsEndedAt). Says how many. The caller adds sessionsEndedEvent, with the same
 * `endedAt`, to the platform chain in the same transaction, so the end can't be set back unseen (R-15).
 */
export async function endSessionsOf(tx: Transaction<IdentityTables>, userId: string, endedAt: Date): Promise<number> {
  // The end kept first: it waits for a sign-in that has read the last one (sessionsEndedAt, FOR SHARE) to commit, so
  // the delete after it, on a fresh snapshot (READ COMMITTED, as every transaction here), takes that session too.
  await tx
    .updateTable('identity.users')
    .set((eb) => ({ sessions_ended_at: eb.fn('greatest', [eb.ref('sessions_ended_at'), eb.val(endedAt)]) }))
    .where('id', '=', userId)
    .execute();
  const rows = await tx.deleteFrom('identity.sessions').where('user_id', '=', userId).returning('id').execute();
  return rows.length;
}

/**
 * The platform chain's signed record of a person's sessions all ended (R-15, S206), at the moment endSessionsOf was
 * given. The column alone can be set back by the database's owner, with no MAC to break, and a sign-in begun before
 * the end would then open a session; this record can't be set back without breaking the chain. On the platform's
 * chain, not an organisation's: one person's ends come from every organisation they belong to and from none (a
 * change at the login service), and a sign-in reads them all in one indexed look-up (0084's by-person index).
 */
export const SESSIONS_ENDED = 'identity.sessions_ended';

/**
 * The record of the end, for the caller to add to the platform chain in the same transaction as endSessionsOf, with
 * the same moment, and last of its locks (ADR-006 §6: the platform head comes last).
 */
export const sessionsEndedEvent = (userId: string, endedAt: Date): PlatformEvent => ({
  actor: { type: 'system', id: 'api' },
  action: SESSIONS_ENDED,
  details: { person: userId.toLowerCase(), at: endedAt.toISOString() },
});

/** How far before a sign-in the platform chain is checked for ends: the app's clock and the database's may differ. */
const CLOCKS_DIFFER_MS = 2 * 60 * 1000;

/**
 * The most platform events a sign-in checks (R-15): a login flow lives ten minutes (LOGIN_FLOW_SECONDS), so this is
 * the events the whole platform records in about twelve. More than this, and the sign-in is refused, not let past.
 */
export const MOST_EVENTS_CHECKED = 5000;

/** What a sign-in finds of the person's ends (sessionsEndedAt). */
export type SessionsEnded =
  /** The latest end believed, or null for none. */
  | { readonly kind: 'read'; readonly endedAt: Date | null }
  /** The platform chain's recent stretch didn't hold: the alarm raised. */
  | { readonly kind: 'tampered' }
  /** More recent platform events than a sign-in checks: logged. */
  | { readonly kind: 'unchecked' };

/** The latest moment among the checked events' records of the person's sessions ended, or null. */
function latestEndIn(events: readonly CheckedPlatformEvent[], person: string): Date | null {
  let latest: Date | null = null;
  for (const { action, details } of events) {
    if (action !== SESSIONS_ENDED) continue;
    const { person: named, at } = JSON.parse(details) as { person?: unknown; at?: unknown };
    const when = typeof at === 'string' ? new Date(at) : undefined;
    if (named !== person || when === undefined || Number.isNaN(when.getTime())) continue;
    latest = later(latest, when);
  }
  return latest;
}

/** The later of two moments, either of which may be none. */
const later = (one: Date | null, other: Date | null): Date | null =>
  one === null || (other !== null && other > one) ? other : one;

/**
 * When the person's sessions were last all ended (endSessionsOf), or null, for a sign-in made at `signedInAt`, in the
 * caller's transaction, their row locked FOR SHARE until it ends: an end committing at the same moment is waited for
 * and then read, so a session can't be opened past it. Taken after any of their sessions is locked (the sign-in's
 * previous one ended), as an end locks the sessions before the row.
 *
 * R-15 (S206): the column alone is the owner's to set back, or to put an older value of back. So each end is signed on
 * the platform chain too (sessionsEndedEvent), and the end believed is the latest of three:
 * - the column;
 * - the person's latest signed end, read in the same statement by 0084's by-person index, so a column set back
 *   behind it raises the alarm wherever that end lies;
 * - the person's ends among the platform events recorded since a little before `signedInAt` (an ID token's time, the
 *   login service's, which the owner can't move), the only ends that can make this sign-in stale, each checked in
 *   place with the stretch it lies in through the chain's head (recentPlatformEvents): a record deleted or edited,
 *   even for a moment and put back after, breaks that stretch now. The stretch is a login flow's few minutes, never
 *   the person's whole history.
 * The column behind either signed end raises the alarm (check `user`), and the signed end is believed; a stretch that
 * doesn't hold raises it too (check `platform_chain`), and nothing is believed. Left unseen: the newest events
 * deleted with the head wound back to an older one, which the anchor check finds once an anchor has passed them.
 */
export async function sessionsEndedAt(
  tx: Kysely<IdentityTables>,
  userId: string,
  { keys, logger }: RowMacs,
  signedInAt: Date,
): Promise<SessionsEnded> {
  const person = userId.toLowerCase();
  // The platform chain's tables are reached in the same transaction: they belong to no organisation.
  const platform = tx as unknown as PlatformTransaction;
  const signed = latestPlatformTimeOfRead(platform, 'at', [{ action: SESSIONS_ENDED, facts: { person } }]);
  const row = await tx
    .selectFrom('identity.users')
    .select(['sessions_ended_at', sql<Date | null>`(${signed})`.as('signed_end')])
    .where('id', '=', userId)
    .forShare()
    .executeTakeFirstOrThrow();
  // Read after the row's lock: an end of the person's can't commit from here on, as it would wait for that lock.
  const since = new Date(signedInAt.getTime() - CLOCKS_DIFFER_MS);
  const recent = await recentPlatformEvents(platform, keys, since, MOST_EVENTS_CHECKED);
  if (recent.kind === 'broken') {
    const { reason, seq } = recent.problem;
    logger.error('audit.integrity_failed', { check: 'platform_chain', reason, seq: seq.toString(), userId });
    return { kind: 'tampered' };
  }
  if (recent.kind === 'too_many') {
    logger.error('sign_in.ends_unchecked', { userId, most: MOST_EVENTS_CHECKED });
    return { kind: 'unchecked' };
  }
  const column = row.sessions_ended_at;
  // The checked stretch's own ends too, not the index's alone: the index was read on the first statement's snapshot,
  // before any wait for the row's lock, so a record deleted then and put back while the sign-in waited is missed there.
  const signedEnd = later(row.signed_end, latestEndIn(recent.events, person));
  if (signedEnd !== null && (column === null || column < signedEnd)) {
    logger.error('audit.integrity_failed', {
      check: 'user',
      reason: 'sessions_ended_rolled_back',
      rowId: userId,
      userId,
    });
  }
  return { kind: 'read', endedAt: later(column, signedEnd) };
}

/** The columns a session's MAC is made from, with the MAC itself. */
export const SESSION_SEALED = [
  'id',
  'user_id',
  'cookie_hash',
  'idp_session_id',
  'auth_time',
  'amr',
  'created_at',
  'ends_at',
  'mac',
  'mac_key_version',
] as const;

/** A session's facts as its columns keep them, without the MAC. */
export interface SessionRow {
  readonly id: string;
  readonly user_id: string;
  readonly cookie_hash: Buffer;
  readonly idp_session_id: string | null;
  readonly auth_time: Date;
  readonly amr: readonly string[];
  readonly created_at: Date;
  readonly ends_at: Date;
}

export const sessionRowMessage = (row: SessionRow) =>
  sessionMessage({
    id: row.id,
    userId: row.user_id,
    cookieHash: row.cookie_hash,
    idpSessionId: row.idp_session_id,
    authTime: row.auth_time,
    amr: row.amr,
    createdAt: row.created_at,
    endsAt: row.ends_at,
  });

export function createSessions({
  ids,
  clock,
  timeouts,
  keys,
  logger,
}: RowMacs & {
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

  /** Whether the row is the app's own: a row whose MAC doesn't hold raises the alarm, and is no session. */
  const genuine = (row: SessionRow & { readonly mac: Buffer; readonly mac_key_version: number }): boolean => {
    if (macHolds(keys, sessionRowMessage(row), row)) return true;
    rowForged(logger, 'session', row);
    return false;
  };

  return {
    async open(db, userId, evidence) {
      checkEvidence(evidence);
      const now = clock.now();
      const cookie = newCookie();
      const row = {
        id: ids.next(),
        user_id: userId,
        cookie_hash: hashOf(cookie),
        idp_session_id: evidence.idpSessionId ?? null,
        auth_time: evidence.authTime,
        amr: [...evidence.amr],
        created_at: now,
        ends_at: new Date(now.getTime() + absoluteSeconds * 1000),
      };
      await db
        .insertInto('identity.sessions')
        .values({ ...row, ...macOf(keys, sessionRowMessage(row)), last_seen_at: now })
        .execute();
      return { sessionId: row.id, cookie };
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
        .returning([...SESSION_SEALED, 'last_seen_at'])
        .executeTakeFirst();
      if (row === undefined || !genuine(row)) return undefined;
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

    async holder(db, cookie) {
      if (!isCookie(cookie)) return undefined;
      const now = clock.now();
      const row = await db
        .selectFrom('identity.sessions')
        .select(SESSION_SEALED)
        .where('cookie_hash', '=', hashOf(cookie))
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .executeTakeFirst();
      return row !== undefined && genuine(row) ? row.user_id : undefined;
    },

    async rotate(db, sessionId) {
      if (typeof sessionId !== 'string' || !UUID.test(sessionId)) return undefined;
      const now = clock.now();
      const live = await db
        .selectFrom('identity.sessions')
        .select(SESSION_SEALED)
        .where('id', '=', sessionId)
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .executeTakeFirst();
      // Only a row whose MAC held gets a new one: rotating a forged row would make it genuine.
      if (live === undefined || !genuine(live)) return undefined;
      const cookie = newCookie();
      const cookieHash = hashOf(cookie);
      const row = await db
        .updateTable('identity.sessions')
        .set({ cookie_hash: cookieHash, ...macOf(keys, sessionRowMessage({ ...live, cookie_hash: cookieHash })) })
        .where('id', '=', sessionId)
        // Only the row as it was checked: changed meanwhile (rotated, or written by anyone else), it is left as it is.
        .where('cookie_hash', '=', live.cookie_hash)
        .where('mac', '=', live.mac)
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .returning('id')
        .executeTakeFirst();
      return row === undefined ? undefined : cookie;
    },

    async end(db, cookie) {
      if (!isCookie(cookie)) return undefined;
      // Deleted whatever its MAC: ending a session is always safe. Its person is named, for the login service's own
      // sessions to end too, only where the row is the app's own (S205): a forged one would end someone else's.
      const row = await db
        .deleteFrom('identity.sessions')
        .where('cookie_hash', '=', hashOf(cookie))
        .returning(SESSION_SEALED)
        .executeTakeFirst();
      return row !== undefined && genuine(row) ? row.user_id : undefined;
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) {
        throw new RangeError('a sweep deletes at least one session at a time');
      }
      const now = clock.now();
      return db.transaction().execute(async (tx) => {
        await limitStatements(tx);
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
