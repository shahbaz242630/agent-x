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
// A row whose MAC holds may still be one the app deleted, put back by the owner
// as it was (R-15, S207). So each end is signed on the platform chain: a
// sign-out's (`identity.session_ended`, naming the session) and a person's all
// ended (`identity.sessions_ended`). A session either names, as ended after its
// sign-in, is no session and raises the alarm: read in the statement that finds
// the row, by 0109's by-record and 0116's by-person indexes, so no request costs
// a trip more, nor reads more as the person signs out more. A signed
// end deleted to hide it breaks the platform chain, which the anchor check reads.
// So is each rotation (`identity.session_rotated`, S207 GM-4), naming the
// session and the MAC its row had: a row put back as it was before a step-up,
// which the cookie it held then would find, is no session and raises the alarm,
// read the same way, by 0109's index.
//
// A signed end deleted once it lies below the platform chain's anchor, older than
// its last 1,000 events, isn't found by the chain's check each run (R-15, AT13c).
// So where this process keeps the signed states' digest (digest-log.ts, given as
// `digest`), each end the anchor check's walk read is known there, and a session's
// read that finds no end the digest knows of (or a person's newest all-ended older
// than it) is no session. Read again on its own first: an end committed after the
// statement's snapshot, then walked, is the session ending as it is read, refused
// without the alarm; one still missing is put back past the app, the alarm.
//
// Nor is an end the chain's newest events took with them, cut off by the owner
// with an earlier sealed head put back before any anchor passed them (AT13h): no
// walk read it, and every seal still holds. So the same statement reads the
// platform chain's head and the event at the highest head this process has seen
// (platformHeadRead, the digest's `heads`): one below it, or another event at its
// place, is the chain cut back, and the session is refused with the alarm. Only
// the reads that let a session in (`use`, `holder`, `rotate`): a sign-out still
// ends one, and a sign-in is held by its own check of the chain (signed-ends.ts).
//
// A cut found is answered, not left standing (AT13h, S208's partner decision): given
// the `database`, the read that finds it ends every session there is, once, signed
// (sessions-all-ended.ts), and the chain is taken as it then stands for these reads
// (the digest's `accepted`, held to and raised as the head seen is), so people sign
// in again and carry on with no operator and no restart. The read itself is refused,
// as is every read inside the minute after an answer. Each read finds that record by
// its index too, as a person's all ended: a session signed in before it is no session,
// refused quietly (a request reading its own row as the rows went keeps it, and a
// sign-in under way as they went opens one: neither is tampering).
//
// Its last use is the owner's to move too, and moved on, an idle session lived
// again for a cookie stolen while it was live. So the last use has a MAC of
// its own, with the cookie's hash (0111): `use` writes it with the new last use,
// in its one statement, and checks the one it replaced, read in the same
// statement from the row as it was; one the app didn't write, or none, ends the
// session, with the alarm (S208: the rollout's grace, which only warned, deleted
// early; a release from before 0111 rolled back to would page for each session
// it touched). `holder` and `rotate` check it as they read the row.
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
import type { Logger } from '@agentx/platform/observability';
import { type ExpressionBuilder, type Kysely, sql, type Transaction } from 'kysely';

import { type Clock, type IdGenerator, UUID } from '../../../shared-kernel/index.ts';
import type { StateDigest } from '../../audit/index.ts';
import {
  latestPlatformSeqRead,
  latestPlatformTimeOfRead,
  type PlatformControlsTables,
  platformCutBack,
  platformEventWithRead,
  type PlatformHeadOfRow,
  platformHeadRead,
  type PlatformTransaction,
} from '../../platform-controls/index.ts';
import { checkEvidence, type SignInEvidence } from '../domain/sign-in.ts';
import { lastUseMessage, macHolds, macOf, type RowMacs, rowForged, sessionMessage } from './row-macs.ts';
import { createAllSessionsEnding } from './sessions-all-ended.ts';
import {
  EVERYONE,
  type RetiredSession,
  SESSION_ENDED,
  SESSION_ROTATED,
  SESSIONS_ALL_ENDED,
  SESSIONS_ENDED,
  signedEndKey,
  type SignedEnds,
} from './signed-ends.ts';
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

/** A session a sign-out deleted, the app's own: its person, and its record for the signed end (sessionEndedEvent). */
export interface EndedSession {
  readonly userId: string;
  readonly sessionId: string;
}

/** A session given a new cookie ID: the cookie ID to send the browser, and its row as it was, for the signed rotation (sessionRotatedEvent). */
interface RotatedSession {
  readonly cookie: string;
  readonly retired: RetiredSession;
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
  /**
   * The live session this cookie ID belongs to, its last use moved on; undefined for any other cookie ID. One whose
   * last use the app didn't write is ended: call it in a transaction, so no other request sees the last use it wrote.
   */
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
   * session isn't live. The caller signs the rotation (sessionRotatedEvent) in
   * the same transaction, or the row as it was could be put back (R-15).
   */
  rotate(db: Kysely<IdentityTables>, sessionId: string): Promise<RotatedSession | undefined>;
  /**
   * Ends the session this cookie ID belongs to, live or not; its person and
   * record, undefined if there is none, or if its MAC doesn't hold (deleted all
   * the same). The caller signs the end (sessionEndedEvent) in the same transaction.
   */
  end(db: Kysely<IdentityTables>, cookie: string): Promise<EndedSession | undefined>;
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

/**
 * The longest absolute timeout there can be: AGENTX_SESSION_ABSOLUTE_HOURS's maximum, 24 hours. A session's absolute
 * end is set at its sign-in and held by its row's MAC, so none ends later than this past it, whatever the setting then
 * or since. The signed states' digest forgets the platform chain's session ends past it (AT13g, digest-log.ts): a row
 * an end names, put back, is past its end by then.
 */
export const LONGEST_ABSOLUTE_SECONDS = 24 * 60 * 60;

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

export {
  SESSION_ENDED,
  sessionEndedEvent,
  SESSION_ROTATED,
  sessionRotatedEvent,
  SESSIONS_ENDED,
  sessionsEndedEvent,
} from './signed-ends.ts';

/** How far before a sign-in the platform chain is checked for ends: the app's clock and the database's may differ. */
const CLOCKS_DIFFER_MS = 2 * 60 * 1000;

/**
 * How a person's or everyone's signed end read by its index decides (AT13h, S208): only at or below the platform
 * chain's head, and only with a time no later than the database's now and those two minutes. A row the owner planted
 * past the head (in no walk, no stretch's check) or with a time to come would otherwise refuse every sign-in and
 * session for good with no alarm; one planted inside the chain breaks the chain's check, which raises it.
 */
const SIGNED_END = { belowHead: true, notAhead: 'at' } as const;

/** What a sign-in finds of the person's ends (sessionsEndedAt). */
export type SessionsEnded =
  /** The latest end believed, or null for none. */
  | { readonly kind: 'read'; readonly endedAt: Date | null }
  /** The platform chain's stretch didn't hold: the alarm raised. */
  | { readonly kind: 'tampered' };

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
 * - the person's latest signed end, read in the same statement by 0116's by-person index, so a column set back
 *   behind it raises the alarm wherever that end lies;
 * - the person's latest end among the platform events checked in place since a little before `signedInAt` (an ID
 *   token's time, the login service's, which the owner can't move): the only ends that can make this sign-in stale.
 *   `signedEnds` checks them from where this process got to (signed-ends.ts), so a record deleted, even for a moment
 *   and put back, is seen. It counts too where the index missed it: the index is read on the first statement's
 *   snapshot, before any wait for the row's lock, and a record put back while the sign-in waited is missing there.
 * The column behind either signed end raises the alarm (check `user`), and the signed end is believed; a chain that
 * doesn't hold raises it too (check `platform_chain`), and nothing is believed. Every session's end at once (AT13h,
 * sessions-all-ended.ts) is everyone's end too, read the same two ways, and no column is held to it.
 */
export async function sessionsEndedAt(
  tx: Kysely<IdentityTables>,
  userId: string,
  { logger, signedEnds }: { readonly logger: Logger; readonly signedEnds: SignedEnds },
  signedInAt: Date,
): Promise<SessionsEnded> {
  const person = userId.toLowerCase();
  // The platform chain's tables are reached in the same transaction: they belong to no organisation.
  const platform = tx as unknown as PlatformTransaction;
  const signed = latestPlatformTimeOfRead(platform, 'at', [
    { action: SESSIONS_ENDED, facts: { person }, ...SIGNED_END },
  ]);
  // Every session's end at once (AT13h): everyone's, never the column's to agree with.
  const everyone = latestPlatformTimeOfRead(platform, 'at', [{ action: SESSIONS_ALL_ENDED, facts: {}, ...SIGNED_END }]);
  const row = await tx
    .selectFrom('identity.users')
    .select([
      'sessions_ended_at',
      sql<Date | null>`(${signed})`.as('signed_end'),
      sql<Date | null>`(${everyone})`.as('everyone_end'),
    ])
    .where('id', '=', userId)
    .forShare()
    .executeTakeFirstOrThrow();
  // After the row's lock: an end of the person's can't commit from here on, as it would wait for that lock.
  const checked = await signedEnds.check(platform, new Date(signedInAt.getTime() - CLOCKS_DIFFER_MS));
  if (checked.kind === 'broken') {
    const { reason, seq } = checked.problem;
    logger.error('audit.integrity_failed', { check: 'platform_chain', reason, seq: seq.toString(), userId });
    return { kind: 'tampered' };
  }
  const column = row.sessions_ended_at;
  const signedEnd = later(row.signed_end, checked.ends.get(person)?.at ?? null);
  if (signedEnd !== null && (column === null || column < signedEnd)) {
    logger.error('audit.integrity_failed', {
      check: 'user',
      reason: 'sessions_ended_rolled_back',
      rowId: userId,
      userId,
    });
  }
  const everyoneEnd = later(row.everyone_end, checked.ends.get(EVERYONE)?.at ?? null);
  return { kind: 'read', endedAt: later(later(column, signedEnd), everyoneEnd) };
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

/**
 * The session's signed ends, read with its row (R-15, S207): whether its own sign-out is signed (one entry of 0109's
 * by-record index, however often the person signed out), whether a rotation retired the row as it stands (the
 * session's few rotations, by the same index), and its person's latest all ended (0116's by-person index). Each a
 * subquery of the statement, on the row's own columns.
 */
const signedEndsOfRow = (db: Kysely<IdentityTables>, heldTo: Parameters<typeof platformHeadRead>[0]) => {
  const platform = db as unknown as Kysely<PlatformControlsTables>;
  const person = sql<string>`identity.sessions.user_id::text`;
  const record = sql<string>`identity.sessions.id::text`;
  const retired = sql<string>`pg_catalog.encode(identity.sessions.mac, 'hex')`;
  return [
    sql<boolean>`exists (${platformEventWithRead(platform, SESSION_ENDED, {}, { record, person })})`.as('signed_out'),
    sql<boolean>`exists (${platformEventWithRead(platform, SESSION_ROTATED, {}, { record, person, retired })})`.as(
      'rotated_away',
    ),
    sql<Date | null>`(${latestPlatformTimeOfRead(platform, 'at', [{ action: SESSIONS_ENDED, facts: {}, factsFrom: { person }, ...SIGNED_END }])})`.as(
      'all_ended_at',
    ),
    // Its place too, for the digest (AT13c), which keeps places: by the same index, the person's few such ends.
    sql<
      bigint | null
    >`(${latestPlatformSeqRead(platform, { action: SESSIONS_ENDED, facts: {}, factsFrom: { person }, ...SIGNED_END })})`.as(
      'all_ended_seq',
    ),
    // Every session's end at once (AT13h), its time and place: by 0057's by-action index, a few such ends ever.
    sql<Date | null>`(${latestPlatformTimeOfRead(platform, 'at', [{ action: SESSIONS_ALL_ENDED, facts: {}, ...SIGNED_END }])})`.as(
      'everyone_ended_at',
    ),
    sql<
      bigint | null
    >`(${latestPlatformSeqRead(platform, { action: SESSIONS_ALL_ENDED, facts: {}, ...SIGNED_END })})`.as(
      'everyone_ended_seq',
    ),
    // The platform chain's head, held to the highest seen (AT13h, the header).
    ...platformHeadRead(heldTo),
  ] as const;
};

/** The row's signed ends, as signedEndsOfRow reads them. */
interface SignedEndsOfRow {
  readonly signed_out: boolean;
  readonly rotated_away: boolean;
  readonly all_ended_at: Date | null;
  readonly all_ended_seq: bigint | null;
  readonly everyone_ended_at: Date | null;
  readonly everyone_ended_seq: bigint | null;
}

/** The ends the read is held to the digest by: its person, record and MAC, and what it found of each. */
type EndsRead = Pick<SignedEndsOfRow, 'signed_out' | 'rotated_away' | 'all_ended_seq' | 'everyone_ended_seq'> & {
  readonly id: string;
  readonly user_id: string;
  readonly mac: Buffer;
};

const PLATFORM = { kind: 'platform' } as const;

/**
 * A signed end the digest knows of (AT13c) that the read didn't find, if any: the session's sign-out, the rotation
 * that retired the row as it stands, or a person's all-ended newer than the newest found. None without a digest.
 */
function endUnseen(digest: Pick<StateDigest, 'latest'> | undefined, row: EndsRead): 'ended' | 'rotated' | undefined {
  if (digest === undefined) return undefined;
  const [person, record] = [row.user_id, row.id];
  if (!row.signed_out && digest.latest(PLATFORM, SESSION_ENDED, signedEndKey.ended(person, record)) !== undefined) {
    return 'ended';
  }
  const retired = signedEndKey.rotated(person, record, row.mac.toString('hex'));
  if (!row.rotated_away && digest.latest(PLATFORM, SESSION_ROTATED, retired) !== undefined) return 'rotated';
  const allEnded = digest.latest(PLATFORM, SESSIONS_ENDED, person.toLowerCase());
  if (allEnded !== undefined && (row.all_ended_seq === null || row.all_ended_seq < allEnded)) return 'ended';
  const everyone = digest.latest(PLATFORM, SESSIONS_ALL_ENDED, EVERYONE);
  return everyone !== undefined && (row.everyone_ended_seq === null || row.everyone_ended_seq < everyone)
    ? 'ended'
    : undefined;
}

/** The row's signed ends read again on their own, from the facts the row named: one statement. */
async function endsNow(db: Kysely<IdentityTables>, row: EndsRead): Promise<EndsRead> {
  const platform = db as unknown as Kysely<PlatformControlsTables>;
  const [person, record] = [row.user_id.toLowerCase(), row.id.toLowerCase()];
  const retired = row.mac.toString('hex');
  const read = await platform
    .selectNoFrom([
      sql<boolean>`exists (${platformEventWithRead(platform, SESSION_ENDED, { record, person })})`.as('signed_out'),
      sql<boolean>`exists (${platformEventWithRead(platform, SESSION_ROTATED, { record, person, retired })})`.as(
        'rotated_away',
      ),
      sql<
        bigint | null
      >`(${latestPlatformSeqRead(platform, { action: SESSIONS_ENDED, facts: { person }, ...SIGNED_END })})`.as(
        'all_ended_seq',
      ),
      sql<
        bigint | null
      >`(${latestPlatformSeqRead(platform, { action: SESSIONS_ALL_ENDED, facts: {}, ...SIGNED_END })})`.as(
        'everyone_ended_seq',
      ),
    ])
    .executeTakeFirstOrThrow();
  return { ...row, ...read };
}

/** A session's last use as the row keeps it, with its MAC (0111): none on a session from before. */
interface LastUse {
  readonly at: Date;
  readonly mac: Buffer | null;
  readonly version: number | null;
}

/** The row's own last use, as `holder` and `rotate` read it. */
const lastUseOf = (row: {
  readonly last_seen_at: Date;
  readonly last_use_mac: Buffer | null;
  readonly last_use_mac_key_version: number | null;
}): LastUse => ({ at: row.last_seen_at, mac: row.last_use_mac, version: row.last_use_mac_key_version });

/** The columns `holder` and `rotate` read: the sealed ones, and the last use with its MAC. */
const SESSION_READ = [...SESSION_SEALED, 'last_seen_at', 'last_use_mac', 'last_use_mac_key_version'] as const;

/**
 * Whether a signed end names the session: signed out, or its person's sessions all ended after its sign-in. The
 * sign-in's own rule (sessionsEndedAt): a session whose sign-in was before the end can't be opened after it, and
 * the end deletes every one opened before.
 */
const endedBySignature = (row: SignedEndsOfRow & { readonly auth_time: Date }): boolean =>
  row.signed_out || (row.all_ended_at !== null && row.auth_time < row.all_ended_at);

/**
 * Whether every session's end at once (AT13h) names the session: its sign-in before it, or at the same moment (a sign-in
 * as the rows went may be one of them: only signed in again, never let through).
 */
const endedForEveryone = (row: SignedEndsOfRow & { readonly auth_time: Date }): boolean =>
  row.everyone_ended_at !== null && row.auth_time <= row.everyone_ended_at;

export function createSessions({
  ids,
  clock,
  timeouts,
  keys,
  logger,
  digest,
  database,
}: RowMacs & {
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly timeouts: SessionTimeouts;
  /**
   * Where a cut platform chain is answered, in a transaction of its own (AT13h, the header: every session ended,
   * signed): none, and a cut chain refuses every session read as before.
   */
  readonly database?: Kysely<IdentityTables>;
  /**
   * The signed states' digest this process keeps, asked at each read (AT13c, the header): given at boot, kept by the
   * jobs once they lead; none, or none yet, and the reads are as before it.
   */
  readonly digest?: () => (Pick<StateDigest, 'latest'> & Partial<Pick<StateDigest, 'heads'>>) | undefined;
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
  if (absoluteSeconds > LONGEST_ABSOLUTE_SECONDS) {
    throw new RangeError(
      `the absolute timeout must not be longer than ${LONGEST_ABSOLUTE_SECONDS} seconds, which the digest relies on`,
    );
  }

  /** The last use a session must have had after, to be live now. */
  const idleSince = (now: Date): Date => new Date(now.getTime() - idleSeconds * 1000);

  /** Whether the row is the app's own: a row whose MAC doesn't hold raises the alarm, and is no session. */
  const genuine = (row: SessionRow & { readonly mac: Buffer; readonly mac_key_version: number }): boolean => {
    if (macHolds(keys, sessionRowMessage(row), row)) return true;
    rowForged(logger, 'session', row);
    return false;
  };

  /** Whether the row is the app's own, named by no signed end and retired by no signed rotation (one put back raises the alarm). */
  const standing = (row: Parameters<typeof genuine>[0] & SignedEndsOfRow): boolean => {
    if (!genuine(row)) return false;
    if (endedBySignature(row)) {
      rowForged(logger, 'session', row, 'ended');
      return false;
    }
    // Quietly: a row a request held as every session ended, or one a sign-in under way then opened, is no tampering.
    if (endedForEveryone(row)) return false;
    if (!row.rotated_away) return true;
    rowForged(logger, 'session', row, 'rotated');
    return false;
  };

  /** What a read holds the platform chain's head to (AT13h), asked before its statement: none without a digest. */
  const platformWatch = () => digest?.()?.heads?.(PLATFORM);

  /** The head a read is held to: where a cut answered took the chain as it stands, else the head seen (the header). */
  const heldTo = (watch: ReturnType<typeof platformWatch>) => watch?.accepted ?? watch;

  const ending =
    database === undefined ? undefined : createAllSessionsEnding({ db: database, keys, ids, clock, logger });

  /**
   * Whether the platform chain was cut back below the head the read was held to (AT13h): the alarm, the cut answered
   * (every session ended, signed, at most once a minute), and no session.
   */
  const platformCut = async (
    db: Kysely<IdentityTables>,
    watch: ReturnType<typeof platformWatch>,
    row: PlatformHeadOfRow & { readonly id: string; readonly user_id: string },
  ): Promise<boolean> => {
    if (watch === undefined) return false;
    const held = platformCutBack(keys, db, heldTo(watch), row);
    if (held === undefined) return false;
    logger.error('audit.integrity_failed', {
      check: 'platform_chain',
      reason: 'cut_back',
      seq: held.seq.toString(),
      rowId: row.id,
      userId: row.user_id,
    });
    await ending?.answer({ watch, held, found: row.platform_head_seq });
    return true;
  };

  /** Whether the session's last use is the app's: one moved, or with no MAC, raises the alarm. */
  const lastUseHolds = (
    row: { readonly id: string; readonly user_id: string; readonly cookie_hash: Buffer },
    lastUse: LastUse,
  ): boolean => {
    // macHolds believes no null MAC.
    const sealed = { mac: lastUse.mac, mac_key_version: lastUse.version };
    if (macHolds(keys, lastUseMessage(row.cookie_hash, lastUse.at), sealed)) return true;
    rowForged(logger, 'session', row, 'last_use');
    return false;
  };

  /**
   * Whether no signed end the digest knows of is missing from the row's read (AT13c). One missing is read again on its
   * own: found now, the end committed after the read's snapshot (the session ending as it was read), refused quietly;
   * still missing, deleted past the app with the row put back, the alarm.
   */
  const heldToDigest = async (db: Kysely<IdentityTables>, row: EndsRead): Promise<boolean> => {
    const held = digest?.();
    if (endUnseen(held, row) === undefined) return true;
    const unseen = endUnseen(held, await endsNow(db, row));
    if (unseen !== undefined) rowForged(logger, 'session', row, unseen);
    return false;
  };

  /** Whether the row is a session of the app's: standing, held to the digest, and its last use the app's. */
  const believed = async (
    db: Kysely<IdentityTables>,
    row: Parameters<typeof standing>[0],
    lastUse: LastUse,
  ): Promise<boolean> => standing(row) && (await heldToDigest(db, row)) && lastUseHolds(row, lastUse);

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
      const lastUse = macOf(keys, lastUseMessage(row.cookie_hash, now));
      await db
        .insertInto('identity.sessions')
        .values({
          ...row,
          ...macOf(keys, sessionRowMessage(row)),
          last_seen_at: now,
          last_use_mac: lastUse.mac,
          last_use_mac_key_version: lastUse.mac_key_version,
        })
        .execute();
      return { sessionId: row.id, cookie };
    },

    async use(db, cookie) {
      if (!isCookie(cookie)) return undefined;
      const now = clock.now();
      const cookieHash = hashOf(cookie);
      const sealed = macOf(keys, lastUseMessage(cookieHash, now));
      const watch = platformWatch();
      // Never backwards: a request timed a moment earlier can't shorten the session, nor change its last use's MAC.
      const onward = sql<boolean>`identity.sessions.last_seen_at < ${now}`;
      const row = await db
        .updateTable('identity.sessions')
        // The row as it was, on the statement's own snapshot (the same row, by its ID): the last use it replaces.
        .from('identity.sessions as was')
        .set({
          last_seen_at: sql<Date>`case when ${onward} then ${now}::timestamptz else identity.sessions.last_seen_at end`,
          last_use_mac: sql<Buffer>`case when ${onward} then ${sealed.mac}::bytea else identity.sessions.last_use_mac end`,
          last_use_mac_key_version: sql<number>`case when ${onward} then ${sealed.mac_key_version}::integer
            else identity.sessions.last_use_mac_key_version end`,
        })
        .whereRef('was.id', '=', 'identity.sessions.id')
        .where('identity.sessions.cookie_hash', '=', cookieHash)
        .where('identity.sessions.last_seen_at', '>', idleSince(now))
        .where('identity.sessions.ends_at', '>', now)
        // `was` is the row on the statement's snapshot, which the conditions above found live; a row moved meanwhile
        // (the statement waited for its lock) is asked them again, but `was` stays the one found (the request is let
        // in: the session was live), and the moved last use is the next request's to check.
        .returning([
          ...SESSION_SEALED.map((column) => `identity.sessions.${column}` as const),
          'identity.sessions.last_seen_at',
          'was.last_seen_at as was_seen_at',
          'was.last_use_mac as was_mac',
          'was.last_use_mac_key_version as was_mac_key_version',
          ...signedEndsOfRow(db, heldTo(watch)?.heldTo ?? []),
        ])
        .executeTakeFirst();
      if (
        row === undefined ||
        (await platformCut(db, watch, row)) ||
        !standing(row) ||
        !(await heldToDigest(db, row))
      ) {
        return undefined;
      }
      if (!lastUseHolds(row, { at: row.was_seen_at, mac: row.was_mac, version: row.was_mac_key_version })) {
        // The last use just written would make it whole again: ended, in the caller's transaction, before anyone sees it.
        // (A row that isn't standing stays refused whatever its last use, as it was.)
        await db.deleteFrom('identity.sessions').where('id', '=', row.id).execute();
        return undefined;
      }
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
      const watch = platformWatch();
      const row = await db
        .selectFrom('identity.sessions')
        .select([...SESSION_READ, ...signedEndsOfRow(db, heldTo(watch)?.heldTo ?? [])])
        .where('cookie_hash', '=', hashOf(cookie))
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .executeTakeFirst();
      if (row === undefined || (await platformCut(db, watch, row))) return undefined;
      return (await believed(db, row, lastUseOf(row))) ? row.user_id : undefined;
    },

    async rotate(db, sessionId) {
      if (typeof sessionId !== 'string' || !UUID.test(sessionId)) return undefined;
      const now = clock.now();
      const watch = platformWatch();
      const live = await db
        .selectFrom('identity.sessions')
        .select([...SESSION_READ, ...signedEndsOfRow(db, heldTo(watch)?.heldTo ?? [])])
        .where('id', '=', sessionId)
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .executeTakeFirst();
      // Only a row whose MACs held, and never ended, gets new ones: rotating a forged or put-back row would make it genuine.
      if (live === undefined || (await platformCut(db, watch, live)) || !(await believed(db, live, lastUseOf(live)))) {
        return undefined;
      }
      const cookie = newCookie();
      const cookieHash = hashOf(cookie);
      // Its last use goes with the new cookie's hash, never backwards (as `use`'s).
      const lastSeen = live.last_seen_at > now ? live.last_seen_at : now;
      const lastUse = macOf(keys, lastUseMessage(cookieHash, lastSeen));
      const row = await db
        .updateTable('identity.sessions')
        .set({
          cookie_hash: cookieHash,
          ...macOf(keys, sessionRowMessage({ ...live, cookie_hash: cookieHash })),
          last_seen_at: lastSeen,
          last_use_mac: lastUse.mac,
          last_use_mac_key_version: lastUse.mac_key_version,
        })
        .where('id', '=', sessionId)
        // Only the row as it was checked: changed meanwhile (rotated, or written by anyone else), it is left as it is.
        .where('cookie_hash', '=', live.cookie_hash)
        .where('mac', '=', live.mac)
        .where('last_seen_at', '>', idleSince(now))
        .where('ends_at', '>', now)
        .returning('id')
        .executeTakeFirst();
      if (row === undefined) return undefined;
      return { cookie, retired: { userId: live.user_id, sessionId: live.id, mac: live.mac } };
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
      return row !== undefined && genuine(row) ? { userId: row.user_id, sessionId: row.id } : undefined;
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
