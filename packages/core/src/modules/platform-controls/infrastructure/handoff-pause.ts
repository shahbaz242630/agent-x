// The platform hand-off pause (Phase 4 B1; BR-11; SEC-OPS-03; partner
// decision 4, S135): one switch for the whole platform that stops every
// hand-off of an approved payment to the bank, moved only by the operator's
// command, with a reason, each move a signed event on the platform chain.
//
// Its row (0057) is believed only as its newest event says: it must point at
// the newest `platform.handoff_paused` or `platform.handoff_resumed` event,
// by seq and ID, and say what that event did; or, with no such event ever,
// be the row as born, paused and pointing at nothing (ADR-014 §4: the first
// production start runs with the pause ON). Anything else (the row deleted,
// flipped, pointed at an older event, or its pointers cleared once an event
// exists) is tampering: the integrity alarm is raised, and every caller reads
// it as paused, so a hand-off fails closed.
//
// The read checks the row against its newest event, and that event alone
// against its seal (its hash and MAC, platformEventSealed), its actor (the
// operator's command, the one actor that moves the pause) and that actor's own
// signature (PL-57, which the API can't make): an event planted
// with the app's own rights (it may add platform events, and moves this row)
// is never believed, the B1 review's catch. The chain whole (an event deleted
// or reordered) is the anchor check's, every 5 minutes; no hand-off pays for
// a full check of its own.
//
// Its newest events deleted once they lie below the platform chain's anchor,
// older than its last 1,000, with the row pointed back at an older one, would
// read true here (R-15). So where the process keeps the signed states' digest
// (AT13c, digest-log.ts), the anchor check's walk keeps the pause's newest
// place there (`pauseSubjectOf`), and a read finding an older newest event, or
// none, is tampering too: the alarm, read as paused. Asked before the event's
// statement, so whatever the walk read was committed before its snapshot.
//
// Nor is a pause the chain's newest events took with them, cut off by the owner
// with an earlier sealed head put back and the row pointed at the resume before
// it, before any anchor passed it (AT13h): every seal still holds, and no walk
// read it. So the event's statement also reads the platform chain's head, held
// to the highest this process has seen (platformCutBack, as a session's read):
// a head below it, or another event at its place, is tampering, read as paused.
//
// The row is the first lock any transaction that reads or moves it takes
// (ADR-006 §6 level 1): FOR SHARE by a hand-off, FOR NO KEY UPDATE by a
// change, so a pause can't commit halfway through a hand-off's check, and
// whichever commits second sees the first. The change records its event
// last, under the chain head's lock (level 13).
import type { StateDigest } from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { PlatformEventRefused, type PlatformActor } from '../domain/event.ts';
import {
  type PlatformChain,
  platformCutBack,
  platformEventSealed,
  platformEventsSigned,
  platformHeadRead,
  type PlatformTransaction,
} from './platform-chain.ts';

/** The one actor whose event moves the pause: the operator's command (apps/operator). */
export const PAUSE_ACTOR: PlatformActor = { type: 'system', id: 'operator' };

/** The platform event that pauses every hand-off. */
export const HANDOFF_PAUSED = 'platform.handoff_paused';

/** The platform event that resumes them. */
export const HANDOFF_RESUMED = 'platform.handoff_resumed';

/** The pause's object in the signed states' digest (AT13c): one for the platform. */
const PAUSE_SUBJECT = ['platform.handoff_pause', 'pause'] as const;

/** The digest's object a platform event is, if it moves the pause: what the anchor check's walk keeps (AT13c). */
export const pauseSubjectOf = (action: string): readonly [string, string] | undefined =>
  action === HANDOFF_PAUSED || action === HANDOFF_RESUMED ? PAUSE_SUBJECT : undefined;

/** The pause as its row and newest event agree on it: since when, and by which event (none for the row as born). */
export type HandoffPause =
  | {
      readonly outcome: 'paused' | 'running';
      /** When its event was recorded; null for the row as born, paused by no event. */
      readonly since: Date | null;
      readonly eventId: string | null;
    }
  | { readonly outcome: 'tampered' };

/** How the read locks the row: FOR SHARE to rest a hand-off on it, FOR NO KEY UPDATE to change it. */
export type HandoffPauseLock = 'share' | 'change';

/** A pause or resume to record, as the operator asks it. */
export interface HandoffPauseChange {
  /** True to pause every hand-off, false to resume them. */
  readonly paused: boolean;
  /** Why, as a case reference: sealed on the platform chain, never logged. */
  readonly reason: string;
  readonly actor: PlatformActor;
  /** The release that runs the change, named in its event. */
  readonly release: string;
  /** The job's run, as Azure names it; null for a run by hand. */
  readonly run: string | null;
}

/** What a change did: recorded it, found the pause there already (nothing recorded), or found the row tampered with. */
export type HandoffPauseChanged =
  | {
      readonly outcome: 'changed';
      readonly eventId: string;
      readonly seq: bigint;
      readonly recordedAt: Date;
    }
  | {
      readonly outcome: 'unchanged';
      readonly paused: boolean;
      readonly since: Date | null;
      readonly eventId: string | null;
    }
  | { readonly outcome: 'tampered' };

/** The row and the newest pause or resume, as stored. */
interface Read {
  /** The row, or why there is none to believe: none at all, or more than the key allows. */
  readonly row:
    { readonly paused: boolean; readonly seq: bigint | null; readonly id: string | null } | 'missing' | 'unreadable';
  readonly newest:
    | {
        readonly seq: bigint;
        readonly id: string;
        readonly action: string;
        readonly at: Date;
        /** Sealed as its hash and MAC say, and recorded by the operator's command. */
        readonly believed: boolean;
      }
    | undefined;
  /** Where the digest says the newest pause or resume is (AT13c), if it says. */
  readonly known: bigint | undefined;
  /** Where the platform chain was cut back below the head this process saw (AT13h), if it was. */
  readonly cut?: bigint | undefined;
}

/** What the pause's read is held to: the digest the process keeps, if it keeps one. */
type PauseDigest = (Pick<StateDigest, 'latest'> & Partial<Pick<StateDigest, 'heads'>>) | undefined;

/**
 * The row, locked, then the newest event. Two statements, in this order: under
 * read committed each statement sees what was committed when it began, so the
 * event is read after the lock is held, once a change in flight has committed
 * its row and its event together. One statement joining the two would see the
 * event as it was before the wait while Postgres re-reads the row as it is
 * after, and take a pause just made for tampering.
 */
async function readPause(
  tx: PlatformTransaction,
  lock: HandoffPauseLock,
  keys: KeyProvider,
  digest: PauseDigest,
): Promise<Read> {
  const locking = tx.selectFrom('platform_controls.handoff_pause').select(['paused', 'event_seq', 'event_id']);
  const rows = await (lock === 'share' ? locking.forShare() : locking.forNoKeyUpdate()).execute();
  // Before the event's statement: what the walk read was committed before that statement's snapshot.
  const known = digest?.latest({ kind: 'platform' }, ...PAUSE_SUBJECT);
  const watch = digest?.heads?.({ kind: 'platform' });
  const newest = await platformEventsSigned(tx)
    .select(platformHeadRead(watch?.seen?.seq))
    .where('e.action', 'in', [HANDOFF_PAUSED, HANDOFF_RESUMED])
    .orderBy('e.seq', 'desc')
    .limit(1)
    .executeTakeFirst();
  // The key holds one row at most; should the owner drop it and add a second, neither can be believed.
  const [row, ...others] = rows;
  let read: Read['row'] = 'unreadable';
  if (row === undefined) read = 'missing';
  else if (others.length === 0) read = { paused: row.paused, seq: row.event_seq, id: row.event_id };
  return {
    row: read,
    known,
    // With no pause or resume ever, nothing was there to cut off but the row as born, which is paused.
    cut: newest === undefined ? undefined : platformCutBack(keys, tx, watch, newest),
    newest:
      newest === undefined
        ? undefined
        : {
            seq: newest.seq,
            id: newest.id,
            action: newest.action,
            at: newest.recorded_at,
            // Every platform event's actor is a process (`system`, event.ts): its name is what tells the operator's.
            believed: newest.actor_id === PAUSE_ACTOR.id && platformEventSealed(keys, newest),
          },
  };
}

/** Whether the newest pause or resume read is older than the digest's, or gone (AT13c): moved or deleted past the app. */
const rolledBack = ({ newest, known }: Read): boolean =>
  known !== undefined && (newest === undefined || newest.seq < known);

/** The pause its row and newest event agree on, or undefined when they don't. */
function agreed({ row, newest }: Read): HandoffPause | undefined {
  if (typeof row === 'string') return undefined;
  if (newest === undefined) {
    // Never moved: believed only as born, paused by no event.
    return row.paused && row.seq === null && row.id === null
      ? { outcome: 'paused', since: null, eventId: null }
      : undefined;
  }
  // An event's ID is its own (the table's unique key): the row names the newest event by it.
  const same = row.id?.toLowerCase() === newest.id.toLowerCase();
  if (!newest.believed || !same || row.paused !== (newest.action === HANDOFF_PAUSED)) return undefined;
  return { outcome: row.paused ? 'paused' : 'running', since: newest.at, eventId: newest.id };
}

/**
 * The hand-off pause, its row locked as `lock` asks, the first lock the
 * caller's transaction takes (ADR-006 §6 level 1). `tampered` when the row
 * and its newest event don't agree, or that event is older than the digest's
 * (`digest`, AT13c), with the integrity alarm raised: a caller reads it as
 * paused, so nothing is handed off on a row that can't be believed.
 */
export async function handoffPauseOf(
  tx: PlatformTransaction,
  lock: HandoffPauseLock,
  { keys, logger, digest }: { readonly keys: KeyProvider; readonly logger: Logger; readonly digest?: PauseDigest },
): Promise<HandoffPause> {
  const read = await readPause(tx, lock, keys, digest);
  const pause = rolledBack(read) || read.cut !== undefined ? undefined : agreed(read);
  if (pause !== undefined) return pause;
  logger.error('audit.integrity_failed', {
    chain: 'platform',
    check: 'handoff_pause',
    reason: pauseProblem(read),
    ...(placeOf(read) === undefined ? {} : { seq: String(placeOf(read)) }),
  });
  return { outcome: 'tampered' };
}

/** Where the alarm says the pause's newest event should be: the head seen where the chain was cut back, else the digest's. */
const placeOf = (read: Read): bigint | undefined => read.cut ?? read.known;

/** What the alarm says of a pause not believed: the row's own problem first, then the digest's, then the event's. */
function pauseProblem(read: Read): string {
  if (typeof read.row === 'string') return read.row;
  if (rolledBack(read)) return 'rolled_back';
  if (read.cut !== undefined) return 'cut_back';
  return read.newest?.believed === false ? 'unsealed' : 'mismatch';
}

/**
 * Pauses or resumes every hand-off, in the caller's transaction: the row
 * locked first, then, unless it is that way already, the platform event
 * recorded (the head's lock last, level 13) and the row pointed at it.
 * `unchanged` records nothing; `tampered` changes nothing, the alarm raised.
 * Throws PlatformEventRefused for a reason left blank (SEC-OPS-03: a resume
 * needs a reason, and a pause gives one too).
 */
export async function changeHandoffPause(
  tx: PlatformTransaction,
  { chain, keys, logger }: { readonly chain: PlatformChain; readonly keys: KeyProvider; readonly logger: Logger },
  { paused, reason, actor, release, run }: HandoffPauseChange,
): Promise<HandoffPauseChanged> {
  if (reason.trim() === '') throw new PlatformEventRefused(['details.reason must be given']);
  // Any other actor's event would never be believed: the pause would read as tampered for good.
  if (actor.id !== PAUSE_ACTOR.id) {
    throw new PlatformEventRefused(['actor must be the operator']);
  }
  const now = await handoffPauseOf(tx, 'change', { keys, logger });
  if (now.outcome === 'tampered') return now;
  if ((now.outcome === 'paused') === paused) {
    return { outcome: 'unchanged', paused, since: now.since, eventId: now.eventId };
  }
  const recorded = await chain.record(tx, {
    actor,
    action: paused ? HANDOFF_PAUSED : HANDOFF_RESUMED,
    details: { reason, release, run },
  });
  await tx
    .updateTable('platform_controls.handoff_pause')
    .set({ paused, event_seq: recorded.seq, event_id: recorded.id })
    .where('only_row', '=', true)
    .execute();
  return { outcome: 'changed', eventId: recorded.id, seq: recorded.seq, recordedAt: recorded.recordedAt };
}
