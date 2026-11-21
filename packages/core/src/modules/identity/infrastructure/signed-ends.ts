// The people's sessions' ends signed on the platform chain (R-15, S206), as this
// process has checked them, for sign-ins to believe over a column the database's
// owner could set back (sessionsEndedAt).
//
// Each end is recorded on the platform chain as `identity.sessions_ended`, in the
// transaction that ends the sessions (sessionsEndedEvent). A sign-in needs the
// person's ends recorded since a little before its ID token's time, each checked
// in place with the chain around it, so that a record deleted for a moment and put
// back is seen while it is gone. Checking that stretch afresh for every sign-in
// would read every platform event of the last minutes each time; so the process
// keeps where it has checked up to (the event's place and hash), and the ends it
// saw there for the last KEPT_MS. A sign-in checks only from there to the head,
// usually a few events; an end already checked stays known here if its record is
// deleted afterwards, and a head wound back behind that place breaks the check.
//
// A process just started, one whose last check is older than the sign-in's moment,
// or a sign-in older than what is kept, checks from that moment instead, a page at
// a time, however many events there are: their number never refuses anyone, only
// a chain that doesn't hold does. Sign-ins arriving while a check runs share the
// next one, which starts once it ends (so after each of them read the person's
// row), from the earliest moment any of them asked for.
//
// Every session's end at once (`identity.sessions_all_ended`, AT13h, S208): the console's answer to a platform chain
// cut back (sessions-all-ended.ts), every person's sessions ended at its `at`. Kept as everyone's end here. A head
// wound back behind where this process got to breaks the check, as before, unless such an end was recorded after the
// event it got to (the database's clock, under the head's lock, for both): then the chain was cut back before it, the
// end answers it, and the check goes on afresh from the sign-in's moment, the ends kept carried over. An end this
// process never checked, cut off by a later cut, is no better known afresh than by a process just started (its bound);
// the session such a sign-in opens is still held by the sessions' reads (sessions.ts). Only a wound-back chain is
// answered so: an event edited or missing breaks the check, and raises the alarm, as before.
import type { KeyProvider } from '@agentx/platform/keys';
import { sql } from 'kysely';

import {
  checkPlatformStretch,
  type CheckedPlatformEvent,
  type PlatformEvent,
  platformEventSealed,
  platformEventsSigned,
  type PlatformPoint,
  type PlatformTransaction,
  type StretchCheck,
  type StretchStart,
} from '../../platform-controls/index.ts';

/**
 * The platform chain's signed record of a person's sessions all ended. On the platform's chain, not an organisation's:
 * one person's ends come from every organisation they belong to and from none (a change at the login service), and a
 * sign-in reads them all in one place, outside any organisation's wall.
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

/**
 * The platform chain's signed record of one session ended by a sign-out (S207, R-15): its row is deleted, and the
 * owner could put it back as it was, its MAC still holding. A session this names is never found again (sessions.ts).
 */
export const SESSION_ENDED = 'identity.session_ended';

/** The record of one session's end, for the caller to add to the platform chain in the transaction that deleted it, last of its locks. */
export const sessionEndedEvent = (ended: { readonly userId: string; readonly sessionId: string }, endedAt: Date) =>
  ({
    actor: { type: 'system', id: 'api' },
    action: SESSION_ENDED,
    // The session by its record ID, never its cookie's, as `record`: audit rows never hold a fact named for a session.
    details: { person: ended.userId.toLowerCase(), record: ended.sessionId.toLowerCase(), at: endedAt.toISOString() },
  }) satisfies PlatformEvent;

/**
 * The platform chain's signed record of a session's row as it was before a step-up gave it a new cookie ID (S207 GM-4,
 * R-15): the owner could put that row back, its MAC still holding, and the cookie it held before would sign in again.
 * The row is named by its record ID and the MAC it had (`retired`): a row with that MAC is never found again
 * (sessions.ts). A MAC is no secret and tells nothing of the cookie.
 */
export const SESSION_ROTATED = 'identity.session_rotated';

/** A session's row as a rotation left it behind: its person, record and MAC (sessionRotatedEvent). */
export interface RetiredSession {
  readonly userId: string;
  readonly sessionId: string;
  readonly mac: Buffer;
}

/** The record of a rotation, for the caller to add to the platform chain in the transaction that rotated, last of its locks. */
export const sessionRotatedEvent = (retired: RetiredSession, rotatedAt: Date) =>
  ({
    actor: { type: 'system', id: 'api' },
    action: SESSION_ROTATED,
    details: {
      person: retired.userId.toLowerCase(),
      record: retired.sessionId.toLowerCase(),
      retired: retired.mac.toString('hex'),
      at: rotatedAt.toISOString(),
    },
  }) satisfies PlatformEvent;

/**
 * The platform chain's signed record of every session ended at once (AT13h, S208's partner decision): a process found
 * the chain cut back below the head it held the console's sessions to, so any of them could be one whose signed end the
 * cut took. Every session whose sign-in was before its `at` is no session, and everyone signs in again.
 */
export const SESSIONS_ALL_ENDED = 'identity.sessions_all_ended';

/** Where the end of everyone's sessions is kept beside each person's: no person's ID is this. */
export const EVERYONE = 'everyone';

/** A cut the end answers: the head the reads were held to, and the place of the head found below or beside it. */
export interface CutAnswered {
  readonly held: { readonly seq: bigint; readonly hash: Buffer };
  readonly found: bigint | null;
}

/** The record of every session's end, for the transaction that deletes them, last of its locks. */
export const sessionsAllEndedEvent = ({ held, found }: CutAnswered, endedAt: Date) =>
  ({
    actor: { type: 'system', id: 'api' },
    action: SESSIONS_ALL_ENDED,
    details: {
      reason: 'platform_chain_cut',
      at: endedAt.toISOString(),
      seen: held.seq.toString(),
      seenHash: held.hash.toString('hex'),
      found: found === null ? 'none' : found.toString(),
    },
  }) satisfies PlatformEvent;

/**
 * Each signed end's object in the signed states' digest (AT13c, digest-log.ts): the facts a session's read matches it
 * by, as its ID. A sign-out by its person and record; a rotation by those and the MAC it retired; a person's sessions
 * all ended by the person, its newest place the newest such end.
 */
export const signedEndKey = {
  ended: (person: string, record: string): string => `${person.toLowerCase()}/${record.toLowerCase()}`,
  rotated: (person: string, record: string, retired: string): string =>
    `${person.toLowerCase()}/${record.toLowerCase()}/${retired.toLowerCase()}`,
};

/** A fact of the details, if it is text. */
const textIn = (details: Readonly<Record<string, unknown>>, name: string): string | undefined => {
  const value = details[name];
  return typeof value === 'string' ? value : undefined;
};

/**
 * The digest's object a platform event is, if it is a signed end (AT13c): what the anchor check's walk of the platform
 * chain keeps, so an end deleted below the anchor, its session's row put back, is found at the session's next read.
 * Details that can't be read give none: the chain's own check is what judges the event.
 */
export function signedEndSubjectOf(action: string, detailsJson: string): readonly [string, string] | undefined {
  if (action === SESSIONS_ALL_ENDED) return [action, EVERYONE];
  if (action !== SESSION_ENDED && action !== SESSION_ROTATED && action !== SESSIONS_ENDED) return undefined;
  let details: unknown;
  try {
    details = JSON.parse(detailsJson);
  } catch {
    return undefined;
  }
  if (typeof details !== 'object' || details === null) return undefined;
  const facts = details as Readonly<Record<string, unknown>>;
  const [person, record, retired] = [textIn(facts, 'person'), textIn(facts, 'record'), textIn(facts, 'retired')];
  if (person === undefined) return undefined;
  if (action === SESSIONS_ENDED) return [action, person.toLowerCase()];
  if (record === undefined) return undefined;
  if (action === SESSION_ENDED) return [action, signedEndKey.ended(person, record)];
  return retired === undefined ? undefined : [action, signedEndKey.rotated(person, record, retired)];
}

/** How long ends are kept past the newest event checked: a login flow's ten minutes, two for clocks, and spare. */
const KEPT_MS = 20 * 60 * 1000;

/** A person's latest end checked, and when its record was recorded (the database's clock), to drop it in time. */
interface KeptEnd {
  readonly at: Date;
  readonly recordedAt: Date;
}

/** A check's answer: the chain's problem, or each person's latest end checked, by person, and how many events it read. */
type EndsChecked =
  | Extract<StretchCheck, { kind: 'broken' }>
  | { readonly kind: 'checked'; readonly ends: ReadonlyMap<string, KeptEnd>; readonly read: number };

export interface SignedEnds {
  /**
   * Checks the platform chain through its head, from where this process got to, or from `since` if it got nowhere
   * that covers it, in `tx` (the caller's, or the first waiting one's when it shares a check). Call it after the
   * person's row is read under lock, so the head it reads is no older than the person's last end.
   */
  check(tx: PlatformTransaction, since: Date): Promise<EndsChecked>;
}

/** Where the process got to: the place checked up to, the moment from which every event since is checked, the ends. */
interface Reached {
  readonly point: PlatformPoint | undefined;
  readonly from: Date;
  readonly ends: Map<string, KeptEnd>;
}

/** Each event's end, kept as the person's latest; every session's end at once, as everyone's (EVERYONE). */
function keep(ends: Map<string, KeptEnd>, events: readonly CheckedPlatformEvent[]): void {
  for (const { action, details, recordedAt } of events) {
    if (action !== SESSIONS_ENDED && action !== SESSIONS_ALL_ENDED) continue;
    const facts = JSON.parse(details) as { person?: unknown; at?: unknown };
    const person = action === SESSIONS_ALL_ENDED ? EVERYONE : facts.person;
    const when = typeof facts.at === 'string' ? new Date(facts.at) : undefined;
    if (typeof person !== 'string' || when === undefined || Number.isNaN(when.getTime())) continue;
    const kept = ends.get(person);
    if (kept === undefined || kept.at < when) ends.set(person, { at: when, recordedAt });
  }
}

/**
 * Whether every session was ended at once (AT13h) after the event at `point` was recorded, sealed and at or below the
 * head: the database's clock for both, taken under the head's lock, so such an end found with `point` gone from the
 * chain was recorded on the chain as cut. One statement.
 */
async function allEndedAfter(tx: PlatformTransaction, keys: KeyProvider, point: PlatformPoint): Promise<boolean> {
  const row = await platformEventsSigned(tx)
    .where('e.action', '=', SESSIONS_ALL_ENDED)
    .where('e.recorded_at', '>', point.recordedAt)
    .where('e.seq', '<=', sql<bigint>`(select h.seq from platform_controls.audit_head h limit 1)`)
    .orderBy('e.seq', 'desc')
    .limit(1)
    .executeTakeFirst();
  return row !== undefined && platformEventSealed(keys, row);
}

/** The problems a stretch's check gives for a chain wound back behind a place checked before (checkPlatformStretch). */
const WOUND_BACK: ReadonlySet<string> = new Set(['head', 'anchor']);

export function createSignedEnds(keys: KeyProvider): SignedEnds {
  let reached: Reached | undefined;
  let running: Promise<EndsChecked> | undefined;
  /** The next check, for the sign-ins that came while one ran, from the earliest moment any of them asked for. */
  let waiting: Promise<EndsChecked> | undefined;
  let waitingSince = new Date(0);

  const walkFrom = async (tx: PlatformTransaction, since: Date, was: Reached | undefined): Promise<EndsChecked> => {
    // From where it got to, if that covers `since` and is no older than it; otherwise afresh from `since`.
    const on = was?.point !== undefined && was.from <= since && was.point.recordedAt >= since ? was : undefined;
    // Afresh, nothing kept is needed: the walk reads every end since `since`, and must run through where it got to.
    // Past a cut answered (AT13h, the header), the ends kept are carried over: `was` with no place.
    const ends = on?.ends ?? new Map<string, KeptEnd>(was?.point === undefined ? was?.ends : undefined);
    let start: StretchStart = { since };
    if (on?.point !== undefined) start = { after: on.point };
    else if (was?.point !== undefined) start = { since, through: was.point };
    let read = 0;
    const found = await checkPlatformStretch(tx, keys, start, (events) => {
      read += events.length;
      keep(ends, events);
    });
    // Broken: what was checked before still holds, so where it got to stays; the next check finds the same problem.
    if (found.kind === 'broken') return found;
    const point = found.reached;
    const kept = point === undefined ? undefined : new Date(point.recordedAt.getTime() - KEPT_MS);
    const from = on?.from ?? since;
    const keptFrom = kept === undefined || kept < from ? from : kept;
    for (const [person, end] of ends) if (end.recordedAt < keptFrom) ends.delete(person);
    reached = { point, from: keptFrom, ends };
    return { kind: 'checked', ends, read };
  };

  const checkFrom = async (tx: PlatformTransaction, since: Date): Promise<EndsChecked> => {
    const was = reached;
    const found = await walkFrom(tx, since, was);
    // Only the chain wound back behind where it got to (a head below it, or another event there) is answered so: an event
    // edited or missing breaks the check as before.
    if (found.kind === 'checked' || was?.point === undefined || !WOUND_BACK.has(found.problem.reason)) return found;
    if (!(await allEndedAfter(tx, keys, was.point))) return found;
    // AT13h, the header: the chain cut back behind where it got to, answered by every session's end: afresh from `since`.
    return walkFrom(tx, since, { point: undefined, from: since, ends: was.ends });
  };

  const begin = (tx: PlatformTransaction, since: Date): Promise<EndsChecked> => {
    const run = checkFrom(tx, since).finally(() => {
      if (running === run) running = undefined;
    });
    running = run;
    return run;
  };

  return {
    check(tx, since) {
      if (running === undefined) return begin(tx, since);
      if (waiting === undefined) {
        waitingSince = since;
        const settled = running.then(
          () => undefined,
          () => undefined,
        );
        waiting = settled.then(() => {
          waiting = undefined;
          return begin(tx, waitingSince);
        });
        return waiting;
      }
      if (since < waitingSince) waitingSince = since;
      return waiting;
    },
  };
}
