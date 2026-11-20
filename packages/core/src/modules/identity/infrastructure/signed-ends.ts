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
import type { KeyProvider } from '@agentx/platform/keys';

import {
  checkPlatformStretch,
  type CheckedPlatformEvent,
  type PlatformEvent,
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

/** Each event's end, kept as the person's latest. */
function keep(ends: Map<string, KeptEnd>, events: readonly CheckedPlatformEvent[]): void {
  for (const { action, details, recordedAt } of events) {
    if (action !== SESSIONS_ENDED) continue;
    const { person, at } = JSON.parse(details) as { person?: unknown; at?: unknown };
    const when = typeof at === 'string' ? new Date(at) : undefined;
    if (typeof person !== 'string' || when === undefined || Number.isNaN(when.getTime())) continue;
    const kept = ends.get(person);
    if (kept === undefined || kept.at < when) ends.set(person, { at: when, recordedAt });
  }
}

export function createSignedEnds(keys: KeyProvider): SignedEnds {
  let reached: Reached | undefined;
  let running: Promise<EndsChecked> | undefined;
  /** The next check, for the sign-ins that came while one ran, from the earliest moment any of them asked for. */
  let waiting: Promise<EndsChecked> | undefined;
  let waitingSince = new Date(0);

  const checkFrom = async (tx: PlatformTransaction, since: Date): Promise<EndsChecked> => {
    const was = reached;
    // From where it got to, if that covers `since` and is no older than it; otherwise afresh from `since`.
    const on = was?.point !== undefined && was.from <= since && was.point.recordedAt >= since ? was : undefined;
    // Afresh, nothing kept is needed: the walk reads every end since `since`, and must run through where it got to.
    const ends = on?.ends ?? new Map<string, KeptEnd>();
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
