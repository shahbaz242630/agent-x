// Whose turn it is in the anchor check (4D2e E6). A run may end before every
// organisation has had its turn, so the places are kept here between runs and the
// next run goes on from them. Three kinds wait apart:
// - quick chains go round on their own, and never wait for a slow one;
// - slow chains, seen to take long, go round on their own too: a share of the lanes,
//   and any lane idle;
// - repeats come back every run: an organisation that left the list and a chain that
//   failed, whose alarms repeat; a chain whose anchor landed during its check, whose
//   comparison is owed; one cut off by the run's end. At most half the lanes;
// - chains past AGENTX_AUDIT_MOST_ORGANISATIONS, kept here as no more than a cursor through
//   the list: the same share as the slow ones, turn about with them. Past a restart it
//   starts over.
// Repeats and the shares together leave a lane for quick ones, and a lone lane takes turn
// about, so however many of them there are, fresh chains advance.
//
// Places are this process's memory, and a restart loses them. What survives is the
// order each round starts in (`roundOrder`): by the store, oldest anchor first, and an
// idle chain's anchor is signed again as it is checked (anchor-check.ts), so restarts
// more often than a round still reach every chain. With no store, a fresh shuffle.
import { randomInt } from 'node:crypto';

/** A check this long marks its chain slow: most take milliseconds, and this is a quarter of a chain's whole deadline. */
export const SLOW_AFTER_MS = 30_000;

/** The lanes asked for, in half the pool at most: the requests and the other jobs have the rest. A small pool's check goes slower, no less. */
export const lanesWithin = (asked: number, poolMax: number): number =>
  Math.min(asked, Math.max(1, Math.floor(poolMax / 2)));

/** A new order each time, so with no store to go by, restarts can't keep the same tail unreached. */
export function shuffledAfresh(orgIds: readonly string[]): string[] {
  const shuffled = [...orgIds];
  for (let last = shuffled.length - 1; last > 0; last -= 1) {
    const other = randomInt(last + 1);
    [shuffled[last], shuffled[other]] = [shuffled[other] as string, shuffled[last] as string];
  }
  return shuffled;
}

export interface Turns {
  /**
   * The start of a run. `listed` is all of them, `fresh` those never seen before, `unlisted` those seen and not listed.
   * `pastCap` are those no place is kept for, each taken at most once a run, from where the last run left off.
   * Places held from the last run stay; quick and slow chains each start again where theirs have all had a turn.
   */
  begin(
    listed: readonly string[],
    fresh: readonly string[],
    unlisted: readonly string[],
    pastCap?: readonly string[],
  ): void;
  /** The organisation to take next, gone from the places; nothing when none is left this run. */
  next(): string | undefined;
  /**
   * How a turn went: `again` makes it a repeat next run. `ms` is how long a check took that ran to its end or its deadline,
   * and says whether its chain counts as slow; with none (a check cut off, or that met one not finished) its mark stands.
   */
  after(orgId: string, took: { readonly ms: number | undefined; readonly again: boolean }): void;
  /** A repeat next run, for a check that came back after its turn. */
  repeat(orgId: string): void;
  /** Its check has ended, whenever that was: one past its deadline still counts against its kind's share until then. */
  ended(orgId: string): void;
  /** How many still wait for their turn. */
  left(): number;
  /** Whether the chains past the cap start a new round this run. */
  pastCapStarts(): boolean;
}

type Kind = 'repeat' | 'slow' | 'pastCap' | 'quick';

export function createTurns(lanes: number, roundOrder: (orgIds: readonly string[]) => readonly string[]): Turns {
  const places: Record<'repeat' | 'slow' | 'quick', Set<string>> = {
    repeat: new Set(),
    slow: new Set(),
    quick: new Set(),
  };
  let pastCap: readonly string[] = [];
  let cursor = 0;
  let pastCapThisRun = 0;
  let lastShared: Kind = 'pastCap';
  // Fresh each run. A set's iterator goes on past deletions, without walking what was deleted again.
  let walking: Record<'repeat' | 'slow' | 'quick', Iterator<string, undefined>> = {
    repeat: places.repeat.values(),
    slow: places.slow.values(),
    quick: places.quick.values(),
  };
  const slowChains = new Set<string>();
  const again = new Set<string>();
  const busy = new Map<string, Kind>();
  // A lone lane's turn about: it starts with what may be an alarm owed.
  let lastWasQuick = true;

  const mostRepeats = Math.max(1, Math.floor(lanes / 2));
  const mostSlow = Math.max(1, Math.floor(lanes / 4));
  const busyOf = (kind: Kind): number => [...busy.values()].filter((each) => each === kind).length;

  const kindOf = (orgId: string): 'slow' | 'quick' => (slowChains.has(orgId) ? 'slow' : 'quick');

  const taken = (kind: Kind, orgId: string): string => {
    busy.set(orgId, kind);
    lastWasQuick = kind === 'quick';
    if (kind === 'slow' || kind === 'pastCap') lastShared = kind;
    return orgId;
  };

  const takePastCap = (): string | undefined => {
    while (pastCapThisRun > 0) {
      const orgId = pastCap[cursor] as string;
      cursor = (cursor + 1) % pastCap.length;
      pastCapThisRun -= 1;
      if (!places.repeat.has(orgId)) return taken('pastCap', orgId);
    }
    return undefined;
  };

  const take = (kind: Kind): string | undefined => {
    if (kind === 'pastCap') return takePastCap();
    const { done, value } = walking[kind].next();
    if (done === true) return undefined;
    places[kind].delete(value);
    return taken(kind, value);
  };

  return {
    begin(listed, fresh, unlisted, pastCapNow = []) {
      pastCap = pastCapNow;
      if (cursor >= pastCap.length) cursor = 0;
      pastCapThisRun = pastCap.length;
      for (const orgId of [...unlisted, ...again]) {
        places.repeat.add(orgId);
        places.quick.delete(orgId);
        places.slow.delete(orgId);
      }
      again.clear();
      for (const kind of ['quick', 'slow'] as const) {
        if (places[kind].size > 0) continue;
        const round = listed.filter((orgId) => kindOf(orgId) === kind && !places.repeat.has(orgId));
        for (const orgId of roundOrder(round)) places[kind].add(orgId);
      }
      for (const orgId of fresh) if (!places.repeat.has(orgId)) places[kindOf(orgId)].add(orgId);
      walking = { repeat: places.repeat.values(), slow: places.slow.values(), quick: places.quick.values() };
    },
    next() {
      const repeats = busyOf('repeat');
      const shared: readonly ('slow' | 'pastCap')[] = lastShared === 'slow' ? ['pastCap', 'slow'] : ['slow', 'pastCap'];
      const othersFirst = lanes === 1 ? lastWasQuick : busy.size - busyOf('quick') < lanes - 1;
      const shares: readonly (Kind | false)[] = [
        othersFirst && repeats < mostRepeats && 'repeat',
        ...shared.map((kind) => othersFirst && busyOf(kind) < mostSlow && kind),
        // Past their shares only with no quick chain left to hold up.
        'quick',
        ...shared,
        'repeat',
      ];
      for (const kind of shares) {
        const orgId = kind === false ? undefined : take(kind);
        if (orgId !== undefined) return orgId;
      }
      return undefined;
    },
    after(orgId, { ms, again: isAgain }) {
      if (ms !== undefined) {
        if (ms >= SLOW_AFTER_MS) slowChains.add(orgId);
        else slowChains.delete(orgId);
      }
      if (isAgain) again.add(orgId);
    },
    repeat(orgId) {
      again.add(orgId);
    },
    ended(orgId) {
      busy.delete(orgId);
    },
    left: () => places.repeat.size + places.quick.size + places.slow.size + pastCapThisRun,
    pastCapStarts: () => cursor === 0,
  };
}
