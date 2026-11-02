// Whose turn it is in the anchor check (4D2e E6). A run may end before every
// organisation has had its turn, so the places are kept here between runs and the
// next run goes on from them. Three kinds wait apart:
// - quick chains go round on their own, and never wait for a slow one;
// - slow chains, seen to take long, go round on their own too: a share of the lanes,
//   and any lane idle;
// - repeats come back every run: an organisation that left the list and a chain that
//   failed, whose alarms repeat; a chain whose anchor landed during its check, whose
//   comparison is owed; one cut off by the run's end. At most half the lanes.
// Repeats and slow chains together leave a lane for quick ones, and a lone lane takes
// turn about, so however many of them there are, fresh chains advance.
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
   * Places held from the last run stay; quick and slow chains each start again where theirs have all had a turn.
   */
  begin(listed: readonly string[], fresh: readonly string[], unlisted: readonly string[]): void;
  /** The organisation to take next, gone from the places; nothing when none is left this run. */
  next(): string | undefined;
  /** How a turn went: `again` makes it a repeat next run, and how long it took says whether its chain counts as slow. */
  after(orgId: string, took: { readonly ms: number; readonly again: boolean }): void;
  /** A repeat next run, for a check that came back after its turn. */
  repeat(orgId: string): void;
  /** Its check has ended, whenever that was: one past its deadline still counts against its kind's share until then. */
  ended(orgId: string): void;
  /** How many still wait for their turn. */
  left(): number;
}

type Kind = 'repeat' | 'slow' | 'quick';

export function createTurns(lanes: number, roundOrder: (orgIds: readonly string[]) => readonly string[]): Turns {
  const places: Record<Kind, Set<string>> = { repeat: new Set(), slow: new Set(), quick: new Set() };
  // Fresh each run. A set's iterator goes on past deletions, without walking what was deleted again.
  let walking: Record<Kind, Iterator<string, undefined>> = {
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

  const take = (kind: Kind): string | undefined => {
    const { done, value } = walking[kind].next();
    if (done === true) return undefined;
    places[kind].delete(value);
    busy.set(value, kind);
    lastWasQuick = kind === 'quick';
    return value;
  };

  return {
    begin(listed, fresh, unlisted) {
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
      const [repeats, slows] = [busyOf('repeat'), busyOf('slow')];
      const othersFirst = lanes === 1 ? lastWasQuick : repeats + slows < lanes - 1;
      const shares: readonly (Kind | false)[] = [
        othersFirst && repeats < mostRepeats && 'repeat',
        othersFirst && slows < mostSlow && 'slow',
        // Past their shares only with no quick chain left to hold up.
        'quick',
        'slow',
        'repeat',
      ];
      for (const kind of shares) {
        const orgId = kind === false ? undefined : take(kind);
        if (orgId !== undefined) return orgId;
      }
      return undefined;
    },
    after(orgId, { ms, again: isAgain }) {
      if (ms >= SLOW_AFTER_MS) slowChains.add(orgId);
      else slowChains.delete(orgId);
      if (isAgain) again.add(orgId);
    },
    repeat(orgId) {
      again.add(orgId);
    },
    ended(orgId) {
      busy.delete(orgId);
    },
    left: () => places.repeat.size + places.quick.size + places.slow.size,
  };
}
