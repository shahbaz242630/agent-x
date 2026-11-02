// Whose turn it is in the anchor check (4D2e E6). A run may end before every
// organisation has had its turn, so the places are kept here between runs: the
// next run goes on from them, and a new round begins only when this one is done.
// All in this process's memory: a restart starts a round, which is no loss, as the
// bound on a turn is counted from each chain's own last check.
//
// `first` comes before the round: an organisation that left the list, whose alarm
// repeats every run; a chain that failed, so its alarm does too; a chain whose
// anchor landed during its check, whose comparison is owed (`unanchored`); one cut
// off by the run's end. A chain seen to be slow keeps to one lane, so however many
// there are, every lane but that one stays with everyone else.

/** A check this long marks its chain slow: most take milliseconds, and this is a quarter of a chain's whole deadline. */
export const SLOW_AFTER_MS = 30_000;

/** The lanes asked for, in half the pool at most: the requests and the other jobs have the rest. A small pool's check goes slower, no less. */
export const lanesWithin = (asked: number, poolMax: number): number =>
  Math.min(asked, Math.max(1, Math.floor(poolMax / 2)));

export interface Turns {
  /**
   * The start of a run. `listed` is all of them, `fresh` those never seen before, `unlisted` those seen and not listed.
   * Places held from the last run stay.
   */
  begin(listed: Iterable<string>, fresh: readonly string[], unlisted: readonly string[]): void;
  /** The organisation this lane should take next, gone from the places; nothing when it has none left this run. */
  next(lane: number): string | undefined;
  /** How a turn went: `again` puts it first next run, and how long it took says whether its chain counts as slow. */
  after(orgId: string, took: { readonly ms: number; readonly again: boolean }): void;
  /** Those still waiting for their turn this round; those to go again have had theirs. */
  waiting(): Iterable<string>;
  /** How many that is. */
  left(): number;
}

export function createTurns(lanes: number): Turns {
  const first = new Set<string>();
  const quick = new Set<string>();
  const slow = new Set<string>();
  const slowChains = new Set<string>();
  const again = new Set<string>();
  // Fresh each run. A set's iterator goes on past deletions, without walking what was deleted again.
  let [firsts, quicks, slows] = [first.values(), quick.values(), slow.values()];

  const place = (orgId: string): void => {
    (slowChains.has(orgId) ? slow : quick).add(orgId);
  };

  const taken = (from: Set<string>, places: Iterator<string, undefined>): string | undefined => {
    const { done, value } = places.next();
    if (done === true) return undefined;
    from.delete(value);
    return value;
  };

  const takeFirst = (): string | undefined => taken(first, firsts);
  const takeQuick = (): string | undefined => taken(quick, quicks);
  const takeSlow = (): string | undefined => taken(slow, slows);

  return {
    begin(listed, fresh, unlisted) {
      for (const orgId of [...unlisted, ...again]) {
        first.add(orgId);
        quick.delete(orgId);
        slow.delete(orgId);
      }
      again.clear();
      const roundDone = quick.size === 0 && slow.size === 0;
      for (const orgId of roundDone ? listed : fresh) if (!first.has(orgId)) place(orgId);
      [firsts, quicks, slows] = [first.values(), quick.values(), slow.values()];
    },
    next(lane) {
      const before = takeFirst();
      if (before !== undefined) return before;
      // Lane 0 goes to the slow chains first where others can carry the rest; a lone lane leaves them to last.
      if (lane === 0 && lanes > 1) return takeSlow() ?? takeQuick();
      return lane === 0 ? (takeQuick() ?? takeSlow()) : takeQuick();
    },
    after(orgId, { ms, again: isAgain }) {
      if (ms >= SLOW_AFTER_MS) slowChains.add(orgId);
      else slowChains.delete(orgId);
      if (isAgain) again.add(orgId);
    },
    *waiting() {
      yield* first;
      yield* quick;
      yield* slow;
    },
    left: () => first.size + quick.size + slow.size,
  };
}
