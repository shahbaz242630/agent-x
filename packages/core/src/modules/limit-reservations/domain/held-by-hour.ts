// What a payee's window holds, hour by hour (0112, GM-1b; ADR-006 §9; ADR-014
// §5): each whole hour since 1970 that holds anything, with the minor units its
// reservations hold, as a payee window's sealed `held_by_hour` writes it
// (`hour:amount`, comma between, in order, each hour once and holding at least
// 1). Kept back as far as any split window can reach, and an hour more for two
// processes' clocks a little apart; older hours go as the row is next written.
//
// A split window counts whole hours: from the hour its start falls in, so up
// to an hour more than its length, never less (the safer side: a payment
// split across the window's edge is still counted with the rest). The exact
// instant would need every reservation's own time sealed, which the database's
// owner could otherwise move across the edge unseen (R-15).
import { HOUR_MS, MOST_WINDOW_HOURS, windowStart } from '../../../shared-kernel/index.ts';

/** Minor units held in each hour, by the hour's number since 1970; none for an hour holding nothing. */
export type HeldByHour = ReadonlyMap<number, bigint>;

/** The whole hour `at` falls in, counted from 1970. */
export const hourOf = (at: Date): number => Math.floor(at.getTime() / HOUR_MS);

/** The first hour a split window of `hours` ending at `now` counts, whole: the hour its start falls in. */
export const windowFromHour = (now: Date, hours: number): number => hourOf(windowStart(now, hours));

/** The oldest hour kept at `now`: every hour the longest window can count, and one more for clocks a little apart. */
export const keptFromHour = (now: Date): number => hourOf(now) - MOST_WINDOW_HOURS - 1;

/** One hour as written: its number and its amount, each in canonical form (no leading zero, at least 1). */
const ENTRY = /^(0|[1-9][0-9]{0,8}):([1-9][0-9]{0,18})$/;

/** The hours a sealed `held_by_hour` names, or undefined for text the app never writes (out of order, an hour twice). */
export function heldByHourFrom(text: string): HeldByHour | undefined {
  const held = new Map<number, bigint>();
  if (text === '') return held;
  let last = -1;
  for (const entry of text.split(',')) {
    const found = ENTRY.exec(entry);
    if (found === null) return undefined;
    const hour = Number(found[1]);
    if (hour <= last) return undefined;
    last = hour;
    held.set(hour, BigInt(String(found[2])));
  }
  return held;
}

/** The text a payee window seals for what it holds: its hours in order, each holding something. */
export const heldByHourText = (held: HeldByHour): string =>
  [...held]
    .filter(([, amount]) => amount > 0n)
    .toSorted(([a], [b]) => a - b)
    .map(([hour, amount]) => `${String(hour)}:${amount.toString()}`)
    .join(',');

/** The hours kept from `keptFrom` on, older ones gone. */
const keptOf = (held: HeldByHour, keptFrom: number): Map<number, bigint> =>
  new Map([...held].filter(([hour]) => hour >= keptFrom));

/** `amount` added at `hour`, the hours before `keptFrom` gone. */
export function heldAdded(held: HeldByHour, hour: number, amount: bigint, keptFrom: number): HeldByHour {
  const kept = keptOf(held, keptFrom);
  kept.set(hour, (kept.get(hour) ?? 0n) + amount);
  return kept;
}

/**
 * Each `amount` taken off its hour, the hours before `keptFrom` gone: an hour gone already has nothing left to take
 * (no window counts it). `short`: an hour kept held less than was taken from it, which goes to nothing, never below:
 * something past the app took it first.
 */
export function heldTaken(
  held: HeldByHour,
  taken: readonly { readonly hour: number; readonly amount: bigint }[],
  keptFrom: number,
): { readonly held: HeldByHour; readonly short: boolean } {
  const kept = keptOf(held, keptFrom);
  let short = false;
  for (const { hour, amount } of taken) {
    if (hour < keptFrom) continue;
    const before = kept.get(hour) ?? 0n;
    if (before < amount) short = true;
    if (before > amount) kept.set(hour, before - amount);
    else kept.delete(hour);
  }
  return { held: kept, short };
}

/** What the hours from `fromHour` on hold. */
export const heldSince = (held: HeldByHour, fromHour: number): bigint =>
  [...held].reduce((sum, [hour, amount]) => (hour >= fromHour ? sum + amount : sum), 0n);

/**
 * A payee's split total from its rows' totals over the window: its supplier's and its key's, less the pair's, which
 * both count (ADR-014 §3's supplier-or-key rule). Never less than either row alone: a pair's row holding more than
 * the two share (past the app) must not take what either holds away.
 */
export const payeeSplit = (supplier: bigint, key: bigint, pair: bigint): bigint => {
  const both = supplier + key - pair;
  const most = supplier > key ? supplier : key;
  return both > most ? both : most;
};
