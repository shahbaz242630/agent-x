// Business periods (ADR-006 §4; PRD §3.1): a mandate lineage fixes its IANA
// time zone (default Asia/Dubai) and its split-check window when made, and
// every monthly total and rolling window is computed here, by these two
// functions alone, so no two places can draw a boundary differently.
//
// Built on Intl's time-zone data (Node 24 has no Temporal without a flag). A
// month starts at the first instant whose local date is its 1st: where the
// clocks skip midnight that is the end of the gap, and where midnight happens
// twice, the earlier one.
import { HOUR_MS } from './clock.ts';

/** A lineage's default time zone: AED's (PRD §3.1). */
export const DEFAULT_TIME_ZONE = 'Asia/Dubai';

/** A calendar month in a time zone: from its first instant up to the next month's first, and its name. */
export interface Period {
  /** `YYYY-MM`, as the zone's own calendar names it. */
  readonly month: string;
  readonly start: Date;
  /** The next month's start: a period holds every instant from `start` up to, not including, `end`. */
  readonly end: Date;
}

/**
 * The zone as this runtime names it, for a lineage to keep: an IANA zone in
 * any spelling Intl takes (`asia/dubai` is `Asia/Dubai`); undefined for one it
 * doesn't know or a bare UTC offset (`+04:00`), which has no daylight-saving
 * rules. Intl may name a zone by an older alias (`Asia/Katmandu`), which every
 * later runtime still takes.
 */
export function timeZoneOf(zone: string): string | undefined {
  try {
    const named = formatOf(zone).resolvedOptions().timeZone;
    return /^[+-]/.test(named) ? undefined : named;
  } catch {
    return undefined;
  }
}

/** The most formatters kept: every zone Intl knows, several times over. */
const MOST_FORMATS = 2_000;
const formats = new Map<string, Intl.DateTimeFormat>();

/**
 * One formatter a zone, kept, as building one is far slower than using it;
 * RangeError for a zone it doesn't know. Kept by the spelling asked for, so
 * the store is emptied when full: odd spellings can't grow it without end.
 */
function formatOf(zone: string): Intl.DateTimeFormat {
  let format = formats.get(zone);
  if (format === undefined) {
    if (formats.size >= MOST_FORMATS) formats.clear();
    format = new Intl.DateTimeFormat('en-US', {
      timeZone: zone,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    });
    formats.set(zone, format);
  }
  return format;
}

/** The zone's wall clock at `ms`, read as if it were UTC: comparable as a number, whole seconds. */
function wallAt(ms: number, zone: string): number {
  const parts: Record<string, number> = {};
  for (const { type, value } of formatOf(zone).formatToParts(new Date(ms))) parts[type] = Number(value);
  const { year = 0, month = 1, day = 1, hour = 0, minute = 0, second = 0 } = parts;
  return Date.UTC(year, month - 1, day, hour, minute, second);
}

/** The zone's offset from UTC at `ms`, in milliseconds, to the second. */
const offsetAt = (ms: number, zone: string): number => wallAt(ms, zone) - Math.floor(ms / 1000) * 1000;

/** The longest any zone is from UTC, with a day's margin for a transition beside it. */
const FARTHEST_MS = 40 * HOUR_MS;

/**
 * The first instant at which the zone's clock reads `wall` or later (`wall`
 * a local time read as UTC). Two offset guesses cover a transition near it:
 * a local time that happens twice takes the earlier, and one the clocks skip
 * is found by halving the gap to the millisecond.
 */
function firstAtOrAfter(wall: number, zone: string): number {
  const guesses = [offsetAt(wall - FARTHEST_MS / 2, zone), offsetAt(wall + FARTHEST_MS / 2, zone)].map(
    (offset) => wall - offset,
  );
  const exact = guesses.filter((ms) => wallAt(ms, zone) === wall);
  if (exact.length > 0) return Math.min(...exact);
  // Skipped: the guess by the offset after the gap falls before it, reading less than `wall`, the other after it.
  let before = Math.min(...guesses);
  let after = Math.max(...guesses);
  if (wallAt(before, zone) >= wall || wallAt(after, zone) < wall) {
    throw new RangeError(`No first instant found for a local time in ${zone}`);
  }
  while (after - before > 1) {
    const middle = Math.floor((before + after) / 2);
    if (wallAt(middle, zone) >= wall) after = middle;
    else before = middle;
  }
  return after;
}

/** The calendar month holding `at` in `zone`; RangeError for a zone this runtime doesn't know. */
export function periodOf(at: Date, zone: string): Period {
  const local = new Date(wallAt(at.getTime(), zone));
  const year = local.getUTCFullYear();
  const month = local.getUTCMonth();
  const start = firstAtOrAfter(Date.UTC(year, month, 1), zone);
  const end = firstAtOrAfter(Date.UTC(year, month + 1, 1), zone);
  return {
    month: `${String(year).padStart(4, '0')}-${String(month + 1).padStart(2, '0')}`,
    start: new Date(start),
    end: new Date(end),
  };
}

/** The longest split-check window: 31 days. */
const MOST_WINDOW_HOURS = 31 * 24;

/**
 * Where a rolling window ending at `at` begins (ADR-006 §9: the split check's,
 * default 24 hours, so splitting an order across midnight gains nothing): a
 * whole number of hours, from 1 to 31 days'.
 */
export function windowStart(at: Date, hours: number): Date {
  if (!Number.isInteger(hours) || hours < 1 || hours > MOST_WINDOW_HOURS) {
    throw new RangeError(`A window is a whole number of hours, from 1 to ${String(MOST_WINDOW_HOURS)}`);
  }
  return new Date(at.getTime() - hours * HOUR_MS);
}
