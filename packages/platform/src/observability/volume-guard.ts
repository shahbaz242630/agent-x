// SEC-AV-09, AV-8 (ADR-012 §9, ADR-013 rule 6): a flood of one kind of log
// line must not fill the log store's daily cap and leave us blind. Each event
// gets a cap per clock minute. Lines past the cap are held back, but never
// silently: after the minute, the logger writes one `log.suppressed` line per
// event with the exact count and the minute it covers, so counts and alerts
// stay right however late the line is written.

/** How many lines of one event were held back in one minute, and the most severe level among them. */
interface Suppressed {
  readonly event: string;
  readonly count: number;
  /** pino's level number: the summary is written at this level, so a level filter never hides it. */
  readonly level: number;
  /** The start of the minute, in milliseconds since 1970. */
  readonly minuteStart: number;
}

export interface VolumeGuard {
  /** Counts one line of this event at this level, and says whether it may be written. */
  admit(event: string, level: number): boolean;
  /**
   * Returns the counts held back in finished minutes, once each. With
   * `includeCurrentMinute`, as at shutdown, the current minute's so far too;
   * its later lines are still capped, and counted from there.
   */
  takeSuppressed(includeCurrentMinute?: boolean): readonly Suppressed[];
}

export const MINUTE_MS = 60_000;

/**
 * A memory bound: events beyond this many in one minute share one bucket.
 * Event names are fixed in code, so this is only reached by a bug or an attack.
 */
export const MAX_EVENTS_PER_MINUTE = 1000;
export const OTHER_EVENTS = '(other events)';

interface Tally {
  lines: number;
  /** Lines already reported by an early (shutdown) report. */
  reported: number;
  /** The most severe level among the lines held back and not yet reported. */
  level: number;
}

export function createVolumeGuard(capPerMinute: number, now: () => number): VolumeGuard {
  let minute = Math.floor(now() / MINUTE_MS);
  let tallies = new Map<string, Tally>();
  let finished: Suppressed[] = [];

  function report(event: string, tally: Tally): void {
    const count = tally.lines - Math.max(capPerMinute, tally.reported);
    if (count > 0) finished.push({ event, count, level: tally.level, minuteStart: minute * MINUTE_MS });
    tally.reported = Math.max(tally.lines, capPerMinute);
    tally.level = 0;
  }

  function roll(): void {
    // Minutes only move forward: a clock stepped back can't reopen a minute and reset its caps.
    const current = Math.floor(now() / MINUTE_MS);
    if (current <= minute) return;
    for (const [event, tally] of tallies) report(event, tally);
    tallies = new Map();
    minute = current;
  }

  return {
    admit(event, level) {
      roll();
      const bucket = tallies.has(event) || tallies.size < MAX_EVENTS_PER_MINUTE ? event : OTHER_EVENTS;
      const tally = tallies.get(bucket) ?? { lines: 0, reported: 0, level: 0 };
      tallies.set(bucket, tally);
      tally.lines += 1;
      if (tally.lines <= capPerMinute) return true;
      tally.level = Math.max(tally.level, level);
      return false;
    },
    takeSuppressed(includeCurrentMinute = false) {
      roll();
      if (includeCurrentMinute) {
        for (const [event, tally] of tallies) report(event, tally);
      }
      const taken = finished;
      finished = [];
      return taken;
    },
  };
}
