// SEC-AV-09, AV-8 (ADR-012 §9, ADR-013 rule 6): a flood of one kind of log
// line must not fill the log store's daily cap and leave us blind. Each event
// gets a budget per clock minute. Lines past it are held back, but never
// silently: after the minute, the logger writes one `log.suppressed` line per
// event with the exact count and the minute it covers, so counts and alerts
// stay right however late the line is written.
//
// Budgets (4D2e Stage F, PL-52): each event gets the configured cap on its
// own, warnings, errors and security lines included, since an outsider can
// drive those and uncapped they could fill the workspace's daily cap and stop
// all logging. The decision line gets 20,000 a minute a process, since peak
// traffic passes 600 in seconds. Info and debug lines of the money and audit
// families are never held back: their volume follows real payments and chain
// events, not callers. A warning or error of any family, those included, keeps
// the configured cap on its own event name, since a signed-in caller can repeat
// some (a backlog line per page read): a flood of one never hides another, and
// an alarm's first lines always get out.

/** How many lines of one event were held back in one minute, and the level to write their count at. */
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

/** pino's warn level number: every warning and error is capped, and a count of lost decision lines is one. */
const WARN = 40;

/** The decision line (PL-52): its own budget, and a count of lost ones is a warning. */
export const DECISION_EVENT = 'spend_request.decided';
export const DECISION_BUDGET_PER_MINUTE = 20_000;

/** Event families whose info and debug lines are never held back, nor counted: the hand-off, payment moves, the audit trail. */
export const NEVER_HELD_BACK = [
  'handoff.',
  'payment.',
  'payment_check.',
  'instruction.',
  'transaction.',
  'audit.',
] as const;

/** An event's lines a minute at this level before any are held back; infinite for those never held back. */
export function budgetOf(event: string, level: number, capPerMinute: number): number {
  if (level < WARN && NEVER_HELD_BACK.some((family) => event.startsWith(family))) return Number.POSITIVE_INFINITY;
  // A configured cap above the decision budget, as in a load run, stands for decisions too.
  return event === DECISION_EVENT ? Math.max(capPerMinute, DECISION_BUDGET_PER_MINUTE) : capPerMinute;
}

/**
 * A memory bound: events beyond this many in one minute share one bucket.
 * Event names are fixed in code, so this is only reached by a bug or an attack.
 */
export const MAX_EVENTS_PER_MINUTE = 1000;
export const OTHER_EVENTS = '(other events)';

interface Tally {
  readonly budget: number;
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
    const count = tally.lines - Math.max(tally.budget, tally.reported);
    // Decision lines lost make the denial-surge alert undercount (PL-52), so their count is a warning.
    const level = event === DECISION_EVENT ? Math.max(tally.level, WARN) : tally.level;
    if (count > 0) finished.push({ event, count, level, minuteStart: minute * MINUTE_MS });
    tally.reported = Math.max(tally.lines, tally.budget);
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
      // Never counted, so they take no room in the tallies either.
      if (budgetOf(event, level, capPerMinute) === Number.POSITIVE_INFINITY) return true;
      const bucket = tallies.has(event) || tallies.size < MAX_EVENTS_PER_MINUTE ? event : OTHER_EVENTS;
      const tally = tallies.get(bucket) ?? {
        budget: budgetOf(bucket, level, capPerMinute),
        lines: 0,
        reported: 0,
        level: 0,
      };
      tallies.set(bucket, tally);
      tally.lines += 1;
      if (tally.lines <= tally.budget) return true;
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
