// The background work's health over one Stage G step (4D2e design item 9),
// from lines the API and the jobs already write (no new line): the anchor
// check's `audit.anchor_check_done` (chains failed, left unchecked, still
// waiting their turn), the jobs' `jobs.pulse`, and every warning or error the
// API logged in the step's window. Read from the log as load.ts reads it: one
// JSON line per event, the logger's `time` on each. Under load the checks must
// run, never fail and never fall behind, the jobs must say they are alive
// every minute, and nothing may go wrong: no error line at all, and no warning
// but the busy lines a step meant to overload causes by design.

/** When a step ran, as its k6 summary dates it. */
export interface StepWindow {
  readonly from: string;
  readonly to: string;
}

/** A count over the step's anchor check runs: the most any run said, and what the last said. */
interface Peak {
  readonly most: number;
  readonly last: number;
}

export interface BackgroundHealth {
  readonly minutes: number;
  /** Whether a line LATE_LINES_MINUTES past the window's end has arrived: before then the window's may be on their way. */
  readonly complete: boolean;
  /** Anchor check runs that finished in the window. */
  readonly anchorChecks: number;
  /** Chain checks that failed, over every run. */
  readonly failed: number;
  /** Chains a run couldn't reach in its time; none without a run. */
  readonly unchecked: Peak | null;
  /** Chains still waiting their turn when a run ended. */
  readonly left: Peak | null;
  /** The jobs said to have stalled, each once (job.stalled, an error line, counted there too). */
  readonly stalled: readonly string[];
  /** Error and fatal lines, by event. */
  readonly errors: Readonly<Record<string, number>>;
  /** Warning lines, by event, but the offenders'. */
  readonly warnings: Readonly<Record<string, number>>;
  /** Warning lines of the organisations the step means to be in trouble (the neighbours' busy and stuck ones), by event. */
  readonly offenderWarnings: Readonly<Record<string, number>>;
  readonly pulses: number;
  /** The longest time without a pulse, the window's two ends counted as edges. */
  readonly longestPulseGapMinutes: number;
}

/**
 * Container logs reach the workspace minutes late, and the runner reads them
 * once they have settled: a line this long past the window's end is the sign
 * that the window's own lines are all there.
 */
const LATE_LINES_MINUTES = 2;

/** Pulses come every minute (job-watch.ts's PULSE_EVERY_MS): three missed is the jobs stopped or none leading. */
const PULSE_GAP_MINUTES = 3;

/**
 * The most chains a run may leave unchecked, or waiting their turn, under load
 * (Claude's stated number): a few behind is a run cut at its time limit, more
 * is the check falling behind. Either way the last run must be back to none.
 */
const BEHIND_CEILING = 10;

/**
 * The lines a step meant to overload causes by design, and the only warnings it
 * may log: a decision turned away busy (503) or refused for rate (429), each
 * named in the report with its count.
 */
const BUSY_LINES: ReadonlySet<string> = new Set([
  'spend_request.agent_busy',
  'spend_request.supplier_busy',
  'spend_request.organisation_busy',
  'spend_request.platform_full',
  'db.organisation_busy',
  'db.pool_wait_ran_out',
  'http.request_rate_limited',
]);

const MINUTE_MS = 60_000;

type Line = Readonly<Record<string, unknown>>;

const parsed = (raw: string): Line | undefined => {
  try {
    const value: unknown = JSON.parse(raw);
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Line) : undefined;
  } catch {
    return undefined;
  }
};

const numberOf = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : 0);

const peakOf = (values: readonly number[]): Peak | null => {
  const last = values.at(-1);
  return last === undefined ? null : { most: Math.max(...values), last };
};

const eventOf = ({ event }: Line): string => (typeof event === 'string' ? event : '(no event)');

const countBy = (lines: readonly Line[]): Record<string, number> => {
  const counts: Record<string, number> = {};
  for (const line of lines) counts[eventOf(line)] = (counts[eventOf(line)] ?? 0) + 1;
  return counts;
};

/**
 * The health of the background work over `window`, from the log's text: lines
 * outside it, or not the logger's JSON, are skipped. `offenders` are the
 * organisations the step means to be in trouble, whose busy lines are theirs.
 */
export function backgroundHealth(
  text: string,
  window: StepWindow,
  offenders: ReadonlySet<string> = new Set(),
): BackgroundHealth {
  const from = Date.parse(window.from);
  const to = Date.parse(window.to);
  const timed = text
    .split(/\r?\n/)
    .map(parsed)
    .flatMap((line) => {
      const at = typeof line?.time === 'string' ? Date.parse(line.time) : Number.NaN;
      return line === undefined || Number.isNaN(at) ? [] : [{ line, at }];
    })
    .sort((a, b) => a.at - b.at);
  const lines = timed.filter(({ at }) => at >= from && at <= to);
  const of = (event: string) => lines.filter(({ line }) => line.event === event);
  const anchors = of('audit.anchor_check_done').map(({ line }) => line);
  const pulses = of('jobs.pulse').map(({ at }) => at);
  const edges = [from, ...pulses, to];
  const gaps = edges.slice(1).map((at, index) => at - (edges[index] ?? at));
  const atLevel = (...levels: string[]) =>
    lines.map(({ line }) => line).filter(({ level }) => typeof level === 'string' && levels.includes(level));
  const warned = atLevel('warn');
  const isOffender = ({ orgId }: Line) => typeof orgId === 'string' && offenders.has(orgId);
  return {
    minutes: (to - from) / MINUTE_MS,
    complete: timed.some(({ at }) => at >= to + LATE_LINES_MINUTES * MINUTE_MS),
    anchorChecks: anchors.length,
    failed: anchors.reduce((sum, { failed }) => sum + numberOf(failed), 0),
    unchecked: peakOf(anchors.map(({ unchecked }) => numberOf(unchecked))),
    left: peakOf(anchors.map(({ left }) => numberOf(left))),
    stalled: [
      ...new Set(of('job.stalled').map(({ line: { job } }) => (typeof job === 'string' ? job : '(no job named)'))),
    ],
    errors: countBy(atLevel('error', 'fatal')),
    warnings: countBy(warned.filter((line) => !isOffender(line))),
    offenderWarnings: countBy(warned.filter(isOffender)),
    pulses: pulses.length,
    longestPulseGapMinutes: Math.max(...gaps) / MINUTE_MS,
  };
}

/**
 * The warnings a step may log, by event, with their counts: the offenders'
 * busy lines always, and everyone's when the step means to overload the platform.
 */
export function allowedBusyLines(health: BackgroundHealth, overloading: boolean): Record<string, number> {
  const allowed: Record<string, number> = {};
  const sources = overloading ? [health.offenderWarnings, health.warnings] : [health.offenderWarnings];
  for (const counts of sources) {
    for (const [event, count] of Object.entries(counts)) {
      if (BUSY_LINES.has(event)) allowed[event] = (allowed[event] ?? 0) + count;
    }
  }
  return allowed;
}

/** A warning not allowed in the step: any but a busy line, or a busy line where nothing is meant to be busy. */
function warningsNotAllowed(health: BackgroundHealth, overloading: boolean): [string, number][] {
  const busyAllowed = (event: string) => BUSY_LINES.has(event);
  return [
    ...Object.entries(health.warnings).filter(([event]) => !(overloading && busyAllowed(event))),
    ...Object.entries(health.offenderWarnings).filter(([event]) => !busyAllowed(event)),
  ];
}

const behind = (peak: Peak | null, what: string): string[] => {
  if (peak === null) return [];
  return [
    ...(peak.most > BEHIND_CEILING
      ? [
          `A run left ${String(peak.most)} chains ${what}, above the ceiling of ${String(BEHIND_CEILING)}: the anchor check fell behind.`,
        ]
      : []),
    ...(peak.last > 0
      ? [`The step's last anchor check run still left ${String(peak.last)} chains ${what}: it never caught up.`]
      : []),
  ];
};

/**
 * What the background work's health says went wrong in the step, in plain
 * words: none when it kept up. Logs not yet complete are never judged: that
 * is said alone, and is not a pass.
 */
export function backgroundFailures(health: BackgroundHealth, overloading: boolean): string[] {
  if (!health.complete) {
    return [
      `The step's logs are not complete yet: no line ${String(LATE_LINES_MINUTES)} minutes past its end has arrived, so its background work is not judged. Read them again later.`,
    ];
  }
  const gap = health.longestPulseGapMinutes;
  return [
    ...(health.anchorChecks === 0
      ? ['The background check never ran: no audit.anchor_check_done line in the step.']
      : []),
    ...(health.failed > 0
      ? [
          `The anchor check failed ${String(health.failed)} chain check(s) in the step: read its audit.anchor_check_done lines.`,
        ]
      : []),
    ...behind(health.unchecked, 'unchecked'),
    ...behind(health.left, 'waiting their turn'),
    ...Object.entries(health.errors).map(
      ([event, count]) => `The API logged ${event} ${String(count)} time(s) at error level in the step.`,
    ),
    ...warningsNotAllowed(health, overloading).map(
      ([event, count]) =>
        `The API logged ${event} ${String(count)} warning(s) in the step: only the busy lines of a step meant to overload are allowed.`,
    ),
    ...(gap > PULSE_GAP_MINUTES
      ? [
          `No jobs.pulse for ${gap.toFixed(1)} minutes in the step: the background jobs stopped, or none held the lease.`,
        ]
      : []),
  ];
}
