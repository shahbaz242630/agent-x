// The background work's health over one Stage G step (4D2e design item 9),
// from lines the API and the jobs already write (no new line): the anchor
// check's `audit.anchor_check_done` (chains failed, left unchecked, still
// waiting their turn), the jobs' `jobs.pulse`, and every warning or error the
// API logged in the step's window. Read from the log as load.ts reads it: one
// JSON line per event, the logger's `time` on each, with the replica that
// wrote it (the workspace's RevisionName and ContainerGroupName). Under load the checks must
// run, never fail and never fall behind, the jobs must say they are alive
// every minute, and nothing may go wrong: no error line at all, and no warning
// but the busy lines a step meant to overload causes by design.

import { percentilesOf } from './logs.ts';

/** When a step ran, as its k6 summary dates it. */
export interface StepWindow {
  readonly from: string;
  readonly to: string;
}

/** One line of the log as the workspace holds it: the logger's JSON, and which replica wrote it. */
export interface LogLine {
  /** `<RevisionName>/<ContainerGroupName>`: one API replica, or one of the jobs app's. */
  readonly replica: string;
  readonly log: string;
}

/** A count over the step's anchor check runs: the most any run said, and what the last said. */
interface Peak {
  readonly most: number;
  readonly last: number;
}

export interface BackgroundHealth {
  readonly minutes: number;
  /**
   * What hasn't arrived yet that says the window's lines are all in: a
   * jobs.pulse after its end, and a line after its end from each API replica.
   * Empty when the window can be judged.
   */
  readonly missing: readonly string[];
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

/** Pulses come every minute (job-watch.ts's PULSE_EVERY_MS): three missed is the jobs stopped or none leading. */
const PULSE_GAP_MINUTES = 3;

/**
 * The most chains a run may leave unchecked, or waiting their turn, under load
 * (Claude's stated number): a few behind is a run cut at its time limit, more
 * is the check falling behind. Either way the last run must be back to none.
 */
const BEHIND_CEILING = 10;

/**
 * The anchor check's line comes at most every 10 minutes at the default
 * interval (anchor-check.ts: 5 between runs, 4 of run, 1 for the last write):
 * a shorter step may see none with nothing wrong (S176's 2-minute smoke).
 */
const ANCHOR_LINE_GAP_MINUTES = 10;

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

/** The log's lines that are the logger's JSON with a time, oldest first. */
const timedLines = (log: readonly LogLine[]) =>
  log
    .flatMap(({ replica, log: raw }) => {
      const line = parsed(raw);
      const at = typeof line?.time === 'string' ? Date.parse(line.time) : Number.NaN;
      return line === undefined || Number.isNaN(at) ? [] : [{ line, at, replica }];
    })
    .sort((a, b) => a.at - b.at);

/**
 * What must still arrive before a window ending at `to` can be judged: logs
 * reach the workspace minutes late, and each replica's on its own.
 */
function missingAfter(timed: ReturnType<typeof timedLines>, to: number, apiReplicas: readonly string[]): string[] {
  const after = timed.filter(({ at }) => at > to);
  const said = new Set(after.map(({ replica }) => replica));
  return [
    ...(after.some(({ line }) => line.event === 'jobs.pulse') ? [] : ['a jobs.pulse line after the step ended']),
    ...(apiReplicas.length === 0 ? ['the names of the API replicas that ran the step, to wait for each'] : []),
    ...apiReplicas
      .filter((replica) => !said.has(replica))
      .map((replica) => `a line from API replica ${replica} after the step ended`),
  ];
}

/**
 * The health of the background work over `window`, from the log's lines:
 * lines outside it, or not the logger's JSON, are skipped. `apiReplicas` are
 * the API's replicas while the step ran, each of whose lines must have come in;
 * `offenders` the organisations the step means to be in trouble.
 */
export function backgroundHealth(
  log: readonly LogLine[],
  window: StepWindow,
  {
    apiReplicas,
    offenders = new Set(),
  }: { readonly apiReplicas: readonly string[]; readonly offenders?: ReadonlySet<string> | undefined },
): BackgroundHealth {
  const from = Date.parse(window.from);
  const to = Date.parse(window.to);
  const timed = timedLines(log);
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
    missing: missingAfter(timed, to, apiReplicas),
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
 * The pool every organisation shares: run out, one organisation's trouble has
 * reached the others (PL-63), so never an offender's own busy line.
 */
const SHARED_POOL_RAN_OUT = 'db.pool_wait_ran_out';

const offenderMayLog = (event: string): boolean => BUSY_LINES.has(event) && event !== SHARED_POOL_RAN_OUT;

/**
 * The warnings a step may log, by event, with their counts: the offenders'
 * busy lines always, and everyone's when the step means to overload the platform.
 */
export function allowedBusyLines(health: BackgroundHealth, overloading: boolean): Record<string, number> {
  const allowed: Record<string, number> = {};
  const sources = overloading ? [health.offenderWarnings, health.warnings] : [health.offenderWarnings];
  for (const counts of sources) {
    for (const [event, count] of Object.entries(counts)) {
      // Only an overloaded platform may run its shared pool out: beside the neighbours that is their trouble spreading.
      const mayLog = overloading ? BUSY_LINES.has(event) : offenderMayLog(event);
      if (mayLog) allowed[event] = (allowed[event] ?? 0) + count;
    }
  }
  return allowed;
}

/** A warning not allowed in the step: any but a busy line, or a busy line where nothing is meant to be busy. */
function warningsNotAllowed(health: BackgroundHealth, overloading: boolean): [string, number][] {
  return [
    ...Object.entries(health.warnings).filter(([event]) => !(overloading && BUSY_LINES.has(event))),
    ...Object.entries(health.offenderWarnings).filter(
      ([event]) => !(offenderMayLog(event) || (overloading && BUSY_LINES.has(event))),
    ),
  ];
}

const warningSaid = ([event, count]: [string, number]): string =>
  event === SHARED_POOL_RAN_OUT
    ? `The API logged ${event} ${String(count)} warning(s) in the step: the shared pool ran out, so one organisation's trouble reached the others.`
    : `The API logged ${event} ${String(count)} warning(s) in the step: only the busy lines of a step meant to overload are allowed.`;

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
 * words: none when it kept up. Only for a window whose lines are all in
 * (`missing` empty): the report never judges one before.
 */
export function backgroundFailures(health: BackgroundHealth, overloading: boolean): string[] {
  const gap = health.longestPulseGapMinutes;
  return [
    ...(health.anchorChecks === 0 && health.minutes >= ANCHOR_LINE_GAP_MINUTES
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
    ...warningsNotAllowed(health, overloading).map(warningSaid),
    ...(gap > PULSE_GAP_MINUTES
      ? [
          `No jobs.pulse for ${gap.toFixed(1)} minutes in the step: the background jobs stopped, or none held the lease.`,
        ]
      : []),
  ];
}

/**
 * The decisions' p95 over `window`, from the API's own spend_request.decided
 * lines, as logs.ts times them (nearest rank); null when none was made in it.
 */
export function decisionP95In(log: readonly LogLine[], window: StepWindow): number | null {
  const from = Date.parse(window.from);
  const to = Date.parse(window.to);
  const times = timedLines(log).flatMap(({ line, at }) =>
    line.event === 'spend_request.decided' && typeof line.durationMs === 'number' && at >= from && at <= to
      ? [line.durationMs]
      : [],
  );
  return times.length === 0 ? null : percentilesOf(times).p95;
}
