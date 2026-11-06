// The background work's health over one Stage G step (4D2e design item 9),
// from lines the API and the jobs already write (no new line): the anchor
// check's `audit.anchor_check_done` (chains failed, left unchecked, still
// waiting their turn), `job.stalled`, and the jobs' `jobs.pulse`. Read from the
// log as load.ts reads it: one JSON line per event, the logger's `time` on each.
// Under load the checks must never fail and never fall behind, no job may
// stall, and the jobs must say they are alive as often as the alert expects.

/** When a step ran, as its k6 summary dates it. */
export interface StepWindow {
  readonly from: string;
  readonly to: string;
}

/** A count at the step's first reading and its last. */
interface Trend {
  readonly first: number;
  readonly last: number;
}

export interface BackgroundHealth {
  readonly minutes: number;
  /** Anchor check runs that finished in the window. */
  readonly anchorChecks: number;
  /** Chain checks that failed, over every run. */
  readonly failed: number;
  /** Chains a run couldn't reach in its time, at the first run and the last; none without a run. */
  readonly unchecked: Trend | null;
  /** Chains still waiting their turn when a run ended. */
  readonly left: Trend | null;
  /** The jobs said to have stalled, each once. */
  readonly stalled: readonly string[];
  readonly pulses: number;
  /** The longest time without a pulse, the window's two ends counted as edges. */
  readonly longestPulseGapMinutes: number;
}

/** The jobs-stopped alert's window (environment.bicep): no pulse this long is down. */
const PULSE_GAP_MINUTES = 15;

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

const trendOf = (values: readonly number[]): Trend | null => {
  const [first] = values;
  return first === undefined ? null : { first, last: values.at(-1) ?? first };
};

/** The health of the background work over `window`, from the log's text: lines outside it, or not the logger's JSON, are skipped. */
export function backgroundHealth(text: string, window: StepWindow): BackgroundHealth {
  const from = Date.parse(window.from);
  const to = Date.parse(window.to);
  const lines = text
    .split(/\r?\n/)
    .map(parsed)
    .flatMap((line) => {
      const at = typeof line?.time === 'string' ? Date.parse(line.time) : Number.NaN;
      return line !== undefined && at >= from && at <= to ? [{ line, at }] : [];
    })
    .sort((a, b) => a.at - b.at);
  const of = (event: string) => lines.filter(({ line }) => line.event === event);
  const anchors = of('audit.anchor_check_done').map(({ line }) => line);
  const pulses = of('jobs.pulse').map(({ at }) => at);
  const edges = [from, ...pulses, to];
  const gaps = edges.slice(1).map((at, index) => at - (edges[index] ?? at));
  return {
    minutes: (to - from) / MINUTE_MS,
    anchorChecks: anchors.length,
    failed: anchors.reduce((sum, { failed }) => sum + numberOf(failed), 0),
    unchecked: trendOf(anchors.map(({ unchecked }) => numberOf(unchecked))),
    left: trendOf(anchors.map(({ left }) => numberOf(left))),
    stalled: [
      ...new Set(of('job.stalled').map(({ line: { job } }) => (typeof job === 'string' ? job : '(no job named)'))),
    ],
    pulses: pulses.length,
    longestPulseGapMinutes: Math.max(...gaps) / MINUTE_MS,
  };
}

const grew = (trend: Trend | null): trend is Trend => trend !== null && trend.last > trend.first;

/** What the background work's health says went wrong in the step, in plain words: none when it kept up. */
export function backgroundFailures(health: BackgroundHealth): string[] {
  const { failed, unchecked, left, stalled, longestPulseGapMinutes: gap } = health;
  return [
    ...(failed > 0
      ? [
          `The anchor check failed ${String(failed)} chain check(s) in the step: read its audit.anchor_check_done lines.`,
        ]
      : []),
    ...(grew(unchecked)
      ? [
          `The anchor check left ${String(unchecked.last)} chains unchecked at the step's end, ${String(unchecked.first)} at its start: it fell behind.`,
        ]
      : []),
    ...(grew(left)
      ? [
          `${String(left.last)} chains were waiting their turn at the step's end, ${String(left.first)} at its start: the anchor check fell behind.`,
        ]
      : []),
    ...(stalled.length > 0 ? [`A background job stalled in the step: ${stalled.join(', ')}.`] : []),
    ...(gap > PULSE_GAP_MINUTES
      ? [
          `No jobs.pulse for ${gap.toFixed(1)} minutes in the step: the background jobs stopped, or none held the lease.`,
        ]
      : []),
    // A shorter step may end between two runs: only a window as long as the pulse alert's must hold one.
    ...(health.anchorChecks === 0 && health.minutes >= PULSE_GAP_MINUTES
      ? [
          `No anchor check finished in the step's ${health.minutes.toFixed(1)} minutes, so nothing says the checks kept up.`,
        ]
      : []),
  ];
}
