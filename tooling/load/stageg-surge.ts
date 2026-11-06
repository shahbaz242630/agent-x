// A surge's numbers, window by window (4D2e design item 9, PL-62): the spike's
// and the overload's steps hold a base load, surge, and come back to it. What
// they must show: a base hold that meets the target (requests, decisions and
// failed answers), refusals for rate (429) during the surge and its recovery
// only, and latency back within the step's window, counted from the last bad
// window. Pure functions of the step's stages and k6's windows (plain.k6.js's
// windowNumbers), for the report (stageg-report.ts) and the runner.
import type { StepWindow } from './stageg-background.ts';
import { type K6Stages, MAX_ERROR_SHARE, REQUEST_P95_MS, stagesSeconds, type WindowNumbers } from './stageg.ts';
import { POLICY_P95_MS } from './plan.ts';

/** Back to the base load's latency: a window's p95 within this much of the base hold's median. */
const RECOVERED_MARGIN = 0.15;

const secondsOf = (duration: string): number => Number.parseInt(duration, 10);
const ms = (value: number): string => value.toFixed(1);
const share = (value: number): string => `${(value * 100).toFixed(2)}%`;

/** Where a surge's stages lie, in seconds from the step's start: they end rise, peak, fall, recovery (stageg.ts's k6Stages). */
function surgeTimes(stages: K6Stages) {
  const opening = stages.stages.slice(0, -4).map(({ duration }) => secondsOf(duration));
  return {
    baseFrom: opening.length > 1 ? (opening[0] ?? 0) : 0,
    baseTo: opening.reduce((sum, seconds) => sum + seconds, 0),
    surgeEnd: stagesSeconds(stages) - secondsOf(stages.stages.at(-1)?.duration ?? '0s'),
    end: stagesSeconds(stages),
  };
}

const span = (first: number, last: number): number[] =>
  Array.from({ length: Math.max(0, last - first + 1) }, (_, index) => first + index);

/** The windows of each part of a surge: the base hold's whole ones, the surge's, and every one from its end. */
function surgeWindows(stages: K6Stages, windowSeconds: number) {
  const { baseFrom, baseTo, surgeEnd, end } = surgeTimes(stages);
  const afterFrom = Math.floor(surgeEnd / windowSeconds);
  return {
    base: span(Math.ceil(baseFrom / windowSeconds), Math.floor(baseTo / windowSeconds) - 1),
    surge: span(Math.floor(baseTo / windowSeconds), afterFrom - 1),
    after: span(afterFrom, Math.ceil(end / windowSeconds) - 1),
    surgeEnd,
  };
}

/** When the base hold ran, for the decisions the API logged in it (stageg-background.ts's decisionP95In). */
export function baseHoldWindow(stages: K6Stages, startedAt: string): StepWindow {
  const { baseFrom, baseTo } = surgeTimes(stages);
  const at = (seconds: number) => new Date(Date.parse(startedAt) + seconds * 1000).toISOString();
  return { from: at(baseFrom), to: at(baseTo) };
}

/** The middle value, the lower of the two middles for an even count. */
const median = (values: readonly number[]): number =>
  values.toSorted((a, b) => a - b)[Math.floor((values.length - 1) / 2)] ?? 0;

/** Failed answers but the refusals for rate, which are judged apart. */
const failedNotRefused = ({ failedShare, refusedShare }: WindowNumbers): number =>
  Math.max(0, failedShare - refusedShare);

/**
 * The first window after which every window is back: its p95 within
 * RECOVERED_MARGIN of the base hold's median (capped at the request target, so
 * a base already slow can't lower the bar) and its failed answers, refusals for
 * rate apart, below `maxFailedShare`. Every window from the surge's end must be
 * there: a missing one is not back. Null if the last is not back, or no window
 * of the base hold has numbers.
 */
function backWindow(
  stages: K6Stages,
  windowSeconds: number,
  windows: readonly WindowNumbers[],
  maxFailedShare: number,
): number | null {
  const { base, after } = surgeWindows(stages, windowSeconds);
  const byWindow = new Map(windows.map((each) => [each.window, each]));
  const baseP95s = base.flatMap((window) => byWindow.get(window)?.p95Ms ?? []);
  if (baseP95s.length === 0) return null;
  const limit = Math.min(median(baseP95s), REQUEST_P95_MS) * (1 + RECOVERED_MARGIN);
  const isBack = (window: number) => {
    const numbers = byWindow.get(window);
    return numbers !== undefined && numbers.p95Ms <= limit && failedNotRefused(numbers) < maxFailedShare;
  };
  return after[after.findLastIndex((window) => !isBack(window)) + 1] ?? null;
}

/** Seconds from the surge's end to the start of the window it was back from for good (backWindow), or null. */
export function recoverySeconds(
  stages: K6Stages,
  windowSeconds: number,
  windows: readonly WindowNumbers[],
  maxFailedShare: number,
): number | null {
  const back = backWindow(stages, windowSeconds, windows, maxFailedShare);
  return back === null ? null : Math.max(0, back * windowSeconds - surgeWindows(stages, windowSeconds).surgeEnd);
}

/**
 * The base hold before a surge judged by the target's rules, each window and
 * its decisions: what the surge must come back to must itself be right.
 * `decisionP95Ms` is the API's over baseHoldWindow; null or undefined, not measured.
 */
export function baseHoldFailures(
  stages: K6Stages,
  windowSeconds: number,
  windows: readonly WindowNumbers[],
  decisionP95Ms: number | null | undefined,
): string[] {
  const byWindow = new Map(windows.map((each) => [each.window, each]));
  const perWindow = surgeWindows(stages, windowSeconds).base.flatMap((window) => {
    const numbers = byWindow.get(window);
    if (numbers === undefined) {
      return [
        `Window ${String(window)} of the base load before the surge has no numbers: there is nothing sure to come back to.`,
      ];
    }
    const failed = failedNotRefused(numbers);
    return numbers.p95Ms < REQUEST_P95_MS && failed < MAX_ERROR_SHARE
      ? []
      : [
          `The base load before the surge already missed the target in window ${String(window)}: p95 ${ms(numbers.p95Ms)} ms (under ${String(REQUEST_P95_MS)}), ${share(failed)} failed (under ${String(MAX_ERROR_SHARE * 100)}%).`,
        ];
  });
  if (decisionP95Ms === null || decisionP95Ms === undefined) {
    return [
      ...perWindow,
      "The base load's decisions before the surge were not measured: no decision line in its time.",
    ];
  }
  return decisionP95Ms > POLICY_P95_MS
    ? [
        ...perWindow,
        `The base load's decisions before the surge had a p95 of ${ms(decisionP95Ms)} ms, over the ${ms(POLICY_P95_MS)} ms limit.`,
      ]
    : perWindow;
}

/** The share of a phase's answers refused for rate: null when it had none; undefined when the phase never came. */
type PhaseShare = number | null | undefined;

export interface RefusedByPhase {
  readonly base: PhaseShare;
  readonly surge: PhaseShare;
  readonly recovery: PhaseShare;
  /** Undefined when latency never came back. */
  readonly afterRecovering: PhaseShare;
}

/** The refusals for rate in each phase of a surge, each window weighed by its answers. */
export function refusedByPhase(
  stages: K6Stages,
  windowSeconds: number,
  windows: readonly WindowNumbers[],
  maxFailedShare: number,
): RefusedByPhase {
  const { base, surge, after } = surgeWindows(stages, windowSeconds);
  const byWindow = new Map(windows.map((each) => [each.window, each]));
  const of = (phase: readonly number[]): PhaseShare => {
    const numbers = phase.flatMap((window) => byWindow.get(window) ?? []);
    const answers = numbers.reduce((sum, { requests }) => sum + requests, 0);
    return answers === 0 ? null : numbers.reduce((sum, each) => sum + each.refusedShare * each.requests, 0) / answers;
  };
  const back = backWindow(stages, windowSeconds, windows, maxFailedShare);
  return {
    base: of(base),
    surge: of(surge),
    recovery: of(after.filter((window) => back === null || window < back)),
    afterRecovering: back === null ? undefined : of(after.filter((window) => window >= back)),
  };
}

const phaseCell = (value: PhaseShare): string => {
  if (value === undefined) return 'never recovered';
  return value === null ? 'no answers' : share(value);
};

/** The refusals for rate by phase, as the report prints them. */
export const refusedLine = (phases: RefusedByPhase): string =>
  `Refused for rate (429), by phase: base ${phaseCell(phases.base)}, surge ${phaseCell(phases.surge)}, recovery ${phaseCell(phases.recovery)}, after recovering ${phaseCell(phases.afterRecovering)}.`;

/** A surge means its refusals for rate to come with it: any in the base hold or after it recovered fails the step. */
export function refusedFailures(phases: RefusedByPhase): string[] {
  const outside = (value: PhaseShare, when: string): string[] =>
    value !== null && value !== undefined && value > 0
      ? [`Turned away outside the surge: ${share(value)} of the answers ${when} were refused for rate (429).`]
      : [];
  return [
    ...outside(phases.base, 'in the base load before it'),
    ...outside(phases.afterRecovering, 'after it recovered'),
  ];
}
