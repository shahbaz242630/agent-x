// The report's Stage G section (4D2e design item 9, PL-62, PL-63): a test's
// steps side by side, the first as the baseline, each judged by its profile's
// rules (stageg.ts's judgeStep), its database checks (stageg-checks.ts), its
// background work (stageg-background.ts) and its API replicas' restarts; then
// what the test is for: the breaking rate of a climb, the recovery after a
// surge, the soak's trend. A pure function of what the runner collected, so
// the same numbers always give the same text.
import { type BackgroundHealth, backgroundFailures } from './stageg-background.ts';
import {
  breakingRate,
  judgeStep,
  type K6Stages,
  type Profile,
  rateAt,
  type StepMeasured,
  type StepRun,
  stagesSeconds,
  type WindowNumbers,
} from './stageg.ts';
import { CROWD_AGENTS, STAGE_G_HEAVY_EVERY, STAGE_G_HUGE_CHAIN_EVENTS, STAGE_G_LIGHT_EVERY } from './plan.ts';

/** One kind of traffic's numbers in a step, as plain.k6.js's kindNumbers gives them. */
interface KindNumbers {
  readonly requests: number;
  readonly serverErrors: number;
  readonly rateLimited: number;
  readonly p95Ms: number;
}

/** A step's numbers as stage-g.k6.js prints them (plain.k6.js's stageGSummary, the `load.stageg_summary` line). */
export interface StageGSummary {
  readonly test: string;
  readonly step: string;
  readonly orgs: number;
  readonly requests: number;
  readonly created: number;
  readonly serverErrors: number;
  readonly rateLimited: number;
  readonly checksFailed: number;
  readonly dropped: number;
  readonly asksMs: { readonly p50: number; readonly p95: number; readonly p99: number; readonly max: number } | null;
  readonly kinds: Readonly<Record<string, KindNumbers>>;
  readonly aborted: boolean;
  readonly windows: readonly WindowNumbers[] | null;
  readonly startedAt: string;
  readonly endedAt: string;
}

/** What the runner collected for one step. */
export interface StageGStepResult {
  readonly run: StepRun;
  readonly summary: StageGSummary;
  /** The decisions' p95 over the step's window, from the API's own `spend_request.decided` lines. */
  readonly decisionP95Ms: number;
  readonly background: BackgroundHealth;
  /** The API replicas' restarts summed, before the step and after; null when they couldn't be read. */
  readonly restarts: { readonly before: number; readonly after: number } | null;
  /** What stageg-checks.ts found wrong after the step: none on a clean one. */
  readonly databaseFailures: readonly string[];
  /** For the soak: the API's memory and the database's connections at the segment's end, where they were read. */
  readonly resources?: { readonly memoryMb: number | null; readonly connections: number | null };
}

export interface StageGReportInput {
  readonly profile: Profile;
  /** The steps that ran, in order: a climb stopped at its first failed step has fewer than its profile. */
  readonly steps: readonly StageGStepResult[];
  /** The p95 a step is compared with, when it isn't the first step's (the neighbours' is the target's). */
  readonly baselineP95Ms?: number;
}

/** The kind a step is judged by, as plain.k6.js's judgedKind names it. */
const JUDGED: Readonly<Record<Profile['mix'], string>> = { steady: 'steady', neighbours: 'calm' };

/** Back to the base load's latency: a window's p95 within this much of the base hold's slowest window's. */
const RECOVERED_MARGIN = 0.15;

/** Back means failed answers below the target's 1% too (stageg.ts's MAX_ERROR_SHARE), where a step has no rule of its own. */
const RECOVERED_FAILED_SHARE = 0.01;

const NO_KIND: KindNumbers = { requests: 0, serverErrors: 0, rateLimited: 0, p95Ms: 0 };

const ms = (value: number): string => value.toFixed(1);
const percent = (share: number): string => `${share >= 0 ? '+' : ''}${(share * 100).toFixed(1)}%`;

const secondsOf = (duration: string): number => Number.parseInt(duration, 10);

/**
 * Seconds from a surge's end to the start of the first window after which
 * every window is back: its p95 within RECOVERED_MARGIN of the base hold's
 * slowest window and its failed share below `maxFailedShare`. Counted from the
 * last bad window, so a relapse after a good one counts. Null if the last
 * window is still bad, or no window was in the base hold to compare with.
 * A surge's stages end rise, peak, fall, recovery (stageg.ts's k6Stages).
 */
export function recoverySeconds(
  stages: K6Stages,
  windowSeconds: number,
  windows: readonly WindowNumbers[],
  maxFailedShare: number,
): number | null {
  const opening = stages.stages.slice(0, -4).map(({ duration }) => secondsOf(duration));
  const baseTo = opening.reduce((sum, seconds) => sum + seconds, 0);
  const baseFrom = opening.length > 1 ? (opening[0] ?? 0) : 0;
  const surgeEnd = stagesSeconds(stages) - secondsOf(stages.stages.at(-1)?.duration ?? '0s');
  const startOf = ({ window }: WindowNumbers) => window * windowSeconds;
  const base = windows.filter((each) => startOf(each) >= baseFrom && startOf(each) + windowSeconds <= baseTo);
  if (base.length === 0) return null;
  const limit = Math.max(...base.map(({ p95Ms }) => p95Ms)) * (1 + RECOVERED_MARGIN);
  const after = windows
    .filter((each) => startOf(each) + windowSeconds > surgeEnd)
    .toSorted((a, b) => a.window - b.window);
  const lastBad = after.findLastIndex(({ p95Ms, failedShare }) => p95Ms > limit || failedShare >= maxFailedShare);
  const back = after[lastBad + 1];
  return back === undefined ? null : Math.max(0, startOf(back) - surgeEnd);
}

const isSurge = (run: StepRun): boolean => run.test === 'spike' || run.test === 'overload';

/**
 * A step's recovery seconds (null: never back), or undefined when k6 gave no
 * windows to read it from. Failed answers are judged by the step's own rule,
 * or the target's where it has none (the overload's, refused past its peak by design).
 */
const measuredRecovery = ({ run, summary }: StageGStepResult, rules: Profile['rules']): number | null | undefined =>
  run.windowSeconds === null || summary.windows === null
    ? undefined
    : recoverySeconds(run, run.windowSeconds, summary.windows, rules.maxErrorShare ?? RECOVERED_FAILED_SHARE);

/** Every reason a step failed, in plain words: its rules, its checks, its background work and its replicas. */
function stepFailures(input: StageGReportInput, result: StageGStepResult, baselineP95Ms: number | undefined): string[] {
  const { run, summary, decisionP95Ms, restarts } = result;
  const judged = summary.kinds[JUDGED[input.profile.mix]] ?? NO_KIND;
  const recovery = isSurge(run) ? measuredRecovery(result, input.profile.rules) : null;
  // A surge k6 gave no windows for can't be judged on its recovery: said apart, never as "never came back".
  const unmeasured = recovery === undefined;
  const measured: StepMeasured = {
    decisionP95Ms,
    requests: judged.requests,
    serverErrors: judged.serverErrors,
    rateLimited: judged.rateLimited,
    dropped: summary.dropped,
    calmP95Ms: summary.asksMs?.p95 ?? judged.p95Ms,
    recoverySeconds: recovery ?? null,
  };
  const rules = unmeasured ? { ...input.profile.rules, recoveryWithinSeconds: null } : input.profile.rules;
  return [
    ...judgeStep(rules, measured, baselineP95Ms).failures,
    ...(unmeasured ? ['The recovery after the surge was not measured: k6 gave no window numbers for this step.'] : []),
    ...result.databaseFailures,
    ...backgroundFailures(result.background),
    ...(restarts !== null && restarts.after > restarts.before
      ? [
          `The API's replicas restarted ${String(restarts.after - restarts.before)} time(s) during the step: a crash, or a replica killed for memory.`,
        ]
      : []),
  ];
}

const timesCell = (summary: StageGSummary): string => {
  const { asksMs } = summary;
  return asksMs === null ? 'none | none | none' : `${ms(asksMs.p50)} | ${ms(asksMs.p95)} | ${ms(asksMs.p99)}`;
};

const refusedCell = ({ kinds }: StageGSummary): string =>
  Object.entries(kinds)
    .map(([kind, { rateLimited }]) => `${kind} ${String(rateLimited)}`)
    .join(', ') || 'no traffic';

function stepRow(result: StageGStepResult, baselineP95Ms: number | undefined, index: number, failed: boolean): string {
  const { summary } = result;
  const p95 = summary.asksMs?.p95;
  let versus = 'not compared';
  if (p95 !== undefined && index === 0 && baselineP95Ms === p95) versus = 'baseline';
  else if (p95 !== undefined && baselineP95Ms !== undefined && baselineP95Ms > 0)
    versus = percent(p95 / baselineP95Ms - 1);
  return (
    `| ${result.run.label} | ${String(summary.orgs)} | ${String(summary.requests)} | ${String(summary.created)} | ${timesCell(summary)} | ` +
    `${String(summary.serverErrors)} | ${refusedCell(summary)} | ${String(summary.dropped)} | ${ms(result.decisionP95Ms)} | ${versus} | ${failed ? '**Failed**' : 'Passed'} |`
  );
}

const trendCell = (trend: BackgroundHealth['unchecked']): string =>
  trend === null ? 'no run' : `${String(trend.first)} → ${String(trend.last)}`;

function backgroundRow({ run, background: b, restarts }: StageGStepResult): string {
  const restarted = restarts === null ? 'not read' : `${String(restarts.before)} → ${String(restarts.after)}`;
  return (
    `| ${run.label} | ${b.minutes.toFixed(1)} | ${String(b.anchorChecks)} | ${String(b.failed)} | ${trendCell(b.unchecked)} | ${trendCell(b.left)} | ` +
    `${b.stalled.length === 0 ? 'none' : b.stalled.join(', ')} | ${String(b.pulses)} | ${b.longestPulseGapMinutes.toFixed(1)} | ${restarted} |`
  );
}

/** Where a breaking-point climb broke, from its windows. */
function breakingSection(steps: readonly StageGStepResult[]): string[] {
  return steps.flatMap(({ run, summary }) => {
    if (run.abort === null || run.test !== 'breaking') return [];
    const ceiling = rateAt(run, stagesSeconds(run));
    const rate = summary.windows === null ? null : breakingRate(run, run.abort, summary.windows);
    const said =
      rate === null
        ? `The climb reached its ceiling of ${String(ceiling)} requests a second without breaking: the breaking point is past it.`
        : `The climb broke at ${rate.toFixed(0)} requests a second: the first ${String(run.abort.windowSeconds)} s window whose p95 reached ${String(run.abort.p95Ms)} ms or whose failed share reached ${String(run.abort.errorShare * 100)}%. The overload test is sized from this rate.`;
    return ['', '### The breaking point', '', said];
  });
}

/** How long each surge took to recover, against its rule. */
function recoverySection(input: StageGReportInput): string[] {
  const window = input.profile.rules.recoveryWithinSeconds;
  return input.steps.flatMap((result) => {
    if (!isSurge(result.run)) return [];
    const seconds = measuredRecovery(result, input.profile.rules);
    let said = `Latency was back to the base load's ${String(seconds)} s after the surge ended (the rule: within ${String(window)} s).`;
    if (seconds === undefined) said = 'Recovery: not measured, k6 gave no window numbers for this step.';
    else if (seconds === null) said = "Recovery: latency never came back to the base load's.";
    return ['', '### Recovery after the surge', '', said];
  });
}

const resourceCell = (value: number | null | undefined): string =>
  value === null || value === undefined ? 'not measured' : String(value);

/** The soak's segments in a row, and whether anything crept. */
function soakSection(input: StageGReportInput): string[] {
  if (input.profile.test !== 'soak' || input.steps.length === 0) return [];
  const p95s = input.steps.map(({ summary }) => summary.asksMs?.p95 ?? 0);
  const first = p95s[0] ?? 0;
  const last = p95s.at(-1) ?? 0;
  const creep = (pick: (each: NonNullable<StageGStepResult['resources']>) => number | null, what: string): string => {
    const values = input.steps.map(({ resources }) => (resources === undefined ? null : pick(resources)));
    const [start] = values;
    const end = values.at(-1);
    return start === null || start === undefined || end === null || end === undefined
      ? `${what}: not measured.`
      : `${what}: ${String(start)} at the first segment's end, ${String(end)} at the last's.`;
  };
  return [
    '',
    '### The soak, segment by segment',
    '',
    '| Segment | p95 ms | API memory MB | Database connections |',
    '| --- | --- | --- | --- |',
    ...input.steps.map(
      ({ run, summary, resources }) =>
        `| ${run.label} | ${summary.asksMs === null ? 'none' : ms(summary.asksMs.p95)} | ${resourceCell(resources?.memoryMb)} | ${resourceCell(resources?.connections)} |`,
    ),
    '',
    `p95 from ${ms(first)} ms in the first segment to ${ms(last)} ms in the last (${first === 0 ? 'not compared' : percent(last / first - 1)}).`,
    creep(({ memoryMb }) => memoryMb, "The API's memory (MB)"),
    creep(({ connections }) => connections, "The database's connections"),
  ];
}

/** The cohort's shape, which no source gives: Claude's stated assumptions (StageG research). */
const ASSUMPTIONS = [
  `Stated assumptions, not sourced: one organisation in ${String(STAGE_G_LIGHT_EVERY)} is light-active (${String(100 / STAGE_G_LIGHT_EVERY)}%), one agent each, sending the steady traffic;`,
  `one in ${String(STAGE_G_HEAVY_EVERY)} is heavy (${String(100 / STAGE_G_HEAVY_EVERY)}%), ${String(CROWD_AGENTS)} agents sharing three suppliers; the rest are idle with a short history;`,
  `the first organisation holds a long chain of ${STAGE_G_HUGE_CHAIN_EVENTS.toLocaleString('en-GB')} partner refreshes.`,
].join(' ');

/** The Stage G section of a test's report, as markdown. */
export function renderStageG(input: StageGReportInput): string {
  const { profile, steps } = input;
  const baselineP95Ms = input.baselineP95Ms ?? steps[0]?.summary.asksMs?.p95;
  const failures = steps.map((step) => stepFailures(input, step, baselineP95Ms));
  const failedAt = failures.findIndex((each) => each.length > 0);
  const stopped = steps[failedAt]?.run.label;
  const verdict =
    stopped === undefined
      ? steps.length === profile.steps.length
        ? '**Passed: every step.**'
        : `**Not finished: ${String(steps.length)} of ${String(profile.steps.length)} steps ran, each passing.**`
      : `**Failed at step ${stopped}.** The climb stops there: fix it, then resume with \`--from ${stopped}\`.`;
  const baselineStep =
    input.baselineP95Ms === undefined ? 'the first step, ' + String(steps[0]?.run.label) : 'the target step';
  const baseline =
    baselineP95Ms === undefined
      ? 'No step had a p95 to set as the baseline.'
      : `Baseline: ${baselineStep}, p95 ${ms(baselineP95Ms)} ms.` +
        (profile.rules.calmMargin === null
          ? ''
          : ` A step's p95 more than ${String(profile.rules.calmMargin * 100)}% above it fails (AWS's investigation threshold).`);
  const lines = [
    `## Stage G: ${profile.test} (${String(steps.length)} of ${String(profile.steps.length)} steps)`,
    '',
    verdict,
    '',
    ASSUMPTIONS,
    '',
    '| Step | Organisations | Requests | New | p50 ms | p95 ms | p99 ms | 5xx | 429 by kind | Not sent | Decision p95 ms | p95 vs baseline | Result |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
    ...steps.map((step, index) => stepRow(step, baselineP95Ms, index, (failures[index] ?? []).length > 0)),
    '',
    baseline,
    '',
    '### Background work in each step’s window',
    '',
    '| Step | Minutes | Anchor checks | Failed | Unchecked (first → last) | Waiting (first → last) | Stalled jobs | Pulses | Longest pulse gap min | API restarts (before → after) |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
    ...steps.map(backgroundRow),
    ...breakingSection(steps),
    ...recoverySection(input),
    ...soakSection(input),
  ];
  const named = steps.flatMap(({ run }, index) =>
    (failures[index] ?? []).map((failure) => `- ${run.label}: ${failure}`),
  );
  if (named.length > 0) lines.push('', '### What failed', '', ...named);
  return `${lines.join('\n')}\n`;
}
