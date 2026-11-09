import { describe, expect, it } from 'vitest';

import type { BackgroundHealth } from './stageg-background.ts';
import {
  judgeStageGStep,
  renderStageG,
  type StageGReportInput,
  type StageGStepResult,
  type StageGSummary,
} from './stageg-report.ts';
import { baseHoldWindow, recoverySeconds } from './stageg-surge.ts';
import { type Profile, stageGProfile, stepRun, type WindowNumbers } from './stageg.ts';

const CALM: BackgroundHealth = {
  minutes: 20,
  anchorChecks: 4,
  failed: 0,
  missing: [],
  unchecked: { most: 0, last: 0 },
  left: { most: 3, last: 0 },
  stalled: [],
  errors: {},
  warnings: {},
  offenderWarnings: {},
  stuckWarnings: {},
  pulses: 20,
  longestPulseGapMinutes: 1.2,
};

/** The checks as stageg-checks.ts returns them after a clean step. */
const CLEAN_CHECKS = [
  { name: 'lost no request', failures: [] },
  { name: 'put no row in another organisation', failures: [] },
];

const summaryOf = (label: string, orgs: number, p95: number, more: Partial<StageGSummary> = {}): StageGSummary => ({
  test: 'orgs',
  step: label,
  orgs,
  requests: 153_000,
  created: 152_100,
  serverErrors: 0,
  rateLimited: 0,
  checksFailed: 0,
  dropped: 0,
  asksMs: { p50: p95 / 2, p95, p99: p95 * 1.5, max: p95 * 3 },
  kinds: { steady: { requests: 153_000, serverErrors: 0, rateLimited: 0, failedAnswers: 0, p95Ms: p95 } },
  aborted: false,
  windows: null,
  startedAt: '2026-11-06T10:00:00.000Z',
  endedAt: '2026-11-06T10:20:00.000Z',
  ...more,
});

/** A step of `profile` with clean results, its numbers changed by `more`. */
const stepOf = (
  profile: Profile,
  index: number,
  p95: number,
  more: Partial<Omit<StageGStepResult, 'run' | 'summary'>> & { readonly summary?: Partial<StageGSummary> } = {},
): StageGStepResult => {
  const step = profile.steps[index];
  if (step === undefined) throw new Error(`No step ${String(index)}.`);
  const { summary, ...rest } = more;
  return {
    run: stepRun(profile, step),
    summary: summaryOf(step.label, step.orgs, p95, summary),
    decisionP95Ms: 60,
    baseDecisionP95Ms: 60,
    background: CALM,
    restarts: { before: 0, after: 0 },
    databaseChecks: CLEAN_CHECKS,
    ...rest,
  };
};

const orgs = stageGProfile('orgs');

const HEAD = [
  '| Step | Organisations | Requests | New | p50 ms | p95 ms | p99 ms | 5xx | 429 by kind | Not sent | Decision p95 ms | p95 vs baseline | Result |',
  '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
];
const BACKGROUND_HEAD = [
  '### Background work in each step’s window',
  '',
  '| Step | Minutes | Anchor checks | Failed | Unchecked (most / last) | Waiting (most / last) | Stalled jobs | Pulses | Longest pulse gap min | API restarts (before → after) |',
  '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
];
const ASSUMPTIONS =
  'Stated assumptions, not sourced: one organisation in 50 is light-active (2%), one agent each, sending the steady traffic; one in 200 is heavy (0.5%), 10 agents sharing three suppliers; the rest are idle with a short history; the first organisation holds a long chain of 20,000 partner refreshes.';

describe("the report's Stage G section", () => {
  it('sets a passing climb’s steps side by side against the first', () => {
    const text = renderStageG({
      site: 'azure',
      profile: orgs,
      steps: [stepOf(orgs, 0, 40), stepOf(orgs, 1, 42), stepOf(orgs, 2, 44.8), stepOf(orgs, 3, 45.6)],
    });
    expect(text).toBe(
      [
        '## Stage G: orgs (4 of 4 steps)',
        '',
        '**Passed: every step.**',
        '',
        ASSUMPTIONS,
        '',
        ...HEAD,
        '| orgs-100 | 100 | 153000 | 152100 | 20.0 | 40.0 | 60.0 | 0 | steady 0 | 0 | 60.0 | baseline | Passed |',
        '| orgs-1000 | 1000 | 153000 | 152100 | 21.0 | 42.0 | 63.0 | 0 | steady 0 | 0 | 60.0 | +5.0% | Passed |',
        '| orgs-3000 | 3000 | 153000 | 152100 | 22.4 | 44.8 | 67.2 | 0 | steady 0 | 0 | 60.0 | +12.0% | Passed |',
        '| orgs-10000 | 10000 | 153000 | 152100 | 22.8 | 45.6 | 68.4 | 0 | steady 0 | 0 | 60.0 | +14.0% | Passed |',
        '',
        'Baseline: the first step, orgs-100, p95 40.0 ms.',
        '',
        ...BACKGROUND_HEAD,
        '| orgs-100 | 20.0 | 4 | 0 | 0 / 0 | 3 / 0 | none | 20 | 1.2 | 0 → 0 |',
        '| orgs-1000 | 20.0 | 4 | 0 | 0 / 0 | 3 / 0 | none | 20 | 1.2 | 0 → 0 |',
        '| orgs-3000 | 20.0 | 4 | 0 | 0 / 0 | 3 / 0 | none | 20 | 1.2 | 0 → 0 |',
        '| orgs-10000 | 20.0 | 4 | 0 | 0 / 0 | 3 / 0 | none | 20 | 1.2 | 0 → 0 |',
        '',
      ].join('\n'),
    );
  });

  it('names each reason a failing climb stopped where it did, and how to resume it', () => {
    const text = renderStageG({
      site: 'azure',
      profile: orgs,
      steps: [
        stepOf(orgs, 0, 40),
        stepOf(orgs, 1, 47, {
          summary: {
            serverErrors: 3,
            dropped: 12,
            kinds: { steady: { requests: 153_000, serverErrors: 3, rateLimited: 2, failedAnswers: 5, p95Ms: 47 } },
          },
          decisionP95Ms: 160,
          background: { ...CALM, failed: 1, stalled: ['anchor-check'], unchecked: null, errors: { 'job.stalled': 1 } },
          restarts: { before: 1, after: 2 },
          databaseChecks: [
            {
              name: 'lost no request',
              failures: [
                'The database holds 152099 requests of step orgs-1000, but k6 was answered 201 for 152100 new ones.',
              ],
            },
          ],
        }),
      ],
    });
    expect(text).toBe(
      [
        '## Stage G: orgs (2 of 4 steps)',
        '',
        '**Failed at step orgs-1000.** The climb stops there: fix it, then resume with `--from orgs-1000`.',
        '',
        ASSUMPTIONS,
        '',
        ...HEAD,
        '| orgs-100 | 100 | 153000 | 152100 | 20.0 | 40.0 | 60.0 | 0 | steady 0 | 0 | 60.0 | baseline | Passed |',
        '| orgs-1000 | 1000 | 153000 | 152100 | 23.5 | 47.0 | 70.5 | 3 | steady 2 | 12 | 160.0 | +17.5% | **Failed** |',
        '',
        'Baseline: the first step, orgs-100, p95 40.0 ms.',
        '',
        ...BACKGROUND_HEAD,
        '| orgs-100 | 20.0 | 4 | 0 | 0 / 0 | 3 / 0 | none | 20 | 1.2 | 0 → 0 |',
        '| orgs-1000 | 20.0 | 4 | 1 | no run | 3 / 0 | anchor-check | 20 | 1.2 | 1 → 2 |',
        '',
        '### What failed',
        '',
        "- orgs-1000: The decisions' p95 was 160.0 ms, over the 150.0 ms limit.",
        '- orgs-1000: 12 requests were never sent (k6 had no free VU): the step carried less load than it says.',
        '- orgs-1000: The database holds 152099 requests of step orgs-1000, but k6 was answered 201 for 152100 new ones.',
        '- orgs-1000: The anchor check failed 1 chain check(s) in the step: read its audit.anchor_check_done lines.',
        '- orgs-1000: The API logged job.stalled 1 time(s) at error level in the step.',
        "- orgs-1000: The API's replicas restarted 1 time(s) during the step: a crash, or a replica killed for memory.",
        '',
      ].join('\n'),
    );
  });
});

const windowsOf = (p95s: Readonly<Record<number, number>>): WindowNumbers[] =>
  Object.entries(p95s).map(([window, p95Ms]) => ({
    window: Number(window),
    p95Ms,
    failedShare: 0,
    refusedShare: 0,
    requests: 1000,
  }));

const spike = stageGProfile('spike');
const overload = stageGProfile('overload', 400);

/** A window's p95, failed share and refused share (429s, counted in the failed too), by window number: 1,000 answers each. */
type Windows = Readonly<Record<number, readonly [number, number, number?]>>;
const windowsWith = (each: Windows): WindowNumbers[] =>
  Object.entries(each).map(([window, [p95Ms, failedShare, refusedShare = 0]]) => ({
    window: Number(window),
    p95Ms,
    failedShare,
    refusedShare,
    requests: 1000,
  }));

/** Windows `from` to `to`, each with the p95 and failed share given. */
const span = (from: number, to: number, numbers: readonly [number, number, number?]): Windows =>
  Object.fromEntries(Array.from({ length: to - from + 1 }, (_, i) => [from + i, numbers]));

/**
 * The spike's base hold is 300 to 600 s: windows 10 to 19, their median 40 ms,
 * so back is at most 46 ms. Its surge ends at 800 s, inside window 26; its
 * last window is 56 (1,680-1,700 s). Every window from 26 on is 42 ms unless `after` says.
 */
const spikeWindows = (after: Windows, base: readonly [number, number] = [40, 0]) =>
  windowsWith({ ...span(10, 19, base), 15: [50, 0], 22: [900, 0.2], ...span(26, 56, [42, 0]), ...after });

describe('a bad run never passes for what the error share left out (review S175)', () => {
  const failing = (test: 'orgs' | 'spike', kinds: StageGSummary['kinds'], checksFailed = 0) => {
    const profile = test === 'orgs' ? orgs : stageGProfile('spike');
    return renderStageG({
      site: 'azure',
      profile,
      steps: [stepOf(profile, 0, 40, { summary: { kinds, checksFailed } })],
    });
  };
  const steady = (failedAnswers: number, rateLimited: number) => ({
    steady: { requests: 10_000, serverErrors: 0, rateLimited, failedAnswers, p95Ms: 40 },
  });

  it('shows a decision time not read yet as "not read", never NaN or a time', () => {
    const text = renderStageG({
      site: 'azure',
      profile: orgs,
      steps: [stepOf(orgs, 0, 40, { decisionP95Ms: Number.NaN })],
    });
    expect(text).toContain('| not read |');
    expect(text).not.toContain('NaN');
  });

  it('counts every answer but a 2xx in the error share: 4xx ones that are neither 5xx nor 429 too', () => {
    // 150 answers 409/422, none a 5xx or a 429: 1.5%, which the share of 5xx and 429 alone called 0%.
    expect(failing('orgs', steady(150, 0))).toContain(
      '- orgs-100: 1.50% of answers failed (not 2xx: a server error, busy, refused for rate or any other), not below 1%.',
    );
  });

  it('leaves out only the refusals for rate a surge means to cause', () => {
    // A spike: 3,000 refused for rate are its point; 99 others (busy 503s) are 0.99%, under its 1%.
    expect(failing('spike', steady(3099, 3000))).not.toContain('of answers failed');
    expect(failing('spike', steady(3100, 3000))).toContain('1.00% of answers failed');
    // The organisations' climb means none: 100 refused for rate are 1%.
    expect(failing('orgs', steady(100, 100))).toContain('1.00% of answers failed');
  });

  it('fails a step whose k6 checks failed: an answer not turned away was wrong', () => {
    expect(failing('orgs', steady(0, 0), 3)).toContain(
      "- orgs-100: k6's checks failed 3 time(s): answers not turned away were wrong (read the checks in k6's output).",
    );
  });
});

/** The spike's report with these windows, every other number clean. */
const spikeReport = (windows: WindowNumbers[]): string => {
  const step = stepOf(spike, 0, 40);
  return renderStageG({ site: 'azure', profile: spike, steps: [{ ...step, summary: { ...step.summary, windows } }] });
};

describe('the recovery after a surge, from its windows', () => {
  const run = stepOf(spike, 0, 40).run;
  const recovered = (after: Windows, base?: readonly [number, number]) =>
    recoverySeconds(run, 30, spikeWindows(after, base), 0.01);
  const without = (windows: WindowNumbers[], gone: number) => windows.filter(({ window }) => window !== gone);

  it('times the spike and overload by 30 s windows, with no rule to stop them', () => {
    expect([run.windowSeconds, run.abort]).toEqual([30, null]);
    expect(stepOf(overload, 0, 40).run.windowSeconds).toBe(30);
  });

  it('recovers in time: from the surge’s end to the first window that stays back', () => {
    // Window 26 (780-810 s) still slow, 27 (810-840 s) back and every one after it.
    expect(recovered({ 26: [300, 0], 27: [45, 0.009] })).toBe(10);
    expect(recovered({})).toBe(0);
  });

  it('recovers late: slow, or failing 1%, until window 29 (870 s)', () => {
    expect(recovered({ 26: [300, 0], 27: [70, 0], 28: [44, 0.01] })).toBe(70);
  });

  it('never recovers: the last window still bad or missing, or no window in the base hold', () => {
    expect(recovered({ 56: [90, 0] })).toBeNull();
    expect(recovered({ 56: [44, 0.5] })).toBeNull();
    expect(recoverySeconds(run, 30, without(spikeWindows({}), 56), 0.01)).toBeNull();
    expect(recoverySeconds(run, 30, windowsWith(span(26, 56, [42, 0])), 0.01)).toBeNull();
  });

  it('counts a missing window after the surge as not back: the clock runs from the next one', () => {
    // Window 40 (1,200 s) has no numbers: back for good from 41 (1,230 s), 430 s after the surge.
    expect(recoverySeconds(run, 30, without(spikeWindows({ 26: [300, 0] }), 40), 0.01)).toBe(430);
  });

  it('counts from the last bad window: a brief relapse after it was back restarts the clock', () => {
    // Back in 27, a relapse in 31 (930-960 s), back for good from 32 (960 s): 160 s, not 10.
    expect(recovered({ 26: [300, 0], 31: [200, 0] })).toBe(160);
  });

  it('measures back against the base hold’s median, capped at the request target', () => {
    // One slow base window (15, 50 ms) doesn't raise the bar: 47 ms is not back, where the slowest's 57.5 ms was.
    expect(recovered({ 56: [47, 0] })).toBeNull();
    // A base hold already at 800 ms can't make 700 ms back: the cap is 500 ms, back at most 575.
    expect(recovered({}, [800, 0])).toBe(0);
    expect(recovered({ 56: [700, 0] }, [800, 0])).toBeNull();
  });

  it('judges each surge against its own window: the spike 60 s, the overload 300 s', () => {
    const report = (profile: typeof spike, windows: WindowNumbers[]) => {
      const step = stepOf(profile, 0, 40);
      return renderStageG({ site: 'azure', profile, steps: [{ ...step, summary: { ...step.summary, windows } }] });
    };
    const inTime = report(spike, spikeWindows({ 26: [300, 0], 27: [45, 0] }));
    expect(inTime).toContain(
      "### Recovery after the surge\n\nLatency was back to the base load's 10 s after the surge ended (the rule: within 60 s).",
    );
    expect(inTime).toContain('**Passed: every step.**');
    const late = report(spike, spikeWindows({ 26: [300, 0], 27: [70, 0], 28: [44, 0.01] }));
    expect(late).toContain('**Failed at step spike.**');
    expect(late).toContain('- spike: Latency took 70 s to come back after the surge, over the 60 s window.');
    const never = report(spike, spikeWindows({ 56: [90, 0] }));
    expect(never).toContain("Recovery: latency never came back to the base load's.");
    expect(never).toContain("- spike: Latency never came back to the base load's after the surge.");
    // The overload's base hold is windows 10-19, its surge ends at 1,320 s (window 44), its last window is 103:
    // 44 slow, 45 failing 2%, back from 46 (1,380 s): 60 s, inside its 300.
    const overloadWindows = windowsWith({
      ...span(10, 19, [55, 0]),
      30: [2000, 0.4],
      ...span(44, 103, [60, 0]),
      44: [400, 0.05],
      45: [60, 0.02],
    });
    expect(report(overload, overloadWindows)).toContain(
      "Latency was back to the base load's 60 s after the surge ended (the rule: within 300 s).",
    );
    expect(report(overload, overloadWindows)).toContain('**Passed: every step.**');
  });

  it('fails a surge whose base hold missed the target, or has a window with no numbers', () => {
    const report = spikeReport;
    const slowBase = report(spikeWindows({ 11: [600, 0], 12: [40, 0.02] }));
    expect(slowBase).toContain(
      '- spike: The base load before the surge already missed the target in window 11: p95 600.0 ms (under 500), 0.00% failed (under 1%).',
    );
    expect(slowBase).toContain(
      '- spike: The base load before the surge already missed the target in window 12: p95 40.0 ms (under 500), 2.00% failed (under 1%).',
    );
    expect(report(without(spikeWindows({}), 13))).toContain(
      '- spike: Window 13 of the base load before the surge has no numbers: there is nothing sure to come back to.',
    );
  });

  it("fails a surge whose base hold's decisions missed the 150 ms rule, or weren't measured", () => {
    const withDecisions = (baseDecisionP95Ms: number | null) => {
      const step = stepOf(spike, 0, 40, { baseDecisionP95Ms });
      return renderStageG({
        site: 'azure',
        profile: spike,
        steps: [{ ...step, summary: { ...step.summary, windows: spikeWindows({}) } }],
      });
    };
    expect(withDecisions(150)).toContain('**Passed: every step.**');
    expect(withDecisions(151)).toContain(
      "- spike: The base load's decisions before the surge had a p95 of 151.0 ms, over the 150.0 ms limit.",
    );
    expect(withDecisions(null)).toContain(
      "- spike: The base load's decisions before the surge were not measured: no decision line in its time.",
    );
    // The base hold's time, for the decisions read from the API's lines: 300 to 600 s into the step.
    expect(baseHoldWindow(stepOf(spike, 0, 40).run, '2026-11-06T10:00:00.000Z')).toEqual({
      from: '2026-11-06T10:05:00.000Z',
      to: '2026-11-06T10:10:00.000Z',
    });
  });

  it('prints the refusals for rate by phase, and fails one outside the surge: in the base hold or after it recovered', () => {
    const report = spikeReport;
    // The surge's windows 20-25 (600-780 s): 20, 22 and 24 shown; 26 still slow and refusing, back from 27.
    const surged = spikeWindows({
      20: [300, 0.3, 0.3],
      22: [900, 0.2, 0.1],
      24: [400, 0.1, 0.05],
      26: [300, 0.05, 0.04],
    });
    const clean = report(surged);
    expect(clean).toContain(
      'Refused for rate (429), by phase: base 0.00%, surge 15.00%, recovery 4.00%, after recovering 0.00%.',
    );
    expect(clean).toContain('**Passed: every step.**');
    const inBase = report([
      ...surged.filter(({ window }) => window !== 12),
      { window: 12, p95Ms: 40, failedShare: 0.002, refusedShare: 0.002, requests: 1000 },
    ]);
    expect(inBase).toContain(
      '- spike: Turned away outside the surge: 0.02% of the answers in the base load before it were refused for rate (429).',
    );
    const afterBack = report(
      surged.map((each) => (each.window === 50 ? { ...each, failedShare: 0.03, refusedShare: 0.03 } : each)),
    );
    expect(afterBack).toContain('after recovering 0.10%.');
    expect(afterBack).toContain(
      '- spike: Turned away outside the surge: 0.10% of the answers after it recovered were refused for rate (429).',
    );
    const never = report(spikeWindows({ 56: [90, 0] }));
    expect(never).toContain('recovery 0.00%, after recovering never recovered.');
    expect(report(spikeWindows({}).filter(({ window }) => window < 20 || window > 25))).toContain('surge no answers');
  });

  it('says a surge k6 gave no windows for was not measured, never that it never recovered', () => {
    const unmeasured = renderStageG({ site: 'azure', profile: spike, steps: [stepOf(spike, 0, 40)] });
    expect(unmeasured).toContain('Recovery: not measured, k6 gave no window numbers for this step.');
    expect(unmeasured).toContain(
      '- spike: The recovery after the surge was not measured: k6 gave no window numbers for this step.',
    );
    expect(unmeasured).not.toContain('never came back');
  });
});

describe("the report's tests apart from the climb", () => {
  it('names the rate a breaking-point climb broke at, or the ceiling it reached', () => {
    const breaking = stageGProfile('breaking');
    const broke = (windows: readonly WindowNumbers[] | null) =>
      renderStageG({
        site: 'azure',
        profile: breaking,
        steps: [stepOf(breaking, 0, 40, { summary: { windows, aborted: true } })],
      });
    expect(broke(windowsOf({ 29: 300, 30: 600 }))).toContain(
      '### The breaking point\n\nThe climb broke at 425 requests a second: the first 30 s window whose p95 reached 500 ms or whose failed share reached 1%. The overload test is sized from this rate.',
    );
    expect(broke(windowsOf({ 29: 300 }))).toContain(
      'The climb reached its ceiling of 1700 requests a second without breaking: the breaking point is past it.',
    );
    expect(broke(null)).toContain('The climb reached its ceiling of 1700 requests a second');
  });

  it('sets the soak’s segments in a row, with what was and wasn’t measured', () => {
    const soak = stageGProfile('soak');
    const text = renderStageG({
      site: 'azure',
      profile: soak,
      steps: [
        stepOf(soak, 0, 40, { resources: { memoryMb: 410, connections: 18 } }),
        stepOf(soak, 1, 41, { resources: { memoryMb: 415, connections: null } }),
        stepOf(soak, 2, 0, { summary: { asksMs: null } }),
        stepOf(soak, 3, 44, { resources: { memoryMb: 430, connections: null } }),
      ],
    });
    expect(text).toContain(
      [
        '### The soak, segment by segment',
        '',
        '| Segment | p95 ms | API memory MB | Database connections |',
        '| --- | --- | --- | --- |',
        '| soak-1 | 40.0 | 410 | 18 |',
        '| soak-2 | 41.0 | 415 | not measured |',
        '| soak-3 | none | not measured | not measured |',
        '| soak-4 | 44.0 | 430 | not measured |',
        '',
        'p95 from 40.0 ms in the first segment to 44.0 ms in the last (+10.0%).',
        "The API's memory (MB): 410 at the first segment's end, 430 at the last's.",
        "The database's connections: not measured.",
      ].join('\n'),
    );
    expect(text).toContain('| soak-3 | 10000 | 153000 | 152100 | none | none | none |');
    expect(
      renderStageG({ site: 'azure', profile: soak, steps: [stepOf(soak, 0, 0, { summary: { asksMs: null } })] }),
    ).toContain('p95 from 0.0 ms in the first segment to 0.0 ms in the last (not compared).');
  });

  it('compares the neighbours with the target’s p95, judged by the calm organisations only', () => {
    const neighbours = stageGProfile('neighbours');
    const kinds = {
      calm: { requests: 9000, serverErrors: 0, rateLimited: 4, failedAnswers: 4, p95Ms: 50 },
      busy: { requests: 15_000, serverErrors: 0, rateLimited: 900, failedAnswers: 900, p95Ms: 20 },
      stuck: { requests: 3000, serverErrors: 2, rateLimited: 0, failedAnswers: 2, p95Ms: 4000 },
    };
    const text = renderStageG({
      site: 'azure',
      profile: neighbours,
      baselineP95Ms: 45,
      steps: [stepOf(neighbours, 0, 50, { summary: { kinds } })],
    });
    expect(text).toContain('| 0 | calm 4, busy 900, stuck 0 | 0 | 60.0 | +11.1% | **Failed** |');
    expect(text).toContain('Baseline: the target step, p95 45.0 ms.');
    expect(text).toContain(
      '- neighbours: The calm organisations were refused for rate 4 times: only the offender may be.',
    );
  });

  it('names each busy line a step was allowed, with its count, and fails one logged where nothing is meant busy', () => {
    const busy = { ...CALM, warnings: { 'spend_request.platform_full': 12 } };
    const spikeStep = stepOf(spike, 0, 40, { background: busy });
    expect(renderStageG({ site: 'azure', profile: spike, steps: [spikeStep] })).toContain(
      'Busy lines allowed in spike: spend_request.platform_full 12.',
    );
    const calm = renderStageG({ site: 'azure', profile: orgs, steps: [stepOf(orgs, 0, 40, { background: busy })] });
    expect(calm).not.toContain('Busy lines allowed');
    expect(calm).toContain(
      '- orgs-100: The API logged spend_request.platform_full 12 warning(s) in the step: only the busy lines of a step meant to overload are allowed.',
    );
  });

  it('fails a step whose database checks never ran, and one whose restarts were not read on Azure only', () => {
    const run = (site: 'local' | 'azure', more: Parameters<typeof stepOf>[3]) =>
      renderStageG({ site, profile: orgs, steps: [stepOf(orgs, 0, 40, more)] });
    expect(run('azure', { databaseChecks: [] })).toContain(
      '- orgs-100: The database checks never ran after the step, so nothing says its rows are right.',
    );
    expect(run('azure', { restarts: null })).toContain(
      "- orgs-100: The API's replica restarts were not read, so a crash during the step can't be ruled out.",
    );
    expect(run('local', { restarts: null })).toContain('**Not finished: 1 of 4 steps ran, each passing.**');
  });

  it('says a climb not yet finished, and a step with no p95 has no baseline', () => {
    expect(renderStageG({ site: 'azure', profile: orgs, steps: [stepOf(orgs, 0, 40)] })).toContain(
      '**Not finished: 1 of 4 steps ran, each passing.**',
    );
    const none = renderStageG({
      site: 'azure',
      profile: orgs,
      steps: [stepOf(orgs, 0, 0, { summary: { asksMs: null, kinds: {} }, restarts: null })],
    });
    expect(none).toContain('No step had a p95 to set as the baseline.');
    expect(none).toContain('| 0 | no traffic | 0 | 60.0 | not compared | **Failed** |');
    expect(none).toContain('| 0 / 0 | 3 / 0 | none | 20 | 1.2 | not read |');
    expect(none).toContain('- orgs-100: The step sent no request, so nothing could be judged.');
    expect(
      renderStageG({
        site: 'azure',
        profile: stageGProfile('target'),
        steps: [stepOf(stageGProfile('target'), 0, 40)],
      }),
    ).toContain('Baseline: the first step, target, p95 40.0 ms.\n');
  });

  it('says a step whose logs are still arriving is not judged yet, never passed or failed, with what it waits for', () => {
    const waiting = { ...CALM, missing: ['a jobs.pulse line after the step ended'] };
    const input: StageGReportInput = {
      site: 'azure',
      profile: orgs,
      steps: [stepOf(orgs, 0, 40), stepOf(orgs, 1, 400, { background: waiting, databaseChecks: [] })],
    };
    const [first, second] = input.steps;
    expect(first && judgeStageGStep(input, first, 40)).toEqual({ state: 'passed' });
    expect(second && judgeStageGStep(input, second, 40)).toEqual({
      state: 'not-judged-yet',
      missing: ['a jobs.pulse line after the step ended'],
    });
    const text = renderStageG(input);
    expect(text).toContain(
      '**Not judged yet — logs still arriving for step orgs-1000.** Read them again before going on.',
    );
    expect(text).toContain('| 60.0 | +900.0% | not judged yet — logs still arriving |');
    expect(text).toContain(
      '### Not judged yet: still waiting for\n\n- orgs-1000: a jobs.pulse line after the step ended',
    );
    expect(text).not.toContain('**Failed');
    expect(text).not.toContain('### What failed');
    const failing = { ...input, steps: [stepOf(orgs, 0, 40, { databaseChecks: [] })] };
    expect(failing.steps[0] && judgeStageGStep(failing, failing.steps[0], 40)).toEqual({
      state: 'failed',
      failures: ['The database checks never ran after the step, so nothing says its rows are right.'],
    });
  });
});
