// Stage G's profiles (stageg.ts): the research table's rates and holds, the
// stages k6 is handed for each shape, and how a step's result is judged.
import { describe, expect, it } from 'vitest';

import { POLICY_P95_MS } from './plan.ts';
import {
  breakingRate,
  judgeStep,
  k6Stages,
  type PassRules,
  rateAt,
  STAGE_G_JOB_MARGIN_SECONDS,
  STAGE_G_JOB_SECONDS,
  STAGE_G_TESTS,
  stageGProfile,
  stagesSeconds,
  type Step,
  type StepMeasured,
  type StepRun,
  stepRun,
  type WindowNumbers,
} from './stageg.ts';

/** A step's stages as `rate@seconds`, easy to read against the research table. */
const shape = (step: Step): string[] => {
  const { startRate, stages } = k6Stages(step);
  return [`start ${String(startRate)}`, ...stages.map(({ target, duration }) => `${String(target)}@${duration}`)];
};

const steps = (test: Parameters<typeof stageGProfile>[0], breakingRate?: number): readonly Step[] =>
  stageGProfile(test, breakingRate).steps;

/** What k6 is handed for each of a test's steps. */
const runs = (test: Parameters<typeof stageGProfile>[0]): StepRun[] => {
  const profile = stageGProfile(test);
  return profile.steps.map((step) => stepRun(profile, step));
};

describe("Stage G's profiles, as the research table sets them", () => {
  it('smokes at 100 organisations, 2 a second, for 2 minutes, straight at the rate', () => {
    expect(steps('smoke').map((step) => [step.label, step.orgs, shape(step)])).toEqual([
      ['smoke', 100, ['start 2', '2@120s']],
    ]);
  });

  it("steps the organisations 100, 1k, 3k, 10k at each one's share of 170/s: 5 minutes up, 15 held, 30 at 10k", () => {
    // Each active agent at the target's pace (S176): never 170/s on 100 organisations' 2 agents.
    expect(steps('orgs').map((step) => [step.label, step.orgs, shape(step)])).toEqual([
      ['orgs-100', 100, ['start 0', '2@300s', '2@900s']],
      ['orgs-1000', 1000, ['start 0', '17@300s', '17@900s']],
      ['orgs-3000', 3000, ['start 0', '51@300s', '51@900s']],
      ['orgs-10000', 10_000, ['start 0', '170@300s', '170@1800s']],
    ]);
  });

  it('sends a duplicate and a replay each second at 170/s, as rarely beside a smaller step, at most each second', () => {
    const everyOf = (test: Parameters<typeof stageGProfile>[0]) => runs(test).map((run) => run.extrasEverySeconds);
    expect(everyOf('smoke')).toEqual([85]);
    expect(everyOf('orgs')).toEqual([85, 10, 3, 1]);
    expect(everyOf('rates')).toEqual([4, 2, 1, 1, 1]);
    expect([...everyOf('target'), ...everyOf('breaking'), ...everyOf('neighbours')]).toEqual([1, 1, 1]);
  });

  it('holds the target, past 10k and the HA run at 170/s for 30 minutes, at 10k, 30k and 10k organisations', () => {
    for (const [test, orgs] of [
      ['target', 10_000],
      ['past10k', 30_000],
      ['ha', 10_000],
    ] as const) {
      expect(steps(test).map((step) => [step.label, step.orgs, shape(step)])).toEqual([
        [test, orgs, ['start 0', '170@300s', '170@1800s']],
      ]);
    }
  });

  it('steps the rate 43, 85, 170, 255, 340 a second, 10 minutes each after a minute up', () => {
    expect(steps('rates').map((step) => [step.label, step.orgs, shape(step)])).toEqual(
      [43, 85, 170, 255, 340].map((rate) => [
        `rate-${String(rate)}`,
        10_000,
        ['start 0', `${String(rate)}@60s`, `${String(rate)}@600s`],
      ]),
    );
  });

  it('spikes from 170/s to three times within 10 s for 3 minutes, back to 170/s and holds 15 minutes', () => {
    expect(steps('spike').map(shape)).toEqual([
      ['start 0', '170@300s', '170@300s', '510@10s', '510@180s', '170@10s', '170@900s'],
    ]);
  });

  it('runs the neighbours beside the calm organisations at the target, with phase 5 offenders', () => {
    expect(steps('neighbours').map(shape)).toEqual([['start 0', '170@300s', '170@900s']]);
    expect(runs('neighbours')).toMatchObject([{ mix: 'neighbours', neighbours: { busyRate: 25, stuckRate: 5 } }]);
  });

  it('climbs smoothly from 170/s to ten times over 30 minutes, stopped at p95 500 ms or 1% failed in any 30 s window', () => {
    expect(steps('breaking').map(shape)).toEqual([['start 0', '170@300s', '170@300s', '1700@1800s']]);
    expect(runs('breaking').map(({ abort }) => abort)).toEqual([{ p95Ms: 500, errorShare: 0.01, windowSeconds: 30 }]);
  });

  it('overloads to one and a half times the measured breaking rate for 10 minutes, then 30 back at 170/s', () => {
    expect(steps('overload', 401).map(shape)).toEqual([
      ['start 0', '170@300s', '170@300s', '602@60s', '602@600s', '170@60s', '170@1800s'],
    ]);
  });

  it('refuses an overload with no measured breaking rate, saying to run the breaking test first', () => {
    for (const rate of [undefined, 0, -5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => stageGProfile('overload', rate)).toThrow(/run "breaking" first/);
    }
  });

  it('soaks four hours as four one-hour runs, the first ramped 5 minutes and the rest one', () => {
    expect(steps('soak').map((step) => [step.label, step.shape, shape(step)])).toEqual([
      ['soak-1', { kind: 'soak', segment: 1, segments: 4 }, ['start 0', '170@300s', '170@3300s']],
      ['soak-2', { kind: 'soak', segment: 2, segments: 4 }, ['start 0', '170@60s', '170@3540s']],
      ['soak-3', { kind: 'soak', segment: 3, segments: 4 }, ['start 0', '170@60s', '170@3540s']],
      ['soak-4', { kind: 'soak', segment: 4, segments: 4 }, ['start 0', '170@60s', '170@3540s']],
    ]);
  });

  it("fits a soak segment's full hour of traffic and a 300 s margin inside the 4500 s load-step job", () => {
    expect([STAGE_G_JOB_SECONDS, STAGE_G_JOB_MARGIN_SECONDS]).toEqual([4500, 300]);
    for (const step of steps('soak')) {
      const traffic = stagesSeconds(k6Stages(step));
      expect(traffic).toBe(3600);
      expect(traffic + STAGE_G_JOB_MARGIN_SECONDS).toBeLessThanOrEqual(STAGE_G_JOB_SECONDS);
    }
  });

  it('gives every test a profile, its steps labelled apart, each with its margin inside the load-step job', () => {
    for (const test of STAGE_G_TESTS) {
      const profile = stageGProfile(test, 400);
      expect(profile.test).toBe(test);
      const labels = profile.steps.map(({ label }) => label);
      expect(new Set(labels).size).toBe(labels.length);
      for (const step of profile.steps) {
        expect(stagesSeconds(k6Stages(step)) + STAGE_G_JOB_MARGIN_SECONDS).toBeLessThanOrEqual(STAGE_G_JOB_SECONDS);
      }
    }
  });

  it('judges the target by the decision p95 limit, errors below 1% and nothing unsent', () => {
    expect(stageGProfile('target').rules).toEqual({
      decisionP95Ms: POLICY_P95_MS,
      maxErrorShare: 0.01,
      droppedAllowed: false,
      calmMargin: null,
      calmNeverLimited: false,
      recoveryWithinSeconds: null,
    });
    expect(stageGProfile('smoke').rules).toEqual(stageGProfile('target').rules);
    expect(stageGProfile('soak').rules).toEqual(stageGProfile('target').rules);
  });

  it('judges only the neighbours against a baseline, and only they forbid 429s; the orgs steps report theirs', () => {
    // Each orgs step at its own rate (S176): judged by the decision limit, its p95 against the first step's reported.
    expect(stageGProfile('orgs').rules).toEqual(stageGProfile('target').rules);
    expect(stageGProfile('neighbours').rules).toMatchObject({ calmMargin: 0.15, calmNeverLimited: true });
  });

  it('reports the rate steps, the breaking point and the overload apart from the limits they would break by design', () => {
    expect(stageGProfile('rates').rules).toMatchObject({
      decisionP95Ms: null,
      maxErrorShare: 0.01,
      droppedAllowed: false,
    });
    expect(stageGProfile('breaking').rules).toMatchObject({
      decisionP95Ms: null,
      maxErrorShare: null,
      droppedAllowed: true,
    });
    expect(stageGProfile('overload', 400).rules).toMatchObject({
      decisionP95Ms: null,
      maxErrorShare: null,
      droppedAllowed: true,
      recoveryWithinSeconds: 300,
    });
    expect(stageGProfile('spike').rules).toMatchObject({
      decisionP95Ms: null,
      maxErrorShare: 0.01,
      droppedAllowed: false,
      recoveryWithinSeconds: 60,
    });
  });
});

describe('what k6 is handed for one step', () => {
  it('names the test, the step, its organisations and VUs for half a second of its peak, at least 10, five times or 5 s of its peak at most', () => {
    expect(runs('smoke')).toEqual([
      {
        test: 'smoke',
        label: 'smoke',
        orgs: 100,
        mix: 'steady',
        startRate: 2,
        stages: [{ target: 2, duration: '120s' }],
        vus: { pre: 10, max: 50 },
        abort: null,
        windowSeconds: null,
        neighbours: null,
        extrasEverySeconds: 85,
      },
    ]);
    // Room for 5 s of the peak's arrivals unanswered: 510 a second's spike; the target's 170 rides out a storage flush.
    expect(runs('spike').map(({ vus }) => vus)).toEqual([{ pre: 255, max: 2550 }]);
    expect(runs('target').map(({ vus }) => vus)).toEqual([{ pre: 85, max: 850 }]);
    // The stall room stops at the breaking climb's 4,250, but never cuts five times the ready VUs: overload past it keeps them.
    expect(runs('breaking').map(({ vus }) => vus)).toEqual([{ pre: 850, max: 4250 }]);
    const overload = stageGProfile('overload', 1700);
    expect(overload.steps.map((step) => stepRun(overload, step).vus)).toEqual([{ pre: 1275, max: 6375 }]);
    // Timed by 30 s windows: the climb for its abort rule, the surges for their recovery; the rest whole.
    const windowed = STAGE_G_TESTS.map((test) => [
      test,
      stageGProfile(test, 400).steps.map((step) => stepRun(stageGProfile(test, 400), step).windowSeconds)[0],
    ]);
    expect(Object.fromEntries(windowed)).toEqual({
      smoke: null,
      orgs: null,
      target: null,
      rates: null,
      spike: 30,
      neighbours: null,
      breaking: 30,
      overload: 30,
      soak: null,
      past10k: null,
      ha: null,
    });
  });

  it('works out the rate asked at any second, so a stopped climb names its breaking rate', () => {
    // Halfway up the ramp, at the hold, halfway up the climb, and long after it ended.
    const seconds = [0, 150, 450, 600 + 900, 99_999];
    expect(runs('breaking').map((climb) => seconds.map((at) => rateAt(climb, at)))).toEqual([[0, 85, 170, 935, 1700]]);
  });
});

describe("naming a climb's breaking rate from its windows", () => {
  const climb = runs('breaking')[0];
  if (climb === undefined || climb.abort === null) throw new Error('The breaking test has an abort rule.');
  const { abort } = climb;
  /** The 95th percentile by nearest rank, as near k6's as this needs. */
  const p95 = (times: readonly number[]): number =>
    [...times].sort((a, b) => a - b)[Math.ceil(times.length * 0.95) - 1] ?? 0;
  /** A thousand answers a window: `slow` of them at 900 ms past the knee, the rest at 100 ms. */
  const answers = (slow: number): number[] => Array.from({ length: 1000 }, (_, i) => (i < slow ? 900 : 100));
  const KNEE = 40;

  it('catches a gradual knee, 6% slow growing to 10%, in its first window, where the whole run hides it', () => {
    const times = Array.from({ length: 80 }, (_, window) =>
      answers(window < KNEE ? 0 : Math.min(100, 60 + (window - KNEE) * 10)),
    );
    const windows: WindowNumbers[] = times.map((each, window) => ({
      window,
      p95Ms: p95(each),
      failedShare: 0,
      refusedShare: 0,
      requests: 1000,
    }));
    // At 40 windows of 30 s, 1,200 s in: 170/s plus a third of the climb to 1,700/s.
    expect(breakingRate(climb, abort, windows)).toBe(680);
    expect(rateAt(climb, KNEE * 30)).toBe(680);
    // The whole run up to that window, as k6's own cumulative p95 would read it, still looks fine.
    expect(p95(times.slice(0, KNEE + 1).flat())).toBeLessThan(abort.p95Ms);
  });

  it('breaks on the failed share alone, at the limit, and names no rate for a climb that never broke', () => {
    const calm = (window: number): WindowNumbers => ({
      window,
      p95Ms: 120,
      failedShare: 0.002,
      refusedShare: 0,
      requests: 1000,
    });
    expect(breakingRate(climb, abort, [calm(0), calm(30), { ...calm(31), failedShare: 0.01 }, calm(32)])).toBe(
      rateAt(climb, 31 * 30),
    );
    expect(breakingRate(climb, abort, [{ ...calm(25), p95Ms: 500 }, calm(0), { ...calm(12), p95Ms: 499.9 }])).toBe(
      rateAt(climb, 25 * 30),
    );
    expect(breakingRate(climb, abort, [calm(0), calm(1)])).toBeNull();
  });
});

describe("judging a step's measured result", () => {
  const target = stageGProfile('target').rules;
  const good: StepMeasured = {
    decisionP95Ms: 120,
    requests: 10_000,
    serverErrors: 50,
    rateLimited: 49,
    dropped: 0,
    calmP95Ms: 80,
    recoverySeconds: 30,
  };

  it('passes a step inside every rule', () => {
    expect(judgeStep(target, good)).toEqual({ passed: true, failures: [] });
  });

  it('fails the decision p95 over its limit, a 1% error share and any request never sent, each in plain words', () => {
    expect(judgeStep(target, { ...good, decisionP95Ms: 150.1, serverErrors: 51, dropped: 3 })).toEqual({
      passed: false,
      failures: [
        "The decisions' p95 was 150.1 ms, over the 150.0 ms limit.",
        '1.00% of answers failed (not 2xx: a server error, busy, refused for rate or any other), not below 1%.',
        '3 requests were never sent (k6 had no free VU): the step carried less load than it says.',
      ],
    });
  });

  it('fails a step that sent nothing, rather than pass it on no numbers', () => {
    expect(judgeStep(target, { ...good, requests: 0, serverErrors: 0, rateLimited: 0 }).failures).toEqual([
      'The step sent no request, so nothing could be judged.',
    ]);
  });

  it('ignores the limits a profile leaves null', () => {
    const none: PassRules = { ...target, decisionP95Ms: null, maxErrorShare: null, droppedAllowed: true };
    expect(judgeStep(none, { ...good, decisionP95Ms: 9_999, serverErrors: 9_000, dropped: 70 }).passed).toBe(true);
  });

  it("holds the calm p95 within 15% of the baseline step's, failing without a baseline", () => {
    const calm: PassRules = { ...target, calmMargin: stageGProfile('neighbours').rules.calmMargin };
    expect(judgeStep(calm, { ...good, calmP95Ms: 92 }, 80).passed).toBe(true);
    expect(judgeStep(calm, { ...good, calmP95Ms: 92.1 }, 80).failures).toEqual([
      "The p95 was 92.1 ms, more than 15% above the baseline step's 80.0 ms.",
    ]);
    expect(judgeStep(calm, good).failures).toEqual(['No baseline step was given to compare the p95 with.']);
  });

  it('fails the neighbours when a calm organisation was refused for rate at all', () => {
    const neighbours = stageGProfile('neighbours').rules;
    expect(judgeStep(neighbours, { ...good, rateLimited: 0 }, 80).passed).toBe(true);
    expect(judgeStep(neighbours, { ...good, rateLimited: 1 }, 80).failures).toEqual([
      'The calm organisations were refused for rate 1 times: only the offender may be.',
    ]);
  });

  it('holds a surge to its recovery window, and fails one that never recovered', () => {
    const spike = stageGProfile('spike').rules;
    expect(judgeStep(spike, { ...good, recoverySeconds: 60 }).passed).toBe(true);
    expect(judgeStep(spike, { ...good, recoverySeconds: 61 }).failures).toEqual([
      'Latency took 61 s to come back after the surge, over the 60 s window.',
    ]);
    expect(judgeStep(spike, { ...good, recoverySeconds: null }).failures).toEqual([
      "Latency never came back to the base load's after the surge.",
    ]);
  });
});
