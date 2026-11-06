// What both load scripts share that needs nothing of k6's (plain.k6.js), loaded
// as k6 loads it: the scenarios and thresholds, Stage G's step as the runner
// hands it (stageg.ts's stepRun, checked on arrival), and the summaries' numbers.
import { describe, expect, it } from 'vitest';

import { STAGE_G_TESTS, stageGProfile, type StepRun, stepRun } from './stageg.ts';

type Metrics = Record<string, { values: Record<string, number>; thresholds?: Record<string, { ok: boolean }> }>;

interface K6Data {
  metrics: Metrics;
  state: { testRunDurationMs: number };
}

interface StepOptions {
  summaryTrendStats: string[];
  tags: Record<string, string>;
  scenarios: Record<string, Record<string, unknown>>;
  thresholds: Record<string, unknown[]>;
}

interface PlainModule {
  constantRate: (seconds: number, rate: number, run: string, vus: number) => Record<string, unknown>;
  namedOnly: (kinds: readonly string[], metric: string, rule: string) => Record<string, string[]>;
  readStep: (text: string | undefined) => StepRun;
  stageGOptions: (step: StepRun) => StepOptions;
  stepSeconds: (step: StepRun) => number;
  countOf: (metrics: Metrics, name: string) => number;
  thresholdResults: (metrics: Metrics) => Record<string, boolean>;
  kindNumbers: (metrics: Metrics, kind: string) => Record<string, number>;
  runWindow: (state: K6Data['state'], endedAt?: number) => { startedAt: string; endedAt: string };
  stageGSummary: (step: StepRun, data: K6Data, endedAt?: number) => Record<string, unknown>;
  windowOf: (t0: number, now: number, windowSeconds: number) => number;
  windowCount: (step: StepRun) => number;
  windowMetrics: (window: number) => { ms: string; failed: string };
}

/** A plain JavaScript file has no types: named by URL so TypeScript takes it as the interface above. */
const PLAIN_FILE = new URL('./plain.k6.js', import.meta.url).href;
const plain = (await import(PLAIN_FILE)) as PlainModule;

/** Every step of every test, as the runner would hand it to k6. */
const everyRun = STAGE_G_TESTS.flatMap((test) => {
  const profile = stageGProfile(test, 400);
  return profile.steps.map((step) => stepRun(profile, step));
});

const runOf = (test: (typeof STAGE_G_TESTS)[number]): StepRun => {
  const run = everyRun.find((each) => each.test === test);
  if (run === undefined) throw new Error(`No ${test} step.`);
  return run;
};

const target = runOf('target');

describe('the scenarios and thresholds both scripts build', () => {
  it('sends a fixed rate for the seconds given, with five times the ready VUs at most', () => {
    expect(plain.constantRate(120, 25, 'steady', 60)).toEqual({
      executor: 'constant-arrival-rate',
      rate: 25,
      timeUnit: '1s',
      duration: '120s',
      preAllocatedVUs: 60,
      maxVUs: 300,
      exec: 'steady',
    });
  });

  it('names a metric for each kind with a rule that never fails, so k6 times and counts each apart', () => {
    expect(plain.namedOnly(['calm', 'busy'], 'http_reqs', 'count>=0')).toEqual({
      'http_reqs{kind:calm}': ['count>=0'],
      'http_reqs{kind:busy}': ['count>=0'],
    });
  });
});

describe("Stage G's step, as k6 is handed it", () => {
  it('takes every step of every profile as stepRun makes it, unchanged', () => {
    expect(everyRun.length).toBeGreaterThan(STAGE_G_TESTS.length);
    for (const run of everyRun) expect(plain.readStep(JSON.stringify(run))).toEqual(run);
  });

  it('refuses no step, or one that is not JSON, saying so and that k6 sent nothing', () => {
    for (const [text, said] of [
      [undefined, 'STEP is not set'],
      ['', 'STEP is not set'],
      ['{"test":', 'STEP is not JSON'],
    ] as const) {
      expect(() => plain.readStep(text)).toThrow(`${said}, so k6 sent nothing.`);
    }
  });

  it('refuses a step with a field missing or one more, or that is not an object', () => {
    const { abort: _abort, ...missing } = target;
    for (const step of [missing, { ...target, extra: 1 }, [target], null, 'target']) {
      expect(() => plain.readStep(JSON.stringify(step))).toThrow('STEP must have exactly these fields: test, label,');
    }
  });

  it('refuses each part that is not as stepRun makes it, naming the part', () => {
    const wrong: [string, Partial<Record<keyof StepRun, unknown>>][] = [
      ['test or label', { label: 'Orgs 100' }],
      ['test or label', { test: 7 }],
      ['test or label', { label: 'x'.repeat(41) }],
      ['organisations', { orgs: 0 }],
      ['organisations', { orgs: 2.5 }],
      ['mix', { mix: 'toString' }],
      ['stages', { startRate: -1 }],
      ['stages', { stages: [] }],
      ['stages', { stages: 'fast' }],
      ['stages', { stages: [{ target: 170, duration: '0s' }] }],
      ['stages', { stages: [{ target: 170, duration: '5m' }] }],
      ['stages', { stages: [{ target: Number.NaN, duration: '5s' }] }],
      ['stages', { stages: [{ target: 170, duration: '5s', extra: 1 }] }],
      ['VUs', { vus: { pre: 10, max: 5 } }],
      ['VUs', { vus: { pre: 0, max: 5 } }],
      ['VUs', { vus: { pre: 10 } }],
      ['abort rule', { abort: { p95Ms: 500, errorShare: 1, windowSeconds: 30 } }],
      ['abort rule', { abort: { p95Ms: 0, errorShare: 0.01, windowSeconds: 30 } }],
      ['abort rule', { abort: { p95Ms: 500, errorShare: 0.01, windowSeconds: 0.5 } }],
      ['windows', { windowSeconds: 0 }],
      ['windows', { windowSeconds: '30' }],
      ['windows', { abort: { p95Ms: 500, errorShare: 0.01, windowSeconds: 30 }, windowSeconds: 60 }],
      ['abort rule', { abort: { p95Ms: 500, errorShare: 0.01 } }],
      ['neighbours', { neighbours: { busyRate: 25, stuckRate: 5 } }],
      ['neighbours', { mix: 'neighbours', neighbours: null }],
      ['neighbours', { mix: 'neighbours', neighbours: { busyRate: 0, stuckRate: 5 } }],
    ];
    for (const [part, change] of wrong) {
      expect(() => plain.readStep(JSON.stringify({ ...target, ...change })), part).toThrow(
        `STEP has a wrong ${part}, so k6 sent nothing.`,
      );
    }
  });
});

describe("a Stage G step's k6 options", () => {
  it("ramps the steady traffic by the step's own stages, the duplicates and replays beside it for as long", () => {
    const options = plain.stageGOptions(target);
    expect(plain.stepSeconds(target)).toBe(2100);
    expect(options.tags).toEqual({ test: 'target', step: 'target' });
    expect(options.summaryTrendStats).toEqual(['med', 'p(95)', 'p(99)', 'max', 'count']);
    expect(options.scenarios).toEqual({
      steady: {
        executor: 'ramping-arrival-rate',
        startRate: 0,
        timeUnit: '1s',
        stages: [
          { target: 170, duration: '300s' },
          { target: 170, duration: '1800s' },
        ],
        preAllocatedVUs: 85,
        maxVUs: 425,
        exec: 'steady',
      },
      duplicates: plain.constantRate(2100, 1, 'duplicate', 4),
      replays: plain.constantRate(2100, 1, 'replay', 4),
    });
    expect(options.thresholds).toEqual({
      'http_req_duration{kind:steady}': ['max>=0'],
      'http_reqs{kind:steady}': ['count>=0'],
      'server_errors{kind:steady}': ['count>=0'],
      'rate_limited{kind:steady}': ['count>=0'],
      'failed_answers{kind:steady}': ['count>=0'],
    });
  });

  it('runs the busy and stuck organisations beside the calm ones, each kind timed and counted apart', () => {
    const options = plain.stageGOptions(runOf('neighbours'));
    expect(options.scenarios.busy).toEqual(plain.constantRate(1200, 25, 'busy', 60));
    expect(options.scenarios.stuck).toEqual(plain.constantRate(1200, 5, 'stuck', 60));
    expect(Object.keys(options.thresholds)).toEqual(
      ['http_req_duration', 'http_reqs', 'server_errors', 'rate_limited', 'failed_answers'].flatMap((metric) =>
        ['calm', 'busy', 'stuck'].map((kind) => `${metric}{kind:${kind}}`),
      ),
    );
  });

  it("stops the breaking-point climb itself on any 30 s window's p95 or failed share, after a minute of numbers", () => {
    const breaking = runOf('breaking');
    const { thresholds } = plain.stageGOptions(breaking);
    // 2,400 s of stages: 80 windows, each judged on its own.
    expect(plain.windowCount(breaking)).toBe(80);
    const windowed = Object.keys(thresholds).filter((name) => name.startsWith('window_'));
    expect(windowed).toHaveLength(160);
    for (const window of [0, 41, 79]) {
      expect(thresholds[`window_ms_${String(window)}`]).toEqual([
        { threshold: 'p(95)<500', abortOnFail: true, delayAbortEval: '60s' },
      ]);
      expect(thresholds[`window_failed_${String(window)}`]).toEqual([
        { threshold: 'rate<0.01', abortOnFail: true, delayAbortEval: '60s' },
      ]);
    }
    expect(thresholds.window_ms_80).toBeUndefined();
    // The whole run's p95 is reported, never what stops the climb.
    expect(thresholds['http_req_duration{kind:steady}']).toEqual(['max>=0']);
  });

  it('times a surge by window too, with no threshold: its windows are its own metrics, in the summary without one', () => {
    for (const test of ['spike', 'overload'] as const) {
      const surge = runOf(test);
      expect(Object.keys(plain.stageGOptions(surge).thresholds).filter((name) => name.startsWith('window_'))).toEqual(
        [],
      );
      expect(plain.windowCount(surge)).toBe(test === 'spike' ? 57 : 104);
    }
    expect(plain.windowMetrics(7)).toEqual({
      ms: 'window_ms_7',
      failed: 'window_failed_7',
      refused: 'window_refused_7',
    });
    const summary = plain.stageGSummary(
      runOf('spike'),
      {
        metrics: {
          window_ms_26: { values: { 'p(95)': 300, count: 5100 } },
          window_failed_26: { values: { rate: 0.02 } },
          window_refused_26: { values: { rate: 0.015 } },
        },
        state: { testRunDurationMs: 1_700_000 },
      },
      Date.parse('2026-11-06T10:35:00.000Z'),
    );
    expect(summary).toMatchObject({
      aborted: false,
      windows: [{ window: 26, p95Ms: 300, failedShare: 0.02, refusedShare: 0.015, requests: 5100 }],
    });
    expect(
      plain.stageGSummary(
        target,
        { metrics: {}, state: { testRunDurationMs: 1 } },
        Date.parse('2026-11-06T10:35:00.000Z'),
      ).windows,
    ).toBeNull();
  });

  it("counts a request into its window from setup's start, a short last window counted too", () => {
    const t0 = Date.parse('2026-11-06T10:00:00.000Z');
    expect([0, 29_999, 30_000, 61_000, 2_399_999].map((ms) => plain.windowOf(t0, t0 + ms, 30))).toEqual([
      0, 0, 1, 2, 79,
    ]);
    // A VU's clock a moment behind setup's still counts into the first window.
    expect(plain.windowOf(t0, t0 - 5, 30)).toBe(0);
    expect(plain.windowCount({ ...runOf('breaking'), stages: [{ target: 170, duration: '31s' }] })).toBe(2);
  });
});

describe("the summaries' numbers", () => {
  const trend = { med: 20, 'p(95)': 88.5, 'p(99)': 140, max: 310 };
  const metrics: Metrics = {
    http_reqs: { values: { count: 1000 } },
    created: { values: { count: 900 } },
    server_errors: { values: { count: 2 } },
    checks: { values: { fails: 3 }, thresholds: { 'rate==1': { ok: false } } },
    'http_req_duration{kind:steady}': { values: trend, thresholds: { 'max>=0': { ok: true } } },
    'http_reqs{kind:steady}': { values: { count: 990 } },
    'failed_answers{kind:steady}': { values: { count: 4 } },
    'rate_limited{kind:steady}': { values: { count: 1 } },
  };
  const ended = Date.parse('2026-11-06T10:35:00.000Z');

  it('counts what k6 counted, 0 for what it never did, and lists each threshold as metric and rule', () => {
    expect(plain.countOf(metrics, 'created')).toBe(900);
    expect(plain.countOf(metrics, 'dropped_iterations')).toBe(0);
    expect(plain.thresholdResults(metrics)).toEqual({
      'checks rate==1': false,
      'http_req_duration{kind:steady} max>=0': true,
    });
    expect(plain.kindNumbers(metrics, 'busy')).toEqual({
      requests: 0,
      serverErrors: 0,
      rateLimited: 0,
      failedAnswers: 0,
      p95Ms: 0,
    });
  });

  it('dates the run back from its end by its own duration', () => {
    expect(plain.runWindow({ testRunDurationMs: 2_100_000 }, ended)).toEqual({
      startedAt: '2026-11-06T10:00:00.000Z',
      endedAt: '2026-11-06T10:35:00.000Z',
    });
    const before = Date.now();
    expect(Date.parse(plain.runWindow({ testRunDurationMs: 0 }).endedAt)).toBeGreaterThanOrEqual(before);
  });

  it("sums a step up by its test, label and organisations, its judged traffic's times and each kind's numbers", () => {
    expect(plain.stageGSummary(target, { metrics, state: { testRunDurationMs: 2_101_500 } }, ended)).toEqual({
      test: 'target',
      step: 'target',
      orgs: 10_000,
      requests: 1000,
      created: 900,
      serverErrors: 2,
      rateLimited: 0,
      checksFailed: 3,
      dropped: 0,
      asksMs: { p50: 20, p95: 88.5, p99: 140, max: 310 },
      kinds: { steady: { requests: 990, serverErrors: 0, rateLimited: 1, failedAnswers: 4, p95Ms: 88.5 } },
      aborted: false,
      windows: null,
      thresholds: { 'checks rate==1': false, 'http_req_duration{kind:steady} max>=0': true },
      durationMs: 2_101_500,
      startedAt: '2026-11-06T09:59:58.500Z',
      endedAt: '2026-11-06T10:35:00.000Z',
    });
  });

  it('says a climb its window rule stopped was aborted, and has no times when the judged traffic got no answer', () => {
    const broken = { values: { rate: 0.2 }, thresholds: { 'rate<0.01': { ok: false } } };
    const summary = plain.stageGSummary(
      runOf('breaking'),
      {
        metrics: { http_reqs: { values: { count: 0 } }, window_failed_3: broken },
        state: { testRunDurationMs: 1_000_000 },
      },
      ended,
    );
    expect(summary).toMatchObject({ aborted: true, asksMs: null, checksFailed: 0 });
  });

  it('never calls a run aborted for ending a few ms short, or for a failed rule outside the windows (S175 smoke)', () => {
    const failedOutside = {
      http_reqs: { values: { count: 721 } },
      checks: { values: { fails: 1 }, thresholds: { 'rate==1': { ok: false } } },
    };
    const short = { testRunDurationMs: 119_985 };
    expect(plain.stageGSummary(runOf('smoke'), { metrics: failedOutside, state: short }, ended).aborted).toBe(false);
    const heldWindow = {
      window_failed_0: { values: { rate: 0 }, thresholds: { 'rate<0.01': { ok: true } } },
    };
    expect(plain.stageGSummary(runOf('breaking'), { metrics: heldWindow, state: short }, ended).aborted).toBe(false);
  });

  it("gives a climb's p95 and failed share window by window, for the windows that saw an answer", () => {
    const window = (n: number, p95: number, failed?: number): Metrics => ({
      [`window_ms_${String(n)}`]: { values: { 'p(95)': p95 } },
      ...(failed === undefined ? {} : { [`window_failed_${String(n)}`]: { values: { rate: failed } } }),
    });
    const summary = plain.stageGSummary(
      runOf('breaking'),
      {
        metrics: { ...window(0, 40, 0), ...window(1, 75), ...window(3, 620, 0.002) },
        state: { testRunDurationMs: 130_000 },
      },
      ended,
    );
    expect(summary.windows).toEqual([
      { window: 0, p95Ms: 40, failedShare: 0, refusedShare: 0, requests: 0 },
      { window: 1, p95Ms: 75, failedShare: 0, refusedShare: 0, requests: 0 },
      { window: 3, p95Ms: 620, failedShare: 0.002, refusedShare: 0, requests: 0 },
    ]);
  });
});
