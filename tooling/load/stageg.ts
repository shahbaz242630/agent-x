// Stage G's load tests (4D2e, PL-62, PL-63) as data: the research's tests 0-10
// (Documents/Phase-4/Slices/4D2e-StageG-Research-S175.md), each an ordered list
// of steps with its pass rules. One step is one k6 run (stage-g.k6.js): the
// runner hands it the step's own k6 stages from here (stepRun), so the shapes
// live in this file only; k6 runs no TypeScript and only checks what it is given.
import { POLICY_P95_MS } from './plan.ts';

/** The tests in the order the sources run them (smoke first, breaking point last of the climb). */
export const STAGE_G_TESTS = [
  'smoke',
  'orgs',
  'target',
  'rates',
  'spike',
  'neighbours',
  'breaking',
  'overload',
  'soak',
  'past10k',
  'ha',
] as const;

export type StageGTest = (typeof STAGE_G_TESTS)[number];

/** When a breaking-point climb stops itself: the traffic's own p95 or its share of failed answers past these, in any one window. */
interface AbortRule {
  readonly p95Ms: number;
  readonly errorShare: number;
  /** Judged window by window: the whole run's p95 would hide a knee under every faster request before it. */
  readonly windowSeconds: number;
}

type StepShape =
  | { readonly kind: 'ramp-hold' }
  /** One of the soak's one-hour segments, each its own run of the load-step job (STAGE_G_JOB_SECONDS). */
  | { readonly kind: 'soak'; readonly segment: number; readonly segments: number }
  /** After the hold, up to `peakRate` within `riseSeconds`, held, back to the step's rate, held to recover. */
  | {
      readonly kind: 'spike' | 'overload';
      readonly peakRate: number;
      readonly riseSeconds: number;
      readonly peakSeconds: number;
      readonly recoverySeconds: number;
    }
  /** After the hold, a smooth climb to `ceilingRate` over `climbSeconds`, stopped by `abort` first. */
  | {
      readonly kind: 'breaking';
      readonly ceilingRate: number;
      readonly climbSeconds: number;
      readonly abort: AbortRule;
    };

/** One k6 run: ramp from nothing to `rate` a second, hold it, then whatever its shape adds. */
export interface Step {
  readonly label: string;
  /** How many organisations the throwaway database holds for it (the organisations dial). */
  readonly orgs: number;
  readonly rampSeconds: number;
  readonly holdSeconds: number;
  /** The steady traffic's requests a second at the hold (the load dial). */
  readonly rate: number;
  readonly shape: StepShape;
}

/** What a step's measured result must show. A null limit is reported, not judged. */
export interface PassRules {
  /** The decisions' p95 from the API's own log line, at most this. */
  readonly decisionP95Ms: number | null;
  /** Server errors and refusals for rate, as a share of the judged traffic's requests: below this. */
  readonly maxErrorShare: number | null;
  /** Past the breaking point k6 runs out of VUs by design; below it, a request never sent is load the run didn't carry. */
  readonly droppedAllowed: boolean;
  /** The judged traffic's p95 at most this much above the baseline step's. */
  readonly calmMargin: number | null;
  /** The calm organisations are never refused for rate: only the offender is. */
  readonly calmNeverLimited: boolean;
  /** Back to the base load's latency within this many seconds of the surge's end. */
  readonly recoveryWithinSeconds: number | null;
}

export interface Profile {
  readonly test: StageGTest;
  /** steady: one agent an organisation sending the steady traffic; neighbours: calm ones beside a busy and a stuck one. */
  readonly mix: 'steady' | 'neighbours';
  readonly steps: readonly Step[];
  readonly rules: PassRules;
}

/** The request rate the scale plan names for ~10k accounts (Claude's stated assumption, 4D2e-Scale-Plan.md). */
const TARGET_RATE = 170;

/** The organisations the target is set for (partner S167). */
const TARGET_ORGS = 10_000;

/** Past the target: three times the organisations, the target's load (research test 9). */
const PAST_TARGET_ORGS = 30_000;

/** Ramp, don't jump: five minutes to the step's rate (research table). */
const RAMP_SECONDS = 300;

/** "A minimum of 15 minutes at steady state" (AWS). */
const HOLD_SECONDS = 900;

/** A step held 30 minutes (AWS's scalability test), for the target and the 10k organisations step. */
const LONG_HOLD_SECONDS = 1800;

/** The organisations dial (research table): 3,000 added between 1k and 10k, Slack's "not too coarse". */
const ORG_STEPS = [100, 1000, 3000, TARGET_ORGS] as const;

/** The load dial: a quarter, half, one, one and a half and twice the target, 10 minutes each (research table). */
const RATE_STEPS = [43, 85, TARGET_RATE, 255, 340] as const;
const RATE_STEP_HOLD_SECONDS = 600;

/** A tenth of a rate step's hold: inside k6's 5-15% ramp guidance. */
const RATE_STEP_RAMP_SECONDS = 60;

/**
 * The steady traffic for `orgs` organisations at the target's pace for each:
 * its active agents each send about as often as at 10k (S176: 100 organisations
 * at 170/s put 85 a second on each of its 2 agents, a shape no customer has).
 */
const rateFor = (orgs: number): number => Math.max(1, Math.round((TARGET_RATE * orgs) / TARGET_ORGS));

/**
 * The duplicates and replays, one of each a second beside the target's rate:
 * as rare beside a smaller step's traffic, never more often than that (S176's
 * smoke sent them as often as its 2 agents' own traffic).
 */
const extrasEverySeconds = (rate: number): number => Math.max(1, Math.round(TARGET_RATE / rate));

/** The smoke run: the wiring proved at a trickle (research test 0), at 100 organisations' share of the target. */
const SMOKE = { orgs: 100, rate: rateFor(100), holdSeconds: 120 } as const;

/** Steady base load before a surge, for the report to compare the surge and the recovery with. */
const BASE_SECONDS = 300;

/** The spike: three times the target (the top of the table's 2-3×) within 10 s, for 3 minutes, then 15 minutes back at the target. */
const SPIKE = { factor: 3, riseSeconds: 10, peakSeconds: 180, recoverySeconds: 900 } as const;

/** Breaking point: ten times the target is past any knee seen so far; a 30-minute climb is smooth and fits one job. */
const BREAKING = { factor: 10, climbSeconds: 1800 } as const;

/**
 * The climb stops at the Pilot's request target (PRD §8, money-paths.k6.js's p(95)<500) or 1% failed answers,
 * in any 30 s window: about 1% of the climb's 30 minutes, short enough to name the rate, long enough for a p95.
 */
/** The Pilot's request target (PRD §8, money-paths.k6.js's p(95)<500): a request's p95 under this. */
export const REQUEST_P95_MS = 500;

const BREAKING_ABORT: AbortRule = { p95Ms: REQUEST_P95_MS, errorShare: 0.01, windowSeconds: 30 };

/** Overload: half again the measured breaking rate (top of the table's 1.2-1.5×) for 10 minutes, then 30 back at the target. */
const OVERLOAD = { factor: 1.5, riseSeconds: 60, peakSeconds: 600, recoverySeconds: 1800 } as const;

/**
 * The load-step job's limit (decided S175, set by the wiring PR): one step's
 * traffic, the soak's full hour the longest, plus STAGE_G_JOB_MARGIN_SECONDS.
 */
export const STAGE_G_JOB_SECONDS = 4500;

/** What a job spends beside the traffic: starting, k6's gracefulStop, the summary and the checks. */
export const STAGE_G_JOB_MARGIN_SECONDS = 300;

/** The soak: 4 hours, the sources' minimum, as four runs of a full hour's traffic; later segments ramp a minute, the system already warm. */
const SOAK = { segments: 4, segmentSeconds: 3600, laterRampSeconds: 60 } as const;

/** Failed answers below 1% (Azure's example criterion). */
export const MAX_ERROR_SHARE = 0.01;

/** More than 15% off the baseline is worth investigating (AWS). */
const CALM_MARGIN = 0.15;

/** A spike recovers within a minute (AWS: latency back within ~30-60 s). */
const SPIKE_RECOVERY_SECONDS = 60;

/** An overload has queues to drain first: five minutes, stated as the window (Google SRE asks for one). */
const OVERLOAD_RECOVERY_SECONDS = 300;

/** Phase 5's offenders' rates (money-paths.k6.js): a busy organisation at 25 a second, a stuck one at 5. */
const NEIGHBOUR_RATES = { busyRate: 25, stuckRate: 5 } as const;

/** VUs ready for half a second of arrivals at the peak: a request answered in time holds one no longer. */
const VU_SECONDS = 0.5;
const LEAST_VUS = 10;

/** As money-paths.k6.js: five times the ready VUs at most, for the moments answers slow down. */
const VU_HEADROOM = 5;

const TARGET_RULES: PassRules = {
  decisionP95Ms: POLICY_P95_MS,
  maxErrorShare: MAX_ERROR_SHARE,
  droppedAllowed: false,
  calmMargin: null,
  calmNeverLimited: false,
  recoveryWithinSeconds: null,
};

const rampHold = (label: string, orgs: number, holdSeconds: number, rate = TARGET_RATE): Step => ({
  label,
  orgs,
  rampSeconds: RAMP_SECONDS,
  holdSeconds,
  rate,
  shape: { kind: 'ramp-hold' },
});

const atTarget = (test: StageGTest, orgs: number): Profile => ({
  test,
  mix: 'steady',
  steps: [rampHold(test, orgs, LONG_HOLD_SECONDS)],
  rules: TARGET_RULES,
});

/** A surge to `peakRate` from the target's base load: the spike and the overload differ in size and windows only. */
function surge(test: 'spike' | 'overload', peakRate: number, timing: typeof SPIKE | typeof OVERLOAD): Profile {
  const { riseSeconds, peakSeconds, recoverySeconds } = timing;
  return {
    test,
    mix: 'steady',
    steps: [
      {
        ...rampHold(test, TARGET_ORGS, BASE_SECONDS),
        shape: { kind: test, peakRate, riseSeconds, peakSeconds, recoverySeconds },
      },
    ],
    rules: {
      ...TARGET_RULES,
      decisionP95Ms: null,
      maxErrorShare: test === 'spike' ? MAX_ERROR_SHARE : null,
      droppedAllowed: test === 'overload',
      recoveryWithinSeconds: test === 'spike' ? SPIKE_RECOVERY_SECONDS : OVERLOAD_RECOVERY_SECONDS,
    },
  };
}

function soakSegment(segment: number): Step {
  const rampSeconds = segment === 1 ? RAMP_SECONDS : SOAK.laterRampSeconds;
  return {
    ...rampHold(`soak-${String(segment)}`, TARGET_ORGS, SOAK.segmentSeconds - rampSeconds),
    rampSeconds,
    shape: { kind: 'soak', segment, segments: SOAK.segments },
  };
}

const PROFILES: Record<Exclude<StageGTest, 'overload'>, Profile> = {
  smoke: {
    test: 'smoke',
    mix: 'steady',
    steps: [{ label: 'smoke', ...SMOKE, rampSeconds: 0, shape: { kind: 'ramp-hold' } }],
    rules: TARGET_RULES,
  },
  orgs: {
    test: 'orgs',
    mix: 'steady',
    steps: ORG_STEPS.map((orgs) =>
      rampHold(`orgs-${String(orgs)}`, orgs, orgs === TARGET_ORGS ? LONG_HOLD_SECONDS : HOLD_SECONDS, rateFor(orgs)),
    ),
    // The p95 against the first step's is reported, not judged: the steps' rates differ with their organisations
    // (S176), so a 2/s baseline says nothing of 170/s; the decision limit judges each step instead.
    rules: TARGET_RULES,
  },
  target: atTarget('target', TARGET_ORGS),
  rates: {
    test: 'rates',
    mix: 'steady',
    steps: RATE_STEPS.map((rate) => ({
      ...rampHold(`rate-${String(rate)}`, TARGET_ORGS, RATE_STEP_HOLD_SECONDS, rate),
      rampSeconds: RATE_STEP_RAMP_SECONDS,
    })),
    // Finding the knee: latency is reported step by step, not judged; failed or unsent requests still fail a step.
    rules: { ...TARGET_RULES, decisionP95Ms: null },
  },
  spike: surge('spike', TARGET_RATE * SPIKE.factor, SPIKE),
  // One busy and one stuck organisation beside the calm ones. The long chain is seeded (stageg-seed.ts, the first
  // organisation) and loads the background checks; k6 sends nothing as it: that needs a scenario of its own.
  neighbours: {
    test: 'neighbours',
    mix: 'neighbours',
    steps: [rampHold('neighbours', TARGET_ORGS, HOLD_SECONDS)],
    rules: { ...TARGET_RULES, calmMargin: CALM_MARGIN, calmNeverLimited: true },
  },
  breaking: {
    test: 'breaking',
    mix: 'steady',
    steps: [
      {
        ...rampHold('breaking', TARGET_ORGS, BASE_SECONDS),
        shape: {
          kind: 'breaking',
          ceilingRate: TARGET_RATE * BREAKING.factor,
          climbSeconds: BREAKING.climbSeconds,
          abort: BREAKING_ABORT,
        },
      },
    ],
    // It passes by naming what ran out first (the report's): nothing here is judged.
    rules: { ...TARGET_RULES, decisionP95Ms: null, maxErrorShare: null, droppedAllowed: true },
  },
  soak: {
    test: 'soak',
    mix: 'steady',
    steps: Array.from({ length: SOAK.segments }, (_, index) => soakSegment(index + 1)),
    rules: TARGET_RULES,
  },
  past10k: atTarget('past10k', PAST_TARGET_ORGS),
  // The target's run again on zone-redundant HA (PL-64): the difference is the database's, not the traffic's.
  ha: atTarget('ha', TARGET_ORGS),
};

/**
 * A test's profile. The overload is sized from the breaking point the breaking
 * test measured (`breakingRate`, requests a second), so it can't exist before it.
 */
export function stageGProfile(test: StageGTest, breakingRate?: number): Profile {
  if (test !== 'overload') return PROFILES[test];
  if (breakingRate === undefined || !Number.isFinite(breakingRate) || breakingRate <= 0) {
    throw new Error(
      'The overload test is sized from the breaking test\'s measured rate: run "breaking" first and pass its rate.',
    );
  }
  return surge('overload', Math.round(breakingRate * OVERLOAD.factor), OVERLOAD);
}

/** One of k6's `ramping-arrival-rate` stages: reach `target` a second over `duration`. */
interface K6Stage {
  readonly target: number;
  readonly duration: `${number}s`;
}

export interface K6Stages {
  readonly startRate: number;
  readonly stages: readonly K6Stage[];
}

const stage = (target: number, seconds: number): K6Stage => ({ target, duration: `${seconds}s` });

/** A step as k6's `ramping-arrival-rate` runs it: from nothing (or straight at the rate with no ramp), then its shape. */
export function k6Stages(step: Step): K6Stages {
  const { rate, rampSeconds, holdSeconds, shape } = step;
  const opening = [...(rampSeconds > 0 ? [stage(rate, rampSeconds)] : []), stage(rate, holdSeconds)];
  const startRate = rampSeconds > 0 ? 0 : rate;
  switch (shape.kind) {
    case 'ramp-hold':
    case 'soak':
      return { startRate, stages: opening };
    case 'spike':
    case 'overload':
      return {
        startRate,
        stages: [
          ...opening,
          stage(shape.peakRate, shape.riseSeconds),
          stage(shape.peakRate, shape.peakSeconds),
          stage(rate, shape.riseSeconds),
          stage(rate, shape.recoverySeconds),
        ],
      };
    case 'breaking':
      return { startRate, stages: [...opening, stage(shape.ceilingRate, shape.climbSeconds)] };
  }
}

const secondsOf = (stage: K6Stage): number => Number.parseInt(stage.duration, 10);

/** How long a step's traffic runs, in seconds. */
export const stagesSeconds = ({ stages }: K6Stages): number => stages.reduce((sum, each) => sum + secondsOf(each), 0);

/** The rate k6 was asked for `atSeconds` into the run: where a breaking-point climb stopped is its breaking rate. */
export function rateAt({ startRate, stages }: K6Stages, atSeconds: number): number {
  let from = startRate;
  let elapsed = 0;
  for (const each of stages) {
    const length = secondsOf(each);
    if (atSeconds < elapsed + length) return from + ((each.target - from) * (atSeconds - elapsed)) / length;
    from = each.target;
    elapsed += length;
  }
  return from;
}

/** One window of a climb, as stage-g.k6.js's summary gives it (`windows`). */
export interface WindowNumbers {
  readonly window: number;
  readonly p95Ms: number;
  /** Every answer but a 2xx or 3xx, refusals for rate included. */
  readonly failedShare: number;
  /** Refused for rate (429), as a share of the window's answers. */
  readonly refusedShare: number;
  /** The window's answers. */
  readonly requests: number;
}

/**
 * The climb's breaking rate: the rate asked at the start of the first window
 * whose p95 or failed share broke the abort rule (k6's thresholds read them
 * the same way: `p(95)<limit` and `rate<share` hold strictly below), or null
 * if none did and the climb reached its ceiling.
 */
export function breakingRate(stages: K6Stages, abort: AbortRule, windows: readonly WindowNumbers[]): number | null {
  const broke = windows
    .filter(({ p95Ms, failedShare }) => p95Ms >= abort.p95Ms || failedShare >= abort.errorShare)
    .map(({ window }) => window);
  return broke.length === 0 ? null : rateAt(stages, Math.min(...broke) * abort.windowSeconds);
}

/** What the runner hands stage-g.k6.js for one step, as JSON in `STEP`: all k6 needs, nothing it works out itself. */
export interface StepRun extends K6Stages {
  readonly test: StageGTest;
  readonly label: string;
  readonly orgs: number;
  readonly mix: Profile['mix'];
  readonly vus: { readonly pre: number; readonly max: number };
  readonly abort: AbortRule | null;
  /** The judged traffic's window, for a climb's abort rule and a surge's recovery; null for a step timed whole. */
  readonly windowSeconds: number | null;
  readonly neighbours: typeof NEIGHBOUR_RATES | null;
  /** One duplicate and one replay every this many seconds. */
  readonly extrasEverySeconds: number;
}

/** A surge's recovery read window by window: as long as the climb's, so a minute's rule is two windows. */
const RECOVERY_WINDOW_SECONDS = 30;

/** The window a step is timed by, if any. */
function windowSecondsOf({ shape }: Step): number | null {
  if (shape.kind === 'breaking') return shape.abort.windowSeconds;
  return shape.kind === 'spike' || shape.kind === 'overload' ? RECOVERY_WINDOW_SECONDS : null;
}

/** One step of a profile as stage-g.k6.js runs it. */
export function stepRun(profile: Profile, step: Step): StepRun {
  const stages = k6Stages(step);
  const peak = Math.max(stages.startRate, ...stages.stages.map(({ target }) => target));
  const pre = Math.max(LEAST_VUS, Math.ceil(peak * VU_SECONDS));
  return {
    test: profile.test,
    label: step.label,
    orgs: step.orgs,
    mix: profile.mix,
    ...stages,
    vus: { pre, max: pre * VU_HEADROOM },
    abort: step.shape.kind === 'breaking' ? step.shape.abort : null,
    windowSeconds: windowSecondsOf(step),
    neighbours: profile.mix === 'neighbours' ? NEIGHBOUR_RATES : null,
    extrasEverySeconds: extrasEverySeconds(step.rate),
  };
}

/** A step's numbers, of its judged traffic (the steady, or the calm organisations'), as the report gathers them. */
export interface StepMeasured {
  readonly decisionP95Ms: number;
  readonly requests: number;
  readonly serverErrors: number;
  readonly rateLimited: number;
  readonly dropped: number;
  readonly calmP95Ms: number;
  /** Seconds from the surge's end until latency was back to the base load's; null if it never was. */
  readonly recoverySeconds: number | null;
}

export interface StepVerdict {
  readonly passed: boolean;
  readonly failures: readonly string[];
}

type Rule = (rules: PassRules, measured: StepMeasured, baselineP95Ms: number | undefined) => string | undefined;

const ms = (value: number): string => `${value.toFixed(1)} ms`;

const RULES: readonly Rule[] = [
  ({ decisionP95Ms: limit }, { decisionP95Ms }) =>
    limit !== null && decisionP95Ms > limit
      ? `The decisions' p95 was ${ms(decisionP95Ms)}, over the ${ms(limit)} limit.`
      : undefined,
  ({ maxErrorShare }, { requests, serverErrors, rateLimited }) => {
    const share = (serverErrors + rateLimited) / requests;
    return maxErrorShare !== null && share >= maxErrorShare
      ? `${(share * 100).toFixed(2)}% of answers failed (not 2xx: a server error, busy, refused for rate or any other), not below ${String(maxErrorShare * 100)}%.`
      : undefined;
  },
  ({ droppedAllowed }, { dropped }) =>
    !droppedAllowed && dropped > 0
      ? `${String(dropped)} requests were never sent (k6 had no free VU): the step carried less load than it says.`
      : undefined,
  ({ calmNeverLimited }, { rateLimited }) =>
    calmNeverLimited && rateLimited > 0
      ? `The calm organisations were refused for rate ${String(rateLimited)} times: only the offender may be.`
      : undefined,
  ({ calmMargin }, { calmP95Ms }, baseline) => {
    if (calmMargin === null) return undefined;
    if (baseline === undefined) return 'No baseline step was given to compare the p95 with.';
    return calmP95Ms > baseline * (1 + calmMargin)
      ? `The p95 was ${ms(calmP95Ms)}, more than ${String(calmMargin * 100)}% above the baseline step's ${ms(baseline)}.`
      : undefined;
  },
  ({ recoveryWithinSeconds: window }, { recoverySeconds }) => {
    if (window === null) return undefined;
    if (recoverySeconds === null) return "Latency never came back to the base load's after the surge.";
    return recoverySeconds > window
      ? `Latency took ${String(recoverySeconds)} s to come back after the surge, over the ${String(window)} s window.`
      : undefined;
  },
];

/**
 * Whether a step's measured result passes its profile's rules, and each rule it
 * failed in plain words. `baselineP95Ms` is the baseline step's p95 (the first
 * organisations step's, or the target's for the neighbours), where a rule compares.
 */
export function judgeStep(rules: PassRules, measured: StepMeasured, baselineP95Ms?: number): StepVerdict {
  const failures =
    measured.requests > 0
      ? RULES.flatMap((rule) => rule(rules, measured, baselineP95Ms) ?? [])
      : ['The step sent no request, so nothing could be judged.'];
  return { passed: failures.length === 0, failures };
}
