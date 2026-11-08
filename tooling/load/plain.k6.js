// What both load scripts (money-paths.k6.js, stage-g.k6.js) share that needs
// nothing of k6's: their scenarios and thresholds, Stage G's step, and the
// numbers their summaries read. It imports nothing, so Vitest loads it as k6 does.

/** A scenario sending `rate` iterations of `run` every `unitSeconds` for `seconds`, `vus` ready and five times that at most. */
export const constantRate = (seconds, rate, run, vus, unitSeconds = 1) => ({
  executor: 'constant-arrival-rate',
  rate,
  timeUnit: `${unitSeconds}s`,
  duration: `${seconds}s`,
  preAllocatedVUs: vus,
  maxVUs: vus * 5,
  exec: run,
});

/** No limit: named so k6 times and counts each kind apart, as it does only a metric a threshold names. */
export const namedOnly = (kinds, metric, rule) =>
  Object.fromEntries(kinds.map((kind) => [`${metric}{kind:${kind}}`, [rule]]));

// Stage G's one step (stage-g.k6.js), as the runner hands it from stageg.ts's
// stepRun in STEP: checked here, never worked out here, so the shapes have one source.

/** The traffic each mix times and counts apart: the first is the one a step is judged by. */
const KINDS = { steady: ['steady'], neighbours: ['calm', 'busy', 'stuck'] };

const STEP_FIELDS = [
  'test',
  'label',
  'orgs',
  'mix',
  'startRate',
  'stages',
  'vus',
  'abort',
  'windowSeconds',
  'neighbours',
  'extrasEverySeconds',
];

/** Lowercase words and dashes, short: it goes into every order reference (100 characters at most). */
const isLabel = (value) => typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,39}$/.test(value);
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const hasFields = (value, fields) => isObject(value) && Object.keys(value).sort().join() === [...fields].sort().join();
const isRate = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const isPositive = (value) => isRate(value) && value > 0;
const isWhole = (value) => Number.isInteger(value) && value > 0;
const isStage = (stage) =>
  hasFields(stage, ['target', 'duration']) && isRate(stage.target) && /^[1-9]\d{0,5}s$/.test(stage.duration);

/** Each part of a step, and whether it is as stepRun makes it. */
const STEP_PARTS = [
  ['test or label', (step) => isLabel(step.test) && isLabel(step.label)],
  ['organisations', (step) => isWhole(step.orgs)],
  ['mix', (step) => Object.hasOwn(KINDS, step.mix)],
  [
    'stages',
    (step) =>
      isRate(step.startRate) && Array.isArray(step.stages) && step.stages.length > 0 && step.stages.every(isStage),
  ],
  [
    'VUs',
    (step) =>
      hasFields(step.vus, ['pre', 'max']) &&
      isWhole(step.vus.pre) &&
      isWhole(step.vus.max) &&
      step.vus.pre <= step.vus.max,
  ],
  [
    'abort rule',
    (step) =>
      step.abort === null ||
      (hasFields(step.abort, ['p95Ms', 'errorShare', 'windowSeconds', 'fromSeconds']) &&
        isPositive(step.abort.p95Ms) &&
        Number.isInteger(step.abort.fromSeconds) &&
        step.abort.fromSeconds >= 0 &&
        isWhole(step.abort.windowSeconds) &&
        isPositive(step.abort.errorShare) &&
        step.abort.errorShare < 1),
  ],
  [
    'windows',
    (step) =>
      (step.windowSeconds === null || isWhole(step.windowSeconds)) &&
      (step.abort === null || step.abort.windowSeconds === step.windowSeconds),
  ],
  [
    'neighbours',
    (step) =>
      step.mix === 'neighbours'
        ? hasFields(step.neighbours, ['busyRate', 'stuckRate']) &&
          isPositive(step.neighbours.busyRate) &&
          isPositive(step.neighbours.stuckRate)
        : step.neighbours === null,
  ],
  ['extras', (step) => isWhole(step.extrasEverySeconds)],
];

/** STEP read and checked, or a refusal saying what is wrong with it: k6 then sends nothing. */
export function readStep(text) {
  const refuse = (what) => {
    throw new Error(
      `STEP ${what}, so k6 sent nothing. Pass one step of a Stage G profile as JSON, as stageg.ts's stepRun makes it.`,
    );
  };
  if (text === undefined || text === '') refuse('is not set');
  let step;
  try {
    step = JSON.parse(text);
  } catch {
    refuse('is not JSON');
  }
  if (!hasFields(step, STEP_FIELDS)) refuse(`must have exactly these fields: ${STEP_FIELDS.join(', ')}`);
  const wrong = STEP_PARTS.find(([, isRight]) => !isRight(step));
  if (wrong !== undefined) refuse(`has a wrong ${wrong[0]}`);
  return step;
}

/** The kind a step's traffic is judged by: the steady traffic, or the calm organisations beside the neighbours. */
export const judgedKind = (step) => KINDS[step.mix][0];

/** The kinds a step times and counts apart. */
export const kindsOf = (step) => KINDS[step.mix];

/** How long a step's traffic runs, in seconds. */
export const stepSeconds = (step) => step.stages.reduce((sum, stage) => sum + Number.parseInt(stage.duration, 10), 0);

/** A step's k6 options: its stages for the judged traffic, the duplicates, replays and any neighbours beside them. */
export function stageGOptions(step) {
  const seconds = stepSeconds(step);
  const kinds = kindsOf(step);
  return {
    // `count` for a window's answers, so its shares weigh as much as it carried.
    summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max', 'count'],
    // Every metric carries its step, so a step's numbers are never another's.
    tags: { test: step.test, step: step.label },
    scenarios: {
      steady: {
        executor: 'ramping-arrival-rate',
        startRate: step.startRate,
        timeUnit: '1s',
        stages: step.stages,
        preAllocatedVUs: step.vus.pre,
        maxVUs: step.vus.max,
        exec: 'steady',
      },
      duplicates: constantRate(seconds, 1, 'duplicate', 4, step.extrasEverySeconds),
      replays: constantRate(seconds, 1, 'replay', 4, step.extrasEverySeconds),
      ...(step.neighbours === null
        ? {}
        : {
            busy: constantRate(seconds, step.neighbours.busyRate, 'busy', 60),
            // Each can wait many seconds on the held lock, or for a free connection: room for all of them.
            stuck: constantRate(seconds, step.neighbours.stuckRate, 'stuck', 60),
          }),
    },
    thresholds: {
      ...namedOnly(kinds, 'http_req_duration', 'max>=0'),
      ...namedOnly(kinds, 'http_reqs', 'count>=0'),
      ...namedOnly(kinds, 'server_errors', 'count>=0'),
      ...namedOnly(kinds, 'rate_limited', 'count>=0'),
      ...namedOnly(kinds, 'failed_answers', 'count>=0'),
      ...(step.abort === null ? {} : abortThresholds(step)),
    },
  };
}

/** A minute of numbers before a climb may stop itself, so its first few slow answers can't. */
const ABORT_AFTER = '60s';

/**
 * Which window of a step a request falls in, counted from `t0` (setup's):
 * judged window by window, a knee or a recovery shows in its own window,
 * where the whole run's p95 would hide it under every other request.
 */
export const windowOf = (t0, now, windowSeconds) => Math.max(0, Math.floor((now - t0) / (windowSeconds * 1000)));

/** How many windows a windowed step's stages span, the last one maybe short. */
export const windowCount = (step) => Math.ceil(stepSeconds(step) / step.windowSeconds);

/**
 * The judged traffic's metrics of one window, stage-g.k6.js's own: a custom
 * metric is in the summary with no threshold, where a tagged one is there only
 * if a threshold names it, so only a climb's windows carry thresholds.
 */
export const windowMetrics = (window) => ({
  ms: `window_ms_${window}`,
  failed: `window_failed_${window}`,
  refused: `window_refused_${window}`,
});

const windows = (step) => Array.from({ length: windowCount(step) }, (_, window) => window);

/**
 * The breaking-point climb stops itself in the first window whose p95 or failed share passes its rule, counted from
 * the climb's own start: the ramp and the hold before it carry no threshold (stageg.ts AbortRule.fromSeconds).
 */
const abortThresholds = (step) => {
  const { p95Ms, errorShare, fromSeconds } = step.abort;
  const stop = (threshold) => [{ threshold, abortOnFail: true, delayAbortEval: ABORT_AFTER }];
  return Object.fromEntries(
    windows(step)
      .filter((window) => window * step.windowSeconds >= fromSeconds)
      .flatMap((window) => {
        const { ms, failed } = windowMetrics(window);
        return [
          [ms, stop(`p(95)<${p95Ms}`)],
          [failed, stop(`rate<${errorShare}`)],
        ];
      }),
  );
};

/** Each window's p95 and failed share, for the windows that saw an answer: a climb's breaking rate, a surge's recovery. */
const windowNumbers = (step, metrics) =>
  windows(step).flatMap((window) => {
    const { ms, failed, refused } = windowMetrics(window);
    const times = metrics[ms]?.values;
    if (times === undefined) return [];
    return [
      {
        window,
        p95Ms: times['p(95)'],
        failedShare: metrics[failed]?.values.rate ?? 0,
        // 429s apart from the rest: a surge means to cause them, and only during the surge.
        refusedShare: metrics[refused]?.values.rate ?? 0,
        requests: times.count ?? 0,
      },
    ];
  });

/** A count k6 summed up, 0 when nothing was counted. */
export const countOf = (metrics, name) => metrics[name]?.values.count ?? 0;

/** Each threshold, as `metric rule`, and whether it held. */
export const thresholdResults = (metrics) =>
  Object.fromEntries(
    Object.entries(metrics).flatMap(([name, metric]) =>
      Object.entries(metric.thresholds ?? {}).map(([rule, result]) => [`${name} ${rule}`, result.ok]),
    ),
  );

/** A timed kind's milliseconds, as the report reads them (summaryTrendStats names these four). */
export const trendMs = (values) => ({ p50: values.med, p95: values['p(95)'], p99: values['p(99)'], max: values.max });

/** One kind's numbers, as the report sets them side by side. */
export function kindNumbers(metrics, kind) {
  const times = metrics[`http_req_duration{kind:${kind}}`]?.values;
  const count = (name) => countOf(metrics, `${name}{kind:${kind}}`);
  return {
    requests: count('http_reqs'),
    serverErrors: count('server_errors'),
    rateLimited: count('rate_limited'),
    failedAnswers: count('failed_answers'),
    p95Ms: times?.['p(95)'] ?? 0,
  };
}

/** When a run started and ended, from k6's own duration, as the report finds its log lines. */
export function runWindow(state, endedAt = Date.now()) {
  return {
    startedAt: new Date(endedAt - state.testRunDurationMs).toISOString(),
    endedAt: new Date(endedAt).toISOString(),
  };
}

/** Whether any window's p95 or failed-share rule failed, which is what stops a climb (abortOnFail). */
const windowRuleBroken = (metrics) =>
  Object.entries(metrics).some(
    ([name, metric]) => name.startsWith('window_') && Object.values(metric.thresholds ?? {}).some(({ ok }) => !ok),
  );

/** A Stage G step's numbers, as stage-g.k6.js prints them (load.stageg_summary) for the runner and the report. */
export function stageGSummary(step, { metrics, state }, endedAt = Date.now()) {
  const judged = metrics[`http_req_duration{kind:${judgedKind(step)}}`]?.values;
  return {
    test: step.test,
    step: step.label,
    orgs: step.orgs,
    requests: countOf(metrics, 'http_reqs'),
    created: countOf(metrics, 'created'),
    serverErrors: countOf(metrics, 'server_errors'),
    rateLimited: countOf(metrics, 'rate_limited'),
    checksFailed: metrics.checks?.values.fails ?? 0,
    dropped: countOf(metrics, 'dropped_iterations'),
    asksMs: judged === undefined ? null : trendMs(judged),
    kinds: Object.fromEntries(kindsOf(step).map((kind) => [kind, kindNumbers(metrics, kind)])),
    // Only a climb's own window rule stops a run: k6 can end a few ms short of its stages, which is no abort (S175).
    aborted: step.abort !== null && windowRuleBroken(metrics),
    windows: step.windowSeconds === null ? null : windowNumbers(step, metrics),
    thresholds: thresholdResults(metrics),
    durationMs: state.testRunDurationMs,
    ...runWindow(state, endedAt),
  };
}
