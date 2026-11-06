// What both load scripts (money-paths.k6.js, stage-g.k6.js) share that needs
// nothing of k6's: their scenarios and thresholds, Stage G's step, and the
// numbers their summaries read. It imports nothing, so Vitest loads it as k6 does.

/** A scenario sending `rate` iterations of `run` a second for `seconds`, `vus` ready and five times that at most. */
export const constantRate = (seconds, rate, run, vus) => ({
  executor: 'constant-arrival-rate',
  rate,
  timeUnit: '1s',
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

const STEP_FIELDS = ['test', 'label', 'orgs', 'mix', 'startRate', 'stages', 'vus', 'abort', 'neighbours'];

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
      (hasFields(step.abort, ['p95Ms', 'errorShare']) &&
        isPositive(step.abort.p95Ms) &&
        isPositive(step.abort.errorShare) &&
        step.abort.errorShare < 1),
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
  const judged = judgedKind(step);
  const kinds = kindsOf(step);
  return {
    summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
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
      duplicates: constantRate(seconds, 1, 'duplicate', 4),
      replays: constantRate(seconds, 1, 'replay', 4),
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
      ...(step.abort === null ? {} : abortThresholds(judged, step.abort)),
    },
  };
}

/** A minute of numbers before a climb may stop itself, so its first few slow answers can't. */
const ABORT_AFTER = '60s';

/** The breaking-point climb stops itself once the judged traffic's p95 or failed share passes its rule. */
const abortThresholds = (judged, { p95Ms, errorShare }) => ({
  [`http_req_duration{kind:${judged}}`]: [
    { threshold: `p(95)<${p95Ms}`, abortOnFail: true, delayAbortEval: ABORT_AFTER },
  ],
  [`http_req_failed{kind:${judged}}`]: [
    { threshold: `rate<${errorShare}`, abortOnFail: true, delayAbortEval: ABORT_AFTER },
  ],
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
    // A climb its abort rule stopped ran short of its stages: the runner names its breaking rate from durationMs.
    aborted: state.testRunDurationMs < stepSeconds(step) * 1000,
    thresholds: thresholdResults(metrics),
    durationMs: state.testRunDurationMs,
    ...runWindow(state, endedAt),
  };
}
