// The k6 options both load scripts build (money-paths.k6.js, stage-g.k6.js),
// importing nothing of k6's, so Vitest loads this file as k6 does.

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
