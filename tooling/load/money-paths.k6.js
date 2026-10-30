// The money paths under load (Phase 4 D2, PL-38), as k6 runs them against
// the load stack's API, straight to it on the internal network (run.ts). Each
// phase (PHASE=1, then 2 after the API restarts) is two minutes of:
// - steady: 25 requests a second from the ample agents, AED 1 to 9, so about
//   half are allowed and half wait for approval (above AED 5)
// - duplicates: an order asked for twice under two keys, the second denied
// - replays: a request sent twice under one key, answered with the same one
// and, in phase 2, a spike: 50 requests of AED 4 at once from the capped
// agent, whose month (AED 100) stops at 25. They queue on that one month's
// lock by design, so they are timed apart (kind:spike) from the steady
// traffic the request target is for, and reported on their own.
// Phases 3 and 4 (4D2d, S164) send the same steady, duplicate and replay traffic
// from ten agents of one organisation, picked at random, so nothing here keeps
// them apart by the clock: each with three suppliers of its own (3, the chain
// head shared), or all sharing the same three (4, the suppliers' locks shared
// too). No target of their own yet: reported apart, tagged kind:crowd.
// Every request must be answered 201, quickly, never 5xx or 429. k6's own
// result goes to /out for the runner, which checks the database and the log.
// On Azure (D2c) the run's job names the API's internal address, the seed's
// file and the results folder (API, SEED, OUT), and the summary's JSON line
// on stdout is how the result reaches the report: the job keeps no files.
// SMOKE=1 (load.ts run --smoke, the wiring run) sends the same kinds for 20
// seconds at 5 a second, the spike at 5 seconds: it proves the run is wired,
// and measures nothing.
import { check } from 'k6';
import exec from 'k6/execution';
import http from 'k6/http';
import { Counter } from 'k6/metrics';

const PHASE = __ENV.PHASE;
if (!['1', '2', '3', '4'].includes(PHASE)) throw new Error('PHASE must be 1, 2, 3 or 4');
const CROWD = { 3: 'crowd-own', 4: 'crowd-shared' }[PHASE];
const TRAFFIC = CROWD === undefined ? 'ask' : 'crowd';

const API = __ENV.API ?? 'http://api:8080';
const OUT = __ENV.OUT ?? '/out';
const SMOKE = __ENV.SMOKE === '1';
const SECONDS = SMOKE ? 20 : 120;
const { agents } = JSON.parse(open(__ENV.SEED ?? `${OUT}/seed.json`));
const steadyAgents = agents.filter((agent) => agent.kind === (CROWD ?? 'ample'));
const capped = agents.find((agent) => agent.kind === 'capped');

const created = new Counter('created');
const serverErrors = new Counter('server_errors');
const rateLimited = new Counter('rate_limited');

const steadily = (rate, run, vus) => ({
  executor: 'constant-arrival-rate',
  rate,
  timeUnit: '1s',
  duration: `${SECONDS}s`,
  preAllocatedVUs: vus,
  maxVUs: vus * 5,
  exec: run,
});

export const options = {
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    // Enough VUs ready for the spike's ten seconds, when each steady request takes longer: none left unsent.
    steady: SMOKE ? steadily(5, 'steady', 12) : steadily(25, 'steady', 60),
    duplicates: steadily(1, 'duplicate', 4),
    replays: steadily(1, 'replay', 4),
    ...(PHASE === '2'
      ? {
          spike: {
            executor: 'per-vu-iterations',
            vus: 50,
            iterations: 1,
            startTime: SMOKE ? '5s' : '30s',
            exec: 'spike',
          },
        }
      : {}),
  },
  thresholds: {
    // The Pilot's request target (PRD §8); a crowd's has none yet: named so k6 times it apart.
    [`http_req_duration{kind:${TRAFFIC}}`]: [CROWD === undefined ? 'p(95)<500' : 'max>=0'],
    // No target of its own (it queues by design): named so k6 times it apart, as it does only a metric a threshold names.
    'http_req_duration{kind:spike}': ['max>=0'],
    // An arrival k6 had no free VU for is a request never sent: the run then sent less than it says.
    dropped_iterations: ['count==0'],
    server_errors: ['count==0'],
    rate_limited: ['count==0'],
    checks: ['rate==1'],
  },
};

/**
 * Which supplier the `n`th order goes to: round the three for the steady traffic,
 * scattered from `n` for a crowd, so nothing lines its agents and suppliers up.
 * From `n`, never at random: an order's two asks must name the same supplier.
 */
const supplierAt = (n) => (CROWD === undefined ? n : (n * 2654435761) >>> 8);

/** The agent asks to pay its `n`th supplier (round the three) `amountMinor` fils for the order, timed as `kind`. */
function ask(agent, key, orderReference, amountMinor, n, kind = TRAFFIC) {
  const body = {
    amountMinor,
    currency: 'AED',
    supplierId: agent.supplierIds[supplierAt(n) % agent.supplierIds.length],
    fundingSourceId: agent.sourceId,
    orderReference,
    purpose: 'Load test order',
  };
  return http.post(`${API}/v1/spend-requests`, JSON.stringify(body), {
    headers: { authorization: `Bearer ${agent.key}`, 'idempotency-key': key, 'content-type': 'application/json' },
    tags: { kind },
  });
}

/** Counts the answer: a request made (not a replay's answer), a server error, a refusal for rate. */
function counted(answer, isNew) {
  if (answer.status >= 500) serverErrors.add(1);
  if (answer.status === 429) rateLimited.add(1);
  if (answer.status === 201 && isNew) created.add(1);
  return answer;
}

const decided = (answer) => answer.status === 201;

export function steady() {
  const n = exec.scenario.iterationInTest;
  const order = `P${PHASE}-S-${n}`;
  const agent =
    CROWD === undefined
      ? steadyAgents[n % steadyAgents.length]
      : steadyAgents[Math.floor(Math.random() * steadyAgents.length)];
  const answer = counted(ask(agent, order, order, 100 + ((n * 37) % 801), n), true);
  check(answer, { 'decided (201)': decided });
}

export function duplicate() {
  const n = exec.scenario.iterationInTest;
  const agent = steadyAgents[n % steadyAgents.length];
  const order = `P${PHASE}-D-${n}`;
  const first = counted(ask(agent, `${order}-a`, order, 300, n), true);
  const second = counted(ask(agent, `${order}-b`, order, 300, n), true);
  check(first, { 'decided (201)': decided });
  check(second, { 'the same order again denied': (r) => decided(r) && r.json('status') === 'DENIED' });
}

export function replay() {
  const n = exec.scenario.iterationInTest;
  const order = `P${PHASE}-R-${n}`;
  const agent = steadyAgents[n % steadyAgents.length];
  const first = counted(ask(agent, order, order, 200, n), true);
  const again = counted(ask(agent, order, order, 200, n), false);
  check(first, { 'decided (201)': decided });
  check(again, { 'replayed: the same request': (r) => decided(r) && r.json('id') === first.json('id') });
}

export function spike() {
  const order = `P${PHASE}-X-${exec.scenario.iterationInTest}`;
  const answer = counted(ask(capped, order, order, 400, exec.scenario.iterationInTest, 'spike'), true);
  check(answer, { 'decided (201)': decided });
}

/** k6's numbers the runner reads, as one small JSON file, and a line for whoever watches. */
export function handleSummary(data) {
  const { metrics } = data;
  const asks = metrics[`http_req_duration{kind:${TRAFFIC}}`].values;
  const spike = metrics['http_req_duration{kind:spike}']?.values;
  const count = (name) => metrics[name]?.values.count ?? 0;
  const thresholds = Object.fromEntries(
    Object.entries(metrics).flatMap(([name, metric]) =>
      Object.entries(metric.thresholds ?? {}).map(([rule, result]) => [`${name} ${rule}`, result.ok]),
    ),
  );
  const result = {
    phase: Number(PHASE),
    requests: count('http_reqs'),
    created: count('created'),
    serverErrors: count('server_errors'),
    rateLimited: count('rate_limited'),
    checksFailed: metrics.checks.values.fails,
    dropped: count('dropped_iterations'),
    asksMs: { p50: asks.med, p95: asks['p(95)'], p99: asks['p(99)'], max: asks.max },
    spikeMs: PHASE === '2' && spike !== undefined ? { p50: spike.med, p95: spike['p(95)'], max: spike.max } : null,
    thresholds,
  };
  return {
    [`${OUT}/k6-phase-${PHASE}.json`]: JSON.stringify(result),
    stdout:
      `Phase ${PHASE}: ${result.requests} requests, ${result.created} new, p95 ${asks['p(95)'].toFixed(1)} ms\n` +
      `${JSON.stringify({ event: 'load.k6_summary', ...result })}\n`,
  };
}
