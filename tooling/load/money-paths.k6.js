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
// Phase 5 (4D2d, PL-63) asks whether one organisation's trouble reaches another:
// ten calm organisations send what the steady traffic sends (kind:calm), beside
// a busy organisation sending 25 a second on three shared suppliers (kind:busy)
// and a stuck one sending 5 a second with two of its three suppliers held
// locked by the runner for the phase (kind:stuck). Nothing in it fails the run
// yet: the report sets the calm ones' numbers beside the steady traffic's.
// Every other request must be answered 201, quickly, never 5xx or 429. k6's own
// result goes to /out for the runner, which checks the database and the log.
// On Azure (D2c) the run's job names the API's internal address, the seed's
// file and the results folder (API, SEED, OUT), and the summary's JSON line
// on stdout is how the result reaches the report: the job keeps no files.
// SMOKE=1 (load.ts run --smoke, the wiring run) sends the same kinds for 20
// seconds at 5 a second, the spike at 5 seconds: it proves the run is wired,
// and measures nothing.
// The requests, how they are counted and the scenarios' shapes are shared
// with Stage G's script (stage-g.k6.js): traffic.k6.js and options.k6.js.
import { check } from 'k6';
import exec from 'k6/execution';

import { constantRate, namedOnly } from './options.k6.js';
import {
  anyOf,
  ask,
  countOf,
  counted,
  decided,
  kindNumbers,
  ofKind,
  runWindow,
  scattered,
  sendDuplicate,
  sendReplay,
  sendSteady,
  steadyAmount,
  thresholdResults,
  trendMs,
} from './traffic.k6.js';

const PHASE = __ENV.PHASE;
if (!['1', '2', '3', '4', '5'].includes(PHASE)) throw new Error('PHASE must be 1, 2, 3, 4 or 5');
const CROWD = { 3: 'crowd-own', 4: 'crowd-shared' }[PHASE];
const NEIGHBOURS = PHASE === '5';
const TRAFFIC = NEIGHBOURS ? 'calm' : CROWD === undefined ? 'ask' : 'crowd';
/** The kinds phase 5 times and counts apart. */
const NEIGHBOUR_KINDS = ['calm', 'busy', 'stuck'];

const OUT = __ENV.OUT ?? '/out';
const SMOKE = __ENV.SMOKE === '1';
const SECONDS = SMOKE ? 20 : 120;
const { agents } = JSON.parse(open(__ENV.SEED ?? `${OUT}/seed.json`));
const steadyAgents = ofKind(agents, NEIGHBOURS ? 'neighbour-calm' : (CROWD ?? 'ample'));
const busyAgents = ofKind(agents, 'neighbour-busy');
const stuckAgents = ofKind(agents, 'neighbour-stuck');
const capped = agents.find((agent) => agent.kind === 'capped');

const steadily = (rate, run, vus) => constantRate(SECONDS, rate, run, vus);

/** What fails a run: phase 5's trouble is reported, and doesn't fail it yet (the partner's call, S165). */
const judged = NEIGHBOURS
  ? {
      ...namedOnly(NEIGHBOUR_KINDS, 'http_req_duration', 'max>=0'),
      ...namedOnly(NEIGHBOUR_KINDS, 'http_reqs', 'count>=0'),
      ...namedOnly(NEIGHBOUR_KINDS, 'server_errors', 'count>=0'),
      ...namedOnly(NEIGHBOUR_KINDS, 'rate_limited', 'count>=0'),
    }
  : {
      // The Pilot's request target (PRD §8); a crowd's has none yet: named so k6 times it apart.
      [`http_req_duration{kind:${TRAFFIC}}`]: [CROWD === undefined ? 'p(95)<500' : 'max>=0'],
      // An arrival k6 had no free VU for is a request never sent: the run then sent less than it says. A crowd's
      // is slowness the report's crowd section names (S164: slow, not wrong, doesn't fail a run); its errors still do.
      dropped_iterations: [CROWD === undefined ? 'count==0' : 'count>=0'],
      server_errors: ['count==0'],
      rate_limited: ['count==0'],
      checks: ['rate==1'],
    };

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
    ...(NEIGHBOURS
      ? {
          busy: SMOKE ? steadily(5, 'busy', 12) : steadily(25, 'busy', 60),
          // Each can wait many seconds on the held lock, or for a free connection: room for all of them.
          stuck: SMOKE ? steadily(2, 'stuck', 12) : steadily(5, 'stuck', 60),
        }
      : {}),
  },
  thresholds: {
    ...judged,
    // No target of its own (it queues by design): named so k6 times it apart, as it does only a metric a threshold names.
    'http_req_duration{kind:spike}': ['max>=0'],
  },
};

/**
 * Which supplier the `n`th order goes to: round the three for the steady traffic,
 * scattered from `n` for a crowd, so nothing lines its agents and suppliers up.
 */
const supplierAt = (n) => (CROWD === undefined ? n : scattered(n));

export function steady() {
  const n = exec.scenario.iterationInTest;
  const agent = CROWD === undefined ? steadyAgents[n % steadyAgents.length] : anyOf(steadyAgents);
  sendSteady(agent, `P${PHASE}-S-${n}`, n, supplierAt(n), TRAFFIC);
}

export function duplicate() {
  const n = exec.scenario.iterationInTest;
  sendDuplicate(steadyAgents[n % steadyAgents.length], `P${PHASE}-D-${n}`, supplierAt(n), TRAFFIC);
}

export function replay() {
  const n = exec.scenario.iterationInTest;
  sendReplay(steadyAgents[n % steadyAgents.length], `P${PHASE}-R-${n}`, supplierAt(n), TRAFFIC);
}

export function spike() {
  const n = exec.scenario.iterationInTest;
  const order = `P${PHASE}-X-${n}`;
  const answer = counted(ask(capped, order, order, 400, supplierAt(n), 'spike'), true, 'spike');
  check(answer, { 'decided (201)': decided });
}

/** The busy organisation's traffic: its agents picked at random, its three suppliers shared, as phase 4's. */
export function busy() {
  const n = exec.scenario.iterationInTest;
  sendSteady(anyOf(busyAgents), `P${PHASE}-B-${n}`, n, scattered(n), 'busy');
}

/** The stuck organisation's traffic: what it is answered is the point, so nothing is checked of it. */
export function stuck() {
  const n = exec.scenario.iterationInTest;
  const order = `P${PHASE}-K-${n}`;
  counted(ask(anyOf(stuckAgents), order, order, steadyAmount(n), scattered(n), 'stuck'), true, 'stuck');
}

/** k6's numbers the runner reads, as one small JSON file, and a line for whoever watches. */
export function handleSummary(data) {
  const { metrics, state } = data;
  const asks = metrics[`http_req_duration{kind:${TRAFFIC}}`].values;
  const spike = metrics['http_req_duration{kind:spike}']?.values;
  const result = {
    phase: Number(PHASE),
    requests: countOf(metrics, 'http_reqs'),
    created: countOf(metrics, 'created'),
    serverErrors: countOf(metrics, 'server_errors'),
    rateLimited: countOf(metrics, 'rate_limited'),
    checksFailed: metrics.checks?.values.fails ?? 0,
    dropped: countOf(metrics, 'dropped_iterations'),
    asksMs: trendMs(asks),
    spikeMs: PHASE === '2' && spike !== undefined ? { p50: spike.med, p95: spike['p(95)'], max: spike.max } : null,
    thresholds: thresholdResults(metrics),
    durationMs: state.testRunDurationMs,
    ...(NEIGHBOURS
      ? {
          neighbours: Object.fromEntries(NEIGHBOUR_KINDS.map((kind) => [kind, kindNumbers(metrics, kind)])),
          ...runWindow(state),
        }
      : {}),
  };
  return {
    [`${OUT}/k6-phase-${PHASE}.json`]: JSON.stringify(result),
    stdout:
      `Phase ${PHASE}: ${result.requests} requests, ${result.created} new, p95 ${asks['p(95)'].toFixed(1)} ms\n` +
      `${JSON.stringify({ event: 'load.k6_summary', ...result })}\n`,
  };
}
