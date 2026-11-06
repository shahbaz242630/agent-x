// One step of a Stage G load test (4D2e, PL-62, PL-63), as k6 runs it against
// the API. The runner hands the step in STEP, as stageg.ts's stepRun makes it:
// its stages for the steady traffic (k6's ramping-arrival-rate), its VUs, any
// abort rule (the breaking-point climb) and the neighbours' rates. Nothing
// here works a shape out: stageg.ts is the one source, checked on arrival.
// Beside the steady traffic, as in PL-38's phases (money-paths.k6.js), with
// the same requests and counts (traffic.k6.js):
// - duplicates: an order asked for twice under two keys, the second denied
// - replays: a request sent twice under one key, answered with the same one
// - for the neighbours test, a busy organisation and a stuck one beside the
//   calm organisations, which are then the traffic the step is judged by.
// Every metric is tagged with the test and the step (plain.k6.js). The
// summary (plain.k6.js's stageGSummary) is one JSON line on stdout
// (load.stageg_summary), as the jobs keep no files; stageg.ts's judgeStep
// says whether the step passed.
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';
import { Rate, Trend } from 'k6/metrics';

import {
  judgedKind,
  readStep,
  stageGOptions,
  stageGSummary,
  windowCount,
  windowMetrics,
  windowOf,
} from './plain.k6.js';
import {
  anyOf,
  ask,
  counted,
  ofKind,
  scattered,
  sendDuplicate,
  sendReplay,
  sendSteady,
  steadyAmount,
} from './traffic.k6.js';

const STEP = readStep(__ENV.STEP);
const TRAFFIC = judgedKind(STEP);
const NEIGHBOURS = STEP.neighbours !== null;

const SEED = __ENV.SEED ?? '/out/seed.json';
/** One kind's agents, read from the seed once and shared by every VU: thousands of VUs never each parse it. */
const sharedAgents = (kind) => new SharedArray(kind, () => ofKind(JSON.parse(open(SEED)).agents, kind));
const steadyAgents = sharedAgents(NEIGHBOURS ? 'neighbour-calm' : 'ample');
const busyAgents = NEIGHBOURS ? sharedAgents('neighbour-busy') : [];
const stuckAgents = NEIGHBOURS ? sharedAgents('neighbour-stuck') : [];
const missing = [
  ['the steady traffic', steadyAgents],
  ...(NEIGHBOURS
    ? [
        ['the busy organisation', busyAgents],
        ['the stuck organisation', stuckAgents],
      ]
    : []),
].find(([, list]) => list.length === 0);
if (missing !== undefined) {
  throw new Error(`The seed has no agent for ${missing[0]}, so k6 sent nothing. Seed the step's organisations first.`);
}

export const options = stageGOptions(STEP);

/**
 * One name for this run, shared by every VU: a re-run of a step after a fix
 * asks for new orders, never ones its first run already made (they would be denied as the same order).
 */
export function setup() {
  const t0 = Date.now();
  return { run: t0.toString(36), t0 };
}

const orderOf = ({ run }, letter, n) => `G-${STEP.label}-${run}-${letter}-${n}`;

/**
 * A windowed step's metrics, one pair a window (plain.k6.js's windowMetrics):
 * made here in the init stage, as k6 makes every metric. A climb's stop it;
 * a surge's show when latency came back.
 */
const WINDOWS =
  STEP.windowSeconds === null
    ? null
    : Array.from({ length: windowCount(STEP) }, (_, window) => {
        const { ms, failed } = windowMetrics(window);
        return { ms: new Trend(ms, true), failed: new Rate(failed) };
      });

/** The steady (or calm) traffic: round the agents, so every active organisation sends, each round its suppliers. */
export function steady(data) {
  const n = exec.scenario.iterationInTest;
  // Its window from when it was sent; past the last (k6's graceful stop) it counts in none.
  const window = WINDOWS?.[windowOf(data.t0, Date.now(), STEP.windowSeconds)];
  const answer = sendSteady(steadyAgents[n % steadyAgents.length], orderOf(data, 'S', n), n, n, TRAFFIC);
  if (window === undefined) return;
  window.ms.add(answer.timings.duration);
  // As k6's http_req_failed: anything but a 2xx or 3xx answer, a timeout's status 0 included.
  window.failed.add(answer.status < 200 || answer.status >= 400);
}

export function duplicate(data) {
  const n = exec.scenario.iterationInTest;
  sendDuplicate(steadyAgents[n % steadyAgents.length], orderOf(data, 'D', n), n, TRAFFIC);
}

export function replay(data) {
  const n = exec.scenario.iterationInTest;
  sendReplay(steadyAgents[n % steadyAgents.length], orderOf(data, 'R', n), n, TRAFFIC);
}

/** The busy organisation: its agents picked at random, its suppliers shared, as PL-38's phase 5. */
export function busy(data) {
  const n = exec.scenario.iterationInTest;
  sendSteady(anyOf(busyAgents), orderOf(data, 'B', n), n, scattered(n), 'busy');
}

/** The stuck organisation: what it is answered is the point, so nothing is checked of it. */
export function stuck(data) {
  const n = exec.scenario.iterationInTest;
  const order = orderOf(data, 'K', n);
  counted(ask(anyOf(stuckAgents), order, order, steadyAmount(n), scattered(n), 'stuck'), true, 'stuck');
}

/** The step's numbers as one JSON line, and a line for whoever watches. */
export function handleSummary(data) {
  const result = stageGSummary(STEP, data);
  const p95 = result.asksMs === null ? 'no answers' : `p95 ${result.asksMs.p95.toFixed(1)} ms`;
  return {
    stdout:
      `Stage G ${STEP.test} ${STEP.label}: ${result.requests} requests, ${result.created} new, ${p95}\n` +
      `${JSON.stringify({ event: 'load.stageg_summary', ...result })}\n`,
  };
}
