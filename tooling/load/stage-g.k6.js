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
import exec from 'k6/execution';

import { judgedKind, readStep, stageGOptions, stageGSummary } from './plain.k6.js';
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

const { agents } = JSON.parse(open(__ENV.SEED ?? '/out/seed.json'));
const steadyAgents = ofKind(agents, NEIGHBOURS ? 'neighbour-calm' : 'ample');
const busyAgents = ofKind(agents, 'neighbour-busy');
const stuckAgents = ofKind(agents, 'neighbour-stuck');
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
  return { run: Date.now().toString(36) };
}

const orderOf = ({ run }, letter, n) => `G-${STEP.label}-${run}-${letter}-${n}`;

/** The steady (or calm) traffic: round the agents, so every active organisation sends, each round its suppliers. */
export function steady(data) {
  const n = exec.scenario.iterationInTest;
  sendSteady(steadyAgents[n % steadyAgents.length], orderOf(data, 'S', n), n, n, TRAFFIC);
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
