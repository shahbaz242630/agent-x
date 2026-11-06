// The traffic both load scripts send, as k6 runs it: money-paths.k6.js (PL-38's
// phases) and stage-g.k6.js (Stage G's steps). Asking, counting the answers,
// the orders' amounts and suppliers, and the summary pieces both read back.
// Kept in one place so the two scripts send the same requests and count them
// the same way: a Stage G step and a PL-38 phase are then comparable.
import { check } from 'k6';
import http from 'k6/http';
import { Counter } from 'k6/metrics';

const API = __ENV.API ?? 'http://api:8080';

const created = new Counter('created');
const serverErrors = new Counter('server_errors');
const rateLimited = new Counter('rate_limited');

/** The seeded agents of one kind, as the seed's file names them. */
export const ofKind = (agents, kind) => agents.filter((agent) => agent.kind === kind);

/**
 * A supplier number scattered from `n`, so nothing lines a crowd's agents and
 * suppliers up. From `n`, never at random: an order's two asks must name the same supplier.
 */
export const scattered = (n) => (n * 2654435761) >>> 8;

/** The `n`th steady order's amount: AED 1 to 9, so about half are allowed and half wait for approval (above AED 5). */
export const steadyAmount = (n) => 100 + ((n * 37) % 801);

export const anyOf = (list) => list[Math.floor(Math.random() * list.length)];

export const decided = (answer) => answer.status === 201;

/** The agent asks to pay its `supplierN`th supplier `amountMinor` fils for the order, timed as `kind`. */
export function ask(agent, key, orderReference, amountMinor, supplierN, kind) {
  const body = {
    amountMinor,
    currency: 'AED',
    supplierId: agent.supplierIds[supplierN % agent.supplierIds.length],
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
export function counted(answer, isNew, kind) {
  if (answer.status >= 500) serverErrors.add(1, { kind });
  if (answer.status === 429) rateLimited.add(1, { kind });
  if (answer.status === 201 && isNew) created.add(1);
  return answer;
}

/** One steady order: asked once under its own reference as key, and expected decided. */
export function sendSteady(agent, order, n, supplierN, kind) {
  const answer = counted(ask(agent, order, order, steadyAmount(n), supplierN, kind), true, kind);
  check(answer, { 'decided (201)': decided });
}

/** An order asked for twice under two keys: the second must be denied as the same order. */
export function sendDuplicate(agent, order, supplierN, kind) {
  const first = counted(ask(agent, `${order}-a`, order, 300, supplierN, kind), true, kind);
  const second = counted(ask(agent, `${order}-b`, order, 300, supplierN, kind), true, kind);
  check(first, { 'decided (201)': decided });
  check(second, { 'the same order again denied': (r) => decided(r) && r.json('status') === 'DENIED' });
}

/** A request sent twice under one key: the second must be answered with the same request. */
export function sendReplay(agent, order, supplierN, kind) {
  const first = counted(ask(agent, order, order, 200, supplierN, kind), true, kind);
  // A first ask refused as busy made nothing, so the same key's second is the one that makes it (phase 5, S166).
  const again = counted(ask(agent, order, order, 200, supplierN, kind), first.status !== 201, kind);
  check(first, { 'decided (201)': decided });
  check(again, { 'replayed: the same request': (r) => decided(r) && r.json('id') === first.json('id') });
}

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
export function runWindow(state) {
  const endedAt = Date.now();
  return {
    startedAt: new Date(endedAt - state.testRunDurationMs).toISOString(),
    endedAt: new Date(endedAt).toISOString(),
  };
}
