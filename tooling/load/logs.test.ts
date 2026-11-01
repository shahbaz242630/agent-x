import { describe, expect, it } from 'vitest';

import { logFailures, percentile, percentilesOf, summariseLogs, troubleWindowOf } from './logs.ts';

const line = (fields: Record<string, unknown>) => JSON.stringify({ level: 'info', ...fields });
const decided = (durationMs: number) => line({ event: 'spend_request.decided', durationMs });
const checked = (requests: number, mismatched = 0, tampered = 0) =>
  line({ event: 'holdings_check.passed', requests, mismatched, tampered });
const NO_PARTS = {
  connectionWaitP95: 0,
  turnWaitP95: 0,
  supplierTurnWaitP95: 0,
  gateWaitP95: 0,
  tripsP50: 0,
  decisionRowsP95: 0,
  headLockP95: 0,
  busyRefusals: 0,
};
const NO_NEIGHBOUR = { count: 0, p50: 0, p95: 0, p99: 0, max: 0, ...NO_PARTS };

describe('percentiles', () => {
  it('takes the nearest rank, and 0 of nothing', () => {
    const sorted = Array.from({ length: 100 }, (_, n) => n + 1);
    expect(percentile(sorted, 50)).toBe(50);
    expect(percentile(sorted, 95)).toBe(95);
    expect(percentile(sorted, 100)).toBe(100);
    expect(percentile([7], 99)).toBe(7);
    expect(percentile([], 95)).toBe(0);
  });

  it('sorts what it is given', () => {
    expect(percentilesOf([30, 10, 20])).toEqual({ count: 3, p50: 20, p95: 30, p99: 30, max: 30 });
  });
});

describe('the API’s log after a load run', () => {
  it('reads each decision’s supplier and gate waits, and counts those turned away, each with its organisation', () => {
    const decidedIn = (orgId: string, waits: Record<string, number>) =>
      line({ event: 'spend_request.decided', orgId, durationMs: 10, ...waits });
    const refusal = (event: string, orgId: string) => JSON.stringify({ level: 'warn', event, orgId });
    const summary = summariseLogs(
      [
        decidedIn('steady', { supplierTurnWaitMs: 7, gateWaitMs: 9 }),
        decidedIn('busy', { supplierTurnWaitMs: 70, gateWaitMs: 90 }),
        refusal('spend_request.agent_busy', 'busy'),
        refusal('spend_request.supplier_busy', 'busy'),
        refusal('spend_request.organisation_busy', 'busy'),
        refusal('db.organisation_busy', 'busy'),
        refusal('spend_request.platform_full', 'calm'),
        refusal('spend_request.supplier_busy', 'steady'),
        // Not a refusal, and with no organisation it counts for no one.
        refusal('http.request_failed', 'busy'),
      ].join('\n'),
      { busy: new Set(['busy']), calm: new Set(['calm']) },
    );
    expect(summary.steadyParts).toMatchObject({ supplierTurnWaitP95: 7, gateWaitP95: 9, busyRefusals: 1 });
    expect(summary.neighbours.busy).toMatchObject({ supplierTurnWaitP95: 70, gateWaitP95: 90, busyRefusals: 4 });
    expect(summary.neighbours.calm).toMatchObject({ count: 0, busyRefusals: 1 });
    expect(summary.platformFull).toBe(1);
  });

  it('times each crowd’s decisions apart, and counts only the steady traffic’s allowed', () => {
    const inOrg = (orgId: string, durationMs: number, decision: string) =>
      line({ event: 'spend_request.decided', orgId, durationMs, decision });
    const summary = summariseLogs(
      [
        inOrg('steady', 10, 'ALLOW'),
        inOrg('steady', 11, 'REQUIRE_APPROVAL'),
        inOrg('own', 20, 'ALLOW'),
        inOrg('shared', 30, 'ALLOW'),
        inOrg('spike', 40, 'ALLOW'),
      ].join('\n'),
      { spike: new Set(['spike']), crowdOwn: new Set(['own']), crowdShared: new Set(['shared']) },
    );
    expect(summary.decisions.count).toBe(2);
    expect(summary.crowdOwnDecisions).toEqual({ count: 1, p50: 20, p95: 20, p99: 20, max: 20, ...NO_PARTS });
    expect(summary.crowdSharedDecisions).toEqual({ count: 1, p50: 30, p95: 30, p99: 30, max: 30, ...NO_PARTS });
    expect(summary.spikeDecisions.count).toBe(1);
    expect(summary.allowed).toBe(1);
  });

  it('fails a run that allowed too few to measure both paths (S164), never a run too small to say', () => {
    const decisions = (allowed: number, rest: number) =>
      [
        checked(3),
        ...Array.from({ length: allowed }, () =>
          line({ event: 'spend_request.decided', durationMs: 1, decision: 'ALLOW' }),
        ),
        ...Array.from({ length: rest }, () =>
          line({ event: 'spend_request.decided', durationMs: 1, decision: 'DENY' }),
        ),
      ].join('\n');
    expect(logFailures(summariseLogs(decisions(29, 71)), 100, 150)).toEqual([
      'Only 29 of 100 steady decisions allowed the request at once: the run should allow about half, or it measures one path only.',
    ]);
    expect(logFailures(summariseLogs(decisions(30, 70)), 100, 150)).toEqual([]);
    expect(logFailures(summariseLogs(decisions(0, 99)), 99, 150)).toEqual([]);
  });

  it('counts every kind of decision against those the run made', () => {
    const inOrg = (orgId: string) => line({ event: 'spend_request.decided', orgId, durationMs: 1, decision: 'ALLOW' });
    const logs = summariseLogs([checked(3), inOrg('a'), inOrg('own'), inOrg('shared'), inOrg('spike')].join('\n'), {
      spike: new Set(['spike']),
      crowdOwn: new Set(['own']),
      crowdShared: new Set(['shared']),
    });
    expect(logFailures(logs, 4, 150)).toEqual([]);
    expect(logFailures(logs, 3, 150)).toEqual(['The log has 4 decision line(s) for 3 decision(s).']);
  });

  it('reads the decisions’ times, the holdings checks and every warning or error', () => {
    const summary = summariseLogs(
      [
        decided(12),
        decided(40),
        checked(0),
        '',
        checked(2000, 1),
        line({ event: 'holdings_check.paused', requests: 500, mismatched: 0, tampered: 2 }),
        line({ level: 'warn', event: 'db.transaction_retried' }),
        line({ level: 'warn', event: 'db.transaction_retried' }),
        line({ level: 'error', event: 'holdings_check.failed' }),
        line({ level: 'warn', event: 'log.suppressed' }),
        line({ event: 'http.request' }),
        'Error: a stack trace',
        '42',
      ].join('\r\n'),
    );

    expect(summary).toEqual({
      problems: { 'db.transaction_retried': 2, 'holdings_check.failed': 1, 'log.suppressed': 1 },
      platformFull: 0,
      suppressed: 1,
      unreadable: 2,
      holdingsChecks: [
        { requests: 0, mismatched: 0, tampered: 0 },
        { requests: 2000, mismatched: 1, tampered: 0 },
        { requests: 500, mismatched: 0, tampered: 2 },
      ],
      decisions: { count: 2, p50: 12, p95: 40, p99: 40, max: 40 },
      spikeDecisions: { count: 0, p50: 0, p95: 0, p99: 0, max: 0 },
      crowdOwnDecisions: NO_NEIGHBOUR,
      crowdSharedDecisions: NO_NEIGHBOUR,
      allowed: 0,
      steadyParts: NO_PARTS,
      neighbours: { calm: NO_NEIGHBOUR, busy: NO_NEIGHBOUR, stuck: NO_NEIGHBOUR },
      neighbourProblems: {},
    });
  });

  it('times each neighbour apart with where its time went, none of it in the steady numbers or the allowed count', () => {
    const inOrg = (orgId: string, durationMs: number, poolWaitMs: number, turnWaitMs: number, trips: number) =>
      line({
        event: 'spend_request.decided',
        orgId,
        durationMs,
        poolWaitMs,
        turnWaitMs,
        trips,
        decision: 'ALLOW',
        decisionRowsMs: trips + 100,
        headLockMs: trips + 200,
      });
    const summary = summariseLogs(
      [
        checked(1),
        inOrg('steady', 10, 1, 2, 19),
        inOrg('calm', 20, 3, 4, 20),
        inOrg('busy', 30, 5, 6, 21),
        inOrg('stuck', 40, 7, 8, 22),
      ].join('\n'),
      { calm: new Set(['calm']), busy: new Set(['busy']), stuck: new Set(['stuck']) },
    );
    expect(summary.decisions.count).toBe(1);
    expect(summary.allowed).toBe(1);
    expect(summary.steadyParts).toEqual({
      connectionWaitP95: 1,
      turnWaitP95: 2,
      supplierTurnWaitP95: 0,
      gateWaitP95: 0,
      tripsP50: 19,
      decisionRowsP95: 119,
      headLockP95: 219,
      busyRefusals: 0,
    });
    const percentiles = (n: number) => ({ count: 1, p50: n, p95: n, p99: n, max: n });
    expect(summary.neighbours).toEqual({
      calm: {
        ...percentiles(20),
        connectionWaitP95: 3,
        turnWaitP95: 4,
        supplierTurnWaitP95: 0,
        gateWaitP95: 0,
        tripsP50: 20,
        decisionRowsP95: 120,
        headLockP95: 220,
        busyRefusals: 0,
      },
      busy: {
        ...percentiles(30),
        connectionWaitP95: 5,
        turnWaitP95: 6,
        supplierTurnWaitP95: 0,
        gateWaitP95: 0,
        tripsP50: 21,
        decisionRowsP95: 121,
        headLockP95: 221,
        busyRefusals: 0,
      },
      stuck: {
        ...percentiles(40),
        connectionWaitP95: 7,
        turnWaitP95: 8,
        supplierTurnWaitP95: 0,
        gateWaitP95: 0,
        tripsP50: 22,
        decisionRowsP95: 122,
        headLockP95: 222,
        busyRefusals: 0,
      },
    });
    // Each neighbour's line accounts for a decision the run made.
    expect(logFailures(summary, 4, 150)).toEqual([]);
    expect(logFailures(summary, 3, 150)).toEqual(['The log has 4 decision line(s) for 3 decision(s).']);
  });

  it('keeps the trouble’s warnings apart, by phase 5’s window, and fails a run on any outside it', () => {
    const window = { from: '2026-11-01T10:02:00.000Z', to: '2026-11-01T10:04:15.000Z' };
    const warned = (time: string | undefined, event: string) => line({ level: 'error', event, time });
    const summary = summariseLogs(
      [
        checked(3),
        warned('2026-11-01T10:01:59.999Z', 'before'),
        warned('2026-11-01T10:02:00.000Z', 'at.the.start'),
        warned('2026-11-01T10:04:15.000Z', 'at.the.end'),
        warned('2026-11-01T10:04:15.001Z', 'after'),
        warned(undefined, 'no.time'),
      ].join('\n'),
      {},
      window,
    );
    expect(summary.neighbourProblems).toEqual({ 'at.the.start': 1, 'at.the.end': 1 });
    expect(summary.problems).toEqual({ before: 1, after: 1, 'no.time': 1 });
    expect(logFailures(summary, 0, 150)).toHaveLength(3);
  });

  it('counts every warning as the run’s when no phase 5 ran', () => {
    expect(troubleWindowOf([{}, {}])).toBeUndefined();
    expect(troubleWindowOf([{ startedAt: '2026-11-01T10:02:00.000Z' }])).toBeUndefined();
    const summary = summariseLogs(line({ level: 'warn', event: 'a', time: '2026-11-01T10:03:00.000Z' }));
    expect(summary.problems).toEqual({ a: 1 });
    expect(summary.neighbourProblems).toEqual({});
  });

  it('runs phase 5’s window from k6’s start to a margin past its end', () => {
    expect(
      troubleWindowOf([{}, { startedAt: '2026-11-01T10:02:00.000Z', endedAt: '2026-11-01T10:04:00.000Z' }]),
    ).toEqual({ from: '2026-11-01T10:02:00.000Z', to: '2026-11-01T10:04:15.000Z' });
  });

  it('times the spike’s decisions apart, by the capped agent’s organisation, and counts both against the run', () => {
    const spikeOrg = '01a16d8a-a36a-7140-abc0-cd368b76d749';
    const summary = summariseLogs(
      [
        checked(0),
        checked(3),
        decided(20),
        decided(30),
        line({ event: 'spend_request.decided', durationMs: 900, orgId: spikeOrg }),
      ].join('\n'),
      { spike: new Set([spikeOrg]) },
    );
    expect(summary.decisions).toEqual({ count: 2, p50: 20, p95: 30, p99: 30, max: 30 });
    expect(summary.spikeDecisions).toEqual({ count: 1, p50: 900, p95: 900, p99: 900, max: 900 });
    // The spike's 900 ms is no steady decision's: the target holds; all three lines account for the three decisions.
    expect(logFailures(summary, 3, 150)).toEqual([]);
    expect(logFailures(summary, 4, 150)).toEqual(['The log has 3 decision line(s) for 4 decision(s).']);
  });

  it('finds nothing wrong with a clean run', () => {
    const summary = summariseLogs([checked(0), decided(20), decided(30), checked(2)].join('\n'));
    expect(logFailures(summary, 2, 150)).toEqual([]);
  });

  it('names each thing wrong in plain words', () => {
    const summary = summariseLogs(
      [
        checked(0),
        checked(5, 1),
        decided(150),
        line({ level: 'warn', event: 'db.transaction_retried' }),
        line({ level: 'warn', event: 'log.suppressed' }),
        'not JSON',
      ].join('\n'),
    );
    expect(logFailures(summary, 2, 150)).toEqual([
      'The API logged db.transaction_retried 1 time(s); a load run must log no warning or error.',
      'The API logged log.suppressed 1 time(s); a load run must log no warning or error.',
      'The API suppressed log lines, so the run’s numbers are incomplete.',
      '1 line(s) of the API’s output were not its JSON log: read the log.',
      'A holdings check found a request whose money held did not match its decision.',
      'The log has 1 decision line(s) for 2 decision(s).',
      "A decision's p95 was 150 ms, at or past the 150 ms target.",
    ]);
  });

  it('fails a run whose holdings check never checked a request, or never said how many matched', () => {
    expect(logFailures(summariseLogs(checked(0)), 0, 150)).toEqual([
      'The holdings check did not check any request: it did not run at the restart between the phases.',
    ]);
    const unsaid = summariseLogs(line({ event: 'holdings_check.passed', requests: 3 }));
    expect(logFailures(unsaid, 0, 150)).toEqual([
      'A holdings check found a request whose money held did not match its decision.',
    ]);
  });
});
