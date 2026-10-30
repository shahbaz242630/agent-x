import { describe, expect, it } from 'vitest';

import { logFailures, percentile, percentilesOf, summariseLogs } from './logs.ts';

const line = (fields: Record<string, unknown>) => JSON.stringify({ level: 'info', ...fields });
const decided = (durationMs: number) => line({ event: 'spend_request.decided', durationMs });
const checked = (requests: number, mismatched = 0, tampered = 0) =>
  line({ event: 'holdings_check.passed', requests, mismatched, tampered });

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
    expect(summary.crowdOwnDecisions).toEqual({ count: 1, p50: 20, p95: 20, p99: 20, max: 20 });
    expect(summary.crowdSharedDecisions).toEqual({ count: 1, p50: 30, p95: 30, p99: 30, max: 30 });
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
      suppressed: 1,
      unreadable: 2,
      holdingsChecks: [
        { requests: 0, mismatched: 0, tampered: 0 },
        { requests: 2000, mismatched: 1, tampered: 0 },
        { requests: 500, mismatched: 0, tampered: 2 },
      ],
      decisions: { count: 2, p50: 12, p95: 40, p99: 40, max: 40 },
      spikeDecisions: { count: 0, p50: 0, p95: 0, p99: 0, max: 0 },
      crowdOwnDecisions: { count: 0, p50: 0, p95: 0, p99: 0, max: 0 },
      crowdSharedDecisions: { count: 0, p50: 0, p95: 0, p99: 0, max: 0 },
      allowed: 0,
    });
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
