import { describe, expect, it } from 'vitest';

import { summariseLogs } from './logs.ts';
import { type PhaseResult, phaseFailures, renderReport, type RunResult } from './report.ts';

const phase = (n: number, overrides: Partial<PhaseResult> = {}): PhaseResult => ({
  phase: n,
  requests: 3300,
  created: 3150,
  serverErrors: 0,
  rateLimited: 0,
  checksFailed: 0,
  dropped: 0,
  asksMs: { p50: 21.25, p95: 88.5, p99: 140, max: 310.75 },
  thresholds: { 'checks rate==1': true, 'http_req_duration{kind:ask} p(95)<500': true },
  ...overrides,
});

const clean: RunResult = {
  at: '2026-10-22T12:00:00.000Z',
  commit: 'abc1234',
  site: 'local',
  apiCpus: 0.5,
  phases: [phase(1), phase(2)],
  logs: summariseLogs(
    [
      JSON.stringify({ level: 'info', event: 'holdings_check.passed', requests: 3150, mismatched: 0, tampered: 0 }),
      JSON.stringify({ level: 'info', event: 'spend_request.decided', durationMs: 31 }),
    ].join('\n'),
  ),
  databaseChecksPassed: true,
  failures: [],
};

describe('a phase’s numbers', () => {
  it('fail on each threshold that did not hold, and on no request made', () => {
    expect(phaseFailures(phase(1))).toEqual([]);
    expect(
      phaseFailures(
        phase(2, {
          created: 0,
          thresholds: { 'checks rate==1': false, 'dropped_iterations count==0': false, 'server_errors count==0': true },
        }),
      ),
    ).toEqual([
      "Phase 2: k6's threshold checks rate==1 did not hold.",
      "Phase 2: k6's threshold dropped_iterations count==0 did not hold.",
      'Phase 2: no request was made.',
    ]);
  });
});

describe('the report', () => {
  it('gives a clean run’s numbers, and says a laptop run doesn’t close PL-38', () => {
    const report = renderReport(clean);
    expect(report).toContain('# Load test, 2026-10-22 (local, API 0.5 CPU)\n\n**Passed.**');
    expect(report).toContain("the API\nsized as staging's (half a CPU, 1 GiB, ten connections)");
    expect(report).toContain('| 1 | 3300 | 3150 | 0 | 21.3 | 88.5 | 140.0 | 310.8 | 0 | 0 | 0 |');
    expect(report).toContain('the hand-off is\npaused');
    expect(report).toContain('| 1 | 31 | 31 | 31 | 31 |');
    expect(report).toContain('they do not close PL-38');
    expect(report).toContain('The database after the run: passed');
    expect(report).toContain('The holdings check at the restart: 1 run(s) over 3150 request(s).');
    expect(report).toContain('Warnings or errors logged: 0; lines suppressed: 0.');
    expect(report).not.toContain('What failed');
  });

  it('says when the API was given more than staging’s half a CPU', () => {
    const report = renderReport({ ...clean, apiCpus: 2 });
    expect(report).toContain('# Load test, 2026-10-22 (local, API 2 CPU)');
    expect(report).toContain('the API\ngiven 2 CPU(s) (staging has half), 1 GiB and ten connections as staging, k6');
  });

  it('says an Azure run is the one PL-38 closes on, sized up on staging', () => {
    const report = renderReport({ ...clean, site: 'azure', apiCpus: 2 });
    expect(report).toContain('# Load test, 2026-10-22 (azure, API 2 CPU)\n\n**Passed.**');
    expect(report).toContain('on staging in Azure UAE North, sized up for the run: the API\ngiven 2 CPU(s)');
    expect(report).toContain('This is the run PL-38 closes on (D2c).');
    expect(report).not.toContain('laptop');
    expect(report).toContain('| 1 | 3300 | 3150 | 0 | 21.3 | 88.5 | 140.0 | 310.8 | 0 | 0 | 0 |');
  });

  it('lists what failed', () => {
    const report = renderReport({ ...clean, databaseChecksPassed: false, failures: ['One.', 'Two.'] });
    expect(report).toContain('**Failed: 2 check(s).**');
    expect(report).toContain('The database after the run: failed');
    expect(report.endsWith('## What failed\n\n- One.\n- Two.\n')).toBe(true);
  });
});
