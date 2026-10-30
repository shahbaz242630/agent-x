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
  spikeMs: null,
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
    expect(report).toContain('| Steady | 1 | 31 | 31 | 31 | 31 |');
    expect(report).not.toContain('spike, 50 requests');
    expect(report).not.toContain('| The spike |');
    expect(report).toContain('they do not close PL-38');
    expect(report).toContain('The database after the run: passed');
    expect(report).toContain('The holdings check at the restart: 1 run(s) over 3150 request(s).');
    expect(report).toContain('Warnings or errors logged: 0; lines suppressed: 0.');
    expect(report).not.toContain('What failed');
  });

  it('gives phase 2’s spike its own numbers, apart from the steady traffic’s targets', () => {
    const spikeDecided = JSON.stringify({ level: 'info', event: 'spend_request.decided', durationMs: 640, orgId: 'o' });
    const report = renderReport({
      ...clean,
      phases: [phase(1), phase(2, { spikeMs: { p50: 410.25, p95: 757.5, max: 812 } })],
      logs: summariseLogs(spikeDecided, { spike: new Set(['o']) }),
    });
    expect(report).toContain(
      "Phase 2's spike, 50 requests at once from the capped agent, queued on its month's lock by design: " +
        'p50 410.3 ms, p95 757.5 ms, max 812.0 ms.',
    );
    expect(report).toContain('| The spike | 1 | 640 | 640 | 640 | 640 |');
  });

  it('gives the crowds their own section, apart from the phases held to the targets', () => {
    expect(renderReport(clean)).not.toContain('Many agents in one organisation');
    const decided = (orgId: string, durationMs: number) =>
      JSON.stringify({ level: 'info', event: 'spend_request.decided', durationMs, orgId, decision: 'ALLOW' });
    const report = renderReport({
      ...clean,
      phases: [
        phase(1),
        phase(2),
        phase(3, { requests: 3480, asksMs: { p50: 90, p95: 137.5, p99: 170, max: 300 } }),
        phase(4, { requests: 3490, dropped: 2, serverErrors: 1, rateLimited: 3, checksFailed: 4 }),
      ],
      logs: summariseLogs([decided('steady', 31), decided('own', 41), decided('shared', 51)].join('\n'), {
        crowdOwn: new Set(['own']),
        crowdShared: new Set(['shared']),
      }),
    });
    expect(report).toContain(
      '## Many agents in one organisation (apart from the numbers above; the same 150 ms decision target, not yet failing a run)',
    );
    expect(report).toContain('Decision target met in each: p95 under 150 ms.');
    expect(report).not.toContain('**But many agents');
    expect(report).toContain(
      '| Each agent with its own three suppliers | 3480 | 0 | 137.5 | 1 | 41 | 41 | 41 | 41 | 0 | 0 | 0 |',
    );
    expect(report).toContain(
      '| All agents sharing three suppliers | 3490 | 2 | 88.5 | 1 | 51 | 51 | 51 | 51 | 1 | 3 | 4 |',
    );
    // The main table stays the steady traffic's, so its numbers compare with earlier runs.
    expect(report).not.toContain('| 3 | 3480 |');
    expect(report).toContain('| Steady | 1 | 31 | 31 | 31 | 31 |');
    expect(report).toContain('Allowed at once: 1 of the 1 steady decisions;');
    expect(report).toContain("Hand-offs are paused, so what follows an allowed request isn't timed.");
  });

  it('names a crowd that missed the decision target, in the crowds’ own section', () => {
    const decided = JSON.stringify({ level: 'info', event: 'spend_request.decided', durationMs: 181, orgId: 'shared' });
    const report = renderReport({
      ...clean,
      phases: [phase(1), phase(2), phase(3), phase(4)],
      logs: summariseLogs(decided, { crowdShared: new Set(['shared']) }),
    });
    expect(report).toContain(
      "**Decision target missed (150 ms).** All agents sharing three suppliers: a decision's p95 was 181 ms.",
    );
    expect(report).not.toContain('Decision target met');
    expect(report).toContain(
      '**Passed.**\n\n**But many agents in one organisation missed the 150 ms decision target: see below.**',
    );
  });

  it('says when the API was given more than staging’s half a CPU', () => {
    const report = renderReport({ ...clean, apiCpus: 2 });
    expect(report).toContain('# Load test, 2026-10-22 (local, API 2 CPU)');
    expect(report).toContain('the API\ngiven 2 CPU(s) (staging has half), 1 GiB and ten connections as staging, k6');
  });

  it('says an Azure run is the one PL-38 closes on, sized up on staging', () => {
    const report = renderReport({
      ...clean,
      site: 'azure',
      apiCpus: 2,
      database: 'Standard_D2ads_v5 (GeneralPurpose)',
    });
    expect(report).toContain('# Load test, 2026-10-22 (azure, API 2 CPU)\n\n**Passed.**');
    expect(report).toContain(
      'on staging in Azure UAE North: the API\ngiven 2 CPU(s) and ten connections, the database Standard_D2ads_v5 (GeneralPurpose), k6',
    );
    expect(report).toContain('Sized up for the run, this is the run PL-38 closes on (D2c).');
    expect(report).not.toContain('--smoke');
    expect(report).not.toContain('laptop');
    expect(report).toContain('| 1 | 3300 | 3150 | 0 | 21.3 | 88.5 | 140.0 | 310.8 | 0 | 0 | 0 |');
  });

  it("says the wiring run (--smoke) measures nothing, and isn't the run PL-38 closes on", () => {
    const report = renderReport({ ...clean, site: 'azure', apiCpus: 0.5, smoke: true });
    expect(report).toContain('# Load test, 2026-10-22 (azure, smoke, API 0.5 CPU)');
    expect(report).toContain('the database of a size not read');
    expect(report).toContain('its numbers measure nothing.**');
    expect(report).not.toContain('PL-38 closes on');
  });

  it('says the database trips each request cost, phase by phase, and the delay added to the database (4D2d P0)', () => {
    expect(renderReport(clean)).not.toContain('Database trips');
    expect(renderReport({ ...clean, delayMs: 0 })).not.toContain('ms was added');
    const report = renderReport({
      ...clean,
      delayMs: 2,
      statements: [
        { phase: 1, statements: 528_000 },
        { phase: 2, statements: 3300 },
      ],
    });
    expect(report).toContain(
      "k6 straight to it. 2 ms was added to every packet the database sent, as Azure's network adds it. As",
    );
    expect(report).toContain(
      "\nDatabase trips a request (the app's round trips over the phase, its timers' included: its statements by pg_stat_statements, less those sent in another's trip): phase 1 160.0, phase 2 1.0.\n",
    );
    // A phase with no request has no trips a request to give.
    const none = renderReport({
      ...clean,
      phases: [phase(1, { requests: 0 }), phase(2)],
      statements: [
        { phase: 1, statements: 5 },
        { phase: 2, statements: 6600 },
        { phase: 3, statements: 1 },
      ],
    });
    expect(none).toContain("less those sent in another's trip): phase 2 2.0.\n");
  });

  it('lists what failed', () => {
    const report = renderReport({ ...clean, databaseChecksPassed: false, failures: ['One.', 'Two.'] });
    expect(report).toContain('**Failed: 2 check(s).**');
    expect(report).toContain('The database after the run: failed');
    expect(report.endsWith('## What failed\n\n- One.\n- Two.\n')).toBe(true);
  });
});
