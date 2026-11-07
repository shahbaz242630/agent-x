import { describe, expect, it } from 'vitest';

import {
  allowedBusyLines,
  backgroundFailures,
  backgroundHealth,
  decisionP95In,
  type LogLine,
} from './stageg-background.ts';

const at = (minute: number) => new Date(Date.UTC(2026, 10, 6, 10, minute)).toISOString();
const line = (minute: number, event: string, fields: Record<string, unknown> = {}) =>
  JSON.stringify({ time: at(minute), level: 'info', service: 'api', event, ...fields });
const anchored = (minute: number, fields: Record<string, number> = {}) =>
  line(minute, 'audit.anchor_check_done', {
    chains: 300,
    anchored: 10,
    unchanged: 290,
    unanchored: 0,
    failed: 0,
    unchecked: 0,
    left: 0,
    ...fields,
  });
const pulsesEvery = (from: number, to: number) =>
  Array.from({ length: to - from + 1 }, (_, index) => line(from + index, 'jobs.pulse', { jobs: 12, running: 1 }));
const WINDOW = { from: at(0), to: at(30) };
/** The API's one replica, and the jobs app's, as the workspace names them. */
const API = 'api--r1/api-r1-0';
const JOBS = 'jobs--r1/jobs-r1-0';
/** Lines after the window's end from the jobs (a pulse) and the API's replica: the window's own lines are all in. */
const SETTLED = [line(31, 'jobs.pulse'), line(31, 'http.request_completed')];
/** Each line as a replica wrote it: pulses from the jobs app, the rest from the API. */
const asLog = (lines: readonly string[]): LogLine[] =>
  lines.map((log) => ({ replica: log.includes('"jobs.pulse"') ? JOBS : API, log }));
/** A clean step: two anchor check runs, a pulse every minute, the log settled. */
const CLEAN = [anchored(5, { left: 4 }), anchored(20), ...pulsesEvery(0, 30), ...SETTLED];

const failuresOf = (lines: readonly string[], overloading = false, offenders?: ReadonlySet<string>) =>
  backgroundFailures(backgroundHealth(asLog(lines), WINDOW, { apiReplicas: [API], offenders }), overloading);

describe("the background work's health over a step's window", () => {
  it('reads the anchor check, the stalls, the trouble lines and the pulses inside the window, and skips the rest', () => {
    const text = [
      anchored(-5, { failed: 9 }),
      line(1, 'jobs.pulse'),
      line(2, 'jobs.pulse'),
      line(10, 'jobs.pulse'),
      line(24, 'jobs.pulse'),
      anchored(5, { unchecked: 2, left: 4 }),
      'not the logger’s JSON',
      'null',
      '[1]',
      JSON.stringify({ event: 'jobs.pulse' }),
      JSON.stringify({ time: 'not a time', event: 'jobs.pulse' }),
      JSON.stringify({ time: at(12), level: 'error', event: 'job.stalled', job: 'anchor-check' }),
      JSON.stringify({ time: at(13), level: 'error', event: 'job.stalled', job: 'anchor-check' }),
      JSON.stringify({ time: at(14), level: 'error', event: 'job.stalled' }),
      JSON.stringify({ time: at(15), level: 'fatal' }),
      JSON.stringify({ time: at(16), level: 'warn', event: 'spend_request.agent_busy', orgId: 'busy' }),
      JSON.stringify({ time: at(16), level: 'warn', event: 'spend_request.agent_busy', orgId: 'calm' }),
      JSON.stringify({ time: at(17), level: 'warn', event: 'db.transaction_retried' }),
      anchored(20, { failed: 1, unchecked: 3, left: 1 }),
      line(45, 'job.stalled', { job: 'later' }),
      ...SETTLED,
    ];
    expect(backgroundHealth(asLog(text), WINDOW, { apiReplicas: [API], offenders: new Set(['busy']) })).toEqual({
      minutes: 30,
      missing: [],
      anchorChecks: 2,
      failed: 1,
      unchecked: { most: 3, last: 3 },
      left: { most: 4, last: 1 },
      stalled: ['anchor-check', '(no job named)'],
      errors: { 'job.stalled': 3, '(no event)': 1 },
      warnings: { 'spend_request.agent_busy': 1, 'db.transaction_retried': 1 },
      offenderWarnings: { 'spend_request.agent_busy': 1 },
      pulses: 4,
      // 10 to 24: the edges (0 to 1, 24 to 30) are shorter.
      longestPulseGapMinutes: 14,
    });
  });

  it('passes a step whose checks ran and kept up, whose jobs pulsed each minute, with nothing logged wrong', () => {
    expect(failuresOf(CLEAN)).toEqual([]);
  });

  it('says what has not arrived yet: a pulse after the window, and a line after it from each API replica', () => {
    const health = (log: LogLine[], apiReplicas: string[]) => backgroundHealth(log, WINDOW, { apiReplicas }).missing;
    const lines = asLog(CLEAN.slice(0, -2));
    expect(health(lines, [API, 'api--r1/api-r1-1'])).toEqual([
      'a jobs.pulse line after the step ended',
      'a line from API replica api--r1/api-r1-0 after the step ended',
      'a line from API replica api--r1/api-r1-1 after the step ended',
    ]);
    // A pulse and one replica's line in; the other replica's still on its way.
    expect(health([...lines, ...asLog(SETTLED)], [API, 'api--r1/api-r1-1'])).toEqual([
      'a line from API replica api--r1/api-r1-1 after the step ended',
    ]);
    // A line at the window's very end is the window's own, not after it.
    expect(health([...lines, { replica: API, log: line(30, 'http.request_completed') }], [API])).toContain(
      'a line from API replica api--r1/api-r1-0 after the step ended',
    );
    expect(health([...lines, ...asLog(SETTLED)], [])).toEqual([
      'the names of the API replicas that ran the step, to wait for each',
    ]);
    expect(health([...lines, ...asLog(SETTLED)], [API])).toEqual([]);
  });

  it('fails a step of 10 minutes or more whose background check never ran; a shorter one may see no run', () => {
    const failures = (minutes: number) =>
      backgroundFailures(
        backgroundHealth(
          asLog([
            ...pulsesEvery(0, minutes),
            line(minutes + 1, 'jobs.pulse'),
            line(minutes + 1, 'http.request_completed'),
          ]),
          { from: at(0), to: at(minutes) },
          { apiReplicas: [API] },
        ),
        false,
      );
    const neverRan = ['The background check never ran: no audit.anchor_check_done line in the step.'];
    // A run's line comes at most every 10 minutes (anchor-check.ts): S176's 2-minute smoke saw none, with nothing wrong.
    expect(failures(2)).toEqual([]);
    expect(failures(9)).toEqual([]);
    expect(failures(10)).toEqual(neverRan);
    expect(failuresOf([...pulsesEvery(0, 30), ...SETTLED])).toEqual(neverRan);
  });

  it('fails a check above its ceiling, or not back to none by the step’s last run, which first-to-last missed', () => {
    // First 0, last 0, but 40 behind between: the old first-to-last rule passed it.
    expect(
      failuresOf([anchored(3), anchored(10, { unchecked: 40 }), anchored(25), ...pulsesEvery(0, 30), ...SETTLED]),
    ).toEqual(['A run left 40 chains unchecked, above the ceiling of 10: the anchor check fell behind.']);
    // Behind from the start and still behind at the end: never growing, never caught up.
    expect(
      failuresOf([anchored(3, { left: 5 }), anchored(25, { left: 5 }), ...pulsesEvery(0, 30), ...SETTLED]),
    ).toEqual(["The step's last anchor check run still left 5 chains waiting their turn: it never caught up."]);
  });

  it('fails every error line of the API, whatever the job: a crash, an integrity failure, a check behind', () => {
    const errors = [
      'audit.anchor_check_crashed',
      'audit.integrity_failed',
      'audit.anchor_check_behind',
      'job.skipping_runs',
      'audit.anchor_check_over_size',
    ];
    const lines = errors.map((event) => JSON.stringify({ time: at(12), level: 'error', event, reason: 'x' }));
    expect(failuresOf([...CLEAN, ...lines])).toEqual(
      errors.map((event) => `The API logged ${event} 1 time(s) at error level in the step.`),
    );
  });

  it('allows only the busy lines, and only on a step meant to overload or from its offenders, each counted', () => {
    const warn = (event: string, orgId = 'calm') => JSON.stringify({ time: at(12), level: 'warn', event, orgId });
    const busy = [warn('spend_request.agent_busy'), warn('spend_request.agent_busy'), warn('db.pool_wait_ran_out')];
    expect(failuresOf([...CLEAN, ...busy], true)).toEqual([]);
    expect(failuresOf([...CLEAN, ...busy], false)).toEqual([
      'The API logged spend_request.agent_busy 2 warning(s) in the step: only the busy lines of a step meant to overload are allowed.',
      "The API logged db.pool_wait_ran_out 1 warning(s) in the step: the shared pool ran out, so one organisation's trouble reached the others.",
    ]);
    // Beside the neighbours, the offender's busy lines are its trouble; any other warning of its still fails.
    const offender = new Set(['busy']);
    const theirs = [warn('spend_request.supplier_busy', 'busy'), warn('db.transaction_retried', 'busy')];
    expect(failuresOf([...CLEAN, ...theirs], false, offender)).toEqual([
      'The API logged db.transaction_retried 1 warning(s) in the step: only the busy lines of a step meant to overload are allowed.',
    ]);
    expect(failuresOf([...CLEAN, warn('db.transaction_retried')], true)).toHaveLength(1);
    const health = backgroundHealth(asLog([...CLEAN, ...busy, ...theirs]), WINDOW, {
      apiReplicas: [API],
      offenders: offender,
    });
    expect(allowedBusyLines(health, false)).toEqual({ 'spend_request.supplier_busy': 1 });
    expect(allowedBusyLines(health, true)).toEqual({
      'spend_request.supplier_busy': 1,
      'spend_request.agent_busy': 2,
      'db.pool_wait_ran_out': 1,
    });
  });

  it('fails a failed chain check, and a pulse gap past three minutes', () => {
    const gap = [...pulsesEvery(0, 10), ...pulsesEvery(14, 30)];
    expect(failuresOf([anchored(5, { failed: 2 }), anchored(20), ...gap, ...SETTLED])).toEqual([
      'The anchor check failed 2 chain check(s) in the step: read its audit.anchor_check_done lines.',
      'No jobs.pulse for 4.0 minutes in the step: the background jobs stopped, or none held the lease.',
    ]);
    const justInside = [...pulsesEvery(0, 10), ...pulsesEvery(13, 30)];
    expect(failuresOf([anchored(5), ...justInside, ...SETTLED])).toEqual([]);
  });

  it('fails the neighbours on the shared pool running out, even as the offender’s own line (PL-63)', () => {
    const offender = new Set(['busy']);
    const ranOut = JSON.stringify({ time: at(12), level: 'warn', event: 'db.pool_wait_ran_out', orgId: 'busy' });
    expect(failuresOf([...CLEAN, ranOut], false, offender)).toEqual([
      "The API logged db.pool_wait_ran_out 1 warning(s) in the step: the shared pool ran out, so one organisation's trouble reached the others.",
    ]);
    const health = backgroundHealth(asLog([...CLEAN, ranOut]), WINDOW, { apiReplicas: [API], offenders: offender });
    expect(allowedBusyLines(health, false)).toEqual({});
    // Where the whole platform is meant to overload (a surge), the pool running out is its point.
    expect(allowedBusyLines(health, true)).toEqual({ 'db.pool_wait_ran_out': 1 });
    expect(failuresOf([...CLEAN, ranOut], true, offender)).toEqual([]);
  });

  it("reads the decisions' p95 in a time range from the API's own lines, none when none was made", () => {
    const decided = (minute: number, durationMs: number) => line(minute, 'spend_request.decided', { durationMs });
    const log = asLog([decided(-1, 900), ...[40, 60, 80, 100, 120].map((d, i) => decided(i + 1, d)), decided(31, 900)]);
    expect(decisionP95In(log, WINDOW)).toBe(120);
    expect(decisionP95In(asLog([line(5, 'spend_request.decided')]), WINDOW)).toBeNull();
  });
});
