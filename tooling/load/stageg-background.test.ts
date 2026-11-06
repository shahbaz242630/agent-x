import { describe, expect, it } from 'vitest';

import { backgroundFailures, backgroundHealth } from './stageg-background.ts';

const at = (minute: number) => new Date(Date.UTC(2026, 10, 6, 10, minute)).toISOString();
const line = (minute: number, event: string, fields: Record<string, unknown> = {}) =>
  JSON.stringify({ time: at(minute), level: 'info', service: 'api', event, ...fields });
const anchored = (minute: number, fields: Record<string, number>) =>
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
const pulses = (minutes: readonly number[]) =>
  minutes.map((minute) => line(minute, 'jobs.pulse', { jobs: 12, running: 1 }));
const WINDOW = { from: at(0), to: at(30) };

describe("the background work's health over a step's window", () => {
  it('reads the anchor check, the stalls and the pulses inside the window, and skips the rest', () => {
    const text = [
      anchored(-5, { failed: 9 }),
      ...pulses([1, 2, 10, 24]),
      anchored(5, { unchecked: 2, left: 4 }),
      'not the logger’s JSON',
      'null',
      '[1]',
      JSON.stringify({ event: 'jobs.pulse' }),
      line(12, 'job.stalled', { job: 'anchor-check', runningMs: 900_000 }),
      line(13, 'job.stalled', { job: 'anchor-check', runningMs: 960_000 }),
      line(14, 'job.stalled'),
      anchored(20, { failed: 1, unchecked: 3, left: 4 }),
      line(45, 'job.stalled', { job: 'later' }),
    ].join('\r\n');
    expect(backgroundHealth(text, WINDOW)).toEqual({
      minutes: 30,
      anchorChecks: 2,
      failed: 1,
      unchecked: { first: 2, last: 3 },
      left: { first: 4, last: 4 },
      stalled: ['anchor-check', '(no job named)'],
      pulses: 4,
      // 10 to 24: the edges (0 to 1, 24 to 30) are shorter.
      longestPulseGapMinutes: 14,
    });
  });

  it('passes a step whose checks kept up and whose jobs said they were alive', () => {
    const health = backgroundHealth(
      [anchored(3, { unchecked: 2, left: 6 }), anchored(18, { unchecked: 1, left: 0 }), ...pulses([0, 14, 28])].join(
        '\n',
      ),
      WINDOW,
    );
    expect(backgroundFailures(health)).toEqual([]);
  });

  it('says in plain words each way the background work fell behind', () => {
    const health = backgroundHealth(
      [
        anchored(10, { failed: 2, unchecked: 0, left: 1 }),
        anchored(25, { unchecked: 5, left: 9 }),
        line(26, 'job.stalled', { job: 'handoff' }),
      ].join('\n'),
      WINDOW,
    );
    expect(backgroundFailures(health)).toEqual([
      'The anchor check failed 2 chain check(s) in the step: read its audit.anchor_check_done lines.',
      "The anchor check left 5 chains unchecked at the step's end, 0 at its start: it fell behind.",
      "9 chains were waiting their turn at the step's end, 1 at its start: the anchor check fell behind.",
      'A background job stalled in the step: handoff.',
      'No jobs.pulse for 30.0 minutes in the step: the background jobs stopped, or none held the lease.',
    ]);
  });

  it('asks for an anchor check only in a window as long as the pulse alert’s', () => {
    expect(backgroundFailures(backgroundHealth(pulses([0, 10, 20, 30]).join('\n'), WINDOW))).toEqual([
      "No anchor check finished in the step's 30.0 minutes, so nothing says the checks kept up.",
    ]);
    const short = { from: at(0), to: at(2) };
    expect(backgroundHealth('', short)).toMatchObject({ anchorChecks: 0, unchecked: null, left: null, pulses: 0 });
    expect(backgroundFailures(backgroundHealth('', short))).toEqual([]);
  });
});
