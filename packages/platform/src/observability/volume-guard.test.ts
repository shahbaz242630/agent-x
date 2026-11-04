import { describe, expect, it } from 'vitest';

import {
  budgetOf,
  createVolumeGuard,
  DECISION_BUDGET_PER_MINUTE,
  DECISION_EVENT,
  MAX_EVENTS_PER_MINUTE,
  MINUTE_MS,
  NEVER_HELD_BACK,
  OTHER_EVENTS,
} from './volume-guard.ts';

/** pino's level numbers. */
const DEBUG = 20;
const INFO = 30;
const WARN = 40;
const ERROR = 50;
const START = Date.UTC(2026, 8, 14, 10, 0, 0);

/** A clock the test moves by hand, starting at the top of a minute. */
function manualClock(): { now: () => number; advance: (ms: number) => void } {
  let time = START;
  return {
    now: () => time,
    advance: (ms) => {
      time += ms;
    },
  };
}

/** The start of the nth minute after START. */
const minute = (n: number): number => START + n * MINUTE_MS;

describe('SEC-AV-09 each event is capped per minute, and nothing is dropped silently', () => {
  it('admits lines up to the cap, then holds the rest back', () => {
    const guard = createVolumeGuard(3, manualClock().now);
    const admitted = Array.from({ length: 5 }, () => guard.admit('auth.failed', WARN));
    expect(admitted).toEqual([true, true, true, false, false]);
  });

  it('caps each event on its own', () => {
    const guard = createVolumeGuard(1, manualClock().now);
    expect([guard.admit('a.one', INFO), guard.admit('b.two', INFO), guard.admit('a.one', INFO)]).toEqual([
      true,
      true,
      false,
    ]);
  });

  it('reports the exact count held back, and its minute, once, after the minute ends', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(2, clock.now);
    for (let i = 0; i < 7; i++) guard.admit('auth.failed', WARN);
    guard.admit('quiet.event', INFO);
    expect(guard.takeSuppressed()).toEqual([]);

    clock.advance(MINUTE_MS);
    expect(guard.takeSuppressed()).toEqual([{ event: 'auth.failed', count: 5, level: WARN, minuteStart: minute(0) }]);
    expect(guard.takeSuppressed()).toEqual([]);
  });

  it('reports the most severe level among the lines held back, so a level filter never hides the count', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(1, clock.now);
    guard.admit('db.failed', ERROR);
    guard.admit('db.failed', INFO);
    guard.admit('db.failed', ERROR);
    guard.admit('db.failed', WARN);
    clock.advance(MINUTE_MS);
    expect(guard.takeSuppressed()).toEqual([{ event: 'db.failed', count: 3, level: ERROR, minuteStart: minute(0) }]);
  });

  it('takes the level from the lines held back only, not from the lines written', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(1, clock.now);
    guard.admit('mixed.event', ERROR);
    guard.admit('mixed.event', INFO);
    clock.advance(MINUTE_MS);
    expect(guard.takeSuppressed()).toEqual([{ event: 'mixed.event', count: 1, level: INFO, minuteStart: minute(0) }]);
  });

  it('starts each minute afresh', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(1, clock.now);
    expect(guard.admit('x.y', INFO)).toBe(true);
    expect(guard.admit('x.y', INFO)).toBe(false);
    clock.advance(MINUTE_MS);
    expect(guard.admit('x.y', INFO)).toBe(true);
  });

  it('uses clock minutes, so a minute ends on the minute, not a minute after the first line', () => {
    const clock = manualClock();
    clock.advance(59_000);
    const guard = createVolumeGuard(1, clock.now);
    guard.admit('x.y', INFO);
    expect(guard.admit('x.y', INFO)).toBe(false);
    clock.advance(1_000);
    expect(guard.admit('x.y', INFO)).toBe(true);
  });

  it('never reopens a minute when the clock steps back, so the cap can’t be reset that way', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(1, clock.now);
    clock.advance(MINUTE_MS);
    guard.admit('x.y', INFO);
    clock.advance(-MINUTE_MS);
    expect(guard.admit('x.y', INFO)).toBe(false);
    clock.advance(MINUTE_MS);
    expect(guard.admit('x.y', INFO)).toBe(false);
  });

  it('keeps counts from a minute nobody asked about until they are taken, each with its own minute', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(1, clock.now);
    guard.admit('x.y', INFO);
    guard.admit('x.y', INFO);
    clock.advance(MINUTE_MS);
    guard.admit('x.y', WARN);
    guard.admit('x.y', WARN);
    clock.advance(MINUTE_MS);
    expect(guard.takeSuppressed()).toEqual([
      { event: 'x.y', count: 1, level: INFO, minuteStart: minute(0) },
      { event: 'x.y', count: 1, level: WARN, minuteStart: minute(1) },
    ]);
  });

  it('can report the current minute too, as at shutdown, without counting a line twice', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(2, clock.now);
    for (let i = 0; i < 5; i++) guard.admit('auth.failed', WARN);
    guard.admit('quiet.event', INFO);
    expect(guard.takeSuppressed(true)).toEqual([
      { event: 'auth.failed', count: 3, level: WARN, minuteStart: minute(0) },
    ]);
    expect(guard.takeSuppressed(true)).toEqual([]);

    // The rest of the minute is still capped, and counted from where the report left off.
    expect(guard.admit('auth.failed', INFO)).toBe(false);
    clock.advance(MINUTE_MS);
    // Its level is the level of the lines this report counts, not of those reported before.
    expect(guard.takeSuppressed()).toEqual([{ event: 'auth.failed', count: 1, level: INFO, minuteStart: minute(0) }]);
  });

  it('shares one bucket among events past the memory bound, so a flood of names cannot use up memory', () => {
    const guard = createVolumeGuard(1, manualClock().now);
    for (let i = 0; i < MAX_EVENTS_PER_MINUTE; i++) guard.admit(`event.n${i}`, INFO);
    expect(guard.admit('event.late_one', INFO)).toBe(true);
    expect(guard.admit('event.late_two', INFO)).toBe(false);
    expect(guard.admit('event.n0', INFO)).toBe(false);
    expect(guard.takeSuppressed(true)).toContainEqual({
      event: OTHER_EVENTS,
      count: 1,
      level: INFO,
      minuteStart: minute(0),
    });
  });
});

describe('4D2e F8 each event has its budget; money and audit lines are never held back (PL-52)', () => {
  const FLOOD = 50;
  const flood = (event: string, level: number, cap = 2) => {
    const clock = manualClock();
    const guard = createVolumeGuard(cap, clock.now);
    const admitted = Array.from({ length: FLOOD }, () => guard.admit(event, level)).filter(Boolean).length;
    clock.advance(MINUTE_MS);
    return { admitted, suppressed: guard.takeSuppressed() };
  };

  it.each(NEVER_HELD_BACK.map((family) => `${family}some_line`))(
    'never holds back %s at info or debug, a money or audit line',
    (event) => {
      for (const level of [DEBUG, INFO]) expect(flood(event, level)).toEqual({ admitted: FLOOD, suppressed: [] });
    },
  );

  it.each(NEVER_HELD_BACK.map((family) => `${family}some_line`))(
    'caps %s at warn and error like any other, so a caller who can repeat one cannot fill the log',
    (event) => {
      for (const level of [WARN, ERROR]) {
        expect(flood(event, level).suppressed).toEqual([{ event, count: FLOOD - 2, level, minuteStart: minute(0) }]);
      }
    },
  );

  it('holds back a flood of audit.backlog errors with a count, while an integrity alarm still gets out', () => {
    const clock = manualClock();
    const guard = createVolumeGuard(3, clock.now);
    for (let i = 0; i < FLOOD; i++) guard.admit('audit.backlog', ERROR);
    expect(guard.admit('audit.integrity_failed', ERROR)).toBe(true);
    // The family's info lines are still never held back during the flood.
    expect(Array.from({ length: FLOOD }, () => guard.admit('audit.anchored', INFO)).every(Boolean)).toBe(true);
    clock.advance(MINUTE_MS);
    expect(guard.takeSuppressed()).toEqual([
      { event: 'audit.backlog', count: FLOOD - 3, level: ERROR, minuteStart: minute(0) },
    ]);
  });

  it('keeps the cap on warnings, errors and the security and activity-log lines an outsider can drive', () => {
    for (const [event, level] of [
      ['db.transaction_retried', WARN],
      ['http.request_failed', ERROR],
      ['security.events_written', INFO],
      ['access_log.write_failed', WARN],
    ] as const) {
      expect(flood(event, level).suppressed).toEqual([{ event, count: FLOOD - 2, level, minuteStart: minute(0) }]);
    }
  });

  it('holds back a line only by its whole family name, never one that merely starts alike', () => {
    expect(flood('handoffs.other', INFO).admitted).toBe(2);
    expect(flood('auditor.read', INFO).admitted).toBe(2);
  });

  it('a line never held back takes no room in the tallies, so it never pushes others into the shared bucket', () => {
    const guard = createVolumeGuard(1, manualClock().now);
    for (let i = 0; i < MAX_EVENTS_PER_MINUTE * 2; i++) guard.admit(`audit.n${i}`, INFO);
    expect(guard.admit('plain.event', INFO)).toBe(true);
    expect(guard.admit('plain.event', INFO)).toBe(false);
    expect(guard.takeSuppressed(true)).toEqual([
      { event: 'plain.event', count: 1, level: INFO, minuteStart: minute(0) },
    ]);
  });

  it('gives a decision line 20,000 a minute a process, the configured cap for the rest', () => {
    expect(budgetOf(DECISION_EVENT, INFO, 600)).toBe(DECISION_BUDGET_PER_MINUTE);
    expect(DECISION_BUDGET_PER_MINUTE).toBe(20_000);
    expect(budgetOf('http.request_completed', INFO, 600)).toBe(600);
    const clock = manualClock();
    const guard = createVolumeGuard(600, clock.now);
    let admitted = 0;
    for (let i = 0; i < DECISION_BUDGET_PER_MINUTE + 3; i++) if (guard.admit(DECISION_EVENT, INFO)) admitted += 1;
    expect(admitted).toBe(DECISION_BUDGET_PER_MINUTE);
    clock.advance(MINUTE_MS);
    // A count of lost decision lines is a warning: the denial-surge alert undercounts that minute.
    expect(guard.takeSuppressed()).toEqual([{ event: DECISION_EVENT, count: 3, level: WARN, minuteStart: minute(0) }]);
  });

  it('keeps a configured cap above the decision budget for decisions too, as in a load run', () => {
    expect(budgetOf(DECISION_EVENT, INFO, 200_000)).toBe(200_000);
    expect(flood(DECISION_EVENT, INFO, 100).admitted).toBe(FLOOD);
  });

  it('writes the count of other events at their own level, not raised to a warning', () => {
    expect(flood('busy.event', DEBUG).suppressed).toEqual([
      { event: 'busy.event', count: FLOOD - 2, level: DEBUG, minuteStart: minute(0) },
    ]);
  });
});
