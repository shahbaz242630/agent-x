import { describe, expect, it } from 'vitest';

import { createVolumeGuard, MAX_EVENTS_PER_MINUTE, MINUTE_MS, OTHER_EVENTS } from './volume-guard.ts';

/** pino's level numbers. */
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
