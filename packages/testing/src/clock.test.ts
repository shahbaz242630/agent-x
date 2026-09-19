import { describe, expect, expectTypeOf, it } from 'vitest';

import type { Clock } from '../../core/src/shared-kernel/index.ts';
import { FixedClock } from './clock.ts';

const START = new Date('2026-09-13T20:00:00.000Z');

describe('FixedClock', () => {
  it("fits core's Clock", () => {
    expectTypeOf<FixedClock>().toExtend<Clock>();
  });

  it('stays at its start time until moved', () => {
    const clock = new FixedClock(START);

    expect(clock.now().toISOString()).toBe('2026-09-13T20:00:00.000Z');
    expect(clock.now().toISOString()).toBe('2026-09-13T20:00:00.000Z');
  });

  it('is not changed by mutating the Date passed in or handed out', () => {
    const start = new Date(START);
    const clock = new FixedClock(start);

    start.setUTCFullYear(2000);
    clock.now().setUTCFullYear(2000);

    expect(clock.now().toISOString()).toBe('2026-09-13T20:00:00.000Z');
  });

  it('moves forward by exactly the step asked for', () => {
    const clock = new FixedClock(START);

    clock.advanceBy(4 * 60 * 60 * 1000);
    clock.advanceBy(0);

    expect(clock.now().toISOString()).toBe('2026-09-14T00:00:00.000Z');
  });

  it.each([-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY])('refuses the step %s', (step) => {
    const clock = new FixedClock(START);

    expect(() => {
      clock.advanceBy(step);
    }).toThrow(RangeError);
    expect(clock.now().toISOString()).toBe('2026-09-13T20:00:00.000Z');
  });

  it('refuses an invalid start date', () => {
    expect(() => new FixedClock(new Date('not a date'))).toThrow('FixedClock needs a valid date');
  });

  it('refuses a step that runs past the last representable date', () => {
    const clock = new FixedClock(new Date(8.64e15));

    expect(() => {
      clock.advanceBy(1);
    }).toThrow('FixedClock needs a valid date');
  });
});
