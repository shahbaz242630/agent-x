// ADR-006 §4 (FX-CLOCK): one function draws every month boundary, in the
// lineage's own time zone, and one every rolling window.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { DEFAULT_TIME_ZONE, isTimeZone, periodOf, windowStart } from './period.ts';

/** The zone's local date at an instant, as `YYYY-MM-DD`. */
const localDate = (at: Date, zone: string): string => at.toLocaleDateString('en-CA', { timeZone: zone });

describe('periodOf', () => {
  it('draws Dubai’s month from local midnight on the 1st (UTC+4, no daylight saving)', () => {
    expect(periodOf(new Date('2026-10-06T08:00:00Z'), DEFAULT_TIME_ZONE)).toEqual({
      month: '2026-10',
      start: new Date('2026-09-30T20:00:00Z'),
      end: new Date('2026-10-31T20:00:00Z'),
    });
  });

  it('puts the last millisecond before local midnight in the old month and midnight itself in the new', () => {
    expect(periodOf(new Date('2026-09-30T19:59:59.999Z'), DEFAULT_TIME_ZONE).month).toBe('2026-09');
    expect(periodOf(new Date('2026-09-30T20:00:00.000Z'), DEFAULT_TIME_ZONE).month).toBe('2026-10');
  });

  it('turns the year in December', () => {
    expect(periodOf(new Date('2026-12-31T19:00:00Z'), DEFAULT_TIME_ZONE)).toEqual({
      month: '2026-12',
      start: new Date('2026-11-30T20:00:00Z'),
      end: new Date('2026-12-31T20:00:00Z'),
    });
  });

  it('starts a month whose midnight the clocks skip at the end of the gap (Asunción, 1 October 2023)', () => {
    const october = periodOf(new Date('2023-10-15T12:00:00Z'), 'America/Asuncion');

    expect(october.start).toEqual(new Date('2023-10-01T04:00:00Z'));
    expect(periodOf(new Date('2023-10-01T03:59:59.999Z'), 'America/Asuncion').month).toBe('2023-09');
  });

  it('starts a month whose midnight happens twice at the earlier one (Havana, 1 November 2026)', () => {
    expect(periodOf(new Date('2026-11-15T12:00:00Z'), 'America/Havana').start).toEqual(
      new Date('2026-11-01T04:00:00Z'),
    );
  });

  it('holds every instant in exactly one month, in zones with and without daylight saving', () => {
    const zones = [
      DEFAULT_TIME_ZONE,
      'UTC',
      'Asia/Kathmandu',
      'Europe/London',
      'America/New_York',
      'America/Havana',
      'America/Asuncion',
      'Australia/Lord_Howe',
      'Pacific/Apia',
      'Pacific/Kiritimati',
      'Pacific/Pago_Pago',
    ];
    fc.assert(
      fc.property(
        fc.integer({ min: Date.UTC(2010, 0, 1), max: Date.UTC(2035, 0, 1) }),
        fc.constantFrom(...zones),
        (ms, zone) => {
          const at = new Date(ms);
          const { month, start, end } = periodOf(at, zone);

          expect(start.getTime()).toBeLessThanOrEqual(ms);
          expect(end.getTime()).toBeGreaterThan(ms);
          expect(localDate(at, zone).slice(0, 7)).toBe(month);
          expect(localDate(start, zone)).toBe(`${month}-01`);
          expect(localDate(new Date(start.getTime() - 1), zone).slice(0, 7)).not.toBe(month);
          // The next month starts where this one ends.
          expect(periodOf(end, zone).start).toEqual(end);
        },
      ),
      { numRuns: 2_000 },
    );
  });

  it('refuses a zone the runtime doesn’t know', () => {
    expect(() => periodOf(new Date('2026-10-06T00:00:00Z'), 'Mars/Olympus_Mons')).toThrow(RangeError);
    expect(isTimeZone('Mars/Olympus_Mons')).toBe(false);
    expect(isTimeZone(DEFAULT_TIME_ZONE)).toBe(true);
  });
});

describe('windowStart', () => {
  it('reaches back a whole number of hours, the default 24 across midnight', () => {
    expect(windowStart(new Date('2026-10-06T00:30:00Z'), 24)).toEqual(new Date('2026-10-05T00:30:00Z'));
    expect(windowStart(new Date('2026-10-06T00:30:00Z'), 1)).toEqual(new Date('2026-10-05T23:30:00Z'));
  });

  it.each([0, -1, 1.5, 745, Number.NaN])('refuses a window of %s hours', (hours) => {
    expect(() => windowStart(new Date('2026-10-06T00:00:00Z'), hours)).toThrow(RangeError);
  });
});
