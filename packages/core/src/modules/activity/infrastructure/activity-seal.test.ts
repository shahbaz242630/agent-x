// L6: the daily seal's days: a UTC day holds the UUIDv7s made in it, from
// the floor of its first instant to the floor of the next day's; sealed only
// once it has been closed a while.
import { v7 } from 'uuid';
import { describe, expect, it } from 'vitest';

import { dayOfId, idsOfDay, nextDay, sealable, v7Floor } from './activity-seal.ts';

const ms = (iso: string) => Date.parse(iso);

describe('L6 the daily seal’s days', () => {
  it('floor a UUIDv7 to its instant, every bit after its time zero', () => {
    expect(v7Floor(0)).toBe('00000000-0000-0000-0000-000000000000');
    expect(v7Floor(ms('2026-10-19T00:00:00.000Z'))).toBe('01a15175-3c00-0000-0000-000000000000');
  });

  it('hold every UUIDv7 made in the day, the last millisecond in, the next day’s first out', () => {
    const { from, to } = idsOfDay('2026-10-19');
    const first = v7({ msecs: ms('2026-10-19T00:00:00.000Z') });
    const last = v7({ msecs: ms('2026-10-19T23:59:59.999Z') });
    const next = v7({ msecs: ms('2026-10-20T00:00:00.000Z') });

    expect(from <= first && first < to).toBe(true);
    expect(from <= last && last < to).toBe(true);
    expect(next >= to).toBe(true);
    expect(dayOfId(first)).toBe('2026-10-19');
    expect(dayOfId(last)).toBe('2026-10-19');
    expect(dayOfId(next)).toBe('2026-10-20');
  });

  it('follow one another across a month and a year, and refuse a day not named YYYY-MM-DD', () => {
    expect(nextDay('2026-10-31')).toBe('2026-11-01');
    expect(nextDay('2026-12-31')).toBe('2027-01-01');
    expect(nextDay('2028-02-28')).toBe('2028-02-29');
    expect(() => nextDay('19 October')).toThrow(new RangeError('A day is named YYYY-MM-DD'));
  });

  it('are sealed only once closed for 15 minutes', () => {
    expect(sealable('2026-10-19', new Date('2026-10-20T00:14:59.999Z'))).toBe(false);
    expect(sealable('2026-10-19', new Date('2026-10-20T00:15:00.000Z'))).toBe(true);
    expect(sealable('2026-10-20', new Date('2026-10-20T12:00:00.000Z'))).toBe(false);
  });
});
