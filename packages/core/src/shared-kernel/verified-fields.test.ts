// A verified row's fields read back into their kinds: each reader's every outcome.
import { describe, expect, it } from 'vitest';

import { minorOf, oneOf, oneOfOrNull, timeOf, wholeOf } from './verified-fields.ts';

describe('the verified-field readers', () => {
  it('oneOf and oneOfOrNull: a word of theirs, null, or undefined', () => {
    expect(oneOf(['on', 'off'], 'on')).toBe('on');
    expect(oneOf(['on', 'off'], 'maybe')).toBeUndefined();
    expect(oneOfOrNull(['on', 'off'], null)).toBeNull();
    expect(oneOfOrNull(['on', 'off'], 'off')).toBe('off');
    expect(oneOfOrNull(['on', 'off'], undefined)).toBeUndefined();
  });

  it('timeOf: a time, null, or undefined for one missing or not a time', () => {
    expect(timeOf('2026-10-07T09:00:00.000Z')).toEqual(new Date('2026-10-07T09:00:00.000Z'));
    expect(timeOf(null)).toBeNull();
    expect(timeOf(undefined)).toBeUndefined();
    expect(timeOf('not a time')).toBeUndefined();
  });

  it('wholeOf: a whole number from 1, null, or undefined', () => {
    expect(wholeOf('24')).toBe(24);
    expect(wholeOf(null)).toBeNull();
    expect(wholeOf(undefined)).toBeUndefined();
    for (const value of ['0', '-1', '1.5', '01', '12345678901']) expect(wholeOf(value)).toBeUndefined();
  });

  it('minorOf: an amount from 1 as a bigint, or undefined for anything else, null included', () => {
    expect(minorOf('9007199254740993')).toBe(9_007_199_254_740_993n);
    for (const value of [null, undefined, '0', '-5', '1.5', '01', '1'.repeat(20)]) {
      expect(minorOf(value)).toBeUndefined();
    }
  });
});
