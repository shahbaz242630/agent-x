// L5c: a background download's months, UTC, and the part of its range each
// holds; where each try's file is stored.
import { describe, expect, it } from 'vitest';

import { monthsOf, rangeInMonth, storedName } from './background-exports.ts';

const at = (iso: string) => new Date(iso);

describe('L5c a background download’s months', () => {
  it('are the UTC months its range touches, oldest first, by their first day', () => {
    expect(monthsOf({ from: at('2026-08-15T00:00:00Z'), to: at('2026-10-02T00:00:00Z') })).toEqual([
      '2026-08-01',
      '2026-09-01',
      '2026-10-01',
    ]);
  });

  it('end before a month its range stops at the start of, and cross a year', () => {
    expect(monthsOf({ from: at('2025-12-31T23:00:00Z'), to: at('2026-02-01T00:00:00Z') })).toEqual([
      '2025-12-01',
      '2026-01-01',
    ]);
    expect(monthsOf({ from: at('2026-03-01T00:00:00Z'), to: at('2026-03-01T00:00:00.001Z') })).toEqual(['2026-03-01']);
  });

  it('hold at most 13 for the longest range, 366 days', () => {
    expect(monthsOf({ from: at('2026-01-15T00:00:00Z'), to: at('2027-01-16T00:00:00Z') })).toHaveLength(13);
  });

  it('each hold the part of the range within them, the first and last cut to it', () => {
    const range = { from: at('2026-08-15T10:00:00Z'), to: at('2026-10-02T00:00:00Z') };

    expect(rangeInMonth(range, '2026-08-01')).toEqual({ from: range.from, to: at('2026-09-01T00:00:00Z') });
    expect(rangeInMonth(range, '2026-09-01')).toEqual({
      from: at('2026-09-01T00:00:00Z'),
      to: at('2026-10-01T00:00:00Z'),
    });
    expect(rangeInMonth(range, '2026-10-01')).toEqual({ from: at('2026-10-01T00:00:00Z'), to: range.to });
  });

  it('store each try’s file apart, under its organisation, download and month', () => {
    const name = (attempt: number) =>
      storedName('org', { exportId: 'export', month: '2026-08-01', attempt, format: 'ndjson' });

    expect(name(1)).toBe('org/export/2026-08-try1.ndjson.gz');
    expect(name(2)).toBe('org/export/2026-08-try2.ndjson.gz');
  });
});
