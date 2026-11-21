// GM-1b: what a payee's window holds, hour by hour, as its sealed text writes it, and the split read from its rows.
import { describe, expect, it } from 'vitest';

import {
  heldAdded,
  heldByHourFrom,
  heldByHourText,
  heldSince,
  heldTaken,
  hourOf,
  keptFromHour,
  payeeSplit,
  windowFromHour,
} from './held-by-hour.ts';

const AT = new Date('2026-10-08T08:30:00Z');
const HOUR = hourOf(AT);

describe('an hour', () => {
  it('is the whole hour an instant falls in, from 1970', () => {
    expect(hourOf(new Date(0))).toBe(0);
    expect(hourOf(new Date(3_599_999))).toBe(0);
    expect(hourOf(new Date(3_600_000))).toBe(1);
    expect(hourOf(new Date('2026-10-08T08:00:00Z'))).toBe(HOUR);
    expect(hourOf(new Date('2026-10-08T08:59:59.999Z'))).toBe(HOUR);
  });

  it('counts a window from the hour its start falls in, whole: up to an hour more, never less', () => {
    // 24 hours back from 08:30 is 08:30 the day before: its whole hour, 08:00, counts.
    expect(windowFromHour(AT, 24)).toBe(HOUR - 24);
    expect(windowFromHour(new Date('2026-10-08T08:00:00Z'), 1)).toBe(HOUR - 1);
    expect(windowFromHour(AT, 744)).toBe(HOUR - 744);
    expect(() => windowFromHour(AT, 745)).toThrow(RangeError);
  });

  it('is kept as far back as the longest window counts, and one more for clocks a little apart', () => {
    expect(keptFromHour(AT)).toBe(HOUR - 745);
    expect(keptFromHour(AT)).toBeLessThan(windowFromHour(AT, 744));
  });
});

describe('the sealed text', () => {
  it('reads back what it writes: each hour holding anything, in order', () => {
    const held = new Map([
      [HOUR, 25_000n],
      [HOUR - 3, 1n],
      [HOUR - 1, 0n],
    ]);
    const text = heldByHourText(held);
    expect(text).toBe(`${String(HOUR - 3)}:1,${String(HOUR)}:25000`);
    expect(heldByHourFrom(text)).toEqual(
      new Map([
        [HOUR - 3, 1n],
        [HOUR, 25_000n],
      ]),
    );
    expect(heldByHourText(new Map())).toBe('');
    expect(heldByHourFrom('')).toEqual(new Map());
  });

  it('refuses text the app never writes: out of order, an hour twice, a zero, a leading zero, anything else', () => {
    for (const odd of ['2:5,1:5', '1:5,1:5', '1:0', '01:5', '1:05', '1:5,', ':5', '1:', '-1:5', '1:5 ', 'a:5']) {
      expect(heldByHourFrom(odd)).toBeUndefined();
    }
    expect(heldByHourFrom('0:5,1:9999999999999999999')).toEqual(
      new Map([
        [0, 5n],
        [1, 9_999_999_999_999_999_999n],
      ]),
    );
  });
});

describe('an amount added and taken', () => {
  it('adds at its hour, letting go of the hours no window counts', () => {
    const before = new Map([
      [HOUR - 800, 9n],
      [HOUR - 745, 7n],
      [HOUR, 5n],
    ]);
    expect(heldAdded(before, HOUR, 10n, keptFromHour(AT))).toEqual(
      new Map([
        [HOUR - 745, 7n],
        [HOUR, 15n],
      ]),
    );
    expect(heldAdded(new Map(), HOUR, 10n, keptFromHour(AT))).toEqual(new Map([[HOUR, 10n]]));
  });

  it('takes from each hour, to nothing and never below, saying when an hour held less', () => {
    const held = new Map([
      [HOUR - 2, 10n],
      [HOUR, 30n],
    ]);
    expect(heldTaken(held, [{ hour: HOUR, amount: 10n }], keptFromHour(AT))).toEqual({
      held: new Map([
        [HOUR - 2, 10n],
        [HOUR, 20n],
      ]),
      short: false,
    });
    expect(heldTaken(held, [{ hour: HOUR - 2, amount: 10n }], keptFromHour(AT))).toEqual({
      held: new Map([[HOUR, 30n]]),
      short: false,
    });
    expect(heldTaken(held, [{ hour: HOUR, amount: 31n }], keptFromHour(AT))).toEqual({
      held: new Map([[HOUR - 2, 10n]]),
      short: true,
    });
    expect(heldTaken(held, [{ hour: HOUR - 1, amount: 1n }], keptFromHour(AT)).short).toBe(true);
    // Several takes of one hour, each counted.
    expect(
      heldTaken(
        held,
        [
          { hour: HOUR, amount: 10n },
          { hour: HOUR, amount: 15n },
        ],
        keptFromHour(AT),
      ).held.get(HOUR),
    ).toBe(5n);
  });

  it('takes nothing from an hour already let go: no window counts it, so nothing is short', () => {
    const held = new Map([
      [HOUR - 800, 10n],
      [HOUR, 5n],
    ]);
    expect(heldTaken(held, [{ hour: HOUR - 800, amount: 10n }], keptFromHour(AT))).toEqual({
      held: new Map([[HOUR, 5n]]),
      short: false,
    });
  });
});

describe('a window read', () => {
  it('counts the hours from its first on', () => {
    const held = new Map([
      [HOUR - 25, 1n],
      [HOUR - 24, 10n],
      [HOUR, 100n],
    ]);
    expect(heldSince(held, HOUR - 24)).toBe(110n);
    expect(heldSince(held, HOUR - 25)).toBe(111n);
    expect(heldSince(held, HOUR + 1)).toBe(0n);
  });

  it("is the supplier's and the key's, less the pair's, never less than either alone", () => {
    expect(payeeSplit(50n, 0n, 0n)).toBe(50n);
    expect(payeeSplit(50n, 30n, 20n)).toBe(60n);
    expect(payeeSplit(50n, 50n, 50n)).toBe(50n);
    expect(payeeSplit(0n, 30n, 0n)).toBe(30n);
    // A pair's row holding more than the two share (past the app) takes nothing away from either.
    expect(payeeSplit(50n, 30n, 90n)).toBe(50n);
    expect(payeeSplit(30n, 50n, 90n)).toBe(50n);
  });
});
