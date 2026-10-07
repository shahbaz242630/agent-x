// ADR-006 §1–2 (SEC-LIM-07): money is whole minor units of one currency,
// never a float, and two currencies are never mixed.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { compare, money, MoneyRefused, moneyFromJson, plus, total, withinLimit } from './money.ts';

const aed = (minor: bigint) => money(minor, 'AED');

describe('money', () => {
  it('keeps whole minor units and the currency, frozen', () => {
    const amount = aed(150_000n);

    expect(amount).toEqual({ minor: 150_000n, currency: 'AED' });
    expect(Object.isFrozen(amount)).toBe(true);
  });

  it.each([
    ['a negative amount', () => aed(-1n)],
    ['a lower-case code', () => money(1n, 'aed')],
    ['a code of two letters', () => money(1n, 'AE')],
    ['a numeric code', () => money(1n, '784')],
  ])('refuses %s', (_what, make) => {
    expect(make).toThrow(MoneyRefused);
  });
});

describe('moneyFromJson', () => {
  it('takes a safe whole number as a bigint', () => {
    expect(moneyFromJson(Number.MAX_SAFE_INTEGER, 'AED')).toEqual(aed(BigInt(Number.MAX_SAFE_INTEGER)));
    expect(moneyFromJson(1, 'AED')).toEqual(aed(1n));
  });

  it.each([
    ['zero', 0],
    ['a negative', -5],
    ['a fraction', 10.5],
    ['past 2^53', 2 ** 53],
    ['a string', '100'],
    ['a bigint', 100n],
    ['not a number', Number.NaN],
    ['infinity', Number.POSITIVE_INFINITY],
    ['nothing', null],
  ])('refuses %s, never saying the amount', (_what, value) => {
    expect(() => moneyFromJson(value, 'AED')).toThrow(MoneyRefused);
    expect(() => moneyFromJson(value, 'AED')).not.toThrow(String(value));
  });
});

describe('arithmetic', () => {
  it('adds and totals one currency exactly, past what a float can hold', () => {
    const big = aed(BigInt(Number.MAX_SAFE_INTEGER));

    expect(plus(big, aed(2n)).minor).toBe(9_007_199_254_740_993n);
    expect(total([aed(1n), aed(2n), aed(3n)], 'AED')).toEqual(aed(6n));
    expect(total([], 'AED')).toEqual(aed(0n));
  });

  it('never mixes two currencies', () => {
    const usd = money(1n, 'USD');

    expect(() => plus(aed(1n), usd)).toThrow(MoneyRefused);
    expect(() => compare(aed(1n), usd)).toThrow(MoneyRefused);
    expect(() => total([usd], 'AED')).toThrow(MoneyRefused);
    expect(() => withinLimit(aed(1n), usd)).toThrow(MoneyRefused);
  });

  it('checks a limit inclusively: the limit itself is within it, one fil more is not', () => {
    expect(withinLimit(aed(500n), aed(500n))).toBe(true);
    expect(withinLimit(aed(501n), aed(500n))).toBe(false);
    expect(compare(aed(1n), aed(2n))).toBe(-1);
    expect(compare(aed(2n), aed(2n))).toBe(0);
    expect(compare(aed(3n), aed(2n))).toBe(1);
  });

  it('sums in any order to the same total, which is within a limit only when every part fits under it together', () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt({ min: 0n, max: 10n ** 15n }), { maxLength: 50 }),
        fc.bigInt({ min: 0n, max: 10n ** 16n }),
        (parts, limit) => {
          const amounts = parts.map(aed);
          const sum = total(amounts, 'AED');

          expect(total([...amounts].reverse(), 'AED')).toEqual(sum);
          expect(sum.minor).toBe(parts.reduce((a, b) => a + b, 0n));
          expect(withinLimit(sum, aed(limit))).toBe(sum.minor <= limit);
        },
      ),
    );
  });
});
