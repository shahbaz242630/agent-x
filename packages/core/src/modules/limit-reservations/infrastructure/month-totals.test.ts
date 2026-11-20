// GM-1a: the month total's rules that need no database (the rest are proven on
// the migrated schema, apps/api/src/month-totals.db.test.ts).
import { describe, expect, it } from 'vitest';

import type { SignedStates, VerifiedState } from '../../audit/index.ts';
import {
  checkMonthTotals,
  givenBack,
  monthTotalFrom,
  monthTotalKeyText,
  monthTotalOrder,
  reservationsHeldIn,
} from './month-totals.ts';

/** A transaction and signed states any use of which would fail: the rules below decide before either is touched. */
const NONE = null as never;
const STATES = {} as SignedStates;

const verified = (held: string | null): VerifiedState => ({
  outcome: 'verified',
  version: 1,
  eventId: '0199a0f0-0000-7000-8000-000000000001',
  recordedAt: new Date(0),
  fields: new Map([['held_minor', held]]),
});

describe('a month total read', () => {
  it('holds what its sealed amount says, from nothing up', () => {
    expect(monthTotalFrom(verified('0'))).toMatchObject({ outcome: 'held', held: 0n });
    expect(monthTotalFrom(verified('2500000'))).toMatchObject({ outcome: 'held', held: 2_500_000n });
    expect(monthTotalFrom({ outcome: 'missing' })).toEqual({ outcome: 'none' });
    expect(monthTotalFrom({ outcome: 'tampered', sign: 'seal' })).toEqual({ outcome: 'tampered', sign: 'seal' });
  });

  it('is never an amount its table refuses: one past it is a bug, thrown', () => {
    expect(() => monthTotalFrom(verified('-1'))).toThrow('holds no amount');
    expect(() => monthTotalFrom(verified('01'))).toThrow('holds no amount');
    expect(() => monthTotalFrom(verified(null))).toThrow('holds no amount');
  });
});

describe('the order totals are locked in', () => {
  it('is the order Postgres keeps uuids in: lower first, the same as equal', () => {
    const low = '0199a0f0-0000-7000-8000-00000000000a';
    const high = '0199a0f0-0000-7000-8000-0000000000a0';
    expect([high, low].toSorted(monthTotalOrder)).toEqual([low, high]);
    expect(monthTotalOrder(low, high)).toBe(-1);
    expect(monthTotalOrder(high, low)).toBe(1);
    expect(monthTotalOrder(low, low)).toBe(0);
  });
});

describe("a total's key as text", () => {
  it('names its agent in lower case, then its month and currency', () => {
    expect(monthTotalKeyText({ agentId: 'ABC', month: '2026-10', currency: 'AED' })).toBe('abc|2026-10|AED');
  });
});

describe('the rules decided before any read', () => {
  it('reads no reservations for no month asked', async () => {
    expect(await reservationsHeldIn(NONE, [])).toEqual(new Map());
  });

  it('gives nothing back to a total tampered with: its alarm was raised by its read', async () => {
    await givenBack(
      NONE,
      STATES,
      '0199a0f0-0000-7000-8000-000000000002',
      {
        key: { agentId: 'a', month: '2026-10', currency: 'AED' },
        total: { outcome: 'tampered', sign: 'seal' },
        amount: 1n,
      },
      {
        at: new Date(0),
        change: { actor: { type: 'system', id: 'test' }, action: 'month_total.released', details: {} },
      },
    );
  });

  it.each([null, undefined])('gives nothing back where there is no total to give back to (%s)', async (held) => {
    await givenBack(NONE, STATES, '0199a0f0-0000-7000-8000-000000000002', held, {
      at: new Date(0),
      change: { actor: { type: 'system', id: 'test' }, action: 'month_total.released', details: {} },
    });
  });

  it.each([0, 1.5, 201])('refuses a page of %s totals', async (limit) => {
    await expect(checkMonthTotals(NONE, STATES, 'org', { after: null, limit })).rejects.toThrow(RangeError);
  });
});
