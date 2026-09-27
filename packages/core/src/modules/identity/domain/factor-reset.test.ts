// SEC-OPS-04 (B6-3a): a reset's machine and its clocks.
import { describe, expect, it } from 'vitest';

import {
  confirmableAt,
  FACTOR_RESET,
  hasLapsed,
  isDue,
  isOpenReset,
  OPEN_RESET_STATUSES,
  RESET_CONFIRM_HOURS,
  RESET_COOLING_OFF_HOURS,
  resetCoolingOffUntil,
  resetExpiresAt,
} from './factor-reset.ts';

const at = new Date('2026-09-27T10:00:00.000Z');
const hours = (count: number): Date => new Date(at.getTime() + count * 3_600_000);

describe('SEC-OPS-04 a reset of a lost second factor', () => {
  it('starts as a draft and moves only as 0025’s guard lists', () => {
    expect(FACTOR_RESET.initial).toBe('DRAFT');
    expect(FACTOR_RESET.moves.map(({ from, to }) => `${from}>${to}`).sort()).toEqual(
      [
        'DRAFT>AWAITING_CONTACT',
        'AWAITING_CONTACT>COOLING_OFF',
        'COOLING_OFF>COMPLETED',
        'DRAFT>CANCELLED',
        'AWAITING_CONTACT>CANCELLED',
        'COOLING_OFF>CANCELLED',
        'DRAFT>EXPIRED',
        'AWAITING_CONTACT>EXPIRED',
      ].sort(),
    );
  });

  it('can’t be cancelled or lapse once the factor is removed, nor come back once closed', () => {
    for (const closed of ['COMPLETED', 'CANCELLED', 'EXPIRED'] as const) {
      expect(FACTOR_RESET.isFinal(closed)).toBe(true);
      expect(isOpenReset(closed)).toBe(false);
    }
    expect(FACTOR_RESET.transition('COOLING_OFF', 'expire')).toMatchObject({ ok: false, problem: 'not_allowed' });
    expect(OPEN_RESET_STATUSES.every((status) => isOpenReset(status))).toBe(true);
  });

  it('gives the contacts three days to confirm, up to but not at the lapse', () => {
    expect(RESET_CONFIRM_HOURS).toBe(72);
    expect(resetExpiresAt(at)).toEqual(hours(72));
    expect(confirmableAt(hours(72), new Date(hours(72).getTime() - 1))).toBe(true);
    expect(confirmableAt(hours(72), hours(72))).toBe(false);
  });

  it('B6-3b has lapsed only while waiting for its admin or a contact, from the lapse on', () => {
    const expiresAt = hours(72);
    const just = new Date(expiresAt.getTime() - 1);

    for (const status of ['DRAFT', 'AWAITING_CONTACT'] as const) {
      expect(hasLapsed({ status, expiresAt }, just)).toBe(false);
      expect(hasLapsed({ status, expiresAt }, expiresAt)).toBe(true);
    }
    for (const status of ['COOLING_OFF', 'COMPLETED', 'CANCELLED', 'EXPIRED'] as const) {
      expect(hasLapsed({ status, expiresAt }, hours(100))).toBe(false);
    }
  });

  it('is due a day after a contact confirmed, and only while cooling off', () => {
    expect(RESET_COOLING_OFF_HOURS).toBe(24);
    const until = resetCoolingOffUntil(at);
    expect(until).toEqual(hours(24));
    expect(isDue({ status: 'COOLING_OFF', coolingOffUntil: until }, new Date(until.getTime() - 1))).toBe(false);
    expect(isDue({ status: 'COOLING_OFF', coolingOffUntil: until }, until)).toBe(true);
    expect(isDue({ status: 'CANCELLED', coolingOffUntil: until }, hours(48))).toBe(false);
    expect(isDue({ status: 'COOLING_OFF', coolingOffUntil: null }, hours(48))).toBe(false);
  });
});
