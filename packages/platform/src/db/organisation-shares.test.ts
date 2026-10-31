import { afterEach, describe, expect, it, vi } from 'vitest';

import { createKeyedSlots } from './keyed-slots.ts';
import {
  createOrganisationShares,
  isLockWaitRunOut,
  OrganisationBusy,
  organisationShareOf,
} from './organisation-shares.ts';

const settled = () => new Promise<void>((resolve) => setImmediate(resolve));

afterEach(() => {
  vi.useRealTimers();
});

describe('an organisation’s share of the pool', () => {
  it.each([
    [1, 1],
    [3, 1],
    [4, 1],
    [10, 3],
    [20, 6],
    [100, 30],
  ])('of %i connections is %i', (poolMax, share) => {
    expect(organisationShareOf(poolMax)).toBe(share);
  });

  it('leaves others room with two organisations each at their share', () => {
    expect(10 - 2 * organisationShareOf(10)).toBe(4);
  });
});

describe('a lock’s wait run out', () => {
  it('is Postgres’s lock_not_available, and nothing else', () => {
    expect(isLockWaitRunOut(Object.assign(new Error('x'), { code: '55P03' }))).toBe(true);
    expect(isLockWaitRunOut(Object.assign(new Error('x'), { code: '57014' }))).toBe(false);
    expect(isLockWaitRunOut(new Error('x'))).toBe(false);
    expect(isLockWaitRunOut(null)).toBe(false);
    expect(isLockWaitRunOut('55P03')).toBe(false);
  });
});

describe('the slots behind a share', () => {
  it('lets the limit in at once, the rest in the order they came, and closes the line when none are left', async () => {
    const slots = createKeyedSlots({ perKey: 2, waitMs: 1000, exceeded: () => new Error('too long') });
    await slots.enter('a');
    await slots.enter('a');
    const order: string[] = [];
    const third = slots.enter('a').then(() => order.push('third'));
    const fourth = slots.enter('a').then(() => order.push('fourth'));
    await settled();
    expect(order).toEqual([]);
    slots.leave('a');
    await third;
    expect(order).toEqual(['third']);
    slots.leave('a');
    await fourth;
    expect(order).toEqual(['third', 'fourth']);
    expect(slots.keysInHand()).toBe(1);
    slots.leave('a');
    expect(slots.keysInHand()).toBe(1);
    slots.leave('a');
    expect(slots.keysInHand()).toBe(0);
  });

  it('keeps each key’s apart', async () => {
    const slots = createKeyedSlots({ perKey: 1, waitMs: 1000, exceeded: () => new Error('too long') });
    await slots.enter('a');
    await expect(slots.enter('b')).resolves.toBeUndefined();
    expect(slots.keysInHand()).toBe(2);
  });

  it('ignores a leave of a key not in hand', () => {
    const slots = createKeyedSlots({ perKey: 1, waitMs: 1000, exceeded: () => new Error('too long') });
    slots.leave('a');
    expect(slots.keysInHand()).toBe(0);
  });

  it('refuses past the wait, out of the line, so a leave passes to the next who still waits', async () => {
    vi.useFakeTimers();
    const shares = createOrganisationShares(1, 1000);
    await shares.enter('a');
    const refused = shares.enter('a');
    const check = expect(refused).rejects.toEqual(new OrganisationBusy(1000));
    await vi.advanceTimersByTimeAsync(500);
    let reached = false;
    const later = shares.enter('a').then(() => {
      reached = true;
    });
    await vi.advanceTimersByTimeAsync(500);
    await check;
    expect(reached).toBe(false);
    shares.leave('a');
    await later;
    expect(reached).toBe(true);
  });

  it('never refuses a waiter it let in before the wait ran out', async () => {
    vi.useFakeTimers();
    const shares = createOrganisationShares(1, 1000);
    await shares.enter('a');
    const waited = shares.enter('a');
    await vi.advanceTimersByTimeAsync(999);
    shares.leave('a');
    await vi.advanceTimersByTimeAsync(5000);
    await expect(waited).resolves.toBeUndefined();
  });
});
