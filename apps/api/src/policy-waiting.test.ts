// Phase 3 F1 G8 (decision 33b): the choice past 20, and the leftovers a
// `reject` keeps on the policy's new version for the waiting-rejections job,
// 20 IDs a detail, read back only as a `reject` past 20 writes them.
import { describe, expect, it } from 'vitest';

import { MandateRefused } from './mandate-reads.ts';
import {
  leftoverOf,
  WAITING_LEFTOVER_KEYS,
  waitingChosen,
  waitingDetails,
  waitingHashParts,
  type WaitingPlan,
} from './policy-waiting.ts';

/** The nth made-up request ID, in lower case. */
const idOf = (n: number) => `0199a0f0-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;

const LISTED = Array.from({ length: 20 }, (_, at) => ({
  id: idOf(at),
  agentId: idOf(1000),
  amount: { minor: 100n, currency: 'AED' },
  reasons: ['POLICY_MONTHLY_CAP' as const],
}));

/** A plan of 20 listed and `leftover` more, the rest past them. */
const planOf = (leftover: number): WaitingPlan => ({
  rejected: LISTED,
  more: leftover > 0,
  leftover: Array.from({ length: leftover }, (_, at) => idOf(100 + at)),
});

describe('the choice past 20 (decision 33b)', () => {
  it('takes `reject` with more than 20, as `leave`', () => {
    expect(waitingChosen(planOf(5), 'reject')).toBe('reject');
    expect(waitingChosen(planOf(5), 'leave')).toBe('leave');
    expect(() => waitingChosen(planOf(5), undefined)).toThrow(MandateRefused);
  });

  it('binds the leftovers into the step-up for `reject` alone', () => {
    const plan = planOf(2);
    expect(waitingHashParts('reject', plan).slice(-3)).toEqual(['leftover', idOf(100), idOf(101)]);
    expect(waitingHashParts('leave', plan)).not.toContain('leftover');
    expect(waitingHashParts('reject', planOf(0))).toContain('leftover');
  });
});

describe('the leftovers kept on the version, and read back', () => {
  it('keeps 20 a detail, as many as needed, for `reject` alone; none past none', () => {
    const details = waitingDetails('reject', planOf(41));
    expect(details).toMatchObject({ waitingRequests: 'reject', waitingStatementVersion: 3, waitingMore: true });
    expect(Object.keys(details).filter((key) => key.startsWith('waitingLeftover'))).toEqual(
      WAITING_LEFTOVER_KEYS.slice(0, 3),
    );
    expect(leftoverOf(details)).toEqual(planOf(41).leftover);
    expect(Object.keys(waitingDetails('leave', planOf(41)))).not.toContain('waitingLeftover1');
    expect(Object.keys(waitingDetails('reject', planOf(0)))).not.toContain('waitingLeftover1');
    expect(waitingDetails(null, planOf(0))).toEqual({});
  });

  it('keeps the most a plan leaves, 80, in the four details, each within a detail’s 1,024 characters', () => {
    const details: Record<string, unknown> = waitingDetails('reject', planOf(80));
    for (const key of WAITING_LEFTOVER_KEYS) expect(String(details[key]).length).toBeLessThanOrEqual(1024);
    expect(leftoverOf(details)).toHaveLength(80);
  });

  it('reads none from an event that names none', () => {
    expect(leftoverOf({ waitingRequests: 'leave', waitingMore: true })).toEqual([]);
    expect(leftoverOf({})).toEqual([]);
  });

  it('believes none a `reject` past 20 never writes', () => {
    const one = { waitingRequests: 'reject', waitingMore: true, waitingLeftover1: idOf(1) };
    expect(leftoverOf(one)).toEqual([idOf(1)]);
    expect(leftoverOf({ ...one, waitingRequests: 'leave' })).toBeUndefined();
    expect(leftoverOf({ ...one, waitingMore: false })).toBeUndefined();
    expect(leftoverOf({ ...one, waitingMore: 'true' })).toBeUndefined();
    // A gap: the second given without the first.
    const { waitingLeftover1: _first, ...gap } = { ...one, waitingLeftover2: idOf(2) };
    expect(leftoverOf(gap)).toBeUndefined();
    expect(leftoverOf({ ...one, waitingLeftover1: 7 })).toBeUndefined();
    expect(leftoverOf({ ...one, waitingLeftover1: idOf(1).toUpperCase() })).toBeUndefined();
    expect(leftoverOf({ ...one, waitingLeftover1: `${idOf(1)}  ${idOf(2)}` })).toBeUndefined();
    const over = Array.from({ length: 21 }, (_, at) => idOf(at)).join(' ');
    expect(leftoverOf({ ...one, waitingLeftover1: over })).toBeUndefined();
  });
});
