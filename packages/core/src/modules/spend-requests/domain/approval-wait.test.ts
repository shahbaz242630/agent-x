// Phase 3 E6 (partner decisions 15, 20): a waiting request's wait as its
// decided event sealed it, 72 hours for one sealed before E6; a value never
// offered is a bug, thrown; its expiry from its decision's sealed time.
import { describe, expect, it } from 'vitest';

import { approvalWaitOf, expiresAtOf, SHORTEST_APPROVAL_WAIT_MS, waitedOut } from './approval-wait.ts';

const HOUR = 3_600_000;
const decidedAt = new Date('2026-10-16T08:00:00.000Z');

describe('a waiting request’s wait (E6)', () => {
  it('reads each wait offered as sealed, and 72 hours for a decision sealed before E6', () => {
    expect(approvalWaitOf({ approvalWaitHours: 24 })).toBe(24);
    expect(approvalWaitOf({ approvalWaitHours: 48 })).toBe(48);
    expect(approvalWaitOf({ approvalWaitHours: 72 })).toBe(72);
    expect(approvalWaitOf({ decision: 'REQUIRE_APPROVAL' })).toBe(72);
    expect(approvalWaitOf(undefined)).toBe(72);
  });

  it('throws on a wait never offered: a bug, never guessed', () => {
    for (const sealed of [36, 0, 96, '24', null]) {
      expect(() => approvalWaitOf({ approvalWaitHours: sealed })).toThrow(/never offered/);
    }
  });

  it('expires a request its wait after its decision, not a millisecond before', () => {
    const clock = { decidedAt, waitHours: 24 } as const;
    const due = new Date(decidedAt.getTime() + 24 * HOUR);
    expect(expiresAtOf(clock)).toEqual(due);
    expect(waitedOut(clock, new Date(due.getTime() - 1))).toBe(false);
    expect(waitedOut(clock, due)).toBe(true);
    expect(waitedOut({ decidedAt, waitHours: 72 }, due)).toBe(false);
    expect(SHORTEST_APPROVAL_WAIT_MS).toBe(24 * HOUR);
  });
});
