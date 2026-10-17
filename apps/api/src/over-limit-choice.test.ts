// The over-limit choice's words and reads (Phase 3 decision 23, E9).
import { describe, expect, it } from 'vitest';

import { money } from '@agentx/core/shared-kernel';

import {
  consentCeilingOf,
  OVER_LIMIT_CHOICE,
  overLimitDetails,
  overLimitIn,
  overMandateLimit,
} from './over-limit-choice.ts';

describe('the over-limit choice (decision 23)', () => {
  it('is kept on the event with the version of its words', () => {
    expect(overLimitDetails('approval')).toEqual({ overLimit: 'approval', overLimitStatementVersion: 1 });
    expect(overLimitDetails('refuse')).toEqual({ overLimit: 'refuse', overLimitStatementVersion: 1 });
  });

  it('reads back only a choice it knows: none recorded (before E9) or anything else is null, so refused', () => {
    expect(overLimitIn({ overLimit: 'approval' })).toBe('approval');
    expect(overLimitIn({ overLimit: 'refuse' })).toBe('refuse');
    expect(overLimitIn({})).toBeNull();
    expect(overLimitIn(undefined)).toBeNull();
    expect(overLimitIn({ overLimit: 'APPROVAL' })).toBeNull();
  });

  it('takes no default: a body without it is refused', () => {
    expect(OVER_LIMIT_CHOICE.safeParse(undefined).success).toBe(false);
    expect(OVER_LIMIT_CHOICE.safeParse('ask').success).toBe(false);
  });

  it('finds a weighing past either of the mandate’s own limits, and nothing else', () => {
    expect(overMandateLimit(['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'])).toBe(true);
    expect(overMandateLimit(['MANDATE_MONTHLY_LIMIT'])).toBe(true);
    expect(overMandateLimit(['APPROVAL_THRESHOLD', 'POLICY_ORDER_CAP'])).toBe(false);
  });

  it('reaches a consent’s month only when it counts by the month: another period is never read as one', () => {
    const consent = { currency: 'AED', maxPayment: money(500n, 'AED'), maxPeriod: money(2_000n, 'AED') };
    expect(consentCeilingOf({ ...consent, limitPeriod: 'month' })).toEqual({
      maxPayment: money(500n, 'AED'),
      maxMonth: money(2_000n, 'AED'),
    });
    for (const limitPeriod of ['day', 'week', 'year'] as const) {
      expect(consentCeilingOf({ ...consent, limitPeriod })).toEqual({ maxPayment: money(500n, 'AED'), maxMonth: null });
    }
  });
});
