// GA4 (PRD §9.3): the money-path snapshot's own arithmetic, without a database:
// the window a pass reads at, how organisations' counts add up, and the line.
// money-path-snapshot.db.test.ts reads them from the migrated schema.
import { v7Floor } from '@agentx/core/modules/activity';
import type { MoneyPath } from '@agentx/core/modules/outcomes';
import { describe, expect, it } from 'vitest';

import { added, EXPIRED_WITHIN_MS, lineOf, STUCK_AFTER_MS, windowAt } from './money-path-snapshot.ts';

const NOW = new Date('2027-03-10T12:00:00.000Z');
const HOUR_MS = 60 * 60_000;

const none: MoneyPath = {
  approvalsWaiting: 0,
  approvalsExpired: 0,
  unknownPayments: 0,
  oldestUnknownAt: null,
  stuckPayments: 0,
  held: [],
};

describe('GA4 the money-path snapshot', () => {
  it('reads a pass at its time: a day of expiries, from the ID the oldest could have, an hour to be stuck', () => {
    expect(windowAt(NOW)).toEqual({
      now: NOW,
      expiredSince: new Date(NOW.getTime() - EXPIRED_WITHIN_MS),
      // The day, the longest wait (72 hours) and an hour spare.
      idFloor: v7Floor(NOW.getTime() - 24 * HOUR_MS - 72 * HOUR_MS - HOUR_MS),
      stuckBefore: new Date(NOW.getTime() - STUCK_AFTER_MS),
    });
    expect(STUCK_AFTER_MS).toBe(HOUR_MS);
  });

  it('adds organisations up: counts summed, the older UNKNOWN kept, money summed by currency past 2^53', () => {
    const older = new Date('2027-03-08T00:00:00.000Z');
    const newer = new Date('2027-03-09T00:00:00.000Z');
    const total = added([
      {
        approvalsWaiting: 2,
        approvalsExpired: 1,
        unknownPayments: 1,
        oldestUnknownAt: newer,
        stuckPayments: 0,
        held: [
          { currency: 'USD', reservations: 1, amountMinor: '500' },
          { currency: 'AED', reservations: 2, amountMinor: '9007199254740993' },
        ],
      },
      none,
      {
        approvalsWaiting: 3,
        approvalsExpired: 0,
        unknownPayments: 2,
        oldestUnknownAt: older,
        stuckPayments: 4,
        held: [{ currency: 'AED', reservations: 1, amountMinor: '7' }],
      },
      { ...none, unknownPayments: 1, oldestUnknownAt: newer },
    ]);
    expect(total).toEqual({
      approvalsWaiting: 5,
      approvalsExpired: 1,
      unknownPayments: 4,
      oldestUnknownAt: older,
      stuckPayments: 4,
      held: [
        { currency: 'AED', reservations: 3, amountMinor: '9007199254741000' },
        { currency: 'USD', reservations: 1, amountMinor: '500' },
      ],
    });
  });

  it('adds nothing up to nothing', () => {
    expect(added([])).toEqual(none);
  });

  it('logs the oldest UNKNOWN as its age in whole seconds, none where none is, never below zero', () => {
    const at = (oldestUnknownAt: Date | null) => lineOf({ ...none, oldestUnknownAt }, NOW).oldestUnknownSeconds;
    expect(at(null)).toBeNull();
    expect(at(new Date(NOW.getTime() - 90_500))).toBe(90);
    // A payment made a moment after the pass's time (another copy's clock).
    expect(at(new Date(NOW.getTime() + 2_000))).toBe(0);
    expect(lineOf({ ...none, approvalsExpired: 3, stuckPayments: 1 }, NOW)).toEqual({
      approvalsWaiting: 0,
      approvalsExpiredLastDay: 3,
      unknownPayments: 0,
      oldestUnknownSeconds: null,
      stuckPayments: 1,
      stuckAfterMinutes: 60,
      held: [],
    });
  });
});
