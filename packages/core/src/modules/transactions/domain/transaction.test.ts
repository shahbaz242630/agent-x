// PRD §4.3 (Phase 4 B3): a transaction's machine, as 0058's status guard holds it.
import { describe, expect, it } from 'vitest';

import { isSettled, TRANSACTION } from './transaction.ts';

describe('the transaction’s machine (PRD §4.3)', () => {
  it('is born SUBMISSION_PENDING, never CREATED: the instruction and its transaction are made together', () => {
    expect(TRANSACTION.initial).toBe('SUBMISSION_PENDING');
    expect(TRANSACTION.isState('CREATED')).toBe(false);
  });

  it.each([
    ['SUBMISSION_PENDING', 'fail', 'FAILED'],
    ['SUBMISSION_PENDING', 'lose_track', 'UNKNOWN'],
    ['SUBMISSION_PENDING', 'submitted', 'SUBMITTED'],
    ['SUBMITTED', 'succeed', 'SUCCEEDED'],
    ['UNKNOWN', 'fail', 'FAILED'],
    ['UNKNOWN', 'cancel', 'CANCELLED'],
    ['SUCCEEDED', 'reverse', 'REVERSED'],
  ] as const)('moves %s by %s to %s', (from, event, to) => {
    expect(TRANSACTION.transition(from, event)).toMatchObject({ ok: true, to });
  });

  it.each([
    ['SUBMISSION_PENDING', 'succeed'],
    ['SUCCEEDED', 'fail'],
    ['FAILED', 'succeed'],
    ['FAILED', 'lose_track'],
    ['UNKNOWN', 'lose_track'],
    ['REVERSED', 'reverse'],
  ] as const)('SEC-DP-13 refuses %s by %s', (from, event) => {
    expect(TRANSACTION.transition(from, event).ok).toBe(false);
  });

  // Every event, from where nothing more is expected: a paid one only reversed, never lost track of again.
  const EVENTS = ['submitted', 'processing', 'succeed', 'fail', 'cancel', 'lose_track', 'reverse'] as const;
  it.each([
    ['SUBMISSION_PENDING', ['submitted', 'fail', 'lose_track']],
    ['SUCCEEDED', ['reverse']],
    ['FAILED', []],
    ['CANCELLED', []],
    ['REVERSED', []],
  ] as const)('SEC-DP-13 moves %s only by %j', (from, allowed) => {
    expect(EVENTS.filter((event) => TRANSACTION.transition(from, event).ok)).toEqual(allowed);
  });

  it('calls settled only an outcome nothing more is expected of but a reversal', () => {
    expect(TRANSACTION.states.filter(isSettled)).toEqual(['SUCCEEDED', 'FAILED', 'CANCELLED', 'REVERSED']);
  });
});
