// PRD §4.2 (Phase 2 D1): a spend request's status.
import { describe, expect, it } from 'vitest';

import { SPEND_REQUEST } from './spend-request.ts';

describe('a spend request’s status (D1)', () => {
  it('starts VALIDATING, and moves only as 0039’s guard lists', () => {
    expect(SPEND_REQUEST.initial).toBe('VALIDATING');
    expect(SPEND_REQUEST.moves.map(({ from, to }) => `${from}>${to}`)).toEqual([
      'VALIDATING>DENIED',
      'APPROVAL_REQUIRED>DENIED',
      'APPROVED>DENIED',
      'INSTRUCTION_READY>DENIED',
      'VALIDATING>APPROVAL_REQUIRED',
      'VALIDATING>APPROVED',
      'APPROVAL_REQUIRED>APPROVED',
      'APPROVAL_REQUIRED>EXPIRED',
      'APPROVAL_REQUIRED>CANCELLED',
      'APPROVED>CANCELLED',
      'INSTRUCTION_READY>CANCELLED',
      'APPROVED>INSTRUCTION_READY',
      'INSTRUCTION_READY>HANDED_OFF',
    ]);
  });

  it('never moves on from DENIED, EXPIRED, CANCELLED or HANDED_OFF (PRD §4.2)', () => {
    const ended = ['DENIED', 'EXPIRED', 'CANCELLED', 'HANDED_OFF'];
    expect(SPEND_REQUEST.moves.filter(({ from }) => ended.includes(from))).toEqual([]);
  });
});
