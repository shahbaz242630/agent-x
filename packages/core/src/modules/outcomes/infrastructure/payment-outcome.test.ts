import { describe, expect, it } from 'vitest';

import { moveDetails, NO_FACTS } from './payment-outcome.ts';

describe('a move’s details (gate H1; ADR-007 §9)', () => {
  const INSTRUCTION = '01a16d8a-adf4-7045-8705-0543df50fb23';

  it('gives a fail with no reject code the bank’s reference as its evidence, or our instruction’s where it gave none', () => {
    expect(moveDetails('fail', { ...NO_FACTS, paymentInstructionRef: 'AANI-123' }, 'bank_check', INSTRUCTION)).toEqual({
      via: 'bank_check',
      evidenceRef: 'bank_status:AANI-123',
    });
    expect(moveDetails('fail', NO_FACTS, 'accepted', INSTRUCTION)).toEqual({
      via: 'accepted',
      evidenceRef: `bank_status:${INSTRUCTION}`,
    });
  });

  it('gives every other move its path alone: a reject code is its own proof, and no other move needs one', () => {
    expect(moveDetails('fail', { ...NO_FACTS, rejectCode: 'AANI.AM04' }, 'refused', INSTRUCTION)).toEqual({
      via: 'refused',
    });
    for (const event of ['submitted', 'processing', 'succeed', 'cancel', 'lose_track'] as const) {
      expect(moveDetails(event, NO_FACTS, 'accepted', INSTRUCTION)).toEqual({ via: 'accepted' });
    }
  });
});
