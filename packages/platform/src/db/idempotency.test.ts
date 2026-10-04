import { describe, expect, it } from 'vitest';

import { isUnwritten } from './idempotency.ts';

const RESULT = { status: 201, resourceId: '01a0ce75-93de-71d7-ba13-5979d5695a46' };

describe('isUnwritten', () => {
  it.each(['refused', 'conflict', 'busy'])('takes %s as final, with nothing written to read back', (outcome) => {
    expect(isUnwritten({ outcome })).toBe(true);
  });

  it.each(['done', 'replayed'])('leaves %s to read back what it wrote', (outcome) => {
    expect(isUnwritten({ outcome, result: RESULT })).toBe(false);
  });

  it('leaves any other answer, such as a step-up asked, to its caller', () => {
    expect(isUnwritten({ outcome: 'asked' })).toBe(false);
  });
});
