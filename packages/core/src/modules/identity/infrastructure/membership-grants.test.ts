// OR1c: which throws a membership change answers as INTEGRITY_FAILED. Only a tamper sign has its alarm raised
// already; a programming error ('basis', 'lock_order') or anything else stays a 500, so it is never passed off as
// tampering (mutation pass S188, T16).
import { describe, expect, it } from 'vitest';

import { SignedStateFailed } from '../../audit/index.ts';
import { tamperThrown } from './membership-grants.ts';

describe('tamperThrown (OR1c)', () => {
  it('is true for a tamper sign alone', () => {
    expect(tamperThrown(new SignedStateFailed('tampered', 'a summary out of step'))).toBe(true);
  });

  it('is false for every other reason, a plain error, and nothing thrown as an error', () => {
    for (const reason of ['basis', 'lock_order', 'not_applied'] as const) {
      expect(tamperThrown(new SignedStateFailed(reason, 'not a tamper sign'))).toBe(false);
    }
    expect(tamperThrown(new Error('tampered'))).toBe(false);
    expect(tamperThrown({ name: 'SignedStateFailed', reason: 'tampered' })).toBe(false);
    expect(tamperThrown(undefined)).toBe(false);
  });
});
