// E4c, decision 17: what a new mandate version's terms do to each pending request carried over.
import { describe, expect, it } from 'vitest';

import { carries } from './mandate-carry.ts';

describe('a pending request weighed again under a new mandate version (E4c, decision 17)', () => {
  it('is cancelled when the new terms deny it, whatever its status', () => {
    for (const status of ['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'] as const) {
      for (const decidedAs of ['ALLOW', 'REQUIRE_APPROVAL'] as const) {
        expect(carries(status, decidedAs, 'DENY')).toBe(false);
        expect(carries(status, decidedAs, 'REQUIRE_NEW_MANDATE')).toBe(false);
      }
    }
  });

  it('is carried when the new terms allow it, a waiting one still waiting for its approver', () => {
    expect(carries('APPROVAL_REQUIRED', 'REQUIRE_APPROVAL', 'ALLOW')).toBe(true);
    expect(carries('APPROVED', 'ALLOW', 'ALLOW')).toBe(true);
    expect(carries('INSTRUCTION_READY', 'REQUIRE_APPROVAL', 'ALLOW')).toBe(true);
  });

  it('sent for approval: carried while waiting, or approved by a person; cancelled when no person approved it', () => {
    expect(carries('APPROVAL_REQUIRED', 'REQUIRE_APPROVAL', 'REQUIRE_APPROVAL')).toBe(true);
    expect(carries('APPROVED', 'REQUIRE_APPROVAL', 'REQUIRE_APPROVAL')).toBe(true);
    expect(carries('INSTRUCTION_READY', 'REQUIRE_APPROVAL', 'REQUIRE_APPROVAL')).toBe(true);
    expect(carries('APPROVED', 'ALLOW', 'REQUIRE_APPROVAL')).toBe(false);
    expect(carries('INSTRUCTION_READY', 'ALLOW', 'REQUIRE_APPROVAL')).toBe(false);
  });
});
