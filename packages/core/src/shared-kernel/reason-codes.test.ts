import { describe, expect, it } from 'vitest';

import { isReasonCode, REASON_CODES } from './reason-codes.ts';

const entries = Object.entries(REASON_CODES);

describe('SEC-EVD-06 every reason code is registered and documented', () => {
  it('has codes to check (so the checks below are not vacuous)', () => {
    expect(entries.length).toBeGreaterThanOrEqual(4);
  });

  it.each(entries)('%s is written in capitals, words joined by underscores', (code) => {
    expect(code).toMatch(/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/);
  });

  it.each(entries)('%s has a description written as full sentences', (_code, description) => {
    expect(description).toMatch(/^[A-Z].{20,}[.]$/);
  });

  it('keeps codes in alphabetical order, so a new code is added where a reviewer expects it', () => {
    const codes = entries.map(([code]) => code);
    expect(codes).toEqual(codes.toSorted());
  });
});

describe('SEC-EVD-06 isReasonCode: a code read back from outside is checked', () => {
  it.each(entries)('accepts %s', (code) => {
    expect(isReasonCode(code)).toBe(true);
  });

  it.each(['', 'UNKNOWN_CODE', 'org_frozen', ' ORG_FROZEN', 'ORG_FROZEN ', 'ORG-FROZEN'])('refuses %j', (value) => {
    expect(isReasonCode(value)).toBe(false);
  });

  it.each(['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf'])(
    'refuses the inherited name %s',
    (value) => {
      expect(isReasonCode(value)).toBe(false);
    },
  );
});
