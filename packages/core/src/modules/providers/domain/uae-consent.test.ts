// Rail map §2 (D1-1): what each consent status makes of a source, and the
// moves the rail allows.
import { describe, expect, it } from 'vitest';

import { availabilityOf, CONSENT_STATUSES, consentMayMove, isConsentStatus } from './uae-consent.ts';

describe('a UAE payment consent (D1-1)', () => {
  it.each([
    ['AwaitingAuthorization', 'PENDING'],
    ['Authorized', 'ACTIVE'],
    ['Suspended', 'SUSPENDED'],
    ['Rejected', 'UNAVAILABLE'],
    ['Revoked', 'UNAVAILABLE'],
    ['Expired', 'UNAVAILABLE'],
    ['Consumed', 'UNAVAILABLE'],
  ] as const)('%s makes its source %s', (status, availability) => {
    expect(availabilityOf(status)).toBe(availability);
  });

  it('knows the standard’s seven statuses and nothing else', () => {
    expect(CONSENT_STATUSES).toHaveLength(7);
    expect(CONSENT_STATUSES.every(isConsentStatus)).toBe(true);
    for (const other of ['authorized', 'Active', '', null, 7]) expect(isConsentStatus(other)).toBe(false);
  });

  it('never leaves a terminal status, and never stays put', () => {
    for (const from of ['Rejected', 'Revoked', 'Expired', 'Consumed'] as const) {
      expect(CONSENT_STATUSES.filter((to) => consentMayMove(from, to))).toEqual([]);
    }
    for (const status of CONSENT_STATUSES) expect(consentMayMove(status, status)).toBe(false);
  });

  it('lets a suspended consent come back, and only an authorised one be consumed', () => {
    expect(consentMayMove('Suspended', 'Authorized')).toBe(true);
    expect(consentMayMove('Authorized', 'Consumed')).toBe(true);
    expect(consentMayMove('Suspended', 'Consumed')).toBe(false);
    expect(consentMayMove('AwaitingAuthorization', 'Suspended')).toBe(false);
  });
});
