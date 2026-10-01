// ADR-014 §3 (E2-1): a beneficiary registration's moves, and the payee key's
// one source per partner, never mixed.
import { describe, expect, it } from 'vitest';

import { BENEFICIARY_REGISTRATION, payeeKeySource } from './registration.ts';

describe('a beneficiary registration (E2-1)', () => {
  it('starts STARTED and ends REGISTERED or FAILED, from STARTED or after a call lost on the way', () => {
    expect(BENEFICIARY_REGISTRATION.initial).toBe('STARTED');
    expect(BENEFICIARY_REGISTRATION.moves.map(({ from, to }) => `${from}>${to}`)).toEqual([
      'STARTED>REGISTERED',
      'UNKNOWN>REGISTERED',
      'STARTED>FAILED',
      'UNKNOWN>FAILED',
      'STARTED>UNKNOWN',
    ]);
  });

  it('is never moved again once it has ended, nor lost twice', () => {
    for (const ended of ['REGISTERED', 'FAILED'] as const) {
      expect(BENEFICIARY_REGISTRATION.isFinal(ended)).toBe(true);
    }
    expect(BENEFICIARY_REGISTRATION.transition('UNKNOWN', 'lost')).toMatchObject({ ok: false });
  });
});

describe('the payee key’s source (ADR-014 §3)', () => {
  const both = ['hosted', 'pass_through'];

  it('is the partner’s stable identity where it gives one, whatever the route', () => {
    const stable = { beneficiaryRoutes: both, stablePayeeIdentity: true };
    expect(payeeKeySource(stable, 'hosted')).toBe('partner');
    expect(payeeKeySource(stable, 'pass_through')).toBe('partner');
  });

  it('is our fingerprint with no identity, and pass-through the only route then, when the partner offers it', () => {
    const offer = { beneficiaryRoutes: both, stablePayeeIdentity: false };
    expect(payeeKeySource(offer, 'pass_through')).toBe('fingerprint');
    expect(() => payeeKeySource(offer, 'hosted')).toThrow(RangeError);
    expect(payeeKeySource({ beneficiaryRoutes: ['pass_through'], stablePayeeIdentity: false }, 'pass_through')).toBe(
      'fingerprint',
    );
  });

  it('is none only where the hosted form is all there is, with no identity (R-13)', () => {
    expect(payeeKeySource({ beneficiaryRoutes: ['hosted'], stablePayeeIdentity: false }, 'hosted')).toBe('none');
  });

  it('refuses a route the partner doesn’t offer', () => {
    expect(() => payeeKeySource({ beneficiaryRoutes: ['hosted'], stablePayeeIdentity: true }, 'pass_through')).toThrow(
      RangeError,
    );
    expect(() => payeeKeySource({ beneficiaryRoutes: ['pass_through'], stablePayeeIdentity: false }, 'hosted')).toThrow(
      RangeError,
    );
  });
});
