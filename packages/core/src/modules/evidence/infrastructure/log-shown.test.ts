// An event's facts as an organisation is shown them (E10) and as a spend
// request's evidence holds them (Phase 6 C2a, SEC-EVD-04): the platform's seals
// never shown, and in the evidence no fact whose name could carry a financial
// secret or a credential, whatever event records one later.
import { describe, expect, it } from 'vitest';

import { evidenceFacts, factsShown } from './log-shown.ts';

const namesOf = (facts: readonly (readonly [string, unknown])[]) => facts.map(([name]) => name);

describe('factsShown (E10: the platform’s seals left out)', () => {
  it('leaves out a signed state’s fingerprint and its key’s version, and keeps every other fact', () => {
    expect(
      namesOf(factsShown({ stateFingerprint: 'ab12', stateKeyVersion: 3, amountMinor: 500, status: 'HELD' })),
    ).toEqual(['amountMinor', 'status']);
  });
});

describe('evidenceFacts (SEC-EVD-04: no financial secret in the evidence)', () => {
  it.each([
    'payeeRef',
    'payee',
    'accountConsentId',
    'consentStatus',
    'beneficiaryRef',
    'iban',
    'accountNumber',
    'accountRef',
    'keyVersion',
    'stateKeyVersion',
    'stateFingerprint',
    'refreshToken',
    'clientSecret',
    'password',
    'credentialId',
    'mac',
    'MAC',
  ])('leaves out a fact named %s', (name) => {
    expect(evidenceFacts({ [name]: 'secret', status: 'HELD' })).toEqual([['status', 'HELD']]);
  });

  it('keeps the facts a request’s evidence needs, a name merely holding “mac” among them', () => {
    const facts = { spendRequestId: '0199a0f0-0000-7000-8000-00000000c2a1', amountMinor: 500, machine: 'rail-1' };
    expect(evidenceFacts(facts)).toEqual(Object.entries(facts));
  });
});
