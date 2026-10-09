import { describe, expect, it } from 'vitest';

import { money } from '../../../shared-kernel/index.ts';
import { type ClaimHolding, holdingsMatch, type RequestHolding, type ReservationHolding } from './holdings.ts';
import { SPEND_REQUEST, type SpendRequestStatus } from './spend-request.ts';

const request = (status: SpendRequestStatus): RequestHolding => ({
  agentId: 'agent',
  mandateId: 'mandate',
  supplierId: 'supplier',
  amount: money(100_000n, 'AED'),
  status,
});

const reservation = (overrides: Partial<ReservationHolding> = {}): ReservationHolding => ({
  agentId: 'agent',
  mandateId: 'mandate',
  supplierId: 'supplier',
  amountMinor: 100_000n,
  currency: 'AED',
  state: 'HELD',
  ...overrides,
});

const OPEN: ClaimHolding = { released: false, itsOwn: true };
const RELEASED: ClaimHolding = { released: true, itsOwn: true };

describe('what a request holds (E1)', () => {
  it.each(['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'] as const)(
    '%s: exactly one HELD reservation of its own and one open claim of its own',
    (status) => {
      expect(holdingsMatch(request(status), [reservation()], [OPEN])).toBe(true);

      expect(holdingsMatch(request(status), [], [OPEN])).toBe(false);
      expect(holdingsMatch(request(status), [reservation()], [])).toBe(false);
      expect(holdingsMatch(request(status), [reservation(), reservation()], [OPEN])).toBe(false);
      expect(holdingsMatch(request(status), [reservation()], [OPEN, OPEN])).toBe(false);
      expect(holdingsMatch(request(status), [reservation()], [RELEASED])).toBe(false);
      expect(holdingsMatch(request(status), [reservation()], [{ released: false, itsOwn: false }])).toBe(false);
      for (const state of ['RELEASED', 'FINALISED', 'BLOCKED_UNKNOWN']) {
        expect(holdingsMatch(request(status), [reservation({ state })], [OPEN])).toBe(false);
      }
      for (const changed of [
        { agentId: 'another' },
        { mandateId: 'another' },
        { supplierId: 'another' },
        { amountMinor: 99_999n },
        { currency: 'USD' },
      ]) {
        expect(holdingsMatch(request(status), [reservation(changed)], [OPEN])).toBe(false);
      }
    },
  );

  it('HANDED_OFF: its reservation follows the payment, never released, and its claim stays open', () => {
    for (const state of ['HELD', 'FINALISED', 'BLOCKED_UNKNOWN']) {
      expect(holdingsMatch(request('HANDED_OFF'), [reservation({ state })], [OPEN])).toBe(true);
    }
    expect(holdingsMatch(request('HANDED_OFF'), [reservation({ state: 'RELEASED' })], [OPEN])).toBe(false);
    expect(holdingsMatch(request('HANDED_OFF'), [reservation()], [RELEASED])).toBe(false);
    expect(holdingsMatch(request('HANDED_OFF'), [reservation({ amountMinor: 1n })], [OPEN])).toBe(false);
  });

  it.each(['DENIED', 'EXPIRED', 'CANCELLED'] as const)('%s: nothing held, or all of it given back', (status) => {
    expect(holdingsMatch(request(status), [], [])).toBe(true);
    expect(holdingsMatch(request(status), [reservation({ state: 'RELEASED' })], [RELEASED])).toBe(true);

    expect(holdingsMatch(request(status), [reservation()], [])).toBe(false);
    expect(holdingsMatch(request(status), [], [OPEN])).toBe(false);
    expect(
      holdingsMatch(request(status), [reservation({ state: 'RELEASED' }), reservation({ state: 'RELEASED' })], []),
    ).toBe(false);
    expect(holdingsMatch(request(status), [], [RELEASED, RELEASED])).toBe(false);
  });

  it('VALIDATING never matches: a request leaves it in the transaction that made it', () => {
    expect(holdingsMatch(request('VALIDATING'), [], [])).toBe(false);
    expect(holdingsMatch(request('VALIDATING'), [reservation()], [OPEN])).toBe(false);
  });

  it('knows every status', () => {
    for (const status of SPEND_REQUEST.states) expect(typeof holdingsMatch(request(status), [], [])).toBe('boolean');
  });
});
