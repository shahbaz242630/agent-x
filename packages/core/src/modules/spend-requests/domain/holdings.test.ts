import { describe, expect, it } from 'vitest';

import { money } from '../../../shared-kernel/index.ts';
import {
  type ClaimHolding,
  heldOf,
  holdingsMatch,
  holdsNow,
  type RequestHolding,
  type ReservationHolding,
} from './holdings.ts';
import { SPEND_REQUEST, type SpendRequestStatus } from './spend-request.ts';

const AT = new Date('2026-10-08T08:00:00Z');

const request = (status: SpendRequestStatus, held: RequestHolding['held'] = { month: '2026-10', reservedAt: AT }) => ({
  agentId: 'agent',
  mandateId: 'mandate',
  supplierId: 'supplier',
  amount: money(100_000n, 'AED'),
  status,
  held,
});

const reservation = (overrides: Partial<ReservationHolding> = {}): ReservationHolding => ({
  agentId: 'agent',
  mandateId: 'mandate',
  supplierId: 'supplier',
  amountMinor: 100_000n,
  currency: 'AED',
  state: 'HELD',
  month: '2026-10',
  reservedAt: AT,
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
        { month: '2026-09' },
        { reservedAt: new Date(AT.getTime() - 1) },
      ]) {
        expect(holdingsMatch(request(status), [reservation(changed)], [OPEN])).toBe(false);
      }
    },
  );

  it('compares the month and instant only where the decision sealed them (decided before E1: none)', () => {
    const unsealed = request('APPROVED', null);
    expect(holdingsMatch(unsealed, [reservation({ month: '2026-09', reservedAt: new Date(0) })], [OPEN])).toBe(true);
    expect(holdingsMatch(unsealed, [reservation({ amountMinor: 1n })], [OPEN])).toBe(false);
  });

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

  it('reads the month and instant a decision sealed, and nothing from details that hold none', () => {
    expect(heldOf({ heldMonth: '2026-10', heldAt: AT.toISOString(), decision: 'ALLOW' })).toEqual({
      month: '2026-10',
      reservedAt: AT,
    });
    expect(heldOf(undefined)).toBeNull();
    expect(heldOf({ decision: 'ALLOW' })).toBeNull();
    expect(heldOf({ heldMonth: '2026-10' })).toBeNull();
    expect(heldOf({ heldAt: AT.toISOString() })).toBeNull();
    expect(heldOf({ heldMonth: 202610, heldAt: AT.toISOString() })).toBeNull();
  });

  it('says which statuses still hold anything', () => {
    expect(SPEND_REQUEST.states.filter(holdsNow)).toEqual([
      'APPROVAL_REQUIRED',
      'APPROVED',
      'INSTRUCTION_READY',
      'HANDED_OFF',
    ]);
  });

  it('knows every status', () => {
    for (const status of SPEND_REQUEST.states) expect(typeof holdingsMatch(request(status), [], [])).toBe('boolean');
  });
});
