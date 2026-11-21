import { describe, expect, it } from 'vitest';

import { money } from '../../../shared-kernel/index.ts';
import {
  type ClaimHolding,
  heldOf,
  holdingsMatch,
  holdsNow,
  type PaymentHolds,
  type RequestHolding,
  type ReservationHolding,
} from './holdings.ts';
import { SPEND_REQUEST, type SpendRequestStatus } from './spend-request.ts';

const AT = new Date('2026-10-08T08:00:00Z');

const SEAL = { mac: 'ab'.repeat(32), keyVersion: 1 };

const request = (
  status: SpendRequestStatus,
  held: RequestHolding['held'] = { month: '2026-10', reservedAt: AT, payee: SEAL, bankKeyed: true, windows: null },
) => ({
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
  payeeAsSealed: true,
  ...overrides,
});

const OPEN: ClaimHolding = { released: false, itsOwn: true, payeeAsSealed: true };
const RELEASED: ClaimHolding = { released: true, itsOwn: true, payeeAsSealed: true };

describe('an ended request whose signed ending kept its capacity (AT13d)', () => {
  const kept = (status: SpendRequestStatus) => ({ ...request(status), capacityKept: true });

  it.each(['DENIED', 'EXPIRED', 'CANCELLED'] as const)(
    '%s: its one reservation HELD as decided, its claim released',
    (status) => {
      expect(holdingsMatch(kept(status), [reservation()], [RELEASED])).toBe(true);
      expect(holdingsMatch(kept(status), [reservation()], [])).toBe(true);
    },
  );

  it('anything else is a mismatch: none held, released, or not as decided; its claim open', () => {
    const ended = kept('DENIED');
    expect(holdingsMatch(ended, [], [RELEASED])).toBe(false);
    for (const state of ['RELEASED', 'FINALISED', 'BLOCKED_UNKNOWN']) {
      expect(holdingsMatch(ended, [reservation({ state })], [RELEASED])).toBe(false);
    }
    for (const changed of [
      { amountMinor: 99_999n },
      { month: '2026-09' },
      { agentId: 'another' },
      { payeeAsSealed: false },
      { reservedAt: new Date(AT.getTime() - 1) },
    ]) {
      expect(holdingsMatch(ended, [reservation(changed)], [RELEASED])).toBe(false);
    }
    expect(holdingsMatch(ended, [reservation()], [OPEN])).toBe(false);
    expect(holdingsMatch(ended, [reservation(), reservation()], [RELEASED])).toBe(false);
  });

  it('a HELD reservation of an ended request whose ending kept nothing is the mismatch it always was', () => {
    expect(holdingsMatch(request('DENIED'), [reservation()], [RELEASED])).toBe(false);
    expect(holdingsMatch({ ...request('DENIED'), capacityKept: false }, [reservation()], [RELEASED])).toBe(false);
    expect(
      holdingsMatch({ ...request('DENIED'), capacityKept: false }, [reservation({ state: 'RELEASED' })], [RELEASED]),
    ).toBe(true);
    // Kept or not, a request still holding is judged as ever.
    expect(holdingsMatch({ ...request('APPROVED'), capacityKept: true }, [reservation()], [OPEN])).toBe(true);
  });
});

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
      expect(holdingsMatch(request(status), [reservation()], [{ ...OPEN, itsOwn: false }])).toBe(false);
      // E1b: a claim or reservation on another payee key than the decision sealed.
      expect(holdingsMatch(request(status), [reservation()], [{ ...OPEN, payeeAsSealed: false }])).toBe(false);
      expect(holdingsMatch(request(status), [reservation({ payeeAsSealed: false })], [OPEN])).toBe(false);
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

  describe('HANDED_OFF: as its payment says (Phase 4 C3)', () => {
    const handedOff = (payment?: PaymentHolds) => ({ ...request('HANDED_OFF'), payment });
    const STATES = ['HELD', 'FINALISED', 'BLOCKED_UNKNOWN', 'RELEASED'];

    it.each([
      ['following', 'HELD'],
      ['spent', 'FINALISED'],
      ['blocked', 'BLOCKED_UNKNOWN'],
    ] as const)('%s: its reservation %s, of its own, and its claim open', (payment, held) => {
      for (const state of STATES) {
        expect(holdingsMatch(handedOff(payment), [reservation({ state })], [OPEN]), state).toBe(state === held);
      }
      expect(holdingsMatch(handedOff(payment), [reservation({ state: held })], [RELEASED])).toBe(false);
      expect(holdingsMatch(handedOff(payment), [reservation({ state: held, amountMinor: 1n })], [OPEN])).toBe(false);
      expect(holdingsMatch(handedOff(payment), [reservation({ state: held, payeeAsSealed: false })], [OPEN])).toBe(
        false,
      );
      expect(holdingsMatch(handedOff(payment), [], [OPEN])).toBe(false);
    });

    it('ended (a verified failure or cancellation): all of it given back, as an ended request', () => {
      expect(holdingsMatch(handedOff('ended'), [reservation({ state: 'RELEASED' })], [RELEASED])).toBe(true);
      expect(holdingsMatch(handedOff('ended'), [reservation({ state: 'RELEASED' })], [OPEN])).toBe(false);
      for (const state of ['HELD', 'FINALISED', 'BLOCKED_UNKNOWN']) {
        expect(holdingsMatch(handedOff('ended'), [reservation({ state })], [RELEASED]), state).toBe(false);
      }
    });

    it('never matches a payment that can’t be read, or none given', () => {
      for (const payment of ['unreadable', undefined] as const) {
        for (const state of STATES) {
          expect(holdingsMatch(handedOff(payment), [reservation({ state })], [OPEN])).toBe(false);
          expect(holdingsMatch(handedOff(payment), [reservation({ state })], [RELEASED])).toBe(false);
        }
      }
    });
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
      payee: 'none',
      bankKeyed: false,
      windows: null,
    });
    // G5's decisions seal `possibleDuplicate`, whichever it was: their claims' bank keys are compared.
    for (const possibleDuplicate of [false, true]) {
      expect(heldOf({ heldMonth: '2026-10', heldAt: AT.toISOString(), possibleDuplicate })?.bankKeyed).toBe(true);
    }
    expect(heldOf({ heldMonth: '2026-10', heldAt: AT.toISOString(), possibleDuplicate: 'false' })?.bankKeyed).toBe(
      false,
    );
    expect(heldOf(undefined)).toBeNull();
    expect(heldOf({ decision: 'ALLOW' })).toBeNull();
    expect(heldOf({ heldMonth: '2026-10' })).toBeNull();
    expect(heldOf({ heldAt: AT.toISOString() })).toBeNull();
    expect(heldOf({ heldMonth: 202610, heldAt: AT.toISOString() })).toBeNull();
  });

  it('reads the payee windows a decision sealed (GM-1b): none before GM-1b, nor for text not in their form', () => {
    const windows = (sealed: unknown) =>
      heldOf({ heldMonth: '2026-10', heldAt: AT.toISOString(), payeeWindows: sealed });
    const a = '0199a0f0-0000-8000-8000-00000000a001';
    const b = '0199a0f0-0000-8000-8000-00000000b001';
    expect(windows(a)?.windows).toEqual([a]);
    expect(windows(`${a},${b}`)?.windows).toEqual([a, b]);
    for (const odd of [undefined, 7, '', a.toUpperCase(), `${a},`, `${a};${b}`, `${a},not-an-id`]) {
      expect(windows(odd)?.windows).toBeNull();
    }
  });

  it('reads the payee seal a decision sealed (E1b): none before E1b, unreadable if not whole', () => {
    const sealed = (payee: Record<string, unknown>) =>
      heldOf({ heldMonth: '2026-10', heldAt: AT.toISOString(), ...payee })?.payee;
    expect(sealed({ payeeSeal: SEAL.mac, payeeSealKeyVersion: 1 })).toEqual(SEAL);
    expect(sealed({ payeeSeal: SEAL.mac })).toBe('unreadable');
    expect(sealed({ payeeSealKeyVersion: 1 })).toBe('unreadable');
    expect(sealed({ payeeSeal: SEAL.mac.toUpperCase(), payeeSealKeyVersion: 1 })).toBe('unreadable');
    expect(sealed({ payeeSeal: SEAL.mac.slice(2), payeeSealKeyVersion: 1 })).toBe('unreadable');
    expect(sealed({ payeeSeal: SEAL.mac, payeeSealKeyVersion: 0 })).toBe('unreadable');
    expect(sealed({ payeeSeal: SEAL.mac, payeeSealKeyVersion: 1.5 })).toBe('unreadable');
    expect(sealed({ payeeSeal: SEAL.mac, payeeSealKeyVersion: '1' })).toBe('unreadable');
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
