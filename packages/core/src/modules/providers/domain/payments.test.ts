// Phase 4 B2 (rail map §4; PRD §4.3; ADR-007 §9, §11): the partner's status
// mapped to the rail-neutral state, and the rail's key and reference rules.
import { describe, expect, it } from 'vitest';

import { PARTNER_IDEMPOTENCY_KEY, paymentStateOf, PROVIDER_STATUSES, RAIL_PAYMENT_REFERENCE } from './payments.ts';

describe('paymentStateOf (rail map §4)', () => {
  it.each([
    ['Pending', false, 'PROCESSING'],
    ['AcceptedSettlementCompleted', false, 'PROCESSING'],
    ['AcceptedWithoutPosting', false, 'PROCESSING'],
    // Only the creditor's account credited is success (STA-1 open: the safe choice holds the reservation).
    ['AcceptedCreditSettlementCompleted', false, 'SUCCEEDED'],
    // A rejection is a failure only with the partner's proof that nothing was debited.
    ['Rejected', true, 'FAILED'],
    ['Rejected', false, 'UNKNOWN'],
  ] as const)('%s, no debit proven %s: %s', (providerStatus, noDebitProven, state) => {
    expect(paymentStateOf({ providerStatus, noDebitProven })).toBe(state);
  });

  it('maps every one of the rail’s five statuses', () => {
    expect(PROVIDER_STATUSES).toHaveLength(5);
    for (const providerStatus of PROVIDER_STATUSES) {
      expect(['PROCESSING', 'SUCCEEDED', 'FAILED', 'UNKNOWN']).toContain(
        paymentStateOf({ providerStatus, noDebitProven: false }),
      );
    }
  });
});

describe('the rail’s key and payment reference', () => {
  it('takes a UUID as its idempotency key, never one with a space or past 40 characters', () => {
    expect(PARTNER_IDEMPOTENCY_KEY.test('0199a0f0-0000-7000-8000-0000000000e1')).toBe(true);
    expect(PARTNER_IDEMPOTENCY_KEY.test('a b')).toBe(false);
    expect(PARTNER_IDEMPOTENCY_KEY.test('x'.repeat(41))).toBe(false);
    expect(PARTNER_IDEMPOTENCY_KEY.test('')).toBe(false);
  });

  it('takes 1 to 35 of its own characters as a payment reference, nothing else', () => {
    expect(RAIL_PAYMENT_REFERENCE.test("INV-1001 /?:().,'+")).toBe(true);
    expect(RAIL_PAYMENT_REFERENCE.test('x'.repeat(35))).toBe(true);
    expect(RAIL_PAYMENT_REFERENCE.test('x'.repeat(36))).toBe(false);
    expect(RAIL_PAYMENT_REFERENCE.test('INV_1001')).toBe(false);
    expect(RAIL_PAYMENT_REFERENCE.test('فاتورة')).toBe(false);
  });
});
