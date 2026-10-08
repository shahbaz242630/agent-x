// A policy's rules (Phase 2 C3; decision 5): their shape, and a mandate's own
// policy never wider than its mandate (SEC-LIM-11).
import { describe, expect, it } from 'vitest';

import { money } from '../../../shared-kernel/index.ts';
import { type PolicyRules, policyRules, PolicyRulesRefused, widerThanMandate } from './policy.ts';
import type { MandateTerms } from './terms.ts';

const aed = (dirhams: number) => money(BigInt(dirhams) * 100n, 'AED');
const fils = (minor: bigint) => money(minor, 'AED');
const A = '01a0ce75-93de-71d7-ba13-0000000000a1';
const B = '01a0ce75-93de-71d7-ba13-0000000000a2';

const NONE: PolicyRules = {
  currency: 'AED',
  perOrderCap: null,
  monthlyCap: null,
  approvalThreshold: null,
  supplierIds: null,
};

/** The BRD's example: AED 50,000 a month, 25,000 an order, approval above 10,000. */
const TERMS: MandateTerms = {
  purpose: 'Office supplies',
  perOrderLimit: aed(25_000),
  monthlyLimit: aed(50_000),
  approvalThreshold: aed(10_000),
  supplierIds: [A, B],
  fundingSourceId: '01a0ce75-93de-71d7-ba13-0000000000b1',
  splitCheck: true,
  consentLimits: 'strict',
  endsAt: null,
};

const refusal = (rules: PolicyRules): readonly string[] => {
  try {
    policyRules(rules);
  } catch (error) {
    if (error instanceof PolicyRulesRefused) return error.problems;
    throw error;
  }
  return [];
};

describe('policyRules', () => {
  it('keeps a policy that sets nothing, and one that sets every rule, nested', () => {
    expect(policyRules(NONE)).toEqual(NONE);
    const all = {
      ...NONE,
      perOrderCap: { cap: aed(5_000), over: 'REQUIRE_APPROVAL' as const },
      monthlyCap: aed(5_000),
      approvalThreshold: aed(5_000),
      supplierIds: [B.toUpperCase(), A],
    };
    expect(policyRules(all)).toEqual({ ...all, supplierIds: [A, B] });
  });

  it.each<[string, Partial<PolicyRules>, string]>([
    [
      'a threshold above the cap',
      { approvalThreshold: aed(2), perOrderCap: { cap: aed(1), over: 'DENY' } },
      'the approval threshold is above the per-order cap',
    ],
    [
      'a cap above the monthly cap',
      { perOrderCap: { cap: aed(2), over: 'DENY' }, monthlyCap: aed(1) },
      'the per-order cap is above the monthly cap',
    ],
    [
      'a threshold above the monthly cap',
      { approvalThreshold: aed(2), monthlyCap: aed(1) },
      'the approval threshold is above the monthly cap',
    ],
    ['an amount in another currency', { monthlyCap: money(1n, 'USD') }, 'the rules are not all in one currency'],
    [
      'a currency that is no ISO 4217 code, with no amount',
      { currency: 'aed' },
      'the currency is not an ISO 4217 code',
    ],
    ['an empty supplier list', { supplierIds: [] }, 'a supplier list names 1 to 100 suppliers'],
    [
      '101 suppliers',
      { supplierIds: Array.from({ length: 101 }, (_, i) => `01a0ce75-93de-71d7-ba13-${String(i).padStart(12, '0')}`) },
      'a supplier list names 1 to 100 suppliers',
    ],
    ['a supplier twice', { supplierIds: [A, A.toUpperCase()] }, 'a supplier is named twice'],
    ['a supplier not by ID', { supplierIds: ['acme'] }, 'a supplier is not named by its ID'],
  ])('refuses %s', (_what, change, problem) => {
    expect(refusal({ ...NONE, ...change })).toEqual([problem]);
  });

  it('weighs only rules that are set, and equal ones nest', () => {
    expect(refusal({ ...NONE, approvalThreshold: aed(9), perOrderCap: null, monthlyCap: null })).toEqual([]);
    expect(refusal({ ...NONE, perOrderCap: { cap: aed(3), over: 'DENY' }, monthlyCap: aed(3) })).toEqual([]);
  });
});

describe('widerThanMandate (SEC-LIM-11)', () => {
  it('is nothing for rules within the mandate, at its own limits', () => {
    const within = {
      ...NONE,
      perOrderCap: { cap: aed(25_000), over: 'DENY' as const },
      monthlyCap: aed(50_000),
      approvalThreshold: aed(10_000),
      supplierIds: [A],
    };
    expect(widerThanMandate(within, TERMS)).toEqual([]);
    expect(widerThanMandate(NONE, TERMS)).toEqual([]);
  });

  it('names each rule above the mandate’s, and a supplier it doesn’t name', () => {
    const wider = {
      ...NONE,
      perOrderCap: { cap: fils(2_500_001n), over: 'DENY' as const },
      monthlyCap: fils(5_000_001n),
      approvalThreshold: fils(1_000_001n),
      supplierIds: [A, '01a0ce75-93de-71d7-ba13-0000000000ff'],
    };
    expect(widerThanMandate(wider, TERMS)).toEqual([
      'the per-order cap is above the mandate’s',
      'the monthly cap is above the mandate’s',
      'the approval threshold is above the mandate’s',
      'a supplier is not one the mandate names',
    ]);
  });

  it('refuses another currency than the mandate’s', () => {
    expect(widerThanMandate({ ...NONE, currency: 'USD' }, TERMS)).toEqual([
      'the policy is not in the mandate’s currency',
    ]);
  });
});
