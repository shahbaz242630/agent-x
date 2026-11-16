// 6D3b: a policy's rules as the console reads and builds them. Amounts typed
// are read exactly as whole minor units (never through floating point); a
// draft makes rules only once every choice is made, by the API's own rules
// (threshold ≤ per-order cap ≤ monthly cap; a mandate's within its terms).
import { describe, expect, it } from 'vitest';

import { ApiError } from './api.ts';
import {
  amountField,
  type Draft,
  draftFrom,
  type MandateTerms,
  parseAmount,
  policyRefusal,
  rulesFrom,
  waitingOffered,
  waitingSeen,
  wordsOf,
} from './policies.ts';
import { StepUpStorageBlocked } from './step-up.ts';

const SUPPLIER_A = '0199a0f0-0000-7000-8000-0000000000d1';
const SUPPLIER_B = '0199a0f0-0000-7000-8000-0000000000d2';
const SUPPLIER_C = '0199a0f0-0000-7000-8000-0000000000d3';

describe('reading a typed amount (6D3b)', () => {
  it.each([
    ['2500', 250_000],
    ['2500.5', 250_050],
    ['2500.50', 250_050],
    ['2,500.50', 250_050],
    ['1,234,567.89', 123_456_789],
    ['0.01', 1],
    [' 12 ', 1200],
    ['90071992547409.91', Number.MAX_SAFE_INTEGER],
    // 0.29 is no exact binary fraction: read as integers it stays 29 fils.
    ['0.29', 29],
    ['1.10', 110],
  ])('reads %s as %d fils', (typed, minor) => {
    expect(parseAmount(typed, 2)).toBe(minor);
  });

  it.each([
    ['', 'nothing'],
    ['0', 'zero'],
    ['0.00', 'zero with decimals'],
    ['-5', 'a sign'],
    ['+5', 'a plus'],
    ['2500.505', 'three decimals'],
    ['1e3', 'an exponent'],
    ['2 500', 'a space inside'],
    ['25,00', 'a comma out of place'],
    ['.5', 'no whole part'],
    ['5.', 'a point with nothing after'],
    ['90071992547409.92', 'past 2^53 − 1'],
    ['١٢', 'digits of another script'],
    ['AED 5', 'a currency'],
  ])('refuses %s (%s)', (typed) => {
    expect(parseAmount(typed, 2)).toBeNull();
  });

  it('reads a currency with no minor digits, and refuses a fraction in it', () => {
    expect(parseAmount('7', 0)).toBe(7);
    expect(parseAmount('7.5', 0)).toBeNull();
    expect(parseAmount('7.500', 3)).toBe(7500);
  });

  it('shows whole minor units for change exactly, and reads them back the same', () => {
    expect(amountField(250_050, 2)).toBe('2500.50');
    expect(amountField(1, 2)).toBe('0.01');
    expect(amountField(7, 0)).toBe('7');
    expect(amountField(Number.MAX_SAFE_INTEGER, 2)).toBe('90071992547409.91');
    expect(parseAmount(amountField(Number.MAX_SAFE_INTEGER, 2), 2)).toBe(Number.MAX_SAFE_INTEGER);
  });
});

/** A draft with every choice made: a cap of AED 1,000 refused above, AED 5,000 a month, approval above AED 500, any supplier. */
const made = (change: Partial<Draft> = {}): Draft => ({
  perOrder: 'cap',
  perOrderAmount: '1000',
  over: 'DENY',
  monthly: 'amount',
  monthlyAmount: '5000',
  threshold: 'amount',
  thresholdAmount: '500',
  suppliers: 'any',
  supplierIds: [],
  wait: '48',
  ...change,
});

const AED = { currency: 'AED', digits: 2, withWait: false };

const TERMS: MandateTerms = {
  currency: 'AED',
  perOrderLimitMinor: 100_000,
  monthlyLimitMinor: 500_000,
  approvalThresholdMinor: 50_000,
  supplierIds: [SUPPLIER_A, SUPPLIER_B],
  fundingSourceId: '0199a0f0-0000-7000-8000-0000000000f1',
};

describe('a draft of a policy’s rules (6D3b)', () => {
  it('starts with no choice made, the amount fields holding the rules in force', () => {
    const draft = draftFrom(
      {
        currency: 'AED',
        perOrderCap: { capMinor: 100_000, over: 'REQUIRE_APPROVAL' },
        monthlyCapMinor: null,
        approvalThresholdMinor: 25_050,
        supplierIds: [SUPPLIER_A],
      },
      2,
      2_000_000,
    );
    expect(draft).toStrictEqual({
      perOrder: null,
      perOrderAmount: '1000.00',
      over: null,
      monthly: null,
      // No monthly cap in force: the suggested amount, filled in only, never chosen.
      monthlyAmount: '20000.00',
      threshold: null,
      thresholdAmount: '250.50',
      suppliers: null,
      supplierIds: [SUPPLIER_A],
      wait: null,
    });
  });

  it('starts empty with no rules in force and nothing suggested', () => {
    expect(draftFrom(null, 2)).toStrictEqual({
      perOrder: null,
      perOrderAmount: '',
      over: null,
      monthly: null,
      monthlyAmount: '',
      threshold: null,
      thresholdAmount: '',
      suppliers: null,
      supplierIds: [],
      wait: null,
    });
  });

  it('makes no rules until every choice is made: each one not made is said', () => {
    expect(rulesFrom(draftFrom(null, 2), { ...AED, withWait: true })).toStrictEqual({
      problems: ['perOrder', 'monthly', 'threshold', 'suppliers', 'wait'],
    });
  });

  it('makes the rules chosen, in whole minor units', () => {
    expect(rulesFrom(made(), { ...AED, withWait: true })).toStrictEqual({
      rules: {
        currency: 'AED',
        perOrderCap: { capMinor: 100_000, over: 'DENY' },
        monthlyCapMinor: 500_000,
        approvalThresholdMinor: 50_000,
        supplierIds: null,
      },
      wait: 48,
    });
  });

  it('makes rules of none where none is chosen, whatever the fields hold, and no wait unless asked', () => {
    const none = made({ perOrder: 'none', over: null, monthly: 'none', threshold: 'none', perOrderAmount: 'x' });
    expect(rulesFrom(none, AED)).toStrictEqual({
      rules: {
        currency: 'AED',
        perOrderCap: null,
        monthlyCapMinor: null,
        approvalThresholdMinor: null,
        supplierIds: null,
      },
      wait: null,
    });
  });

  it('says an amount it can’t read, and a cap with no choice of what happens above it', () => {
    const draft = made({ perOrderAmount: '1,00', over: null, monthlyAmount: '-1', thresholdAmount: '0.001' });
    expect(rulesFrom(draft, AED)).toStrictEqual({
      problems: ['perOrderAmount', 'over', 'monthlyAmount', 'thresholdAmount'],
    });
  });

  it('holds the rules nested as the API does: threshold ≤ per-order cap ≤ monthly cap', () => {
    const draft = made({ perOrderAmount: '6000', thresholdAmount: '7000' });
    expect(rulesFrom(draft, AED)).toStrictEqual({
      problems: ['thresholdAbovePerOrder', 'perOrderAboveMonthly', 'thresholdAboveMonthly'],
    });
  });

  it('allows equal amounts', () => {
    const draft = made({ perOrderAmount: '5000', thresholdAmount: '5000' });
    expect('rules' in rulesFrom(draft, AED)).toBe(true);
  });

  it('sends the suppliers ticked, in order, and asks for 1 to 100', () => {
    const only = rulesFrom(made({ suppliers: 'only', supplierIds: [SUPPLIER_B, SUPPLIER_A] }), AED);
    expect('rules' in only && only.rules.supplierIds).toStrictEqual([SUPPLIER_A, SUPPLIER_B]);
    expect(rulesFrom(made({ suppliers: 'only', supplierIds: [] }), AED)).toStrictEqual({ problems: ['supplierIds'] });
    const many = Array.from({ length: 101 }, (_, n) => `0199a0f0-0000-7000-8000-${String(n).padStart(12, '0')}`);
    expect(rulesFrom(made({ suppliers: 'only', supplierIds: many }), AED)).toStrictEqual({ problems: ['supplierIds'] });
    // Any supplier: the ones ticked earlier are never sent.
    const any = rulesFrom(made({ suppliers: 'any', supplierIds: [SUPPLIER_A] }), AED);
    expect('rules' in any && any.rules.supplierIds).toBeNull();
  });

  it('holds a mandate’s rules within its terms, each rule past them said', () => {
    expect('rules' in rulesFrom(made(), { ...AED, within: TERMS })).toBe(true);
    const wider = made({
      perOrderAmount: '1000.01',
      monthlyAmount: '5000.01',
      thresholdAmount: '500.01',
      suppliers: 'only',
      supplierIds: [SUPPLIER_C.toUpperCase()],
    });
    expect(rulesFrom(wider, { ...AED, within: TERMS })).toStrictEqual({
      problems: ['perOrderAboveMandate', 'monthlyAboveMandate', 'thresholdAboveMandate', 'supplierOutsideMandate'],
    });
    // A supplier the mandate names, in another case, is the same supplier.
    const named = made({ suppliers: 'only', supplierIds: [SUPPLIER_A.toUpperCase()] });
    expect('rules' in rulesFrom(named, { ...AED, within: TERMS })).toBe(true);
  });

  it('holds a mandate’s rules of none within any terms', () => {
    const none = made({ perOrder: 'none', monthly: 'none', threshold: 'none' });
    expect('rules' in rulesFrom(none, { ...AED, within: TERMS })).toBe(true);
    expect('rules' in rulesFrom(none, { ...AED, within: null })).toBe(true);
  });
});

describe('the waiting requests a change would reject (6D3b)', () => {
  const listed = (id: string, codes: readonly string[]) => ({
    id,
    agentId: SUPPLIER_C,
    amountMinor: 100,
    currency: 'AED',
    reasons: codes.map((code) => ({ code, message: code, whatToDo: '' })),
  });

  it('offers a choice when any would be rejected, or more wait than were weighed', () => {
    expect(waitingOffered({ rejected: [], more: false })).toBe(false);
    expect(waitingOffered({ rejected: [], more: true })).toBe(true);
    expect(waitingOffered({ rejected: [listed(SUPPLIER_A, ['X'])], more: false })).toBe(true);
  });

  it('tells a plan apart by its requests, their rules and whether there are more, not by case', () => {
    const plan = { rejected: [listed(SUPPLIER_A, ['PER_ORDER_CAP'])], more: false };
    expect(waitingSeen(plan)).toBe(
      waitingSeen({ rejected: [listed(SUPPLIER_A.toUpperCase(), ['PER_ORDER_CAP'])], more: false }),
    );
    expect(waitingSeen(plan)).not.toBe(waitingSeen({ ...plan, more: true }));
    expect(waitingSeen(plan)).not.toBe(waitingSeen({ rejected: [listed(SUPPLIER_A, ['MONTHLY_CAP'])], more: false }));
    expect(waitingSeen(plan)).not.toBe(waitingSeen({ rejected: [listed(SUPPLIER_B, ['PER_ORDER_CAP'])], more: false }));
  });
});

describe('the API’s words for a choice (6D3b)', () => {
  const read = {
    statements: [{ id: 'waiting_requests', version: 4, words: [{ choice: 'reject', text: 'Rejected now.' }] }],
  };

  it('finds a choice’s words with their version, and none for a set or choice not read', () => {
    expect(wordsOf(read, 'waiting_requests', 'reject')).toStrictEqual({ version: 4, text: 'Rejected now.' });
    expect(wordsOf(read, 'waiting_requests', 'leave')).toBeUndefined();
    expect(wordsOf(read, 'monthly_cap', 'none')).toBeUndefined();
    expect(wordsOf(undefined, 'waiting_requests', 'reject')).toBeUndefined();
  });
});

describe('a policy’s refusals (6D3b)', () => {
  it.each([
    [new ApiError(409, 'POLICY_WIDER_THAN_MANDATE'), /goes past the mandate's own terms/],
    [new ApiError(409, 'POLICY_CHANGES_SPENT'), /as many times today/],
    [new ApiError(503, 'INTEGRITY_FAILED'), /integrity check/],
    [new ApiError(409, 'SOMETHING_NEW'), /reason SOMETHING_NEW/],
    [new ApiError(502, 'UNREADABLE'), /couldn't be reached/],
    [new StepUpStorageBlocked(), /keeps no site storage/],
  ])('says %s plainly', (error, said) => {
    expect(policyRefusal(error)).toMatch(said);
  });
});
