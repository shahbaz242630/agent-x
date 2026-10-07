// PRD §3.1, partner S86–S87 (Phase 2 B2): a mandate version's terms, and how
// they stand against the bank consent.
import { describe, expect, it } from 'vitest';

import { money } from '../../../shared-kernel/index.ts';
import { type ConsentAllows, consentCheck, type MandateTerms, mandateTerms, MandateTermsRefused } from './terms.ts';

const NOW = new Date('2026-10-06T08:00:00Z');
const AED = (minor: number) => money(BigInt(minor), 'AED');
const SUPPLIER_A = '0199a000-0000-7000-8000-00000000000a';
const SUPPLIER_B = '0199a000-0000-7000-8000-00000000000b';

const TERMS: MandateTerms = {
  purpose: 'Office supplies',
  perOrderLimit: AED(500_000),
  monthlyLimit: AED(2_000_000),
  approvalThreshold: AED(100_000),
  supplierIds: [SUPPLIER_B, SUPPLIER_A],
  fundingSourceId: '0199a000-0000-7000-8000-0000000000f0',
  splitCheck: true,
  consentLimits: 'strict',
  endsAt: null,
};

const refused = (run: () => unknown): readonly string[] => {
  try {
    run();
  } catch (error) {
    if (error instanceof MandateTermsRefused) return error.problems;
    throw error;
  }
  throw new Error('Not refused');
};

describe('a mandate’s terms (B2)', () => {
  it('are kept with the purpose composed and the suppliers sorted in lower case', () => {
    const kept = mandateTerms(
      { ...TERMS, purpose: 'Café supplies', supplierIds: [SUPPLIER_B.toUpperCase(), SUPPLIER_A] },
      NOW,
    );

    expect(kept.purpose).toBe('Café supplies');
    expect(kept.supplierIds).toEqual([SUPPLIER_A, SUPPLIER_B]);
  });

  it('nest: approval threshold ≤ per-order ≤ monthly, equal allowed', () => {
    expect(() =>
      mandateTerms({ ...TERMS, approvalThreshold: AED(500_000), monthlyLimit: AED(500_000) }, NOW),
    ).not.toThrow();
    expect(refused(() => mandateTerms({ ...TERMS, approvalThreshold: AED(500_001) }, NOW))).toEqual([
      'the approval threshold is above the per-order limit',
    ]);
    expect(refused(() => mandateTerms({ ...TERMS, perOrderLimit: AED(2_000_001) }, NOW))).toEqual([
      'the per-order limit is above the monthly limit',
    ]);
  });

  it('are in one currency', () => {
    expect(refused(() => mandateTerms({ ...TERMS, monthlyLimit: money(2_000_000n, 'USD') }, NOW))).toEqual([
      'the limits are not all in one currency',
    ]);
  });

  it('name 1 to 100 suppliers, each once, by ID', () => {
    const many = Array.from({ length: 101 }, (_, i) => `0199a000-0000-7000-8000-${i.toString().padStart(12, '0')}`);

    expect(refused(() => mandateTerms({ ...TERMS, supplierIds: [] }, NOW))).toEqual([
      'the mandate names 1 to 100 suppliers',
    ]);
    expect(refused(() => mandateTerms({ ...TERMS, supplierIds: many }, NOW))).toEqual([
      'the mandate names 1 to 100 suppliers',
    ]);
    expect(() => mandateTerms({ ...TERMS, supplierIds: many.slice(1) }, NOW)).not.toThrow();
    expect(refused(() => mandateTerms({ ...TERMS, supplierIds: [SUPPLIER_A, SUPPLIER_A.toUpperCase()] }, NOW))).toEqual(
      ['a supplier is named twice'],
    );
    expect(refused(() => mandateTerms({ ...TERMS, supplierIds: ['Gulf Office'] }, NOW))).toEqual([
      'a supplier is not named by its ID',
    ]);
  });

  it('draw on a source named by its ID, and end in the future if they end', () => {
    expect(refused(() => mandateTerms({ ...TERMS, fundingSourceId: 'main account', endsAt: NOW }, NOW))).toEqual([
      'the funding source is not named by its ID',
      'the mandate ends in the past',
    ]);
    expect(() => mandateTerms({ ...TERMS, endsAt: new Date(NOW.getTime() + 1) }, NOW)).not.toThrow();
  });

  it('have a purpose that is a visible name of at most 200 characters', () => {
    expect(refused(() => mandateTerms({ ...TERMS, purpose: ' ' }, NOW))).toContain(
      'the purpose starts or ends with a space',
    );
    expect(refused(() => mandateTerms({ ...TERMS, purpose: 'x'.repeat(201) }, NOW))).toEqual([
      'the purpose is 1 to 200 characters',
    ]);
  });
});

describe('the terms against the bank consent (partner, S86–S87)', () => {
  const CONSENT: ConsentAllows = {
    currency: 'AED',
    maxPayment: AED(500_000),
    maxPeriod: AED(2_000_000),
    limitPeriod: 'month',
  };

  it('fit it with no problem', () => {
    expect(consentCheck(TERMS, CONSENT)).toEqual({ refused: false, problems: [] });
  });

  it('strict: refused past it, per payment and per month', () => {
    expect(consentCheck({ ...TERMS, perOrderLimit: AED(500_001), monthlyLimit: AED(2_000_001) }, CONSENT)).toEqual({
      refused: true,
      problems: [
        'the per-order limit is above the bank consent’s per payment',
        'the monthly limit is above the bank consent’s per month',
      ],
    });
  });

  it('flexible: kept past it, the problems its warnings', () => {
    expect(consentCheck({ ...TERMS, consentLimits: 'flexible', perOrderLimit: AED(500_001) }, CONSENT)).toEqual({
      refused: false,
      problems: ['the per-order limit is above the bank consent’s per payment'],
    });
  });

  it('compares the month only with a consent counted by the month', () => {
    expect(consentCheck({ ...TERMS, monthlyLimit: AED(9_000_000) }, { ...CONSENT, limitPeriod: 'week' })).toEqual({
      refused: false,
      problems: [],
    });
  });

  it('refuses another currency than the consent’s, flexible or not', () => {
    expect(consentCheck({ ...TERMS, consentLimits: 'flexible' }, { ...CONSENT, currency: 'USD' })).toEqual({
      refused: true,
      problems: ['the mandate is not in its funding source’s currency'],
    });
  });
});
