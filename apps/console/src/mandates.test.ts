// 6D3a: a mandate's terms as typed, read by the API's own rules before
// anything is sent: amounts in dirhams read exactly as whole fils, the limits
// nested, every setting chosen; and which answers decide a draft sent with a
// held key, and what each says.
import { describe, expect, it } from 'vitest';

import { ApiError } from './api.ts';
import {
  amountMinor,
  amountTyped,
  amountWords,
  carryIn,
  currencyDigits,
  decidesTheDraft,
  draftBody,
  draftFailure,
  draftProblems,
  type DraftTyped,
  localTyped,
  mandateRefusal,
  type MandateVersion,
  NO_TERMS,
  termsBody,
  termsFrom,
  termsProblems,
  type TermsTyped,
} from './mandates.ts';
import { StepUpStorageBlocked } from './step-up.ts';

const SUPPLIER = '0199a0f0-0000-7000-8000-0000000000d1';
const SOURCE = '0199a0f0-0000-7000-8000-0000000000f1';
const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const NOW = Date.parse('2026-11-16T10:00:00.000Z');

const TERMS: TermsTyped = {
  purpose: 'Office supplies',
  perOrder: '2,500.50',
  monthly: '20000',
  threshold: '1000.5',
  supplierIds: [SUPPLIER],
  fundingSourceId: SOURCE,
  splitCheck: 'on',
  consentLimits: 'strict',
  ends: 'never',
  endsAt: '',
};
const DRAFT: DraftTyped = { ...TERMS, agentId: AGENT, timeZone: 'Asia/Dubai', splitWindowHours: '24' };

describe('an amount typed in dirhams (6D3a)', () => {
  it.each([
    ['2500', 250_000],
    ['2,500', 250_000],
    ['2,500.5', 250_050],
    ['2500.05', 250_005],
    [' 0.01 ', 1],
    ['1,000,000.00', 100_000_000],
    ['90071992547409.91', Number.MAX_SAFE_INTEGER],
    // Through floating point this reads 9007199254740898: one fils lost.
    ['90071992547408.99', 9_007_199_254_740_899],
  ])('reads %s as %d fils, exactly', (typed, fils) => {
    expect(amountMinor(typed)).toBe(fils);
  });

  it.each([
    '',
    '0',
    '0.00',
    '-5',
    '+5',
    '1.234',
    '1.',
    '.5',
    '1.2.3',
    '1..5',
    '1e3',
    '25,00',
    '2,5000',
    'AED 5',
    '90071992547409.92',
    '99999999999999999999',
  ])('refuses %j', (typed) => {
    expect(amountMinor(typed)).toBeUndefined();
  });

  it('reads a currency by its own minor digits', () => {
    expect(amountMinor('2500', 0)).toBe(2500);
    expect(amountMinor('2500.5', 0)).toBeUndefined();
    expect(amountMinor('1.234', 3)).toBe(1234);
    expect(amountMinor('1.2345', 3)).toBeUndefined();
    expect(amountTyped(2500, 0)).toBe('2500');
    expect(amountTyped(1234, 3)).toBe('1.234');
    expect(currencyDigits('AED')).toBe(2);
    expect(currencyDigits('JPY')).toBe(0);
    expect(currencyDigits('KWD')).toBe(3);
    expect(currencyDigits('A1')).toBeUndefined();
    // Intl formats any well-formed code: one it doesn't list as a currency isn't known.
    expect(currencyDigits('XYZ')).toBeUndefined();
    expect(currencyDigits('aed')).toBe(2);
  });

  it('says what to type in the account’s currency and digits, AED’s until one is chosen', () => {
    expect(amountWords(undefined)).toEqual({
      currency: 'AED',
      example: '2500.00',
      decimals: 'with at most 2 decimals',
    });
    expect(amountWords('JPY')).toEqual({ currency: 'JPY', example: '2500', decimals: 'with no decimals' });
    expect(amountWords('KWD')).toMatchObject({ example: '2500.000', decimals: 'with at most 3 decimals' });
    expect(amountWords('XYZ')).toMatchObject({ currency: 'XYZ', example: '2500.00' });
  });

  it('shows whole fils to change as they read back, never grouped', () => {
    expect(amountTyped(250_050)).toBe('2500.50');
    expect(amountTyped(1)).toBe('0.01');
    expect(amountMinor(amountTyped(Number.MAX_SAFE_INTEGER))).toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe('a version’s terms as typed', () => {
  it('finds nothing in terms the API would take, and sends them as it takes them', () => {
    expect(termsProblems(TERMS, NOW)).toEqual([]);
    expect(termsBody(TERMS, 'AED')).toEqual({
      purpose: 'Office supplies',
      currency: 'AED',
      perOrderLimitMinor: 250_050,
      monthlyLimitMinor: 2_000_000,
      approvalThresholdMinor: 100_050,
      supplierIds: [SUPPLIER],
      fundingSourceId: SOURCE,
      splitCheck: true,
      consentLimits: 'strict',
      endsAt: null,
    });
  });

  it('says every setting not chosen and every field not filled, none picked for the admin', () => {
    expect(termsProblems(NO_TERMS, NOW)).toEqual([
      'purpose',
      'perOrder',
      'monthly',
      'threshold',
      'suppliers',
      'source',
      'splitCheck',
      'consentLimits',
      'ends',
    ]);
  });

  it('keeps the limits nested: approval threshold ≤ per-order ≤ monthly', () => {
    expect(termsProblems({ ...TERMS, threshold: '2500.51' }, NOW)).toEqual(['thresholdAbove']);
    expect(termsProblems({ ...TERMS, perOrder: '20000.01', threshold: '1' }, NOW)).toEqual(['perOrderAbove']);
    expect(termsProblems({ ...TERMS, perOrder: '20000', threshold: '20000' }, NOW)).toEqual([]);
  });

  it('refuses a purpose the API wouldn’t take, and more than 100 suppliers', () => {
    expect(termsProblems({ ...TERMS, purpose: ' Office' }, NOW)).toEqual(['purpose']);
    expect(termsProblems({ ...TERMS, purpose: 'x'.repeat(201) }, NOW)).toEqual(['purpose']);
    const many = Array.from({ length: 101 }, (_, at) => `0199a0f0-0000-7000-8000-${String(at).padStart(12, '0')}`);
    expect(termsProblems({ ...TERMS, supplierIds: many }, NOW)).toEqual(['suppliers']);
  });

  it('takes an end only in the future, and sends it as an instant', () => {
    const ends = { ...TERMS, ends: 'on' as const };
    expect(termsProblems({ ...ends, endsAt: '' }, NOW)).toEqual(['endsAt']);
    expect(termsProblems({ ...ends, endsAt: 'not a time' }, NOW)).toEqual(['endsAt']);
    expect(termsProblems({ ...ends, endsAt: '2020-01-01T00:00' }, NOW)).toEqual(['endsAt']);
    const future = { ...ends, endsAt: '2099-01-01T10:30' };
    expect(termsProblems(future, NOW)).toEqual([]);
    expect(termsBody(future, 'AED').endsAt).toBe(new Date('2099-01-01T10:30').toISOString());
  });

  it('checks and sends the amounts by the bank account’s currency, and refuses one it can’t read', () => {
    expect(termsProblems(TERMS, NOW, 'JPY')).toEqual(['perOrder', 'threshold']);
    const yen = { ...TERMS, perOrder: '2,500', threshold: '1000' };
    expect(termsProblems(yen, NOW, 'JPY')).toEqual([]);
    expect(termsBody(yen, 'JPY')).toMatchObject({
      currency: 'JPY',
      perOrderLimitMinor: 2500,
      monthlyLimitMinor: 20_000,
    });
    expect(termsProblems(TERMS, NOW, 'A1')).toEqual(['currency']);
    expect(() => termsBody(TERMS, 'A1')).toThrow('Checked by termsProblems');
  });

  it('refuses to send terms not checked first', () => {
    expect(() => termsBody(NO_TERMS, 'AED')).toThrow('Checked by termsProblems');
  });
});

describe('a new mandate as typed', () => {
  it('checks its agent, zone and window, then its terms', () => {
    expect(draftProblems(DRAFT, NOW)).toEqual([]);
    expect(draftBody(DRAFT, 'AED')).toMatchObject({ agentId: AGENT, timeZone: 'Asia/Dubai', splitWindowHours: 24 });
    const none = { ...NO_TERMS, agentId: null, timeZone: '', splitWindowHours: '' };
    expect(draftProblems(none, NOW).slice(0, 3)).toEqual(['agent', 'timeZone', 'splitWindowHours']);
  });

  it.each(['0', '745', '1.5', '-1', '24h', '1000'])('refuses a split window of %j hours', (hours) => {
    expect(draftProblems({ ...DRAFT, splitWindowHours: hours }, NOW)).toEqual(['splitWindowHours']);
  });

  it.each(['1', '744'])('takes a split window of %s hours', (hours) => {
    expect(draftProblems({ ...DRAFT, splitWindowHours: hours }, NOW)).toEqual([]);
  });

  it('refuses a time zone the browser doesn’t know', () => {
    expect(draftProblems({ ...DRAFT, timeZone: 'Mars/Olympus' }, NOW)).toEqual(['timeZone']);
  });
});

describe('a version to change for a new one', () => {
  const version: MandateVersion = {
    id: AGENT,
    version: 1,
    purpose: 'Office supplies',
    currency: 'AED',
    perOrderLimitMinor: 250_050,
    monthlyLimitMinor: 2_000_000,
    approvalThresholdMinor: 100_000,
    supplierIds: [SUPPLIER],
    fundingSourceId: SOURCE,
    splitCheck: true,
    consentLimits: 'strict',
    endsAt: '2099-01-01T06:30:00.000Z',
    overLimit: 'refuse',
    termsHash: 'a'.repeat(64),
    draftedBy: AGENT,
    draftedAt: '2026-01-01T00:00:00.000Z',
    consentWarnings: [],
    capWarnings: [],
    splitCheckWarning: null,
  };

  it('fills in its terms and leaves every setting to be chosen again', () => {
    expect(termsFrom(version)).toEqual({
      purpose: 'Office supplies',
      perOrder: '2500.50',
      monthly: '20000.00',
      threshold: '1000.00',
      supplierIds: [SUPPLIER],
      fundingSourceId: SOURCE,
      splitCheck: null,
      consentLimits: null,
      ends: null,
      endsAt: localTyped('2099-01-01T06:30:00.000Z'),
    });
    expect(termsFrom({ ...version, endsAt: null }).endsAt).toBe('');
  });

  it('fills in amounts by the version’s own currency', () => {
    expect(termsFrom({ ...version, currency: 'JPY', perOrderLimitMinor: 2500 }).perOrder).toBe('2500');
  });

  it('shows an end in the browser’s own zone, to the minute', () => {
    expect(new Date(localTyped('2099-01-01T06:30:00.000Z')).toISOString()).toBe('2099-01-01T06:30:00.000Z');
  });
});

describe('a carry’s plan as the ask answers it', () => {
  it('reads the plan and how many wait their turn, and nothing from anything else', () => {
    const plan = [{ id: SUPPLIER, outcome: 'cancel', reasons: [] }];
    expect(carryIn({ carry: plan, carryLater: 3 })).toEqual({ plan, later: 3 });
    expect(carryIn({ carry: null, carryLater: 0 })).toEqual({ plan: [], later: 0 });
    expect(carryIn(null)).toEqual({ plan: [], later: 0 });
    expect(carryIn({})).toEqual({ plan: [], later: 0 });
  });
});

describe('a draft sent with a held key', () => {
  const refused = (status: number, code: string) => new ApiError(status, code);

  it('is decided by any refusal of a first send, never by no answer or a 5xx', () => {
    expect(decidesTheDraft(refused(409, 'MANDATE_OPEN'), false)).toBe(true);
    expect(decidesTheDraft(refused(409, 'STATEMENT_CHANGED'), false)).toBe(true);
    expect(decidesTheDraft(new TypeError('Failed to fetch'), false)).toBe(false);
    expect(decidesTheDraft(refused(503, 'INTEGRITY_FAILED'), false)).toBe(false);
  });

  it('asked again, is decided only past the gates', () => {
    expect(decidesTheDraft(refused(409, 'MANDATE_OPEN'), true)).toBe(true);
    for (const code of [
      'STATEMENT_CHANGED',
      'FORBIDDEN',
      'RATE_LIMITED',
      'IDEMPOTENCY_KEY_BUSY',
      'AGENT_BUSY',
      'ORGANISATION_BUSY',
      'PLATFORM_BUSY',
    ]) {
      expect(decidesTheDraft(refused(409, code), true)).toBe(false);
    }
    expect(decidesTheDraft(refused(401, 'UNAUTHENTICATED'), true)).toBe(false);
  });

  it('says why it is still held, or the refusal that ended it', () => {
    expect(draftFailure(refused(409, 'MANDATE_OPEN'), true)).toContain('already has a mandate');
    expect(draftFailure(new TypeError('Failed to fetch'), false)).toContain("isn't known yet");
    expect(draftFailure(refused(503, 'INTEGRITY_FAILED'), false)).toContain('integrity check');
    expect(draftFailure(refused(409, 'STATEMENT_CHANGED'), true)).toContain('Stop trying first');
    expect(draftFailure(refused(429, 'RATE_LIMITED'), true)).toMatch(/too many tries.*still held/s);
    // A held draft's body is checked before its key: refused as sent again, the first try may still stand.
    expect(decidesTheDraft(refused(400, 'BAD_REQUEST'), true)).toBe(true);
    expect(draftFailure(refused(400, 'BAD_REQUEST'), true)).toContain('the first try may have made it');
    expect(draftFailure(refused(400, 'BAD_REQUEST'), false)).toContain("couldn't accept what was entered");
  });
});

describe('a mandate change’s refusal', () => {
  it('is said in plain words, by its code when it has none, and a blocked browser as itself', () => {
    expect(mandateRefusal(new ApiError(409, 'MANDATE_NOT_SUSPENDED'))).toContain("isn't suspended");
    expect(mandateRefusal(new ApiError(409, 'SOMETHING_NEW'))).toContain('SOMETHING_NEW');
    expect(mandateRefusal(new StepUpStorageBlocked())).toContain('storage');
  });

  it.each([
    'AGENT_NOT_ACTIVE',
    'AGENT_ZONE_KEPT',
    'MANDATE_DRAFTS_SPENT',
    'MANDATE_DRAFT_EXPIRED',
    'MANDATE_ENDED',
    'MANDATE_NOT_ACCEPTED',
    'MANDATE_NOT_ACTIVE',
    'MANDATE_NOT_SUSPENDED',
    'MANDATE_NOT_WAITING',
    'MANDATE_OPEN',
    'MANDATE_PAST_CONSENT',
    'MANDATE_SUSPENDED',
    'PENDING_CHOICE_NOT_OFFERED',
    'PENDING_CHOICE_REQUIRED',
    'PENDING_REQUESTS_CANCELLED',
    'SOURCE_NOT_USABLE',
    'SUPPLIER_UNKNOWN',
    'HISTORY_TOO_LONG',
    'STATEMENT_CHANGED',
    'STEP_UP_NOT_ASKED',
    'IDEMPOTENCY_KEY_BUSY',
    'IDEMPOTENCY_KEY_REUSED',
    'RATE_LIMITED',
    'BAD_REQUEST',
    'FORBIDDEN',
    'NOT_FOUND',
  ])('says %s in its own plain words, never by its code', (code) => {
    expect(mandateRefusal(new ApiError(409, code))).not.toContain(code);
  });
});
