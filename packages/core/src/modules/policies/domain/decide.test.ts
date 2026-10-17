// The decision engine (Phase 2 C2): SEC-LIM-05 (a policy never allows more
// than its mandate), SEC-LIM-06 (over the mandate's own limits is
// REQUIRE_NEW_MANDATE, never approval; precedence), SEC-LIM-11 (a narrower
// policy decides exactly as it states), SEC-AG-14 (free text never weighs),
// and partner decision 5 (the strictest rule wins, except the monthly cap per
// agent: the mandate's policy's, else the organisation's), with Phase 3
// decision 15 (E2): no default, nothing spent until an admin chooses it.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { type Money, money } from '../../../shared-kernel/index.ts';
import {
  type Decision,
  DECISIONS,
  decide,
  type DecisionInput,
  decisionFacts,
  decisionInputText,
  type MandateInForce,
  type PolicyRules,
  type SpendAsked,
  reasonsShownToAgent,
} from './decide.ts';

const aed = (dirhams: number): Money => money(BigInt(Math.round(dirhams * 100)), 'AED');

const AGENT = '01a0ce75-93de-71d7-ba13-000000000001';
const SUPPLIER = '01a0ce75-93de-71d7-ba13-0000000000a1';
const OTHER_SUPPLIER = '01a0ce75-93de-71d7-ba13-0000000000a2';
const SOURCE = '01a0ce75-93de-71d7-ba13-0000000000b1';
const NOW = new Date('2026-10-07T10:00:00Z');

/** FX-MANDATES: the BRD's example, AED 50,000 a month, AED 25,000 an order, approval above AED 10,000. */
const MANDATE: MandateInForce = {
  id: '01a0ce75-93de-71d7-ba13-0000000000c1',
  agentId: AGENT,
  status: 'ACTIVE',
  versionId: '01a0ce75-93de-71d7-ba13-0000000000c2',
  perOrderLimit: aed(25_000),
  monthlyLimit: aed(50_000),
  approvalThreshold: aed(10_000),
  supplierIds: [SUPPLIER, OTHER_SUPPLIER],
  fundingSourceId: SOURCE,
  splitCheck: true,
  endsAt: null,
  overLimit: 'refuse',
};

/** A policy that sets nothing, as an organisation's whose only row is there. */
const NO_RULES: PolicyRules = {
  versionId: '01a0ce75-93de-71d7-ba13-0000000000d1',
  perOrderCap: null,
  monthlyCap: null,
  approvalThreshold: null,
  supplierIds: null,
};

/** A request of `dirhams` that passes every check, unless `changes` say otherwise. */
function input(dirhams: number, changes: Partial<DecisionInput> = {}): DecisionInput {
  return {
    request: { amount: aed(dirhams), supplierId: SUPPLIER, fundingSourceId: SOURCE },
    now: NOW,
    agent: { id: AGENT, status: 'ACTIVE' },
    mandate: MANDATE,
    supplierStatus: 'VERIFIED',
    sourceMayFund: true,
    organizationPolicy: null,
    organizationCapChosen: true,
    mandatePolicy: null,
    monthSpent: aed(0),
    splitOpen: aed(0),
    duplicateOrder: false,
    possibleDuplicate: false,
    consent: { maxPayment: aed(100_000), maxMonth: aed(200_000) },
    ...changes,
  };
}

/** A request of AED 5,000 whose own fields `changes` say. */
const asking = (changes: Partial<SpendAsked>): DecisionInput => {
  const given = input(5_000);
  return { ...given, request: { ...given.request, ...changes } };
};

const orgPolicy = (rules: Partial<PolicyRules>): PolicyRules => ({ ...NO_RULES, ...rules });
const mandatePolicy = (rules: Partial<PolicyRules>): PolicyRules => ({
  ...NO_RULES,
  versionId: '01a0ce75-93de-71d7-ba13-0000000000e1',
  ...rules,
});

describe('decide: the mandate alone (SEC-LIM-06)', () => {
  it('allows an order within every limit, naming the versions weighed', () => {
    expect(decide(input(5_000))).toEqual({
      decision: 'ALLOW',
      reasons: [],
      versions: { mandate: MANDATE.versionId, organizationPolicy: null, mandatePolicy: null },
      monthlyCapFrom: 'none',
    });
  });

  it('allows an order exactly at the threshold, and asks approval one fils above it', () => {
    expect(decide(input(10_000)).decision).toBe('ALLOW');
    expect(decide(input(10_000.01))).toMatchObject({ decision: 'REQUIRE_APPROVAL', reasons: ['APPROVAL_THRESHOLD'] });
  });

  it('needs a new mandate one fils over the per-order limit, never an approval', () => {
    const policy = orgPolicy({ monthlyCap: aed(50_000) });
    expect(decide(input(25_000, { organizationPolicy: policy })).decision).toBe('REQUIRE_APPROVAL');
    expect(decide(input(25_000.01, { organizationPolicy: policy }))).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'],
    });
  });

  it("needs a new mandate when the month's total passes the mandate's monthly limit", () => {
    const policy = orgPolicy({ monthlyCap: aed(60_000) });
    const spent = { organizationPolicy: policy, monthSpent: aed(45_000) };
    expect(decide(input(5_000, spent)).decision).toBe('ALLOW');
    expect(decide(input(5_000.01, spent))).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_MONTHLY_LIMIT'],
    });
  });

  it.each<[string, Partial<DecisionInput>, string]>([
    ['the agent suspended', { agent: { id: AGENT, status: 'SUSPENDED' } }, 'AGENT_SUSPENDED'],
    ['no mandate', { mandate: null }, 'MANDATE_NOT_IN_FORCE'],
    [
      'a mandate waiting for acceptance',
      { mandate: { ...MANDATE, status: 'PENDING_ACCEPTANCE' } },
      'MANDATE_NOT_IN_FORCE',
    ],
    ['a suspended mandate', { mandate: { ...MANDATE, status: 'SUSPENDED' } }, 'MANDATE_NOT_IN_FORCE'],
    ['a revoked mandate', { mandate: { ...MANDATE, status: 'REVOKED' } }, 'MANDATE_NOT_IN_FORCE'],
    ['an expired mandate', { mandate: { ...MANDATE, status: 'EXPIRED' } }, 'MANDATE_NOT_IN_FORCE'],
    ['a mandate ending now', { mandate: { ...MANDATE, endsAt: NOW } }, 'MANDATE_NOT_IN_FORCE'],
    ['another agent’s mandate', { mandate: { ...MANDATE, agentId: SOURCE } }, 'MANDATE_NOT_IN_FORCE'],
    ['an unknown supplier', { supplierStatus: null }, 'SUPPLIER_NOT_VERIFIED'],
    ['an unverified supplier', { supplierStatus: 'UNVERIFIED' }, 'SUPPLIER_NOT_VERIFIED'],
    ['a suspended supplier', { supplierStatus: 'SUSPENDED' }, 'SUPPLIER_NOT_VERIFIED'],
    ['a source that may not fund', { sourceMayFund: false }, 'SOURCE_NOT_USABLE'],
    ['a duplicate order', { duplicateOrder: true }, 'DUPLICATE_ORDER_REFERENCE'],
    [
      'a supplier the mandate does not name',
      { mandate: { ...MANDATE, supplierIds: [OTHER_SUPPLIER] } },
      'SUPPLIER_NOT_ALLOWED',
    ],
  ])('denies %s', (_what, changes, reason) => {
    expect(decide(input(5_000, changes))).toMatchObject({ decision: 'DENY', reasons: [reason] });
  });

  it('allows a mandate ending a millisecond after the request', () => {
    expect(decide(input(5_000, { mandate: { ...MANDATE, endsAt: new Date(NOW.getTime() + 1) } })).decision).toBe(
      'ALLOW',
    );
  });

  it("denies a source other than the mandate's", () => {
    expect(decide(asking({ fundingSourceId: SUPPLIER }))).toMatchObject({
      decision: 'DENY',
      reasons: ['SOURCE_NOT_MANDATED'],
    });
  });

  it('denies, never throws, when any amount weighed is in another currency', () => {
    const usd = money(1n, 'USD');
    for (const given of [
      asking({ amount: money(9_999_999_999n, 'USD') }),
      input(5_000, { monthSpent: usd }),
      input(5_000, { splitOpen: usd }),
      input(5_000, { organizationPolicy: orgPolicy({ perOrderCap: { cap: usd, over: 'DENY' } }) }),
      input(5_000, { organizationPolicy: orgPolicy({ monthlyCap: usd }) }),
      input(5_000, { mandatePolicy: mandatePolicy({ approvalThreshold: usd }) }),
    ]) {
      expect(decide(given)).toMatchObject({ decision: 'DENY', reasons: ['CURRENCY_NOT_ALLOWED'] });
    }
  });

  it("weighs a mandate in another currency only against caps in its own (E2: no default's currency)", () => {
    const usd = (minor: bigint) => money(minor, 'USD');
    const limits = { perOrderLimit: usd(1_000n), monthlyLimit: usd(1_000n), approvalThreshold: usd(1_000n) };
    const inUsd = {
      ...asking({ amount: usd(1n) }),
      mandate: { ...MANDATE, ...limits },
      monthSpent: usd(0n),
      splitOpen: usd(0n),
    };
    expect(decide(inUsd).decision).toBe('ALLOW');
    expect(decide({ ...inUsd, organizationPolicy: orgPolicy({ monthlyCap: usd(500n) }) }).decision).toBe('ALLOW');
    const inAed = orgPolicy({ monthlyCap: aed(500) });
    expect(decide({ ...inUsd, organizationPolicy: inAed }).reasons).toEqual(['CURRENCY_NOT_ALLOWED']);
  });

  it('reads the IDs a request names in any case', () => {
    const upper = asking({ supplierId: SUPPLIER.toUpperCase(), fundingSourceId: SOURCE.toUpperCase() });
    expect(decide(upper).decision).toBe('ALLOW');
  });

  it('denies an expired mandate over its limit, with every failing reason (precedence)', () => {
    const ended = { mandate: { ...MANDATE, status: 'EXPIRED' }, supplierStatus: 'SUSPENDED' };
    expect(decide(input(30_000, ended))).toMatchObject({
      decision: 'DENY',
      reasons: ['SUPPLIER_NOT_VERIFIED', 'MANDATE_NOT_IN_FORCE'],
    });
    const capped = { organizationPolicy: orgPolicy({ monthlyCap: aed(20_000) }) };
    expect(decide(input(30_000, { ...capped, duplicateOrder: true }))).toMatchObject({
      decision: 'DENY',
      reasons: ['DUPLICATE_ORDER_REFERENCE', 'MANDATE_ORDER_LIMIT', 'POLICY_MONTHLY_CAP', 'APPROVAL_THRESHOLD'],
    });
  });
});

describe('decide: over the mandate’s own limits, sent for approval (decision 23)', () => {
  const approving = { ...MANDATE, overLimit: 'approval' as const };
  const policy = orgPolicy({ monthlyCap: aed(500_000) });
  const consent = (maxPayment: number, maxMonth: number | null) => ({
    maxPayment: aed(maxPayment),
    maxMonth: maxMonth === null ? null : aed(maxMonth),
  });

  it('asks approval past the per-order limit within the consent’s per payment, exactly at it too', () => {
    const at = { mandate: approving, organizationPolicy: policy, consent: consent(30_000, null) };
    expect(decide(input(30_000, at))).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'],
    });
    // Past the consent the bank would refuse it, which the team didn't set: named, so no approval rejects it for the limit.
    expect(decide(input(30_000.01, at))).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_ORDER_LIMIT', 'MANDATE_LIMIT_PAST_CONSENT', 'APPROVAL_THRESHOLD'],
    });
  });

  it('asks approval past the monthly limit within the consent’s month, exactly at it too', () => {
    const spent = { mandate: approving, organizationPolicy: policy, monthSpent: aed(45_000) };
    const at = { ...spent, consent: consent(100_000, 55_000) };
    expect(decide(input(10_000, at))).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['MANDATE_MONTHLY_LIMIT'],
    });
    expect(decide(input(10_000.01, at))).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_MONTHLY_LIMIT', 'MANDATE_LIMIT_PAST_CONSENT', 'APPROVAL_THRESHOLD'],
    });
    // A consent counted by another period is weighed per payment alone.
    expect(decide(input(10_000.01, { ...spent, consent: consent(100_000, null) })).decision).toBe('REQUIRE_APPROVAL');
  });

  it('needs a new mandate as always when the version chose refuse, or with no consent in its currency', () => {
    const past = { organizationPolicy: policy, consent: consent(100_000, null) };
    expect(decide(input(25_000.01, past))).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'],
    });
    // Within its own limits the consent is never named here, whatever it allows.
    expect(decide(input(5_000, { ...past, consent: consent(1_000, null) })).reasons).toEqual([]);
    expect(decide(input(25_000.01, { ...past, mandate: approving, consent: null })).decision).toBe(
      'REQUIRE_NEW_MANDATE',
    );
    const inUsd = { maxPayment: money(10_000_000n, 'USD'), maxMonth: null };
    expect(decide(input(25_000.01, { ...past, mandate: approving, consent: inUsd })).decision).toBe(
      'REQUIRE_NEW_MANDATE',
    );
  });

  it('still denies what the organisation’s cap or a refusing policy denies', () => {
    const past = { mandate: approving, consent: consent(100_000, null) };
    const lowCap = orgPolicy({ monthlyCap: aed(25_000) });
    expect(decide(input(25_000.01, { ...past, organizationPolicy: lowCap }))).toMatchObject({
      decision: 'DENY',
      reasons: ['MANDATE_ORDER_LIMIT', 'POLICY_MONTHLY_CAP', 'APPROVAL_THRESHOLD'],
    });
    const capped = orgPolicy({ monthlyCap: aed(500_000), perOrderCap: { cap: aed(25_000), over: 'DENY' } });
    expect(decide(input(25_000.01, { ...past, organizationPolicy: capped })).decision).toBe('DENY');
  });
});

describe('decide: a possible duplicate (decision 11a)', () => {
  it('asks approval for an order an open claim’s looks like, however small', () => {
    expect(decide(input(1, { possibleDuplicate: true }))).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['POSSIBLE_DUPLICATE_ORDER'],
    });
  });

  it('still denies the exact duplicate, and what the mandate refuses', () => {
    expect(decide(input(5_000, { duplicateOrder: true, possibleDuplicate: true }))).toMatchObject({
      decision: 'DENY',
      reasons: ['DUPLICATE_ORDER_REFERENCE', 'POSSIBLE_DUPLICATE_ORDER'],
    });
    expect(decide(input(30_000, { possibleDuplicate: true })).decision).toBe(decide(input(30_000)).decision);
  });
});

describe('decide: the split check (ADR-014 §5)', () => {
  it("asks approval when the supplier's open orders and this one cross the threshold together", () => {
    expect(decide(input(6_000, { splitOpen: aed(4_000) })).decision).toBe('ALLOW');
    expect(decide(input(6_000, { splitOpen: aed(4_000.01) }))).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['AGGREGATE_THRESHOLD'],
    });
  });

  it('adds nothing for an order over the threshold alone, and nothing with the check off', () => {
    expect(decide(input(12_000, { splitOpen: aed(9_000) })).reasons).toEqual(['APPROVAL_THRESHOLD']);
    const off = { mandate: { ...MANDATE, splitCheck: false }, splitOpen: aed(9_000) };
    expect(decide(input(6_000, off)).decision).toBe('ALLOW');
  });

  it("crosses the policies' lower threshold too", () => {
    const policy = mandatePolicy({ approvalThreshold: aed(5_000) });
    expect(decide(input(3_000, { mandatePolicy: policy, splitOpen: aed(2_500) }))).toMatchObject({
      decision: 'REQUIRE_APPROVAL',
      reasons: ['AGGREGATE_THRESHOLD'],
    });
  });
});

describe('decide: a narrower policy (SEC-LIM-11, decision 5)', () => {
  it.each<[string, 'organizationPolicy' | 'mandatePolicy']>([
    ["the organisation's", 'organizationPolicy'],
    ["the mandate's", 'mandatePolicy'],
  ])('%s per-order cap denies, or asks approval, as it says', (_whose, which) => {
    const under = (policy: PolicyRules): Partial<DecisionInput> =>
      which === 'organizationPolicy' ? { organizationPolicy: policy } : { mandatePolicy: policy };
    const deny = under(orgPolicy({ perOrderCap: { cap: aed(4_000), over: 'DENY' } }));
    expect(decide(input(4_000, deny)).decision).toBe('ALLOW');
    expect(decide(input(4_000.01, deny))).toMatchObject({ decision: 'DENY', reasons: ['POLICY_ORDER_CAP'] });
    const ask = under(orgPolicy({ perOrderCap: { cap: aed(4_000), over: 'REQUIRE_APPROVAL' } }));
    expect(decide(input(4_000.01, ask))).toMatchObject({ decision: 'REQUIRE_APPROVAL', reasons: ['POLICY_ORDER_CAP'] });
  });

  it('applies both caps, the stricter outcome winning', () => {
    const both = {
      organizationPolicy: orgPolicy({ perOrderCap: { cap: aed(8_000), over: 'DENY' } }),
      mandatePolicy: mandatePolicy({ perOrderCap: { cap: aed(3_000), over: 'REQUIRE_APPROVAL' } }),
    };
    expect(decide(input(5_000, both)).decision).toBe('REQUIRE_APPROVAL');
    expect(decide(input(9_000, both))).toMatchObject({ decision: 'DENY', reasons: ['POLICY_ORDER_CAP'] });
  });

  it('takes the lowest approval threshold of the three', () => {
    const thresholds = {
      organizationPolicy: orgPolicy({ approvalThreshold: aed(7_000) }),
      mandatePolicy: mandatePolicy({ approvalThreshold: aed(8_000) }),
    };
    expect(decide(input(7_000, thresholds)).decision).toBe('ALLOW');
    expect(decide(input(7_000.01, thresholds)).reasons).toEqual(['APPROVAL_THRESHOLD']);
    const higher = { organizationPolicy: orgPolicy({ approvalThreshold: aed(20_000) }) };
    expect(decide(input(10_000.01, higher)).reasons).toEqual(['APPROVAL_THRESHOLD']);
  });

  it("denies a supplier either policy's list leaves out", () => {
    const narrowed = orgPolicy({ supplierIds: [OTHER_SUPPLIER] });
    expect(decide(input(5_000, { organizationPolicy: narrowed }))).toMatchObject({
      decision: 'DENY',
      reasons: ['POLICY_SUPPLIER_NOT_ALLOWED'],
    });
    expect(decide(input(5_000, { mandatePolicy: narrowed })).reasons).toEqual(['POLICY_SUPPLIER_NOT_ALLOWED']);
    expect(decide(input(5_000, { mandatePolicy: orgPolicy({ supplierIds: [SUPPLIER] }) })).decision).toBe('ALLOW');
    // An empty list allows no one: never read as no list.
    expect(decide(input(5_000, { mandatePolicy: orgPolicy({ supplierIds: [] }) })).reasons).toEqual([
      'POLICY_SUPPLIER_NOT_ALLOWED',
    ]);
  });

  it("weighs a policy's supplier list with no mandate in force too", () => {
    const narrowed = orgPolicy({ supplierIds: [OTHER_SUPPLIER] });
    expect(decide(input(5_000, { mandate: null, organizationPolicy: narrowed })).reasons).toEqual([
      'MANDATE_NOT_IN_FORCE',
      'POLICY_SUPPLIER_NOT_ALLOWED',
    ]);
  });
});

describe('decide: the monthly cap per agent (decision 5)', () => {
  it("denies every request until an admin chose the organisation's, even under a mandate's policy's cap (E2)", () => {
    const unchosen = { organizationPolicy: NO_RULES, organizationCapChosen: false };
    expect(decide(input(1, unchosen))).toMatchObject({
      decision: 'DENY',
      reasons: ['ORG_MONTHLY_CAP_NOT_SET'],
      monthlyCapFrom: 'not-set',
    });
    expect(decide(input(1, { ...unchosen, organizationPolicy: null })).reasons).toEqual(['ORG_MONTHLY_CAP_NOT_SET']);
    const capped = { ...unchosen, mandatePolicy: mandatePolicy({ monthlyCap: aed(30_000) }) };
    expect(decide(input(1, capped))).toMatchObject({
      decision: 'DENY',
      reasons: ['ORG_MONTHLY_CAP_NOT_SET'],
      monthlyCapFrom: 'not-set',
    });
  });

  it("holds the agent to the mandate's own monthly limit alone with none chosen, no default (E2)", () => {
    const none = { organizationPolicy: NO_RULES, monthSpent: aed(45_000) };
    expect(decide(input(5_000, none))).toMatchObject({ decision: 'ALLOW', reasons: [], monthlyCapFrom: 'none' });
    expect(decide(input(5_000.01, none))).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_MONTHLY_LIMIT'],
    });
  });

  it("is the organisation's when it sets one, higher or lower", () => {
    const lower = { organizationPolicy: orgPolicy({ monthlyCap: aed(8_000) }), monthSpent: aed(3_000) };
    expect(decide(input(5_000, lower))).toMatchObject({ decision: 'ALLOW', monthlyCapFrom: 'organization-policy' });
    expect(decide(input(5_000.01, lower)).reasons).toEqual(['POLICY_MONTHLY_CAP']);
    const higher = { organizationPolicy: orgPolicy({ monthlyCap: aed(40_000) }), monthSpent: aed(30_000) };
    expect(decide(input(5_000, higher)).decision).toBe('ALLOW');
  });

  it("is the mandate's policy's when it sets one, above the organisation's or below it", () => {
    const organizationPolicy = orgPolicy({ monthlyCap: aed(8_000) });
    const above = {
      organizationPolicy,
      mandatePolicy: mandatePolicy({ monthlyCap: aed(30_000) }),
      monthSpent: aed(20_000),
    };
    expect(decide(input(5_000, above))).toMatchObject({ decision: 'ALLOW', monthlyCapFrom: 'mandate-policy' });
    const below = { organizationPolicy, mandatePolicy: mandatePolicy({ monthlyCap: aed(2_000) }) };
    expect(decide(input(2_000.01, below))).toMatchObject({ decision: 'DENY', reasons: ['POLICY_MONTHLY_CAP'] });
    // The mandate's policy setting none leaves the organisation's.
    const unset = { organizationPolicy, mandatePolicy: NO_RULES };
    expect(decide(input(8_000.01, unset))).toMatchObject({
      reasons: ['POLICY_MONTHLY_CAP'],
      monthlyCapFrom: 'organization-policy',
    });
  });

  it("never lifts the mandate's own monthly limit", () => {
    const wide = { mandatePolicy: mandatePolicy({ monthlyCap: aed(900_000) }), monthSpent: aed(48_000) };
    expect(decide(input(5_000, wide))).toMatchObject({
      decision: 'REQUIRE_NEW_MANDATE',
      reasons: ['MANDATE_MONTHLY_LIMIT'],
    });
  });
});

describe('decisionInputText', () => {
  it('is the same for the same facts, and changes with any fact weighed', () => {
    const base = input(5_000, { organizationPolicy: orgPolicy({ perOrderCap: { cap: aed(4_000), over: 'DENY' } }) });
    expect(decisionInputText(base)).toBe(
      decisionInputText(input(5_000, { organizationPolicy: base.organizationPolicy })),
    );
    for (const changed of [
      input(5_000.01, { organizationPolicy: base.organizationPolicy }),
      { ...base, monthSpent: aed(1) },
      { ...base, splitOpen: aed(1) },
      { ...base, duplicateOrder: true },
      { ...base, possibleDuplicate: true },
      { ...base, organizationCapChosen: false },
      { ...base, organizationPolicy: orgPolicy({ perOrderCap: { cap: aed(4_000), over: 'REQUIRE_APPROVAL' } }) },
      { ...base, mandatePolicy: NO_RULES },
      { ...base, mandate: { ...MANDATE, endsAt: NOW } },
      { ...base, mandate: { ...MANDATE, overLimit: 'approval' as const } },
      { ...base, consent: null },
      { ...base, consent: { maxPayment: aed(1), maxMonth: aed(200_000) } },
      { ...base, consent: { maxPayment: aed(100_000), maxMonth: null } },
      { ...base, now: new Date(NOW.getTime() + 1) },
    ]) {
      expect(decisionInputText(changed)).not.toBe(decisionInputText(base));
    }
  });

  it('keeps in decisionFacts every fact weighed that no versioned record holds (G3)', () => {
    const base = input(5_000);
    expect(decisionFacts(base)).toEqual({
      weighedAt: NOW.toISOString(),
      agentStatus: base.agent.status,
      mandateStatus: MANDATE.status,
      supplierStatus: base.supplierStatus,
      sourceMayFund: base.sourceMayFund,
      monthSpent: '0 AED',
      splitOpen: '0 AED',
      duplicateOrder: false,
      possibleDuplicate: false,
      defaultMonthlyCap: null,
      organizationCapChosen: true,
      overLimit: 'refuse',
      consentMaxPayment: '10000000 AED',
      consentMaxMonth: '20000000 AED',
    });
    // A fact added to the text must be added here too, or kept in a versioned record: this counts them.
    expect(JSON.parse(decisionInputText(base))).toHaveLength(16);
    for (const changed of [
      { ...base, now: new Date(NOW.getTime() + 1) },
      { ...base, agent: { ...base.agent, status: 'SUSPENDED' } },
      { ...base, mandate: { ...MANDATE, status: 'SUSPENDED' } },
      { ...base, supplierStatus: null },
      { ...base, sourceMayFund: !base.sourceMayFund },
      { ...base, monthSpent: aed(1) },
      { ...base, splitOpen: aed(1) },
      { ...base, duplicateOrder: true },
      { ...base, possibleDuplicate: true },
      { ...base, organizationCapChosen: false },
      { ...base, mandate: { ...MANDATE, overLimit: 'approval' as const } },
      { ...base, consent: { maxPayment: aed(1), maxMonth: aed(200_000) } },
      { ...base, consent: { maxPayment: aed(100_000), maxMonth: null } },
    ]) {
      expect(decisionFacts(changed)).not.toEqual(decisionFacts(base));
    }
  });

  it("keeps the old default's place empty, the admin's choice (E2), then the over-limit choice and consent last (E9)", () => {
    const textOf = (given: DecisionInput) => JSON.parse(decisionInputText(given)) as unknown[];
    const text = textOf(input(5_000));
    expect(text[11]).toBeNull();
    expect(text[12]).toBe(false);
    expect(text[13]).toBe(true);
    expect(textOf(input(5_000, { organizationCapChosen: false }))[13]).toBe(false);
    expect(text.slice(-2)).toEqual(['refuse', ['10000000 AED', '20000000 AED']]);
    expect(textOf(input(5_000, { mandate: null, consent: null })).slice(-2)).toEqual([null, null]);
    expect(decisionFacts(input(5_000, { mandate: null, consent: null }))).toMatchObject({
      overLimit: null,
      consentMaxPayment: null,
      consentMaxMonth: null,
    });
  });

  it('reads IDs in any case, and keeps amounts as exact text', () => {
    expect(decisionInputText(asking({ supplierId: SUPPLIER.toUpperCase() }))).toBe(decisionInputText(input(5_000)));
    expect(decisionInputText(input(5_000))).toContain('"500000 AED"');
    expect(decisionInputText(input(5_000, { mandate: null }))).toContain(',null,');
  });
});

// Property-based (SEC-LIM-05, SEC-LIM-06, SEC-AG-14).
const minor = fc.bigInt({ min: 1n, max: 10_000_000n });
const maybe = <T>(arb: fc.Arbitrary<T>): fc.Arbitrary<T | null> => fc.option(arb, { nil: null });
const anAed = minor.map((m) => money(m, 'AED'));
const suppliers = fc.subarray([SUPPLIER, OTHER_SUPPLIER]);
const rules = fc.record({
  versionId: fc.constant(NO_RULES.versionId),
  perOrderCap: maybe(
    fc.record({ cap: anAed, over: fc.constantFrom<'DENY' | 'REQUIRE_APPROVAL'>('DENY', 'REQUIRE_APPROVAL') }),
  ),
  monthlyCap: maybe(anAed),
  approvalThreshold: maybe(anAed),
  supplierIds: maybe(suppliers),
});
const anyInput: fc.Arbitrary<DecisionInput> = fc
  .record({
    amount: anAed,
    supplierId: fc.constantFrom(SUPPLIER, OTHER_SUPPLIER),
    fundingSourceId: fc.constantFrom(SOURCE, SUPPLIER),
    mandateAgent: fc.constantFrom(AGENT, SOURCE),
    // Ended an hour ago, a millisecond from now, or never.
    endsAt: fc.constantFrom(new Date(NOW.getTime() - 3_600_000), new Date(NOW.getTime() + 1), null),
    limits: fc.tuple(minor, minor, minor).map((l) => [...l].sort((a, b) => Number(a - b))),
    mandateSuppliers: suppliers,
    splitCheck: fc.boolean(),
    agentStatus: fc.constantFrom('ACTIVE', 'SUSPENDED'),
    mandateStatus: fc.constantFrom('ACTIVE', 'SUSPENDED', 'REVOKED'),
    supplierStatus: fc.constantFrom('VERIFIED', 'UNVERIFIED', null),
    sourceMayFund: fc.boolean(),
    organizationPolicy: maybe(rules),
    organizationCapChosen: fc.boolean(),
    mandatePolicy: maybe(rules),
    monthSpent: minor,
    splitOpen: minor,
    duplicateOrder: fc.boolean(),
    possibleDuplicate: fc.boolean(),
    overLimit: fc.constantFrom<'refuse' | 'approval'>('refuse', 'approval'),
    consent: maybe(fc.record({ maxPayment: anAed, maxMonth: maybe(anAed) })),
  })
  .map((g) => {
    const [threshold = 1n, perOrder = 1n, monthly = 1n] = g.limits;
    return input(0, {
      request: { amount: g.amount, supplierId: g.supplierId, fundingSourceId: g.fundingSourceId },
      agent: { id: AGENT, status: g.agentStatus },
      mandate: {
        ...MANDATE,
        status: g.mandateStatus,
        agentId: g.mandateAgent,
        endsAt: g.endsAt,
        approvalThreshold: money(threshold, 'AED'),
        perOrderLimit: money(perOrder, 'AED'),
        monthlyLimit: money(monthly, 'AED'),
        supplierIds: g.mandateSuppliers,
        splitCheck: g.splitCheck,
        overLimit: g.overLimit,
      },
      supplierStatus: g.supplierStatus,
      sourceMayFund: g.sourceMayFund,
      organizationPolicy: g.organizationPolicy,
      organizationCapChosen: g.organizationCapChosen,
      mandatePolicy: g.mandatePolicy,
      monthSpent: money(g.monthSpent, 'AED'),
      splitOpen: money(g.splitOpen, 'AED'),
      duplicateOrder: g.duplicateOrder,
      possibleDuplicate: g.possibleDuplicate,
      consent: g.consent,
    });
  });

const rank = (decision: Decision): number => DECISIONS.indexOf(decision);

describe('reasonsShownToAgent (decision 11c)', () => {
  it('shows an approval every reason, and a refusal only the reasons that made it', () => {
    expect(reasonsShownToAgent('REQUIRE_APPROVAL', ['APPROVAL_THRESHOLD', 'AGGREGATE_THRESHOLD'])).toEqual([
      'APPROVAL_THRESHOLD',
      'AGGREGATE_THRESHOLD',
    ]);
    expect(reasonsShownToAgent('ALLOW', [])).toEqual([]);
    // A policy's order cap that asks approval is shown with the rest.
    expect(reasonsShownToAgent('REQUIRE_APPROVAL', ['POLICY_ORDER_CAP', 'APPROVAL_THRESHOLD'])).toEqual([
      'POLICY_ORDER_CAP',
      'APPROVAL_THRESHOLD',
    ]);
    expect(reasonsShownToAgent('DENY', ['SUPPLIER_NOT_ALLOWED', 'MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'])).toEqual([
      'SUPPLIER_NOT_ALLOWED',
    ]);
    expect(reasonsShownToAgent('REQUIRE_NEW_MANDATE', ['MANDATE_MONTHLY_LIMIT', 'APPROVAL_THRESHOLD'])).toEqual([
      'MANDATE_MONTHLY_LIMIT',
    ]);
  });

  it('never names the mandate’s own limits to the agent on an approval (partner, S121)', () => {
    expect(reasonsShownToAgent('REQUIRE_APPROVAL', ['MANDATE_ORDER_LIMIT', 'APPROVAL_THRESHOLD'])).toEqual([
      'APPROVAL_THRESHOLD',
    ]);
    expect(reasonsShownToAgent('REQUIRE_APPROVAL', ['MANDATE_MONTHLY_LIMIT'])).toEqual([]);
    // A refusal past the consent is shown as it is: both made it.
    expect(reasonsShownToAgent('REQUIRE_NEW_MANDATE', ['MANDATE_ORDER_LIMIT', 'MANDATE_LIMIT_PAST_CONSENT'])).toEqual([
      'MANDATE_ORDER_LIMIT',
      'MANDATE_LIMIT_PAST_CONSENT',
    ]);
  });

  it('shows a policy’s order cap only when nothing else could have denied', () => {
    expect(reasonsShownToAgent('DENY', ['POLICY_ORDER_CAP', 'APPROVAL_THRESHOLD'])).toEqual(['POLICY_ORDER_CAP']);
    expect(reasonsShownToAgent('DENY', ['POLICY_MONTHLY_CAP', 'POLICY_ORDER_CAP'])).toEqual(['POLICY_MONTHLY_CAP']);
  });
});

describe('decide: properties', () => {
  it('never allows, or sends for approval, what the mandate does not allow (SEC-LIM-05, -06; decision 23)', () => {
    fc.assert(
      fc.property(anyInput, (given) => {
        const { decision } = decide(given);
        if (rank(decision) < rank('REQUIRE_APPROVAL')) return;
        const { mandate, request, monthSpent, now, consent } = given;
        if (mandate === null) throw new Error('anyInput always has a mandate');
        expect(mandate.status).toBe('ACTIVE');
        expect(mandate.agentId).toBe(given.agent.id);
        expect(mandate.endsAt === null || now < mandate.endsAt).toBe(true);
        expect(request.fundingSourceId).toBe(mandate.fundingSourceId);
        const monthTotal = monthSpent.minor + request.amount.minor;
        const withinOwn =
          request.amount.minor <= mandate.perOrderLimit.minor && monthTotal <= mandate.monthlyLimit.minor;
        if (!withinOwn) {
          // Past its own limits only as its version chose, to a person, and never past the bank consent.
          expect(mandate.overLimit).toBe('approval');
          expect(decision).toBe('REQUIRE_APPROVAL');
          if (consent === null) throw new Error('sent for approval past the mandate with no consent');
          expect(request.amount.minor).toBeLessThanOrEqual(consent.maxPayment.minor);
          if (consent.maxMonth !== null) expect(monthTotal).toBeLessThanOrEqual(consent.maxMonth.minor);
          expect(decide(given).reasons).not.toContain('MANDATE_LIMIT_PAST_CONSENT');
        }
        expect(mandate.supplierIds).toContain(request.supplierId);
        if (decision === 'ALLOW') expect(request.amount.minor).toBeLessThanOrEqual(mandate.approvalThreshold.minor);
        // A possible duplicate is never allowed without a person (decision 11a).
        if (decision === 'ALLOW') expect(given.possibleDuplicate).toBe(false);
      }),
    );
  });

  it("denies whatever else is weighed until the organisation's monthly cap is chosen (E2)", () => {
    fc.assert(
      fc.property(anyInput, (given) => {
        const made = decide({ ...given, organizationCapChosen: false });
        expect(made.decision).toBe('DENY');
        expect(made.reasons).toContain('ORG_MONTHLY_CAP_NOT_SET');
        expect(made.monthlyCapFrom).toBe('not-set');
      }),
    );
  });

  it('is never less strict for a policy, but for the monthly cap per agent (decision 5)', () => {
    fc.assert(
      fc.property(anyInput, rules, (given, policy) => {
        // Its monthly cap may raise the organisation's for this agent, so the baseline keeps it.
        const narrowed = decide({ ...given, mandatePolicy: policy });
        const capOnly = decide({ ...given, mandatePolicy: { ...NO_RULES, monthlyCap: policy.monthlyCap } });
        expect(rank(narrowed.decision)).toBeLessThanOrEqual(rank(capOnly.decision));
      }),
    );
  });

  it('shows the agent at least one reason for any refusal, and none that asks approval (decision 11c)', () => {
    fc.assert(
      fc.property(anyInput, (given) => {
        const { decision, reasons } = decide(given);
        const shown = reasonsShownToAgent(decision, reasons);
        expect(shown.every((code) => reasons.includes(code))).toBe(true);
        if (decision === 'DENY' || decision === 'REQUIRE_NEW_MANDATE') {
          expect(shown.length).toBeGreaterThan(0);
          expect(shown).not.toContain('APPROVAL_THRESHOLD');
          expect(shown).not.toContain('AGGREGATE_THRESHOLD');
          expect(shown).not.toContain('POSSIBLE_DUPLICATE_ORDER');
        } else {
          expect(shown).not.toContain('MANDATE_ORDER_LIMIT');
          expect(shown).not.toContain('MANDATE_MONTHLY_LIMIT');
          expect(shown).toEqual(reasons.filter((code) => !code.startsWith('MANDATE_')));
        }
      }),
    );
  });

  it('decides the same whatever the purpose or wording, and each reason once (SEC-AG-14)', () => {
    fc.assert(
      fc.property(anyInput, fc.string(), fc.string(), (given, purpose, orderReference) => {
        const made = decide(given);
        // Free text a caller might pass along is never read.
        const request = { ...given.request, purpose, orderReference };
        const withText = decide({ ...given, request });
        expect(withText).toEqual(made);
        expect(new Set(made.reasons).size).toBe(made.reasons.length);
        expect(made.decision === 'ALLOW').toBe(made.reasons.length === 0);
      }),
    );
  });
});
