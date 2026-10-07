// The decision engine (Phase 2 C2): SEC-LIM-05 (a policy never allows more
// than its mandate), SEC-LIM-06 (over the mandate's own limits is
// REQUIRE_NEW_MANDATE, never approval; precedence), SEC-LIM-11 (a narrower
// policy decides exactly as it states), SEC-AG-14 (free text never weighs),
// and partner decision 5 (the strictest rule wins, except the monthly cap per
// agent: the mandate's policy's, else the organisation's, else AED 20,000).
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { type Money, money } from '../../../shared-kernel/index.ts';
import {
  type Decision,
  DECISIONS,
  decide,
  type DecisionInput,
  decisionInputText,
  DEFAULT_MONTHLY_CAP,
  type MandateInForce,
  type PolicyRules,
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
    request: { amount: aed(dirhams), supplierId: SUPPLIER, fundingSourceId: SOURCE, at: NOW },
    agent: { id: AGENT, status: 'ACTIVE' },
    mandate: MANDATE,
    supplierStatus: 'VERIFIED',
    sourceMayFund: true,
    organizationPolicy: null,
    mandatePolicy: null,
    monthSpent: aed(0),
    splitOpen: aed(0),
    duplicateOrder: false,
    ...changes,
  };
}

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
      monthlyCapFrom: 'default',
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

  it("denies a source other than the mandate's, and another currency, weighing no amount in it", () => {
    const elsewhere = input(5_000);
    expect(decide({ ...elsewhere, request: { ...elsewhere.request, fundingSourceId: SUPPLIER } })).toMatchObject({
      decision: 'DENY',
      reasons: ['SOURCE_NOT_MANDATED'],
    });
    const usd = { ...elsewhere.request, amount: money(9_999_999_999n, 'USD') };
    expect(decide({ ...elsewhere, request: usd })).toMatchObject({
      decision: 'DENY',
      reasons: ['CURRENCY_NOT_ALLOWED'],
    });
  });

  it('reads the IDs a request names in any case', () => {
    const asked = input(5_000).request;
    const upper = { ...asked, supplierId: SUPPLIER.toUpperCase(), fundingSourceId: SOURCE.toUpperCase() };
    expect(decide({ ...input(5_000), request: upper }).decision).toBe('ALLOW');
  });

  it('denies an expired mandate over its limit, with every failing reason (precedence)', () => {
    const ended = { mandate: { ...MANDATE, status: 'EXPIRED' }, supplierStatus: 'SUSPENDED' };
    expect(decide(input(30_000, ended))).toMatchObject({
      decision: 'DENY',
      reasons: ['SUPPLIER_NOT_VERIFIED', 'MANDATE_NOT_IN_FORCE'],
    });
    expect(decide(input(30_000, { duplicateOrder: true }))).toMatchObject({
      decision: 'DENY',
      reasons: ['DUPLICATE_ORDER_REFERENCE', 'MANDATE_ORDER_LIMIT', 'POLICY_MONTHLY_CAP', 'APPROVAL_THRESHOLD'],
    });
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
  it('is AED 20,000 when no policy sets one', () => {
    expect(DEFAULT_MONTHLY_CAP).toEqual(aed(20_000));
    const spent = { monthSpent: aed(15_000), organizationPolicy: NO_RULES };
    expect(decide(input(5_000, spent))).toMatchObject({ decision: 'ALLOW', monthlyCapFrom: 'default' });
    expect(decide(input(5_000.01, spent))).toMatchObject({ decision: 'DENY', reasons: ['POLICY_MONTHLY_CAP'] });
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
      { ...base, organizationPolicy: orgPolicy({ perOrderCap: { cap: aed(4_000), over: 'REQUIRE_APPROVAL' } }) },
      { ...base, mandatePolicy: NO_RULES },
      { ...base, mandate: { ...MANDATE, endsAt: NOW } },
      { ...base, request: { ...base.request, at: new Date(NOW.getTime() + 1) } },
    ]) {
      expect(decisionInputText(changed)).not.toBe(decisionInputText(base));
    }
  });

  it('reads IDs in any case, and keeps amounts as exact text', () => {
    const asked = input(5_000).request;
    const upper = { ...input(5_000), request: { ...asked, supplierId: SUPPLIER.toUpperCase() } };
    expect(decisionInputText(upper)).toBe(decisionInputText(input(5_000)));
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
    limits: fc.tuple(minor, minor, minor).map((l) => [...l].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))),
    mandateSuppliers: suppliers,
    splitCheck: fc.boolean(),
    agentStatus: fc.constantFrom('ACTIVE', 'SUSPENDED'),
    mandateStatus: fc.constantFrom('ACTIVE', 'SUSPENDED', 'REVOKED'),
    supplierStatus: fc.constantFrom('VERIFIED', 'UNVERIFIED', null),
    sourceMayFund: fc.boolean(),
    organizationPolicy: maybe(rules),
    mandatePolicy: maybe(rules),
    monthSpent: minor,
    splitOpen: minor,
    duplicateOrder: fc.boolean(),
  })
  .map((g) => {
    const [threshold = 1n, perOrder = 1n, monthly = 1n] = g.limits;
    return input(0, {
      request: { amount: g.amount, supplierId: g.supplierId, fundingSourceId: SOURCE, at: NOW },
      agent: { id: AGENT, status: g.agentStatus },
      mandate: {
        ...MANDATE,
        status: g.mandateStatus,
        approvalThreshold: money(threshold, 'AED'),
        perOrderLimit: money(perOrder, 'AED'),
        monthlyLimit: money(monthly, 'AED'),
        supplierIds: g.mandateSuppliers,
        splitCheck: g.splitCheck,
      },
      supplierStatus: g.supplierStatus,
      sourceMayFund: g.sourceMayFund,
      organizationPolicy: g.organizationPolicy,
      mandatePolicy: g.mandatePolicy,
      monthSpent: money(g.monthSpent, 'AED'),
      splitOpen: money(g.splitOpen, 'AED'),
      duplicateOrder: g.duplicateOrder,
    });
  });

const rank = (decision: Decision): number => DECISIONS.indexOf(decision);

describe('decide: properties', () => {
  it('never allows, or sends for approval, what the mandate does not allow (SEC-LIM-05, -06)', () => {
    fc.assert(
      fc.property(anyInput, (given) => {
        const { decision } = decide(given);
        if (rank(decision) < rank('REQUIRE_APPROVAL')) return;
        const { mandate, request, monthSpent } = given;
        expect(mandate?.status).toBe('ACTIVE');
        expect(request.amount.minor).toBeLessThanOrEqual(mandate?.perOrderLimit.minor ?? -1n);
        expect(monthSpent.minor + request.amount.minor).toBeLessThanOrEqual(mandate?.monthlyLimit.minor ?? -1n);
        expect(mandate?.supplierIds).toContain(request.supplierId);
        if (decision === 'ALLOW')
          expect(request.amount.minor).toBeLessThanOrEqual(mandate?.approvalThreshold.minor ?? -1n);
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
