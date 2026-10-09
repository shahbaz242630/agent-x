// Phase 2 C4: the policy simulator's route over HTTP, its use case a stub:
// what it hands the use case (the request checked, proposed rules as Money),
// the answer field by field (a proposed policy's version shown as none),
// that it takes no idempotency key as it writes nothing (SEC-AG-09), who may
// use it (decision 9: never a viewer), the edge's refusals and the use
// case's. What the use case weighs, and that it writes nothing, is
// spend-request-decisions.db.test.ts ("the simulator").
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import { money, REASON_CODES } from '@agentx/core/shared-kernel';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { PolicySimulations, Simulated, WhatIf } from './policy-simulations.ts';
import type { Refused } from './refused.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import type { SpendWeighed } from './spend-request-decisions.ts';

const MANDATE_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const VERSION_ID = '0199a0f0-0000-7000-8000-0000000000d2';
const ORG_POLICY_VERSION = '0199a0f0-0000-7000-8000-0000000000d3';
const SUPPLIER_ID = '0199a0f0-0000-7000-8000-0000000000e1';
const SOURCE_ID = '0199a0f0-0000-7000-8000-0000000000f1';
const MEMBER = '0199a0f0-0000-7000-8000-000000000033';
const URL = `/v1/mandates/${MANDATE_ID}/policy/simulate`;

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-09T09:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-09T09:00:05.000Z'),
  lastSeenAt: new Date('2026-10-09T09:10:00.000Z'),
  endsAt: new Date('2099-10-07T21:00:05.000Z'),
  idleEndsAt: new Date('2099-10-07T09:40:00.000Z'),
};

const AED = (minor: bigint) => money(minor, 'AED');

const BODY = {
  amountMinor: 1_000_000,
  currency: 'AED',
  supplierId: SUPPLIER_ID,
  fundingSourceId: SOURCE_ID,
};

const SIMULATED: Simulated = {
  outcome: 'simulated',
  made: {
    decision: 'REQUIRE_APPROVAL',
    reasons: ['APPROVAL_THRESHOLD'],
    versions: { mandate: VERSION_ID, organizationPolicy: ORG_POLICY_VERSION, mandatePolicy: 'proposed' },
    monthlyCapFrom: 'mandate-policy',
  },
  mandateId: MANDATE_ID,
  month: '2026-10',
  monthSpent: AED(250_000n),
  proposed: { organizationPolicy: false, mandatePolicy: true },
};

interface Call {
  readonly orgId: string;
  readonly mandateId: string;
  readonly asked: SpendWeighed;
  readonly whatIf: WhatIf;
}

afterEach(closeServers);

/** A server whose simulator answers `answer`, the caller holding `role`. */
async function withSimulations(answer: Simulated | Refused = SIMULATED, role: Role = 'developer') {
  const calls: Call[] = [];
  const simulations: PolicySimulations = {
    simulate: (orgId, mandateId, asked, whatIf) => {
      calls.push({ orgId, mandateId, asked, whatIf });
      return Promise.resolve(answer);
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: MEMBER, role };
  const app = await routeServer({ live: LIVE, member, policySimulations: simulations });
  return { app, calls };
}

const simulate = (payload: unknown): InjectOptions => ({
  method: 'POST',
  url: URL,
  headers: {
    cookie: `${SESSION_COOKIE}=${COOKIE}`,
    [ORGANIZATION_HEADER]: ORG,
    origin: PUBLIC_ORIGIN,
    'content-type': 'application/json',
  },
  payload: JSON.stringify(payload),
});

describe('POST /v1/mandates/{id}/policy/simulate (C4, decision 9)', () => {
  it('weighs the request with proposed rules, taking no idempotency key, and answers field by field', async () => {
    const { app, calls } = await withSimulations();
    const response = await app.inject(
      simulate({
        ...BODY,
        orderReference: 'INV-e\u0301',
        whatIf: { mandatePolicy: { currency: 'AED', approvalThresholdMinor: 500_000 } },
      }),
    );

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      decision: 'REQUIRE_APPROVAL',
      reasons: [{ code: 'APPROVAL_THRESHOLD', message: REASON_CODES.APPROVAL_THRESHOLD }],
      mandateId: MANDATE_ID,
      // The proposed policy's version is none: none was made.
      versions: { mandate: VERSION_ID, organizationPolicy: ORG_POLICY_VERSION, mandatePolicy: null },
      proposed: { organizationPolicy: false, mandatePolicy: true },
      monthlyCapFrom: 'mandate-policy',
      month: '2026-10',
      monthSpentMinor: 250_000,
    });
    expect(calls).toEqual([
      {
        orgId: ORG,
        mandateId: MANDATE_ID,
        asked: {
          amount: AED(1_000_000n),
          supplierId: SUPPLIER_ID,
          fundingSourceId: SOURCE_ID,
          orderReference: 'INV-\u00e9',
        },
        whatIf: {
          organizationPolicy: undefined,
          mandatePolicy: {
            currency: 'AED',
            perOrderCap: null,
            monthlyCap: null,
            approvalThreshold: AED(500_000n),
            supplierIds: null,
          },
        },
      },
    ]);
  });

  it('weighs the rules in force with no proposed ones, and no order checked without one named', async () => {
    const inForce = { ...SIMULATED, proposed: { organizationPolicy: false, mandatePolicy: false } };
    const { app, calls } = await withSimulations({
      ...inForce,
      made: { ...inForce.made, versions: { ...inForce.made.versions, mandatePolicy: null } },
    });
    const response = await app.inject(simulate(BODY));

    expect(response.json()).toMatchObject({ versions: { mandatePolicy: null }, proposed: { mandatePolicy: false } });
    expect(calls[0]?.asked.orderReference).toBeNull();
    expect(calls[0]?.whatIf).toEqual({ organizationPolicy: undefined, mandatePolicy: undefined });
  });

  it.each(['admin', 'approver', 'developer'] as const)('lets an %s simulate', async (role) => {
    const { app } = await withSimulations(SIMULATED, role);
    expect((await app.inject(simulate(BODY))).statusCode).toBe(200);
  });

  it('refuses a viewer before the use case runs (decision 9)', async () => {
    const { app, calls } = await withSimulations(SIMULATED, 'viewer');
    expect((await app.inject(simulate(BODY))).statusCode).toBe(403);
    expect(calls).toEqual([]);
  });

  it.each([
    ['an amount of nothing', { amountMinor: 0 }],
    ['a currency that is no ISO code', { currency: 'dirham' }],
    ['an order reference with no letter or digit', { orderReference: '#' }],
    [
      'proposed rules that nest wrongly',
      {
        whatIf: {
          organizationPolicy: { currency: 'AED', perOrderCap: { capMinor: 5, over: 'DENY' }, monthlyCapMinor: 1 },
        },
      },
    ],
    ['proposed rules for a policy it doesn’t name', { whatIf: { supplierPolicy: { currency: 'AED' } } }],
    ['a field it does not take', { purpose: 'Paper' }],
  ])('refuses %s as 400, before the use case runs', async (_what, change) => {
    const { app, calls } = await withSimulations();
    expect((await app.inject(simulate({ ...BODY, ...change }))).statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [409, 'MANDATE_NOT_IN_FORCE'],
    [409, 'POLICY_WIDER_THAN_MANDATE'],
    [422, 'CURRENCY_NOT_ALLOWED'],
    [409, 'ORG_FROZEN'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal: %i %s', async (status, code) => {
    const { app } = await withSimulations({ outcome: 'refused', status, code });
    const response = await app.inject(simulate(BODY));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('takes the longest body the schema allows within the body limit: two lists of 100 suppliers, every character escaped (B8-3)', async () => {
    const { app } = await withSimulations();
    const escaped = (text: string) =>
      Array.from(
        text,
        (c) => `${String.fromCharCode(92)}u${(c.codePointAt(0) ?? 0).toString(16).padStart(4, '0')}`,
      ).join('');
    const suppliers = Array.from({ length: 100 }, (_, i) => `0199a0f0-0000-7000-8000-${String(i).padStart(12, '0')}`);
    const list = '[' + suppliers.map((id) => '"' + escaped(id) + '"').join(',') + ']';
    const rules = `{"currency":"AED","supplierIds":${list}}`;
    const reference = escaped('\u1F82'.normalize('NFD').repeat(100));
    const body = JSON.stringify({
      ...BODY,
      orderReference: '@',
      whatIf: { organizationPolicy: '#', mandatePolicy: '#' },
    })
      .replace('"@"', `"${reference}"`)
      .replaceAll('"#"', rules);
    const response = await app.inject({ ...simulate(BODY), payload: body });

    expect(response.statusCode).toBe(200);
  });
});
