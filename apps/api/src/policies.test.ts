// Phase 2 C3: the policies' routes, the organisation's and a mandate's,
// answering a member with each outcome of the use case: the rules read from a
// body (or refused at the edge with every problem), each change asked then
// confirmed, every refusal, and the reads. Who reaches them is the access
// hook's (role-matrix.test.ts); what the use case does in the database is
// policy-changes.db.test.ts.
import type { LiveSession, MembershipCheck, Role } from '@agentx/core/modules/identity';
import { money } from '@agentx/core/shared-kernel';
import type { IdempotentRequest } from '@agentx/platform/db';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { PolicyChangeAsked, PolicyChanged, PolicyChanges, PolicyView } from './policy-changes.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const MANDATE_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const VERSION_ID = '0199a0f0-0000-7000-8000-0000000000d3';
const SUPPLIERS = ['0199a0f0-0000-7000-8000-0000000000e1', '0199a0f0-0000-7000-8000-0000000000e2'];
const ADMIN = '0199a0f0-0000-7000-8000-000000000033';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000000c1';
const REQUEST_ID = '0199a0f0-0000-7000-8000-0000000000f1';
const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-08T09:00:00.000Z'),
  // A passkey's sign-in, as an admin needs (ADR-012 §7).
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-08T09:00:05.000Z'),
  lastSeenAt: new Date('2026-10-08T09:10:00.000Z'),
  endsAt: new Date('2099-10-07T21:00:05.000Z'),
  idleEndsAt: new Date('2099-10-07T09:40:00.000Z'),
};

const AED = (minor: bigint) => money(minor, 'AED');

const VIEW: PolicyView = {
  scope: 'mandate',
  id: MANDATE_ID,
  mandateId: MANDATE_ID,
  current: {
    id: VERSION_ID,
    policyId: MANDATE_ID,
    version: 2,
    currency: 'AED',
    perOrderCap: { cap: AED(300_000n), over: 'REQUIRE_APPROVAL' },
    monthlyCap: AED(1_500_000n),
    approvalThreshold: null,
    supplierIds: SUPPLIERS,
    rulesHash: 'b'.repeat(64),
    madeBy: ADMIN,
    madeAt: new Date('2026-10-08T09:15:00.000Z'),
  },
  monthlyCapChoice: null,
};

const ANSWERED = {
  scope: 'mandate',
  id: MANDATE_ID,
  mandateId: MANDATE_ID,
  current: {
    id: VERSION_ID,
    version: 2,
    currency: 'AED',
    perOrderCap: { capMinor: 300_000, over: 'REQUIRE_APPROVAL' },
    monthlyCapMinor: 1_500_000,
    approvalThresholdMinor: null,
    supplierIds: SUPPLIERS,
    rulesHash: 'b'.repeat(64),
    madeBy: ADMIN,
    madeAt: '2026-10-08T09:15:00.000Z',
  },
  monthlyCapChoice: null,
  suggestedMonthlyCapMinor: 2_000_000,
};

afterEach(closeServers);

interface Call {
  readonly kind: 'ask' | 'confirm' | 'show' | 'preview';
  readonly member?: unknown;
  readonly keyed?: IdempotentRequest;
  readonly subject?: unknown;
}

interface Answers {
  readonly asked?: PolicyChangeAsked;
  readonly changed?: PolicyChanged;
  readonly found?: Awaited<ReturnType<PolicyChanges['show']>>;
  readonly previewed?: Awaited<ReturnType<PolicyChanges['preview']>>;
}

/** A server whose policy changes answer `answers`, the caller holding `role`. */
async function withPolicies(answers: Answers, role: Role = 'admin') {
  const calls: Call[] = [];
  const changes: PolicyChanges = {
    ask: (member, keyed, target, asked) => {
      calls.push({ kind: 'ask', member, keyed, subject: { target, ...asked } });
      return Promise.resolve(answers.asked ?? { outcome: 'busy' as const });
    },
    confirm: (member, keyed, target, asked, stepUpChallengeId) => {
      calls.push({ kind: 'confirm', member, keyed, subject: { target, ...asked, stepUpChallengeId } });
      return Promise.resolve(answers.changed ?? { outcome: 'busy' as const });
    },
    show: (orgId, target) => {
      calls.push({ kind: 'show', subject: { orgId, target } });
      return Promise.resolve(answers.found ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
    preview: (member, target, asked) => {
      calls.push({ kind: 'preview', member, subject: { target, ...asked } });
      return Promise.resolve(answers.previewed ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
  };
  const member: MembershipCheck = { outcome: 'active', id: ADMIN, role };
  const app = await routeServer({ live: LIVE, member, policyChanges: changes });
  return { app, calls };
}

const headers = { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG, origin: PUBLIC_ORIGIN };

const post = (url: string, payload: unknown): InjectOptions => ({
  method: 'POST',
  url,
  headers: { ...headers, 'idempotency-key': 'k-1', 'content-type': 'application/json' },
  payload: JSON.stringify(payload),
});

const RULES = {
  currency: 'AED',
  perOrderCap: { capMinor: 300_000, over: 'REQUIRE_APPROVAL' },
  monthlyCapMinor: 1_500_000,
  supplierIds: [SUPPLIERS[1], SUPPLIERS[0]],
};

/** RULES as the use case is given them: Money, the suppliers sorted, the rules left out none. */
const RULES_KEPT = {
  currency: 'AED',
  perOrderCap: { cap: AED(300_000n), over: 'REQUIRE_APPROVAL' },
  monthlyCap: AED(1_500_000n),
  approvalThreshold: null,
  supplierIds: SUPPLIERS,
};

/** Each kind's path, target and operation, and whether its body names the monthly cap choice (the organisation's, E2). */
const PATHS = [
  ['the organisation’s', '/v1/policies/organization', { scope: 'organization' }, 'policies.organization.change', true],
  [
    'a mandate’s',
    `/v1/mandates/${MANDATE_ID}/policy`,
    { scope: 'mandate', mandateId: MANDATE_ID },
    'policies.mandate.change',
    false,
  ],
] as const;

describe.each(PATHS)('changing %s policy (C3)', (_whose, path, target, operation, chooses) => {
  // The body's choice, and as the use case is given it.
  const choice = (chosen: 'amount' | 'none') => (chooses ? { monthlyCapChoice: chosen } : {});
  const kept = (chosen: 'amount' | 'none') => (chooses ? chosen : null);
  const RULES_SENT = { ...RULES, ...choice('amount') };

  it('asks a passkey step-up: 202, passing the member in their session, the key, the policy and its rules', async () => {
    const { app, calls } = await withPolicies({ asked: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });
    const reply = await app.inject(post(`${path}/change`, RULES_SENT));

    expect(reply.statusCode).toBe(202);
    expect(reply.json()).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(calls).toEqual([
      {
        kind: 'ask',
        member: { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId },
        keyed: expect.objectContaining({ operation, key: 'k-1' }) as unknown,
        subject: { target, rules: RULES_KEPT, capChoice: kept('amount') },
      },
    ]);
  });

  it('confirms with the same rules: 200 with the policy, passing the step-up', async () => {
    const { app, calls } = await withPolicies({ changed: { outcome: 'changed', ...VIEW } });
    const reply = await app.inject(post(`${path}/change/confirm`, { ...RULES_SENT, stepUpChallengeId: CHALLENGE }));

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual(ANSWERED);
    expect(calls).toEqual([
      expect.objectContaining({
        kind: 'confirm',
        keyed: expect.objectContaining({ operation: `${operation}.confirm` }) as unknown,
        subject: { target, rules: RULES_KEPT, capChoice: kept('amount'), stepUpChallengeId: CHALLENGE },
      }),
    ]);
  });

  it('takes a policy that sets nothing: every rule left out or null', async () => {
    const { app, calls } = await withPolicies({ asked: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });
    await app.inject(post(`${path}/change`, { currency: 'AED', monthlyCapMinor: null, ...choice('none') }));

    expect(calls[0]?.subject).toEqual({
      target,
      rules: { currency: 'AED', perOrderCap: null, monthlyCap: null, approvalThreshold: null, supplierIds: null },
      capChoice: kept('none'),
    });
  });

  it.each([
    ['no currency', { monthlyCapMinor: 1 }],
    ['a fraction', { ...RULES, monthlyCapMinor: 1.5 }],
    ['an amount as a string', { ...RULES, monthlyCapMinor: '100' }],
    ['a cap with no outcome', { ...RULES, perOrderCap: { capMinor: 5 } }],
    ['a cap above the monthly cap', { ...RULES, monthlyCapMinor: 299_999 }],
    ['a threshold above the cap', { ...RULES, approvalThresholdMinor: 300_001 }],
    ['an empty supplier list', { ...RULES, supplierIds: [] }],
    ['a supplier twice', { ...RULES, supplierIds: [SUPPLIERS[0], SUPPLIERS[0]] }],
    ['a currency in lower case', { ...RULES, currency: 'aed' }],
    ['anything more', { ...RULES, purpose: 'x' }],
  ])('refuses a body with %s at the edge', async (_what, body) => {
    const { app, calls } = await withPolicies({});
    const reply = await app.inject(post(`${path}/change`, { ...body, ...choice('amount') }));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    ['in lower case', 'aed'],
    ['of a NUL', String.fromCharCode(0)],
    ['of four letters', 'AEDX'],
  ])('refuses a currency %s at the edge, though the body sets no amount', async (_what, currency) => {
    const { app, calls } = await withPolicies({});
    const reply = await app.inject(post(`${path}/change`, { currency, ...choice('none') }));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it('takes the longest body the document allows within the body limit: 100 suppliers, every character escaped (B8-3)', async () => {
    const { app } = await withPolicies({ changed: { outcome: 'changed', ...VIEW } });
    const escaped = (text: string) =>
      // ASCII alone, one UTF-16 unit each.
      text.replaceAll(/./g, (c) => String.fromCharCode(92) + 'u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
    const suppliers = Array.from({ length: 100 }, (_, i) => `0199a0f0-0000-7000-8000-${String(i).padStart(12, '0')}`);
    const body = JSON.stringify({ ...RULES_SENT, supplierIds: ['@'], stepUpChallengeId: CHALLENGE }).replace(
      '"@"',
      suppliers.map((id) => `"${escaped(id)}"`).join(','),
    );
    const reply = await app.inject({ ...post(`${path}/change/confirm`, {}), payload: body });

    expect(reply.statusCode).toBe(200);
  });

  it('refuses a confirm with no step-up named', async () => {
    const { app, calls } = await withPolicies({});
    const reply = await app.inject(post(`${path}/change/confirm`, RULES_SENT));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each([
    [{ outcome: 'refused', status: 409, code: 'POLICY_WIDER_THAN_MANDATE' } as const, 409, 'POLICY_WIDER_THAN_MANDATE'],
    [{ outcome: 'conflict' } as const, 409, 'IDEMPOTENCY_KEY_REUSED'],
    [{ outcome: 'busy' } as const, 409, 'IDEMPOTENCY_KEY_BUSY'],
  ])('answers the use case’s %o as %i %s, ask and confirm', async (outcome, status, code) => {
    const { app } = await withPolicies({ asked: outcome, changed: outcome });
    for (const reply of [
      await app.inject(post(`${path}/change`, RULES_SENT)),
      await app.inject(post(`${path}/change/confirm`, { ...RULES_SENT, stepUpChallengeId: CHALLENGE })),
    ]) {
      expect(reply.statusCode).toBe(status);
      expect(reply.json()).toMatchObject({ error: { code } });
    }
  });

  it('refuses a member who isn’t an admin', async () => {
    const { app, calls } = await withPolicies({}, 'approver');
    const reply = await app.inject(post(`${path}/change`, RULES_SENT));

    expect(reply.statusCode).toBe(403);
    expect(calls).toEqual([]);
  });

  it('previews the waiting requests the rules would reject (E5d): 200, oldest first, with what to do, no key taken', async () => {
    const previewed = {
      outcome: 'previewed' as const,
      rejected: [{ id: REQUEST_ID, agentId: AGENT_ID, amount: AED(450_000n), reasons: ['POLICY_ORDER_CAP' as const] }],
      more: true,
    };
    const { app, calls } = await withPolicies({ previewed });
    const { 'idempotency-key': _key, ...unkeyed } = post('', {}).headers ?? {};
    const reply = await app.inject({ ...post(`${path}/change/preview`, RULES_SENT), headers: unkeyed });

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({
      rejected: [
        {
          id: REQUEST_ID,
          agentId: AGENT_ID,
          amountMinor: 450_000,
          currency: 'AED',
          reasons: [
            {
              code: 'POLICY_ORDER_CAP',
              message: expect.any(String) as unknown,
              whatToDo: 'Raise the per-order cap in the organisation’s or the mandate’s policy settings.',
            },
          ],
        },
      ],
      more: true,
    });
    expect(calls).toEqual([
      {
        kind: 'preview',
        member: { orgId: ORG, userId: LIVE.userId, sessionId: LIVE.sessionId },
        subject: { target, rules: RULES_KEPT, capChoice: kept('amount') },
      },
    ]);
  });

  it('previews none waiting, a preview refused, and refuses one not an admin’s or with rules the ask would refuse', async () => {
    const none = await withPolicies({ previewed: { outcome: 'previewed', rejected: [], more: false } });
    const empty = await none.app.inject(post(`${path}/change/preview`, RULES_SENT));
    expect(empty.statusCode).toBe(200);
    expect(empty.json()).toEqual({ rejected: [], more: false });

    const refused = await withPolicies({ previewed: { outcome: 'refused', status: 409, code: 'MANDATE_ENDED' } });
    const ended = await refused.app.inject(post(`${path}/change/preview`, RULES_SENT));
    expect(ended.statusCode).toBe(409);
    expect(ended.json()).toMatchObject({ error: { code: 'MANDATE_ENDED' } });

    const approver = await withPolicies({}, 'approver');
    expect((await approver.app.inject(post(`${path}/change/preview`, RULES_SENT))).statusCode).toBe(403);
    expect(approver.calls).toEqual([]);

    const wrong = await withPolicies({});
    const bad = await wrong.app.inject(post(`${path}/change/preview`, { ...RULES_SENT, currency: 7 }));
    expect(bad.statusCode).toBe(400);
    expect(wrong.calls).toEqual([]);
  });

  it('shows the policy to any member, or none set', async () => {
    const { app, calls } = await withPolicies({ found: { outcome: 'found', ...VIEW, current: null } }, 'viewer');
    const reply = await app.inject({ method: 'GET', url: path, headers });

    expect(reply.statusCode).toBe(200);
    expect(reply.json()).toEqual({ ...ANSWERED, current: null });
    expect(calls).toEqual([{ kind: 'show', subject: { orgId: ORG, target } }]);
  });

  it('answers a read refused', async () => {
    const { app } = await withPolicies({ found: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });
    const reply = await app.inject({ method: 'GET', url: path, headers });

    expect(reply.statusCode).toBe(503);
  });
});

describe('the organisation’s monthly cap choice (E2, decision 15)', () => {
  const path = '/v1/policies/organization/change';
  const { monthlyCapMinor: _cap, ...UNCAPPED } = RULES;

  it.each([
    ['no choice', RULES],
    ['`amount` with no monthly cap', { ...UNCAPPED, monthlyCapChoice: 'amount' }],
    ['`amount` with a null monthly cap', { ...RULES, monthlyCapMinor: null, monthlyCapChoice: 'amount' }],
    ['`none` with a monthly cap', { ...RULES, monthlyCapChoice: 'none' }],
    ['another choice', { ...RULES, monthlyCapChoice: 'default' }],
  ])('refuses %s at the edge, ask and confirm', async (_what, body) => {
    const { app, calls } = await withPolicies({});
    for (const reply of [
      await app.inject(post(path, body)),
      await app.inject(post(`${path}/confirm`, { ...body, stepUpChallengeId: CHALLENGE })),
    ]) {
      expect(reply.statusCode).toBe(400);
    }
    expect(calls).toEqual([]);
  });

  it('takes `none` with no monthly cap, the other rules as they are', async () => {
    const { app, calls } = await withPolicies({ asked: { outcome: 'asked', stepUpChallengeId: CHALLENGE } });
    const reply = await app.inject(post(path, { ...UNCAPPED, monthlyCapChoice: 'none' }));

    expect(reply.statusCode).toBe(202);
    expect(calls[0]?.subject).toEqual({
      target: { scope: 'organization' },
      rules: { ...RULES_KEPT, monthlyCap: null },
      capChoice: 'none',
    });
  });

  it('refuses a choice in a mandate’s policy: only the organisation’s names one', async () => {
    const { app, calls } = await withPolicies({});
    const reply = await app.inject(
      post(`/v1/mandates/${MANDATE_ID}/policy/change`, { ...RULES, monthlyCapChoice: 'amount' }),
    );

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });

  it.each(['amount', 'none', null] as const)(
    'shows the organisation’s choice as %s, with the suggestion',
    async (chosen) => {
      const view = { ...VIEW, scope: 'organization' as const, id: ORG, mandateId: null, monthlyCapChoice: chosen };
      const { app } = await withPolicies({ found: { outcome: 'found', ...view } }, 'viewer');
      const reply = await app.inject({ method: 'GET', url: '/v1/policies/organization', headers });

      expect(reply.statusCode).toBe(200);
      expect(reply.json()).toMatchObject({ monthlyCapChoice: chosen, suggestedMonthlyCapMinor: 2_000_000 });
    },
  );
});

describe('a mandate’s policy (C3)', () => {
  it('refuses a mandate not named by its ID', async () => {
    const { app, calls } = await withPolicies({});
    const reply = await app.inject(post('/v1/mandates/m-1/policy/change', RULES));

    expect(reply.statusCode).toBe(400);
    expect(calls).toEqual([]);
  });
});
