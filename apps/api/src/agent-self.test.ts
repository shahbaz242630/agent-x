// Phase 2 B5 (and D2-4a's sources, moved here): the agent's own mandate and
// sources routes, answering an agent's key with each outcome of the use case:
// the allowlisted fields alone (SEC-AG-05), the page passed, each scope
// needed, a member's session refused, and the use case's refusals. What the
// use case reads is agent-mandate.db.test.ts.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { SourceRecord } from '@agentx/core/modules/funding-sources';
import type { LiveSession } from '@agentx/core/modules/identity';
import { money } from '@agentx/core/shared-kernel';
import type { InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import type { AgentMandates, AgentMandateShown } from './agent-mandate.ts';
import type { SourcesListed } from './funding-source-reads.ts';
import { closeServers, COOKIE, ORG, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const AGENT_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const MANDATE_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const VERSION_ID = '0199a0f0-0000-7000-8000-0000000000d2';
const SOURCE_ID = '0199a0f0-0000-7000-8000-0000000000f1';
const SUPPLIERS = ['0199a0f0-0000-7000-8000-0000000000e1', '0199a0f0-0000-7000-8000-0000000000e2'];
const LAST_ID = '0199a0f0-0000-7000-8000-0000000000ff';
const TERMS_HASH = 'a'.repeat(64);
const DRAFTER = '0199a0f0-0000-7000-8000-000000000033';

const KEY = `axk_${'a'.repeat(32)}_${'b'.repeat(43)}`;
const KEY_READING_ONLY = `axk_${'c'.repeat(32)}_${'b'.repeat(43)}`;
const accepted = (scopes: AcceptedKey['scopes']): AcceptedKey => ({
  orgId: ORG,
  agentId: AGENT_ID,
  keyId: '0199a0f0-0000-7000-8000-0000000000b1',
  scopes,
  expiresAt: new Date('2099-12-28T09:00:00.000Z'),
});
const KEYS: ReadonlyMap<string, AcceptedKey> = new Map([
  [KEY, accepted(['requests:write', 'sources:read'])],
  [KEY_READING_ONLY, accepted(['requests:read'])],
]);

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-07T08:00:00.000Z'),
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-07T08:00:05.000Z'),
  lastSeenAt: new Date('2026-10-07T08:10:00.000Z'),
  endsAt: new Date('2099-10-07T20:00:05.000Z'),
  idleEndsAt: new Date('2099-10-07T08:40:00.000Z'),
};

const FOUND: AgentMandateShown = {
  outcome: 'found',
  mandate: {
    id: MANDATE_ID,
    agentId: AGENT_ID,
    timeZone: 'Asia/Dubai',
    splitWindowHours: 24,
    status: 'ACTIVE',
    currentVersionId: VERSION_ID,
    acceptedBy: DRAFTER,
    acceptedAt: new Date('2026-10-07T09:00:00.000Z'),
    pendingVersionId: null,
  },
  version: {
    id: VERSION_ID,
    mandateId: MANDATE_ID,
    version: 2,
    purpose: 'Office supplies',
    perOrderLimit: money(500_000n, 'AED'),
    monthlyLimit: money(2_000_000n, 'AED'),
    approvalThreshold: money(123_456n, 'AED'),
    supplierIds: SUPPLIERS,
    fundingSourceId: SOURCE_ID,
    splitCheck: true,
    consentLimits: 'flexible',
    endsAt: new Date('2027-01-01T00:00:00.000Z'),
    termsHash: TERMS_HASH,
    draftedBy: DRAFTER,
    draftedAt: new Date('2026-10-07T08:30:00.000Z'),
  },
  // C3c: the organisation's policies hold it below the mandate's monthly limit.
  monthlyCap: money(1_500_000n, 'AED'),
};

const SOURCE: SourceRecord = {
  id: SOURCE_ID,
  linkId: '0199a0f0-0000-7000-8000-0000000000c1',
  partner: 'fake',
  externalRef: 'fake-source-1',
  status: 'ACTIVE',
  availability: 'ACTIVE',
  consentStatus: 'Authorized',
  accountConsentId: 'fake-consent-1',
  replacesConsentId: null,
  consentExpiresAt: new Date('2027-10-01T08:12:00.000Z'),
  controls: {
    currency: 'AED',
    period: 'month',
    maxPaymentMinor: 5_000_000n,
    maxPeriodMinor: 20_000_000n,
    maxPeriodPayments: 100,
  },
  summary: { holderName: 'Jasmine AI FZ-LLC', accountType: 'sme', hint: 'AE…6026' },
  partnerChangedAt: new Date('2026-10-01T08:12:00.000Z'),
};

type Asked =
  | { readonly kind: 'inForce'; readonly orgId: string; readonly agentId: string }
  | { readonly kind: 'sources'; readonly orgId: string; readonly agentId: string; readonly after: string | null };

afterEach(closeServers);

/** A server whose use case answers `shown` and `listed`. */
async function withMandates(answers: { shown?: AgentMandateShown; listed?: SourcesListed }) {
  const asked: Asked[] = [];
  const mandates: AgentMandates = {
    inForce: (orgId, agentId) => {
      asked.push({ kind: 'inForce', orgId, agentId });
      return Promise.resolve(answers.shown ?? { outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    },
    sources: (orgId, agentId, after) => {
      asked.push({ kind: 'sources', orgId, agentId, after });
      return Promise.resolve(answers.listed ?? { outcome: 'listed', sources: [], next: null });
    },
  };
  const app = await routeServer({
    live: LIVE,
    findMembership: () => Promise.resolve({ outcome: 'active', id: DRAFTER, role: 'admin' } as const),
    checkAgentKey: (text) => {
      const key = KEYS.get(text);
      return Promise.resolve(key === undefined ? { outcome: 'refused' } : { outcome: 'accepted', key });
    },
    agentMandates: mandates,
  });
  return { app, asked };
}

const asAgent = (url: string, key = KEY): InjectOptions => ({
  method: 'GET',
  url,
  headers: { authorization: `Bearer ${key}` },
});

const asMember = (url: string): InjectOptions => ({
  method: 'GET',
  url,
  headers: { cookie: `${SESSION_COOKIE}=${COOKIE}`, [ORGANIZATION_HEADER]: ORG },
});

describe('GET /v1/agent/mandate: the mandate an agent acts under (B5, SEC-AG-05)', () => {
  it('answers its terms field by field, never the threshold, consent setting, hash or who drafted and accepted it', async () => {
    const { app, asked } = await withMandates({ shown: FOUND });
    const response = await app.inject(asAgent('/v1/agent/mandate'));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      mandateId: MANDATE_ID,
      status: 'ACTIVE',
      versionId: VERSION_ID,
      version: 2,
      purpose: 'Office supplies',
      currency: 'AED',
      perOrderLimitMinor: 500_000,
      monthlyLimitMinor: 2_000_000,
      monthlyCapMinor: 1_500_000,
      supplierIds: SUPPLIERS,
      fundingSourceId: SOURCE_ID,
      timeZone: 'Asia/Dubai',
      endsAt: '2027-01-01T00:00:00.000Z',
    });
    for (const withheld of ['123456', TERMS_HASH, DRAFTER, 'flexible', 'splitCheck']) {
      expect(response.body).not.toContain(withheld);
    }
    expect(asked).toEqual([{ kind: 'inForce', orgId: ORG, agentId: AGENT_ID }]);
  });

  it.each([
    [404, 'NOT_FOUND'],
    [503, 'INTEGRITY_FAILED'],
  ] as const)('answers the use case’s refusal: %i %s', async (status, code) => {
    const { app } = await withMandates({ shown: { outcome: 'refused', status, code } });
    const response = await app.inject(asAgent('/v1/agent/mandate'));

    expect(response.statusCode).toBe(status);
    expect(response.json()).toMatchObject({ error: { code } });
  });

  it('refuses a key without requests:write, and a member’s session, before the use case runs', async () => {
    const { app, asked } = await withMandates({ shown: FOUND });

    expect((await app.inject(asAgent('/v1/agent/mandate', KEY_READING_ONLY))).json()).toMatchObject({
      error: { code: 'INSUFFICIENT_SCOPE' },
    });
    expect([401, 403]).toContain((await app.inject(asMember('/v1/agent/mandate'))).statusCode);
    expect(asked).toEqual([]);
  });
});

describe('GET /v1/agent/funding-sources: the source its mandate names, the safe summary alone (D2-4a, B5)', () => {
  it('answers each source’s ID, currency, kind and hint, and nothing else of it', async () => {
    const { app, asked } = await withMandates({ listed: { outcome: 'listed', sources: [SOURCE], next: null } });
    const response = await app.inject(asAgent('/v1/agent/funding-sources?limit=10'));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      sources: [{ id: SOURCE_ID, currency: 'AED', accountType: 'sme', hint: 'AE…6026' }],
      next: null,
    });
    for (const withheld of ['Jasmine', 'fake-source', 'fake-consent', 'Authorized', '5000000']) {
      expect(response.body).not.toContain(withheld);
    }
    expect(asked).toEqual([{ kind: 'sources', orgId: ORG, agentId: AGENT_ID, after: null }]);
  });

  it('passes where the page starts', async () => {
    const { app, asked } = await withMandates({});
    await app.inject(asAgent(`/v1/agent/funding-sources?after=${LAST_ID}`));

    expect(asked).toEqual([{ kind: 'sources', orgId: ORG, agentId: AGENT_ID, after: LAST_ID }]);
  });

  it('refuses a key without sources:read, and a member’s session, before the use case runs', async () => {
    const { app, asked } = await withMandates({});

    expect((await app.inject(asAgent('/v1/agent/funding-sources', KEY_READING_ONLY))).json()).toMatchObject({
      error: { code: 'INSUFFICIENT_SCOPE' },
    });
    expect([401, 403]).toContain((await app.inject(asMember('/v1/agent/funding-sources'))).statusCode);
    expect(asked).toEqual([]);
  });

  it('answers 503 INTEGRITY_FAILED as the use case refuses', async () => {
    const { app } = await withMandates({ listed: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } });

    expect((await app.inject(asAgent('/v1/agent/funding-sources'))).statusCode).toBe(503);
  });
});
