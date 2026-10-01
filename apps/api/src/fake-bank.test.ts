// D2-3c: the fake partner's bank on staging, played through the API against
// the fake itself (its records in memory): the accounts it offers, approving
// or turning down a link waiting under a session, only the caller's
// organisation's, and 404 wherever the partner isn't the fake. Who reaches
// the routes is the access hook's (role-matrix.test.ts).
import type { LiveSession, MembershipCheck, SignIn } from '@agentx/core/modules/identity';
import { createFakeRail, type FakeRail, SANDBOX_ACCOUNTS } from '@agentx/core/modules/providers';
import { createLogger } from '@agentx/platform/observability';
import { findLeaks, FixedClock, LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';

const PUBLIC_ORIGIN = 'https://app.agentx.example';
const COOKIE = 'S'.repeat(43);
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000dcba';
const LINK_ID = '0199a0f0-0000-7000-8000-0000000000d1';
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const IBANS = SANDBOX_ACCOUNTS.flatMap((account) => account.AccountIdentifiers.map((each) => each.Identification));

const LIVE: LiveSession = {
  sessionId: '0199a0f0-0000-7000-8000-000000000022',
  userId: '0199a0f0-0000-7000-8000-000000000011',
  idpSessionId: 'V1_1',
  authTime: new Date('2026-10-01T08:00:00.000Z'),
  // A passkey's sign-in, as an admin needs (ADR-012 §7).
  amr: ['pwd', 'user', 'mfa'],
  createdAt: new Date('2026-10-01T08:00:05.000Z'),
  lastSeenAt: new Date('2026-10-01T08:10:00.000Z'),
  endsAt: new Date('2099-10-01T20:00:05.000Z'),
  idleEndsAt: new Date('2099-10-01T08:40:00.000Z'),
};

const SIGN_IN: SignIn = {
  begin: () => Promise.reject(new Error('not in these tests')),
  beginStepUp: () => Promise.reject(new Error('not in these tests')),
  complete: () => Promise.reject(new Error('not in these tests')),
  signOut: () => Promise.resolve(false),
  signedIn: (cookie) => Promise.resolve(cookie === COOKIE ? LIVE : undefined),
};

const ADMIN: MembershipCheck = { outcome: 'active', id: '0199a0f0-0000-7000-8000-000000000033', role: 'admin' };

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** A server whose partner is `rail` (the fake, unless none), its caller an admin of ORG and of OTHER_ORG. */
async function withBank(rail: FakeRail | undefined) {
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: PUBLIC_ORIGIN,
      trustedProxies: [],
      rateLimitPerMinute: 1000,
      rateLimitPerUserPerMinute: 1000,
      rateLimitPerAgentPerMinute: 1000,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const app = await buildServer({
    config,
    logger: createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', ...config },
      destination: new LogCapture(),
    }),
    ids: new SequentialIds(),
    healthChecks: [],
    signIn: { service: SIGN_IN, sessionSeconds: 43_200 },
    restrictedUntil: () => Promise.resolve(undefined),
    findMembership: (orgId) =>
      Promise.resolve([ORG, OTHER_ORG].includes(orgId.toLowerCase()) ? ADMIN : ({ outcome: 'none' } as const)),
    fakeBank: rail?.bank,
  });
  servers.push(app);
  await app.ready();
  return app;
}

/** The fake partner, with a link started for ORG: its session. */
async function started() {
  const rail = createFakeRail({ clock: new FixedClock(new Date('2026-10-01T08:00:00Z')), ids: new SequentialIds() });
  const session = await rail.startSourceLink({ organizationId: ORG, linkId: LINK_ID });
  return { rail, sessionRef: session.sessionRef, app: await withBank(rail) };
}

const headers = (org: string) => ({
  cookie: `${SESSION_COOKIE}=${COOKIE}`,
  [ORGANIZATION_HEADER]: org,
  origin: PUBLIC_ORIGIN,
});

const step = (sessionRef: string, what: 'approve' | 'reject', payload: unknown = {}, org = ORG): InjectOptions => ({
  method: 'POST',
  url: `/v1/fake-bank/sessions/${sessionRef}/${what}`,
  headers: { ...headers(org), 'idempotency-key': crypto.randomUUID(), 'content-type': 'application/json' },
  payload: JSON.stringify(payload),
});

const REGISTRATION_ID = '0199a0f0-0000-7000-8000-0000000000d2';
const IBAN = IBANS[0] ?? '';

/** The fake partner, with a payee registration started through its form for ORG: the form's address. */
async function formOpen() {
  const rail = createFakeRail({ clock: new FixedClock(new Date('2026-10-01T08:00:00Z')), ids: new SequentialIds() });
  const outcome = await rail.registerBeneficiary({
    route: 'hosted',
    organizationId: ORG,
    registrationId: REGISTRATION_ID,
  });
  if (outcome.kind !== 'waiting') throw new Error('a hosted registration waits for its form');
  return { rail, url: outcome.formUrl, app: await withBank(rail) };
}

const fill = (payload: unknown, org = ORG): InjectOptions => ({
  method: 'POST',
  url: '/v1/fake-bank/payee-forms',
  headers: { ...headers(org), 'idempotency-key': crypto.randomUUID(), 'content-type': 'application/json' },
  payload: JSON.stringify(payload),
});

const accounts = (org = ORG): InjectOptions => ({
  method: 'GET',
  url: '/v1/fake-bank/accounts',
  headers: headers(org),
});

describe('GET /v1/fake-bank/accounts lists the bank’s sandbox accounts (D2-3c)', () => {
  it('answers each account’s ID and safe summary, and never a number', async () => {
    const { app } = await started();

    const response = await app.inject(accounts());

    expect(response.statusCode).toBe(200);
    const body = response.json<{ accounts: unknown[] }>();
    expect(body.accounts).toHaveLength(SANDBOX_ACCOUNTS.length);
    expect(body.accounts[0]).toEqual({
      accountId: ACCOUNT,
      holderName: 'Jasmine AI FZ-LLC',
      accountType: 'sme',
      currency: 'AED',
      hint: 'AE…6026',
    });
    expect(findLeaks(response.body, IBANS)).toEqual([]);
  });
});

describe('POST /v1/fake-bank/sessions/:sessionRef/approve (D2-3c)', () => {
  it('approves the link with the account, so the partner confirms it linked', async () => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject(step(sessionRef, 'approve', { accountId: ACCOUNT }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'approved' });
    const outcome = await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID });
    expect(outcome).toMatchObject({
      kind: 'linked',
      source: { availability: 'ACTIVE', summary: { holderName: 'Jasmine AI FZ-LLC', hint: 'AE…6026' } },
    });
  });

  it('leaves the source pending when the bank waits for another authoriser', async () => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject(
      step(sessionRef, 'approve', { accountId: ACCOUNT, awaitingOtherAuthorisers: true }),
    );

    expect(response.statusCode).toBe(200);
    const outcome = await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID });
    expect(outcome).toMatchObject({ kind: 'linked', source: { availability: 'PENDING' } });
  });

  it('answers 409 BANK_LINK_NOT_WAITING once the session is approved, and the first approval stands', async () => {
    const { app, rail, sessionRef } = await started();
    await app.inject(step(sessionRef, 'approve', { accountId: ACCOUNT }));

    const again = await app.inject(step(sessionRef, 'approve', { accountId: 'sme-trading-business-acct-01' }));

    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ error: { code: 'BANK_LINK_NOT_WAITING' } });
    const outcome = await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID });
    expect(outcome).toMatchObject({ kind: 'linked', source: { summary: { holderName: 'Jasmine AI FZ-LLC' } } });
  });

  it('answers 400 BANK_ACCOUNT_UNKNOWN for an account the bank doesn’t hold, and the link still waits', async () => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject(step(sessionRef, 'approve', { accountId: 'someone-else-acct-01' }));

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'BANK_ACCOUNT_UNKNOWN' } });
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID })).toEqual({ kind: 'waiting' });
  });

  it('finds another organisation’s session as none, and approves nothing (SEC-PTR-08)', async () => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject(step(sessionRef, 'approve', { accountId: ACCOUNT }, OTHER_ORG));

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'BANK_LINK_NOT_WAITING' } });
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID })).toEqual({ kind: 'waiting' });
  });

  it.each([
    {},
    { accountId: ACCOUNT, extra: 1 },
    { accountId: 'Not An ID' },
    { accountId: ACCOUNT, awaitingOtherAuthorisers: 'yes' },
  ])('refuses the body %j as malformed, before the bank is asked', async (payload) => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject(step(sessionRef, 'approve', payload));

    expect(response.statusCode).toBe(400);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID })).toEqual({ kind: 'waiting' });
  });
});

describe('POST /v1/fake-bank/sessions/:sessionRef/reject (D2-3c)', () => {
  it('takes no body at all', async () => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject({
      method: 'POST',
      url: `/v1/fake-bank/sessions/${sessionRef}/reject`,
      headers: { ...headers(ORG), 'idempotency-key': crypto.randomUUID() },
    });

    expect(response.statusCode).toBe(200);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID })).toEqual({
      kind: 'refused',
      reason: 'rejected',
    });
  });

  it('turns the link down, so the partner confirms it rejected, and a second time answers 409', async () => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject(step(sessionRef, 'reject'));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'rejected' });
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID })).toEqual({
      kind: 'refused',
      reason: 'rejected',
    });
    const again = await app.inject(step(sessionRef, 'reject'));
    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ error: { code: 'BANK_LINK_NOT_WAITING' } });
  });

  it('finds another organisation’s session as none, and turns nothing down', async () => {
    const { app, rail, sessionRef } = await started();

    const response = await app.inject(step(sessionRef, 'reject', {}, OTHER_ORG));

    expect(response.statusCode).toBe(409);
    expect(await rail.confirmSourceLink({ organizationId: ORG, linkId: LINK_ID })).toEqual({ kind: 'waiting' });
  });
});

describe('POST /v1/fake-bank/payee-forms: the partner’s payee form (E2-2a)', () => {
  it('fills in the form, so the partner holds the payee, masked, and the answer names no account', async () => {
    const { app, rail, url } = await formOpen();

    const response = await app.inject(fill({ url, name: 'Jasmine AI FZ-LLC', iban: IBAN }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'filled' });
    expect(findLeaks(response.body, IBANS)).toEqual([]);
    expect(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION_ID })).toMatchObject({
      kind: 'registered',
      beneficiary: { nameCheck: 'match', hint: 'AE…6026' },
    });
  });

  it('answers 400 BANK_FORM_REFUSED for details the form can’t take, and the form stays open', async () => {
    const { app, rail, url } = await formOpen();

    const response = await app.inject(fill({ url, name: 'Jasmine AI FZ-LLC', iban: 'AE000000000000000000000' }));

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: 'BANK_FORM_REFUSED' } });
    expect(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION_ID })).toMatchObject({
      kind: 'waiting',
    });
  });

  it('answers 409 BANK_FORM_NOT_OPEN once filled in, and for another organisation’s form, which is found as none', async () => {
    const { app, url } = await formOpen();

    const elsewhere = await app.inject(fill({ url, name: 'Jasmine AI FZ-LLC', iban: IBAN }, OTHER_ORG));
    expect(elsewhere.statusCode).toBe(409);
    expect(elsewhere.json()).toMatchObject({ error: { code: 'BANK_FORM_NOT_OPEN' } });

    expect((await app.inject(fill({ url, name: 'Jasmine AI FZ-LLC', iban: IBAN }))).statusCode).toBe(200);
    const again = await app.inject(fill({ url, name: 'Someone Else LLC', iban: IBAN }));
    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ error: { code: 'BANK_FORM_NOT_OPEN' } });
  });

  it.each([
    {},
    { url: 'https://payees.fake-partner.invalid/form/x', name: 'A', iban: IBAN, extra: 1 },
    { url: 'https://payees.fake-partner.invalid/form/x', name: 'A', iban: 'AE07-0331' },
    { url: 'a url with spaces', name: 'A', iban: IBAN },
    { url: 'https://payees.fake-partner.invalid/form/x', name: 'A'.repeat(141), iban: IBAN },
  ])('refuses the body %j as malformed, before the form is asked', async (payload) => {
    const { app, rail } = await formOpen();

    const response = await app.inject(fill(payload));

    expect(response.statusCode).toBe(400);
    expect(await rail.getBeneficiaryState({ organizationId: ORG, registrationId: REGISTRATION_ID })).toMatchObject({
      kind: 'waiting',
    });
  });
});

describe('the fake bank where the partner isn’t the fake (ADR-014 §4)', () => {
  it('answers every step 404 NOT_FOUND', async () => {
    const app = await withBank(undefined);

    for (const request of [
      accounts(),
      step('fake-link-1', 'approve', { accountId: ACCOUNT }),
      step('fake-link-1', 'reject'),
      fill({ url: 'https://payees.fake-partner.invalid/form/x', name: 'A', iban: IBAN }),
    ]) {
      const response = await app.inject(request);
      expect(response.statusCode).toBe(404);
      expect(response.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
    }
  });
});

describe('what the bank throws that isn’t a refusal', () => {
  it('is a failure on our side, answered 500', async () => {
    const { rail } = await started();
    const failing: FakeRail = {
      ...rail,
      bank: { ...rail.bank, reject: () => Promise.reject(new Error('the records are gone')) },
    };
    const app = await withBank(failing);

    const response = await app.inject(step('fake-link-1', 'reject'));

    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({ error: { code: 'INTERNAL_ERROR' } });
  });
});
