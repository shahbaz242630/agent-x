// SEC-OAUTH-02, -04, -05, -07, -08, -10, -12 (6E3a): an MCP client connected
// as an agent, through the use cases the OAuth routes call, on the real
// migrated schema, as the app role: a flow opened, a person's consent with
// step-up, the code exchanged once, the access token accepted at the MCP
// resource, a refresh used once, and the connection revoked by a reused code,
// a reused refresh token, the client, or a hand-over. The routes' own answers
// are oauth-routes.test.ts and oauth-requests.test.ts.
import { createHash } from 'node:crypto';

import {
  addAgent,
  agentKeysOf,
  AGENTS,
  createConnectionTokenCheck,
  MOST_LIVE_CONNECTIONS,
  type Scope,
} from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import {
  addMembership,
  createSessions,
  createStepUpChallenges,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import { challengeOf, flowById, newFlowCookie, type OauthTables } from '@agentx/core/modules/oauth';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { DAY_MS } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createAgentChanges, HAND_OVER_CONFIRM_OPERATION, HAND_OVER_OPERATION } from './agent-changes.ts';
import { createAgentKeyChanges, REVOKE_OPERATION } from './agent-key-changes.ts';
import type { AgentMember, AgentTables } from './agent-writes.ts';
import {
  type ConnectionConsents,
  CONSENT_CONFIRM_OPERATION,
  CONSENT_OPERATION,
  type ConsentAsked,
  type ConsentWrite,
  createConnectionConsents,
  DENY_OPERATION,
} from './connection-consents.ts';
import { createOauthAuthorizing, type OauthAuthorizing } from './oauth-authorizing.ts';
import { createOauthGrants, type GrantAnswer, type OauthGrants } from './oauth-grants.ts';
import { capabilitiesOf } from './oauth-wire.ts';
import type { SecurityEventNote } from './security-recorder.ts';

type Tables = AgentTables & OrganizationsTables & OauthTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x6e3a_a000_0000);
// In the past, so a sealed event's time (Postgres's clock) is never before the one the test reads with.
const START = new Date('2026-09-28T09:00:00Z');
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-00000006e3a0';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const capabilities = capabilitiesOf('https://app.agentx.example');
const REDIRECT = 'https://chatgpt.com/connector/oauth/cb';
const VERIFIER = 'v'.repeat(43);
const CALLER = { correlationId: CORRELATION, ip: '203.0.113.9' };

let clock: FixedClock;
let capture: LogCapture;
let noted: SecurityEventNote[];
let authorizing: OauthAuthorizing;
let grants: OauthGrants;
let consents: ConnectionConsents;
let clientId: string;

const challenges = () => createStepUpChallenges({ ids, clock });
const quiet = () => ({ keys, ids, logger: testLogger() });

type Member = AgentMember & { readonly membershipId: string };
let people = 0;

async function member(org: string, role: Role, amr: readonly string[] = PASSKEY): Promise<Member> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `oauth-connections-${String(people)}` },
    { ids, clock },
  );
  const { sessionId } = await createSessions({
    ids,
    clock,
    timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
  }).open(app, userId, { idpSessionId: 'V1_1', authTime: clock.now(), amr: [...amr] });
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

async function agent(
  org: string,
  owner: Member,
  scopes: readonly Scope[] = ['requests:read', 'requests:write', 'suppliers:read'],
) {
  const id = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addAgent(tx, states, {
      orgId: org,
      id,
      name: 'Buyer',
      owner: owner.membershipId,
      scopes,
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return id;
}

let keysUsed = 0;
const keyed = (who: AgentMember, operation: string, payload: string): IdempotentRequest => {
  keysUsed += 1;
  return {
    orgId: who.orgId,
    client: { kind: 'user', id: who.userId },
    operation,
    key: `k-${String(keysUsed)}`,
    payload,
  };
};

const stepUp = (who: AgentMember, challengeId: string, amr: readonly string[] = PASSKEY) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

/** A flow opened by a browser: its ID and the browser's cookie. */
async function opened(scope?: string, cookie?: string) {
  const answer = await authorizing.authorize(
    {
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT,
      state: 'xyz',
      code_challenge: challengeOf(VERIFIER),
      code_challenge_method: 'S256',
      resource: capabilities.resource,
      ...(scope === undefined ? {} : { scope }),
    },
    cookie,
  );
  if (answer.outcome !== 'opened') throw new Error(`not opened: ${JSON.stringify(answer)}`);
  return { flowId: answer.flowId, cookie: answer.cookie };
}

const consent = (who: AgentMember, flow: { flowId: string; cookie: string | undefined }, asked: ConsentAsked) =>
  consents.consent(who, keyed(who, CONSENT_OPERATION, JSON.stringify(asked)), flow, asked, CORRELATION);

const askedFor = (write: ConsentWrite): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

/** Asks, steps up and confirms; answers the confirm's write. */
async function allowed(
  who: AgentMember,
  flow: { flowId: string; cookie: string | undefined },
  asked: ConsentAsked,
  amr: readonly string[] = PASSKEY,
): Promise<ConsentWrite> {
  const challengeId = askedFor(await consent(who, flow, asked));
  await stepUp(who, challengeId, amr);
  return consents.confirm(
    who,
    keyed(who, CONSENT_CONFIRM_OPERATION, JSON.stringify({ ...asked, challengeId })),
    flow,
    asked,
    challengeId,
    CORRELATION,
  );
}

/** The code the browser was sent back with, after a consent confirmed. */
function codeOf(write: ConsentWrite): string {
  if (write.outcome !== 'connected' || write.redirectTo === null)
    throw new Error(`not connected: ${JSON.stringify(write)}`);
  const url = new URL(write.redirectTo);
  expect(url.origin + url.pathname).toBe(REDIRECT);
  expect(url.searchParams.get('state')).toBe('xyz');
  // SEC-OAUTH-12: the issuer named on the answer.
  expect(url.searchParams.get('iss')).toBe(capabilities.issuer);
  return url.searchParams.get('code') ?? '';
}

const exchange = (code: string, overrides: Partial<Parameters<OauthGrants['exchangeCode']>[0]> = {}) =>
  grants.exchangeCode(
    { code, clientId, redirectUri: REDIRECT, codeVerifier: VERIFIER, resource: capabilities.resource, ...overrides },
    CALLER,
  );

const issued = (answer: GrantAnswer) => {
  if (answer.outcome !== 'issued') throw new Error(`not issued: ${JSON.stringify(answer)}`);
  return answer.tokens;
};

const tokenCheck = () => createConnectionTokenCheck({ database: app, keys, ids, clock, logger: testLogger(capture) });
const accepted = (accessToken: string) => tokenCheck().check(accessToken, CORRELATION, capabilities.resource);

/** A whole connection: an admin's consent to an agent of theirs, the code exchanged. */
async function connected(
  org: string,
  admin: Member,
  agentId: string,
  scopes: readonly Scope[] = ['requests:read', 'suppliers:read'],
) {
  const write = await allowed(admin, await opened(), { agentId, scopes });
  const tokens = issued(await exchange(codeOf(write)));
  if (write.outcome !== 'connected') throw new Error('connected');
  return { ...tokens, keyId: write.connection.keyId, org };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  clock = new FixedClock(START);
  capture = new LogCapture();
  noted = [];
  const logger = testLogger(capture);
  authorizing = createOauthAuthorizing({ database: app, clock, ids, logger, capabilities });
  grants = createOauthGrants({
    database: app,
    keys,
    ids,
    clock,
    logger,
    capabilities,
    securityEvents: { note: (event) => noted.push(event) },
  });
  consents = createConnectionConsents({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    logger,
    issuer: capabilities.issuer,
  });
  const registered = await authorizing.register({ redirect_uris: [REDIRECT], client_name: 'ChatGPT' }, CORRELATION);
  if (registered.outcome !== 'registered') throw new Error('registered');
  clientId = registered.client.clientId;
});

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

describe(`SEC-OAUTH-10 the consent (Postgres ${server.version})`, () => {
  it('connects the client as the agent picked, with the scopes ticked: a key no list of keys shows', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const flow = await opened('requests:read requests:write suppliers:read offline_access');
    expect(await consents.request(flow)).toMatchObject({
      id: flow.flowId,
      client: { id: clientId, name: 'ChatGPT' },
      redirectHost: 'chatgpt.com',
      loopback: false,
      scopesAsked: ['requests:read', 'requests:write', 'suppliers:read'],
    });
    const write = await allowed(admin, flow, { agentId, scopes: ['suppliers:read', 'requests:read'] });
    expect(write).toMatchObject({
      outcome: 'connected',
      connection: { agentId, clientId, scopes: ['requests:read', 'suppliers:read'] },
    });
    expect(codeOf(write)).toMatch(/^axc_/);
    expect(await flowById(app, flow.flowId)).toMatchObject({ decided: 'allowed', orgId: org });
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      expect(await agentKeysOf(tx, states, org, agentId)).toEqual({ outcome: 'listed', keys: [] });
    });
    // Decided: the request is gone for its browser too.
    expect(await consents.request(flow)).toBeUndefined();
  });

  it('shows and decides a flow for its own browser alone', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const flow = await opened();
    for (const cookie of [undefined, newFlowCookie(), 'not a cookie']) {
      expect(await consents.request({ ...flow, cookie })).toBeUndefined();
      expect(await consent(admin, { ...flow, cookie }, { agentId, scopes: ['requests:read'] })).toEqual({
        outcome: 'refused',
        status: 404,
        code: 'NOT_FOUND',
      });
    }
    // A second flow in the same browser shares its cookie.
    const second = await opened(undefined, flow.cookie);
    expect(second.cookie).toBe(flow.cookie);
  });

  it('refuses a developer another member’s agent, an admin without a passkey, a scope not asked, and a suspended agent', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const viewer = await member(org, 'viewer');
    const agentId = await agent(org, admin);
    expect(await consent(developer, await opened(), { agentId, scopes: ['requests:read'] })).toMatchObject({
      code: 'FORBIDDEN',
    });
    expect(await consent(viewer, await opened(), { agentId, scopes: ['requests:read'] })).toMatchObject({
      code: 'FORBIDDEN',
    });
    const own = await agent(org, developer);
    expect(
      await allowed(developer, await opened(), { agentId: own, scopes: ['requests:read'] }, APP_CODE),
    ).toMatchObject({
      outcome: 'connected',
    });
    expect(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] }, APP_CODE)).toMatchObject({
      code: 'STEP_UP_FAILED',
    });
    expect(await consent(admin, await opened('requests:read'), { agentId, scopes: ['requests:write'] })).toMatchObject({
      code: 'CONNECTION_SCOPES_REFUSED',
    });
    const narrow = await agent(org, admin, ['requests:read']);
    expect(await consent(admin, await opened(), { agentId: narrow, scopes: ['suppliers:read'] })).toMatchObject({
      code: 'CONNECTION_SCOPES_REFUSED',
    });
    expect(
      await consent(admin, await opened(), { agentId: narrow, scopes: ['requests:read', 'requests:read'] }),
    ).toMatchObject({
      code: 'CONNECTION_SCOPES_REFUSED',
    });
    await withSignedStates(app, org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: org, id: narrow }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspend',
        details: {},
      }),
    );
    expect(await consent(admin, await opened(), { agentId: narrow, scopes: ['requests:read'] })).toMatchObject({
      code: 'CONNECTION_AGENT_NOT_ACTIVE',
    });
    expect(await consent(admin, await opened(), { agentId: ids.next(), scopes: ['requests:read'] })).toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('confirms a flow once: a confirm for a flow decided since rolls back, and a retry answers no address', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const flow = await opened();
    const asked = { agentId, scopes: ['requests:read'] as const };
    const challengeId = askedFor(await consent(admin, flow, asked));
    await stepUp(admin, challengeId);
    const idempotent = keyed(admin, CONSENT_CONFIRM_OPERATION, 'confirm once');
    const first = await consents.confirm(admin, idempotent, flow, asked, challengeId, CORRELATION);
    expect(first).toMatchObject({ outcome: 'connected' });
    const again = await consents.confirm(admin, idempotent, flow, asked, challengeId, CORRELATION);
    expect(again).toMatchObject({ outcome: 'connected', redirectTo: null, connection: { agentId } });
  });

  it('denies a flow, sending the browser back with access_denied, its state and our issuer', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const flow = await opened();
    const write = await consents.deny(admin, keyed(admin, DENY_OPERATION, 'deny'), flow, CORRELATION);
    if (write.outcome !== 'denied') throw new Error(`not denied: ${JSON.stringify(write)}`);
    const url = new URL(write.redirectTo);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      error: 'access_denied',
      state: 'xyz',
      iss: capabilities.issuer,
    });
    expect(await consents.deny(admin, keyed(admin, DENY_OPERATION, 'deny again'), flow, CORRELATION)).toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it(`keeps an agent to ${String(MOST_LIVE_CONNECTIONS)} live connections`, async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    for (let made = 0; made < MOST_LIVE_CONNECTIONS; made += 1) {
      expect(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] })).toMatchObject({
        outcome: 'connected',
      });
    }
    expect(await consent(admin, await opened(), { agentId, scopes: ['requests:read'] })).toMatchObject({
      code: 'CONNECTIONS_FULL',
    });
  });

  it('keeps an organisation to 20 connections made a day', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agents = [await agent(org, admin), await agent(org, admin), await agent(org, admin)];
    for (let made = 0; made < 20; made += 1) {
      const agentId = agents[made % agents.length] ?? '';
      expect(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] })).toMatchObject({
        outcome: 'connected',
      });
    }
    expect(await consent(admin, await opened(), { agentId: agents[0] ?? '', scopes: ['requests:read'] })).toMatchObject(
      {
        code: 'CONNECTIONS_SPENT',
      },
    );
  });
});

describe(`SEC-OAUTH-02, -03, -11, -12 the authorization request (Postgres ${server.version})`, () => {
  const asked = {
    response_type: 'code',
    redirect_uri: REDIRECT,
    state: 'xyz',
    code_challenge: challengeOf(VERIFIER),
    code_challenge_method: 'S256',
  };

  it('never sends a client it doesn’t know, or an address it never registered, anywhere', async () => {
    expect(
      await authorizing.authorize({ ...asked, client_id: 'axcl_ffffffffffffffffffffffffffffffff' }, undefined),
    ).toEqual({
      outcome: 'not_redirectable',
      problem: 'unknown_client',
    });
    expect(await authorizing.authorize({ ...asked, client_id: undefined }, undefined)).toMatchObject({
      problem: 'unknown_client',
    });
    expect(
      await authorizing.authorize(
        { ...asked, client_id: clientId, redirect_uri: 'https://evil.example/cb' },
        undefined,
      ),
    ).toEqual({ outcome: 'not_redirectable', problem: 'unregistered_redirect' });
  });

  it('takes the one registered address when the request names none', async () => {
    expect(
      await authorizing.authorize({ ...asked, client_id: clientId, redirect_uri: undefined }, undefined),
    ).toMatchObject({ outcome: 'opened' });
  });

  it.each([
    [{ response_type: 'token' }, 'unsupported_response_type'],
    [{ code_challenge: undefined }, 'invalid_request'],
    [{ code_challenge_method: 'plain' }, 'invalid_request'],
    [{ code_challenge: 'short' }, 'invalid_request'],
    [{ scope: 'openid' }, 'invalid_scope'],
    [{ resource: 'https://evil.example/v1/mcp' }, 'invalid_target'],
  ])('sends the browser back to the client with %j’s error, its state and our issuer', async (wrong, error) => {
    const answer = await authorizing.authorize({ ...asked, client_id: clientId, ...wrong }, undefined);
    if (answer.outcome !== 'refused') throw new Error(`not refused: ${JSON.stringify(answer)}`);
    const back = new URL(answer.redirectTo);
    expect(back.origin + back.pathname).toBe(REDIRECT);
    expect(back.searchParams.get('error')).toBe(error);
    expect(back.searchParams.get('state')).toBe('xyz');
    expect(back.searchParams.get('iss')).toBe(capabilities.issuer);
  });

  it('refuses a state too long, sending none back', async () => {
    const answer = await authorizing.authorize({ ...asked, client_id: clientId, state: 's'.repeat(513) }, undefined);
    if (answer.outcome !== 'refused') throw new Error('not refused');
    expect(new URL(answer.redirectTo).searchParams.get('state')).toBeNull();
    expect(new URL(answer.redirectTo).searchParams.get('error')).toBe('invalid_request');
  });

  it('refuses a registration that can’t be kept, with RFC 7591’s error', async () => {
    expect(await authorizing.register({ redirect_uris: ['http://a.example/cb'] }, CORRELATION)).toMatchObject({
      outcome: 'invalid',
      error: 'invalid_redirect_uri',
    });
  });
});

describe(`SEC-OAUTH-02, -04 the code exchanged once (Postgres ${server.version})`, () => {
  it('issues a pair whose access token acts as the agent, at the MCP endpoint, with the scopes ticked', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const tokens = await connected(org, admin, agentId);
    expect(tokens.accessToken).toMatch(/^axa_/);
    expect(tokens.refreshToken).toMatch(/^axr_/);
    expect(tokens.accessExpiresAt).toEqual(new Date(START.getTime() + 3600 * 1000));
    expect(await accepted(tokens.accessToken)).toMatchObject({
      outcome: 'accepted',
      key: { orgId: org, agentId, scopes: ['requests:read', 'suppliers:read'], credential: 'connection' },
    });
  });

  it('refuses a wrong verifier, redirect, client or resource, and a code past its minute', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const code = async () => codeOf(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] }));
    for (const overrides of [
      { codeVerifier: 'w'.repeat(43) },
      { redirectUri: `${REDIRECT}/other` },
      { clientId: 'axcl_ffffffffffffffffffffffffffffffff' },
      { resource: 'https://evil.example/v1/mcp' },
    ]) {
      expect(await exchange(await code(), overrides)).toMatchObject({ outcome: 'refused', error: 'invalid_grant' });
    }
    const late = await code();
    clock.advanceBy(61_000);
    expect(await exchange(late)).toMatchObject({ error: 'invalid_grant' });
    expect(await exchange('axc_not-a-code')).toMatchObject({ error: 'invalid_grant' });
    expect(noted).toContainEqual({ kind: 'oauth_refused', reason: 'invalid_grant', ip: CALLER.ip });
  });

  it('revokes the connection when its code is sent again: someone else holds it', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const code = codeOf(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] }));
    const tokens = issued(await exchange(code));
    expect(await exchange(code)).toMatchObject({ error: 'invalid_grant' });
    expect(await accepted(tokens.accessToken)).toEqual({ outcome: 'refused' });
    expect(lines('oauth.code_reused')).toEqual([expect.objectContaining({ level: 'warn', revoked: true, orgId: org })]);
  });
});

describe(`SEC-OAUTH-05, -08 a refresh token rotated, used once (Postgres ${server.version})`, () => {
  it('rotates a pair, narrowing the scopes when asked, never widening them', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const first = await connected(org, admin, agentId);
    const narrowed = issued(
      await grants.refresh(
        { refreshToken: first.refreshToken, clientId, scope: 'suppliers:read', resource: undefined },
        CALLER,
      ),
    );
    expect(narrowed.scopes).toEqual(['suppliers:read']);
    expect(await accepted(narrowed.accessToken)).toMatchObject({ key: { scopes: ['suppliers:read'] } });
    expect(
      await grants.refresh(
        { refreshToken: narrowed.refreshToken, clientId, scope: 'requests:read', resource: undefined },
        CALLER,
      ),
    ).toMatchObject({ error: 'invalid_scope' });
    expect(
      await grants.refresh(
        { refreshToken: narrowed.refreshToken, clientId, scope: undefined, resource: 'https://evil.example' },
        CALLER,
      ),
    ).toMatchObject({ error: 'invalid_target' });
    // Another client's refresh is refused, and changes nothing.
    expect(
      await grants.refresh(
        {
          refreshToken: narrowed.refreshToken,
          clientId: 'axcl_ffffffffffffffffffffffffffffffff',
          scope: undefined,
          resource: undefined,
        },
        CALLER,
      ),
    ).toMatchObject({ error: 'invalid_grant' });
    expect(
      issued(
        await grants.refresh(
          { refreshToken: narrowed.refreshToken, clientId, scope: undefined, resource: undefined },
          CALLER,
        ),
      ).scopes,
    ).toEqual(['suppliers:read']);
  });

  it('revokes the connection when a refresh token is used twice, and tells its organisation', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const first = await connected(org, admin, agentId);
    const refresh = { refreshToken: first.refreshToken, clientId, scope: undefined, resource: undefined };
    const second = issued(await grants.refresh(refresh, CALLER));
    expect(await grants.refresh(refresh, CALLER)).toMatchObject({ outcome: 'refused', error: 'invalid_grant' });
    expect(await accepted(second.accessToken)).toEqual({ outcome: 'refused' });
    expect(await grants.refresh({ ...refresh, refreshToken: second.refreshToken }, CALLER)).toMatchObject({
      error: 'invalid_grant',
    });
    expect(lines('oauth.refresh_reused')).toEqual([
      expect.objectContaining({ level: 'warn', revoked: true, orgId: org }),
    ]);
    expect(noted).toContainEqual({
      kind: 'connection_token_reused',
      reason: 'refresh_reused',
      ip: CALLER.ip,
      orgId: org,
      agentId,
    });
  });

  it('refuses a refresh token past its 30 idle days, and an access token sent as one', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = await connected(org, admin, await agent(org, admin));
    expect(
      await grants.refresh(
        { refreshToken: first.accessToken, clientId, scope: undefined, resource: undefined },
        CALLER,
      ),
    ).toMatchObject({ error: 'invalid_grant' });
    clock.advanceBy(30 * DAY_MS);
    expect(
      await grants.refresh(
        { refreshToken: first.refreshToken, clientId, scope: undefined, resource: undefined },
        CALLER,
      ),
    ).toMatchObject({ error: 'invalid_grant' });
  });
});

describe(`refusals on the way (Postgres ${server.version})`, () => {
  it('refuses a code whose agent was suspended after the consent', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const code = codeOf(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] }));
    await withSignedStates(app, org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: org, id: agentId }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspend',
        details: {},
      }),
    );
    expect(await exchange(code)).toMatchObject({ error: 'invalid_grant' });
    expect(lines('oauth.grant_refused')).toEqual([expect.objectContaining({ reason: 'agent_suspended' })]);
  });

  it('refuses a refresh token whose key no directory lists, or that is no token at all', async () => {
    const forged = `axr_${'1'.repeat(32)}_${'2'.repeat(32)}_${Buffer.alloc(32, 1).toString('base64url')}`;
    expect(
      await grants.refresh({ refreshToken: forged, clientId, scope: undefined, resource: undefined }, CALLER),
    ).toMatchObject({ error: 'invalid_grant' });
    expect(
      await grants.refresh({ refreshToken: 'axr_nothing', clientId, scope: undefined, resource: undefined }, CALLER),
    ).toMatchObject({ error: 'invalid_grant' });
    await grants.revoke({ token: forged.replace('axr_', 'axa_'), clientId }, CALLER);
    expect(lines('oauth.grant_refused').map(({ reason }) => reason)).toEqual(['unlisted', 'malformed']);
  });

  it('refuses a refresh token made with a pepper version this process no longer holds, logged as an error', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = await connected(org, admin, await agent(org, admin));
    const rotated = createKeyProvider({
      ...Object.fromEntries(
        PURPOSES.map((purpose, index) => [
          purpose,
          { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) },
        ]),
      ),
      'agent-key-pepper': { current: 2, versions: new Map([[2, Buffer.alloc(32, 0x42)]]) },
    });
    const elsewhere = createOauthGrants({
      database: app,
      keys: rotated,
      ids,
      clock,
      logger: testLogger(capture),
      capabilities,
      securityEvents: { note: () => undefined },
    });
    expect(
      await elsewhere.refresh(
        { refreshToken: first.refreshToken, clientId, scope: undefined, resource: undefined },
        CALLER,
      ),
    ).toMatchObject({ error: 'invalid_grant' });
    expect(lines('connection_token.refused')).toEqual([
      expect.objectContaining({ level: 'error', reason: 'key_not_held' }),
    ]);
  });

  it('refuses a consent to an agent tampered with, holding the organisation', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const owner = await tamperAsOwner(database, AGENTS, org);
    await owner.setColumn(agentId, 'scopes', 'requests:read requests:write sources:read suppliers:read');
    await owner.end();
    expect(await consent(admin, await opened(), { agentId, scopes: ['requests:read'] })).toMatchObject({
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`a connection revoked (Postgres ${server.version})`, () => {
  it('by its client, with either token (RFC 7009), and only its own client', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const first = await connected(org, admin, agentId);
    await grants.revoke({ token: first.accessToken, clientId: 'axcl_ffffffffffffffffffffffffffffffff' }, CALLER);
    expect(await accepted(first.accessToken)).toMatchObject({ outcome: 'accepted' });
    await grants.revoke({ token: first.refreshToken, clientId }, CALLER);
    expect(await accepted(first.accessToken)).toEqual({ outcome: 'refused' });
    // Nothing is answered of a token that is none, or already revoked.
    await grants.revoke({ token: 'nonsense', clientId }, CALLER);
    await grants.revoke({ token: first.accessToken, clientId: undefined }, CALLER);
  });

  it('by a hand-over, which revokes every connection key of the agent, as it does every key', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const next = await member(org, 'developer');
    const agentId = await agent(org, admin);
    const first = await connected(org, admin, agentId);
    const changes = createAgentChanges({
      database: app,
      keys,
      ids,
      clock,
      challenges: challenges(),
      outbox: createOutbox({ ids, clock }),
      logger: testLogger(),
    });
    const asked = await changes.handOver(
      admin,
      keyed(admin, HAND_OVER_OPERATION, `${agentId} ${next.membershipId}`),
      agentId,
      next.membershipId,
      CORRELATION,
    );
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    await stepUp(admin, asked.stepUpChallengeId);
    const handed = await changes.handOverConfirm(
      admin,
      keyed(admin, HAND_OVER_CONFIRM_OPERATION, `${agentId} ${next.membershipId} confirm`),
      agentId,
      next.membershipId,
      asked.stepUpChallengeId,
      CORRELATION,
    );
    expect(handed).toMatchObject({ outcome: 'handedOver' });
    expect(await accepted(first.accessToken)).toEqual({ outcome: 'refused' });
    expect(lines('connection_token.refused')).toEqual([expect.objectContaining({ reason: 'revoked' })]);
  });

  it('is no key of the agent’s to rotate or revoke as a key', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const { keyId } = await connected(org, admin, agentId);
    const keyChanges = createAgentKeyChanges({
      database: app,
      keys,
      ids,
      clock,
      challenges: challenges(),
      logger: testLogger(),
    });
    expect(
      await keyChanges.revoke(admin, keyed(admin, REVOKE_OPERATION, keyId), { agentId, keyId }, CORRELATION),
    ).toMatchObject({ code: 'NOT_FOUND' });
  });
});
