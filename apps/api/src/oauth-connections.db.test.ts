// SEC-OAUTH-02, -04, -05, -07, -08, -10, -12 (6E3a): an MCP client connected
// as an agent, through the use cases the OAuth routes call, on the real
// migrated schema, as the app role: a flow opened, a person's consent with
// step-up, the code exchanged once, the access token accepted at the MCP
// resource, a refresh used once, and the connection revoked by a reused code,
// a reused refresh token, the client, a hand-over, a member (6E3b) or the
// member's removal; and an agent's connections listed (6E3b). The routes' own answers
// are oauth-routes.test.ts and oauth-requests.test.ts.
import { createHash } from 'node:crypto';

import {
  addAgent,
  addAgentKey,
  agentKeysOf,
  AGENT_KEYS,
  AGENTS,
  CONNECTIONS,
  ENDED_CONNECTIONS_SHOWN_DAYS,
  createConnectionTokenCheck,
  MOST_LIVE_CONNECTIONS,
  type Scope,
} from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import {
  addMembership,
  createMembershipChanges,
  createSessions,
  DEACTIVATE_CONFIRM_OPERATION,
  DEACTIVATE_OPERATION,
  ROLE_CONFIRM_OPERATION,
  ROLE_OPERATION,
  createStepUpChallenges,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOutbox } from '@agentx/core/modules/notifications';
import {
  challengeOf,
  flowById,
  MOST_OPEN_FLOWS,
  MOST_OPEN_FLOWS_A_BROWSER,
  newFlowCookie,
  type OauthTables,
  sweepClients,
} from '@agentx/core/modules/oauth';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { DAY_MS, HOUR_MS } from '@agentx/core/shared-kernel';
import { AGENT_BRAKE, createDatabase, type Database, type IdempotentRequest, lockName } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilBlocked,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createAgentChanges, HAND_OVER_CONFIRM_OPERATION, HAND_OVER_OPERATION } from './agent-changes.ts';
import { createAgentKeyChanges, REVOKE_OPERATION, ROTATE_OPERATION } from './agent-key-changes.ts';
import type { AgentMember, AgentTables } from './agent-writes.ts';
import {
  CONNECTION_REVOKE_CONFIRM_OPERATION,
  CONNECTION_REVOKE_OPERATION,
  connectionsOfLeaving,
  createConnectionChanges,
} from './connection-changes.ts';
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

  it('takes an empty state as none, never a failure', async () => {
    const answer = await authorizing.authorize({ ...asked, client_id: clientId, state: '' }, undefined);
    if (answer.outcome !== 'opened') throw new Error(`not opened: ${JSON.stringify(answer)}`);
    expect(await flowById(app, answer.flowId)).toMatchObject({ state: null });
  });

  it(`holds one browser to ${String(MOST_OPEN_FLOWS_A_BROWSER)} open flows, a decided one freeing its place`, async () => {
    const cookie = newFlowCookie();
    const flows = [];
    for (let open = 0; open < MOST_OPEN_FLOWS_A_BROWSER; open += 1) flows.push(await opened(undefined, cookie));
    const full = await authorizing.authorize({ ...asked, client_id: clientId }, cookie);
    if (full.outcome !== 'refused') throw new Error(`not refused: ${JSON.stringify(full)}`);
    expect(new URL(full.redirectTo).searchParams.get('error')).toBe('temporarily_unavailable');
    expect(new URL(full.redirectTo).searchParams.get('iss')).toBe(capabilities.issuer);
    // Another browser is not held by it.
    expect(await authorizing.authorize({ ...asked, client_id: clientId }, newFlowCookie())).toMatchObject({
      outcome: 'opened',
    });
    const org = await organization();
    const admin = await member(org, 'admin');
    const [first] = flows;
    if (first === undefined) throw new Error('a flow');
    await consents.deny(admin, keyed(admin, DENY_OPERATION, 'free a place'), first, CORRELATION);
    expect(await authorizing.authorize({ ...asked, client_id: clientId }, cookie)).toMatchObject({ outcome: 'opened' });
  });

  it(`refuses every new flow while ${String(MOST_OPEN_FLOWS)} are open, with the warning`, async () => {
    const admin = database.as('admin');
    await admin.query(
      `insert into oauth.flows (id, kind, client_id, redirect_uri, code_challenge, scopes_asked, resource, browser_hash, created_at, ends_at)
       select gen_random_uuid(), 'code', 'filler', 'https://a.example/cb', $1, 'requests:read', 'r', $2, $3, $4
       from generate_series(1, $5::int)`,
      [challengeOf(VERIFIER), 'f'.repeat(64), START, new Date(START.getTime() + 900_000), MOST_OPEN_FLOWS],
    );
    try {
      const answer = await authorizing.authorize({ ...asked, client_id: clientId }, newFlowCookie());
      if (answer.outcome !== 'refused') throw new Error(`not refused: ${JSON.stringify(answer)}`);
      expect(new URL(answer.redirectTo).searchParams.get('error')).toBe('temporarily_unavailable');
      expect(lines('oauth.flows_capped')).toEqual([expect.objectContaining({ level: 'warn', refused: 1 })]);
      // At most one line a minute, however many are refused, then one counting them.
      await authorizing.authorize({ ...asked, client_id: clientId }, newFlowCookie());
      expect(lines('oauth.flows_capped')).toHaveLength(1);
      clock.advanceBy(60_000);
      await authorizing.authorize({ ...asked, client_id: clientId }, newFlowCookie());
      expect(lines('oauth.flows_capped')).toEqual([
        expect.objectContaining({ refused: 1 }),
        expect.objectContaining({ refused: 2 }),
      ]);
    } finally {
      await admin.query("delete from oauth.flows where client_id = 'filler'");
    }
  });

  it('answers busy back to the client, never a failure, when the flow’s transaction hits a limit', async () => {
    const failing = new Proxy(app, {
      get: (target, name) => {
        if (name === 'transaction') {
          return () => {
            throw Object.assign(new Error('forced'), { code: '57014' });
          };
        }
        const value = Reflect.get(target, name) as unknown;
        // Kysely's own private fields want the real object as `this`.
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    const busy = createOauthAuthorizing({ database: failing, clock, ids, logger: testLogger(capture), capabilities });
    const answer = await busy.authorize({ ...asked, client_id: clientId }, undefined);
    if (answer.outcome !== 'refused') throw new Error(`not refused: ${JSON.stringify(answer)}`);
    expect(new URL(answer.redirectTo).searchParams.get('error')).toBe('temporarily_unavailable');
    expect(new URL(answer.redirectTo).searchParams.get('iss')).toBe(capabilities.issuer);
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

  it('revokes the connection’s key at once when its code is used up without a pair', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const code = codeOf(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] }));
    expect(await exchange(code, { codeVerifier: 'w'.repeat(43) })).toMatchObject({ error: 'invalid_grant' });
    // Revoked by the failed exchange itself, before anyone sends the code again.
    const status = () =>
      withSignedStates(app, org, quiet(), (tx, states) =>
        agentKeysOf(tx, states, org, agentId, 'share', 'connections'),
      );
    expect(await status()).toMatchObject({ keys: [{ status: 'REVOKED' }] });
    // The right verifier now finds the code used, with nothing left to revoke.
    expect(await exchange(code)).toMatchObject({ error: 'invalid_grant' });
    expect(lines('oauth.code_reused')).toEqual([expect.objectContaining({ revoked: false })]);
  });

  it.each(['57014', '40P01'])(
    'lets the client send the same code again after a busy (%s) inside the exchange: no stolen code',
    async (code) => {
      const org = await organization();
      const admin = await member(org, 'admin');
      const agentId = await agent(org, admin);
      const sent = codeOf(await allowed(admin, await opened(), { agentId, scopes: ['requests:read'] }));
      // The tokens' MAC fails once, after the code was marked used inside the same transaction.
      let failed = false;
      const flaky: typeof keys = {
        ...keys,
        mac: (...args: Parameters<typeof keys.mac>) => {
          if (!failed) {
            failed = true;
            throw Object.assign(new Error('forced'), { code });
          }
          return keys.mac(...args);
        },
      };
      const once = createOauthGrants({
        database: app,
        keys: flaky,
        ids,
        clock,
        logger: testLogger(capture),
        capabilities,
        securityEvents: { note: () => undefined },
      });
      const exchanging = { code: sent, clientId, redirectUri: REDIRECT, codeVerifier: VERIFIER, resource: undefined };
      expect(await once.exchangeCode(exchanging, CALLER)).toMatchObject({
        status: 503,
        error: 'temporarily_unavailable',
      });
      const retried = issued(await once.exchangeCode(exchanging, CALLER));
      expect(await accepted(retried.accessToken)).toMatchObject({ outcome: 'accepted' });
      expect(lines('oauth.code_reused')).toEqual([]);
      expect(lines('oauth.grant_in_trouble')).toHaveLength(1);
    },
  );

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

describe(`busy: a database limit answered as temporarily_unavailable (Postgres ${server.version})`, () => {
  it.each(['57014', '40P01'])(
    'answers a refresh, and a revocation, busy when its transaction hits %s',
    async (code) => {
      const org = await organization();
      const admin = await member(org, 'admin');
      const first = await connected(org, admin, await agent(org, admin));
      const failing = new Proxy(app, {
        get: (target, name) => {
          if (name === 'transaction') {
            return () => {
              throw Object.assign(new Error('forced'), { code });
            };
          }
          const value = Reflect.get(target, name) as unknown;
          // Kysely's own private fields want the real object as `this`.
          return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
        },
      });
      const busy = createOauthGrants({
        database: failing,
        keys,
        ids,
        clock,
        logger: testLogger(capture),
        capabilities,
        securityEvents: { note: () => undefined },
      });
      const refresh = { refreshToken: first.refreshToken, clientId, scope: undefined, resource: undefined };
      expect(await busy.refresh(refresh, CALLER)).toMatchObject({ status: 503, error: 'temporarily_unavailable' });
      expect(await busy.revoke({ token: first.accessToken, clientId }, CALLER)).toMatchObject({ status: 503 });
      expect(lines('oauth.grant_in_trouble')).toHaveLength(2);
      // Nothing of it was kept: the refresh token still works.
      expect(await grants.refresh(refresh, CALLER)).toMatchObject({ outcome: 'issued' });
    },
  );
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
    expect(
      await keyChanges.rotate(admin, keyed(admin, ROTATE_OPERATION, keyId), { agentId, keyId }, 'overlap', CORRELATION),
    ).toMatchObject({ code: 'NOT_FOUND' });
  });
});

const connectionChanges = (at: FixedClock = clock) =>
  createConnectionChanges({ database: app, keys, ids, clock: at, challenges: challenges(), logger: testLogger() });

/** Asks to revoke the connection, steps up, and confirms: the confirm's write. */
async function revoked(who: Member, named: { agentId: string; keyId: string }, amr: readonly string[] = PASSKEY) {
  const changes = connectionChanges();
  const asked = await changes.revoke(who, keyed(who, CONNECTION_REVOKE_OPERATION, named.keyId), named, CORRELATION);
  if (asked.outcome !== 'asked') return asked;
  await stepUp(who, asked.stepUpChallengeId, amr);
  return changes.revokeConfirm(
    who,
    keyed(who, CONNECTION_REVOKE_CONFIRM_OPERATION, `${named.keyId} confirm`),
    named,
    asked.stepUpChallengeId,
    CORRELATION,
  );
}

/**
 * An admin asks to remove the member from the organisation (deactivate them) and steps up: the confirm, to send when
 * the test is ready (ADR-006's forced cases send it while a lock is held).
 */
async function removalAsked(admin: Member, gone: Member, leavingAt: FixedClock = clock) {
  const memberships = createMembershipChanges({
    database: app,
    keys,
    ids,
    challenges: challenges(),
    outbox: createOutbox({ ids, clock }),
    logger: testLogger(capture),
    leaving: connectionsOfLeaving(leavingAt),
  });
  const asked = await memberships.ask(
    admin,
    keyed(admin, DEACTIVATE_OPERATION, gone.membershipId),
    gone.membershipId,
    { kind: 'deactivate' },
    CORRELATION,
  );
  if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
  await stepUp(admin, asked.stepUpChallengeId);
  return () =>
    memberships.confirm(
      admin,
      keyed(admin, DEACTIVATE_CONFIRM_OPERATION, `${gone.membershipId} confirm`),
      gone.membershipId,
      { kind: 'deactivate' },
      asked.stepUpChallengeId,
      CORRELATION,
    );
}

/** An admin removes the member from the organisation, with step-up: the confirm's write. */
const removed = async (admin: Member, gone: Member, leavingAt: FixedClock = clock) =>
  (await removalAsked(admin, gone, leavingAt))();

/** The keys a member's removal revoked, by the reason on their events. */
const revokedOnRemoval = async (org: string) =>
  (
    await database.as('admin').query<{ id: string }>(
      `select subject_id as id from audit.events where org_id = $1 and action = 'agent_key.revoked'
           and details::jsonb ->> 'reason' = 'member_removed' order by seq`,
      [org],
    )
  ).map(({ id }) => id);

/** The client's row's connection times, as kept. */
const clientTimes = async (id: string) => {
  const [row] = await database
    .as('admin')
    .query<{ first: Date | null; last: Date | null }>(
      'select first_connected_at as first, last_connected_at as last from oauth.clients where client_id = $1',
      [id],
    );
  return row;
};

const BRAKE_SHARED = 'select pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended($1, 0))';
const BRAKE_ALONE = 'select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))';
const BRAKE_FREE = 'select pg_catalog.pg_try_advisory_lock_shared(pg_catalog.hashtextextended($1, 0)) as free';
const BRAKE_LET_GO = 'select pg_catalog.pg_advisory_unlock_shared(pg_catalog.hashtextextended($1, 0))';
const KEY_SHARE = 'select 1 from agents.agent_keys where org_id = $1 and id = $2 for share';

/** A lock a holding transaction takes. */
type Hold = (holder: TestClient) => Promise<unknown>;
const brakeShared =
  (name: string): Hold =>
  (holder) =>
    holder.query(BRAKE_SHARED, [name]);
const brakeAlone =
  (name: string): Hold =>
  (holder) =>
    holder.query(BRAKE_ALONE, [name]);
const keyShared =
  (org: string, keyId: string): Hold =>
  (holder) =>
    holder.query(KEY_SHARE, [org, keyId]);

/** A transaction of its own, begun, holding what `holds` take, as a decision part-way through its work does. */
async function holding(...holds: readonly Hold[]): Promise<TestClient> {
  const holder = await database.connect('admin');
  await holder.query('begin');
  for (const hold of holds) await hold(holder);
  return holder;
}

const letGo = async (holder: TestClient) => {
  await holder.query('rollback');
  await holder.end();
};

/** Whether the brake is free of any exclusive holder now: a shared try taken and given straight back. */
async function brakeFree(name: string): Promise<boolean> {
  const session = await database.connect('admin');
  try {
    const [row] = await session.query<{ free: boolean }>(BRAKE_FREE, [name]);
    if (row?.free === true) await session.query(BRAKE_LET_GO, [name]);
    return row?.free === true;
  } finally {
    await session.end();
  }
}

describe(`SEC-OAUTH-06, -07 an agent's connections listed (Postgres ${server.version})`, () => {
  it('lists them newest first, each as its signed state says, ended ones until 30 days after their expiry', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const first = await connected(org, admin, agentId);
    clock.advanceBy(60_000);
    const second = await connected(org, admin, agentId, ['requests:read']);
    expect(await revoked(admin, { agentId, keyId: first.keyId })).toMatchObject({ outcome: 'revoked' });

    const listed = await connectionChanges().list(org, agentId, CORRELATION);
    const made = {
      clientId,
      clientName: 'ChatGPT',
      redirectHost: 'chatgpt.com',
      via: 'code',
      madeBy: admin.membershipId,
    };
    expect(listed).toEqual({
      connections: [
        {
          ...made,
          keyId: second.keyId,
          scopes: ['requests:read'],
          createdAt: clock.now(),
          expiresAt: new Date(clock.now().getTime() + 90 * DAY_MS),
          lastConnectedAt: clock.now(),
          status: 'ACTIVE',
        },
        {
          ...made,
          keyId: first.keyId,
          scopes: ['requests:read', 'suppliers:read'],
          createdAt: START,
          expiresAt: new Date(START.getTime() + 90 * DAY_MS),
          lastConnectedAt: START,
          status: 'REVOKED',
        },
      ],
    });
    // Past its expiry, the live one is EXPIRED; each is listed until 30 days past its key's expiry (or when it would
    // have expired, revoked), inside its tokens' 120 days: its last connection is still known (lastConnectedAt).
    const at = (ms: number) => connectionChanges(new FixedClock(new Date(ms)));
    const firstEnds = START.getTime() + 90 * DAY_MS;
    expect(await at(clock.now().getTime() + 90 * DAY_MS).list(org, agentId, CORRELATION)).toMatchObject({
      connections: [
        { keyId: second.keyId, status: 'EXPIRED', lastConnectedAt: clock.now() },
        { keyId: first.keyId, status: 'REVOKED', lastConnectedAt: START },
      ],
    });
    const shownUntil = firstEnds + ENDED_CONNECTIONS_SHOWN_DAYS * DAY_MS;
    expect(ENDED_CONNECTIONS_SHOWN_DAYS).toBe(30);
    expect(await at(shownUntil - 1).list(org, agentId, CORRELATION)).toMatchObject({
      connections: [{ keyId: second.keyId }, { keyId: first.keyId, lastConnectedAt: START }],
    });
    expect(await at(shownUntil).list(org, agentId, CORRELATION)).toMatchObject({
      connections: [{ keyId: second.keyId, status: 'EXPIRED' }],
    });
    const gone = new FixedClock(new Date(clock.now().getTime() + (90 + 30) * DAY_MS));
    expect(await connectionChanges(gone).list(org, agentId, CORRELATION)).toEqual({ connections: [] });
  });

  it('answers NOT_FOUND for another organisation’s agent, and INTEGRITY_FAILED for a connection tampered with', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    await connected(org, admin, agentId);
    const other = await organization();
    expect(await connectionChanges().list(other, agentId, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });

    const owner = await tamperAsOwner(database, CONNECTIONS, org);
    const [row] = await database
      .as('admin')
      .query<{ id: string }>('select id from agents.connections where org_id = $1', [org]);
    // Made once (a trigger refuses any change), so its signed events are what goes.
    await owner.deleteEvents(row?.id ?? '');
    await owner.end();
    expect(await connectionChanges().list(org, agentId, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`SEC-OAUTH-07, -10 a connection revoked by a member (Postgres ${server.version})`, () => {
  it('stops at once, with step-up: its tokens refused, and a second revocation refused', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const { keyId, accessToken, refreshToken } = await connected(org, admin, agentId);

    expect(await revoked(admin, { agentId, keyId })).toMatchObject({
      outcome: 'revoked',
      connections: [{ keyId, status: 'REVOKED' }],
    });
    expect(await accepted(accessToken)).toEqual({ outcome: 'refused' });
    expect(
      await grants.refresh({ refreshToken, clientId, scope: undefined, resource: undefined }, CALLER),
    ).toMatchObject({ error: 'invalid_grant' });
    expect(await revoked(admin, { agentId, keyId })).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'CONNECTION_REVOKED',
    });
  });

  it('is a developer’s only for an agent they own; a key that is no connection is NOT_FOUND', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const viewer = await member(org, 'viewer');
    const agentId = await agent(org, admin);
    const { keyId, accessToken } = await connected(org, admin, agentId);

    expect(await revoked(developer, { agentId, keyId })).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
    expect(await revoked(viewer, { agentId, keyId })).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await accepted(accessToken)).toMatchObject({ outcome: 'accepted' });

    // The agent's own key (the hand-over's new one is one; a plain key here): revoked as a key, not as a connection.
    const plain = await withSignedStates(app, org, quiet(), async (tx, states) => {
      await addAgentKey(tx, states, {
        orgId: org,
        id: ids.next(),
        agentId,
        scopes: ['requests:read'],
        secretMac: Buffer.alloc(32, 7),
        secretKeyVersion: 1,
        expiresAt: new Date(clock.now().getTime() + DAY_MS),
        createdAt: clock.now(),
        actor: OPERATOR,
      });
      return agentKeysOf(tx, states, org, agentId);
    });
    if (plain.outcome !== 'listed') throw new Error('listed');
    const [own] = plain.keys;
    expect(await revoked(admin, { agentId, keyId: own?.id ?? '' })).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });
    // Another agent's connection, named under this agent: NOT_FOUND too.
    const otherAgent = await agent(org, admin);
    expect(await revoked(admin, { agentId: otherAgent, keyId })).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });

    const devAgent = await agent(org, developer);
    const mine = await connected(org, developer, devAgent);
    expect(await revoked(developer, { agentId: devAgent, keyId: mine.keyId })).toMatchObject({ outcome: 'revoked' });
  });

  it('removing a member revokes the connections they made, and only those (decision 7)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const agentId = await agent(org, developer);
    const theirs = await connected(org, developer, agentId);
    const kept = await connected(org, admin, agentId);
    expect(await removed(admin, developer)).toMatchObject({ outcome: 'written', member: { status: 'DEACTIVATED' } });

    expect(await accepted(theirs.accessToken)).toEqual({ outcome: 'refused' });
    expect(await accepted(kept.accessToken)).toMatchObject({ outcome: 'accepted' });
    const events = await database
      .as('admin')
      .query<{ details: { reason?: string; membershipId?: string } }>(
        `select details::jsonb as details from audit.events where org_id = $1 and action = 'agent_key.revoked'`,
        [org],
      );
    expect(events.map(({ details }) => details)).toEqual([
      expect.objectContaining({ reason: 'member_removed', membershipId: developer.membershipId }),
    ]);
  });

  it('answers INTEGRITY_FAILED for anything tampered with, changing nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const agentId = await agent(org, developer);
    const { keyId } = await connected(org, developer, agentId);
    const integrityFailed = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };

    // The connection's key: its scopes widened behind the seal. Its list, its revocation and its maker's removal refuse.
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    const saved = await owner.saveRow(keyId);
    await owner.setColumn(keyId, 'scopes', 'requests:read requests:write sources:read suppliers:read');
    await owner.end();
    expect(await connectionChanges().list(org, agentId, CORRELATION)).toEqual(integrityFailed);
    expect(await revoked(admin, { agentId, keyId })).toEqual(integrityFailed);
    expect(await removed(admin, developer)).toEqual(integrityFailed);

    // The agent, the key put back: the revocation refuses, and the connection is untouched.
    const restoring = await tamperAsOwner(database, AGENT_KEYS, org);
    await restoring.restoreRow(saved);
    await restoring.end();
    const agents = await tamperAsOwner(database, AGENTS, org);
    await agents.setColumn(agentId, 'scopes', 'requests:read requests:write sources:read suppliers:read');
    await agents.end();
    expect(await revoked(admin, { agentId, keyId })).toEqual(integrityFailed);
    expect(await connectionChanges().list(org, agentId, CORRELATION)).toEqual(integrityFailed);
    expect(await connectionChanges().list(org, ids.next(), CORRELATION)).toMatchObject({ code: 'NOT_FOUND' });
    expect(await revoked(admin, { agentId: ids.next(), keyId })).toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe(`ADR-006 §6 1b: removing a member takes their agents' brakes, in order (Postgres ${server.version})`, () => {
  const brakeOf = (org: string, agentId: string) => lockName(AGENT_BRAKE, org, agentId);

  it('queues behind a decision inside the brake holding the key FOR SHARE, and a later one queues behind it', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const agentId = await agent(org, developer);
    const { keyId, accessToken } = await connected(org, developer, agentId);
    const confirm = await removalAsked(admin, developer);
    const monitor = database.as('admin');
    // A decision part-way: the brake's shared side, then the key FOR SHARE, as a key check holds them.
    const inside = await holding(brakeShared(brakeOf(org, agentId)), keyShared(org, keyId));

    const removing = confirm();
    const [remover] = await waitUntilQueued(monitor, 1);
    // A decision after it lines up behind the waiting removal, never past it: the key's FOR SHARE can't starve it.
    const late = await holding();
    const lateTaking = late.query(BRAKE_SHARED, [brakeOf(org, agentId)]);
    const queued = await waitUntilQueued(monitor, 2);
    const latecomer = queued.find((pid) => pid !== remover) ?? 0;
    expect(await waitUntilBlocked(monitor, latecomer)).toContain(remover);

    await letGo(inside);
    expect(await removing).toMatchObject({ outcome: 'written', member: { status: 'DEACTIVATED' } });
    await lateTaking;
    await letGo(late);
    expect(await accepted(accessToken)).toEqual({ outcome: 'refused' });
  });

  it.each([
    ['the lower held: it waits there, holding neither', 'lower'],
    ['the higher held: it waits there, holding the lower', 'higher'],
  ] as const)('takes two agents’ brakes in order of agent ID: %s', async (_, held) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const [lower, higher] = [await agent(org, developer), await agent(org, developer)].sort();
    if (lower === undefined || higher === undefined) throw new Error('two agents');
    const first = await connected(org, developer, lower);
    const second = await connected(org, developer, higher);
    const confirm = await removalAsked(admin, developer);
    const blocker = await holding(brakeAlone(brakeOf(org, held === 'lower' ? lower : higher)));

    const removing = confirm();
    await waitUntilQueued(database.as('admin'), 1);
    expect(await brakeFree(brakeOf(org, held === 'lower' ? higher : lower))).toBe(held === 'lower');

    await letGo(blocker);
    expect(await removing).toMatchObject({ outcome: 'written' });
    expect(await accepted(first.accessToken)).toEqual({ outcome: 'refused' });
    expect(await accepted(second.accessToken)).toEqual({ outcome: 'refused' });
  });

  it('answers ORGANISATION_BUSY past the brake’s wait, nothing changed, with the alarm a stop raises', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const agentId = await agent(org, developer);
    const { accessToken } = await connected(org, developer, agentId);
    const confirm = await removalAsked(admin, developer);
    const stuck = await holding(brakeAlone(brakeOf(org, agentId)));
    try {
      expect(await confirm()).toEqual({ outcome: 'refused', status: 503, code: 'ORGANISATION_BUSY' });
    } finally {
      await letGo(stuck);
    }
    expect(lines('brake.not_applied')).toEqual([expect.objectContaining({ orgId: org })]);
    expect(await accepted(accessToken)).toMatchObject({ outcome: 'accepted' });
    // Nothing was kept: the same removal, sent again, is made.
    expect(await removed(admin, developer)).toMatchObject({ outcome: 'written' });
  }, 40_000);
});

describe(`SEC-OAUTH-06 a connection's own record tampered with, at its revocation (Postgres ${server.version})`, () => {
  it('answers INTEGRITY_FAILED, and a wrong step-up STEP_UP_FAILED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const { keyId } = await connected(org, admin, agentId);
    const changes = connectionChanges();
    const asked = await changes.revoke(
      admin,
      keyed(admin, CONNECTION_REVOKE_OPERATION, keyId),
      { agentId, keyId },
      CORRELATION,
    );
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    expect(
      await changes.revokeConfirm(
        admin,
        keyed(admin, CONNECTION_REVOKE_CONFIRM_OPERATION, `${keyId} unproven`),
        { agentId, keyId },
        asked.stepUpChallengeId,
        CORRELATION,
      ),
    ).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });

    const owner = await tamperAsOwner(database, CONNECTIONS, org);
    await owner.deleteEvents(keyId);
    await owner.end();
    expect(await revoked(admin, { agentId, keyId })).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`mutation pass (6E3b): what each survivor showed untested (Postgres ${server.version})`, () => {
  it('M08: a step-up for one connection’s revocation can’t revoke another', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const a = await connected(org, admin, agentId);
    const b = await connected(org, admin, agentId);
    const changes = connectionChanges();
    const asked = await changes.revoke(
      admin,
      keyed(admin, CONNECTION_REVOKE_OPERATION, a.keyId),
      { agentId, keyId: a.keyId },
      CORRELATION,
    );
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    await stepUp(admin, asked.stepUpChallengeId);
    expect(
      await changes.revokeConfirm(
        admin,
        keyed(admin, CONNECTION_REVOKE_CONFIRM_OPERATION, `${b.keyId} with a's step-up`),
        { agentId, keyId: b.keyId },
        asked.stepUpChallengeId,
        CORRELATION,
      ),
    ).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect(await accepted(b.accessToken)).toMatchObject({ outcome: 'accepted' });
    expect(await accepted(a.accessToken)).toMatchObject({ outcome: 'accepted' });
  });

  it('M20: an agent’s list shows its own connections alone', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const x = await agent(org, admin);
    const y = await agent(org, admin);
    const ofX = await connected(org, admin, x);
    const ofY = await connected(org, admin, y);
    const keysOf = async (agentId: string) => {
      const listed = await connectionChanges().list(org, agentId, CORRELATION);
      if ('outcome' in listed) throw new Error(`not listed: ${JSON.stringify(listed)}`);
      return listed.connections.map(({ keyId }) => keyId);
    };
    expect(await keysOf(x)).toEqual([ofX.keyId]);
    expect(await keysOf(y)).toEqual([ofY.keyId]);
  });

  it('M29, M30: a code’s exchange and a refresh each note when the client connected; the sweep keeps it', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const agentId = await agent(org, admin);
    const { refreshToken } = await connected(org, admin, agentId);
    expect(await clientTimes(clientId)).toEqual({ first: START, last: START });

    clock.advanceBy(HOUR_MS);
    expect(
      await grants.refresh({ refreshToken, clientId, scope: undefined, resource: undefined }, CALLER),
    ).toMatchObject({ outcome: 'issued' });
    expect(await clientTimes(clientId)).toEqual({ first: START, last: clock.now() });
    await sweepClients(app, new Date(clock.now().getTime() + DAY_MS), 1000);
    expect(await clientTimes(clientId)).toBeDefined();
  });

  it('M17: a member’s removal revokes their live connections, never one already expired', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const agentId = await agent(org, developer);
    const ending = await connected(org, developer, agentId);
    clock.advanceBy(10 * 60_000);
    const live = await connected(org, developer, agentId);
    // Read once the first has expired and the second not: its key's 90 days ended 10 minutes before the second's.
    const between = new FixedClock(new Date(START.getTime() + 90 * DAY_MS + 5 * 60_000));
    expect(await removed(admin, developer, between)).toMatchObject({ outcome: 'written' });
    expect(await revokedOnRemoval(org)).toEqual([live.keyId]);
    expect(ending.keyId).not.toBe(live.keyId);
  });

  it('M18, M19: a member’s removal revokes their active connections, never one revoked already', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const agentId = await agent(org, developer);
    const gone = await connected(org, developer, agentId);
    const live = await connected(org, developer, agentId);
    expect(await revoked(admin, { agentId, keyId: gone.keyId })).toMatchObject({ outcome: 'revoked' });
    expect(await removed(admin, developer)).toMatchObject({ outcome: 'written' });
    expect(await revokedOnRemoval(org)).toEqual([live.keyId]);
  });

  it('M03: an admin revokes with a passkey alone; a developer, on their own agent, with their app code', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer', APP_CODE);
    const adminsAgent = await agent(org, admin);
    const theirs = await connected(org, admin, adminsAgent);
    expect(await revoked(admin, { agentId: adminsAgent, keyId: theirs.keyId }, APP_CODE)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await accepted(theirs.accessToken)).toMatchObject({ outcome: 'accepted' });

    const developersAgent = await agent(org, developer);
    const own = await connected(org, admin, developersAgent);
    expect(await revoked(developer, { agentId: developersAgent, keyId: own.keyId }, APP_CODE)).toMatchObject({
      outcome: 'revoked',
    });
    expect(await accepted(own.accessToken)).toEqual({ outcome: 'refused' });
  });

  it('M13: a role change ends nothing of the member’s connections, nor reads them', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const agentId = await agent(org, developer);
    const { keyId, accessToken } = await connected(org, developer, agentId);
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    const saved = await owner.saveRow(keyId);
    await owner.setColumn(keyId, 'scopes', 'requests:read requests:write sources:read suppliers:read');
    await owner.end();
    const memberships = createMembershipChanges({
      database: app,
      keys,
      ids,
      challenges: challenges(),
      outbox: createOutbox({ ids, clock }),
      logger: testLogger(),
      leaving: connectionsOfLeaving(clock),
    });
    const toViewer = { kind: 'role', role: 'viewer' } as const;
    const asked = await memberships.ask(
      admin,
      keyed(admin, ROLE_OPERATION, `${developer.membershipId} viewer`),
      developer.membershipId,
      toViewer,
      CORRELATION,
    );
    if (asked.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(asked)}`);
    await stepUp(admin, asked.stepUpChallengeId);
    expect(
      await memberships.confirm(
        admin,
        keyed(admin, ROLE_CONFIRM_OPERATION, `${developer.membershipId} viewer confirm`),
        developer.membershipId,
        toViewer,
        asked.stepUpChallengeId,
        CORRELATION,
      ),
    ).toMatchObject({ outcome: 'written', member: { role: 'viewer' } });
    const restoring = await tamperAsOwner(database, AGENT_KEYS, org);
    await restoring.restoreRow(saved);
    await restoring.end();
    expect(await accepted(accessToken)).toMatchObject({ outcome: 'accepted' });
    expect(await revokedOnRemoval(org)).toEqual([]);
  });
});
