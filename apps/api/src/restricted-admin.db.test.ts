// SEC-OPS-04 (6F1 gate, G1): for 7 days after a counted second factor
// removal, an admin keeps only what a developer may do, on the routes a
// developer shares too: rotating an agent's key, connecting an MCP client as
// an agent, revoking a connection. A developer does those for an agent of
// their own alone; so does the restricted admin, though their stored role is
// admin. Through the whole server, on the real migrated schema, as the app
// role: the restriction read from the platform chain as the API reads it, the
// membership read again in the use case's own transaction.
import { createHash } from 'node:crypto';

import {
  addAgent,
  addAgentKey,
  agentKeyText,
  createAgentKeyCheck,
  keySecretMessage,
} from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import {
  addMembership,
  createRemovalRestriction,
  createSessions,
  createStepUpChallenges,
  membershipFor,
  type Role,
  SECOND_FACTORS_REMOVED,
  userForSubject,
} from '@agentx/core/modules/identity';
import { challengeOf, type OauthTables } from '@agentx/core/modules/oauth';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { DAY_MS } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { createAgentChanges, REACTIVATE_OPERATION } from './agent-changes.ts';
import { createAgentKeyChanges } from './agent-key-changes.ts';
import type { AgentTables } from './agent-writes.ts';
import { createConnectionChanges } from './connection-changes.ts';
import { createConnectionConsents } from './connection-consents.ts';
import { createOauthAuthorizing, type OauthAuthorizing } from './oauth-authorizing.ts';
import { createOauthClients } from './oauth-clients.ts';
import { createOauthDevice } from './oauth-device.ts';
import { createOauthGrants } from './oauth-grants.ts';
import { capabilitiesOf, CONNECT_COOKIE } from './oauth-wire.ts';
import { buildServer } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { worded } from './statement-words.helper.test.ts';

type Tables = AgentTables & OrganizationsTables & OauthTables & PlatformControlsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x6f1a_0000_0000);
// In the past, so a sealed event's time (Postgres's clock) is never before the one the test reads with.
const START = new Date('2026-10-12T09:00:00Z');
const clock = new FixedClock(START);
const ORIGIN = 'https://app.agentx.example';
const capabilities = capabilitiesOf(ORIGIN);
const REDIRECT = 'https://chatgpt.com/connector/oauth/cb';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000006f1';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const logger = createLogger({
  service: 'test',
  config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
  destination: new LogCapture(),
});
const quiet = { keys, ids, logger };
const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
const challenges = () => createStepUpChallenges({ ids, clock });

interface Person {
  readonly orgId: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly cookie: string;
  readonly membershipId: string;
}

let api: FastifyInstance;
let authorizing: OauthAuthorizing;
let clientId: string;
let people = 0;

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet, (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

/** A member signed in with a passkey; with a second factor removed by a reset a day ago when `restricted`. */
async function member(org: string, role: Role, restricted = false): Promise<Person> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `restricted-admin-${String(people)}` },
    { ids, clock },
  );
  const { sessionId, cookie } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet, (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  if (restricted) {
    await createPlatformChain({ keys, ids }).recordAlone(app, {
      actor: { type: 'system', id: 'api' },
      action: SECOND_FACTORS_REMOVED,
      details: { person: userId, org, reset: ids.next(), at: new Date(START.getTime() - DAY_MS).toISOString() },
    });
  }
  return { orgId: org, userId, sessionId, cookie, membershipId };
}

/** An agent owned by `owner`, with one live key: its ID, the key's, and the key as its agent sends it. */
async function agentWithKey(owner: Person) {
  const agentId = ids.next();
  const keyId = ids.next();
  const secret = Buffer.alloc(32, people);
  await withSignedStates(app, owner.orgId, quiet, async (tx, states) => {
    await addAgent(tx, states, {
      orgId: owner.orgId,
      id: agentId,
      name: 'Purchasing bot',
      owner: owner.membershipId,
      scopes: ['requests:read', 'requests:write'],
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(keyId, secret));
    await addAgentKey(tx, states, {
      orgId: owner.orgId,
      id: keyId,
      agentId,
      scopes: ['requests:read', 'requests:write'],
      secretMac: mac,
      secretKeyVersion: keyVersion,
      expiresAt: new Date(START.getTime() + 90 * DAY_MS),
      createdAt: clock.now(),
      actor: OPERATOR,
    });
  });
  return { agentId, keyId, text: agentKeyText(keyId, secret) };
}

let keysUsed = 0;
/** A write as the person's browser sends it, a flow's cookie beside their session's when given. */
async function sent(who: Person, url: string, body: unknown, flowCookie?: string) {
  keysUsed += 1;
  const cookies = [
    `${SESSION_COOKIE}=${who.cookie}`,
    ...(flowCookie === undefined ? [] : [`${CONNECT_COOKIE}=${flowCookie}`]),
  ];
  return api.inject({
    method: 'POST',
    url,
    headers: {
      cookie: cookies.join('; '),
      [ORGANIZATION_HEADER]: who.orgId,
      origin: ORIGIN,
      'idempotency-key': `restricted-${String(keysUsed)}`,
      'content-type': 'application/json',
    },
    payload: JSON.stringify(worded(url, body)),
  });
}

/** The person signs in again for the challenge with their passkey: its evidence recorded, as the step-up's return does. */
const stepUp = (who: Person, challengeId: string) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr: [...PASSKEY],
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const codeOf = (body: string): string | undefined => (JSON.parse(body) as { error?: { code?: string } }).error?.code;

/**
 * Asks, steps up and confirms a change through its two routes; the answer it stopped at: the ask's refusal, or the
 * confirm's status, code and body.
 */
async function askedAndConfirmed(who: Person, url: string, body: object, flowCookie?: string) {
  const asked = await sent(who, url, body, flowCookie);
  if (asked.statusCode !== 202) return { at: 'ask', status: asked.statusCode, code: codeOf(asked.body) };
  const { stepUpChallengeId } = asked.json<{ stepUpChallengeId: string }>();
  await stepUp(who, stepUpChallengeId);
  const confirmed = await sent(who, `${url}/confirm`, { ...body, stepUpChallengeId }, flowCookie);
  return {
    at: 'confirm',
    status: confirmed.statusCode,
    code: codeOf(confirmed.body),
    body: confirmed.json<Record<string, unknown>>(),
  };
}

/** Whether the agent's key still works, as the key check finds it. */
const works = async (text: string): Promise<boolean> =>
  (await createAgentKeyCheck({ database: app, keys, ids, clock, logger }).check(text, CORRELATION)).outcome ===
  'accepted';

/** Rotates the key, the old one ended at once: what the person got, and whether the owner's key still works. */
async function rotatedEndingNow(who: Person, agent: { agentId: string; keyId: string; text: string }) {
  const answer = await askedAndConfirmed(who, `/v1/agents/${agent.agentId}/keys/${agent.keyId}/rotate`, {
    oldKey: 'end_now',
  });
  return {
    status: answer.status,
    code: answer.code,
    newKey: typeof answer.body?.key === 'string',
    ownersKeyWorks: await works(agent.text),
  };
}

let addresses = 0;
/** A client address of its own for each flow or registration, so none counts against another's share (6F1 G4). */
const fresh = (): string => {
  addresses += 1;
  return `10.${String(Math.floor(addresses / 256))}.${String(addresses % 256)}.2`;
};

/** A flow an MCP client opened in the person's browser: its ID and the browser's cookie. */
async function opened() {
  const answer = await authorizing.authorize(
    {
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT,
      state: 'xyz',
      code_challenge: challengeOf('v'.repeat(43)),
      code_challenge_method: 'S256',
      resource: capabilities.resource,
      scope: 'requests:read',
    },
    undefined,
    fresh(),
  );
  if (answer.outcome !== 'opened') throw new Error(`not opened: ${JSON.stringify(answer)}`);
  return { flowId: answer.flowId, cookie: answer.cookie };
}

/** The person connects the client as the agent, through the consent's routes: where it stopped, and how. */
async function connectedAs(who: Person, agentId: string) {
  const flow = await opened();
  const answer = await askedAndConfirmed(
    who,
    `/v1/oauth/requests/${flow.flowId}/consent`,
    { agentId, scopes: ['requests:read'] },
    flow.cookie,
  );
  const connection = answer.body?.connection as { keyId?: string } | undefined;
  return { at: answer.at, status: answer.status, code: answer.code, keyId: connection?.keyId };
}

/** A connection the agent's owner made through the routes: its key's ID. */
async function connectionOf(owner: Person, agentId: string): Promise<string> {
  const made = await connectedAs(owner, agentId);
  if (made.keyId === undefined) throw new Error(`not connected: ${JSON.stringify(made)}`);
  return made.keyId;
}

/** The person revokes the connection through its routes: where it stopped, and how. */
async function connectionRevoked(who: Person, agentId: string, keyId: string) {
  const answer = await askedAndConfirmed(who, `/v1/agents/${agentId}/connections/${keyId}/revoke`, {});
  return { at: answer.at, status: answer.status, code: answer.code };
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, logger);
  const services = { database: app, keys, ids, clock, logger };
  const clients = createOauthClients({ database: app, clock, logger, metadata: undefined });
  authorizing = createOauthAuthorizing({ database: app, keys, clock, ids, logger, capabilities, clients });
  const registered = await authorizing.register(
    { redirect_uris: [REDIRECT], client_name: 'ChatGPT' },
    CORRELATION,
    fresh(),
  );
  if (registered.outcome !== 'registered') throw new Error('registered');
  clientId = registered.client.clientId;
  const http = {
    host: '127.0.0.1',
    port: 0,
    publicOrigin: ORIGIN,
    trustedProxies: [],
    rateLimitPerMinute: 1000,
    rateLimitPerUserPerMinute: 1000,
    rateLimitPerAgentPerMinute: 1000,
    rateLimitPerOrganisationPerMinute: 100_000,
    webCopies: 1,
    mcpOauth: true,
  };
  api = await buildServer({
    config: { http, log: { level: 'info', eventCapPerMinute: 10_000 } },
    logger,
    ids,
    healthChecks: [],
    signIn: {
      service: {
        begin: () => Promise.reject(new Error('not in these tests')),
        beginStepUp: () => Promise.reject(new Error('not in these tests')),
        complete: () => Promise.reject(new Error('not in these tests')),
        signOut: () => Promise.resolve(undefined),
        holderOf: (cookie) => sessions.holder(app, cookie),
        signedIn: (cookie) => sessions.use(app, cookie),
      },
      sessionSeconds: 43_200,
    },
    findMembership: (orgId, userId) => membershipFor(app, quiet, orgId, userId),
    restrictedUntil: createRemovalRestriction({ database: app, clock }),
    agentKeyChanges: createAgentKeyChanges({ ...services, challenges: challenges() }),
    connectionChanges: createConnectionChanges({ ...services, challenges: challenges() }),
    oauth: {
      authorizing,
      grants: createOauthGrants({ ...services, capabilities, securityEvents: { note: () => undefined }, clients }),
      consents: createConnectionConsents({
        ...services,
        challenges: challenges(),
        issuer: capabilities.issuer,
        clients,
      }),
      device: createOauthDevice({ database: app, keys, clock, ids, logger, capabilities, clients }),
      clock,
    },
  });
  await api.ready();
});

afterAll(async () => {
  await api.close();
  await app.destroy();
  await database.drop();
});

describe(`SEC-OPS-04 a restricted admin keeps only a developer's powers on shared routes (6F1 G1, Postgres ${server.version})`, () => {
  it("refuses a restricted admin's rotation of another member's agent's key: no new key, the owner's key working", async () => {
    const org = await organization();
    const restricted = await member(org, 'admin', true);
    const developer = await member(org, 'developer');
    const theirs = await agentWithKey(developer);

    expect(await rotatedEndingNow(restricted, theirs)).toEqual({
      status: 403,
      code: 'FORBIDDEN',
      newKey: false,
      ownersKeyWorks: true,
    });
  });

  it("refuses a restricted admin's connection of an MCP client as another member's agent", async () => {
    const org = await organization();
    const restricted = await member(org, 'admin', true);
    const developer = await member(org, 'developer');
    const { agentId } = await agentWithKey(developer);

    expect(await connectedAs(restricted, agentId)).toEqual({
      at: 'ask',
      status: 403,
      code: 'FORBIDDEN',
      keyId: undefined,
    });
  });

  it("refuses a restricted admin's revocation of a connection to another member's agent", async () => {
    const org = await organization();
    const restricted = await member(org, 'admin', true);
    const developer = await member(org, 'developer');
    const { agentId } = await agentWithKey(developer);
    const keyId = await connectionOf(developer, agentId);

    expect(await connectionRevoked(restricted, agentId, keyId)).toEqual({ at: 'ask', status: 403, code: 'FORBIDDEN' });
  });

  it('lets an admin with no removal do all three for another member’s agent', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const theirs = await agentWithKey(developer);

    expect(await rotatedEndingNow(admin, theirs)).toEqual({
      status: 201,
      code: undefined,
      newKey: true,
      ownersKeyWorks: false,
    });
    const connected = await connectedAs(admin, theirs.agentId);
    expect(connected).toMatchObject({ at: 'confirm', status: 201 });
    expect(await connectionRevoked(admin, theirs.agentId, connected.keyId ?? '')).toEqual({
      at: 'confirm',
      status: 200,
      code: undefined,
    });
  });

  it('keeps a developer’s powers for a restricted admin: all three on an agent of their own', async () => {
    const org = await organization();
    const restricted = await member(org, 'admin', true);
    const own = await agentWithKey(restricted);

    expect(await rotatedEndingNow(restricted, own)).toEqual({
      status: 201,
      code: undefined,
      newKey: true,
      ownersKeyWorks: false,
    });
    const connected = await connectedAs(restricted, own.agentId);
    expect(connected).toMatchObject({ at: 'confirm', status: 201 });
    expect(await connectionRevoked(restricted, own.agentId, connected.keyId ?? '')).toEqual({
      at: 'confirm',
      status: 200,
      code: undefined,
    });
  });

  it('keeps a member marked without powers to the role they keep in the use case too, whatever role is read again', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { agentId } = await agentWithKey(admin);
    const changes = createAgentChanges({
      database: app,
      keys,
      ids,
      clock,
      challenges: challenges(),
      outbox: createOutbox({ ids, clock }),
      logger,
    });
    // Reactivating is an admin's alone: the admin, marked as the hook marks a restricted one, is a developer here.
    const reactivated = (withoutPowers?: true) => {
      keysUsed += 1;
      const who = {
        orgId: org,
        userId: admin.userId,
        sessionId: admin.sessionId,
        ...(withoutPowers && { withoutPowers }),
      };
      const idempotent = {
        orgId: org,
        client: { kind: 'user' as const, id: admin.userId },
        operation: REACTIVATE_OPERATION,
        key: `restricted-${String(keysUsed)}`,
        payload: agentId,
      };
      return changes.reactivate(who, idempotent, agentId, CORRELATION);
    };

    expect(await reactivated(true)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    // Unmarked, the admin passes the role check, and is refused only as the agent isn't suspended.
    expect(await reactivated()).toMatchObject({ outcome: 'refused', status: 409 });
  });
});
