// C2-1 (ADR-011 §1, SEC-AG-01, SEC-AG-02): an agent's request through the
// whole server, with the real key check, on the real migrated schema, as the
// app role: a live key reaches the agent's route as its agent, in its own
// organisation whatever the request names, and the request's line names the
// key it was sent with; a key refused for any reason is the one 401. What the
// check accepts in every case is key-check.db.test.ts.
import { randomBytes } from 'node:crypto';

import {
  addAgent,
  addAgentKey,
  agentKeyText,
  type AgentsTables,
  createAgentKeyCheck,
  keySecretMessage,
} from '@agentx/core/modules/agents';
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { addMembership, type IdentityTables, userForSubject } from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { DAY_MS } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AGENT_CHALLENGE, ORGANIZATION_HEADER } from './access.ts';
import { REQUEST_COMPLETED } from './request-log.ts';
import { buildServer } from './server.ts';

type Tables = IdentityTables & AgentsTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xc21a_0000_0000);
const START = new Date('2026-09-29T09:00:00Z');
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
let clock: FixedClock;
let capture: LogCapture;
let api: FastifyInstance;

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

let people = 0;

/** An organisation with an agent, owned by a member of it, with one key: its text as the agent sends it. */
async function agentWithKey(expiresAt = new Date(START.getTime() + 90 * DAY_MS)) {
  const orgId = ids.next();
  await withSignedStates(app, orgId, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: orgId, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `agent-access-${String(people)}` },
    { ids, clock, keys, logger: testLogger() },
  );
  const owner = ids.next();
  const agentId = ids.next();
  const keyId = ids.next();
  const secret = randomBytes(32);
  await withSignedStates(app, orgId, quiet(), async (tx, states) => {
    await addMembership(tx, states, { orgId, id: owner, userId, role: 'developer', joinedAt: START, actor: OPERATOR });
    await addAgent(tx, states, {
      orgId,
      id: agentId,
      name: 'Purchasing bot',
      owner,
      scopes: ['requests:read', 'suppliers:read'],
      createdAt: START,
      actor: OPERATOR,
    });
    const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(keyId, secret));
    await addAgentKey(tx, states, {
      orgId,
      id: keyId,
      agentId,
      scopes: ['suppliers:read'],
      secretMac: mac,
      secretKeyVersion: keyVersion,
      expiresAt,
      createdAt: START,
      actor: OPERATOR,
    });
  });
  return { orgId, agentId, keyId, text: agentKeyText(keyId, secret), secret };
}

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

interface Limits {
  readonly rateLimitPerMinute: number;
  readonly rateLimitPerAgentPerMinute: number;
  readonly rateLimitPerOrganisationPerMinute: number;
}

/** The whole server with the real key check, its limits as given; `checked` counts every key it was asked about. */
async function serverWith(limits: Limits, checked: { count: number } = { count: 0 }): Promise<FastifyInstance> {
  const logger = loggerFor(capture);
  const config = {
    http: {
      host: '127.0.0.1',
      port: 0,
      publicOrigin: 'https://app.agentx.example',
      trustedProxies: [],
      rateLimitPerUserPerMinute: 1000,
      ...limits,
      webCopies: 1,
      mcpOauth: false,
    },
    log: { level: 'info' as const, eventCapPerMinute: 10_000 },
  };
  const keyCheck = createAgentKeyCheck({ database: app, keys, ids, clock, logger });
  const built = await buildServer({
    config,
    logger,
    ids: new SequentialIds(),
    healthChecks: [],
    checkAgentKey: (text, correlationId) => {
      checked.count += 1;
      return keyCheck.check(text, correlationId);
    },
  });
  await built.ready();
  return built;
}

beforeEach(async () => {
  clock = new FixedClock(START);
  capture = new LogCapture();
  api = await serverWith({
    rateLimitPerMinute: 1000,
    rateLimitPerAgentPerMinute: 1000,
    rateLimitPerOrganisationPerMinute: 100_000,
  });
});

afterEach(async () => {
  await api.close();
});

describe(`an agent's request with its key (C2-1, Postgres ${server.version})`, () => {
  it('reaches the agent’s route as its agent, and its line names the agent and key, never the secret', async () => {
    const agent = await agentWithKey();
    const response = await api.inject({ url: '/v1/agent', headers: { authorization: `Bearer ${agent.text}` } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      agentId: agent.agentId,
      organizationId: agent.orgId,
      keyId: agent.keyId,
      scopes: ['suppliers:read'],
      keyExpiresAt: new Date(START.getTime() + 90 * DAY_MS).toISOString(),
      credential: 'key',
    });
    expect(lines(REQUEST_COMPLETED)).toEqual([
      expect.objectContaining({ route: '/v1/agent', status: 200, agentId: agent.agentId, agentKeyId: agent.keyId }),
    ]);
    const logged = JSON.stringify(capture.lines());
    expect(logged).not.toContain(agent.text);
    expect(logged).not.toContain(agent.secret.toString('base64url'));
  });

  it('SEC-AG-02 acts in its own organisation alone, whatever organisation the request names', async () => {
    const [one, two] = [await agentWithKey(), await agentWithKey()];
    for (const [agent, other] of [
      [one, two],
      [two, one],
    ] as const) {
      const response = await api.inject({
        url: '/v1/agent',
        headers: { authorization: `Bearer ${agent.text}`, [ORGANIZATION_HEADER]: other.orgId },
      });
      expect(response.json()).toMatchObject({ agentId: agent.agentId, organizationId: agent.orgId });
    }
  });

  it('SEC-AG-01 refuses a key with another’s secret, and one past its expiry, with the one answer', async () => {
    const agent = await agentWithKey(new Date(START.getTime() + DAY_MS));
    const other = await agentWithKey();
    const wrongSecret = `${agent.text.slice(0, 37)}${other.text.slice(37)}`;
    const refusedWith = async (text: string) => {
      const response = await api.inject({ url: '/v1/agent', headers: { authorization: `Bearer ${text}` } });
      return { status: response.statusCode, challenge: response.headers['www-authenticate'], body: response.body };
    };
    const wrong = await refusedWith(wrongSecret);
    clock.advanceBy(DAY_MS);
    const expired = await refusedWith(agent.text);
    for (const refused of [wrong, expired]) {
      expect(refused.status).toBe(401);
      expect(refused.challenge).toBe(`${AGENT_CHALLENGE}, error="invalid_token"`);
    }
    // Only the correlation ID tells the two answers apart.
    expect(wrong.body.replace(/"correlationId":"[^"]+"/, '')).toBe(expired.body.replace(/"correlationId":"[^"]+"/, ''));
    expect(lines('agent_key.refused').map((line) => line.reason)).toEqual(['wrong_secret', 'expired']);
  });
});

describe(`SEC-AG-01 V7 (PL-67) an outsider holding only a key's ID, over HTTP (Postgres ${server.version})`, () => {
  /** Where the outsider sends from: its own address, apart from the agent's. */
  const OUTSIDER = '203.0.113.7';
  const wrongSecret = Buffer.alloc(32, 0xee);

  const sent = async (target: FastifyInstance, text: string, remoteAddress = '127.0.0.1') => {
    const response = await target.inject({
      url: '/v1/agent',
      remoteAddress,
      headers: { authorization: `Bearer ${text}` },
    });
    return {
      status: response.statusCode,
      challenge: response.headers['www-authenticate'],
      body: response.body.replace(/"correlationId":"[^"]+"/, ''),
    };
  };

  it('answers an unlisted ID and a listed ID with a wrong secret alike: the one 401, challenge and body', async () => {
    const agent = await agentWithKey();
    const listed = await sent(api, agentKeyText(agent.keyId, wrongSecret), OUTSIDER);
    const unlisted = await sent(api, agentKeyText(ids.next(), wrongSecret), OUTSIDER);

    expect(listed).toEqual(unlisted);
    expect(listed).toMatchObject({ status: 401, challenge: `${AGENT_CHALLENGE}, error="invalid_token"` });
    expect(lines('agent_key.refused').map((line) => line.reason)).toEqual(['wrong_secret', 'unlisted']);
  });

  it('takes nothing of the organisation’s or its agent’s allowance: after a flood of wrong secrets the agent still gets every request of its limit', async () => {
    const agent = await agentWithKey();
    const limited = await serverWith({
      rateLimitPerMinute: 1000,
      rateLimitPerAgentPerMinute: 3,
      rateLimitPerOrganisationPerMinute: 3,
    });
    try {
      const flood = await Promise.all(
        Array.from({ length: 20 }, (_, index) =>
          sent(limited, agentKeyText(index % 2 === 0 ? agent.keyId : ids.next(), wrongSecret), OUTSIDER),
        ),
      );
      expect(new Set(flood.map(({ status }) => status))).toEqual(new Set([401]));

      const own = [];
      for (let request = 0; request < 4; request += 1) own.push((await sent(limited, agent.text)).status);
      // Its whole limit of three, then the limit's own answer: the limit is real, and none of it went to the flood.
      expect(own).toEqual([200, 200, 200, 429]);
    } finally {
      await limited.close();
    }
    expect(lines('db.organisation_busy')).toEqual([]);
  });

  it('bounds an outsider by its address before any key is looked up, and leaves the agent untouched', async () => {
    const agent = await agentWithKey();
    const checked = { count: 0 };
    const limited = await serverWith(
      { rateLimitPerMinute: 5, rateLimitPerAgentPerMinute: 1000, rateLimitPerOrganisationPerMinute: 100_000 },
      checked,
    );
    try {
      const statuses = [];
      for (let request = 0; request < 8; request += 1) {
        statuses.push((await sent(limited, agentKeyText(ids.next(), wrongSecret), OUTSIDER)).status);
      }
      expect(statuses).toEqual([401, 401, 401, 401, 401, 429, 429, 429]);
      // Past its address's limit, no key is looked up: the directory isn't read for the flood.
      expect(checked.count).toBe(5);
      expect((await sent(limited, agent.text)).status).toBe(200);
    } finally {
      await limited.close();
    }
  });
});
