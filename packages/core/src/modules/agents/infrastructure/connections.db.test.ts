// SEC-OAUTH-01, -05, -06, -07, -08, -14 (6E3a): MCP connections on the real
// migrated schema, as the app role. A connection is a key whose secret was
// thrown away, beside its signed row; its access token is accepted at its MCP
// resource alone, as its agent, with the scopes its token, key and agent all
// hold, in the trips a key takes (five accepted, two refused at the door). A
// connection's key is left out of its agent's key lists and budgets, and a
// refresh token is used once.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import {
  createDatabase,
  type Database,
  noStatementTimes,
  OrganisationBusy,
  timingStatements,
} from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { keySecretMessage, type Scope } from '../domain/agent.ts';
import { connectionTokenText, parseConnectionToken } from '../domain/connection.ts';
import { addAgentKey, AGENT_KEYS, agentKeysOf, keysIssuedSince, revokeKey } from './agent-keys.ts';
import { addAgent, AGENTS } from './agents.ts';
import { createConnectionTokenCheck } from './connection-check.ts';
import { credentialAt } from './key-check.ts';
import { issueTokens, sweepConnectionTokens, tokenRowLocked, usedNow } from './connection-tokens.ts';
import {
  addConnection,
  CONNECTIONS,
  connectionsCounted,
  connectionsMadeSince,
  isConnectionKey,
} from './connections.ts';
import type { AgentsTables } from './tables.ts';

type Tables = AgentsTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x6e3a_0000_0000);
// In the past, so a sealed event's time (Postgres's clock) is never before the one the test reads with.
const START = new Date('2026-09-28T09:00:00Z');
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const RESOURCE = 'https://app.agentx.example/v1/mcp';
const CLIENT = 'axcl_0123456789abcdef0123456789abcdef';
const CORRELATION = '0199a0f0-0000-7000-8000-00000000e3a1';

let capture: LogCapture;
let clock: FixedClock;
let org: string;

const quiet = () => ({ keys, ids, logger: testLogger() });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

const checker = () => createConnectionTokenCheck({ database: app, keys, ids, clock, logger: testLogger(capture) });
const check = (text: string, resource = RESOURCE) => checker().check(text, CORRELATION, resource);

/** Refused, with the one answer, and its reason logged once. */
async function refusedFor(text: string, reason: string): Promise<void> {
  expect(await check(text)).toEqual({ outcome: 'refused' });
  expect(lines('connection_token.refused')).toEqual([expect.objectContaining({ reason })]);
}

const newAgent = (scopes: readonly Scope[] = ['requests:read', 'requests:write', 'suppliers:read']) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const id = ids.next();
    await addAgent(tx, states, {
      orgId: org,
      id,
      name: 'Purchasing bot',
      owner: ids.next(),
      scopes,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    return id;
  });

/** A connection of the agent's, made as the consent makes one: its key's secret random and thrown away. */
const connect = (
  agentId: string,
  { scopes = ['requests:read', 'suppliers:read'] as readonly Scope[], resource = RESOURCE } = {},
) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const keyId = ids.next();
    const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(keyId, randomBytes(32)));
    await addAgentKey(tx, states, {
      orgId: org,
      id: keyId,
      agentId,
      scopes,
      secretMac: mac,
      secretKeyVersion: keyVersion,
      expiresAt: new Date(clock.now().getTime() + 90 * DAY_MS),
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    await addConnection(tx, states, {
      orgId: org,
      keyId,
      agentId,
      clientId: CLIENT,
      clientName: 'ChatGPT',
      resource,
      redirectUri: 'https://chatgpt.com/connector/oauth/cb',
      via: 'code',
      madeBy: ids.next(),
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    return keyId;
  });

/** A pair for the connection, as the token endpoint issues one. */
const tokens = (keyId: string, scopes: readonly Scope[] = ['requests:read', 'suppliers:read'], parentId?: string) =>
  withSignedStates(app, org, quiet(), (tx) =>
    issueTokens(
      tx,
      { keys, ids },
      {
        orgId: org,
        keyId,
        scopes,
        now: clock.now(),
        keyExpiresAt: new Date(clock.now().getTime() + 90 * DAY_MS),
        ...(parentId === undefined ? {} : { parentId }),
      },
    ),
  );

const revoke = (keyId: string) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    revokeKey(tx, states, { orgId: org, keyId, actor: OPERATOR, details: {} }, 'a live key did not revoke'),
  );

const suspend = (agentId: string) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, AGENTS, { orgId: org, id: agentId }, 'suspend', {
      actor: OPERATOR,
      action: 'agent.suspend',
      details: {},
    }),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  clock = new FixedClock(START);
  org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
});

describe(`SEC-OAUTH-01, -07, -08 the connection check (Postgres ${server.version})`, () => {
  it('accepts an access token at its resource, as its agent, with what its token, key and agent all hold', async () => {
    const agent = await newAgent(['requests:read', 'requests:write', 'suppliers:read']);
    const keyId = await connect(agent, { scopes: ['requests:read', 'requests:write', 'suppliers:read'] });
    const { accessToken } = await tokens(keyId, ['requests:read', 'suppliers:read']);

    expect(await check(accessToken)).toEqual({
      outcome: 'accepted',
      key: {
        orgId: org,
        agentId: agent,
        keyId,
        // requests:write is the key's and the agent's, never the token's: narrowed (SEC-OAUTH-08).
        scopes: ['requests:read', 'suppliers:read'],
        expiresAt: new Date(START.getTime() + 90 * DAY_MS),
        credential: 'connection',
      },
    });
    expect(lines('connection_token.refused')).toEqual([]);
  });

  it('refuses a token at another resource: a connection is for the one MCP endpoint it was made for', async () => {
    const keyId = await connect(await newAgent());
    const { accessToken } = await tokens(keyId);
    expect(await check(accessToken, 'https://evil.example/v1/mcp')).toEqual({ outcome: 'refused' });
    expect(lines('connection_token.refused')).toEqual([expect.objectContaining({ reason: 'wrong_resource' })]);
  });

  it('refuses a token whose connection was revoked, or whose agent was suspended, on its very next call', async () => {
    const agent = await newAgent();
    const keyId = await connect(agent);
    const { accessToken } = await tokens(keyId);
    expect(await check(accessToken)).toMatchObject({ outcome: 'accepted' });
    await suspend(agent);
    await refusedFor(accessToken, 'agent_suspended');

    capture = new LogCapture();
    const other = await connect(await newAgent());
    const pair = await tokens(other);
    await revoke(other);
    await refusedFor(pair.accessToken, 'revoked');
  });

  it('refuses an access token past its hour', async () => {
    const { accessToken } = await tokens(await connect(await newAgent()));
    clock.advanceBy(3600 * 1000);
    await refusedFor(accessToken, 'expired');
  });

  it('refuses a refresh token sent as an access token, a token of another key, one never issued, and text that is none', async () => {
    const keyId = await connect(await newAgent());
    const { refreshToken, accessToken } = await tokens(keyId);
    await refusedFor(refreshToken, 'malformed');
    capture = new LogCapture();
    const presented = parseConnectionToken(accessToken, 'access');
    if (presented === undefined) throw new Error('not a token');
    const otherKey = await connect(await newAgent());
    await refusedFor(connectionTokenText('access', otherKey, presented.tokenId, presented.secret), 'missing');
    capture = new LogCapture();
    await refusedFor(connectionTokenText('access', keyId, ids.next(), presented.secret), 'missing');
    capture = new LogCapture();
    await refusedFor(connectionTokenText('access', ids.next(), presented.tokenId, presented.secret), 'unlisted');
    capture = new LogCapture();
    await refusedFor('axa_nothing', 'malformed');
  });

  it('refuses an agent key presented as a connection: the key holds no connection row', async () => {
    const agent = await newAgent();
    const keyId = await withSignedStates(app, org, quiet(), async (tx, states) => {
      const id = ids.next();
      const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(id, randomBytes(32)));
      await addAgentKey(tx, states, {
        orgId: org,
        id,
        agentId: agent,
        scopes: ['requests:read'],
        secretMac: mac,
        secretKeyVersion: keyVersion,
        expiresAt: new Date(START.getTime() + 90 * DAY_MS),
        createdAt: START,
        actor: OPERATOR,
      });
      return id;
    });
    // No token row can name such a key (its foreign key): the transaction's own step refuses one all the same.
    const checked = await withSignedStates(app, org, quiet(), (tx, states) =>
      credentialAt(tx, states, clock.now(), org, keyId, { prove: () => undefined, resource: RESOURCE }),
    );
    expect(checked).toEqual({ outcome: 'refused', reason: 'not_a_connection' });
  });

  it('refuses a connection made for another client, where the client is asked', async () => {
    const keyId = await connect(await newAgent());
    const at = (clientId: string) =>
      withSignedStates(app, org, quiet(), (tx, states) =>
        credentialAt(tx, states, clock.now(), org, keyId, { prove: () => undefined, resource: RESOURCE, clientId }),
      );
    expect(await at(CLIENT)).toMatchObject({ outcome: 'accepted' });
    expect(await at('axcl_ffffffffffffffffffffffffffffffff')).toEqual({ outcome: 'refused', reason: 'wrong_client' });
  });
});

describe(`SEC-OAUTH-06, -14 rows tampered with (Postgres ${server.version})`, () => {
  it('refuses a token whose row was stretched or widened: its MAC no longer matches', async () => {
    const { accessToken } = await tokens(await connect(await newAgent()));
    const presented = parseConnectionToken(accessToken, 'access');
    if (presented === undefined) throw new Error('not a token');
    const owner = await tamperAsOwner(database, CONNECTIONS, org);
    await owner.query(
      "update agents.connection_tokens set scopes = 'requests:read requests:write suppliers:read' where id = $1",
      [presented.tokenId],
    );
    await refusedFor(accessToken, 'wrong_secret');
    capture = new LogCapture();
    await owner.query("update agents.connection_tokens set expires_at = expires_at + interval '1 year' where id = $1", [
      presented.tokenId,
    ]);
    await owner.end();
    await refusedFor(accessToken, 'wrong_secret');
  });

  it('refuses a token whose connection was pointed at another resource, raising the alarm and the hold', async () => {
    const keyId = await connect(await newAgent());
    const { accessToken } = await tokens(keyId);
    const owner = await tamperAsOwner(database, CONNECTIONS, org);
    await owner.query('alter table agents.connections disable trigger made_once');
    await owner.setColumn(keyId, 'resource', 'https://evil.example/v1/mcp');
    await owner.query('alter table agents.connections enable trigger made_once');
    await owner.end();

    await refusedFor(accessToken, 'tampered');
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ level: 'error', subjectType: 'connection', objectId: keyId, orgId: org }),
    ]);
  });

  it.each<[string, (owner: Awaited<ReturnType<typeof tamperAsOwner>>, keyId: string) => Promise<void>]>([
    ['its events stripped of their seals', (owner, keyId) => owner.stripSeals(keyId)],
    [
      'handed to another client',
      async (owner, keyId) => {
        await owner.query('alter table agents.connections disable trigger made_once');
        try {
          await owner.setColumn(keyId, 'client_id', 'axcl_ffffffffffffffffffffffffffffffff');
        } finally {
          await owner.query('alter table agents.connections enable trigger made_once');
        }
      },
    ],
  ])('refuses a token whose connection had %s, raising the alarm (S205)', async (_name, tamper) => {
    const keyId = await connect(await newAgent());
    const { accessToken } = await tokens(keyId);
    const owner = await tamperAsOwner(database, CONNECTIONS, org);
    try {
      await tamper(owner, keyId);
    } finally {
      await owner.end();
    }

    await refusedFor(accessToken, 'tampered');
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ level: 'error', subjectType: 'connection', objectId: keyId, orgId: org }),
    ]);
  });

  it('keeps a connection made once: the app can never change one after its first signed state', async () => {
    const keyId = await connect(await newAgent());
    await expect(
      withSignedStates(app, org, quiet(), (tx) =>
        tx
          .updateTable('agents.connections')
          .set({ resource: 'https://evil.example/v1/mcp' })
          .where('org_id', '=', org)
          .where('id', '=', keyId)
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'made_once' });
  });
});

describe(`SEC-OAUTH-14 trip parity with a key (Postgres ${server.version})`, () => {
  it('takes five trips for a token accepted: the listing’s one, the door’s one and its transaction’s three', async () => {
    const { accessToken } = await tokens(await connect(await newAgent()));
    const times = noStatementTimes();
    expect(await timingStatements(times, () => check(accessToken))).toMatchObject({ outcome: 'accepted' });
    expect(times.trips).toBe(5);
  });

  it('takes two trips for a wrong secret, listed or not: the listing’s and the door’s, and no transaction', async () => {
    const keyId = await connect(await newAgent());
    const { accessToken } = await tokens(keyId);
    const presented = parseConnectionToken(accessToken, 'access');
    if (presented === undefined) throw new Error('not a token');
    for (const named of [keyId, ids.next()]) {
      const times = noStatementTimes();
      const wrong = connectionTokenText('access', named, presented.tokenId, Buffer.alloc(32, 0xee));
      expect(await timingStatements(times, () => check(wrong))).toEqual({ outcome: 'refused' });
      expect(times.trips).toBe(2);
    }
  });

  it('never logs the token, only its key’s and its own IDs', async () => {
    const keyId = await connect(await newAgent());
    const { accessToken } = await tokens(keyId);
    // A secret's last character is one of 16 (32 bytes in base64url): a fixed 'A' left 1 token in 16 unchanged,
    // accepted and never logged (CQ9). Always a different one, so the token presented is always a wrong one.
    const last = accessToken.endsWith('A') ? 'E' : 'A';
    expect(await check(`${accessToken.slice(0, -1)}${last}`)).toEqual({ outcome: 'refused' });
    const presented = parseConnectionToken(accessToken, 'access');
    const text = JSON.stringify(capture.lines());
    // The 42 characters the presented secret shares with the real one: neither secret appears.
    expect(text).not.toContain(accessToken.slice(-43, -1));
    expect(text).toContain(keyId);
    expect(text).toContain(presented?.tokenId);
  });
});

describe(`the connection check's faults on our side (Postgres ${server.version})`, () => {
  it('refuses a token made with a pepper version this process no longer holds, logged as the error it is', async () => {
    const { accessToken } = await tokens(await connect(await newAgent()));
    const rotated = createKeyProvider({
      ...Object.fromEntries(
        PURPOSES.map((purpose, index) => [
          purpose,
          { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) },
        ]),
      ),
      'agent-key-pepper': { current: 2, versions: new Map([[2, Buffer.alloc(32, 0x42)]]) },
    });
    const checked = await createConnectionTokenCheck({
      database: app,
      keys: rotated,
      ids,
      clock,
      logger: testLogger(capture),
    }).check(accessToken, CORRELATION, RESOURCE);
    expect(checked).toEqual({ outcome: 'refused' });
    expect(lines('connection_token.refused')).toEqual([
      expect.objectContaining({ level: 'error', reason: 'key_not_held' }),
    ]);
  });

  it.each(['57014', '40P01'])('answers busy, never a failure, when its transaction hits %s', async (code) => {
    const { accessToken } = await tokens(await connect(await newAgent()));
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
    const checking = createConnectionTokenCheck({ database: failing, keys, ids, clock, logger: testLogger(capture) });
    await expect(checking.check(accessToken, CORRELATION, RESOURCE)).rejects.toBeInstanceOf(OrganisationBusy);
    expect(lines('connection_token.check_in_trouble')).toEqual([
      expect.objectContaining({ level: 'warn', orgId: org }),
    ]);
  });

  it('lets any other failure through', async () => {
    const { accessToken } = await tokens(await connect(await newAgent()));
    const failing = new Proxy(app, {
      get: (target, name) => {
        if (name === 'transaction') {
          return () => {
            throw new Error('not a database limit');
          };
        }
        const value = Reflect.get(target, name) as unknown;
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    const checking = createConnectionTokenCheck({ database: failing, keys, ids, clock, logger: testLogger(capture) });
    await expect(checking.check(accessToken, CORRELATION, RESOURCE)).rejects.toThrow('not a database limit');
  });
});

describe(`the connection check waiting on a lock (forced, Postgres ${server.version})`, () => {
  it('refuses a token whose connection was revoked while the check waited for its key’s lock', async () => {
    const keyId = await connect(await newAgent());
    const { accessToken } = await tokens(keyId);
    const made = Promise.withResolvers<undefined>();
    const letGo = Promise.withResolvers<undefined>();
    const revoking = withSignedStates(app, org, quiet(), async (tx, states) => {
      await revokeKey(tx, states, { orgId: org, keyId, actor: OPERATOR, details: {} }, 'a live key did not revoke');
      made.resolve(undefined);
      await letGo.promise;
    });
    await made.promise;
    const checking = check(accessToken);
    await waitUntilQueued(database.as('admin'), 1);
    letGo.resolve(undefined);
    await revoking;

    expect(await checking).toEqual({ outcome: 'refused' });
    expect(lines('connection_token.refused')).toEqual([expect.objectContaining({ reason: 'revoked' })]);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });
});

describe(`a connection's key apart from the agent's own keys (Postgres ${server.version})`, () => {
  it('leaves connection keys out of the key list and the day’s key budget, and lists them apart for a hand-over', async () => {
    const agent = await newAgent();
    const keyId = await connect(agent);
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      expect(await agentKeysOf(tx, states, org, agent)).toEqual({ outcome: 'listed', keys: [] });
      expect(await agentKeysOf(tx, states, org, agent, 'share', 'connections')).toMatchObject({
        outcome: 'listed',
        keys: [{ id: keyId, agentId: agent, status: 'ACTIVE' }],
      });
      expect(await keysIssuedSince(tx, org, new Date(START.getTime() - DAY_MS))).toBe(0);
      expect(await isConnectionKey(tx, org, keyId)).toBe(true);
      expect(await isConnectionKey(tx, org, ids.next())).toBe(false);
    });
  });

  it('counts an agent’s connections, live and in all, and the organisation’s made since a time', async () => {
    const agent = await newAgent();
    await connect(agent);
    const ended = await connect(agent);
    await revoke(ended);
    await withSignedStates(app, org, quiet(), async (tx) => {
      expect(await connectionsCounted(tx, org, agent, clock.now())).toEqual({ all: 2, live: 1 });
      expect(await connectionsCounted(tx, org, agent, new Date(START.getTime() + 91 * DAY_MS))).toEqual({
        all: 2,
        live: 0,
      });
      expect(await connectionsMadeSince(tx, org, new Date(START.getTime() - DAY_MS))).toBe(2);
      expect(await connectionsMadeSince(tx, org, START)).toBe(0);
    });
  });
});

describe(`SEC-OAUTH-05 a refresh token used once (Postgres ${server.version})`, () => {
  it('fills in its use once: a second use finds it used', async () => {
    const keyId = await connect(await newAgent());
    const { refreshToken } = await tokens(keyId);
    const presented = parseConnectionToken(refreshToken, 'refresh');
    if (presented === undefined) throw new Error('not a token');
    const use = () =>
      withSignedStates(app, org, quiet(), async (tx) => {
        const row = await tokenRowLocked(tx, org, presented.tokenId);
        expect(row).toMatchObject({ keyId, kind: 'refresh' });
        return usedNow(tx, org, presented.tokenId, clock.now());
      });
    expect(await use()).toBe(true);
    expect(await use()).toBe(false);
    await withSignedStates(app, org, quiet(), async (tx) => {
      expect(await tokenRowLocked(tx, org, ids.next())).toBeUndefined();
    });
  });

  it('serialises two uses at once on the row: the second waits, then finds it used', async () => {
    const keyId = await connect(await newAgent());
    const { refreshToken } = await tokens(keyId);
    const presented = parseConnectionToken(refreshToken, 'refresh');
    if (presented === undefined) throw new Error('not a token');
    const made = Promise.withResolvers<undefined>();
    const letGo = Promise.withResolvers<undefined>();
    const first = withSignedStates(app, org, quiet(), async (tx) => {
      await tokenRowLocked(tx, org, presented.tokenId);
      const used = await usedNow(tx, org, presented.tokenId, clock.now());
      made.resolve(undefined);
      await letGo.promise;
      return used;
    });
    await made.promise;
    const second = withSignedStates(app, org, quiet(), async (tx) => {
      await tokenRowLocked(tx, org, presented.tokenId);
      return usedNow(tx, org, presented.tokenId, clock.now());
    });
    await waitUntilQueued(database.as('admin'), 1);
    letGo.resolve(undefined);
    expect(await first).toBe(true);
    expect(await second).toBe(false);
  });
});

describe(`the token rows' retention (0093, Postgres ${server.version})`, () => {
  it('sweeps rows past 120 days, and the database refuses the app any younger', async () => {
    const keyId = await connect(await newAgent());
    const { accessToken } = await tokens(keyId);
    const presented = parseConnectionToken(accessToken, 'access');
    if (presented === undefined) throw new Error('not a token');
    // Before the 120 days: neither the sweep nor a DELETE of the app's own reaches it.
    expect(await sweepConnectionTokens(app, org, new Date(START.getTime() + 200 * DAY_MS), 10)).toBe(0);
    const owner = await tamperAsOwner(database, AGENT_KEYS, org);
    await owner.query(
      "update agents.connection_tokens set created_at = created_at - interval '400 days', expires_at = expires_at - interval '399 days' where key_id = $1",
      [keyId],
    );
    await owner.end();
    expect(await sweepConnectionTokens(app, org, START, 1)).toBe(1);
    expect(await sweepConnectionTokens(app, org, START, 10)).toBe(1);
    expect(await sweepConnectionTokens(app, org, START, 10)).toBe(0);
    await expect(sweepConnectionTokens(app, org, START, 0)).rejects.toBeInstanceOf(RangeError);
  });
});
