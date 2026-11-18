// SEC-OAUTH-04, -13 (6E3a): the OAuth server's global records on the real
// migrated schema, as the app role: a client registered within the day's cap,
// a flow decided once, its code used once, and both swept once past their use.
import { createTestDatabase, type TestDatabase, testLogger, waitUntilQueued } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { checkRegistration, type ClientRegistration } from './client-metadata.ts';
import { challengeOf } from './pkce.ts';
import { clientConnected, clientOf, MOST_REGISTRATIONS_A_DAY, registerClient, sweepClients } from './clients.ts';
import {
  CODE_SECONDS,
  codeHeld,
  codeUsed,
  flowOfCode,
  FLOW_SECONDS,
  flowById,
  flowDecided,
  openCodeFlow,
  sweepFlows,
} from './flows.ts';
import type { OauthTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<OauthTables>;

const NOW = new Date('2026-11-18T09:00:00Z');
const ORG = '0199a0f0-0000-7000-8000-0000000e3a01';
const KEY = '0199a0f0-0000-7000-8000-0000000e3a02';
let next = 0;
const flowId = () => {
  next += 1;
  return `0199a0f0-0000-7000-8000-${next.toString(16).padStart(12, '0')}`;
};

const registration = (): ClientRegistration => {
  const checked = checkRegistration({
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    client_name: 'Claude',
  });
  if (checked.outcome !== 'valid') throw new Error('a valid registration');
  return checked.client;
};

const opened = async (createdAt = NOW) => {
  const id = flowId();
  await openCodeFlow(app, {
    id,
    clientId: 'axcl_0123456789abcdef0123456789abcdef',
    redirectUri: 'https://claude.ai/api/mcp/auth_callback',
    state: 'client state',
    codeChallenge: challengeOf('v'.repeat(43)),
    scopesAsked: ['requests:read', 'suppliers:read'],
    resource: 'https://app.agentx.example/v1/mcp',
    browserHash: 'a'.repeat(64),
    createdAt,
  });
  return id;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<OauthTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`SEC-OAUTH-13 clients registered (Postgres ${server.version})`, () => {
  it('registers a client, reads it back, notes its first connection once, and sweeps it only if it never connected', async () => {
    const registered = await registerClient(app, registration(), NOW);
    if (registered.outcome !== 'registered') throw new Error('registered');
    const { clientId } = registered.client;
    expect(clientId).toMatch(/^axcl_[0-9a-f]{32}$/);
    expect(await clientOf(app, clientId)).toEqual({ ...registration(), clientId, createdAt: NOW });
    expect(await clientOf(app, 'axcl_ffffffffffffffffffffffffffffffff')).toBeUndefined();

    const unused = await registerClient(app, registration(), NOW);
    await clientConnected(app, clientId, new Date(NOW.getTime() + 1000));
    await clientConnected(app, clientId, new Date(NOW.getTime() + 2000));
    // A day on, the one never connected goes; the connected one stays.
    expect(await sweepClients(app, new Date(NOW.getTime() + DAY_MS - 1), 10)).toBe(0);
    expect(await sweepClients(app, new Date(NOW.getTime() + DAY_MS), 10)).toBe(1);
    expect(await clientOf(app, clientId)).toBeDefined();
    if (unused.outcome === 'registered') expect(await clientOf(app, unused.client.clientId)).toBeUndefined();
    await expect(sweepClients(app, NOW, 0)).rejects.toBeInstanceOf(RangeError);
  });

  it(`refuses a registration past ${String(MOST_REGISTRATIONS_A_DAY)} in 24 hours, and takes one again a day on`, async () => {
    const day = new Date('2026-12-01T09:00:00Z');
    const admin = database.as('admin');
    await admin.query(
      `insert into oauth.clients (client_id, name, redirect_uris, application_type, grant_types, created_at)
       select 'axcl_' || lpad(to_hex(n), 32, '0'), 'Filler', array['https://a.example/cb'], 'web', array['authorization_code'], $1
       from generate_series(1, $2::int) as n`,
      [day, MOST_REGISTRATIONS_A_DAY],
    );
    expect(await registerClient(app, registration(), new Date(day.getTime() + 1000))).toEqual({ outcome: 'capped' });
    expect(await registerClient(app, registration(), new Date(day.getTime() + DAY_MS + 1))).toMatchObject({
      outcome: 'registered',
    });
  });
});

describe(`SEC-OAUTH-04 flows decided once, codes used once (Postgres ${server.version})`, () => {
  it('opens a flow for its 15 minutes, and reads it back undecided', async () => {
    const id = await opened();
    expect(await flowById(app, id)).toMatchObject({
      id,
      state: 'client state',
      scopesAsked: ['requests:read', 'suppliers:read'],
      endsAt: new Date(NOW.getTime() + FLOW_SECONDS * 1000),
      decided: null,
      orgId: null,
      keyId: null,
      usedAt: null,
    });
    expect(await flowById(app, flowId())).toBeUndefined();
  });

  it('decides a flow once and only in time', async () => {
    const id = await opened();
    const allowed = { outcome: 'allowed' as const, orgId: ORG, keyId: KEY, codeHash: 'c'.repeat(64) };
    expect(await flowDecided(app, id, allowed, new Date(NOW.getTime() + 1000))).toBe(true);
    expect(await flowDecided(app, id, { outcome: 'denied' }, new Date(NOW.getTime() + 2000))).toBe(false);
    expect(await flowById(app, id)).toMatchObject({
      decided: 'allowed',
      orgId: ORG,
      keyId: KEY,
      codeEndsAt: new Date(NOW.getTime() + 1000 + CODE_SECONDS * 1000),
    });
    const late = await opened();
    expect(await flowDecided(app, late, { outcome: 'denied' }, new Date(NOW.getTime() + FLOW_SECONDS * 1000))).toBe(
      false,
    );
    const denied = await opened();
    expect(await flowDecided(app, denied, { outcome: 'denied' }, NOW)).toBe(true);
    expect(await flowById(app, denied)).toMatchObject({ decided: 'denied', orgId: null, codeEndsAt: null });
  });

  it('holds a code for its use: a second exchange waits, then finds it used; a use rolled back is no use', async () => {
    const id = await opened();
    const codeHash = 'd'.repeat(64);
    await flowDecided(app, id, { outcome: 'allowed', orgId: ORG, keyId: KEY, codeHash }, NOW);
    expect(await flowOfCode(app, codeHash)).toMatchObject({ id, orgId: ORG, keyId: KEY, usedAt: null });
    // A use whose transaction rolls back (a busy) leaves the code unused.
    await expect(
      app.transaction().execute(async (tx) => {
        await codeUsed(tx, id, NOW);
        throw new Error('rolled back');
      }),
    ).rejects.toThrow('rolled back');
    expect(await flowOfCode(app, codeHash)).toMatchObject({ usedAt: null });
    const made = Promise.withResolvers<undefined>();
    const letGo = Promise.withResolvers<undefined>();
    const first = app.transaction().execute(async (tx) => {
      const held = await codeHeld(tx, codeHash);
      await codeUsed(tx, id, NOW);
      made.resolve(undefined);
      await letGo.promise;
      return held?.usedAt;
    });
    await made.promise;
    const second = app.transaction().execute(async (tx) => (await codeHeld(tx, codeHash))?.usedAt);
    await waitUntilQueued(database.as('admin'), 1);
    letGo.resolve(undefined);
    expect(await first).toBeNull();
    expect(await second).toEqual(NOW);
    expect(await app.transaction().execute((tx) => codeHeld(tx, 'e'.repeat(64)))).toBeUndefined();
    expect(await flowOfCode(app, 'e'.repeat(64))).toBeUndefined();
  });

  it('sweeps a flow a day after it ends, never before', async () => {
    const old = new Date('2026-10-01T09:00:00Z');
    const id = await opened(old);
    const ends = old.getTime() + FLOW_SECONDS * 1000;
    expect(await sweepFlows(app, new Date(ends + DAY_MS - 1), 100)).toBe(0);
    expect(await sweepFlows(app, new Date(ends + DAY_MS), 100)).toBeGreaterThanOrEqual(1);
    expect(await flowById(app, id)).toBeUndefined();
    await expect(sweepFlows(app, NOW, 0)).rejects.toBeInstanceOf(RangeError);
  });

  it('holds a flow’s shape in the database: a code flow’s browser and challenge, a decision whole', async () => {
    const admin = database.as('admin');
    await expect(
      admin.query(
        `insert into oauth.flows (id, kind, client_id, redirect_uri, scopes_asked, resource, created_at, ends_at)
         values ($1, 'code', 'c', 'https://a.example/cb', 'requests:read', 'r', $2, $3)`,
        [flowId(), NOW, new Date(NOW.getTime() + 1000)],
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'a_code_flow_is_a_browser' });
    const id = await opened();
    await expect(
      admin.query("update oauth.flows set outcome = 'allowed', decided_at = now() where id = $1", [id]),
    ).rejects.toMatchObject({ code: '23514', constraint: 'allowed_names_its_connection' });
  });
});
