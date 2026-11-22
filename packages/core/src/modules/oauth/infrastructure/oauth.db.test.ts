// SEC-OAUTH-04, -09, -13 (6E3a, 6E3c): the OAuth server's global records on
// the real migrated schema, as the app role: a client registered within the
// day's cap, a flow decided once, its code used once, and both swept once past
// their use; a device's flow claimed once and polled no sooner than its
// interval; a client's metadata document kept a day.
import { createTestDatabase, type TestDatabase, testLogger, waitUntilQueued } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { DAY_MS, HOUR_MS } from '../../../shared-kernel/index.ts';
import { checkRegistration, type ClientRegistration } from './client-metadata.ts';
import {
  CLIENT_METADATA_KEPT_MS,
  CLIENT_METADATA_STALE_MS,
  keepClientMetadata,
  keptClientMetadata,
  sweepClientMetadata,
} from './client-metadata-cache.ts';
import { hashOf } from './codes.ts';
import { openJudged } from './flow-seals.ts';
import { challengeOf } from './pkce.ts';
import {
  CLIENT_KEPT_DAYS,
  clientOf,
  clientSeen,
  MOST_REGISTRATIONS_A_DAY,
  MOST_REGISTRATIONS_A_NETWORK_A_DAY,
  QUIET_NETWORK_REGISTRATIONS,
  registerClient,
  sweepClientNetworks,
  sweepClients,
} from './clients.ts';
import {
  CODE_SECONDS,
  codeHeld,
  codeUsed,
  deviceClaimed,
  deviceFlowOfCode,
  deviceHeld,
  devicePolled,
  flowOfCode,
  FLOW_SECONDS,
  flowById,
  flowDecided,
  MOST_FAILED_CLAIMS_A_FLOW,
  MOST_OPEN_FLOWS,
  MOST_OPEN_FLOWS_A_NETWORK,
  MOST_OPEN_FLOWS_A_SOURCE,
  openCodeFlow,
  openDeviceFlow,
  QUIET_NETWORK_FLOWS,
  sweepFlows,
} from './flows.ts';
import type { OauthTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<OauthTables>;

const NOW = new Date('2026-11-18T09:00:00Z');
const ORG = '0199a0f0-0000-7000-8000-0000000e3a01';
const KEY = '0199a0f0-0000-7000-8000-0000000e3a02';
/** A decision's seal, as the consent makes one: kept and read back here, judged in flow-seals.test.ts. */
const SEAL = { mac: 'e'.repeat(64), keyVersion: 1 };
/** The keys a flow is sealed with as it opens (S205). */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 7)]]) }]),
  ),
);
let next = 0;
const flowId = () => {
  next += 1;
  return `0199a0f0-0000-7000-8000-${next.toString(16).padStart(12, '0')}`;
};

/** A source, or a network, of its own (6F1 G4), so no case's flows or registrations count against another's. */
let sources = 0;
const fresh = (): string => {
  sources += 1;
  return `source ${String(sources)}`;
};

const registration = (): ClientRegistration => {
  const checked = checkRegistration({
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    client_name: 'Claude',
  });
  if (checked.outcome !== 'valid') throw new Error('a valid registration');
  return checked.client;
};

/** A code flow opened at `createdAt` from `source` on `network`, by one browser unless another is named; its ID. */
const opened = async (createdAt = NOW, source = fresh(), browserHash = 'a'.repeat(64), network = source) => {
  const id = flowId();
  const outcome = await openCodeFlow(
    app,
    keys,
    {
      id,
      clientId: 'axcl_0123456789abcdef0123456789abcdef',
      redirectUri: 'https://claude.ai/api/mcp/auth_callback',
      state: 'client state',
      codeChallenge: challengeOf('v'.repeat(43)),
      scopesAsked: ['requests:read', 'suppliers:read'],
      resource: 'https://app.agentx.example/v1/mcp',
      browserHash,
      createdAt,
    },
    { source, network },
  );
  if (outcome !== 'opened') throw new Error(`not opened: ${outcome}`);
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
  it('registers a client, reads it back, notes when it connects at most hourly, and sweeps it once unused', async () => {
    const registered = await registerClient(app, keys, registration(), NOW, fresh());
    if (registered.outcome !== 'registered') throw new Error('registered');
    const { clientId } = registered.client;
    expect(clientId).toMatch(/^axcl_[0-9a-f]{32}$/);
    expect(await clientOf(app, keys, clientId)).toEqual({
      outcome: 'known',
      client: { ...registration(), clientId, createdAt: NOW },
    });
    expect(await clientOf(app, keys, 'axcl_ffffffffffffffffffffffffffffffff')).toBeUndefined();
    const at = (ms: number) => new Date(NOW.getTime() + ms);
    const seen = async () => {
      const [row] = await database
        .as('admin')
        .query<{ first: Date | null; last: Date | null }>(
          'select first_connected_at as first, last_connected_at as last from oauth.clients where client_id = $1',
          [clientId],
        );
      return row;
    };

    const unused = await registerClient(app, keys, registration(), NOW, fresh());
    await clientSeen(app, clientId, at(1000)).execute();
    expect(await seen()).toEqual({ first: at(1000), last: at(1000) });
    // Within the hour, the row isn't written again: a busy client costs one write an hour.
    expect(Number((await clientSeen(app, clientId, at(HOUR_MS)).executeTakeFirst()).numUpdatedRows)).toBe(0);
    await clientSeen(app, clientId, at(1000 + HOUR_MS)).execute();
    expect(await seen()).toEqual({ first: at(1000), last: at(1000 + HOUR_MS) });

    // A day on, the one never connected goes; the connected one stays.
    expect(await sweepClients(app, at(DAY_MS - 1), 10)).toBe(0);
    expect(await sweepClients(app, at(DAY_MS), 10)).toBe(1);
    expect(await clientOf(app, keys, clientId)).toBeDefined();
    if (unused.outcome === 'registered') expect(await clientOf(app, keys, unused.client.clientId)).toBeUndefined();
    // 90 days after its last connection, no connection of its can be refreshed: it goes too.
    const kept = 1000 + HOUR_MS + CLIENT_KEPT_DAYS * DAY_MS;
    expect(await sweepClients(app, at(kept - 1), 10)).toBe(0);
    expect(await sweepClients(app, at(kept), 10)).toBe(1);
    expect(await clientOf(app, keys, clientId)).toBeUndefined();
    await expect(sweepClients(app, NOW, 0)).rejects.toBeInstanceOf(RangeError);
  });

  it(`SEC-OAUTH-13 past ${String(MOST_REGISTRATIONS_A_DAY)} in 24 hours, refuses only a busy network and still takes a quiet one: no lockout (S210 TR-7)`, async () => {
    const day = new Date('2026-12-01T09:00:00Z');
    const admin = database.as('admin');
    // The day's cap filled from 14 networks, each under its own share (about 143 of 150): a spread-out crowd.
    await admin.query(
      `insert into oauth.clients (client_id, name, redirect_uris, application_type, grant_types, created_at, network)
       select 'axcl_' || lpad(to_hex(n), 32, '0'), 'Filler', array['https://a.example/cb'], 'web', array['authorization_code'], $1,
         'tr7-net-' || (n % 14)
       from generate_series(1, $2::int) as n`,
      [day, MOST_REGISTRATIONS_A_DAY],
    );
    try {
      const at = new Date(day.getTime() + 1000);
      // A network of the crowd is refused, the server's cap,
      expect(await registerClient(app, keys, registration(), at, 'tr7-net-1')).toEqual({
        outcome: 'capped',
        cap: 'server',
      });
      // while a network that has registered fewer than its few today still registers, up to them, and only then is refused.
      const quiet = fresh();
      for (let made = 0; made < QUIET_NETWORK_REGISTRATIONS; made += 1) {
        expect(await registerClient(app, keys, registration(), at, quiet)).toMatchObject({ outcome: 'registered' });
      }
      expect(await registerClient(app, keys, registration(), at, quiet)).toEqual({ outcome: 'capped', cap: 'server' });
      // Another fresh network is let in all the same.
      expect(await registerClient(app, keys, registration(), at, fresh())).toMatchObject({ outcome: 'registered' });
      // A day on, the crowd's network registers again.
      expect(
        await registerClient(app, keys, registration(), new Date(day.getTime() + DAY_MS + 1), 'tr7-net-1'),
      ).toMatchObject({
        outcome: 'registered',
      });
    } finally {
      // Its crowd's networks would be left for the sweep below to clear.
      await admin.query("delete from oauth.clients where name = 'Filler'");
    }
  });

  it(`6F1 G4: refuses a network past ${String(MOST_REGISTRATIONS_A_NETWORK_A_DAY)} in 24 hours; another network not`, async () => {
    const day = new Date('2027-01-01T09:00:00Z');
    const network = fresh();
    for (let made = 0; made < MOST_REGISTRATIONS_A_NETWORK_A_DAY; made += 1) {
      expect(await registerClient(app, keys, registration(), day, network)).toMatchObject({ outcome: 'registered' });
    }
    expect(await registerClient(app, keys, registration(), day, network)).toEqual({
      outcome: 'capped',
      cap: 'network',
    });
    expect(await registerClient(app, keys, registration(), day, fresh())).toMatchObject({ outcome: 'registered' });
    const [row] = await database
      .as('admin')
      .query<{ registered: number }>('select count(*)::int as registered from oauth.clients where network = $1', [
        network,
      ]);
    expect(row).toEqual({ registered: MOST_REGISTRATIONS_A_NETWORK_A_DAY });
    expect(
      await registerClient(app, keys, registration(), new Date(day.getTime() + DAY_MS + 1), network),
    ).toMatchObject({
      outcome: 'registered',
    });
  });

  it('AG8: clears the network a client registered from once its day is past, never before; the client stays', async () => {
    const day = new Date('2027-02-01T09:00:00Z');
    // The cases before registered from networks of their own, days before: theirs go first, as the sweep's own job.
    await sweepClientNetworks(app, day, 1000);
    const network = fresh();
    const registered = await registerClient(app, keys, registration(), day, network);
    if (registered.outcome !== 'registered') throw new Error('registered');
    const { clientId } = registered.client;
    const networkOf = async () => {
      const [row] = await database
        .as('admin')
        .query<{ network: string | null }>('select network from oauth.clients where client_id = $1', [clientId]);
      return row?.network;
    };
    expect(await sweepClientNetworks(app, new Date(day.getTime() + DAY_MS - 1), 1000)).toBe(0);
    expect(await networkOf()).toBe(network);
    expect(await sweepClientNetworks(app, new Date(day.getTime() + DAY_MS), 1000)).toBeGreaterThanOrEqual(1);
    expect(await networkOf()).toBeNull();
    expect(await clientOf(app, keys, clientId)).toMatchObject({ client: { clientId } });
    // Cleared once: a second sweep has nothing of it left to clear.
    expect(await sweepClientNetworks(app, new Date(day.getTime() + DAY_MS), 1000)).toBe(0);
    await expect(sweepClientNetworks(app, day, 0)).rejects.toBeInstanceOf(RangeError);
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
    const allowed = { outcome: 'allowed' as const, orgId: ORG, keyId: KEY, codeHash: 'c'.repeat(64), seal: SEAL };
    expect(await flowDecided(app, id, allowed, new Date(NOW.getTime() + 1000))).toBe(true);
    expect(await flowDecided(app, id, { outcome: 'denied' }, new Date(NOW.getTime() + 2000))).toBe(false);
    expect(await flowById(app, id)).toMatchObject({
      decided: 'allowed',
      orgId: ORG,
      keyId: KEY,
      codeEndsAt: new Date(NOW.getTime() + 1000 + CODE_SECONDS * 1000),
      seal: SEAL,
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
    await flowDecided(app, id, { outcome: 'allowed', orgId: ORG, keyId: KEY, codeHash, seal: SEAL }, NOW);
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

describe(`device flows (6E3c, RFC 8628; Postgres ${server.version})`, () => {
  let codes = 0;
  /** A device's flow opened at `createdAt`, its two codes' hashes distinct from every other test's. */
  const device = async (createdAt = NOW, userCodeHash?: string, source = fresh(), network = source) => {
    codes += 1;
    const id = flowId();
    const flow = {
      id,
      clientId: 'https://nousresearch.github.io/hermes/client.json',
      scopesAsked: ['requests:read'] as const,
      resource: 'https://app.agentx.example/v1/mcp',
      deviceHash: hashOf(`device ${String(codes)}`),
      userCodeHash: userCodeHash ?? hashOf(`user ${String(codes)}`),
      intervalSeconds: 5,
      createdAt,
    };
    return { flow, opened: await openDeviceFlow(app, keys, flow, { source, network }) };
  };
  const BROWSER = 'b'.repeat(64);
  const OTHER = 'c'.repeat(64);
  const PERSON = 'd'.repeat(64);
  const OWNER = { browserHash: BROWSER, personHash: PERSON };
  const NOTHING = { outcome: 'not_found' };

  it('opens a device’s flow with no browser, reads it by its device code, and draws again for a user code held', async () => {
    const { flow, opened: outcome } = await device();
    expect(outcome).toBe('opened');
    const read = await deviceFlowOfCode(app, flow.deviceHash);
    if (read === undefined) throw new Error('read');
    // Sealed as it opened (S205): sound, with the pepper's version.
    const { openSeal, ...rest } = read;
    expect(openSeal?.keyVersion).toBe(1);
    expect(openJudged(keys, read)).toBe('sound');
    expect(rest).toEqual({
      kind: 'device',
      id: flow.id,
      clientId: flow.clientId,
      scopesAsked: ['requests:read'],
      resource: flow.resource,
      deviceHash: flow.deviceHash,
      userCodeHash: flow.userCodeHash,
      browserHash: null,
      personHash: null,
      intervalSeconds: 5,
      polledAt: null,
      createdAt: NOW,
      endsAt: new Date(NOW.getTime() + FLOW_SECONDS * 1000),
      decided: null,
      decidedAt: null,
      orgId: null,
      keyId: null,
      seal: null,
      usedAt: null,
    });
    expect(await flowById(app, flow.id)).toMatchObject({ kind: 'device', id: flow.id });
    expect(await flowOfCode(app, flow.deviceHash)).toBeUndefined();
    expect(await deviceFlowOfCode(app, hashOf('no device'))).toBeUndefined();
    const again = await device(NOW, flow.userCodeHash);
    expect(again.opened).toBe('collided');
    expect(await flowById(app, again.flow.id)).toBeUndefined();
  });

  it('is claimed once, by the first browser and person to type its code, and only while open and undecided', async () => {
    const { flow } = await device();
    const claimed = { outcome: 'claimed', flowId: flow.id };
    expect(await deviceClaimed(app, flow.userCodeHash, OWNER, NOW)).toEqual(claimed);
    // The same browser and person again (a reload) finds it.
    expect(await deviceClaimed(app, flow.userCodeHash, OWNER, NOW)).toEqual(claimed);
    expect(await flowById(app, flow.id)).toMatchObject({ browserHash: BROWSER, personHash: PERSON });
    expect(await deviceClaimed(app, hashOf('typed wrong'), OWNER, NOW)).toEqual(NOTHING);
    const ended = await device();
    const end = new Date(NOW.getTime() + FLOW_SECONDS * 1000);
    expect(await deviceClaimed(app, ended.flow.userCodeHash, OWNER, end)).toEqual(NOTHING);
    const decided = await device();
    expect(await flowDecided(app, decided.flow.id, { outcome: 'denied' }, NOW)).toBe(true);
    expect(await deviceClaimed(app, decided.flow.userCodeHash, OWNER, NOW)).toEqual(NOTHING);
  });

  it(`AG8: a claim by another browser or person fails, counted; the ${String(MOST_FAILED_CLAIMS_A_FLOW)}rd denies the flow`, async () => {
    const { flow } = await device();
    expect(await deviceClaimed(app, flow.userCodeHash, OWNER, NOW)).toEqual({ outcome: 'claimed', flowId: flow.id });
    const contested = (failedClaims: number, denied: boolean) => ({
      outcome: 'contested',
      flowId: flow.id,
      failedClaims,
      denied,
    });
    // Another person on the claiming browser, then another browser: each a failed claim, the flow kept as it was.
    expect(await deviceClaimed(app, flow.userCodeHash, { browserHash: BROWSER, personHash: OTHER }, NOW)).toEqual(
      contested(1, false),
    );
    expect(await deviceClaimed(app, flow.userCodeHash, { browserHash: OTHER, personHash: PERSON }, NOW)).toEqual(
      contested(2, false),
    );
    expect(await flowById(app, flow.id)).toMatchObject({ decided: null, browserHash: BROWSER, personHash: PERSON });
    // Its code is known to someone else: at the third no one may decide it, and the device is told no.
    expect(await deviceClaimed(app, flow.userCodeHash, { browserHash: OTHER, personHash: OTHER }, NOW)).toEqual(
      contested(MOST_FAILED_CLAIMS_A_FLOW, true),
    );
    expect(await flowById(app, flow.id)).toMatchObject({ decided: 'denied', orgId: null });
    expect(await deviceClaimed(app, flow.userCodeHash, OWNER, NOW)).toEqual(NOTHING);
    // A flow no one claimed yet is claimed by whoever types its code first, never a failed claim.
    const unclaimed = await device();
    expect(
      await deviceClaimed(app, unclaimed.flow.userCodeHash, { browserHash: OTHER, personHash: OTHER }, NOW),
    ).toEqual({ outcome: 'claimed', flowId: unclaimed.flow.id });
  });

  it('notes a poll no sooner than its interval, one at a time', async () => {
    const { flow } = await device();
    expect(await devicePolled(app, flow.id, NOW)).toBe(true);
    expect(await devicePolled(app, flow.id, new Date(NOW.getTime() + 4999))).toBe(false);
    expect(await deviceFlowOfCode(app, flow.deviceHash)).toMatchObject({ polledAt: NOW });
    expect(await devicePolled(app, flow.id, new Date(NOW.getTime() + 5000))).toBe(true);
    // A code flow is never a device's to poll.
    expect(await devicePolled(app, await opened(), NOW)).toBe(false);
  });

  it('is decided with no code, and held for its tokens’ issue: a second poll waits, then finds it used', async () => {
    const { flow } = await device();
    const allowed = { outcome: 'allowed' as const, orgId: ORG, keyId: KEY, codeHash: null, seal: SEAL };
    expect(await flowDecided(app, flow.id, allowed, NOW)).toBe(true);
    expect(await deviceFlowOfCode(app, flow.deviceHash)).toMatchObject({ decided: 'allowed', orgId: ORG, keyId: KEY });
    expect(await flowById(app, flow.id)).not.toHaveProperty('codeEndsAt');
    const made = Promise.withResolvers<undefined>();
    const letGo = Promise.withResolvers<undefined>();
    const first = app.transaction().execute(async (tx) => {
      const held = await deviceHeld(tx, flow.id);
      await codeUsed(tx, flow.id, NOW);
      made.resolve(undefined);
      await letGo.promise;
      return held?.usedAt;
    });
    await made.promise;
    const second = app.transaction().execute(async (tx) => (await deviceHeld(tx, flow.id))?.usedAt);
    await waitUntilQueued(database.as('admin'), 1);
    letGo.resolve(undefined);
    expect(await first).toBeNull();
    expect(await second).toEqual(NOW);
    expect(await app.transaction().execute(async (tx) => deviceHeld(tx, await opened()))).toBeUndefined();
  });

  it('holds a device flow’s shape in the database: no redirect, challenge, state or code', async () => {
    const { flow } = await device();
    const admin = database.as('admin');
    await expect(admin.query("update oauth.flows set state = 'x' where id = $1", [flow.id])).rejects.toMatchObject({
      code: '23514',
      constraint: 'a_device_flow_is_a_device',
    });
    await expect(
      admin.query('update oauth.flows set code_hash = $2, code_ends_at = now() where id = $1', [
        flow.id,
        'f'.repeat(64),
      ]),
    ).rejects.toMatchObject({ code: '23514', constraint: 'a_device_flow_is_a_device' });
  });

  it(`SEC-OAUTH-13 S210 TR-7: while ${String(MOST_OPEN_FLOWS)} flows are open, refuses only a busy network, of either kind; a quiet one still opens: no lockout`, async () => {
    const admin = database.as('admin');
    const later = new Date('2027-01-01T09:00:00Z');
    // The server's cap filled by a crowd of 400 networks, 50 open flows each: every one under its own share of 100.
    await admin.query(
      `insert into oauth.flows (id, kind, client_id, redirect_uri, code_challenge, browser_hash, scopes_asked,
         resource, created_at, ends_at, source_key, network_key)
       select ('0199a0f0-0000-7000-9000-' || lpad(to_hex(n), 12, '0'))::uuid, 'code', 'c', 'https://a.example/cb',
         $1, $2, 'requests:read', 'r', $3, $4, 'tr7-source-' || n, 'tr7-net-' || (n % 400)
       from generate_series(1, $5::int) as n`,
      [challengeOf('v'.repeat(43)), 'e'.repeat(64), later, new Date(later.getTime() + 1000), MOST_OPEN_FLOWS],
    );
    try {
      // A network of the crowd is refused, a device's flow as a code flow,
      expect((await device(later, undefined, fresh(), 'tr7-net-1')).opened).toBe('full');
      const codeFlow = (network: string) =>
        openCodeFlow(
          app,
          keys,
          {
            id: flowId(),
            clientId: 'axcl_0123456789abcdef0123456789abcdef',
            redirectUri: 'https://claude.ai/api/mcp/auth_callback',
            state: null,
            codeChallenge: challengeOf('v'.repeat(43)),
            scopesAsked: ['requests:read'],
            resource: 'https://app.agentx.example/v1/mcp',
            browserHash: hashOf(fresh()),
            createdAt: later,
          },
          { source: fresh(), network },
        );
      expect(await codeFlow('tr7-net-2')).toBe('full');
      // while a network holding fewer than its few open still opens them, of either kind, and only then is refused.
      const quiet = fresh();
      expect((await device(later, undefined, fresh(), quiet)).opened).toBe('opened');
      for (let open = 1; open < QUIET_NETWORK_FLOWS; open += 1) expect(await codeFlow(quiet)).toBe('opened');
      expect(await codeFlow(quiet)).toBe('full');
      expect((await device(later, undefined, fresh(), quiet)).opened).toBe('full');
      // Another fresh network opens all the same.
      expect(await codeFlow(fresh())).toBe('opened');
    } finally {
      await admin.query("delete from oauth.flows where id::text like '0199a0f0-0000-7000-9000-%'");
    }
  });

  it(`6F1 G4: holds one source to ${String(MOST_OPEN_FLOWS_A_SOURCE)} flows not ended, of either kind, decided or not`, async () => {
    const at = new Date('2027-02-01T09:00:00Z');
    const source = fresh();
    // Each from a browser of its own, as a cookie-less client's are: the browser's cap never holds them.
    const browser = () => hashOf(fresh());
    const first = await opened(at, source, browser());
    // A decided flow still holds its place until it ends: deciding is no way round the cap.
    expect(await flowDecided(app, first, { outcome: 'denied' }, at)).toBe(true);
    for (let open = 1; open < MOST_OPEN_FLOWS_A_SOURCE - 1; open += 1) await opened(at, source, browser());
    expect((await device(at, undefined, source)).opened).toBe('opened');
    expect((await device(at, undefined, source)).opened).toBe('source_full');
    await expect(opened(at, source, browser())).rejects.toThrow('not opened: source_full');
    // Another source is not held by it; once its flows end, this one isn't either.
    expect((await device(at)).opened).toBe('opened');
    await opened(at);
    await opened(new Date(at.getTime() + FLOW_SECONDS * 1000), source, browser());
  });

  it(`AG8: holds one network to ${String(MOST_OPEN_FLOWS_A_NETWORK)} flows not ended, of either kind, whatever source in it`, async () => {
    const at = new Date('2027-03-01T09:00:00Z');
    const network = fresh();
    const browser = () => hashOf(fresh());
    // Each from a source of its own (an IPv6 /64 of one /48): no source comes near its own cap.
    for (let open = 1; open < MOST_OPEN_FLOWS_A_NETWORK; open += 1) await opened(at, fresh(), browser(), network);
    expect((await device(at, undefined, fresh(), network)).opened).toBe('opened');
    expect((await device(at, undefined, fresh(), network)).opened).toBe('network_full');
    await expect(opened(at, fresh(), browser(), network)).rejects.toThrow('not opened: network_full');
    // Another network is not held by it; once its flows end, this one isn't either.
    expect((await device(at)).opened).toBe('opened');
    await opened(new Date(at.getTime() + FLOW_SECONDS * 1000), fresh(), browser(), network);
  });
});

describe(`SEC-OAUTH-09 client metadata documents kept a day (6E3c; Postgres ${server.version})`, () => {
  const DOCUMENT = {
    clientId: 'https://claude.ai/oauth/mcp-oauth-client-metadata',
    name: 'Claude',
    redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
    grantTypes: ['authorization_code', 'refresh_token'] as const,
  };

  it('keeps a document for a day, fetched again over its own row, and sweeps it once past its day', async () => {
    expect(await keptClientMetadata(app, keys, DOCUMENT.clientId, NOW)).toBeUndefined();
    await keepClientMetadata(app, keys, DOCUMENT, NOW);
    expect(await keptClientMetadata(app, keys, DOCUMENT.clientId, NOW)).toEqual({
      outcome: 'kept',
      document: DOCUMENT,
      fresh: true,
    });
    const dayOn = new Date(NOW.getTime() + CLIENT_METADATA_KEPT_MS);
    // Past its day: stale, still kept for 7 days to stand in while it can't be fetched again.
    expect(await keptClientMetadata(app, keys, DOCUMENT.clientId, dayOn)).toEqual({
      outcome: 'kept',
      document: DOCUMENT,
      fresh: false,
    });
    const staleEnd = new Date(dayOn.getTime() + CLIENT_METADATA_STALE_MS);
    expect(await keptClientMetadata(app, keys, DOCUMENT.clientId, new Date(staleEnd.getTime() - 1))).toMatchObject({
      fresh: false,
    });
    expect(await keptClientMetadata(app, keys, DOCUMENT.clientId, staleEnd)).toBeUndefined();
    await keepClientMetadata(app, keys, { ...DOCUMENT, name: 'Claude (new)' }, dayOn);
    expect(await keptClientMetadata(app, keys, DOCUMENT.clientId, dayOn)).toMatchObject({
      document: { name: 'Claude (new)' },
      fresh: true,
    });
    const sweptFrom = new Date(dayOn.getTime() + CLIENT_METADATA_KEPT_MS + CLIENT_METADATA_STALE_MS);
    expect(await sweepClientMetadata(app, new Date(sweptFrom.getTime() - 1), 10)).toBe(0);
    expect(await sweepClientMetadata(app, sweptFrom, 10)).toBe(1);
    expect(await keptClientMetadata(app, keys, DOCUMENT.clientId, dayOn)).toBeUndefined();
    await expect(sweepClientMetadata(app, NOW, 0)).rejects.toBeInstanceOf(RangeError);
  });

  it('holds a document’s shape in the database: an https address, its addresses, a day ahead', async () => {
    const admin = database.as('admin');
    const insert = (clientId: string, uris: readonly string[], expires: Date) =>
      admin.query(
        `insert into oauth.client_metadata (client_id, name, redirect_uris, grant_types, fetched_at, expires_at)
         values ($1, 'x', $2, '{authorization_code}', $3, $4)`,
        [clientId, uris, NOW, expires],
      );
    const later = new Date(NOW.getTime() + 1000);
    await expect(insert('http://claude.ai/x', ['https://a.example/cb'], later)).rejects.toMatchObject({
      code: '23514',
    });
    await expect(insert('https://claude.ai/x', [], later)).rejects.toMatchObject({ code: '23514' });
    await expect(insert('https://claude.ai/x', ['https://a.example/cb'], NOW)).rejects.toMatchObject({
      code: '23514',
      constraint: 'kept_after_it_was_fetched',
    });
  });
});

// SEC-OAUTH-17 (S207 H3, R-15; 0107): the database's owner, holding none of the app's keys, rewrites what a client
// registered or a document said, or how long it is kept: a client so changed is never believed. Each field the seal
// binds, one at a time, so a field left out of the MAC fails here.
describe(`SEC-OAUTH-17 a client's facts rewritten by the database's owner are never believed (Postgres ${server.version})`, () => {
  const EVIL = 'https://attacker.example/cb';
  const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
  /** Past every other case's registrations, which a day's cap counts from any time after a day ago. */
  const REGISTERED_AT = new Date('2027-06-01T09:00:00Z');
  const owner = () => database.as('owner');

  /** A client registered as the app registers one, sealed: its ID. */
  const registeredId = async (): Promise<string> => {
    const registered = await registerClient(app, keys, registration(), REGISTERED_AT, fresh());
    if (registered.outcome !== 'registered') throw new Error('registered');
    return registered.client.clientId;
  };

  /** The owner's edits of a registered client, each by its ID. */
  const CLIENT_EDITS: readonly (readonly [string, (id: string) => Promise<unknown>])[] = [
    [
      'a redirect address planted',
      (id) =>
        owner().query('update oauth.clients set redirect_uris = array_append(redirect_uris, $2) where client_id = $1', [
          id,
          EVIL,
        ]),
    ],
    [
      'its redirect addresses replaced',
      (id) =>
        owner().query('update oauth.clients set redirect_uris = array[$2::text] where client_id = $1', [id, EVIL]),
    ],
    [
      'its grant types widened',
      (id) =>
        owner().query(`update oauth.clients set grant_types = array['authorization_code', $2] where client_id = $1`, [
          id,
          DEVICE,
        ]),
    ],
    [
      'its name changed',
      (id) => owner().query(`update oauth.clients set name = 'Claude (official)' where client_id = $1`, [id]),
    ],
    [
      'its application type changed',
      (id) => owner().query(`update oauth.clients set application_type = 'native' where client_id = $1`, [id]),
    ],
    [
      'its software named',
      (id) => owner().query(`update oauth.clients set software_id = 'planted' where client_id = $1`, [id]),
    ],
    [
      'its software version named',
      (id) => owner().query(`update oauth.clients set software_version = '9' where client_id = $1`, [id]),
    ],
    [
      'when it registered moved',
      (id) =>
        owner().query(`update oauth.clients set created_at = created_at - interval '1 second' where client_id = $1`, [
          id,
        ]),
    ],
  ];

  it.each(CLIENT_EDITS)('a registered client with %s: tampered', async (_, edit) => {
    const clientId = await registeredId();
    expect(await clientOf(app, keys, clientId)).toMatchObject({ outcome: 'known' });
    await edit(clientId);
    expect(await clientOf(app, keys, clientId)).toEqual({ outcome: 'unsealed', judged: 'tampered' });
  });

  it('a registered client with its seal taken out, or of a pepper version not held: never believed', async () => {
    const clientId = await registeredId();
    await owner().query('update oauth.clients set mac_key_version = 9 where client_id = $1', [clientId]);
    expect(await clientOf(app, keys, clientId)).toEqual({ outcome: 'unsealed', judged: 'key_not_held' });
    await owner().query('update oauth.clients set mac = null, mac_key_version = null where client_id = $1', [clientId]);
    expect(await clientOf(app, keys, clientId)).toEqual({ outcome: 'unsealed', judged: 'unsealed' });
  });

  it('a registered client planted with another client’s seal, the same facts but its own ID: tampered', async () => {
    const real = await registeredId();
    const planted = 'axcl_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    await owner().query(
      `insert into oauth.clients (client_id, name, redirect_uris, application_type, grant_types, software_id,
         software_version, created_at, mac, mac_key_version)
       select $2, name, redirect_uris, application_type, grant_types, software_id, software_version, created_at, mac,
         mac_key_version
       from oauth.clients where client_id = $1`,
      [real, planted],
    );
    expect(await clientOf(app, keys, planted)).toEqual({ outcome: 'unsealed', judged: 'tampered' });
    expect(await clientOf(app, keys, real)).toMatchObject({ outcome: 'known' });
  });

  it('a registered client from before 0107, with no seal: never believed', async () => {
    const legacy = 'axcl_dddddddddddddddddddddddddddddddd';
    await owner().query(
      `insert into oauth.clients (client_id, name, redirect_uris, application_type, grant_types, created_at)
       values ($1, 'Claude', array['https://claude.ai/api/mcp/auth_callback'], 'web', array['authorization_code'], $2)`,
      [legacy, NOW],
    );
    expect(await clientOf(app, keys, legacy)).toEqual({ outcome: 'unsealed', judged: 'unsealed' });
  });

  /** A document as a fetch finds it, for a client of its own. */
  let documents = 0;
  const document = (clientId?: string) => {
    documents += 1;
    return {
      clientId: clientId ?? `https://claude.ai/oauth/sealed-${String(documents)}`,
      name: 'Claude',
      redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
      grantTypes: ['authorization_code', 'refresh_token'] as const,
    };
  };
  /** A document kept as the app keeps one, sealed: its client ID. */
  const keptId = async (): Promise<string> => {
    const kept = document();
    await keepClientMetadata(app, keys, kept, NOW);
    return kept.clientId;
  };

  /** The owner's edits of a kept document, each by its client ID. */
  const DOCUMENT_EDITS: readonly (readonly [string, (id: string) => Promise<unknown>])[] = [
    [
      'a redirect address planted',
      (id) =>
        owner().query(
          'update oauth.client_metadata set redirect_uris = array_append(redirect_uris, $2) where client_id = $1',
          [id, EVIL],
        ),
    ],
    [
      'its grant types widened',
      (id) =>
        owner().query(
          `update oauth.client_metadata set grant_types = array['authorization_code', $2] where client_id = $1`,
          [id, DEVICE],
        ),
    ],
    [
      'its name changed',
      (id) => owner().query(`update oauth.client_metadata set name = 'Claude (official)' where client_id = $1`, [id]),
    ],
    [
      'its day extended',
      (id) =>
        owner().query(
          `update oauth.client_metadata set expires_at = expires_at + interval '30 days' where client_id = $1`,
          [id],
        ),
    ],
    [
      'when it was fetched moved',
      (id) =>
        owner().query(
          `update oauth.client_metadata set fetched_at = fetched_at + interval '1 second' where client_id = $1`,
          [id],
        ),
    ],
  ];

  it.each(DOCUMENT_EDITS)('a kept document with %s: tampered, fresh or stale', async (_, edit) => {
    const clientId = await keptId();
    expect(await keptClientMetadata(app, keys, clientId, NOW)).toMatchObject({ outcome: 'kept' });
    await edit(clientId);
    const stale = new Date(NOW.getTime() + CLIENT_METADATA_KEPT_MS + 1);
    for (const at of [NOW, stale]) {
      expect(await keptClientMetadata(app, keys, clientId, at)).toEqual({ outcome: 'unsealed', judged: 'tampered' });
    }
  });

  it('a kept document with its seal taken out, or of a pepper version not held: never believed till kept again', async () => {
    const clientId = await keptId();
    await owner().query('update oauth.client_metadata set mac_key_version = 9 where client_id = $1', [clientId]);
    expect(await keptClientMetadata(app, keys, clientId, NOW)).toEqual({ outcome: 'unsealed', judged: 'key_not_held' });
    await owner().query('update oauth.client_metadata set mac = null, mac_key_version = null where client_id = $1', [
      clientId,
    ]);
    expect(await keptClientMetadata(app, keys, clientId, NOW)).toEqual({ outcome: 'unsealed', judged: 'unsealed' });
    // Kept again over its own row, as a fetch keeps it: sealed again, believed.
    await keepClientMetadata(app, keys, document(clientId), NOW);
    expect(await keptClientMetadata(app, keys, clientId, NOW)).toMatchObject({ outcome: 'kept', fresh: true });
  });

  it('a document’s seal copied to another client’s row, the same facts: tampered', async () => {
    const real = await keptId();
    const other = await keptId();
    await owner().query(
      `update oauth.client_metadata set mac = (select mac from oauth.client_metadata where client_id = $1)
       where client_id = $2`,
      [real, other],
    );
    expect(await keptClientMetadata(app, keys, other, NOW)).toEqual({ outcome: 'unsealed', judged: 'tampered' });
    expect(await keptClientMetadata(app, keys, real, NOW)).toMatchObject({ outcome: 'kept' });
  });
});
