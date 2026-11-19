// SEC-OAUTH-04, -09, -13 (6E3a, 6E3c): the OAuth server's global records on
// the real migrated schema, as the app role: a client registered within the
// day's cap, a flow decided once, its code used once, and both swept once past
// their use; a device's flow claimed once and polled no sooner than its
// interval; a client's metadata document kept a day.
import { createTestDatabase, type TestDatabase, testLogger, waitUntilQueued } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
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
import { challengeOf } from './pkce.ts';
import {
  CLIENT_KEPT_DAYS,
  clientOf,
  clientSeen,
  MOST_REGISTRATIONS_A_DAY,
  MOST_REGISTRATIONS_A_NETWORK_A_DAY,
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
    const registered = await registerClient(app, registration(), NOW, fresh());
    if (registered.outcome !== 'registered') throw new Error('registered');
    const { clientId } = registered.client;
    expect(clientId).toMatch(/^axcl_[0-9a-f]{32}$/);
    expect(await clientOf(app, clientId)).toEqual({ ...registration(), clientId, createdAt: NOW });
    expect(await clientOf(app, 'axcl_ffffffffffffffffffffffffffffffff')).toBeUndefined();
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

    const unused = await registerClient(app, registration(), NOW, fresh());
    await clientSeen(app, clientId, at(1000)).execute();
    expect(await seen()).toEqual({ first: at(1000), last: at(1000) });
    // Within the hour, the row isn't written again: a busy client costs one write an hour.
    expect(Number((await clientSeen(app, clientId, at(HOUR_MS)).executeTakeFirst()).numUpdatedRows)).toBe(0);
    await clientSeen(app, clientId, at(1000 + HOUR_MS)).execute();
    expect(await seen()).toEqual({ first: at(1000), last: at(1000 + HOUR_MS) });

    // A day on, the one never connected goes; the connected one stays.
    expect(await sweepClients(app, at(DAY_MS - 1), 10)).toBe(0);
    expect(await sweepClients(app, at(DAY_MS), 10)).toBe(1);
    expect(await clientOf(app, clientId)).toBeDefined();
    if (unused.outcome === 'registered') expect(await clientOf(app, unused.client.clientId)).toBeUndefined();
    // 90 days after its last connection, no connection of its can be refreshed: it goes too.
    const kept = 1000 + HOUR_MS + CLIENT_KEPT_DAYS * DAY_MS;
    expect(await sweepClients(app, at(kept - 1), 10)).toBe(0);
    expect(await sweepClients(app, at(kept), 10)).toBe(1);
    expect(await clientOf(app, clientId)).toBeUndefined();
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
    expect(await registerClient(app, registration(), new Date(day.getTime() + 1000), fresh())).toEqual({
      outcome: 'capped',
      cap: 'server',
    });
    expect(await registerClient(app, registration(), new Date(day.getTime() + DAY_MS + 1), fresh())).toMatchObject({
      outcome: 'registered',
    });
  });

  it(`6F1 G4: refuses a network past ${String(MOST_REGISTRATIONS_A_NETWORK_A_DAY)} in 24 hours; another network not`, async () => {
    const day = new Date('2027-01-01T09:00:00Z');
    const network = fresh();
    for (let made = 0; made < MOST_REGISTRATIONS_A_NETWORK_A_DAY; made += 1) {
      expect(await registerClient(app, registration(), day, network)).toMatchObject({ outcome: 'registered' });
    }
    expect(await registerClient(app, registration(), day, network)).toEqual({ outcome: 'capped', cap: 'network' });
    expect(await registerClient(app, registration(), day, fresh())).toMatchObject({ outcome: 'registered' });
    const [row] = await database
      .as('admin')
      .query<{ registered: number }>('select count(*)::int as registered from oauth.clients where network = $1', [
        network,
      ]);
    expect(row).toEqual({ registered: MOST_REGISTRATIONS_A_NETWORK_A_DAY });
    expect(await registerClient(app, registration(), new Date(day.getTime() + DAY_MS + 1), network)).toMatchObject({
      outcome: 'registered',
    });
  });

  it('AG8: clears the network a client registered from once its day is past, never before; the client stays', async () => {
    const day = new Date('2027-02-01T09:00:00Z');
    // The cases before registered from networks of their own, days before: theirs go first, as the sweep's own job.
    await sweepClientNetworks(app, day, 1000);
    const network = fresh();
    const registered = await registerClient(app, registration(), day, network);
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
    expect(await clientOf(app, clientId)).toMatchObject({ clientId });
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
    return { flow, opened: await openDeviceFlow(app, flow, { source, network }) };
  };
  const BROWSER = 'b'.repeat(64);
  const OTHER = 'c'.repeat(64);
  const PERSON = 'd'.repeat(64);
  const OWNER = { browserHash: BROWSER, personHash: PERSON };
  const NOTHING = { outcome: 'not_found' };

  it('opens a device’s flow with no browser, reads it by its device code, and draws again for a user code held', async () => {
    const { flow, opened: outcome } = await device();
    expect(outcome).toBe('opened');
    expect(await deviceFlowOfCode(app, flow.deviceHash)).toEqual({
      kind: 'device',
      id: flow.id,
      clientId: flow.clientId,
      scopesAsked: ['requests:read'],
      resource: flow.resource,
      browserHash: null,
      personHash: null,
      intervalSeconds: 5,
      polledAt: null,
      createdAt: NOW,
      endsAt: new Date(NOW.getTime() + FLOW_SECONDS * 1000),
      decided: null,
      orgId: null,
      keyId: null,
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
    const allowed = { outcome: 'allowed' as const, orgId: ORG, keyId: KEY, codeHash: null };
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

  it('counts device flows against the server’s cap of open flows', async () => {
    const admin = database.as('admin');
    const later = new Date('2027-01-01T09:00:00Z');
    await admin.query(
      `insert into oauth.flows (id, kind, client_id, redirect_uri, code_challenge, browser_hash, scopes_asked,
         resource, created_at, ends_at)
       select ('0199a0f0-0000-7000-9000-' || lpad(to_hex(n), 12, '0'))::uuid, 'code', 'c', 'https://a.example/cb',
         $1, $2, 'requests:read', 'r', $3, $4
       from generate_series(1, $5::int) as n`,
      [challengeOf('v'.repeat(43)), 'e'.repeat(64), later, new Date(later.getTime() + 1000), MOST_OPEN_FLOWS],
    );
    expect((await device(later)).opened).toBe('full');
    await admin.query("delete from oauth.flows where id::text like '0199a0f0-0000-7000-9000-%'");
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
    expect(await keptClientMetadata(app, DOCUMENT.clientId, NOW)).toBeUndefined();
    await keepClientMetadata(app, DOCUMENT, NOW);
    expect(await keptClientMetadata(app, DOCUMENT.clientId, NOW)).toEqual({ document: DOCUMENT, fresh: true });
    const dayOn = new Date(NOW.getTime() + CLIENT_METADATA_KEPT_MS);
    // Past its day: stale, still kept for 7 days to stand in while it can't be fetched again.
    expect(await keptClientMetadata(app, DOCUMENT.clientId, dayOn)).toEqual({ document: DOCUMENT, fresh: false });
    const staleEnd = new Date(dayOn.getTime() + CLIENT_METADATA_STALE_MS);
    expect(await keptClientMetadata(app, DOCUMENT.clientId, new Date(staleEnd.getTime() - 1))).toMatchObject({
      fresh: false,
    });
    expect(await keptClientMetadata(app, DOCUMENT.clientId, staleEnd)).toBeUndefined();
    await keepClientMetadata(app, { ...DOCUMENT, name: 'Claude (new)' }, dayOn);
    expect(await keptClientMetadata(app, DOCUMENT.clientId, dayOn)).toMatchObject({
      document: { name: 'Claude (new)' },
      fresh: true,
    });
    const sweptFrom = new Date(dayOn.getTime() + CLIENT_METADATA_KEPT_MS + CLIENT_METADATA_STALE_MS);
    expect(await sweepClientMetadata(app, new Date(sweptFrom.getTime() - 1), 10)).toBe(0);
    expect(await sweepClientMetadata(app, sweptFrom, 10)).toBe(1);
    expect(await keptClientMetadata(app, DOCUMENT.clientId, dayOn)).toBeUndefined();
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
