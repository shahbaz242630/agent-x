// 6E3c (RFC 8628): a device's codes when the flows can't be opened: every
// flow at the server's cap, a user code drawn three times already held, or
// the database busy, each answered as OAuth's own error, never a failure.
// AG8: failed user-code lookups held per network and watched server-wide, and a claimed flow's code
// typed by someone else warned of. The flow on the real schema is
// oauth-connections.db.test.ts.
import { DEVICE_CODE_GRANT, type DeviceClaim, newFlowCookie, type OauthTables } from '@agentx/core/modules/oauth';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { FixedClock, LogCapture, SequentialIds, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { OauthClients } from './oauth-clients.ts';
import {
  createOauthDevice,
  MOST_FAILED_LOOKUPS_A_MINUTE,
  MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE,
} from './oauth-device.ts';
import { capabilitiesOf } from './oauth-wire.ts';

const opened = vi.hoisted(() => ({ answers: [] as (string | Error)[] }));
const claims = vi.hoisted(() => ({ answers: [] as DeviceClaim[], asked: 0 }));
/** Whether a claimed flow reads as its device opened it (S205): sealed, unless a case says otherwise. */
const sealed = vi.hoisted(() => ({ sound: true, userCode: 'BCDFGHJK' }));

vi.mock('@agentx/core/modules/oauth', async (original) => ({
  ...(await original<typeof import('@agentx/core/modules/oauth')>()),
  openDeviceFlow: () => {
    const next = opened.answers.shift() ?? 'opened';
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
  },
  deviceClaimed: () => {
    claims.asked += 1;
    return Promise.resolve(claims.answers.shift() ?? { outcome: 'not_found' });
  },
  flowById: async (_: unknown, id: string) => {
    const { hashOf } = await original<typeof import('@agentx/core/modules/oauth')>();
    return { kind: 'device', id, userCodeHash: hashOf(sealed.userCode) };
  },
  pendingFlowSound: () => sealed.sound,
}));

afterEach(() => {
  opened.answers = [];
  claims.answers = [];
  claims.asked = 0;
  sealed.sound = true;
  sealed.userCode = 'BCDFGHJK';
});

const CLIENT = 'axcl_0123456789abcdef0123456789abcdef';
const clients: OauthClients = {
  find: (clientId) =>
    Promise.resolve(
      clientId === CLIENT
        ? { clientId, name: 'Hermes', redirectUris: [], grantTypes: [DEVICE_CODE_GRANT], verifiedBy: null }
        : undefined,
    ),
  kept: () => Promise.resolve(undefined),
};

function device(capture = new LogCapture(), clock = new FixedClock(new Date('2026-11-18T09:00:00Z')), copies = 1) {
  return createOauthDevice({
    // Never reached: the flow's opening and claiming are the stand-ins above.
    database: {} as Database<OauthTables>,
    keys: {} as KeyProvider,
    clock,
    ids: new SequentialIds(),
    logger: testLogger(capture),
    capabilities: capabilitiesOf('https://app.agentx.example'),
    clients,
    copies,
  });
}

const PERSON = '0199a0f0-0000-7000-8000-00000000a801';
const FLOW = '0199a0f0-0000-7000-8000-00000000a802';

describe('S205: a claimed flow is believed only as its device opened it', () => {
  it('answers a claimed flow whose seal is not its own as nothing found', async () => {
    claims.answers = [{ outcome: 'claimed', flowId: FLOW }];
    sealed.sound = false;
    expect(await device().lookup('BCDF-GHJK', undefined, PERSON, '203.0.113.9')).toEqual({ outcome: 'not_found' });
  });

  it('answers a claimed flow, sound, but now for another user code, as nothing found, with the alarm', async () => {
    claims.answers = [{ outcome: 'claimed', flowId: FLOW }];
    sealed.userCode = 'ZZZZZZZZ';
    const capture = new LogCapture();
    expect(await device(capture).lookup('BCDF-GHJK', undefined, PERSON, '203.0.113.9')).toEqual({
      outcome: 'not_found',
    });
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'audit.integrity_failed', reason: 'user_code', objectId: FLOW }),
    ]);
  });
});

describe('AG8: failed user-code lookups, held per network, watched server-wide, and on each flow', () => {
  const HOME = '203.0.113.9';
  const SITE = '2001:db8:a8:1::7';
  const NEIGHBOUR = '2001:db8:a8:ffff::1';

  it(`holds a network to ${String(MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE)} failed lookups a minute; no other network waits`, async () => {
    const capture = new LogCapture();
    const clock = new FixedClock(new Date('2026-11-18T09:00:00Z'));
    const at = device(capture, clock);
    for (let tried = 0; tried < MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE; tried += 1) {
      expect(await at.lookup('BCDF-GHJK', undefined, PERSON, SITE)).toEqual({ outcome: 'not_found' });
    }
    // Held: not even looked for, a right code too, from any /64 of that /48.
    claims.answers = [{ outcome: 'claimed', flowId: FLOW }];
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, NEIGHBOUR)).toEqual({ outcome: 'held' });
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, SITE)).toEqual({ outcome: 'held' });
    expect(claims.asked).toBe(MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE);
    expect(capture.lines().filter((line) => line.event === 'oauth.device_lookups_network_held')).toEqual([
      expect.objectContaining({ level: 'warn', most: MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE, refused: 1 }),
    ]);
    // Never the address itself in a log line (ADR-011 §7).
    expect(JSON.stringify(capture.lines())).not.toContain('2001:db8');
    // Another network is looked up as ever.
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, HOME)).toMatchObject({ outcome: 'claimed' });
    // The next minute, that network is looked up again.
    clock.advanceBy(60_000);
    claims.answers = [{ outcome: 'claimed', flowId: FLOW }];
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, SITE)).toMatchObject({
      outcome: 'claimed',
      requestId: FLOW,
    });
  });

  it(`only warns, never holds anyone, past ${String(MOST_FAILED_LOOKUPS_A_MINUTE)} failed a minute server-wide`, async () => {
    const capture = new LogCapture();
    const clock = new FixedClock(new Date('2026-11-18T09:00:00Z'));
    const at = device(capture, clock);
    // Each failure from a network of its own: no network comes near its own limit.
    for (let tried = 0; tried < MOST_FAILED_LOOKUPS_A_MINUTE + 5; tried += 1) {
      expect(
        await at.lookup('BCDF-GHJK', undefined, PERSON, `198.51.${String(tried >> 8)}.${String(tried % 256)}`),
      ).toEqual({
        outcome: 'not_found',
      });
    }
    claims.answers = [{ outcome: 'claimed', flowId: FLOW }];
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, HOME)).toMatchObject({ outcome: 'claimed' });
    expect(capture.lines().filter((line) => line.event === 'oauth.device_lookups_capped')).toEqual([
      expect.objectContaining({ level: 'warn', most: MOST_FAILED_LOOKUPS_A_MINUTE }),
    ]);
    // Said again the next minute it is passed, not before.
    clock.advanceBy(59_999);
    await at.lookup('BCDF-GHJK', undefined, PERSON, '192.0.2.1');
    expect(capture.lines().filter((line) => line.event === 'oauth.device_lookups_capped')).toHaveLength(1);
  });

  it('counts a code no user code could be, and holds each copy to its share of each count', async () => {
    const capture = new LogCapture();
    const at = device(capture, undefined, 4);
    const share = Math.ceil(MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE / 4);
    for (let tried = 0; tried < share; tried += 1) {
      expect(await at.lookup('not a code', undefined, PERSON, HOME)).toEqual({ outcome: 'not_found' });
    }
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, HOME)).toEqual({ outcome: 'held' });
    expect(claims.asked).toBe(0);
    const serverShare = Math.ceil(MOST_FAILED_LOOKUPS_A_MINUTE / 4);
    for (let tried = share; tried < serverShare; tried += 1) {
      await at.lookup('not a code', undefined, PERSON, `198.51.100.${String(tried)}`);
    }
    expect(capture.lines().filter((line) => line.event === 'oauth.device_lookups_capped')).toEqual([
      expect.objectContaining({ most: serverShare }),
    ]);
  });

  it('answers a code another browser or person claimed as nothing found, with its warning, and counts it failed', async () => {
    const capture = new LogCapture();
    const at = device(capture);
    claims.answers = [
      { outcome: 'contested', flowId: FLOW, failedClaims: 1, denied: false },
      { outcome: 'contested', flowId: FLOW, failedClaims: 3, denied: true },
    ];
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, HOME)).toEqual({ outcome: 'not_found' });
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, HOME)).toEqual({ outcome: 'not_found' });
    expect(capture.lines().filter((line) => line.event === 'oauth.device_code_contested')).toEqual([
      expect.objectContaining({ level: 'warn', flowId: FLOW, failedClaims: 1, denied: false }),
      expect.objectContaining({ level: 'warn', flowId: FLOW, failedClaims: 3, denied: true }),
    ]);
    for (let tried = 2; tried < MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE; tried += 1) {
      await at.lookup('BCDF-GHJK', undefined, PERSON, HOME);
    }
    expect(await at.lookup('BCDF-GHJK', undefined, PERSON, HOME)).toEqual({ outcome: 'held' });
  });

  it('claims for this browser’s cookie, or a new one, and never counts a claim as failed', async () => {
    const at = device();
    const cookie = newFlowCookie();
    claims.answers = Array.from({ length: MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE + 1 }, () => ({
      outcome: 'claimed' as const,
      flowId: FLOW,
    }));
    expect(await at.lookup('bcdf ghjk', cookie, PERSON, HOME)).toEqual({ outcome: 'claimed', requestId: FLOW, cookie });
    const fresh = await at.lookup('BCDF-GHJK', 'not a cookie', PERSON, HOME);
    expect(fresh).toMatchObject({ outcome: 'claimed', requestId: FLOW });
    expect(fresh.outcome === 'claimed' && fresh.cookie !== 'not a cookie').toBe(true);
    for (let tried = 2; tried <= MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE; tried += 1) {
      await at.lookup('BCDF-GHJK', cookie, PERSON, HOME);
    }
    expect(claims.asked).toBe(MOST_FAILED_LOOKUPS_A_NETWORK_A_MINUTE + 1);
  });
});

describe('a device’s codes refused, never a failure', () => {
  it('draws the user code again while it is held, and opens with the next', async () => {
    opened.answers = ['collided', 'collided', 'opened'];
    expect(await device().authorize({ client_id: CLIENT }, 'c-1', '192.0.2.1')).toMatchObject({ outcome: 'opened' });
  });

  it('answers temporarily_unavailable, with its line, at the cap or after three draws held', async () => {
    const capture = new LogCapture();
    opened.answers = ['full'];
    expect(await device(capture).authorize({ client_id: CLIENT }, 'c-1', '192.0.2.1')).toMatchObject({
      outcome: 'refused',
      status: 503,
      error: 'temporarily_unavailable',
    });
    opened.answers = ['collided', 'collided', 'collided'];
    expect(await device(capture).authorize({ client_id: CLIENT }, 'c-2', '192.0.2.1')).toMatchObject({ status: 503 });
    expect(capture.lines().filter((line) => line.event === 'oauth.flows_capped')).toHaveLength(2);
  });

  it('6F1 G4: answers temporarily_unavailable at its source’s cap, its line at most once a minute', async () => {
    const capture = new LogCapture();
    const at = device(capture);
    opened.answers = ['source_full', 'source_full'];
    expect(await at.authorize({ client_id: CLIENT }, 'c-1', '192.0.2.1')).toMatchObject({
      outcome: 'refused',
      status: 503,
      error: 'temporarily_unavailable',
    });
    await at.authorize({ client_id: CLIENT }, 'c-2', '192.0.2.1');
    expect(capture.lines().filter((line) => line.event === 'oauth.source_capped')).toEqual([
      expect.objectContaining({ level: 'warn', kind: 'device', per: 'source', most: 20, refused: 1 }),
    ]);
    expect(capture.lines().filter((line) => line.event === 'oauth.flows_capped')).toEqual([]);
  });

  it('AG8: answers temporarily_unavailable at its network’s cap, with the network’s own line', async () => {
    const capture = new LogCapture();
    opened.answers = ['network_full'];
    expect(await device(capture).authorize({ client_id: CLIENT }, 'c-1', '2001:db8:a8::1')).toMatchObject({
      outcome: 'refused',
      status: 503,
      error: 'temporarily_unavailable',
    });
    expect(capture.lines().filter((line) => line.event === 'oauth.source_capped')).toEqual([
      expect.objectContaining({ level: 'warn', kind: 'device', per: 'network', most: 100, refused: 1 }),
    ]);
  });

  it('answers a database busy as temporarily_unavailable, and lets any other failure through', async () => {
    const capture = new LogCapture();
    opened.answers = [Object.assign(new Error('deadlock'), { code: '40P01' })];
    expect(await device(capture).authorize({ client_id: CLIENT }, 'c-1', '192.0.2.1')).toMatchObject({ status: 503 });
    expect(capture.lines().filter((line) => line.event === 'oauth.grant_in_trouble')).toEqual([
      expect.objectContaining({ level: 'warn', at: 'device_authorization' }),
    ]);
    opened.answers = [new Error('a bug')];
    await expect(device().authorize({ client_id: CLIENT }, 'c-2', '192.0.2.1')).rejects.toThrow('a bug');
  });
});
