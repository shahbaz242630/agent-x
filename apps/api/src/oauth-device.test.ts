// 6E3c (RFC 8628): a device's codes when the flows can't be opened: every
// flow at the server's cap, a user code drawn three times already held, or
// the database busy, each answered as OAuth's own error, never a failure.
// The flow on the real schema is oauth-connections.db.test.ts.
import type { OauthTables } from '@agentx/core/modules/oauth';
import type { Database } from '@agentx/platform/db';
import { LogCapture, SequentialIds, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { OauthClients } from './oauth-clients.ts';
import { createOauthDevice } from './oauth-device.ts';
import { capabilitiesOf } from './oauth-wire.ts';

const opened = vi.hoisted(() => ({ answers: [] as (string | Error)[] }));

vi.mock('@agentx/core/modules/oauth', async (original) => ({
  ...(await original<typeof import('@agentx/core/modules/oauth')>()),
  openDeviceFlow: () => {
    const next = opened.answers.shift() ?? 'opened';
    return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
  },
}));

afterEach(() => {
  opened.answers = [];
});

const CLIENT = 'axcl_0123456789abcdef0123456789abcdef';
const clients: OauthClients = {
  find: (clientId) =>
    Promise.resolve(clientId === CLIENT ? { clientId, name: 'Hermes', redirectUris: [], verifiedBy: null } : undefined),
  kept: () => Promise.resolve(undefined),
};

function device(capture = new LogCapture()) {
  return createOauthDevice({
    // Never reached: the flow's opening is the stand-in above.
    database: {} as Database<OauthTables>,
    clock: { now: () => new Date('2026-11-18T09:00:00Z') },
    ids: new SequentialIds(),
    logger: testLogger(capture),
    capabilities: capabilitiesOf('https://app.agentx.example'),
    clients,
  });
}

describe('a device’s codes refused, never a failure', () => {
  it('draws the user code again while it is held, and opens with the next', async () => {
    opened.answers = ['collided', 'collided', 'opened'];
    expect(await device().authorize({ client_id: CLIENT }, 'c-1')).toMatchObject({ outcome: 'opened' });
  });

  it('answers temporarily_unavailable, with its line, at the cap or after three draws held', async () => {
    const capture = new LogCapture();
    opened.answers = ['full'];
    expect(await device(capture).authorize({ client_id: CLIENT }, 'c-1')).toMatchObject({
      outcome: 'refused',
      status: 503,
      error: 'temporarily_unavailable',
    });
    opened.answers = ['collided', 'collided', 'collided'];
    expect(await device(capture).authorize({ client_id: CLIENT }, 'c-2')).toMatchObject({ status: 503 });
    expect(capture.lines().filter((line) => line.event === 'oauth.flows_capped')).toHaveLength(2);
  });

  it('answers a database busy as temporarily_unavailable, and lets any other failure through', async () => {
    const capture = new LogCapture();
    opened.answers = [Object.assign(new Error('deadlock'), { code: '40P01' })];
    expect(await device(capture).authorize({ client_id: CLIENT }, 'c-1')).toMatchObject({ status: 503 });
    expect(capture.lines().filter((line) => line.event === 'oauth.grant_in_trouble')).toEqual([
      expect.objectContaining({ level: 'warn', at: 'device_authorization' }),
    ]);
    opened.answers = [new Error('a bug')];
    await expect(device().authorize({ client_id: CLIENT }, 'c-2')).rejects.toThrow('a bug');
  });
});
