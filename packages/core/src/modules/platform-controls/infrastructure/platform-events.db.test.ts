// B6-2b: reading the platform chain's events by their facts, on the real
// migrated schema, as the app role: only events of the action asked for
// count, whatever the others hold.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createPlatformChain } from './platform-chain.ts';
import { latestPlatformTime, platformEventWith } from './platform-events.ts';
import type { PlatformControlsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<PlatformControlsTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const chain = createPlatformChain({ keys, ids: new SequentialIds(0xc6e0) });
const ACTOR = { type: 'system', id: 'api' } as const;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<PlatformControlsTables>(
    { ...database.connection('app'), maxConnections: 2 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the platform chain's events by their facts (B6-2b, Postgres ${server.version})`, () => {
  it('finds nothing, and no time, on a chain that holds none of the action', async () => {
    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-1' })).toBe(false);
    expect(await latestPlatformTime(app, 'idp.event_copied', 'at')).toBeUndefined();
  });

  it('counts only the action asked for, even when another holds the same facts and a later time', async () => {
    await chain.recordAlone(app, {
      actor: ACTOR,
      action: 'other.thing_done',
      details: { event: 'e-2', org: 'none', at: '2026-09-28T00:00:00.000Z' },
    });
    await chain.recordAlone(app, {
      actor: ACTOR,
      action: 'idp.event_copied',
      details: { event: 'e-3', org: 'none', at: '2026-09-27T08:00:00.000Z' },
    });

    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-2', org: 'none' })).toBe(false);
    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-3', org: 'none' })).toBe(true);
    expect(await platformEventWith(app, 'idp.event_copied', { event: 'e-3', org: 'another' })).toBe(false);
    expect(await latestPlatformTime(app, 'idp.event_copied', 'at')).toEqual(new Date('2026-09-27T08:00:00.000Z'));
  });
});
