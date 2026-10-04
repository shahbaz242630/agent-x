// B6-2b: reading the platform chain's events by their facts, on the real
// migrated schema, as the app role: only events of the action asked for
// count, whatever the others hold. B6-3d: the latest time among events of
// several kinds, each by its action and facts.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createPlatformChain } from './platform-chain.ts';
import { latestPlatformTime, latestPlatformTimeOf, platformEventWith } from './platform-events.ts';
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
  app = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
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

describe(`the latest time among the chain's events matching any of several kinds (B6-3d, Postgres ${server.version})`, () => {
  const record = (action: string, details: Record<string, string>) =>
    chain.recordAlone(app, { actor: ACTOR, action, details });

  it('reads the latest time among the events each kind matches: its action, its facts, one of, none of', async () => {
    await record('kind.one', { person: 'p-1', type: 'a', by: 'other', at: '2026-09-28T01:00:00.000Z' });
    await record('kind.one', { person: 'p-1', type: 'b', by: 'system', at: '2026-09-28T02:00:00.000Z' });
    // Not one of the types, by the one excluded, another person's, another action's: none counts.
    await record('kind.one', { person: 'p-1', type: 'c', by: 'other', at: '2026-09-28T09:00:00.000Z' });
    await record('kind.one', { person: 'p-1', type: 'a', by: 'self', at: '2026-09-28T09:00:00.000Z' });
    await record('kind.one', { person: 'p-2', type: 'a', by: 'other', at: '2026-09-28T09:00:00.000Z' });
    await record('kind.other', { person: 'p-1', type: 'a', by: 'other', at: '2026-09-28T09:00:00.000Z' });
    const one = { action: 'kind.one', facts: { person: 'p-1' }, oneOf: { type: ['a', 'b'] }, noneOf: { by: ['self'] } };

    expect(await latestPlatformTimeOf(app, 'at', [one])).toEqual(new Date('2026-09-28T02:00:00.000Z'));
    expect(await latestPlatformTimeOf(app, 'at', [{ ...one, oneOf: { type: ['a'] } }])).toEqual(
      new Date('2026-09-28T01:00:00.000Z'),
    );
    expect(await latestPlatformTimeOf(app, 'at', [{ ...one, noneOf: {} }])).toEqual(
      new Date('2026-09-28T09:00:00.000Z'),
    );
  });

  it('takes the latest across the kinds, a kind of another action among them', async () => {
    await record('kind.three', { person: 'p-3', at: '2026-09-28T03:00:00.000Z' });
    await record('kind.four', { person: 'p-3', at: '2026-09-28T04:00:00.000Z' });
    const three = { action: 'kind.three', facts: { person: 'p-3' } };
    const four = { action: 'kind.four', facts: { person: 'p-3' } };

    expect(await latestPlatformTimeOf(app, 'at', [three])).toEqual(new Date('2026-09-28T03:00:00.000Z'));
    expect(await latestPlatformTimeOf(app, 'at', [three, four])).toEqual(new Date('2026-09-28T04:00:00.000Z'));
    expect(await latestPlatformTimeOf(app, 'at', [four, three])).toEqual(new Date('2026-09-28T04:00:00.000Z'));
  });

  it('counts an event without the fact none of the values names, and no event without one of the values', async () => {
    await record('kind.five', { person: 'p-5', at: '2026-09-28T05:00:00.000Z' });

    expect(
      await latestPlatformTimeOf(app, 'at', [
        { action: 'kind.five', facts: { person: 'p-5' }, noneOf: { by: ['self'] } },
      ]),
    ).toEqual(new Date('2026-09-28T05:00:00.000Z'));
    expect(
      await latestPlatformTimeOf(app, 'at', [
        { action: 'kind.five', facts: { person: 'p-5' }, oneOf: { by: ['other'] } },
      ]),
    ).toBeUndefined();
  });

  it('finds no time for no kinds, or for kinds no event matches', async () => {
    expect(await latestPlatformTimeOf(app, 'at', [])).toBeUndefined();
    expect(await latestPlatformTimeOf(app, 'at', [{ action: 'kind.none', facts: {} }])).toBeUndefined();
  });

  it('fails, rather than passes, on a time that isn’t one', async () => {
    await record('kind.six', { person: 'p-6', at: 'not a time' });

    await expect(latestPlatformTimeOf(app, 'at', [{ action: 'kind.six', facts: { person: 'p-6' } }])).rejects.toThrow();
  });
});
