// S206 V6: the security rows' sealing job and the anchor check sharing the
// jobs' one anchor store, on the real migrated schema: the check anchors the
// platform chain, the sealing records its start and end and anchors after
// each, the check anchors again; every anchor follows the one before, none
// refused, and a store read afresh holds the chain's head. The store's own
// single flight (one read, one write at a time) is what serialises them.
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import type { SecurityEventsTables } from '@agentx/core/modules/security-events';
import { createAnchorLog } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createAnchorCheck } from './anchor-check.ts';
import { createLegacySealJob } from './legacy-seal-job.ts';

const server = inject('postgres');
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x5ea1_0000_0000);
const clock = { now: () => new Date() };

type Tables = SecurityEventsTables & PlatformControlsTables & DirectoryTables;
let database: TestDatabase;
let app: Database<Tables>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the sealing job and the anchor check on one anchor store (S206 V6, Postgres ${server.version})`, () => {
  it('anchor the platform chain in turn, each anchor following the last, none refused', async () => {
    const capture = new LogCapture();
    const logger = testLogger(capture);
    const platform = createPlatformChain({ keys, ids });
    await app
      .transaction()
      .execute((tx) =>
        platform.record(tx, { actor: { type: 'system', id: 'api' }, action: 'platform.started', details: {} }),
      );
    const fake = createFakeWriteOnceStore();
    const anchors = createAnchorLog({
      store: fake.store,
      keys,
      logger,
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 600_000,
    });
    const check = createAnchorCheck({
      chains: [{ chain: { kind: 'platform' }, verify: (anchor) => platform.verifyAlone(app, anchor) }],
      organizations: {
        list: () => Promise.resolve([]),
        recorded: () => Promise.resolve([]),
        verify: () => Promise.resolve({ ok: true, seq: 0n, hash: Buffer.alloc(32), macKeyVersion: 0 }),
        hold: () => Promise.resolve(),
      },
      keys,
      clock,
      logger,
      staleAfterMs: 600_000,
      deadlineMs: 30_000,
      durable: anchors,
      lanes: 1,
    });
    const job = createLegacySealJob({
      database: app,
      anchors,
      keys,
      ids,
      // Before the sealing's cutoff, whatever the day the test runs.
      clock: new FixedClock(new Date('2026-11-25T00:00:00.000Z')),
      logger,
      retentionDays: 30,
    });

    await check.run();
    await job.run();
    await check.run();

    const [head] = await database.as('admin').query<{ seq: string }>('select seq from platform_controls.audit_head');
    expect(capture.lines().find(({ event }) => event === 'security.legacy_seal_done')?.outcome).toBe('sealed');
    expect(
      capture
        .lines()
        .filter(({ level }) => level === 'error')
        .map(({ event }) => event),
    ).toEqual([]);
    expect(anchors.latest({ kind: 'platform' })?.seq).toBe(BigInt(head?.seq ?? '0'));
    // Written, and read back whole by another process.
    const reader = createAnchorLog({
      store: fake.store,
      keys,
      logger,
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 600_000,
    });
    await reader.read();
    expect(reader.state()).toBe('read');
    await reader.pin({ kind: 'platform' });
    expect(reader.latest({ kind: 'platform' })?.seq).toBe(BigInt(head?.seq ?? '0'));
  });
});
