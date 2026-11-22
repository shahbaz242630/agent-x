// SEC-LIM-13 S210 R2-4: the platform chain's growth brake on the real migrated schema, as the app role: on once the
// head is PLATFORM_GROWTH_BRAKE past the latest anchor this process holds, read at most every BRAKE_READ_EVERY_MS;
// off with no anchor held, or a head that can't be read (said).
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { Chain } from '@agentx/platform/audit-chain';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { BRAKE_READ_EVERY_MS, createPlatformGrowthBrake, PLATFORM_GROWTH_BRAKE } from './platform-growth-brake.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<PlatformControlsTables>;

const ANCHORED = 1_000n;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 1 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** Puts the platform head at `seq`, as the owner would find it. */
const headAt = (seq: bigint) =>
  database.as('admin').query(
    `insert into platform_controls.audit_head (seq, hash, mac, mac_key_version) values ($1, $2, $3, 1)
       on conflict (only_row) do update set seq = excluded.seq`,
    [seq.toString(), Buffer.alloc(32), Buffer.alloc(32)],
  );

/** Anchors held, the platform's at `seq`, and which chains were asked. */
const anchorsAt = (seq: bigint | undefined) => {
  const asked: Chain[] = [];
  return {
    asked,
    latest: (chain: Chain) => {
      asked.push(chain);
      return seq === undefined ? undefined : { seq };
    },
  };
};

describe(`SEC-LIM-13 S210 R2-4 the platform chain's growth brake (Postgres ${server.version})`, () => {
  it(`is on once the head is more than ${String(PLATFORM_GROWTH_BRAKE)} past the platform's anchor, read at most every ${String(BRAKE_READ_EVERY_MS)} ms`, async () => {
    const clock = new FixedClock(new Date('2026-12-01T09:00:00Z'));
    const brake = createPlatformGrowthBrake({ database: app, clock, logger: testLogger() });
    // No anchors held yet: off, the head unread.
    expect(await brake.engaged()).toBe(false);

    const anchors = anchorsAt(ANCHORED);
    brake.useAnchors(anchors);
    await headAt(ANCHORED + BigInt(PLATFORM_GROWTH_BRAKE));
    expect(await brake.engaged()).toBe(false);
    expect(anchors.asked).toEqual([{ kind: 'platform' }]);

    // One past: on, but only once the last reading is 30 seconds old; asked meanwhile, the reading kept.
    await headAt(ANCHORED + BigInt(PLATFORM_GROWTH_BRAKE) + 1n);
    clock.advanceBy(BRAKE_READ_EVERY_MS - 1);
    expect(await brake.engaged()).toBe(false);
    clock.advanceBy(1);
    expect(await brake.engaged()).toBe(true);
    expect(anchors.asked).toHaveLength(2);

    // Anchored again (the anchor check's next run, given afresh): off at once.
    brake.useAnchors(anchorsAt(ANCHORED + BigInt(PLATFORM_GROWTH_BRAKE)));
    expect(await brake.engaged()).toBe(false);
  });

  it('is off with no platform anchor, and off, said, when the head cannot be read', async () => {
    const clock = new FixedClock(new Date('2026-12-01T09:00:00Z'));
    await headAt(ANCHORED + BigInt(PLATFORM_GROWTH_BRAKE) * 2n);
    const unanchored = createPlatformGrowthBrake({ database: app, clock, logger: testLogger() });
    unanchored.useAnchors(anchorsAt(undefined));
    expect(await unanchored.engaged()).toBe(false);

    const capture = new LogCapture();
    const logger = createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: capture,
    });
    // A database that can't be read: every statement fails as it is made.
    const away = {
      selectFrom: () => {
        throw new Error('the database is away');
      },
    } as unknown as Database<PlatformControlsTables>;
    const unread = createPlatformGrowthBrake({ database: away, clock, logger });
    unread.useAnchors(anchorsAt(ANCHORED));
    expect(await unread.engaged()).toBe(false);
    expect(capture.lines().filter((line) => line.event === 'auth.platform_growth_unread')).toEqual([
      expect.objectContaining({ level: 'warn' }),
    ]);
  });

  it('reads an empty head as off', async () => {
    await database.as('admin').query('delete from platform_controls.audit_head');
    const brake = createPlatformGrowthBrake({
      database: app,
      clock: new FixedClock(new Date('2026-12-01T09:00:00Z')),
      logger: testLogger(),
    });
    brake.useAnchors(anchorsAt(ANCHORED));
    expect(await brake.engaged()).toBe(false);
  });
});
