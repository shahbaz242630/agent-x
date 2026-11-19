// S206 V6: when the security rows' MACs began, on the real migrated schema as
// the app role: recorded once by the first start (plus the hour for the copies
// before), every later start leaving it; read once and then kept; none yet
// believes no row without a MAC; and one the database's owner rewrote is never
// believed, its alarm raised, at a start and at a read.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import type { PlatformControlsTables } from '../../platform-controls/index.ts';
import { MACS_FROM, macBoundary, recordMacBoundary } from './mac-boundary.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<PlatformControlsTables>;
let capture: LogCapture;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb0d0_0000_0000);
const FIRST = new Date('2026-12-01T10:00:00.000Z');
/** The hour a row of the release before may still come without a MAC. */
const HOUR_MS = 60 * 60_000;

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<PlatformControlsTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
  capture = new LogCapture();
});

afterEach(async () => {
  await app.destroy();
  await database.drop();
});

describe('the security rows’ MAC boundary (S206 V6)', () => {
  it('none yet believes no row without a MAC, and is asked again; the first start records it, every later one leaves it', async () => {
    const read = macBoundary(keys, testLogger(capture));
    expect(await read(app)).toBe(Number.NEGATIVE_INFINITY);

    expect(await recordMacBoundary(app, { keys, ids, clock: new FixedClock(FIRST) })).toBe(FIRST.getTime() + HOUR_MS);
    const later = new FixedClock(new Date(FIRST.getTime() + 86_400_000));
    expect(await recordMacBoundary(app, { keys, ids, clock: later })).toBe(FIRST.getTime() + HOUR_MS);
    expect(await read(app)).toBe(FIRST.getTime() + HOUR_MS);

    const recorded = await app
      .selectFrom('platform_controls.audit_events')
      .select('details')
      .where('action', '=', MACS_FROM)
      .execute();
    expect(recorded).toHaveLength(1);
    expect(alarms()).toEqual([]);
  });

  it('kept once read: the owner rewriting it after moves nothing for this process', async () => {
    await recordMacBoundary(app, { keys, ids, clock: new FixedClock(FIRST) });
    const read = macBoundary(keys, testLogger(capture));
    expect(await read(app)).toBe(FIRST.getTime() + HOUR_MS);

    await database
      .as('admin')
      .query("update platform_controls.audit_events set details = replace(details, '2026', '2099') where action = $1", [
        MACS_FROM,
      ]);

    expect(await read(app)).toBe(FIRST.getTime() + HOUR_MS);
  });

  it('one the owner rewrote is never believed: no row without a MAC is, and the alarm is raised', async () => {
    await recordMacBoundary(app, { keys, ids, clock: new FixedClock(FIRST) });
    await database
      .as('admin')
      .query("update platform_controls.audit_events set details = replace(details, '2026', '2099') where action = $1", [
        MACS_FROM,
      ]);

    expect(await macBoundary(keys, testLogger(capture))(app)).toBe(Number.NEGATIVE_INFINITY);
    expect(await recordMacBoundary(app, { keys, ids, clock: new FixedClock(FIRST) })).toBe('unsealed');
    expect(alarms().map(({ check, reason }) => [check, reason])).toEqual([['security_event', 'boundary']]);
  });
});
