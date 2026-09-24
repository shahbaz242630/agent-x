// B2-5a: security events (0012) on the real migrated schema, as the app role:
// written a batch at a time, refused whole when anything in the batch is
// malformed, and swept once past the retention period, oldest first.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase, within } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import {
  createSecurityEvents,
  LEAST_RETENTION_DAYS,
  MOST_EVENTS_A_BATCH,
  type SecurityEvent,
} from './security-events.ts';
import type { SecurityEventsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SecurityEventsTables>;

const START = new Date('2026-09-24T09:00:00Z');
const DAY = 86_400_000;
const RETENTION = 90;
const ids = new SequentialIds(0x5ec0);

const event = (change: Partial<SecurityEvent> = {}): SecurityEvent => ({
  kind: 'sign_in_failed',
  reason: 'state_mismatch',
  ip: '203.0.113.7',
  userId: undefined,
  windowStart: new Date(START.getTime() - 60_000),
  count: 1,
  ...change,
});

const at = (ms: number, retentionDays = RETENTION) =>
  createSecurityEvents({ ids, clock: new FixedClock(new Date(ms)), retentionDays });

const all = () => app.selectFrom('security.events').selectAll().orderBy('created_at').orderBy('reason').execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SecurityEventsTables>(
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

/** Each test starts from an empty table: the sweep far in the future takes every row. */
async function empty(): Promise<void> {
  await at(START.getTime() + 10_000 * DAY).sweep(app, 1_000_000);
  expect(await all()).toEqual([]);
}

describe(`security events (B2-5a, Postgres ${server.version})`, () => {
  it('writes a batch as counts, each with its address, person and window, stamped when written', async () => {
    await empty();
    const person = '0199a0f0-0000-7000-8000-0000000b25a1';
    await at(START.getTime()).record(app, [
      event({ count: 3 }),
      event({ kind: 'rate_limited', reason: 'user', ip: '2001:db8::1', userId: person, count: 40 }),
      event({ reason: 'callback_incomplete', ip: undefined }),
    ]);

    expect(
      (await all()).map(({ kind, reason, ip, user_id, window_start, count, created_at }) => ({
        kind,
        reason,
        ip,
        user_id,
        window_start,
        count,
        created_at,
      })),
    ).toEqual([
      {
        kind: 'sign_in_failed',
        reason: 'callback_incomplete',
        ip: null,
        user_id: null,
        window_start: event().windowStart,
        count: 1,
        created_at: START,
      },
      {
        kind: 'sign_in_failed',
        reason: 'state_mismatch',
        ip: '203.0.113.7',
        user_id: null,
        window_start: event().windowStart,
        count: 3,
        created_at: START,
      },
      {
        kind: 'rate_limited',
        reason: 'user',
        ip: '2001:db8::1',
        user_id: person,
        window_start: event().windowStart,
        count: 40,
        created_at: START,
      },
    ]);
  });

  it('takes every form of address the API can see: IPv4, IPv6, and IPv4 mapped into IPv6', async () => {
    await empty();
    await at(START.getTime()).record(app, [
      event({ ip: '0.0.0.0' }),
      event({ ip: '255.255.255.255' }),
      event({ ip: '::1' }),
      event({ ip: '::ffff:203.0.113.7' }),
    ]);
    expect((await all()).map((row) => row.ip).sort()).toEqual([
      '0.0.0.0',
      '255.255.255.255',
      '::1',
      '::ffff:203.0.113.7',
    ]);
  });

  it.each([
    ['text that is no address', '203.0.113'],
    ['an address with a port', '203.0.113.7:443'],
    ['an address past 255', '203.0.113.256'],
    ['an address with a leading zero', '203.0.113.07'],
    ['an IPv6 address with a zone', 'fe80::1%eth0'],
    ['an IPv6 address in brackets', '[2001:db8::1]'],
    ['text with a colon that is no address', 'not:an:address'],
    // Text the URL parse alone would take: the host ends at the `]`, and the rest is a path, a query or a fragment.
    ['an IPv6 address closed early, then a path', '::1]/x'],
    ['an IPv6 address closed early, then a query', '::1]?x'],
    ['an IPv6 address closed early, then a fragment', '::1]#x'],
    ['an IPv6 address with a trailing space', '::1 '],
  ])('keeps the event, its address unknown, for %s: it came from outside, and loses nothing else', async (_, ip) => {
    await empty();
    await at(START.getTime()).record(app, [event({ reason: 'first' }), event({ reason: 'odd', ip })]);
    expect((await all()).map((row) => [row.reason, row.ip])).toEqual([
      ['first', '203.0.113.7'],
      ['odd', null],
    ]);
  });

  it('writes nothing for an empty batch', async () => {
    await empty();
    await at(START.getTime()).record(app, []);
    expect(await all()).toEqual([]);
  });

  it.each<[string, Partial<SecurityEvent>]>([
    ['a kind we never record', { kind: 'logged_in' as SecurityEvent['kind'] }],
    ['a reason with capitals', { reason: 'StateMismatch' }],
    ['a reason with a space', { reason: 'state mismatch' }],
    ['an empty reason', { reason: '' }],
    ['a reason too long', { reason: 'a'.repeat(65) }],
    ['a person who is no UUID', { userId: 'someone' }],
    ['a window that never began', { windowStart: new Date(Number.NaN) }],
    ['a window in the future', { windowStart: new Date(START.getTime() + 1) }],
    ['a count of none', { count: 0 }],
    ['a part count', { count: 1.5 }],
  ])('refuses a batch holding %s, writing none of it', async (_, change) => {
    await empty();
    await expect(at(START.getTime()).record(app, [event(), event(change)])).rejects.toThrow(RangeError);
    expect(await all()).toEqual([]);
  });

  it(`writes at most ${String(MOST_EVENTS_A_BATCH)} at a time`, async () => {
    await empty();
    const batch = Array.from({ length: MOST_EVENTS_A_BATCH }, () => event());
    await at(START.getTime()).record(app, batch);
    expect(await all()).toHaveLength(MOST_EVENTS_A_BATCH);
    await expect(at(START.getTime()).record(app, [...batch, event()])).rejects.toThrow(RangeError);
    expect(await all()).toHaveLength(MOST_EVENTS_A_BATCH);
  });

  it(`keeps events at least ${String(LEAST_RETENTION_DAYS)} whole days`, () => {
    expect(() => at(START.getTime(), LEAST_RETENTION_DAYS)).not.toThrow();
    for (const days of [LEAST_RETENTION_DAYS - 1, 0, -1, 30.5, Number.NaN]) {
      expect(() => at(START.getTime(), days)).toThrow(RangeError);
    }
  });

  it('sweeps the events past the retention period to the millisecond, oldest first, a batch at a time', async () => {
    await empty();
    const oldest = START.getTime();
    // Written newest first, so the table's own order is the opposite of the sweep's.
    for (const [offset, reason] of [
      [2 * DAY, 'old'],
      [DAY, 'older'],
      [0, 'oldest'],
    ] as const) {
      await at(oldest + offset).record(app, [event({ reason, windowStart: new Date(oldest + offset) })]);
    }
    const reasons = async () => (await all()).map((row) => row.reason);

    // One millisecond before the oldest is past its 90 days: nothing goes.
    const past = oldest + RETENTION * DAY;
    expect(await at(past - 1).sweep(app, 10)).toBe(0);
    // Past only the oldest.
    expect(await at(past).sweep(app, 10)).toBe(1);
    expect(await reasons()).toEqual(['older', 'old']);
    // Past both that are left, one at a time: the older first.
    expect(await at(past + 2 * DAY).sweep(app, 1)).toBe(1);
    expect(await reasons()).toEqual(['old']);
    expect(await at(past + 2 * DAY).sweep(app, 10)).toBe(1);
    expect(await at(past + 2 * DAY).sweep(app, 10)).toBe(0);
  });

  it('refuses a sweep of no events', async () => {
    for (const most of [0, -1, 1.5, Number.NaN]) {
      await expect(at(START.getTime()).sweep(app, most)).rejects.toThrow(RangeError);
    }
  });

  it('gives up after 10 seconds, a wait for a lock included, rather than hang', async () => {
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table security.events in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, at(START.getTime()).record(app, [event()]), 'the write')).rejects.toThrow(
        /statement timeout/,
      );
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
      await expect(within(20_000, at(START.getTime()).sweep(app, 10), 'the sweep')).rejects.toThrow(
        /statement timeout/,
      );
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('never lets the app change an event once written', async () => {
    await empty();
    await at(START.getTime()).record(app, [event()]);
    await expect(app.updateTable('security.events').set({ count: 1000 }).execute()).rejects.toMatchObject({
      code: '42501',
    });
  });
});
