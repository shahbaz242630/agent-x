// B2-5a: security events (0012) on the real migrated schema, as the app role:
// written a batch at a time, refused whole when anything in the batch is
// malformed, and swept once past the retention period, oldest first.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import {
  createSecurityEvents,
  LEAST_RETENTION_DAYS,
  MOST_EVENTS_A_BATCH,
  type SecurityEvent,
} from './security-events.ts';
import { type OrgEventsToRead, orgSecurityEventsPage } from './org-events.ts';
import type { SecurityEventsTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<SecurityEventsTables>;

const START = new Date('2026-09-24T09:00:00Z');
const RETENTION = 90;
const ids = new SequentialIds(0x5ec0);
const keys = createKeyProvider({ 'session-mac': { current: 1, versions: new Map([[1, Buffer.alloc(32, 9)]]) } }, [
  'session-mac',
]);

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
  createSecurityEvents({ ids, clock: new FixedClock(new Date(ms)), keys, retentionDays });

const all = () => app.selectFrom('security.events').selectAll().orderBy('created_at').orderBy('reason').execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<SecurityEventsTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** Each test starts from an empty table: the sweep far in the future takes every row. */
async function empty(): Promise<void> {
  await at(START.getTime() + 10_000 * DAY_MS).sweep(app, 1_000_000);
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
      [2 * DAY_MS, 'old'],
      [DAY_MS, 'older'],
      [0, 'oldest'],
    ] as const) {
      await at(oldest + offset).record(app, [event({ reason, windowStart: new Date(oldest + offset) })]);
    }
    const reasons = async () => (await all()).map((row) => row.reason);

    // One millisecond before the oldest is past its 90 days: nothing goes.
    const past = oldest + RETENTION * DAY_MS;
    expect(await at(past - 1).sweep(app, 10)).toBe(0);
    // Past only the oldest.
    expect(await at(past).sweep(app, 10)).toBe(1);
    expect(await reasons()).toEqual(['older', 'old']);
    // Past both that are left, one at a time: the older first.
    expect(await at(past + 2 * DAY_MS).sweep(app, 1)).toBe(1);
    expect(await reasons()).toEqual(['old']);
    expect(await at(past + 2 * DAY_MS).sweep(app, 10)).toBe(1);
    expect(await at(past + 2 * DAY_MS).sweep(app, 10)).toBe(0);
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

describe(`an organisation's own security events (6E1b, CO7b, 0091; Postgres ${server.version})`, () => {
  const ORG_A = '0199a0f0-0000-7000-8000-00000000abcd';
  const ORG_B = '0199a0f0-0000-7000-8000-00000000abce';
  const PERSON = '0199a0f0-0000-7000-8000-0000000b25a1';
  const AGENT = '0199a0f0-0000-7000-8000-00000000a9e1';
  const RANGE = { from: new Date(START.getTime() - DAY_MS), to: new Date(START.getTime() + DAY_MS), limit: 100 };
  const limited = (reason: string, change: Partial<SecurityEvent> = {}) =>
    event({ kind: 'rate_limited', reason, ...change });

  /** Each row's MAC checked, every row written by the app having one (S206 V6): none is believed without. */
  let capture = new LogCapture();
  const checked = () => ({ keys, macsFrom: Number.NEGATIVE_INFINITY, logger: testLogger(capture) });

  /** One organisation's page, read inside its own transaction as the admins' route reads it. */
  const pageOf = (orgId: string, asked: Partial<OrgEventsToRead> = {}) =>
    withTenant(app, orgId, (tx) => orgSecurityEventsPage(tx, orgId, { ...RANGE, ...asked }, checked()));

  it('leaves off the page a row planted or edited by the database’s owner, the alarm raised for each (S206 V6)', async () => {
    await emptyOrgs();
    capture = new LogCapture();
    await at(START.getTime()).record(app, [
      limited('per_user', { userId: PERSON, orgId: ORG_A, windowStart: new Date(START.getTime() - 60_000) }),
      limited('per_agent', { agentId: AGENT, orgId: ORG_A, windowStart: new Date(START.getTime() - 120_000) }),
    ]);
    const owner = database.as('admin');
    await owner.query("update security.org_events set count = 99 where reason = 'per_agent'");
    const planted = ids.next();
    await owner.query(
      `insert into security.org_events (org_id, id, kind, reason, ip, user_id, agent_id, window_start, count, created_at)
       values ($1, $2, 'rate_limited', 'per_user', '198.51.100.9', null, null, $3, 7, $3)`,
      [ORG_A, planted, new Date(START.getTime() - 180_000)],
    );

    const page = await pageOf(ORG_A, { limit: 2 });
    expect(page.rows.map(({ reason }) => reason)).toEqual(['per_user']);
    // Where the rows read end: the next page starts past the edited one, never reading it twice.
    expect(page.next?.at).toEqual(new Date(START.getTime() - 120_000));
    expect((await pageOf(ORG_A, { limit: 2, before: page.next ?? undefined })).rows).toEqual([]);
    expect(
      capture
        .lines()
        .filter((line) => line.event === 'audit.integrity_failed')
        .map(({ check, reason, rowId, orgId }) => ({ check, reason, rowId, orgId })),
    ).toEqual([
      { check: 'security_event', reason: 'mac', rowId: expect.any(String) as unknown, orgId: ORG_A },
      { check: 'security_event', reason: 'mac', rowId: planted, orgId: ORG_A },
    ]);
  });

  /** Each test starts with no organisation's events: each organisation's sweep far in the future takes them all. */
  async function emptyOrgs(): Promise<void> {
    await empty();
    for (const orgId of [ORG_A, ORG_B]) {
      await at(START.getTime() + 10_000 * DAY_MS).sweepOrganisation(app, orgId, 1_000_000);
    }
  }

  it('writes each kind an organisation can have to its own table, never the global one', async () => {
    await emptyOrgs();
    await at(START.getTime()).record(app, [
      limited('per_user', { userId: PERSON, orgId: ORG_A.toUpperCase() }),
      limited('per_agent', { agentId: AGENT, orgId: ORG_A }),
      limited('per_organisation', { agentId: AGENT, orgId: ORG_A }),
      event({ reason: 'step_up_challenge_missing', userId: PERSON, orgId: ORG_A }),
    ]);

    expect(await all()).toEqual([]);
    const { rows } = await pageOf(ORG_A);
    expect(
      rows
        .map(({ kind, reason, ip, actor, count }) => ({ kind, reason, ip, actor, count }))
        .toSorted((a, b) => (a.reason < b.reason ? -1 : 1)),
    ).toEqual([
      { kind: 'rate_limited', reason: 'per_agent', ip: '203.0.113.7', actor: { type: 'agent', id: AGENT }, count: 1 },
      {
        kind: 'rate_limited',
        reason: 'per_organisation',
        ip: '203.0.113.7',
        actor: { type: 'agent', id: AGENT },
        count: 1,
      },
      { kind: 'rate_limited', reason: 'per_user', ip: '203.0.113.7', actor: { type: 'user', id: PERSON }, count: 1 },
      {
        kind: 'sign_in_failed',
        reason: 'step_up_challenge_missing',
        ip: '203.0.113.7',
        actor: { type: 'user', id: PERSON },
        count: 1,
      },
    ]);
  });

  it("shows organisation A its own events alone: never B's, never those tied to no one", async () => {
    await emptyOrgs();
    await at(START.getTime()).record(app, [limited('per_user', { userId: PERSON, orgId: ORG_A })]);
    await at(START.getTime()).record(app, [limited('per_agent', { agentId: AGENT, orgId: ORG_B })]);
    await at(START.getTime()).record(app, [limited('per_address')]);

    expect((await pageOf(ORG_A)).rows.map(({ reason }) => reason)).toEqual(['per_user']);
    expect((await pageOf(ORG_B)).rows.map(({ reason }) => reason)).toEqual(['per_agent']);
    // B's own ID asked inside A's transaction: the wall is the database's, not the query's.
    expect((await withTenant(app, ORG_A, (tx) => orgSecurityEventsPage(tx, ORG_B, RANGE, checked()))).rows).toEqual([]);
  });

  it('reaches no row with no organisation set, and refuses a row written for another or a change', async () => {
    await emptyOrgs();
    await at(START.getTime()).record(app, [limited('per_user', { userId: PERSON, orgId: ORG_A })]);

    expect(await app.selectFrom('security.org_events').selectAll().execute()).toEqual([]);
    await expect(
      withTenant(app, ORG_A, (tx) =>
        tx
          .insertInto('security.org_events')
          .values({
            org_id: ORG_B,
            id: ids.next(),
            kind: 'rate_limited',
            reason: 'per_user',
            ip: null,
            user_id: null,
            agent_id: null,
            window_start: START,
            count: 1,
            created_at: START,
          })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      withTenant(app, ORG_A, (tx) => tx.updateTable('security.org_events').set({ count: 1000 }).execute()),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('refuses a batch of two organisations, an agent with none, a person beside an agent, or a partner’s message', async () => {
    await emptyOrgs();
    const writer = at(START.getTime());
    for (const batch of [
      [limited('per_user', { orgId: ORG_A }), limited('per_user', { orgId: ORG_B })],
      [limited('per_user', { orgId: ORG_A }), limited('per_address')],
      [limited('per_agent', { agentId: AGENT })],
      [limited('per_agent', { userId: PERSON, agentId: AGENT, orgId: ORG_A })],
      [event({ kind: 'partner_event_refused', reason: 'signature', orgId: ORG_A })],
      [limited('per_user', { orgId: 'acme' })],
      [limited('per_agent', { agentId: 'agent-1', orgId: ORG_A })],
    ]) {
      await expect(writer.record(app, batch)).rejects.toThrow(RangeError);
    }
    expect((await pageOf(ORG_A)).rows).toEqual([]);
    expect(await all()).toEqual([]);
  });

  it('pages newest first by minute, of one kind when named, from where the last page ended', async () => {
    await emptyOrgs();
    const minute = (n: number) => new Date(START.getTime() - n * 60_000);
    await at(START.getTime()).record(app, [
      limited('per_user', { userId: PERSON, orgId: ORG_A, windowStart: minute(1) }),
      limited('per_agent', { agentId: AGENT, orgId: ORG_A, windowStart: minute(2) }),
      event({ reason: 'step_up_code_rejected', userId: PERSON, orgId: ORG_A, windowStart: minute(3) }),
    ]);

    const first = await pageOf(ORG_A, { limit: 2 });
    expect(first.rows.map(({ reason }) => reason)).toEqual(['per_user', 'per_agent']);
    expect(first.next).toEqual({ at: minute(2), id: first.rows[1]?.id });
    const second = await pageOf(ORG_A, { limit: 2, before: first.next ?? undefined });
    expect(second.rows.map(({ reason }) => reason)).toEqual(['step_up_code_rejected']);
    expect(second.next).toBeNull();
    expect((await pageOf(ORG_A, { kind: 'sign_in_failed' })).rows.map(({ reason }) => reason)).toEqual([
      'step_up_code_rejected',
    ]);
    expect((await pageOf(ORG_A, { from: minute(2), to: minute(1) })).rows.map(({ reason }) => reason)).toEqual([
      'per_agent',
    ]);
  });

  it(`keeps an organisation's own events at least ${String(LEAST_RETENTION_DAYS)} whole days`, async () => {
    await emptyOrgs();
    await at(START.getTime()).record(app, [limited('per_user', { userId: PERSON, orgId: ORG_A })]);
    const wide = { from: new Date(0), to: new Date(START.getTime() + 20_000 * DAY_MS) };

    // No sweep can be made to keep them less: the floor is refused before any organisation's sweep.
    for (const days of [LEAST_RETENTION_DAYS - 1, 0, -1, 30.5, Number.NaN]) {
      expect(() => at(START.getTime(), days)).toThrow(RangeError);
    }
    // At the floor, a millisecond short of it keeps them; at it, they go.
    const floor = (ms: number) => at(ms, LEAST_RETENTION_DAYS).sweepOrganisation(app, ORG_A, 10);
    expect(await floor(START.getTime() + LEAST_RETENTION_DAYS * DAY_MS - 1)).toBe(0);
    expect((await pageOf(ORG_A, wide)).rows).toHaveLength(1);
    expect(await floor(START.getTime() + LEAST_RETENTION_DAYS * DAY_MS)).toBe(1);
  });

  it("sweeps one organisation's own events past their retention, and none of another's", async () => {
    await emptyOrgs();
    await at(START.getTime()).record(app, [limited('per_user', { userId: PERSON, orgId: ORG_A })]);
    await at(START.getTime()).record(app, [limited('per_user', { userId: PERSON, orgId: ORG_B })]);
    const wide = { from: new Date(0), to: new Date(START.getTime() + 20_000 * DAY_MS) };

    // A millisecond short of its retention: kept.
    expect(await at(START.getTime() + RETENTION * DAY_MS - 1).sweepOrganisation(app, ORG_A, 10)).toBe(0);
    expect(await at(START.getTime() + RETENTION * DAY_MS).sweepOrganisation(app, ORG_A, 10)).toBe(1);
    expect((await pageOf(ORG_A, wide)).rows).toEqual([]);
    expect((await pageOf(ORG_B, wide)).rows).toHaveLength(1);
    await expect(at(START.getTime()).sweepOrganisation(app, ORG_A, 0)).rejects.toThrow(RangeError);
  });
});
