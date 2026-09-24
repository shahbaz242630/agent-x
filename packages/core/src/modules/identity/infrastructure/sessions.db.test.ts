// B2-1: the console's sessions (0010), on the real migrated schema, as the app
// role: opened, used within both timeouts, rotated keeping their record
// (SEC-HA-07, the store half), and ended.
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase, within } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { type SignInEvidence, SignInRefused } from '../domain/sign-in.ts';
import { createSessions, LONGEST_IDLE_SECONDS, type Sessions } from './sessions.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const IDLE = 30 * 60;
const ABSOLUTE = 12 * 60 * 60;
const SECOND = 1000;
const START = new Date('2026-09-24T09:00:00Z');

const ids = new SequentialIds(0x200);
const evidence: SignInEvidence = {
  idpSessionId: 'V1_338719472394810051',
  authTime: new Date('2026-09-24T08:59:30Z'),
  amr: ['pwd', 'otp', 'mfa'],
};

let subjects = 0;
/** A user no other test has, and sessions on a clock of the test's own. */
async function setUp(): Promise<{ userId: string; clock: FixedClock; sessions: Sessions }> {
  subjects += 1;
  const clock = new FixedClock(START);
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `sessions-${String(subjects)}` },
    { ids, clock },
  );
  return {
    userId,
    clock,
    sessions: createSessions({ ids, clock, timeouts: { idleSeconds: IDLE, absoluteSeconds: ABSOLUTE } }),
  };
}

const rowOf = (sessionId: string) =>
  app.selectFrom('identity.sessions').selectAll().where('id', '=', sessionId).executeTakeFirst();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>(
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

describe(`the console's sessions (Postgres ${server.version})`, () => {
  it("opens a session holding the sign-in's evidence, and finds it by its cookie ID", async () => {
    const { userId, sessions } = await setUp();
    const { sessionId, cookie } = await sessions.open(app, userId, evidence);

    expect(cookie).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await sessions.use(app, cookie)).toEqual({
      sessionId,
      userId,
      ...evidence,
      createdAt: START,
      lastSeenAt: START,
      endsAt: new Date(START.getTime() + ABSOLUTE * SECOND),
      idleEndsAt: new Date(START.getTime() + IDLE * SECOND),
    });
  });

  it('says when a session ends if unused: its idle timeout from this use, never past its absolute end (B2-4b)', async () => {
    const { userId, clock, sessions } = await setUp();
    const { sessionId, cookie } = await sessions.open(app, userId, evidence);
    const end = START.getTime() + ABSOLUTE * SECOND;

    clock.advanceBy((IDLE - 1) * SECOND);
    expect(await sessions.use(app, cookie)).toMatchObject({
      idleEndsAt: new Date(clock.now().getTime() + IDLE * SECOND),
    });
    // In use until moments before its absolute end: its idle end would come later, so it is the absolute end.
    await app
      .updateTable('identity.sessions')
      .set({ last_seen_at: new Date(end - 10 * SECOND) })
      .where('id', '=', sessionId)
      .execute();
    const late = createSessions({
      ids,
      clock: new FixedClock(new Date(end - SECOND)),
      timeouts: { idleSeconds: IDLE, absoluteSeconds: ABSOLUTE },
    });
    expect(await late.use(app, cookie)).toMatchObject({ idleEndsAt: new Date(end) });
  });

  it('keeps only the hash of the cookie ID, never the cookie ID', async () => {
    const { userId, sessions } = await setUp();
    const { sessionId, cookie } = await sessions.open(app, userId, evidence);

    const row = await rowOf(sessionId);
    expect(row?.cookie_hash).toHaveLength(32);
    expect(JSON.stringify(row)).not.toContain(cookie);
    expect(row?.cookie_hash.toString('base64url')).not.toBe(cookie);
  });

  it('gives every session its own cookie ID', async () => {
    const { userId, sessions } = await setUp();
    const opened = await Promise.all(Array.from({ length: 5 }, () => sessions.open(app, userId, evidence)));

    expect(new Set(opened.map((one) => one.cookie)).size).toBe(5);
    expect(new Set(opened.map((one) => one.sessionId)).size).toBe(5);
  });

  it('keeps a session without the login service session ID', async () => {
    const { userId, sessions } = await setUp();
    const { cookie } = await sessions.open(app, userId, { ...evidence, idpSessionId: undefined });

    expect(await sessions.use(app, cookie)).toMatchObject({ idpSessionId: undefined });
  });

  it('finds nothing for a cookie ID it never gave, or text that is none', async () => {
    const { userId, sessions } = await setUp();
    await sessions.open(app, userId, evidence);

    for (const cookie of [
      'A'.repeat(43),
      '',
      'A'.repeat(42),
      'A'.repeat(44),
      `${'A'.repeat(42)}=`,
      `${'A'.repeat(42)}+`,
    ]) {
      expect(await sessions.use(app, cookie)).toBeUndefined();
    }
    expect(await sessions.use(app, undefined as unknown as string)).toBeUndefined();
  });

  describe('the idle timeout', () => {
    it('keeps a session used within it, each use moving it on', async () => {
      const { userId, clock, sessions } = await setUp();
      const { cookie } = await sessions.open(app, userId, evidence);

      for (let use = 1; use <= 4; use += 1) {
        clock.advanceBy((IDLE - 1) * SECOND);
        expect(await sessions.use(app, cookie)).toMatchObject({ lastSeenAt: clock.now() });
      }
    });

    it('ends a session left unused for it, and for good', async () => {
      const { userId, clock, sessions } = await setUp();
      const { cookie } = await sessions.open(app, userId, evidence);

      clock.advanceBy(IDLE * SECOND);
      expect(await sessions.use(app, cookie)).toBeUndefined();
      // A use refused leaves its last use where it was, so it stays ended.
      expect(await sessions.use(app, cookie)).toBeUndefined();
    });

    it('never moves the last use backwards', async () => {
      const { userId, clock, sessions } = await setUp();
      const { cookie } = await sessions.open(app, userId, evidence);
      clock.advanceBy(10 * SECOND);
      await sessions.use(app, cookie);

      const behind = createSessions({
        ids,
        clock: new FixedClock(new Date(START.getTime() + 5 * SECOND)),
        timeouts: { idleSeconds: IDLE, absoluteSeconds: ABSOLUTE },
      });
      expect(await behind.use(app, cookie)).toMatchObject({ lastSeenAt: clock.now() });
    });
  });

  describe('the absolute timeout', () => {
    it('ends a session at it, however much it is used', async () => {
      const { userId, clock, sessions } = await setUp();
      const { cookie } = await sessions.open(app, userId, evidence);

      const uses = ABSOLUTE / (IDLE / 2);
      for (let use = 1; use < uses; use += 1) {
        clock.advanceBy((IDLE / 2) * SECOND);
        expect(await sessions.use(app, cookie)).toBeDefined();
      }
      clock.advanceBy((IDLE / 2 - 1) * SECOND);
      expect(await sessions.use(app, cookie)).toBeDefined();
      clock.advanceBy(SECOND);
      expect(await sessions.use(app, cookie)).toBeUndefined();
    });
  });

  describe('rotating the cookie ID (SEC-HA-07)', () => {
    it('gives a new cookie ID and keeps the record, its evidence and its ends', async () => {
      const { userId, clock, sessions } = await setUp();
      const { sessionId, cookie } = await sessions.open(app, userId, evidence);
      clock.advanceBy(60 * SECOND);

      const rotated = await sessions.rotate(app, sessionId);

      expect(rotated).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(rotated).not.toBe(cookie);
      expect(await sessions.use(app, cookie)).toBeUndefined();
      expect(await sessions.use(app, rotated ?? '')).toMatchObject({
        sessionId,
        userId,
        ...evidence,
        createdAt: START,
        endsAt: new Date(START.getTime() + ABSOLUTE * SECOND),
      });
    });

    it('refuses a session that is no longer live, and one that never was', async () => {
      const { userId, clock, sessions } = await setUp();
      const { sessionId, cookie } = await sessions.open(app, userId, evidence);
      clock.advanceBy(IDLE * SECOND);

      expect(await sessions.rotate(app, sessionId)).toBeUndefined();
      expect(await sessions.rotate(app, ids.next())).toBeUndefined();
      expect(await sessions.rotate(app, 'not-an-id')).toBeUndefined();
      // Its cookie ID was left as it was, not rotated to one no one holds: seen from its start, it still finds it.
      const atStart = createSessions({
        ids,
        clock: new FixedClock(START),
        timeouts: { idleSeconds: IDLE, absoluteSeconds: ABSOLUTE },
      });
      expect(await atStart.use(app, cookie)).toMatchObject({ sessionId });
    });
  });

  describe('ending a session', () => {
    it('ends the one its cookie ID belongs to, and no other of the same person', async () => {
      const { userId, sessions } = await setUp();
      const ended = await sessions.open(app, userId, evidence);
      const kept = await sessions.open(app, userId, evidence);

      expect(await sessions.end(app, ended.cookie)).toBe(true);
      expect(await sessions.use(app, ended.cookie)).toBeUndefined();
      expect(await rowOf(ended.sessionId)).toBeUndefined();
      expect(await sessions.use(app, kept.cookie)).toMatchObject({ sessionId: kept.sessionId });
    });

    it('ends one past its timeouts too, and says when there was none', async () => {
      const { userId, clock, sessions } = await setUp();
      const { sessionId, cookie } = await sessions.open(app, userId, evidence);
      clock.advanceBy(ABSOLUTE * SECOND);

      expect(await sessions.end(app, cookie)).toBe(true);
      expect(await rowOf(sessionId)).toBeUndefined();
      expect(await sessions.end(app, cookie)).toBe(false);
      expect(await sessions.end(app, 'not a cookie')).toBe(false);
      expect(await sessions.end(app, undefined as unknown as string)).toBe(false);
    });
  });

  it("refuses evidence it couldn't store, storing nothing", async () => {
    const { userId, sessions } = await setUp();

    await expect(sessions.open(app, userId, { ...evidence, amr: [] })).rejects.toBeInstanceOf(SignInRefused);
    expect(await app.selectFrom('identity.sessions').select('id').where('user_id', '=', userId).execute()).toEqual([]);
  });

  it('refuses a session past its absolute end a new cookie ID, however recently used', async () => {
    const { userId, clock, sessions } = await setUp();
    const { sessionId, cookie } = await sessions.open(app, userId, evidence);
    for (let used = 0; used < ABSOLUTE; used += IDLE / 2) {
      clock.advanceBy((IDLE / 2) * SECOND);
      await sessions.use(app, cookie);
    }

    expect(await sessions.rotate(app, sessionId)).toBeUndefined();
  });

  it("holds a row the module didn't write to the table's own limits", async () => {
    const { userId } = await setUp();
    const row = {
      user_id: userId,
      cookie_hash: Buffer.alloc(32, 7),
      idp_session_id: null as string | null,
      auth_time: START,
      amr: ['pwd', 'mfa'],
      created_at: START,
      last_seen_at: START,
      ends_at: new Date(START.getTime() + SECOND),
    };
    const insert = (change: Partial<typeof row>) =>
      app
        .insertInto('identity.sessions')
        .values({ ...row, id: ids.next(), ...change })
        .execute();

    await insert({});
    await expect(insert({ cookie_hash: Buffer.alloc(32, 8), ends_at: START })).rejects.toMatchObject({
      constraint: 'ends_after_it_begins',
    });
    await expect(insert({})).rejects.toMatchObject({ code: '23505', constraint: 'one_session_per_cookie' });
    for (const change of [
      { cookie_hash: Buffer.alloc(31, 9) },
      { cookie_hash: Buffer.alloc(33, 9) },
      { amr: [] },
      { amr: Array.from({ length: 17 }, () => 'otp') },
      { idp_session_id: '' },
    ]) {
      await expect(insert({ cookie_hash: Buffer.alloc(32, 10), ...change })).rejects.toMatchObject({ code: '23514' });
    }
  });

  it('refuses a session for someone who is not a user', async () => {
    const { sessions } = await setUp();

    await expect(sessions.open(app, ids.next(), evidence)).rejects.toMatchObject({
      code: '23503',
      constraint: 'sessions_user_id_fkey',
    });
  });

  it('never lets the app move a session to another person, or change what it proved or when it ends', async () => {
    const { userId, sessions } = await setUp();
    const other = (await setUp()).userId;
    const { sessionId } = await sessions.open(app, userId, evidence);

    for (const change of [
      { user_id: other },
      { auth_time: new Date('2026-09-24T09:10:00Z') },
      { amr: ['pwd'] },
      { idp_session_id: 'V1_other' },
      { created_at: new Date('2026-09-24T08:00:00Z') },
      { ends_at: new Date('2027-01-01T00:00:00Z') },
      { id: ids.next() },
    ]) {
      await expect(
        app.updateTable('identity.sessions').set(change).where('id', '=', sessionId).execute(),
      ).rejects.toMatchObject({ code: '42501' });
    }
    expect(await rowOf(sessionId)).toMatchObject({ user_id: userId, amr: evidence.amr });
  });
});

describe(`the sessions' sweep (B2-4a, Postgres ${server.version})`, () => {
  /** Later than every other test's sessions, so a first sweep takes theirs and each count below is this test's own. */
  const LATER = START.getTime() + 30 * 86_400_000;
  const at = (ms: number) =>
    createSessions({
      ids,
      clock: new FixedClock(new Date(ms)),
      timeouts: { idleSeconds: IDLE, absoluteSeconds: ABSOLUTE },
    });
  /** Sets a session's last use, as a use at that moment would have. */
  const lastUsed = (sessionId: string, when: number) =>
    app
      .updateTable('identity.sessions')
      .set({ last_seen_at: new Date(when) })
      .where('id', '=', sessionId)
      .execute();

  it('deletes only sessions no setting could make live again: past their end, or unused past the longest idle timeout', async () => {
    const { userId } = await setUp();
    const now = LATER;
    await at(now).sweep(app, 1_000_000);
    const open = (openedAt: number, usedAt: number) =>
      at(openedAt)
        .open(app, userId, evidence)
        .then(async (opened) => {
          await lastUsed(opened.sessionId, usedAt);
          return opened;
        });
    const LONGEST = LONGEST_IDLE_SECONDS * SECOND;
    const cases = {
      idleLongestJustNow: await open(now - LONGEST, now - LONGEST),
      idleLongestNotYet: await open(now - LONGEST + SECOND, now - LONGEST + SECOND),
      // Past this process's own idle timeout only: refused, but another setting could still take it.
      idleOwnOnly: await open(now - IDLE * SECOND, now - IDLE * SECOND),
      endsJustNow: await open(now - ABSOLUTE * SECOND, now - SECOND),
      endsNotYet: await open(now - ABSOLUTE * SECOND + SECOND, now - SECOND),
    };

    expect(await at(now).sweep(app, 100)).toBe(2);

    const left = await app.selectFrom('identity.sessions').select('id').where('user_id', '=', userId).execute();
    expect(left.map((row) => row.id).sort()).toEqual(
      [cases.idleLongestNotYet.sessionId, cases.idleOwnOnly.sessionId, cases.endsNotYet.sessionId].sort(),
    );
    // Nothing deleted was still usable; of what was kept, only the one inside every timeout is.
    const usable = await Promise.all(
      Object.entries(cases).map(async ([name, { cookie }]) => [name, (await at(now).use(app, cookie)) !== undefined]),
    );
    expect(Object.fromEntries(usable)).toEqual({
      idleLongestJustNow: false,
      idleLongestNotYet: false,
      idleOwnOnly: false,
      endsJustNow: false,
      endsNotYet: true,
    });
  });

  it('refuses an idle timeout longer than the longest the sweep allows for', () => {
    const make = (idleSeconds: number) =>
      createSessions({ ids, clock: new FixedClock(START), timeouts: { idleSeconds, absoluteSeconds: 24 * 60 * 60 } });
    expect(() => make(LONGEST_IDLE_SECONDS)).not.toThrow();
    expect(() => make(LONGEST_IDLE_SECONDS + 1)).toThrow(RangeError);
  });

  it('deletes a batch at a time, and nothing once none is left', async () => {
    const { userId } = await setUp();
    const now = LATER + 86_400_000;
    await at(now).sweep(app, 1_000_000);
    for (let one = 0; one < 3; one += 1) await at(now - ABSOLUTE * SECOND).open(app, userId, evidence);

    expect(await at(now).sweep(app, 2)).toBe(2);
    expect(await at(now).sweep(app, 2)).toBe(1);
    expect(await at(now).sweep(app, 2)).toBe(0);
  });

  it('leaves a session used while the sweep waited for it: it is live again', async () => {
    const { userId } = await setUp();
    const now = LATER + 2 * 86_400_000;
    await at(now).sweep(app, 1_000_000);
    const { sessionId } = await at(now - LONGEST_IDLE_SECONDS * SECOND).open(app, userId, evidence);
    // A request's use, held open until the sweep has found the session and waits on its lock.
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('select id from identity.sessions where id = $1 for update', [sessionId]);
    try {
      const sweeping = within(15_000, at(now).sweep(app, 100), 'the sweep');
      await vi.waitFor(
        async () => {
          const waiting = await database
            .as('admin')
            .query<{ count: string }>(
              `select count(*) from pg_catalog.pg_stat_activity where datname = pg_catalog.current_database() and wait_event_type = 'Lock' and query like 'delete from "identity"."sessions"%'`,
            );
          expect(waiting).toEqual([{ count: '1' }]);
        },
        { timeout: 10_000 },
      );
      await holder.query('update identity.sessions set last_seen_at = $2 where id = $1', [sessionId, new Date(now)]);
      await holder.query('commit');

      expect(await sweeping).toBe(0);
      expect(await rowOf(sessionId)).toMatchObject({ last_seen_at: new Date(now) });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('gives up after 10 seconds, a wait for a lock included, rather than hang', async () => {
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table identity.sessions in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, at(LATER).sweep(app, 100), 'the sweep')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('refuses a sweep of no sessions', async () => {
    const { sessions } = await setUp();

    for (const most of [0, -1, 1.5, Number.NaN]) {
      await expect(sessions.sweep(app, most)).rejects.toThrow(RangeError);
    }
  });
});
