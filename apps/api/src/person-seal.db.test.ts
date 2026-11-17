// 6E1a (CO8, PL-48; decision 26's L8): the person log's daily seal, its
// check, and a person's own page and download, on the real migrated schema as
// the app role. The person log is one global table, so each test has a
// database of its own (cloned from the migrated template).
//
// The seal: the digest is the one computed here by hand; each closed day
// sealed from the first row's, quiet days too, at most 31 a run; nothing
// sealed twice, by a second run or by a server that sealed the day meanwhile
// (its lock forced, ADR-006 §6); a day that moved while it was digested, by a
// row added or replaced, left for the next run; a newest seal tampered with
// raises the alarm and nothing past it is sealed (and the page and the
// download are refused). The check: an IP blanked after (a lawful erasure)
// holds; a row changed, deleted, slipped in correctly dated or misdated, a
// seal missing, or a row before the first seal raises the alarm. No hold
// anywhere (D3). A person's page and file hold their rows alone; their
// downloads are counted per person, under their lock (forced); a retry with
// their key records nothing again; and their key is theirs alone.
import { createHash } from 'node:crypto';

import { type ActivityTables, PERSON_SEALED, v7Floor } from '@agentx/core/modules/activity';
import { PERSON_LOG_EXPORTED } from '@agentx/core/modules/evidence';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import {
  createDatabase,
  type Database,
  type DatabaseTransaction,
  holdTransactionLock,
  type IdempotentRequest,
} from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createMyActivity,
  MY_ACTIVITY_EXPORT_OPERATION,
  MY_ACTIVITY_EXPORTS_LOCK,
  type MyExportWrite,
  PERSON_KEYS_TENANT,
} from './my-activity.ts';
import { createPersonSealCheck } from './person-seal-check.ts';
import { createPersonSeal, PERSON_SEAL_LOCK } from './person-seal.ts';

type Tables = ActivityTables & PlatformControlsTables;

const server = inject('postgres');
const mounted = writeTestKeys(['audit-mac', 'request-hash', 'operator-signing']);
const keys = loadKeys({ directory: mounted.directory, current: {} }, ['audit-mac', 'request-hash', 'operator-signing']);
let database: TestDatabase;
let app: Database<Tables>;
let capture: LogCapture;

const ids = new SequentialIds(0xe1a0_0000_0000);
const ANA = '0199a0f0-0000-7000-8000-00000000a0a0';
const BEN = '0199a0f0-0000-7000-8000-00000000b0b0';
const CORRELATION = '0199a0f0-0000-7000-8000-0000000e1a00';
const API = { type: 'system', id: 'api' } as const;

let made = 0;
/** A UUIDv7 of the instant `at`, as a row written then has. */
const idAt = (at: string) => {
  made += 1;
  return `${v7Floor(Date.parse(at)).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
};

/** A request of `userId`'s written at `at` (its time `recordedAt`, `at` but for one written past the app). */
async function written(userId: string, at: string, recordedAt = at): Promise<string> {
  const id = idAt(at);
  await app
    .insertInto('access.person_requests')
    .values({
      id,
      recorded_at: new Date(recordedAt),
      user_id: userId,
      claimed_org: null,
      method: 'GET',
      route: '/v1/auth/session',
      path_ids: [],
      status: 200,
      reason: null,
      correlation_id: CORRELATION,
      duration_ms: 3,
      ip: '203.0.113.7',
      country: 'AE',
      city: 'Dubai',
      time_zone: 'Asia/Dubai',
      time_zone_from: 'browser',
    })
    .execute();
  return id;
}

/** The person log's seals, oldest first, each its details. */
const seals = async (): Promise<Record<string, unknown>[]> =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select('details')
      .where('action', '=', PERSON_SEALED)
      .orderBy('seq')
      .execute()
  ).map((row) => JSON.parse(row.details) as Record<string, unknown>);

const days = async () => (await seals()).map((seal) => seal.day);

const sealAt = (clock: FixedClock) =>
  createPersonSeal({ database: app, keys, ids, clock, logger: testLogger(capture), batch: 2 });

/** The check, its older seals read before `pick`'s seq (none before 1). */
const check = (pick: (below: bigint) => bigint = () => 1n) =>
  createPersonSealCheck({ database: app, keys, ids, logger: testLogger(capture), batch: 2, pick });

const alarms = () =>
  capture.lines().filter((line) => line.event === 'audit.integrity_failed' && line.check === 'person_log');

const admin = () => database.as('admin');

/** A seal's details rewritten past the app: its MAC no longer holds. */
const tamperSealOf = (day: string) =>
  admin().query(
    "update platform_controls.audit_events set details = replace(details, $2, '2099-01-01') where action = $1 and details like '%' || $2 || '%'",
    [PERSON_SEALED, day],
  );

/** Holds `lock` in a transaction of the app's, doing `meanwhile` first, until `open` is called. */
function holding(
  lock: readonly [string, ...string[]],
  meanwhile: (tx: DatabaseTransaction<Tables>) => Promise<void> = () => Promise.resolve(),
) {
  const { promise: held, resolve: heldNow } = Promise.withResolvers<undefined>();
  const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
  const done = app.transaction().execute(async (tx) => {
    await holdTransactionLock(tx, ...lock);
    await meanwhile(tx);
    heldNow(undefined);
    await gate;
  });
  return {
    held,
    open: () => {
      open(undefined);
    },
    done,
  };
}

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
  capture = new LogCapture();
});

afterEach(async () => {
  await app.destroy();
  await database.drop();
});

afterAll(() => {
  mounted.remove();
});

describe('the person log’s daily seal (6E1a)', () => {
  it('seals each closed day from the first row’s, quiet days too, its digest the one computed by hand', async () => {
    const anaFirst = await written(ANA, '2026-11-10T09:00:00.000Z');
    const benFirst = await written(BEN, '2026-11-10T10:00:00.000Z');
    await written(ANA, '2026-11-12T09:00:00.000Z');

    await sealAt(new FixedClock(new Date('2026-11-13T00:20:00.000Z'))).run();

    const line = (id: string, user: string, at: string) =>
      `${JSON.stringify([id, at, user, null, 'GET', '/v1/auth/session', [], 200, null, CORRELATION, 3])}\n`;
    const byHand = createHash('sha256')
      .update(line(anaFirst, ANA, '2026-11-10T09:00:00.000000Z'))
      .update(line(benFirst, BEN, '2026-11-10T10:00:00.000000Z'))
      .digest('hex');
    const found = await seals();
    expect(found.map((seal) => seal.day)).toEqual(['2026-11-10', '2026-11-11', '2026-11-12']);
    expect(found[0]).toEqual({
      day: '2026-11-10',
      requests: 2,
      digest: byHand,
      idFrom: anaFirst,
      idTo: benFirst,
      form: 1,
    });
    expect(found[1]).toMatchObject({ requests: 0, idFrom: null, idTo: null });
    expect(alarms()).toEqual([]);
  });

  it('seals at most 31 days a run, the rest over the next runs, none twice', async () => {
    await written(ANA, '2026-08-01T09:00:00.000Z');
    const clock = new FixedClock(new Date('2026-10-20T12:00:00.000Z'));

    await sealAt(clock).run();
    expect(await seals()).toHaveLength(31);
    await sealAt(clock).run();
    await sealAt(clock).run();

    const sealed = await days();
    expect(sealed[0]).toBe('2026-08-01');
    expect(sealed.at(-1)).toBe('2026-10-19');
    expect(new Set(sealed).size).toBe(sealed.length);
  });

  it('FX-RACE a day sealed by another server meanwhile: the run waits on the seal lock, then seals it no second time', async () => {
    await written(ANA, '2026-11-12T09:00:00.000Z');
    const other = holding([PERSON_SEAL_LOCK], async (tx) => {
      await createPlatformChain({ keys, ids }).record(tx, {
        actor: API,
        action: PERSON_SEALED,
        details: { day: '2026-11-12', requests: 1, digest: 'x', idFrom: null, idTo: null, form: 1 },
      });
    });
    await other.held;
    const run = within(20_000, sealAt(new FixedClock(new Date('2026-11-13T00:20:00.000Z'))).run(), 'the run');
    await waitUntilQueued(admin(), 1);
    other.open();

    await other.done;
    await run;
    expect(await days()).toEqual(['2026-11-12']);
    expect(capture.lines().filter((line) => line.event === 'person_log_seal.moved')).toEqual([]);
    expect(capture.lines().filter((line) => line.event === 'person_log_seal.failed')).toEqual([]);
  });

  it('FX-RACE a day that moved while it was digested: left unsealed, and the run stops there, no day skipped', async () => {
    await written(ANA, '2026-11-11T09:00:00.000Z');
    const clock = new FixedClock(new Date('2026-11-13T00:20:00.000Z'));
    const other = holding([PERSON_SEAL_LOCK]);
    await other.held;
    const run = within(20_000, sealAt(clock).run(), 'the run');
    await waitUntilQueued(admin(), 1);
    await written(BEN, '2026-11-11T10:00:00.000Z');
    other.open();

    await other.done;
    await run;
    expect(await seals()).toEqual([]);
    expect(capture.lines().filter((line) => line.event === 'person_log_seal.moved')).toEqual([
      expect.objectContaining({ level: 'error', day: '2026-11-11', digested: 1, counted: 2 }),
    ]);
    await sealAt(clock).run();
    expect((await seals()).map((seal) => [seal.day, seal.requests])).toEqual([
      ['2026-11-11', 2],
      ['2026-11-12', 0],
    ]);
  });

  it('FX-RACE a row replaced in the day while it was digested, the count the same: its last ID shows it moved', async () => {
    await written(ANA, '2026-11-12T09:00:00.000Z');
    const other = holding([PERSON_SEAL_LOCK]);
    await other.held;
    const run = within(20_000, sealAt(new FixedClock(new Date('2026-11-13T00:20:00.000Z'))).run(), 'the run');
    await waitUntilQueued(admin(), 1);
    // Past the app: its one row deleted and another written later the same day.
    await admin().query('delete from access.person_requests');
    await written(ANA, '2026-11-12T10:00:00.000Z');
    other.open();

    await other.done;
    await run;
    expect(await seals()).toEqual([]);
    expect(capture.lines().filter((line) => line.event === 'person_log_seal.moved')).toEqual([
      expect.objectContaining({ day: '2026-11-12', digested: 1, counted: 1 }),
    ]);
  });

  it('seals nothing past a newest seal tampered with, raising the alarm; the page and the download are refused', async () => {
    await written(ANA, '2026-11-11T09:00:00.000Z');
    await sealAt(new FixedClock(new Date('2026-11-12T00:20:00.000Z'))).run();
    await tamperSealOf('2026-11-11');

    await sealAt(new FixedClock(new Date('2026-11-14T00:20:00.000Z'))).run();

    expect(await seals()).toHaveLength(1);
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'unsealed', subjectType: 'person_log' })]);
    const activity = createMyActivity({
      database: app,
      keys,
      ids,
      clock: new FixedClock(new Date()),
      logger: testLogger(capture),
    });
    const range = { from: new Date('2026-11-01T00:00:00.000Z'), to: new Date('2026-11-16T00:00:00.000Z') };
    expect(await activity.page(ANA, { ...range, before: undefined, limit: 10 }, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    expect(await activity.export(ANA, keyed(ANA, 'tampered'), { ...range, format: 'ndjson' }, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });

  it('never seals a day holding a row written past the app (misdated), raising the alarm, holding no one', async () => {
    // A fresh ID of the 12th given a time days before: a row slipped in to pass as an older one.
    await written(BEN, '2026-11-12T09:00:00.000Z', '2026-11-08T09:00:00.000Z');

    await sealAt(new FixedClock(new Date('2026-11-13T00:20:00.000Z'))).run();

    expect(await seals()).toEqual([]);
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'misdated', day: '2026-11-12' })]);
  });
});

describe('the person log’s seals checked (6E1a)', () => {
  /** Days 10 to 12 sealed, a row of Ana's on the 10th and the 12th. */
  const sealed = async () => {
    await written(ANA, '2026-11-10T09:00:00.000Z');
    await written(ANA, '2026-11-12T09:00:00.000Z');
    await sealAt(new FixedClock(new Date('2026-11-13T00:20:00.000Z'))).run();
    expect(await days()).toEqual(['2026-11-10', '2026-11-11', '2026-11-12']);
  };

  it('holds once a row’s IP and place are blanked, as a lawful erasure would', async () => {
    await sealed();
    await admin().query('update access.person_requests set ip = null, country = null, city = null');

    // As the job runs it: its own batch, and its older seals from a point picked at random.
    await createPersonSealCheck({ database: app, keys, ids, logger: testLogger(capture) }).run();

    expect(alarms()).toEqual([]);
  });

  it.each([
    [
      'a row changed',
      () => admin().query("update access.person_requests set status = 500 where recorded_at = '2026-11-12T09:00:00Z'"),
    ],
    [
      'a row deleted',
      () => admin().query("delete from access.person_requests where recorded_at = '2026-11-12T09:00:00Z'"),
    ],
  ])('raises the alarm for %s in a sealed day, holding no one', async (_what, tamper) => {
    await sealed();
    await tamper();

    await check().run();

    expect(alarms()).toEqual([
      expect.objectContaining({ reason: 'digest', day: '2026-11-12', subjectType: 'person_log' }),
    ]);
  });

  it('checks an older seal past the newest two, read from the point picked', async () => {
    await sealed();
    await admin().query("update access.person_requests set status = 500 where recorded_at = '2026-11-10T09:00:00Z'");

    // The newest two are the 12th and the 11th: the 10th is read only among the older seals.
    await check((below) => below).run();

    expect(alarms()).toEqual([expect.objectContaining({ reason: 'digest', day: '2026-11-10' })]);
  });

  it('raises the alarm for a correctly dated row slipped into a sealed day', async () => {
    await sealed();
    await written(BEN, '2026-11-12T15:00:00.000Z');

    await check().run();

    expect(alarms()).toEqual([expect.objectContaining({ reason: 'digest', day: '2026-11-12' })]);
  });

  it('raises the alarm for a seal of another form, though its MAC and its day’s digest hold', async () => {
    await sealed();
    // The 13th, quiet, sealed through the app (its MAC holds) on a form this code doesn't read.
    await app.transaction().execute(async (tx) => {
      await createPlatformChain({ keys, ids }).record(tx, {
        actor: API,
        action: PERSON_SEALED,
        details: {
          day: '2026-11-13',
          requests: 0,
          digest: createHash('sha256').digest('hex'),
          idFrom: null,
          idTo: null,
          form: 2,
        },
      });
    });

    await check().run();

    expect(alarms()).toEqual([expect.objectContaining({ reason: 'digest', day: '2026-11-13' })]);
  });

  it('raises the alarm for a seal missing between two, and for a row written before the first seal', async () => {
    await sealed();
    await admin().query(
      "delete from platform_controls.audit_events where action = $1 and details like '%2026-11-11%'",
      [PERSON_SEALED],
    );
    await check().run();
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'gap', day: '2026-11-10' })]);

    capture = new LogCapture();
    await admin().query(
      "delete from platform_controls.audit_events where action = $1 and details like '%2026-11-10%'",
      [PERSON_SEALED],
    );
    await written(BEN, '2026-11-09T09:00:00.000Z');
    await check().run();
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'before', day: '2026-11-12' })]);
  });

  it('raises the alarm for a newest seal, or an older one, that can’t be believed', async () => {
    await sealed();
    await tamperSealOf('2026-11-12');
    await check().run();
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'unsealed' })]);

    capture = new LogCapture();
    await admin().query(
      "update platform_controls.audit_events set details = replace(details, '2099-01-01', '2026-11-12') where action = $1",
      [PERSON_SEALED],
    );
    await tamperSealOf('2026-11-10');
    // The older seals read from just before the newest: the 10th's among them.
    await check((below) => below).run();
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'unsealed' })]);
  });

  it('finds nothing to check, and raises nothing, before the first seal', async () => {
    await written(ANA, '2026-11-12T09:00:00.000Z');

    await check().run();

    expect(alarms()).toEqual([]);
    expect(capture.lines().filter((line) => line.level === 'error')).toEqual([]);
  });

  it('logs a run that fails, never throwing', async () => {
    const broken = createPersonSealCheck({
      // A database whose every transaction fails to open.
      database: {
        transaction: () => {
          throw new Error('the database is away');
        },
      } as unknown as Database<Tables>,
      keys,
      ids,
      logger: testLogger(capture),
    });

    await broken.run();

    expect(capture.lines().filter((line) => line.event === 'person_log_seal_check.failed')).toEqual([
      expect.objectContaining({ level: 'error' }),
    ]);
  });
});

/** A person's own idempotency key, as the route makes it. */
const keyed = (userId: string, key: string): IdempotentRequest => ({
  orgId: PERSON_KEYS_TENANT,
  client: { kind: 'user', id: userId },
  operation: MY_ACTIVITY_EXPORT_OPERATION,
  key,
  payload: JSON.stringify({ body: { format: 'ndjson' } }),
});

describe('a person’s own page and download (6E1a)', () => {
  const RANGE = { from: new Date('2026-11-01T00:00:00.000Z'), to: new Date('2026-11-16T00:00:00.000Z') };
  // Now, as the database's clock records the downloads: an hour back from it counts them.
  const activity = (mostRequests?: number) =>
    createMyActivity({
      database: app,
      keys,
      ids,
      clock: new FixedClock(new Date()),
      logger: testLogger(capture),
      ...(mostRequests === undefined ? {} : { mostRequests }),
    });
  const exportOf = (userId: string, key: string) =>
    activity().export(userId, keyed(userId, key), { ...RANGE, format: 'ndjson' }, CORRELATION);
  const idsIn = (written: MyExportWrite) => {
    if (written.outcome !== 'exported') throw new Error(`not exported: ${written.outcome}`);
    return written.file.content
      .split('\n')
      .filter((text) => text !== '')
      .map((text) => (JSON.parse(text) as { id: string }).id)
      .sort();
  };
  const recordsOf = async (userId: string) =>
    (
      await app
        .selectFrom('platform_controls.audit_events')
        .select('details')
        .where('action', '=', PERSON_LOG_EXPORTED)
        .execute()
    ).filter((row) => (JSON.parse(row.details) as { person: string }).person === userId).length;

  it('holds one person’s rows alone on their page and in their file, never another’s', async () => {
    const ana = [await written(ANA, '2026-11-10T09:00:00.000Z'), await written(ANA, '2026-11-11T09:00:00.000Z')];
    const ben = [await written(BEN, '2026-11-10T10:00:00.000Z'), await written(BEN, '2026-11-12T10:00:00.000Z')];

    const page = await activity().page(BEN, { ...RANGE, before: undefined, limit: 100 }, CORRELATION);
    if (page.outcome !== 'page') throw new Error('no page');
    expect(page.rows.map((row) => row.id).sort()).toEqual([...ben].sort());

    const file = idsIn(await exportOf(BEN, 'k-1'));
    expect(file).toEqual([...ben].sort());
    expect(file.filter((id) => ana.includes(id))).toEqual([]);
  });

  it('shows a row with no clues as none, and lists Agent X’s exports of the person’s log alone, newest first', async () => {
    const bare = idAt('2026-11-10T09:00:00.000Z');
    await app
      .insertInto('access.person_requests')
      .values({
        id: bare,
        recorded_at: new Date('2026-11-10T09:00:00.000Z'),
        user_id: ANA,
        claimed_org: BEN,
        method: 'POST',
        route: '/v1/invitations/accept',
        path_ids: [],
        status: 403,
        reason: 'INVITATION_INVALID',
        correlation_id: CORRELATION,
        duration_ms: 2,
        ip: null,
        country: null,
        city: null,
        time_zone: null,
        time_zone_from: null,
      })
      .execute();
    // Our exports for a case, as the operator's command records them, as its own role (PL-57).
    const operator = createDatabase<PlatformControlsTables>(
      { ...database.connection('operator'), maxConnections: 1 },
      testLogger(),
    );
    const exported = (person: string, caseRef: string) =>
      createPlatformChain({ keys, ids }).recordAlone(operator, {
        actor: { type: 'system', id: 'operator' },
        action: 'operator.person_log_exported',
        details: {
          person,
          exportId: ids.next(),
          caseRef,
          from: RANGE.from.toISOString(),
          to: RANGE.to.toISOString(),
          requests: 1,
        },
      });
    try {
      await exported(ANA, 'DSP-1');
      await exported(BEN, 'DSP-2');
      await exported(ANA, 'DSP-3');
    } finally {
      await operator.destroy();
    }

    const page = await activity().page(ANA, { ...RANGE, before: undefined, limit: 100 }, CORRELATION);

    if (page.outcome !== 'page') throw new Error('no page');
    expect(page.rows).toEqual([
      expect.objectContaining({
        id: bare,
        claimedOrg: BEN,
        client: { ip: undefined, place: undefined, timeZone: undefined },
      }),
    ]);
    expect(page.exports.map((one) => one.details.caseRef)).toEqual(['DSP-3', 'DSP-1']);

    // A page at a time: the newest first, then the one before it; a city unknown in a known country.
    await admin().query("update access.person_requests set country = 'AE' where id = $1", [bare]);
    const newer = await written(ANA, '2026-11-11T09:00:00.000Z');
    const first = await activity().page(ANA, { ...RANGE, before: undefined, limit: 1 }, CORRELATION);
    if (first.outcome !== 'page' || first.next === null) throw new Error('no next page');
    expect(first.rows.map((row) => row.id)).toEqual([newer]);
    const second = await activity().page(ANA, { ...RANGE, before: first.next, limit: 1 }, CORRELATION);
    if (second.outcome !== 'page') throw new Error('no page');
    expect(second.rows.map((row) => [row.id, row.client.place])).toEqual([[bare, { country: 'AE', city: undefined }]]);
    expect(second.next).toBeNull();
  });

  it('answers a second person sending the first’s key with their own file and record, never the first’s', async () => {
    const ana = await written(ANA, '2026-11-10T09:00:00.000Z');
    const ben = await written(BEN, '2026-11-10T10:00:00.000Z');

    const first = await exportOf(ANA, 'same');
    const second = await exportOf(BEN, 'same');

    expect(idsIn(first)).toEqual([ana]);
    expect(idsIn(second)).toEqual([ben]);
    if (first.outcome !== 'exported' || second.outcome !== 'exported') throw new Error('not exported');
    expect(second.file.id).not.toBe(first.file.id);
  });

  it('records a retry with the same key once: the same file, the count unchanged', async () => {
    await written(ANA, '2026-11-10T09:00:00.000Z');

    const first = await exportOf(ANA, 'again');
    const retry = await exportOf(ANA, 'again');

    expect(retry).toEqual(first);
    expect(await recordsOf(ANA)).toBe(1);
  });

  it('holds a person’s retries with their key to five an hour on one server, its file built again each time', async () => {
    await written(ANA, '2026-11-10T09:00:00.000Z');
    const one = activity();
    const again = () => one.export(ANA, keyed(ANA, 'again'), { ...RANGE, format: 'ndjson' }, CORRELATION);

    const first = await again();
    for (let retry = 1; retry <= 5; retry += 1) expect(await again()).toEqual(first);

    expect(await again()).toEqual({ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORTS_SPENT' });
    expect(await recordsOf(ANA)).toBe(1);
  });

  it('answers a retry the rows its record counted, never one written since', async () => {
    const counted = await written(ANA, '2026-11-10T09:00:00.000Z');

    const first = await exportOf(ANA, 'again');
    await written(ANA, '2026-11-11T09:00:00.000Z');
    const retry = await exportOf(ANA, 'again');

    expect(idsIn(retry)).toEqual([counted]);
    expect(retry).toEqual(first);
  });

  it.each([
    [
      'another person’s download',
      async () => {
        const bens = await exportOf(BEN, 'bens');
        return bens.outcome === 'exported' ? bens.file.id : '';
      },
    ],
    [
      'another kind of event',
      async () => {
        await written(BEN, '2026-11-10T09:00:00.000Z');
        await sealAt(new FixedClock(new Date('2026-11-11T00:20:00.000Z'))).run();
        const [seal] = await admin().query<{ id: string }>(
          'select id from platform_controls.audit_events where action = $1',
          [PERSON_SEALED],
        );
        return seal?.id ?? '';
      },
    ],
  ])('refuses a retry whose key names %s, raising the alarm', async (_what, otherRecord) => {
    await written(ANA, '2026-11-10T09:00:00.000Z');
    await exportOf(ANA, 'mine');
    const other = await otherRecord();
    // The person's key pointed past the app at a record not their own download.
    await admin().query('update idempotency.keys set result_id = $1 where client_id = $2 and key = $3', [
      other,
      ANA,
      'mine',
    ]);
    capture = new LogCapture();

    expect(await exportOf(ANA, 'mine')).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'unsealed' })]);
  });

  it('counts five downloads an hour per person, from their records on the platform chain', async () => {
    for (let one = 1; one <= 5; one += 1) expect((await exportOf(ANA, `k-${String(one)}`)).outcome).toBe('exported');

    expect(await exportOf(ANA, 'k-6')).toEqual({ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORTS_SPENT' });
    expect((await exportOf(BEN, 'k-6')).outcome).toBe('exported');
    expect(await recordsOf(ANA)).toBe(5);
  });

  it('counts only the last hour’s downloads: those 90 minutes old are spent no more', async () => {
    for (let one = 1; one <= 5; one += 1) await exportOf(ANA, `k-${String(one)}`);
    const later = createMyActivity({
      database: app,
      keys,
      ids,
      clock: new FixedClock(new Date(Date.now() + 90 * 60_000)),
      logger: testLogger(capture),
    });

    expect((await later.export(ANA, keyed(ANA, 'k-6'), { ...RANGE, format: 'ndjson' }, CORRELATION)).outcome).toBe(
      'exported',
    );
  });

  it('FX-RACE counts a download recorded under the person’s lock meanwhile: the sixth waits, then is refused', async () => {
    for (let one = 1; one <= 4; one += 1) await exportOf(ANA, `k-${String(one)}`);
    // A fifth, of another server, recorded under Ana's lock and held open before it commits.
    const other = holding([MY_ACTIVITY_EXPORTS_LOCK, ANA], async (tx) => {
      await createPlatformChain({ keys, ids }).record(tx, {
        actor: API,
        action: PERSON_LOG_EXPORTED,
        details: {
          person: ANA,
          from: RANGE.from.toISOString(),
          to: RANGE.to.toISOString(),
          format: 'csv',
          requests: 0,
          writtenUpTo: null,
        },
      });
    });
    await other.held;
    const sixth = within(20_000, exportOf(ANA, 'k-6'), 'the sixth');
    await waitUntilQueued(admin(), 1);
    other.open();

    await other.done;
    expect(await sixth).toEqual({ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORTS_SPENT' });
    expect(await recordsOf(ANA)).toBe(5);
  });

  it('refuses a range past the cap with nothing recorded', async () => {
    for (const at of ['2026-11-14T09:00:00.000Z', '2026-11-14T10:00:00.000Z', '2026-11-14T11:00:00.000Z']) {
      await written(BEN, at);
    }
    const before = await recordsOf(BEN);

    const asked = await activity(2).export(BEN, keyed(BEN, 'big'), { ...RANGE, format: 'csv' }, CORRELATION);

    expect(asked).toEqual({ outcome: 'refused', status: 409, code: 'ACTIVITY_EXPORT_TOO_LARGE' });
    expect(await recordsOf(BEN)).toBe(before);
  });

  it('takes a range holding the cap exactly', async () => {
    for (const at of ['2026-11-14T09:00:00.000Z', '2026-11-14T10:00:00.000Z']) await written(BEN, at);

    const asked = await activity(2).export(BEN, keyed(BEN, 'full'), { ...RANGE, format: 'csv' }, CORRELATION);

    expect(asked).toMatchObject({ outcome: 'exported', file: { requests: 2 } });
  });
});
