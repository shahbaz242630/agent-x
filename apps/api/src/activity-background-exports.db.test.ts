// Phase 3 L5c: the activity log's background downloads, composed in the API,
// on the real migrated schema as the app role: one asked for, recorded on the
// audit chain with its months and the newest request then; refused while
// another is under way, past the hourly budget it shares with the instant
// download, and to a member not an admin. Then built by the builder into a
// local folder: a UTC month a gzip file, newest first, only the requests
// written when it was asked, each file's facts on the audit chain, ready and
// the asker told; a month that keeps failing given up, the asker told; one
// stopped given back.
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';

import {
  type ActivityExportTables,
  type ActivityTables,
  addBackgroundExport,
  createActivityLog as createActivityRecorder,
  storedName,
} from '@agentx/core/modules/activity';
import { createAuditTrail } from '@agentx/core/modules/audit';
import {
  ACTIVITY_EXPORT_DOWNLOADED,
  ACTIVITY_EXPORT_FAILED,
  ACTIVITY_EXPORT_FILE_MADE,
  ACTIVITY_EXPORT_REQUESTED,
} from '@agentx/core/modules/evidence';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createDatabase, type Database, holdTransactionLock, withTenant } from '@agentx/platform/db';
import { type BlockStore, folderBlockStore } from '@agentx/platform/storage';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  BACKGROUND_EXPORT_OPERATION,
  BACKGROUND_EXPORTS_LOCK,
  type BackgroundExportAskedFor,
  type BackgroundExports,
  type BackgroundExportWrite,
  createBackgroundExports,
} from './activity-background-exports.ts';
import { createDownloadFiles, FILE_DOWNLOAD_OPERATION } from './activity-download-files.ts';
import { createActivityExportBuilder } from './activity-export-builder.ts';
import { ACTIVITY_EXPORT_OPERATION, createActivityLogExports } from './activity-log-exports.ts';
import { keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';

type Tables = MandateWorldTables & ActivityTables & ActivityExportTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0xa15c_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000a15c0';
const recorder = createActivityRecorder({ ids });
const trail = createAuditTrail({ keys, ids });

let clock: FixedClock;
let capture: LogCapture;
let folder: string;
let downloads: BackgroundExports;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'activity-background-exports' });
const { world, keyed, member, noticesOf } = shared;

/** August 15 to October 2: three months. */
const ASKED: BackgroundExportAskedFor = {
  from: new Date('2026-08-15T00:00:00.000Z'),
  to: new Date('2026-10-02T00:00:00.000Z'),
  actor: undefined,
  format: 'ndjson',
};

const downloadOf = (write: BackgroundExportWrite) => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.download;
};

/** The download as its organisation reads it, or undefined. */
const oneOf = async (w: World, id: string) => {
  const read = await downloads.one(w.org, id, CORRELATION);
  if (read !== undefined && 'outcome' in read) throw new Error(`refused: ${read.code}`);
  return read;
};

const ask = (w: World, how: Partial<BackgroundExportAskedFor> = {}) =>
  downloads.ask(w.admin, keyed(w.admin, BACKGROUND_EXPORT_OPERATION), { ...ASKED, ...how }, CORRELATION);

/** A request of the world's admin at `at`. */
const requested = (w: World, at: string, route = '/v1/agents/:id') =>
  recorder.recordForOrganisation(app, {
    orgId: w.org,
    actor: { type: 'user', id: w.admin.userId },
    at: new Date(at),
    method: 'GET',
    route,
    pathIds: [],
    status: 200,
    reason: undefined,
    correlationId: CORRELATION,
    durationMs: 7,
    client: { ip: '94.200.1.7', place: { country: 'AE', city: 'Dubai' }, timeZone: undefined },
  });

/** A builder for the world's organisation alone, into `store` (the test's folder unless named). */
const builderFor = (w: World, change: Partial<Parameters<typeof createActivityExportBuilder>[0]> = {}) =>
  createActivityExportBuilder({
    list: () => Promise.resolve([w.org]),
    database: app,
    keys,
    ids,
    store: folderBlockStore(folder),
    outbox: createOutbox({ ids, clock }),
    directory: undefined,
    logger: testLogger(capture),
    batch: 2,
    ...change,
  });

/** The month's file as stored, gunzipped, a line a request. */
const linesOf = async (w: World, exportId: string, month: string, attempt = 1) => {
  const name = storedName(w.org, { exportId, month, attempt, format: 'ndjson' });
  const text = gunzipSync(await readFile(join(folder, name))).toString();
  return text
    .trimEnd()
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line) as { recordedAt: string });
};

const eventsOf = (w: World, action: string) =>
  withTenant(app, w.org, async (tx) =>
    (
      await tx
        .selectFrom('audit.events')
        .select(['actor_type', 'actor_id', 'details'])
        .where('action', '=', action)
        .orderBy('seq')
        .execute()
    ).map((row) => ({ actor: `${row.actor_type}:${row.actor_id}`, details: JSON.parse(row.details) as unknown })),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit log's own clock times its events: the budget's hour is read against it.
  clock = new FixedClock(new Date('2026-10-19T12:00:00.000Z'));
  capture = new LogCapture();
  folder = mkdtempSync(join(tmpdir(), 'agentx-downloads-'));
  downloads = createBackgroundExports({ database: app, keys, ids, clock, logger: testLogger(capture) });
});

afterEach(async () => {
  await rm(folder, { recursive: true, force: true });
});

describe('L5c a background download asked for (decision 31)', () => {
  it('is recorded on the audit log with its months and the newest request then, and listed building', async () => {
    const w = await world();
    await requested(w, '2026-08-20T09:00:00.000Z');

    const download = downloadOf(await ask(w, { actor: { type: 'agent', id: w.agent } }));

    expect(download).toMatchObject({
      requestedBy: w.admin.userId,
      actor: { type: 'agent', id: w.agent },
      format: 'ndjson',
      state: 'building',
      expiresAt: null,
    });
    expect(download.files.map((file) => file.month)).toEqual(['2026-08', '2026-09', '2026-10']);
    const recorded = await withTenant(app, w.org, (tx) => trail.recordedEvent(tx, w.org, { eventId: download.id }));
    expect(recorded).toMatchObject({
      kind: 'recorded',
      event: {
        actor: { type: 'user', id: w.admin.userId },
        action: ACTIVITY_EXPORT_REQUESTED,
        subject: { type: 'access_log', id: w.org, version: 1 },
        details: {
          from: '2026-08-15T00:00:00.000Z',
          to: '2026-10-02T00:00:00.000Z',
          actor: `agent:${w.agent}`,
          format: 'ndjson',
          months: 3,
          writtenUpTo: download.writtenUpTo,
          correlationId: CORRELATION,
        },
      },
    });
    expect(download.writtenUpTo).not.toBeNull();
    expect(await oneOf(w, download.id)).toEqual(download);
    expect(await downloads.list(w.org, { before: undefined, limit: 20 }, CORRELATION)).toEqual({
      downloads: [download],
      next: null,
    });
  });

  it('answers a retry with its key from the same download, asking nothing twice', async () => {
    const w = await world();
    const key = keyed(w.admin, BACKGROUND_EXPORT_OPERATION);

    const first = downloadOf(await downloads.ask(w.admin, key, ASKED, CORRELATION));
    const again = downloadOf(await downloads.ask(w.admin, key, ASKED, CORRELATION));

    expect(again.id).toBe(first.id);
    expect(await eventsOf(w, ACTIVITY_EXPORT_REQUESTED)).toHaveLength(1);
  });

  it('refuses another while one is under way, past the hourly budget it shares with the instant download, and to a member not an admin', async () => {
    const w = await world();
    downloadOf(await ask(w));
    expect(await ask(w)).toEqual(refused(409, 'ACTIVITY_EXPORT_UNDER_WAY'));

    const instant = createActivityLogExports({
      database: app,
      keys,
      ids,
      clock,
      logger: testLogger(capture),
      directory: undefined,
    });
    const day = { from: new Date('2026-10-19T00:00:00.000Z'), to: new Date('2026-10-20T00:00:00.000Z') };
    for (let n = 0; n < 4; n += 1) {
      const made = await instant.export(
        w.admin,
        keyed(w.admin, ACTIVITY_EXPORT_OPERATION),
        { ...day, actor: undefined, format: 'csv' },
        CORRELATION,
      );
      expect(made.outcome).toBe('exported');
    }
    // One background and four instant: the fifth of the hour was the last.
    expect(await ask(w)).toEqual(refused(409, 'ACTIVITY_EXPORTS_SPENT'));
    const approver = await member(w.org, 'approver');
    expect(await downloads.ask(approver, keyed(approver, BACKGROUND_EXPORT_OPERATION), ASKED, CORRELATION)).toEqual(
      refused(403, 'FORBIDDEN'),
    );
  });

  it('FX-RACE two admins asking at once: the second waits on the organisation’s lock, then finds one under way (ADR-006 §6, 2c)', async () => {
    const w = await world();
    const other = await member(w.org, 'admin');
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The first admin's download, its lock taken and its rows added, held open before it commits.
    const first = withTenant(app, w.org, async (tx) => {
      await holdTransactionLock(tx, BACKGROUND_EXPORTS_LOCK, w.org);
      await addBackgroundExport(tx, w.org, {
        ...ASKED,
        id: ids.next(),
        requestedBy: w.admin.userId,
        writtenUpTo: null,
      });
      holding(undefined);
      await gate;
    });
    await held;
    const second = within(
      20_000,
      downloads.ask(other, keyed(other, BACKGROUND_EXPORT_OPERATION), ASKED, CORRELATION),
      'the second admin',
    );
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    await first;
    expect(await second).toEqual(refused(409, 'ACTIVITY_EXPORT_UNDER_WAY'));
  });

  it('is unknown to another organisation, and to an ID it never had', async () => {
    const w = await world();
    const download = downloadOf(await ask(w));
    const other = await world();

    expect(await downloads.one(other.org, download.id, CORRELATION)).toBeUndefined();
    expect(await downloads.one(w.org, other.org, CORRELATION)).toBeUndefined();
  });
});

describe('L5c a background download built (decision 31)', () => {
  it('builds a gzip file a month, newest first, only the requests written when it was asked, then tells the asker', async () => {
    const w = await world();
    await requested(w, '2026-08-14T23:59:59.999Z');
    await requested(w, '2026-08-15T00:00:00.000Z');
    await requested(w, '2026-08-31T23:59:59.999Z');
    await requested(w, '2026-09-01T00:00:00.000Z');
    await requested(w, '2026-09-10T00:00:00.000Z');
    await requested(w, '2026-09-20T00:00:00.000Z');
    const download = downloadOf(await ask(w));
    // Written after it was asked: in its range, but past its newest request.
    await requested(w, '2026-09-25T00:00:00.000Z');

    await builderFor(w).run();
    const built = await oneOf(w, download.id);

    expect(built).toMatchObject({ state: 'ready' });
    expect(built?.files.map((file) => [file.month, file.state, file.requests])).toEqual([
      ['2026-08', 'ready', 2],
      ['2026-09', 'ready', 3],
      ['2026-10', 'ready', 0],
    ]);
    expect((await linesOf(w, download.id, '2026-08-01')).map((line) => line.recordedAt)).toEqual([
      '2026-08-31T23:59:59.999Z',
      '2026-08-15T00:00:00.000Z',
    ]);
    expect((await linesOf(w, download.id, '2026-09-01')).map((line) => line.recordedAt)).toEqual([
      '2026-09-20T00:00:00.000Z',
      '2026-09-10T00:00:00.000Z',
      '2026-09-01T00:00:00.000Z',
    ]);
    expect(await linesOf(w, download.id, '2026-10-01')).toEqual([]);

    const made = await eventsOf(w, ACTIVITY_EXPORT_FILE_MADE);
    expect(made.map(({ actor }) => actor)).toEqual(['system:api', 'system:api', 'system:api']);
    expect(made[0]?.details).toMatchObject({
      exportId: download.id,
      month: '2026-08',
      attempt: 1,
      requests: 2,
      bytes: built?.files[0]?.bytes,
      sha256: built?.files[0]?.sha256,
    });
    expect(await noticesOf(w.org)).toContainEqual({
      kind: 'access_log_export_ready',
      about_id: download.id,
      recipient_user_id: w.admin.userId,
    });
    expect(await oneOf(w, download.id)).toMatchObject({ state: 'ready' });
    // The next may be asked now.
    downloadOf(await ask(w));
  });

  it('writes a CSV month with its header, and each file’s SHA-256 is that of the bytes stored', async () => {
    const w = await world();
    await requested(w, '2026-08-20T09:00:00.000Z');
    const download = downloadOf(await ask(w, { format: 'csv', to: new Date('2026-09-01T00:00:00.000Z') }));

    await builderFor(w).run();
    const built = await oneOf(w, download.id);
    const name = storedName(w.org, { exportId: download.id, month: '2026-08-01', attempt: 1, format: 'csv' });
    const stored = await readFile(join(folder, name));

    expect(gunzipSync(stored).toString().split('\n')[0]).toMatch(/^"id","recordedAt",/);
    expect(built?.files[0]).toMatchObject({ requests: 1, bytes: stored.length });
  });

  it('writes a long month in many blocks, its lease renewed with each, the whole file read back', async () => {
    const w = await world();
    for (let day = 1; day <= 28; day += 1) await requested(w, `2026-08-${String(day).padStart(2, '0')}T09:00:00.000Z`);
    const download = downloadOf(
      await ask(w, { from: new Date('2026-08-01T00:00:00.000Z'), to: new Date('2026-09-01T00:00:00.000Z') }),
    );

    await builderFor(w, { blockBytes: 64 }).run();

    expect((await oneOf(w, download.id))?.files[0]).toMatchObject({ state: 'ready', requests: 28 });
    expect(await linesOf(w, download.id, '2026-08-01')).toHaveLength(28);
  });

  it('stops writing once its lease runs out, leaving the month to the next try', async () => {
    const w = await world();
    for (let day = 1; day <= 10; day += 1) await requested(w, `2026-08-${String(day).padStart(2, '0')}T09:00:00.000Z`);
    const download = downloadOf(
      await ask(w, { from: new Date('2026-08-01T00:00:00.000Z'), to: new Date('2026-09-01T00:00:00.000Z') }),
    );

    await builderFor(w, { blockBytes: 64, leaseMs: 1 }).run();
    expect(capture.lines().map((line) => line.event)).toContain('access_log.export_lease_lost');
    expect((await oneOf(w, download.id))?.files[0]).toMatchObject({ state: 'building' });
    await builderFor(w).run();

    expect((await oneOf(w, download.id))?.files[0]).toMatchObject({ state: 'ready', attempts: 2 });
    expect(await linesOf(w, download.id, '2026-08-01', 2)).toHaveLength(10);
  });

  it('gives a month back when its store fails, and gives the download up on its third try, the asker told', async () => {
    const w = await world();
    const download = downloadOf(await ask(w));
    const broken: BlockStore = {
      putBlock: () => Promise.reject(new Error('the store is down')),
      commit: () => Promise.reject(new Error('the store is down')),
      read: () => Promise.reject(new Error('the store is down')),
    };
    const builder = builderFor(w, { store: broken });

    await builder.run();
    expect((await oneOf(w, download.id))?.files[0]).toMatchObject({
      state: 'waiting',
    });
    await builder.run();
    await builder.run();
    await builder.run();

    expect(await oneOf(w, download.id)).toMatchObject({ state: 'failed' });
    expect(capture.lines().filter((line) => line.event === 'access_log.export_build_failed')).toHaveLength(3);
    expect(capture.lines().filter((line) => line.event === 'access_log.export_failed')).toEqual([
      expect.objectContaining({ level: 'error', exportId: download.id, month: '2026-08', tries: 3 }),
    ]);
    expect(await eventsOf(w, ACTIVITY_EXPORT_FAILED)).toEqual([
      {
        actor: 'system:api',
        details: expect.objectContaining({
          exportId: download.id,
          month: '2026-08',
          reason: 'ACTIVITY_EXPORT_FAILED',
        }) as unknown,
      },
    ]);
    expect(await noticesOf(w.org)).toContainEqual({
      kind: 'access_log_export_failed',
      about_id: download.id,
      recipient_user_id: w.admin.userId,
    });
  });

  it('gives a month back at a stop, no failure logged, and the next run builds it', async () => {
    const w = await world();
    await requested(w, '2026-08-20T09:00:00.000Z');
    const download = downloadOf(await ask(w, { to: new Date('2026-09-01T00:00:00.000Z') }));
    const stopping = new AbortController();
    // The API stopping as the month's first block is put.
    const stopped: BlockStore = {
      ...folderBlockStore(folder),
      putBlock: () => {
        stopping.abort();
        return Promise.reject(new Error('the API is stopping'));
      },
    };

    await builderFor(w, { store: stopped }).run(stopping.signal);
    expect((await oneOf(w, download.id))?.files[0]).toMatchObject({ state: 'waiting' });
    expect(capture.lines().map((line) => line.event)).toContain('access_log.export_stopped');
    expect(capture.lines().some((line) => line.event === 'access_log.export_build_failed')).toBe(false);
    await builderFor(w).run();

    expect(await oneOf(w, download.id)).toMatchObject({ state: 'ready' });
  });

  it('logs a run whose list fails, and goes on next time', async () => {
    const w = await world();

    await builderFor(w, { list: () => Promise.reject(new Error('the directory is down')) }).run();

    expect(capture.lines().filter((line) => line.event === 'access_log.export_run_failed')).toEqual([
      expect.objectContaining({ level: 'error' }),
    ]);
  });
});

describe('L5c a background download’s file downloaded (decision 31: each download logged)', () => {
  /** A download of August built whole. */
  const built = async (w: World) => {
    for (let day = 1; day <= 12; day += 1) await requested(w, `2026-08-${String(day).padStart(2, '0')}T09:00:00.000Z`);
    const download = downloadOf(
      await ask(w, { from: new Date('2026-08-01T00:00:00.000Z'), to: new Date('2026-09-01T00:00:00.000Z') }),
    );
    await builderFor(w).run();
    return download;
  };
  /** The downloads, read from `store` (the test's folder unless named) in parts of 100 bytes. */
  const filesWith = (store: BlockStore = folderBlockStore(folder)) =>
    createDownloadFiles({ database: app, keys, ids, store, logger: testLogger(capture), partBytes: 100 });
  const started = async (w: World, exportId: string) => {
    const start = await filesWith().start(
      w.admin,
      keyed(w.admin, FILE_DOWNLOAD_OPERATION),
      { exportId, month: '2026-08' },
      CORRELATION,
    );
    if (start.outcome !== 'started') throw new Error(`not started: ${JSON.stringify(start)}`);
    return start.download;
  };
  /** Seven days on: file_moves never lets a ready file change, so its time is moved with its trigger off. */
  const expire = async (exportId: string) => {
    const admin = database.as('admin');
    await admin.query('alter table activity_exports.files disable trigger file_moves');
    await admin.query(
      "update activity_exports.files set ready_at = ready_at - interval '7 days' where export_id = $1",
      [exportId],
    );
    await admin.query('alter table activity_exports.files enable trigger file_moves');
  };

  it('records each download on the audit log, then gives the file a part at a time, the parts its SHA-256 whole', async () => {
    const w = await world();
    const download = await built(w);
    const files = filesWith();

    const file = await started(w, download.id);
    const ready = (await oneOf(w, download.id))?.files[0];

    expect(file).toEqual({
      id: file.id,
      exportId: download.id,
      month: '2026-08',
      fileName: 'activity-log-2026-08-01-to-2026-09-01-2026-08.ndjson.gz',
      contentType: 'application/gzip',
      bytes: ready?.bytes,
      sha256: ready?.sha256,
      parts: Math.ceil((ready?.bytes ?? 0) / 100),
      partBytes: 100,
    });
    const parts: Buffer[] = [];
    for (let index = 0; index < file.parts; index += 1) {
      const part = await files.part(w.admin, { exportId: download.id, downloadId: file.id, index }, CORRELATION);
      if (part.outcome !== 'part') throw new Error(`no part ${String(index)}`);
      parts.push(part.content);
    }
    const whole = Buffer.concat(parts);
    expect(createHash('sha256').update(whole).digest('hex')).toBe(file.sha256);
    expect(gunzipSync(whole).toString().trimEnd().split('\n')).toHaveLength(12);
    expect(await eventsOf(w, ACTIVITY_EXPORT_DOWNLOADED)).toEqual([
      {
        actor: `user:${w.admin.userId}`,
        details: expect.objectContaining({
          exportId: download.id,
          month: '2026-08',
          attempt: 1,
          sha256: file.sha256,
          correlationId: CORRELATION,
        }) as unknown,
      },
    ]);
  });

  it('answers a retry with its key from the same record; a second download is recorded on its own', async () => {
    const w = await world();
    const download = await built(w);
    const files = filesWith();
    const file = { exportId: download.id, month: '2026-08' };
    const key = keyed(w.admin, FILE_DOWNLOAD_OPERATION);

    const first = await files.start(w.admin, key, file, CORRELATION);
    const again = await files.start(w.admin, key, file, CORRELATION);
    await files.start(w.admin, keyed(w.admin, FILE_DOWNLOAD_OPERATION), file, CORRELATION);

    expect(again).toEqual(first);
    expect(await eventsOf(w, ACTIVITY_EXPORT_DOWNLOADED)).toHaveLength(2);
  });

  it('refuses a file not ready, a month it doesn’t hold, a download it doesn’t have, one expired, and a member not an admin', async () => {
    const w = await world();
    const download = downloadOf(await ask(w, { to: new Date('2026-09-01T00:00:00.000Z') }));
    const files = filesWith();
    const start = (exportId: string, month: string, who = w.admin) =>
      files.start(who, keyed(who, FILE_DOWNLOAD_OPERATION), { exportId, month }, CORRELATION);

    expect(await start(download.id, '2026-08')).toEqual(refused(409, 'ACTIVITY_EXPORT_NOT_READY'));
    await builderFor(w).run();
    expect(await start(download.id, '2026-10')).toEqual(refused(404, 'NOT_FOUND'));
    expect(await start(w.org, '2026-08')).toEqual(refused(404, 'NOT_FOUND'));
    const approver = await member(w.org, 'approver');
    expect(await start(download.id, '2026-08', approver)).toEqual(refused(403, 'FORBIDDEN'));
    await expire(download.id);
    expect(await start(download.id, '2026-08')).toEqual(refused(410, 'ACTIVITY_EXPORT_EXPIRED'));
    expect(await eventsOf(w, ACTIVITY_EXPORT_DOWNLOADED)).toEqual([]);
  });

  it('gives parts to the admin whose download it is alone, within its file, and none once it has expired', async () => {
    const w = await world();
    const download = await built(w);
    const files = filesWith();
    const file = await started(w, download.id);
    const part = (index: number, who = w.admin, exportId = download.id, downloadId = file.id) =>
      files.part(who, { exportId, downloadId, index }, CORRELATION);
    const other = await member(w.org, 'admin');

    expect(await part(file.parts)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await part(0, other)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await part(0, w.admin, w.org)).toEqual(refused(404, 'NOT_FOUND'));
    expect(await part(0, w.admin, download.id, download.id)).toEqual(refused(404, 'NOT_FOUND'));
    expect((await part(file.parts - 1)).outcome).toBe('part');
    await expire(download.id);
    expect(await part(0)).toEqual(refused(410, 'ACTIVITY_EXPORT_EXPIRED'));
  });

  it('F1 G4 believes a file’s row only as its signed export_file_made holds it: one changed past the app raises the alarm and the hold', async () => {
    const w = await world();
    const download = await built(w);
    const admin = database.as('admin');
    await admin.query('alter table activity_exports.files disable trigger file_moves');
    await admin.query('update activity_exports.files set bytes = bytes + 1 where export_id = $1', [download.id]);
    await admin.query('alter table activity_exports.files enable trigger file_moves');

    expect(
      await filesWith().start(
        w.admin,
        keyed(w.admin, FILE_DOWNLOAD_OPERATION),
        { exportId: download.id, month: '2026-08' },
        CORRELATION,
      ),
    ).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await eventsOf(w, ACTIVITY_EXPORT_DOWNLOADED)).toEqual([]);
    expect(capture.lines().map((line) => line.event)).toEqual(
      expect.arrayContaining(['audit.integrity_failed', 'audit.integrity_hold_set']),
    );
  });

  it('F1 G2 refuses a part of a download whose record was changed past the app, raising the alarm and the hold', async () => {
    const w = await world();
    const download = await built(w);
    const file = await started(w, download.id);
    await database
      .as('admin')
      .query('update audit.events set details = replace(details, \'"attempt":1\', \'"attempt":2\') where id = $1', [
        file.id,
      ]);

    expect(
      await filesWith().part(w.admin, { exportId: download.id, downloadId: file.id, index: 0 }, CORRELATION),
    ).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(capture.lines().map((line) => line.event)).toEqual(
      expect.arrayContaining(['audit.integrity_failed', 'audit.integrity_hold_set']),
    );
  });

  it('answers ACTIVITY_EXPORT_UNREADABLE when the store fails or answers short, warning in plain words', async () => {
    const w = await world();
    const download = await built(w);
    const file = await started(w, download.id);
    const store = folderBlockStore(folder);
    const asked = { exportId: download.id, downloadId: file.id, index: 0 };

    const down = filesWith({ ...store, read: () => Promise.reject(new Error('the store is down')) });
    expect(await down.part(w.admin, asked, CORRELATION)).toEqual(refused(503, 'ACTIVITY_EXPORT_UNREADABLE'));
    const short = filesWith({ ...store, read: () => Promise.resolve(Buffer.from('x')) });
    expect(await short.part(w.admin, asked, CORRELATION)).toEqual(refused(503, 'ACTIVITY_EXPORT_UNREADABLE'));
    expect(capture.lines().filter((line) => line.event === 'access_log.export_read_failed')).toEqual([
      expect.objectContaining({ level: 'warn', exportId: download.id, month: '2026-08', index: 0 }),
      expect.objectContaining({ level: 'warn' }),
    ]);
  });
});
