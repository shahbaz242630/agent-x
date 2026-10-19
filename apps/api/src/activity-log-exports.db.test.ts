// Phase 3 L5: downloading the organisation's activity log, composed in the
// API, on the real migrated schema as the app role: the download recorded on
// the audit chain before a row is read, the file its requests up to the
// newest then, in batches, in either format, each place credited to DB-IP and
// formula cells made text; a retry answering the same file; the cap, the
// hourly budget (its lock forced, ADR-006 §6, 2b), and a member not an admin.
import {
  type ActivityTables,
  createActivityLog as createActivityRecorder,
  type OrganisationRequest,
} from '@agentx/core/modules/activity';
import { createAuditTrail } from '@agentx/core/modules/audit';
import { ACTIVITY_LOG_EXPORTED, EXPORT_BATCH } from '@agentx/core/modules/evidence';
import { createDatabase, type Database, holdTransactionLock, withTenant } from '@agentx/platform/db';
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
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  ACTIVITY_EXPORT_OPERATION,
  ACTIVITY_EXPORTS_LOCK,
  type ActivityExportAsked,
  type ActivityExportWrite,
  type ActivityLogExports,
  createActivityLogExports,
} from './activity-log-exports.ts';
import { keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables & ActivityTables>;

const ids = new SequentialIds(0xa15e_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000a15e0';
const EVER = { from: new Date('2000-01-01T00:00:00Z'), to: new Date('2100-01-01T00:00:00Z') };
const recorder = createActivityRecorder({ ids });
const trail = createAuditTrail({ keys, ids });

let clock: FixedClock;
let exports: ActivityLogExports;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'activity-log-exports' });
const { world, keyed, member } = shared;

const asked = (format: ActivityExportAsked['format'], actor?: ActivityExportAsked['actor']): ActivityExportAsked => ({
  ...EVER,
  actor,
  format,
});

const fileOf = (write: ActivityExportWrite) => {
  if (write.outcome !== 'exported') throw new Error(`not exported: ${JSON.stringify(write)}`);
  return write.file;
};

const exported = (w: World, how: ActivityExportAsked) =>
  exports.export(w.admin, keyed(w.admin, ACTIVITY_EXPORT_OPERATION), how, CORRELATION);

/** A request of the world's admin, or of whoever is named, at `at`. */
const requested = (
  w: World,
  at: string,
  {
    by = { type: 'user', id: w.admin.userId },
    route = '/v1/agents/:id',
  }: Partial<{
    by: OrganisationRequest['actor'];
    route: string;
  }> = {},
) =>
  recorder.recordForOrganisation(app, {
    orgId: w.org,
    actor: by,
    at: new Date(at),
    method: 'GET',
    route,
    pathIds: [w.agent],
    status: 200,
    reason: undefined,
    correlationId: CORRELATION,
    durationMs: 7,
    client: {
      ip: '94.200.1.7',
      place: { country: 'AE', city: '=HYPERLINK("x")' },
      timeZone: { name: 'Asia/Dubai', from: 'organisation' },
    },
  });

/** `rows` requests of the world's admin, a millisecond apart from `at`, in one statement. */
const manyRequested = (w: World, rows: number, at: string) =>
  withTenant(app, w.org, (tx) =>
    tx
      .insertInto('access.requests')
      .values(
        Array.from({ length: rows }, (_, n) => ({
          org_id: w.org,
          id: ids.next(),
          recorded_at: new Date(new Date(at).getTime() + n),
          actor_type: 'user',
          actor_id: w.admin.userId,
          method: 'GET',
          route: '/v1/members',
          path_ids: [],
          status: 200,
          reason: null,
          correlation_id: CORRELATION,
          duration_ms: 1,
          ip: null,
          country: null,
          city: null,
          time_zone: null,
          time_zone_from: null,
        })),
      )
      .execute(),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables & ActivityTables>(
    { ...database.connection('app'), maxConnections: 4 },
    testLogger(),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // The audit log's own clock times its events: the budget's hour is read against it.
  clock = new FixedClock(new Date());
  exports = createActivityLogExports({
    database: app,
    keys,
    ids,
    clock,
    logger: testLogger(new LogCapture()),
    directory: undefined,
    mostRequests: 600,
  });
});

describe('downloading the activity log (L5, decision 26)', () => {
  it('records the download on the audit log first, then gives its requests newest first as NDJSON, each place credited', async () => {
    const w = await world();
    await requested(w, '2026-10-19T09:00:00.000Z');
    await requested(w, '2026-10-19T10:00:00.000Z', { by: { type: 'agent', id: w.agent } });

    const file = fileOf(await exported(w, asked('ndjson')));
    const lines = file.content
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    expect(file).toMatchObject({
      contentType: 'application/x-ndjson',
      requests: 2,
      fileName: 'activity-log-2000-01-01-to-2100-01-01.ndjson',
    });
    expect(lines.map((line) => line.recordedAt)).toEqual(['2026-10-19T10:00:00.000Z', '2026-10-19T09:00:00.000Z']);
    expect(lines[1]).toMatchObject({
      localTime: '2026-10-19T13:00:00.000+04:00',
      actor: { type: 'user', id: w.admin.userId },
      client: {
        ip: '94.200.1.7',
        place: { country: 'AE', approximate: true, by: 'IP Geolocation by DB-IP', link: 'https://db-ip.com' },
        timeZone: { name: 'Asia/Dubai', from: 'organisation' },
      },
    });
    expect(lines[0]).toMatchObject({ actor: { type: 'agent', id: w.agent, name: 'Purchasing agent' } });

    const recorded = await withTenant(app, w.org, (tx) => trail.recordedEvent(tx, w.org, { eventId: file.id }));
    expect(recorded).toMatchObject({
      kind: 'recorded',
      event: {
        actor: { type: 'user', id: w.admin.userId },
        action: ACTIVITY_LOG_EXPORTED,
        subject: { type: 'access_log', id: w.org, version: 1 },
        // The download's own request, sealed in: its activity row and this event link (ADR-011 §7).
        details: { format: 'ndjson', requests: 2, writtenUpTo: lines[0]?.id, actor: null, correlationId: CORRELATION },
      },
    });
  });

  it('gives CSV with a header and every cell quoted, a city a spreadsheet would run made text', async () => {
    const w = await world();
    await requested(w, '2026-10-19T09:00:00.000Z');

    const file = fileOf(await exported(w, asked('csv')));
    const [header, row] = file.content.trimEnd().split('\n');

    expect(file).toMatchObject({ contentType: 'text/csv', requests: 1 });
    expect(header).toBe(
      '"id","recordedAt","localTime","actorType","actorId","actorName","actorEmail","actorNameFrom","method","route","pathIds","status","reason","correlationId","durationMs","ip","approximateCountry","approximateCity","placeBy","timeZone","timeZoneFrom"',
    );
    expect(row).toContain(
      `"GET","/v1/agents/:id","${w.agent}","200","","${CORRELATION}","7","94.200.1.7","AE","'=HYPERLINK(""x"")","IP Geolocation by DB-IP (https://db-ip.com)","Asia/Dubai","organisation"`,
    );
  });

  it('leaves the place, its credit and the time zone empty in CSV for a row with none', async () => {
    const w = await world();
    await manyRequested(w, 1, '2026-10-19T09:00:00.000Z');

    const [, row] = fileOf(await exported(w, asked('csv')))
      .content.trimEnd()
      .split('\n');
    expect(row).toMatch(/"1","","","","","",""$/);
  });

  it('gives one person’s or agent’s requests alone, the actor named in the record', async () => {
    const w = await world();
    await requested(w, '2026-10-19T09:00:00.000Z');
    await requested(w, '2026-10-19T10:00:00.000Z', { by: { type: 'agent', id: w.agent } });

    const file = fileOf(await exported(w, asked('ndjson', { type: 'agent', id: w.agent })));
    expect(file.requests).toBe(1);
    const recorded = await withTenant(app, w.org, (tx) => trail.recordedEvent(tx, w.org, { eventId: file.id }));
    expect(recorded).toMatchObject({ event: { details: { actor: `agent:${w.agent}`, requests: 1 } } });
  });

  it('reads past one batch, every request once, and records an empty range as none', async () => {
    const w = await world();
    const empty = fileOf(await exported(w, asked('ndjson')));
    expect(empty).toMatchObject({ requests: 0, content: '\n' });
    await manyRequested(w, EXPORT_BATCH + 1, '2026-10-19T09:00:00.000Z');

    const file = fileOf(await exported(w, asked('ndjson')));
    const seen = file.content
      .trimEnd()
      .split('\n')
      .map((line) => (JSON.parse(line) as { id: string }).id);
    expect(seen).toHaveLength(EXPORT_BATCH + 1);
    expect(new Set(seen).size).toBe(EXPORT_BATCH + 1);
  });

  it('answers a retry with its key with the same file, requests written since left out, a slow one older than the newest too', async () => {
    const w = await world();
    await requested(w, '2026-10-19T09:00:00.000Z');
    const key = keyed(w.admin, ACTIVITY_EXPORT_OPERATION);
    const first = fileOf(await exports.export(w.admin, key, asked('csv'), CORRELATION));
    await requested(w, '2026-10-19T10:00:00.000Z');
    // A slow request: it arrived before the newest counted, its row written only after the count.
    await requested(w, '2026-10-19T08:00:00.000Z');

    expect(first.requests).toBe(1);
    expect(fileOf(await exports.export(w.admin, key, asked('csv'), CORRELATION))).toEqual(first);
  });

  it('builds one download at a time: another asked meanwhile is ACTIVITY_EXPORTS_BUSY, nothing logged', async () => {
    const w = await world();
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The admin's own download lock held elsewhere, so the first download waits mid-way.
    const holder = withTenant(app, w.org, async (tx) => {
      await holdTransactionLock(tx, ACTIVITY_EXPORTS_LOCK, w.org, w.admin.userId);
      holding(undefined);
      await gate;
    });
    await held;
    const first = within(20_000, exported(w, asked('csv')), 'the first');
    await waitUntilQueued(database.as('admin'), 1);

    const other = await world();
    expect(await exported(other, asked('csv'))).toEqual(refused(503, 'ACTIVITY_EXPORTS_BUSY'));
    open(undefined);
    await holder;
    expect(await first).toMatchObject({ outcome: 'exported' });
    expect(await exported(other, asked('csv'))).toMatchObject({ outcome: 'exported', file: { requests: 0 } });
  });

  it('refuses a range past the cap with nothing logged, an admin’s sixth in an hour, and a member not an admin', async () => {
    const w = await world();
    await manyRequested(w, 600, '2026-10-19T09:00:00.000Z');
    // Exactly the cap is downloaded; one past it is refused, nothing logged.
    expect(await exported(w, asked('csv'))).toMatchObject({ outcome: 'exported', file: { requests: 600 } });
    await manyRequested(w, 1, '2026-10-19T10:00:00.000Z');
    expect(await exported(w, asked('csv'))).toEqual(refused(409, 'ACTIVITY_EXPORT_TOO_LARGE'));
    const few = { ...asked('csv'), from: new Date('2026-10-19T10:00:00.000Z') };

    for (let n = 0; n < 4; n += 1) fileOf(await exported(w, few));
    expect(await exported(w, few)).toEqual(refused(409, 'ACTIVITY_EXPORTS_SPENT'));
    const approver = await member(w.org, 'approver');
    expect(await exports.export(approver, keyed(approver, ACTIVITY_EXPORT_OPERATION), few, CORRELATION)).toEqual(
      refused(403, 'FORBIDDEN'),
    );
  });

  it('counts an admin’s download in flight before their next: the sixth waits on their lock, then is refused (ADR-006 §6, 2b)', async () => {
    const w = await world();
    for (let n = 0; n < 4; n += 1) fileOf(await exported(w, asked('csv')));
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The fifth, its lock taken and its record made, held open before it commits.
    const fifth = withTenant(app, w.org, async (tx) => {
      await holdTransactionLock(tx, ACTIVITY_EXPORTS_LOCK, w.org, w.admin.userId);
      await trail.record(tx, w.org, {
        actor: { type: 'user', id: w.admin.userId },
        action: ACTIVITY_LOG_EXPORTED,
        subject: { type: 'access_log', id: w.org, version: 1 },
        details: { format: 'csv' },
      });
      holding(undefined);
      await gate;
    });
    await held;
    const sixth = within(20_000, exported(w, asked('csv')), 'the sixth');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    await fifth;
    expect(await sixth).toEqual(refused(409, 'ACTIVITY_EXPORTS_SPENT'));
  });

  it('counts the audit log’s own downloads apart: five of them leave the activity log’s budget whole', async () => {
    const w = await world();
    for (let n = 0; n < 5; n += 1) {
      await withTenant(app, w.org, (tx) =>
        trail.record(tx, w.org, {
          actor: { type: 'user', id: w.admin.userId },
          action: 'audit_log.exported',
          subject: { type: 'audit_log', id: w.org, version: 1 },
          details: { format: 'csv' },
        }),
      );
    }

    expect(await exported(w, asked('csv'))).toMatchObject({ outcome: 'exported' });
  });
});
