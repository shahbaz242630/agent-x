// Phase 3 L7: the operator's activity log export for a case against a real
// Postgres (ADR-005 §6): recorded on both chains and told to the admins
// before the log is read out; every sealed day the range touches held to its
// seal first (one that doesn't holds the organisation, and no file is
// written); the file the range's requests written by then, as an admin's
// NDJSON download holds them; a request run again recording nothing twice;
// and what it refuses, with nothing recorded.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { ACTIVITY_SEALED, type ActivityTables, digestOfDay, SEAL_FORM, v7Floor } from '@agentx/core/modules/activity';
import { createAuditTrail } from '@agentx/core/modules/audit';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { createTestDatabase, LogCapture, type TestDatabase, testLogger, writeTestKeys } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { type ActivityExportTables, exportActivityLog } from './activity-export.ts';
import type { CaseExportRequest } from './case-export.ts';
import { createOrganizationAsOperator } from './create-organization.ts';
import { folderStore } from './evidence-store.ts';

const server = inject('postgres');
const mounted = writeTestKeys(['audit-mac', 'field-encryption']);
const keys = loadKeys({ directory: mounted.directory, current: {} }, ['audit-mac', 'field-encryption']);
let database: TestDatabase;
let app: Database<ActivityExportTables & ActivityTables>;
const folder = mkdtempSync(path.join(tmpdir(), 'agentx-activity-export-'));

/** Plain words a test can look for in every log line. */
const CASE = 'DSP-2026/0418';
const PERSON = '0199a0f0-0000-7000-8000-00000000f701';
const RANGE = { from: new Date('2026-10-18T00:00:00Z'), to: new Date('2026-10-20T00:00:00Z') };

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<ActivityExportTables & ActivityTables>(
    { ...database.connection('app'), maxConnections: 2 },
    testLogger(),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
  mounted.remove();
  rmSync(folder, { recursive: true, force: true });
});

/** A new organisation. */
async function organization(): Promise<string> {
  const orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    app,
    { keys, ids: uuidV7Ids, logger: testLogger() },
    { orgId, name: `Activity Export ${orgId.slice(-6)}`, release: 'r-test', run: null },
  );
  return orgId;
}

let made = 0;
/** A request of the person's, written and arriving at `at`. */
async function requested(orgId: string, at: string): Promise<void> {
  made += 1;
  const id = `${v7Floor(Date.parse(at)).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
  await withTenant(app, orgId, (tx) =>
    tx
      .insertInto('access.requests')
      .values({
        org_id: orgId,
        id,
        recorded_at: new Date(at),
        actor_type: 'user',
        actor_id: PERSON,
        method: 'GET',
        route: '/v1/members',
        path_ids: [],
        status: 200,
        reason: null,
        correlation_id: PERSON,
        duration_ms: 4,
        ip: '94.200.1.7',
        country: 'AE',
        city: null,
        time_zone: null,
        time_zone_from: null,
      })
      .execute(),
  );
}

/** The day sealed as the API's job seals it. */
async function seal(orgId: string, day: string): Promise<void> {
  const digest = await digestOfDay((work) => withTenant(app, orgId, work), orgId, day, 100);
  await withTenant(app, orgId, (tx) =>
    createAuditTrail({ keys, ids: uuidV7Ids }).record(tx, orgId, {
      actor: { type: 'system', id: 'api' },
      action: ACTIVITY_SEALED,
      subject: { type: 'access_log', id: orgId, version: 1 },
      details: {
        day,
        requests: digest.requests,
        digest: digest.digest,
        idFrom: digest.idFrom,
        idTo: digest.idTo,
        form: SEAL_FORM,
      },
    }),
  );
}

const requestFor = (orgId: string, overrides: Partial<CaseExportRequest> = {}): CaseExportRequest => ({
  orgId,
  exportId: uuidV7Ids.next(),
  ...RANGE,
  caseRef: CASE,
  release: 'r-test',
  run: null,
  ...overrides,
});

/** Runs the export, its log captured. */
async function exported(request: CaseExportRequest, mostRequests?: number, batch?: number) {
  const capture = new LogCapture();
  const code = await exportActivityLog(
    app,
    { keys, ids: uuidV7Ids, logger: testLogger(capture) },
    folderStore(folder),
    request,
    mostRequests,
    batch,
  );
  const lines = capture.lines();
  return {
    code,
    text: capture.text,
    events: lines.map((line) => String(line.event)),
    line: (event: string) => lines.find((line) => line.event === event),
  };
}

/** The organisation's events of an action, each its actor and details. */
const eventsOf = (orgId: string, action: string) =>
  withTenant(app, orgId, async (tx) =>
    (
      await tx
        .selectFrom('audit.events')
        .select(['id', 'actor_type', 'actor_id', 'details'])
        .where('action', '=', action)
        .orderBy('seq')
        .execute()
    ).map((row) => ({
      id: row.id,
      actor: `${row.actor_type}:${row.actor_id}`,
      details: JSON.parse(row.details) as unknown,
    })),
  );

const fileOf = (request: CaseExportRequest) =>
  readFileSync(path.join(folder, request.orgId, `activity-${request.exportId}.ndjson`), 'utf8')
    .trimEnd()
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line) as { recordedAt: string; sealed: boolean; client: { ip: string } });

describe('L7 the operator exports an activity log for a case (ADR-005 §6)', () => {
  it('records it on both chains and tells the admins, then writes the range’s requests, newest first', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-17T23:00:00.000Z');
    await requested(orgId, '2026-10-18T09:00:00.000Z');
    await requested(orgId, '2026-10-19T09:00:00.000Z');
    await requested(orgId, '2026-10-20T09:00:00.000Z');
    await seal(orgId, '2026-10-18');
    const request = requestFor(orgId);

    const run = await exported(request);

    expect(run.code).toBe(0);
    expect(run.text).not.toContain(CASE);
    expect(run.line('operator.activity_exported')).toMatchObject({
      exportId: request.exportId,
      requests: 2,
      recordedBefore: false,
      write: 'written',
      file: `${orgId}/activity-${request.exportId}.ndjson`,
    });
    expect(fileOf(request).map((line) => line.recordedAt)).toEqual([
      '2026-10-19T09:00:00.000Z',
      '2026-10-18T09:00:00.000Z',
    ]);
    expect(await eventsOf(orgId, 'access_log.exported')).toEqual([
      {
        id: request.exportId,
        actor: 'system:operator',
        details: expect.objectContaining({ caseRef: CASE, requests: 2, format: 'ndjson' }) as unknown,
      },
    ]);
    const notices = await withTenant(app, orgId, (tx) =>
      tx
        .selectFrom('notifications.outbox')
        .select(['kind', 'about_id'])
        .where('kind', '=', 'access_log_exported')
        .execute(),
    );
    expect(notices).toEqual([{ kind: 'access_log_exported', about_id: request.exportId }]);
    const platform = await database
      .as('owner')
      .query<{ details: string }>(
        `select details from platform_controls.audit_events where action = 'operator.access_log_exported'`,
      );
    expect(platform.filter((row) => row.details.includes(request.exportId))).toHaveLength(1);
  });

  it('L6c-2 marks each request sealed or not, every batch against the seal the first one read', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-18T09:00:00.000Z');
    await requested(orgId, '2026-10-19T09:00:00.000Z');
    await seal(orgId, '2026-10-18');
    const request = requestFor(orgId);

    expect((await exported(request, undefined, 1)).code).toBe(0);
    expect(fileOf(request).map((line) => [line.recordedAt, line.sealed])).toEqual([
      ['2026-10-19T09:00:00.000Z', false],
      ['2026-10-18T09:00:00.000Z', true],
    ]);
  });

  it('holds the range’s first day to its seal too', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-18T09:00:00.000Z');
    await seal(orgId, '2026-10-18');
    await database.as('admin').query('update access.requests set status = 500 where org_id = $1', [orgId]);

    expect((await exported(requestFor(orgId))).code).toBe(1);
  });

  it('writes, when run again, only the requests written by the time it was recorded', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-18T09:00:00.000Z');
    const request = requestFor(orgId);
    const failing = await exportActivityLog(
      app,
      { keys, ids: uuidV7Ids, logger: testLogger() },
      { put: () => Promise.reject(new Error('the store is down')) },
      request,
    );
    expect(failing).toBe(1);
    // Written after the export was recorded: in its range, but not in its file.
    await requested(orgId, '2026-10-19T09:00:00.000Z');

    const again = await exported(request);

    expect(again.line('operator.activity_exported')).toMatchObject({ recordedBefore: true, requests: 1 });
    expect(fileOf(request).map((line) => line.recordedAt)).toEqual(['2026-10-18T09:00:00.000Z']);
  });

  it('writes no file for a range with a sealed day tampered with, and holds the organisation', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-19T09:00:00.000Z');
    await seal(orgId, '2026-10-19');
    await database.as('admin').query('update access.requests set status = 500 where org_id = $1', [orgId]);
    const request = requestFor(orgId);

    const run = await exported(request);

    expect(run.code).toBe(1);
    expect(run.line('operator.export_unwritten')).toMatchObject({
      exportId: request.exportId,
      problems: ["the activity log of 2026-10-19 doesn't hold to its seal"],
    });
    expect(run.events).toEqual(expect.arrayContaining(['audit.integrity_failed', 'audit.integrity_hold_set']));
    expect(() => fileOf(request)).toThrow();
  });

  it('checks only the seals of the days the range touches, and the day after its last', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-15T09:00:00.000Z');
    await seal(orgId, '2026-10-15');
    // A day outside the range tampered with: not this export's to find.
    await database.as('admin').query('update access.requests set status = 500 where org_id = $1', [orgId]);

    expect((await exported(requestFor(orgId))).code).toBe(0);
    expect(
      (
        await exported(
          requestFor(orgId, { from: new Date('2026-10-14T00:00:00Z'), to: new Date('2026-10-15T00:00:00Z') }),
        )
      ).code,
    ).toBe(1);
  });

  it('records nothing twice for a request run again, and refuses its ID for another case', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-19T09:00:00.000Z');
    const request = requestFor(orgId);

    await exported(request);
    const again = await exported(request);
    const other = await exported({ ...request, caseRef: 'DSP-2026/0419' });

    expect(again.line('operator.activity_exported')).toMatchObject({ recordedBefore: true, write: 'there_already' });
    expect(other.line('operator.refused')).toMatchObject({
      problems: ['the export ID names another record: write a new request'],
    });
    expect(await eventsOf(orgId, 'access_log.exported')).toHaveLength(1);
  });

  it('refuses a range holding more than its cap, and an organisation that doesn’t exist, recording nothing', async () => {
    const orgId = await organization();
    await requested(orgId, '2026-10-19T09:00:00.000Z');
    await requested(orgId, '2026-10-19T10:00:00.000Z');

    const large = await exported(requestFor(orgId), 1);
    const missing = await exported(requestFor(uuidV7Ids.next()));

    expect(large.line('operator.refused')).toMatchObject({
      problems: ['the range holds more than 1 requests: export it in parts, each its own request'],
    });
    expect(missing.line('operator.refused')).toMatchObject({ problems: ['no organisation has this ID'] });
    expect(await eventsOf(orgId, 'access_log.exported')).toEqual([]);
  });
});
