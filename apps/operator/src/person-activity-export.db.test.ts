// CO8b: the operator's export of one person's own activity log for a case,
// against a real Postgres, as the operator's own role (0092): recorded on the
// platform chain first, where the person's My activity page reads it
// (operatorExportsOf, D2); every sealed day the range touches held to its seal
// before a byte is written (a row changed past the app, the person's or anyone
// else's that day, a seal that can't be believed, a row before the first seal:
// the alarm, and no file); days past the newest seal said and marked unsealed;
// the person's rows alone in the file; the range's cap refused with nothing
// recorded; and a request run again recording nothing twice. The person log
// is one global table, so each test has a database of its own.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  type ActivityTables,
  PERSON_SEAL_FORM,
  PERSON_SEALED,
  personDigestOfDay,
  v7Floor,
} from '@agentx/core/modules/activity';
import { OPERATOR_PERSON_LOG_EXPORTED, operatorExportsOf } from '@agentx/core/modules/evidence';
import type { IdentityTables } from '@agentx/core/modules/identity';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { createTestDatabase, LogCapture, type TestDatabase, testLogger, writeTestKeys } from '@agentx/testing';
import { afterAll, afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { ANOTHER_RECORD } from './case-export.ts';
import { folderStore } from './evidence-store.ts';
import {
  exportPersonActivityLog,
  type PersonActivityExportLimits,
  type PersonActivityExportRequest,
  type PersonActivityExportTables,
} from './person-activity-export.ts';

type Tables = ActivityTables & PlatformControlsTables & IdentityTables;

const server = inject('postgres');
const PURPOSES = ['audit-mac', 'field-encryption', 'operator-signing', 'audit-rebase'] as const;
const mounted = writeTestKeys(PURPOSES);
const keys = loadKeys({ directory: mounted.directory, current: {} }, PURPOSES);
const folder = mkdtempSync(path.join(tmpdir(), 'agentx-person-export-'));
let database: TestDatabase;
let app: Database<Tables>;
/** The operator's command's own role (PL-57), as the job connects: every export below runs as it. */
let operator: Database<PersonActivityExportTables>;

/** Plain words a test can look for in every log line. */
const CASE = 'DSP-2026/0420';
const ANA = '0199a0f0-0000-7000-8000-00000000a0a0';
const BEN = '0199a0f0-0000-7000-8000-00000000b0b0';
const CORRELATION = '0199a0f0-0000-7000-8000-0000000c08b0';
const API = { type: 'system', id: 'api' } as const;
const RANGE = { from: new Date('2026-10-18T00:00:00Z'), to: new Date('2026-10-20T00:00:00Z') };

let made = 0;
/** A request of `userId`'s, written and arriving at `at`. */
async function written(userId: string, at: string): Promise<string> {
  made += 1;
  const id = `${v7Floor(Date.parse(at)).slice(0, 14)}7000-8000-${made.toString(16).padStart(12, '0')}`;
  await app
    .insertInto('access.person_requests')
    .values({
      id,
      recorded_at: new Date(at),
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

/** Each day sealed in turn, as the API's job seals it. */
async function sealed(...days: readonly string[]): Promise<void> {
  for (const day of days) {
    const digest = await personDigestOfDay((work) => app.transaction().execute(work), day, 100);
    await createPlatformChain({ keys, ids: uuidV7Ids }).recordAlone(app, {
      actor: API,
      action: PERSON_SEALED,
      details: {
        day,
        requests: digest.requests,
        digest: digest.digest,
        idFrom: digest.idFrom,
        idTo: digest.idTo,
        form: PERSON_SEAL_FORM,
      },
    });
  }
}

const requestFor = (overrides: Partial<PersonActivityExportRequest> = {}): PersonActivityExportRequest => ({
  userId: ANA,
  exportId: uuidV7Ids.next(),
  ...RANGE,
  caseRef: CASE,
  release: 'r-test',
  run: null,
  ...overrides,
});

/** Runs the export as the operator's role, its log captured. */
async function exported(request: PersonActivityExportRequest, limits?: PersonActivityExportLimits) {
  const capture = new LogCapture();
  const code = await exportPersonActivityLog(
    operator,
    { keys, logger: testLogger(capture) },
    folderStore(folder),
    request,
    limits,
  );
  const lines = capture.lines();
  return {
    code,
    text: capture.text,
    events: lines.map((line) => String(line.event)),
    line: (event: string) => lines.find((line) => line.event === event),
    alarms: lines.filter((line) => line.event === 'audit.integrity_failed' && line.check === 'person_log'),
  };
}

const fileName = (request: PersonActivityExportRequest) =>
  path.join(folder, 'persons', request.userId, `activity-${request.exportId}.ndjson`);

/** The file's lines, each as the person's own download holds it. */
const fileOf = (request: PersonActivityExportRequest) =>
  readFileSync(fileName(request), 'utf8')
    .trimEnd()
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line) as { id: string; recordedAt: string; sealed: boolean });

/** The platform chain's records of our exports of a person's log, each its ID and details. */
const records = async () =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select(['id', 'actor_type', 'actor_id', 'details'])
      .where('action', '=', OPERATOR_PERSON_LOG_EXPORTED)
      .orderBy('seq')
      .execute()
  ).map((row) => ({
    id: row.id,
    actor: `${row.actor_type}:${row.actor_id}`,
    details: JSON.parse(row.details) as Record<string, unknown>,
  }));

/** What the person's own My activity page lists: Agent X's exports of their log (my-activity.ts's read). */
const listedFor = async (userId: string) => {
  const listed = await app.transaction().execute((tx) => operatorExportsOf(tx, keys, userId, 20));
  if (listed === 'unsealed') throw new Error('the listing could not be believed');
  return listed.map(({ id, details }) => ({ id, caseRef: details.caseRef, requests: details.requests }));
};

const admin = () => database.as('admin');

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
  operator = createDatabase<PersonActivityExportTables>(
    { ...database.connection('operator'), maxConnections: 2 },
    testLogger(),
  );
  for (const [id, subject] of [
    [ANA, 'ana'],
    [BEN, 'ben'],
  ] as const) {
    await app
      .insertInto('identity.users')
      .values({ id, issuer: 'https://login.example.test', subject, created_at: new Date('2026-10-01T00:00:00Z') })
      .execute();
  }
});

afterEach(async () => {
  await app.destroy();
  await operator.destroy();
  await database.drop();
});

afterAll(() => {
  mounted.remove();
  rmSync(folder, { recursive: true, force: true });
});

describe("CO8b the operator exports one person's own activity log for a case", () => {
  it('records it first where the person is shown it, then writes their rows of the range alone, newest first', async () => {
    await written(ANA, '2026-10-17T23:00:00.000Z');
    const first = await written(ANA, '2026-10-18T09:00:00.000Z');
    await written(BEN, '2026-10-18T10:00:00.000Z');
    const second = await written(ANA, '2026-10-19T09:00:00.000Z');
    await written(ANA, '2026-10-20T09:00:00.000Z');
    await sealed('2026-10-17', '2026-10-18', '2026-10-19', '2026-10-20');
    const request = requestFor();

    const run = await exported(request);

    expect(run.code).toBe(0);
    expect(run.text).not.toContain(CASE);
    expect(run.alarms).toEqual([]);
    expect(run.line('operator.person_activity_exported')).toMatchObject({
      exportId: request.exportId,
      requests: 2,
      writtenUpTo: second,
      recordedBefore: false,
      write: 'written',
      file: `persons/${ANA}/activity-${request.exportId}.ndjson`,
    });
    expect(run.line('operator.person_log_seals')).toMatchObject({ sealedThrough: '2026-10-20', unsealedFrom: null });
    expect(fileOf(request).map(({ id, sealed }) => ({ id, sealed }))).toEqual([
      { id: second, sealed: true },
      { id: first, sealed: true },
    ]);
    expect(await records()).toEqual([
      {
        id: request.exportId,
        actor: 'system:operator',
        details: {
          person: ANA,
          exportId: request.exportId,
          caseRef: CASE,
          from: RANGE.from.toISOString(),
          to: RANGE.to.toISOString(),
          requests: 2,
          writtenUpTo: second,
          release: 'r-test',
          run: null,
        },
      },
    ]);
    // D2: the person's own page lists it, and no one else's does.
    expect(await listedFor(ANA)).toEqual([{ id: request.exportId, caseRef: CASE, requests: 2 }]);
    expect(await listedFor(BEN)).toEqual([]);
  });

  it('says the days past the newest seal, and marks their rows unsealed', async () => {
    const sealedRow = await written(ANA, '2026-10-19T09:00:00.000Z');
    const open = await written(ANA, '2026-10-21T09:00:00.000Z');
    await sealed('2026-10-19');
    const request = requestFor({ from: new Date('2026-10-19T00:00:00Z'), to: new Date('2026-10-23T00:00:00Z') });

    const run = await exported(request);

    expect(run.code).toBe(0);
    expect(run.line('operator.person_log_seals')).toMatchObject({
      sealedThrough: '2026-10-19',
      unsealedFrom: '2026-10-20',
    });
    expect(fileOf(request).map(({ id, sealed }) => ({ id, sealed }))).toEqual([
      { id: open, sealed: false },
      { id: sealedRow, sealed: true },
    ]);
  });

  it('with no seal yet, or a range wholly newer than every seal, calls the whole range unsealed', async () => {
    await written(ANA, '2026-10-18T09:00:00.000Z');
    const none = await exported(requestFor());
    await sealed('2026-10-18');
    const later = requestFor({ from: new Date('2026-10-25T00:00:00Z'), to: new Date('2026-10-27T00:00:00Z') });
    const newer = await exported(later);

    expect(none.code).toBe(0);
    expect(none.line('operator.person_log_seals')).toMatchObject({ sealedThrough: null, unsealedFrom: '2026-10-18' });
    expect(newer.code).toBe(0);
    expect(newer.line('operator.person_log_seals')).toMatchObject({
      sealedThrough: '2026-10-18',
      unsealedFrom: '2026-10-25',
    });
    expect(newer.line('operator.person_activity_exported')).toMatchObject({ requests: 0 });
    expect(fileOf(later)).toEqual([]);
  });

  it('reads the seals a page at a time, past the newer ones, to the range', async () => {
    const days = Array.from({ length: 8 }, (_, index) => `2026-10-${String(13 + index)}`);
    for (const day of days) await written(ANA, `${day}T09:00:00.000Z`);
    await sealed(...days);

    const run = await exported(
      requestFor({ from: new Date('2026-10-14T00:00:00Z'), to: new Date('2026-10-15T00:00:00Z') }),
      { sealsAPage: 2, batch: 1 },
    );

    expect(run.code).toBe(0);
    expect(run.line('operator.person_activity_exported')).toMatchObject({ requests: 1 });
    expect(run.line('operator.person_log_seals')).toMatchObject({ sealedThrough: '2026-10-20', unsealedFrom: null });
  });
});

describe('CO8b every sealed day of the range is held to its seal before the file', () => {
  /** Two days sealed, ANA's and BEN's rows on the first of the range. */
  async function sealedRange() {
    await written(ANA, '2026-10-17T09:00:00.000Z');
    const anas = await written(ANA, '2026-10-18T09:00:00.000Z');
    const bens = await written(BEN, '2026-10-18T10:00:00.000Z');
    await written(ANA, '2026-10-19T09:00:00.000Z');
    await sealed('2026-10-17', '2026-10-18', '2026-10-19');
    return { anas, bens };
  }

  /** The run refused after its record: the alarm for `day` and `why`, no file, the record still there. */
  async function refusedFor(request: PersonActivityExportRequest, day: string | null, why: string) {
    const run = await exported(request);

    expect(run.code).toBe(1);
    expect(run.alarms).toEqual([expect.objectContaining({ chain: 'platform', reason: why, day })]);
    expect(run.events).not.toContain('operator.person_activity_exported');
    expect(run.line('operator.export_unwritten')).toMatchObject({ exportId: request.exportId });
    expect(() => readFileSync(fileName(request))).toThrow();
    return run;
  }

  it("refuses a day whose row was changed past the app, the person's own", async () => {
    const { anas } = await sealedRange();
    await admin().query('update access.person_requests set status = 500 where id = $1', [anas]);

    const run = await refusedFor(requestFor(), '2026-10-18', 'digest');

    expect(run.line('operator.export_unwritten')?.problems).toEqual([
      "the person log of 2026-10-18 doesn't hold to its seal",
    ]);
  });

  it("refuses a day whose row of someone else's was deleted: the seal holds the whole day", async () => {
    const { bens } = await sealedRange();
    await admin().query('delete from access.person_requests where id = $1', [bens]);

    await refusedFor(requestFor(), '2026-10-18', 'digest');
  });

  /** A day's seal deleted past the app. */
  const sealGone = (day: string) =>
    admin().query("delete from platform_controls.audit_events where action = $1 and details like '%' || $2 || '%'", [
      PERSON_SEALED,
      day,
    ]);

  it.each([
    ['inside the range', '2026-10-19', '2026-10-18', { to: new Date('2026-10-21T00:00:00Z') }],
    ['on its first day, an older seal kept', '2026-10-18', '2026-10-17', {}],
    ['on its last, a newer seal kept', '2026-10-20', '2026-10-19', {}],
  ])('refuses a seal missing %s', async (_where, gone, day, range) => {
    await written(ANA, '2026-10-17T09:00:00.000Z');
    await written(ANA, '2026-10-18T09:00:00.000Z');
    await sealed('2026-10-17', '2026-10-18', '2026-10-19', '2026-10-20', '2026-10-21', '2026-10-22');
    await sealGone(gone);

    await refusedFor(requestFor(range), day, 'gap');
  });

  it("refuses a seal whose record can't be believed", async () => {
    await sealedRange();
    await admin().query(
      "update platform_controls.audit_events set details = replace(details, '2026-10-18', '2099-01-01') where action = $1 and details like '%2026-10-18%'",
      [PERSON_SEALED],
    );

    await refusedFor(requestFor(), null, 'unsealed');
  });

  it('refuses a row written before the first seal, in a range older than every seal', async () => {
    await sealedRange();
    await written(BEN, '2026-10-02T09:00:00.000Z');

    await refusedFor(
      requestFor({ from: new Date('2026-10-01T00:00:00Z'), to: new Date('2026-10-05T00:00:00Z') }),
      '2026-10-17',
      'before',
    );
  });

  it('writes the file once every day holds, a range older than every seal included', async () => {
    await sealedRange();

    const run = await exported(
      requestFor({ from: new Date('2026-10-01T00:00:00Z'), to: new Date('2026-10-05T00:00:00Z') }),
    );

    expect(run.code).toBe(0);
    expect(run.alarms).toEqual([]);
  });
});

describe('CO8b what the export refuses, recording nothing', () => {
  it('refuses a range past the cap, as a person’s own download is', async () => {
    await written(ANA, '2026-10-18T09:00:00.000Z');
    await written(ANA, '2026-10-19T09:00:00.000Z');
    const request = requestFor();

    const over = await exported(request, { mostRequests: 1 });
    const at = await exported(requestFor(), { mostRequests: 2 });

    expect(over.code).toBe(1);
    expect(over.line('operator.refused')).toMatchObject({
      exportId: request.exportId,
      problems: ["the range holds more than 1 of the person's requests: export it in parts, each its own request"],
    });
    expect(over.text).not.toContain(CASE);
    expect(() => readFileSync(fileName(request))).toThrow();
    expect(at.code).toBe(0);
    expect((await records()).map(({ id }) => id)).not.toContain(request.exportId);
  });

  it('refuses a person Agent X doesn’t know', async () => {
    const request = requestFor({ userId: '0199a0f0-0000-7000-8000-00000000c0c0' });

    const run = await exported(request);

    expect(run.code).toBe(1);
    expect(run.line('operator.refused')?.problems).toEqual(['no person has this user ID']);
    expect(await records()).toEqual([]);
  });

  it('run again, records nothing twice and leaves the file as it was', async () => {
    await written(ANA, '2026-10-18T09:00:00.000Z');
    const request = requestFor();

    const first = await exported(request);
    const again = await exported(request);

    expect(first.code).toBe(0);
    expect(again.code).toBe(0);
    expect(again.line('operator.person_activity_exported')).toMatchObject({
      requests: 1,
      recordedBefore: true,
      write: 'there_already',
    });
    expect(await records()).toHaveLength(1);
  });

  it('refuses an export ID naming another case, another person, or another record', async () => {
    await written(ANA, '2026-10-18T09:00:00.000Z');
    const request = requestFor();
    await exported(request);

    for (const other of [
      { ...request, caseRef: 'DSP-2026/0421' },
      { ...request, userId: BEN },
      { ...request, from: new Date('2026-10-17T00:00:00Z') },
    ]) {
      const run = await exported(other);
      expect(run.code).toBe(1);
      expect(run.line('operator.refused')?.problems).toEqual([ANOTHER_RECORD]);
    }
    await sealed('2026-10-18');
    const seal = await app
      .selectFrom('platform_controls.audit_events')
      .select('id')
      .where('action', '=', PERSON_SEALED)
      .executeTakeFirstOrThrow();
    const onSeal = await exported(requestFor({ exportId: seal.id }));
    expect(onSeal.line('operator.refused')?.problems).toEqual([ANOTHER_RECORD]);
    expect(await records()).toHaveLength(1);
  });

  it("refuses an export ID whose record can't be believed, raising the alarm", async () => {
    await written(ANA, '2026-10-18T09:00:00.000Z');
    const request = requestFor();
    await exported(request);
    await admin().query(
      "update platform_controls.audit_events set details = replace(details, 'r-test', 'r-else') where id = $1",
      [request.exportId],
    );

    const run = await exported(request);

    expect(run.code).toBe(1);
    expect(run.line('operator.refused')?.problems).toEqual([
      "the platform audit chain's record of this export ID can't be verified",
    ]);
    expect(run.alarms).toEqual([expect.objectContaining({ reason: 'unsealed', day: null })]);
  });
});
