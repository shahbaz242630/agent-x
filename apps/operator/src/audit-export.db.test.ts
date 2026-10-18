// Phase 3 E10c: the operator's audit export for a case against a real
// Postgres (Rule Book §6; ADR-005 §6): recorded on both chains and told to
// the admins before the log is read out; the file the whole range up to the
// recorded seq, as an admin's NDJSON download holds it; a request run again
// writing a file that wasn't, recording nothing twice; and what it refuses,
// with nothing recorded. The run itself, from its request file, is
// main.db.test.ts.
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { type AuditExportRequest, type AuditExportTables, exportAuditLog } from './audit-export.ts';
import { createOrganizationAsOperator } from './create-organization.ts';
import { type EvidenceStore, folderStore } from './evidence-store.ts';

const server = inject('postgres');
const mounted = writeTestKeys(['audit-mac', 'field-encryption']);
const keys = loadKeys({ directory: mounted.directory, current: {} }, ['audit-mac', 'field-encryption']);
let database: TestDatabase;
let app: Database<AuditExportTables>;
const folder = mkdtempSync(path.join(tmpdir(), 'agentx-audit-export-'));

/** Plain words a test can look for in every log line. */
const CASE = 'DSP-2026/0417';
const EVER = { from: new Date('2000-01-01T00:00:00Z'), to: new Date('2100-01-01T00:00:00Z') };

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<AuditExportTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
  mounted.remove();
  rmSync(folder, { recursive: true, force: true });
});

/** A new organisation, with `extra` events of its own after its creation's two (it, and its hold, clear). */
async function organization(extra = 0): Promise<string> {
  const orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    app,
    { keys, ids: uuidV7Ids, logger: testLogger() },
    { orgId, name: `Export Test ${orgId.slice(-6)}`, release: 'r-test', run: null },
  );
  const trail = createAuditTrail({ keys, ids: uuidV7Ids });
  for (let n = 0; n < extra; n += 1) {
    await withTenant(app, orgId, (tx) =>
      trail.record(tx, orgId, {
        actor: { type: 'system', id: 'api' },
        action: 'probe.noted',
        subject: { type: 'probe', id: orgId, version: 1 },
        details: { n },
      }),
    );
  }
  return orgId;
}

const requestFor = (orgId: string, overrides: Partial<AuditExportRequest> = {}): AuditExportRequest => ({
  orgId,
  exportId: uuidV7Ids.next(),
  ...EVER,
  caseRef: CASE,
  release: 'r-test',
  run: null,
  ...overrides,
});

/** Runs the export, its log captured. */
async function exported(request: AuditExportRequest, store: EvidenceStore = folderStore(folder), mostEvents?: number) {
  const capture = new LogCapture();
  const code = await exportAuditLog(
    app,
    { keys, ids: uuidV7Ids, logger: testLogger(capture) },
    store,
    request,
    mostEvents,
  );
  const lines = capture.lines();
  return {
    code,
    text: capture.text,
    events: lines.map((line) => String(line.event)),
    line: (event: string) => lines.find((line) => line.event === event),
  };
}

/** The organisation's events, in chain order, its actor and action each. */
const eventsOf = (orgId: string) =>
  withTenant(app, orgId, (tx) =>
    tx.selectFrom('audit.events').select(['seq', 'id', 'actor_type', 'actor_id', 'action']).orderBy('seq').execute(),
  );

/** The admins' notices about an export. */
const noticesOf = (orgId: string) =>
  withTenant(app, orgId, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['kind', 'about_id', 'recipient_user_id'])
      .where('org_id', '=', orgId)
      .where('kind', '=', 'audit_log_exported')
      .execute(),
  );

/** The platform chain's export events naming this organisation. */
const platformExportsOf = async (orgId: string) =>
  (
    await database
      .as('owner')
      .query<{ details: string }>(
        `select details from platform_controls.audit_events where action = 'operator.audit_log_exported'`,
      )
  ).filter((row) => row.details.includes(orgId));

/** Changes one of the organisation's events past the app, as the owner, as the tenant wall holds even it. */
async function tamperEvent(orgId: string, seq: number): Promise<void> {
  const owner = await database.connect('owner');
  try {
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [orgId]);
    await owner.query(`update audit.events set details = '{"n":9}' where org_id = $1 and seq = $2`, [orgId, seq]);
  } finally {
    await owner.end();
  }
}

const fileOf = (request: AuditExportRequest) =>
  readFileSync(path.join(folder, request.orgId, `${request.exportId}.ndjson`), 'utf8');

describe(`E10c the operator's audit export for a case (Postgres ${server.version})`, () => {
  it('records it on both chains and tells the admins first, then writes the whole range up to it, never logging the case', async () => {
    const orgId = await organization(3);
    const before = await eventsOf(orgId);
    const request = requestFor(orgId);

    const { code, text, events, line } = await exported(request);

    expect(code).toBe(0);
    expect(events).toEqual(['operator.audit_exported']);
    const after = await eventsOf(orgId);
    expect(after).toHaveLength(before.length + 1);
    expect(after.at(-1)).toMatchObject({
      id: request.exportId,
      actor_type: 'system',
      actor_id: 'operator',
      action: 'audit_log.exported',
    });
    expect(await noticesOf(orgId)).toEqual([
      { kind: 'audit_log_exported', about_id: request.exportId, recipient_user_id: null },
    ]);
    expect(await platformExportsOf(orgId)).toHaveLength(1);
    const lines = fileOf(request)
      .trimEnd()
      .split('\n')
      .map((each) => JSON.parse(each) as Record<string, unknown>);
    // Every event before the export's own record, newest first; the record itself is past its seq.
    expect(lines.map((each) => each.id)).toEqual(before.map((each) => each.id).reverse());
    expect(lines[0]).toMatchObject({
      actor: { type: 'system', id: 'api', name: 'Agent X', email: null, shownFrom: 'agent_x' },
      details: { n: 2 },
    });
    expect(line('operator.audit_exported')).toMatchObject({
      orgId,
      exportId: request.exportId,
      events: before.length,
      upToSeq: String(before.at(-1)?.seq),
      recordedBefore: false,
      write: 'written',
      file: `${orgId}/${request.exportId}.ndjson`,
      sha256: createHash('sha256').update(fileOf(request)).digest('hex'),
    });
    expect(text).not.toContain(CASE);
  });

  it('seals the case reference and the range in the organisation’s record, as the admins read it', async () => {
    const orgId = await organization();
    const request = requestFor(orgId, {
      from: new Date('2026-01-01T00:00:00Z'),
      to: new Date('2100-01-01T00:00:00Z'),
    });

    await exported(request);

    const found = await withTenant(app, orgId, (tx) =>
      createAuditTrail({ keys, ids: uuidV7Ids }).recordedEvent(tx, orgId, { eventId: request.exportId }),
    );
    expect(found).toMatchObject({
      kind: 'recorded',
      event: {
        details: {
          caseRef: CASE,
          from: '2026-01-01T00:00:00.000Z',
          to: '2100-01-01T00:00:00.000Z',
          actions: null,
          format: 'ndjson',
          events: 2,
        },
      },
    });
  });

  it('writes the file a failed run left unwritten when run again, recording and telling nothing twice', async () => {
    const orgId = await organization(1);
    const request = requestFor(orgId);
    const failing: EvidenceStore = { put: () => Promise.reject(new Error('the store is away')) };

    const first = await exported(request, failing);
    const recorded = await eventsOf(orgId);
    const second = await exported(request);
    const third = await exported(request);

    expect(first.code).toBe(1);
    expect(first.line('operator.export_unwritten')).toMatchObject({
      exportId: request.exportId,
      recordedBefore: false,
    });
    expect(second.code).toBe(0);
    expect(second.line('operator.audit_exported')).toMatchObject({ recordedBefore: true, write: 'written' });
    expect(third.line('operator.audit_exported')).toMatchObject({ recordedBefore: true, write: 'there_already' });
    // No hash of a file this run didn't write.
    expect(third.line('operator.audit_exported')).not.toHaveProperty('sha256');
    expect(third.line('operator.audit_exported')).not.toHaveProperty('bytes');
    expect(await eventsOf(orgId)).toEqual(recorded);
    expect(await noticesOf(orgId)).toHaveLength(1);
    expect(await platformExportsOf(orgId)).toHaveLength(1);
    // The same events, to the same seq: the record's, not the log's newest.
    expect(fileOf(request).trimEnd().split('\n')).toHaveLength(recorded.length - 1);
  });

  it.each([
    ['another case', { caseRef: 'DSP-2026/0418' }],
    ['another start', { from: new Date('2001-01-01T00:00:00Z') }],
    ['another end', { to: new Date('2099-01-01T00:00:00Z') }],
  ])('refuses the same export ID for %s, recording nothing', async (_what, change) => {
    const orgId = await organization();
    const request = requestFor(orgId);
    await exported(request);
    const recorded = await eventsOf(orgId);

    const again = await exported({ ...request, ...change });

    expect(again.code).toBe(1);
    expect(again.line('operator.refused')?.problems).toEqual([
      'the export ID names another record: write a new request',
    ]);
    expect(await eventsOf(orgId)).toEqual(recorded);
  });

  it('refuses an export ID that names another kind of record, recording nothing', async () => {
    const orgId = await organization();
    const [created] = await eventsOf(orgId);

    const { code, line } = await exported(requestFor(orgId, { exportId: String(created?.id) }));

    expect(code).toBe(1);
    expect(line('operator.refused')?.problems).toEqual(['the export ID names another record: write a new request']);
    expect(await eventsOf(orgId)).toHaveLength(2);
  });

  it('refuses an export ID another organisation’s export has, recording and telling nothing', async () => {
    const first = requestFor(await organization());
    await exported(first);
    const orgId = await organization();

    const { code, line } = await exported({ ...first, orgId });

    expect(code).toBe(1);
    expect(line('operator.refused')?.problems).toEqual(['the export ID names another record: write a new request']);
    expect(await eventsOf(orgId)).toHaveLength(2);
    expect(await noticesOf(orgId)).toEqual([]);
    expect(await platformExportsOf(orgId)).toEqual([]);
  });

  it('refuses a range past the most events one export holds, recording nothing, and takes one at it', async () => {
    const orgId = await organization(2);

    // Four events: its creation's two, and two more.
    const over = await exported(requestFor(orgId), folderStore(folder), 3);
    const at = await exported(requestFor(orgId), folderStore(folder), 4);

    expect(over.line('operator.refused')?.problems).toEqual([
      'the range holds more than 3 events: export it in parts, each its own request',
    ]);
    expect(at.code).toBe(0);
    expect(await eventsOf(orgId)).toHaveLength(5);
  });

  it('refuses an organisation that isn’t there, recording nothing', async () => {
    const { code, line } = await exported(requestFor(uuidV7Ids.next()));

    expect(code).toBe(1);
    expect(line('operator.refused')?.problems).toEqual(['no organisation has this ID']);
  });

  it('writes no file over an event that can’t be believed, and holds the organisation', async () => {
    // The event tampered with isn't the head, which the record checks as it links to it.
    const orgId = await organization(2);
    await tamperEvent(orgId, 2);
    const request = requestFor(orgId);

    const { code, line } = await exported(request);

    expect(code).toBe(1);
    expect(line('operator.export_unwritten')?.problems).toEqual([
      "an event in the range, or an agent it names, can't be verified",
    ]);
    expect(() => fileOf(request)).toThrow();
    const hold = await withSignedStates(app, orgId, { keys, ids: uuidV7Ids, logger: testLogger() }, (tx, states) =>
      states.holdRecord(tx, orgId),
    );
    expect(hold).toMatchObject({ outcome: 'held' });
  });

  it('exports an empty range: no events, an empty file, and the same again when run again', async () => {
    const orgId = await organization();
    const request = requestFor(orgId, { from: new Date('2099-01-01T00:00:00Z'), to: new Date('2099-12-31T00:00:00Z') });

    const first = await exported(request);
    const again = await exported(request);

    expect(first.line('operator.audit_exported')).toMatchObject({ events: 0, upToSeq: null, write: 'written' });
    expect(again.line('operator.audit_exported')).toMatchObject({
      events: 0,
      upToSeq: null,
      recordedBefore: true,
      write: 'there_already',
    });
    expect(fileOf(request)).toBe(String.fromCharCode(10));
  });

  it('refuses an organisation whose records can’t be verified, recording nothing', async () => {
    const orgId = await organization();
    const owner = await tamperAsOwner(database, ORGANIZATIONS, orgId);
    try {
      await owner.setColumn(orgId, 'status', 'FROZEN');
    } finally {
      await owner.end();
    }

    const { code, line } = await exported(requestFor(orgId));

    expect(code).toBe(1);
    expect(line('operator.refused')?.problems).toEqual(["the organisation's records can't be verified"]);
    // Its hold is recorded (the alarm); the export isn't.
    expect((await eventsOf(orgId)).map((each) => each.action)).not.toContain('audit_log.exported');
    expect(await noticesOf(orgId)).toEqual([]);
  });

  it('refuses an export ID whose record can’t be verified, recording nothing', async () => {
    const orgId = await organization(1);
    await tamperEvent(orgId, 2);
    const [, tampered] = await eventsOf(orgId);

    const { code, line } = await exported(requestFor(orgId, { exportId: String(tampered?.id) }));

    expect(code).toBe(1);
    expect(line('operator.refused')?.problems).toEqual(["the organisation's audit log can't be verified"]);
    expect(await eventsOf(orgId)).toHaveLength(3);
  });

  it('says a failure that is no refusal failed, naming the export', async () => {
    const request = requestFor('not-an-id');

    const { code, line } = await exported(request);

    expect(code).toBe(1);
    expect(line('operator.failed')).toMatchObject({ command: 'audit-export', exportId: request.exportId });
  });
});
