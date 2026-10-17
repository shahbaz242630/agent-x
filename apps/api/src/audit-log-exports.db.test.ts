// Phase 3 E10b: downloading the organisation's audit log, composed in the API,
// on the real migrated schema as the app role: the download recorded before
// its file is read, the file its events up to that seq in either format, the
// platform's seals left out and formula cells made text; a retry answering
// the same file; the cap, the hourly budget, a member not an admin; and an
// event that can't be believed refusing the file, the organisation held.
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
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
  AUDIT_LOG_EXPORTED,
  type AuditLogExports,
  createAuditLogExports,
  EXPORT_OPERATION,
  EXPORTS_LOCK,
  type ExportAsked,
  type ExportWrite,
} from './audit-log-exports.ts';
import {
  keys,
  mandateWorld,
  type MandateWorldTables,
  OPERATOR,
  refused,
  type World,
} from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xe10b_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000e10b0';
const EVER = { from: new Date('2000-01-01T00:00:00Z'), to: new Date('2100-01-01T00:00:00Z') };
const trail = createAuditTrail({ keys, ids });

let clock: FixedClock;
let exports: AuditLogExports;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'audit-log-exports' });
const { world, quiet, keyed, member } = shared;

const asked = (format: ExportAsked['format'], actions?: readonly string[]): ExportAsked => ({
  ...EVER,
  actions,
  format,
});

const fileOf = (write: ExportWrite) => {
  if (write.outcome !== 'exported') throw new Error(`not exported: ${JSON.stringify(write)}`);
  return write.file;
};

/** An event of the organisation's own, recorded through the trail with the app's keys, as a use case would. */
const noted = (w: World, details: Readonly<Record<string, string | number>>) =>
  withTenant(app, w.org, (tx) =>
    trail.record(tx, w.org, {
      actor: OPERATOR,
      action: 'probe.noted',
      subject: { type: 'probe', id: w.org, version: 1 },
      details,
    }),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // The log's own clock times its events: the budget's hour is read against it.
  clock = new FixedClock(new Date());
  exports = createAuditLogExports({
    database: app,
    keys,
    ids,
    clock,
    logger: testLogger(new LogCapture()),
    mostEvents: 50,
  });
});

describe('downloading the audit log (E10b, decision 24)', () => {
  it('records the download first, then gives its events up to that seq, newest first, as NDJSON with their links', async () => {
    const w = await world();
    const sealed = await noted(w, { note: 'kept' });

    const file = fileOf(await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), asked('ndjson'), CORRELATION));
    const lines = file.content
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(file).toMatchObject({ contentType: 'application/x-ndjson', events: lines.length, upToSeq: sealed.seq });
    expect(file.fileName).toBe('audit-log-2000-01-01-to-2100-01-01.ndjson');
    expect(lines[0]).toMatchObject({ seq: sealed.seq.toString(), action: 'probe.noted', details: { note: 'kept' } });
    expect(lines[0]?.prevHash).toBe(lines[1]?.hash);
    // A signed state's keyed seal is the platform's: never in the file.
    expect(file.content).not.toContain('stateFingerprint');

    const recorded = await withTenant(app, w.org, (tx) => trail.recordedEvent(tx, w.org, { eventId: file.id }));
    expect(recorded).toMatchObject({
      kind: 'recorded',
      seq: sealed.seq + 1n,
      event: {
        actor: { type: 'user', id: w.admin.userId },
        action: AUDIT_LOG_EXPORTED,
        details: { format: 'ndjson', events: lines.length, upToSeq: sealed.seq.toString(), actions: null },
      },
    });
  });

  it('gives CSV with a header and every cell quoted, its facts as JSON text', async () => {
    const w = await world();
    await noted(w, { note: '=HYPERLINK("x")' });

    const file = fileOf(
      await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), asked('csv', ['probe.noted']), CORRELATION),
    );
    const [header, row] = file.content.trimEnd().split('\n');
    expect(file).toMatchObject({ contentType: 'text/csv', events: 1 });
    expect(header).toBe(
      '"seq","recordedAt","actorType","actorId","action","subjectType","subjectId","subjectVersion","details","hash","prevHash"',
    );
    // The facts' cell is JSON text, its quotes doubled: it begins with `{`, never a formula (csvCell's own tests).
    expect(row).toContain('"{""note"":""=HYPERLINK(\\""x\\"")""}"');
  });

  it('counts an event recorded at the range’s own start, as the file holds it', async () => {
    const w = await world();
    const sealed = await noted(w, { note: 'at the start' });
    const from = { ...asked('ndjson', ['probe.noted']), from: sealed.recordedAt };

    const file = fileOf(await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), from, CORRELATION));
    expect(file.events).toBe(1);
    const recorded = await withTenant(app, w.org, (tx) => trail.recordedEvent(tx, w.org, { eventId: file.id }));
    expect(recorded).toMatchObject({ kind: 'recorded', event: { details: { events: 1 } } });
  });

  it('answers a retry with its key with the same file, events recorded since left out', async () => {
    const w = await world();
    const key = keyed(w.admin, EXPORT_OPERATION);
    const first = fileOf(await exports.export(w.admin, key, asked('ndjson'), CORRELATION));
    await noted(w, { note: 'later' });

    expect(fileOf(await exports.export(w.admin, key, asked('ndjson'), CORRELATION))).toEqual(first);
  });

  it('refuses a range past the cap with nothing logged, an admin’s sixth in an hour, and a member not an admin', async () => {
    const w = await world();
    for (let n = 0; n < 50; n += 1) await noted(w, { n });
    // Exactly the cap is downloaded; one past it is refused, nothing logged.
    expect(
      await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), asked('csv', ['probe.noted']), CORRELATION),
    ).toMatchObject({ outcome: 'exported', file: { events: 50 } });
    await noted(w, { n: 50 });
    expect(
      await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), asked('csv', ['probe.noted']), CORRELATION),
    ).toEqual(refused(409, 'AUDIT_EXPORT_TOO_LARGE'));
    const few = asked('csv', ['probe.noted', AUDIT_LOG_EXPORTED]);
    expect(
      await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), asked('csv', [AUDIT_LOG_EXPORTED]), CORRELATION),
    ).toMatchObject({ outcome: 'exported', file: { events: 1 } });

    for (let n = 0; n < 3; n += 1) {
      fileOf(
        await exports.export(
          w.admin,
          keyed(w.admin, EXPORT_OPERATION),
          asked('csv', [AUDIT_LOG_EXPORTED]),
          CORRELATION,
        ),
      );
    }
    expect(await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), few, CORRELATION)).toEqual(
      refused(409, 'AUDIT_EXPORTS_SPENT'),
    );
    const approver = await member(w.org, 'approver');
    expect(await exports.export(approver, keyed(approver, EXPORT_OPERATION), few, CORRELATION)).toEqual(
      refused(403, 'FORBIDDEN'),
    );
  });

  it('counts an admin’s download in flight before their next: the sixth waits on their lock, then is refused (ADR-006 §6, 2b)', async () => {
    const w = await world();
    const few = asked('csv', [AUDIT_LOG_EXPORTED]);
    for (let n = 0; n < 4; n += 1)
      fileOf(await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), few, CORRELATION));
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The fifth, its lock taken and its record made, held open before it commits.
    const fifth = withTenant(app, w.org, async (tx) => {
      await holdTransactionLock(tx, EXPORTS_LOCK, w.org, w.admin.userId);
      await trail.record(tx, w.org, {
        actor: { type: 'user', id: w.admin.userId },
        action: AUDIT_LOG_EXPORTED,
        subject: { type: 'audit_log', id: w.org, version: 1 },
        details: { format: 'csv' },
      });
      holding(undefined);
      await gate;
    });
    await held;
    const sixth = within(
      20_000,
      exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), few, CORRELATION),
      'the sixth',
    );
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    await fifth;
    expect(await sixth).toEqual(refused(409, 'AUDIT_EXPORTS_SPENT'));
  });

  it('refuses a file with an event that can’t be believed: INTEGRITY_FAILED, the organisation held', async () => {
    const w = await world();
    const owner = await database.connect('owner');
    try {
      // Past the app: the owner, in the organisation, as the tenant wall holds even it.
      await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [w.org]);
      await owner.query(`update audit.events set details = '{"x":1}' where org_id = $1 and seq = 1`, [w.org]);
    } finally {
      await owner.end();
    }

    expect(await exports.export(w.admin, keyed(w.admin, EXPORT_OPERATION), asked('ndjson'), CORRELATION)).toEqual(
      refused(503, 'INTEGRITY_FAILED'),
    );
    const hold = await withSignedStates(app, w.org, quiet(), (tx, states) => states.holdRecord(tx, w.org));
    expect(hold).toMatchObject({ outcome: 'held' });
  });
});
