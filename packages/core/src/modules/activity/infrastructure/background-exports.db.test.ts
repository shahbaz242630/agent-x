// L5c: the background downloads' reads and writes (0053) on the real migrated
// schema, as the app role: a download asked with its months, claimed a month
// at a time under a lease, a builder that lost its lease changing nothing, a
// month tried too often failing its download, and a download listed as
// building, ready, expired or failed.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger, waitUntilQueued, within } from '@agentx/testing';
import { type Transaction } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import {
  addBackgroundExport,
  type BackgroundExportAsked,
  backgroundExportOf,
  backgroundExportsOf,
  claimFile,
  type ClaimedFile,
  downloadUnderWay,
  fileFailed,
  fileReady,
  giveBack,
  newestWritten,
  renewLease,
} from './background-exports.ts';
import type { ActivityExportTables, ActivityTables } from './tables.ts';

type Tables = ActivityExportTables & ActivityTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ADMIN = '0199a0f0-0000-7000-8000-00000000af01';
const LEASE = { leaseMs: 15 * 60_000, mostTries: 3 };
const FACTS = { requests: 3, bytes: 120, sha256: 'a'.repeat(64) };

let number = 0;
/** A new UUID, so no two tests share an organisation or a download. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0xaf10 + number).toString(16).padStart(12, '0')}`;
};

const inOrg = <T>(orgId: string, work: (tx: Transaction<Tables>) => Promise<T>): Promise<T> =>
  withTenant(app, orgId, work);

/** A download of August 15 to October 2 (three months), asked in the organisation: its ID. */
async function asked(orgId: string, change: Partial<BackgroundExportAsked> = {}): Promise<string> {
  const id = newId();
  await inOrg(orgId, (tx) =>
    addBackgroundExport(tx, orgId, {
      id,
      requestedBy: ADMIN,
      from: new Date('2026-08-15T00:00:00Z'),
      to: new Date('2026-10-02T00:00:00Z'),
      format: 'ndjson',
      writtenUpTo: null,
      ...change,
    }),
  );
  return id;
}

const claimed = async (orgId: string, lease = LEASE): Promise<ClaimedFile> => {
  const claim = await inOrg(orgId, (tx) => claimFile(tx, orgId, lease));
  if (claim.outcome !== 'claimed') throw new Error(`expected a month claimed, got ${claim.outcome}`);
  return claim.file;
};

const heldOf = (orgId: string, file: ClaimedFile, lease = file.lease) => ({
  orgId,
  exportId: file.exportId,
  month: file.month,
  lease,
});

const pause = () => new Promise((resolve) => setTimeout(resolve, 20));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(database.connection('app'), testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe('L5c a background download asked', () => {
  it('is listed building, its months waiting, oldest first; under way until done', async () => {
    const org = newId();
    const id = await asked(org, { actor: { type: 'agent', id: ADMIN } });
    const download = await inOrg(org, (tx) => backgroundExportOf(tx, org, id));

    expect(download).toMatchObject({
      id,
      requestedBy: ADMIN,
      from: new Date('2026-08-15T00:00:00Z'),
      to: new Date('2026-10-02T00:00:00Z'),
      actor: { type: 'agent', id: ADMIN },
      format: 'ndjson',
      writtenUpTo: null,
      state: 'building',
      expiresAt: null,
    });
    expect(download?.files.map((file) => [file.month, file.state, file.attempts])).toEqual([
      ['2026-08', 'waiting', 0],
      ['2026-09', 'waiting', 0],
      ['2026-10', 'waiting', 0],
    ]);
    expect(await inOrg(org, (tx) => downloadUnderWay(tx, org))).toBe(true);
    expect(await inOrg(newId(), (tx) => backgroundExportOf(tx, org, id))).toBeUndefined();
  });

  it('is listed newest first, a page at a time', async () => {
    const org = newId();
    const first = await asked(org);
    const second = await asked(org);
    const third = await asked(org);

    const page = await inOrg(org, (tx) => backgroundExportsOf(tx, org, { limit: 2 }));
    expect(page.downloads.map((download) => download.id)).toEqual([third, second]);
    expect(page.next).toBe(second);
    const rest = await inOrg(org, (tx) => backgroundExportsOf(tx, org, { before: second, limit: 2 }));
    expect(rest).toEqual({ downloads: [expect.objectContaining({ id: first })], next: null });
  });

  it('names the newest request written, by its UUIDv7, or none', async () => {
    const org = newId();
    expect(await inOrg(org, (tx) => newestWritten(tx, org))).toBeNull();
    const ids = ['0199a0f0-0000-7000-8000-00000000af81', '0199a0f0-0000-7000-8000-00000000af82'];
    for (const id of ids.toReversed()) {
      await inOrg(org, (tx) =>
        tx
          .insertInto('access.requests')
          .values({
            org_id: org,
            id,
            recorded_at: new Date('2026-10-19T10:00:00Z'),
            actor_type: 'user',
            actor_id: ADMIN,
            method: 'GET',
            route: '/v1/access-log',
            path_ids: [],
            status: 200,
            reason: null,
            correlation_id: id,
            duration_ms: 1,
            ip: null,
            country: null,
            city: null,
            time_zone: null,
            time_zone_from: null,
          })
          .execute(),
      );
    }

    expect(await inOrg(org, (tx) => newestWritten(tx, org))).toBe(ids[1]);
  });
});

describe('L5c a month built under its lease', () => {
  it('is claimed oldest first, one try counted; the next claim takes the next month', async () => {
    const org = newId();
    const id = await asked(org);

    const august = await claimed(org);
    const september = await claimed(org);

    expect(august).toMatchObject({ exportId: id, month: '2026-08-01', attempt: 1 });
    expect(august.download.id).toBe(id);
    expect(september).toMatchObject({ exportId: id, month: '2026-09-01', attempt: 1 });
  });

  it('is renewed under the lease it holds, and made ready under the renewed one alone', async () => {
    const org = newId();
    await asked(org);
    const file = await claimed(org);

    const renewed = await inOrg(org, (tx) => renewLease(tx, heldOf(org, file), LEASE.leaseMs));
    expect(renewed).toBeInstanceOf(Date);
    expect(await inOrg(org, (tx) => fileReady(tx, heldOf(org, file), FACTS))).toBe('lost');
    expect(await inOrg(org, (tx) => fileReady(tx, heldOf(org, file, renewed), FACTS))).toBe('more');
  });

  it('makes its download ready once every month is, kept 7 days from the last', async () => {
    const org = newId();
    const id = await asked(org, { from: new Date('2026-08-15T00:00:00Z'), to: new Date('2026-09-15T00:00:00Z') });
    const august = await claimed(org);
    const september = await claimed(org);

    expect(await inOrg(org, (tx) => fileReady(tx, heldOf(org, august), FACTS))).toBe('more');
    expect(await inOrg(org, (tx) => fileReady(tx, heldOf(org, september), { ...FACTS, requests: 0 }))).toBe('ready');
    const download = await inOrg(org, (tx) => backgroundExportOf(tx, org, id));

    expect(download?.state).toBe('ready');
    expect(download?.files.map((file) => [file.month, file.state, file.requests, file.bytes])).toEqual([
      ['2026-08', 'ready', 3, 120],
      ['2026-09', 'ready', 0, 120],
    ]);
    // Kept from the last ready, by the database's clock: a few milliseconds after it was asked.
    const kept = (download?.expiresAt?.getTime() ?? 0) - (download?.requestedAt.getTime() ?? 0);
    expect(kept).toBeGreaterThanOrEqual(7 * 86_400_000);
    expect(kept).toBeLessThan(7 * 86_400_000 + 60_000);
    expect(await inOrg(org, (tx) => downloadUnderWay(tx, org))).toBe(false);

    // Seven days on: file_moves never lets a ready file change, so its time is moved with its trigger off.
    const admin = database.as('admin');
    await admin.query('alter table activity_exports.files disable trigger file_moves');
    await admin.query(
      "update activity_exports.files set ready_at = ready_at - interval '7 days' where export_id = $1",
      [id],
    );
    await admin.query('alter table activity_exports.files enable trigger file_moves');
    expect((await inOrg(org, (tx) => backgroundExportOf(tx, org, id)))?.state).toBe('expired');
  });

  it('is lost to its builder once its lease runs out and another takes it on: then nothing the first does lands', async () => {
    const org = newId();
    await asked(org);
    const first = await claimed(org, { ...LEASE, leaseMs: 1 });
    await pause();

    const second = await claimed(org);
    expect(second).toMatchObject({ month: first.month, attempt: 2 });
    expect(await inOrg(org, (tx) => renewLease(tx, heldOf(org, first), LEASE.leaseMs))).toBeUndefined();
    expect(await inOrg(org, (tx) => fileReady(tx, heldOf(org, first), FACTS))).toBe('lost');
    expect(await inOrg(org, (tx) => giveBack(tx, heldOf(org, first)))).toBe(false);
    expect(await inOrg(org, (tx) => fileFailed(tx, heldOf(org, first), 'ACTIVITY_EXPORT_FAILED'))).toBe(false);
    expect(await inOrg(org, (tx) => fileReady(tx, heldOf(org, second), FACTS))).toBe('more');
  });

  it('is given back waiting at a stop, and claimed again with one more try', async () => {
    const org = newId();
    await asked(org);
    const file = await claimed(org);

    expect(await inOrg(org, (tx) => giveBack(tx, heldOf(org, file)))).toBe(true);
    expect(await claimed(org)).toMatchObject({ month: file.month, attempt: 2 });
  });
});

describe('L5c a download’s last months finished at once (ADR-006 §6, 2c)', () => {
  it('FX-RACE two builders finishing its last two months: the second waits on the download’s lock, and sees it ready', async () => {
    const org = newId();
    await asked(org, { from: new Date('2026-08-15T00:00:00Z'), to: new Date('2026-09-15T00:00:00Z') });
    const august = await claimed(org);
    const september = await claimed(org);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // August made ready, its transaction held open before it commits.
    const first = inOrg(org, async (tx) => {
      const done = await fileReady(tx, heldOf(org, august), FACTS);
      holding(undefined);
      await gate;
      return done;
    });
    await held;
    const second = within(
      20_000,
      inOrg(org, (tx) => fileReady(tx, heldOf(org, september), FACTS)),
      'September',
    );
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);

    expect(await first).toBe('more');
    expect(await second).toBe('ready');
  });
});

describe('L5c a download given up', () => {
  it('fails once a month has been tried too often: that month and its waiting ones, none claimed again', async () => {
    const org = newId();
    const id = await asked(org);
    for (let attempt = 1; attempt <= LEASE.mostTries; attempt += 1) {
      await claimed(org, { ...LEASE, leaseMs: 1 });
      await pause();
    }

    const claim = await inOrg(org, (tx) => claimFile(tx, org, LEASE));
    expect(claim).toEqual({ outcome: 'given_up', exportId: id, month: '2026-08-01', requestedBy: ADMIN });
    const download = await inOrg(org, (tx) => backgroundExportOf(tx, org, id));
    expect(download?.state).toBe('failed');
    expect(download?.files.map((file) => file.state)).toEqual(['failed', 'failed', 'failed']);
    expect(await inOrg(org, (tx) => claimFile(tx, org, LEASE))).toEqual({ outcome: 'none' });
    expect(await inOrg(org, (tx) => downloadUnderWay(tx, org))).toBe(false);
  });

  it('fails with a month its builder failed, its waiting months with it, and one being built once it is done', async () => {
    const org = newId();
    const id = await asked(org);
    const august = await claimed(org);
    const september = await claimed(org);

    expect(await inOrg(org, (tx) => fileFailed(tx, heldOf(org, august), 'ACTIVITY_EXPORT_STORE_FAILED'))).toBe(true);
    const download = await inOrg(org, (tx) => backgroundExportOf(tx, org, id));

    expect(download?.state).toBe('failed');
    expect(download?.files.map((file) => file.state)).toEqual(['failed', 'building', 'failed']);
    // The one being built finds its download given up once it would be ready, and fails with it.
    expect(await inOrg(org, (tx) => claimFile(tx, org, LEASE))).toEqual({ outcome: 'none' });
    expect(await inOrg(org, (tx) => fileReady(tx, heldOf(org, september), FACTS))).toBe('given_up');
    const after = await inOrg(org, (tx) => backgroundExportOf(tx, org, id));
    expect(after?.files.map((file) => file.state)).toEqual(['failed', 'failed', 'failed']);
  });
});
