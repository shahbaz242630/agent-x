// L6: a day's digest on the real migrated schema, as the app role: one line
// a row by ID, the time to the microsecond, the same whatever the batch; the
// client's clues outside it; a quiet day the empty text's; the day counted
// again with its last ID; an organisation's first day.
import { createHash } from 'node:crypto';

import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import { sql, type Transaction } from 'kysely';
import { v7 } from 'uuid';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { dayCount, digestOfDay, firstDayOf } from './activity-seal.ts';
import type { ActivityTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<ActivityTables>;

const PERSON = '0199a0f0-0000-7000-8000-00000000b601';
const CORRELATION = '0199a0f0-0000-7000-8000-00000000b602';

let number = 0;
/** A new organisation, so no two tests share a log. */
const newOrg = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0xb610 + number).toString(16).padStart(12, '0')}`;
};

const inOrg =
  (orgId: string) =>
  <T>(work: (tx: Transaction<ActivityTables>) => Promise<T>): Promise<T> =>
    withTenant(app, orgId, work);

/** A row written at `written` (its UUIDv7's time), recorded as arriving at `at`. */
async function row(orgId: string, written: string, at = written, clues = { ip: '94.200.1.7', country: 'AE' }) {
  const id = v7({ msecs: Date.parse(written) });
  await inOrg(orgId)((tx) =>
    tx
      .insertInto('access.requests')
      .values({
        org_id: orgId,
        id,
        recorded_at: new Date(at),
        actor_type: 'user',
        actor_id: PERSON,
        method: 'GET',
        route: '/v1/agents/:id',
        path_ids: [PERSON],
        status: 200,
        reason: null,
        correlation_id: CORRELATION,
        duration_ms: 7,
        ip: clues.ip,
        country: clues.country,
        city: null,
        time_zone: null,
        time_zone_from: null,
      })
      .execute(),
  );
  return id;
}

const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');
const lineOf = (id: string, at: string) =>
  `${JSON.stringify([id, at, 'user', PERSON, 'GET', '/v1/agents/:id', [PERSON], 200, null, CORRELATION, 7])}\n`;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<ActivityTables>(database.connection('app'), testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe('L6 a day’s digest (decision 26, ADR-011 §7)', () => {
  it('is the SHA-256 of a line a row written that day, by ID, its time to the microsecond in UTC', async () => {
    const org = newOrg();
    await row(org, '2026-10-18T23:59:59.999Z');
    const first = await row(org, '2026-10-19T00:00:00.000Z', '2026-10-18T23:59:58.000Z');
    const second = await row(org, '2026-10-19T23:59:59.999Z');
    await row(org, '2026-10-20T00:00:00.000Z');

    const digest = await digestOfDay(inOrg(org), org, '2026-10-19', 100);

    expect(digest).toEqual({
      day: '2026-10-19',
      requests: 2,
      // A slow request that arrived the day before is in the day it was written.
      digest: sha256(lineOf(first, '2026-10-18T23:59:58.000000Z') + lineOf(second, '2026-10-19T23:59:59.999000Z')),
      idFrom: first,
      idTo: second,
      misdated: null,
    });
    expect(await digestOfDay(inOrg(org), org, '2026-10-19', 1)).toEqual(digest);
  });

  it.each([
    ['five hours after its answer: a server clock stepped back, still believed', '2026-10-19T05:00:00.000Z', false],
    ['given a time months old: a fresh ID passing as an old row', '2026-07-01T10:00:00.000Z', true],
    ['made before its own answer', '2026-10-19T10:00:10.000Z', true],
  ])('F1 G3 names a row whose ID was made %s', async (_what, at, misdated) => {
    const org = newOrg();
    await row(org, '2026-10-19T10:00:00.000Z', at);

    const digest = await digestOfDay(inOrg(org), org, '2026-10-19', 100);

    expect(digest.misdated).toBe(misdated ? digest.idFrom : null);
  });

  it('is the same whatever time zone the session reads times in', async () => {
    const org = newOrg();
    await row(org, '2026-10-19T22:30:00.000Z');
    const inDubai = <T>(work: (tx: Transaction<ActivityTables>) => Promise<T>) =>
      inOrg(org)(async (tx) => {
        await sql`set local time zone 'Asia/Dubai'`.execute(tx);
        return work(tx);
      });

    expect(await digestOfDay(inDubai, org, '2026-10-19', 100)).toEqual(
      await digestOfDay(inOrg(org), org, '2026-10-19', 100),
    );
  });

  it('is the empty text’s for a quiet day, with no first or last ID', async () => {
    const org = newOrg();

    expect(await digestOfDay(inOrg(org), org, '2026-10-19', 100)).toEqual({
      day: '2026-10-19',
      requests: 0,
      digest: sha256(''),
      idFrom: null,
      idTo: null,
      misdated: null,
    });
  });

  it('changes with a row’s sealed column changed, its microsecond too; not with its client’s clues blanked', async () => {
    const org = newOrg();
    const id = await row(org, '2026-10-19T10:00:00.000Z');
    const before = await digestOfDay(inOrg(org), org, '2026-10-19', 100);
    const admin = database.as('admin');

    await admin.query('update access.requests set ip = null, country = null where id = $1', [id]);
    expect(await digestOfDay(inOrg(org), org, '2026-10-19', 100)).toEqual(before);
    await admin.query("update access.requests set recorded_at = recorded_at + interval '1 microsecond' where id = $1", [
      id,
    ]);
    expect((await digestOfDay(inOrg(org), org, '2026-10-19', 100)).digest).not.toBe(before.digest);
    await admin.query(
      "update access.requests set recorded_at = recorded_at - interval '1 microsecond', status = 403 where id = $1",
      [id],
    );
    expect((await digestOfDay(inOrg(org), org, '2026-10-19', 100)).digest).not.toBe(before.digest);
  });

  it('counts the day again with its last ID, and names an organisation’s first day; none for one with no rows', async () => {
    const org = newOrg();
    await row(org, '2026-10-17T08:00:00.000Z');
    const last = await row(org, '2026-10-19T09:00:00.000Z');
    await row(org, '2026-10-19T08:00:00.000Z');

    expect(await inOrg(org)((tx) => dayCount(tx, org, '2026-10-19'))).toEqual({ requests: 2, idTo: last });
    expect(await inOrg(org)((tx) => firstDayOf(tx, org))).toBe('2026-10-17');
    expect(await inOrg(newOrg())((tx) => firstDayOf(tx, org))).toBeUndefined();
  });
});
