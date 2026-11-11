// PL-29 follow-up (Carry-Forward S175): the steps a state repair reaches an
// authority table's rows by, on a stand-in table of the owner's, against a
// real Postgres. The plan and the repair themselves are proven on the
// product's own tables in apps/operator/src/state-restore.db.test.ts.
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import { createDatabase, type Database, type SignedStateTable, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { SequentialIds } from '@agentx/testing';

import { type AuditTrail, createAuditTrail } from './audit-trail.ts';
import {
  columnsOf,
  guardsOff,
  guardsOn,
  readRowsAlike,
  rowsAsStored,
  stateObjectIds,
  statesAsRead,
  StateWriteMissed,
  triggersOf,
  writeStateRow,
} from './state-repair.ts';
import type { AuditTables } from './tables.ts';

/** A stand-in authority table with a generated column and a guard of its own name. */
const THINGS = {
  table: 'probe.things',
  subject: 'thing',
  fields: [{ column: 'label', type: 'text' }],
} as const satisfies SignedStateTable;

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  `create table probe.things (org_id uuid not null, id uuid not null, label text not null,
     shout text generated always as (pg_catalog.upper(label)) stored, gone text,
     state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))`,
  'alter table probe.things drop column gone',
  'alter table probe.things enable row level security',
  'alter table probe.things force row level security',
  `create policy tenant_isolation on probe.things ${TENANT_POLICY}`,
  "create trigger status_guard before insert or update on probe.things for each row execute function state_rules.guard_status('x')",
  'alter table probe.things disable trigger status_guard',
];

const server = inject('postgres');
let database: TestDatabase;
let owner: Database<AuditTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const trail = createAuditTrail({ keys, ids: new SequentialIds(0xd00) });

const ORG = '0199a0f0-0000-7000-8000-00000000d001';
const ROW = '0199a0f0-0000-7000-8000-00000000d002';
const NONE = '0199a0f0-0000-7000-8000-00000000d003';
const THIRD = '0199a0f0-0000-7000-8000-00000000d004';
const FOURTH = '0199a0f0-0000-7000-8000-00000000d005';

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  owner = createDatabase<AuditTables>({ ...database.connection('owner'), maxConnections: 1 }, testLogger());
});

afterAll(async () => {
  await owner.destroy();
  await database.drop();
});

describe('PL-29 follow-up: a state repair’s steps', () => {
  it('writes a row from JSON, reads it back whole, and refuses a write that reaches no row', async () => {
    await withTenant(owner, ORG, async (tx) => {
      await readRowsAlike(tx);
      expect(await columnsOf(tx, THINGS)).toEqual([
        'org_id',
        'id',
        'label',
        'shout',
        'state_version',
        'state_event_id',
      ]);
      const columns = await columnsOf(tx, THINGS, true);
      expect(columns).toEqual(['org_id', 'id', 'label', 'state_version', 'state_event_id']);
      const stored = JSON.stringify({
        org_id: ORG,
        id: ROW,
        label: 'first',
        shout: 'FIRST',
        state_version: 1,
        state_event_id: null,
      });
      await writeStateRow(tx, ORG, { action: 'put_back', table: THINGS, id: ROW, stored, exists: false }, columns);
      const read = await rowsAsStored(tx, THINGS, ORG, [ROW, NONE], 'change');
      expect(JSON.parse(String(read.get(ROW)))).toMatchObject({ label: 'first', shout: 'FIRST' });
      expect(read.has(NONE)).toBe(false);
      expect(await rowsAsStored(tx, THINGS, ORG, [])).toEqual(new Map());
      const changed = stored.replace('first', 'second');
      await writeStateRow(
        tx,
        ORG,
        { action: 'put_back', table: THINGS, id: ROW, stored: changed, exists: true },
        columns,
      );
      expect(JSON.parse(String((await rowsAsStored(tx, THINGS, ORG, [ROW])).get(ROW)))).toMatchObject({
        shout: 'SECOND',
      });
      // A row whose JSON names another key is never written over this one.
      const elsewhere = changed.replace(ROW, NONE);
      await expect(
        writeStateRow(
          tx,
          ORG,
          { action: 'put_back', table: THINGS, id: ROW, stored: elsewhere, exists: true },
          columns,
        ),
      ).rejects.toThrow(StateWriteMissed);
      // Nor inserted under this one's key: the insert's twin.
      await expect(
        writeStateRow(
          tx,
          ORG,
          { action: 'put_back', table: THINGS, id: NONE, stored: changed, exists: false },
          columns,
        ),
      ).rejects.toThrow(StateWriteMissed);
      expect((await rowsAsStored(tx, THINGS, ORG, [NONE])).has(NONE)).toBe(false);
    });
    await withTenant(owner, ORG, async (tx) => {
      await expect(writeStateRow(tx, ORG, { action: 'remove', table: THINGS, id: NONE }, [])).rejects.toMatchObject({
        name: 'StateWriteMissed',
        table: 'probe.things',
      });
    });
  });

  it('switches on only the guards it switched off: one already off stays off', async () => {
    await withTenant(owner, ORG, async (tx) => {
      expect(await triggersOf(tx, THINGS)).toEqual(new Map([['status_guard', 'D']]));
      const off = await guardsOff(tx, THINGS);
      expect(off).toEqual([]);
      await guardsOn(tx, THINGS, off);
      expect(await triggersOf(tx, THINGS)).toEqual(new Map([['status_guard', 'D']]));
    });
  });

  it('lists a table’s objects a page at a time, and reads an unsigned row as the verifier would', async () => {
    await withTenant(owner, ORG, async (tx) => {
      const ids = [THIRD, FOURTH];
      for (const id of ids) {
        const stored = JSON.stringify({ org_id: ORG, id, label: 'x', state_version: 1, state_event_id: null });
        await writeStateRow(
          tx,
          ORG,
          { action: 'put_back', table: THINGS, id, stored, exists: false },
          await columnsOf(tx, THINGS, true),
        );
      }
      const first = await stateObjectIds(tx, trail, THINGS, ORG, null, 2);
      expect(first).toEqual({ ids: [ROW, THIRD], next: THIRD });
      expect(await stateObjectIds(tx, trail, THINGS, ORG, first.next, 2)).toEqual({ ids: [FOURTH], next: null });
      const read = await statesAsRead(tx, trail, keys, THINGS, ORG, ids);
      expect(read.get(THIRD)).toMatchObject({
        row: { outcome: 'found' },
        latest: { kind: 'none' },
        check: { outcome: 'tampered', sign: 'unsigned' },
      });
      throw new Error('roll back');
    }).catch((error: unknown) => {
      if (!(error instanceof Error && error.message === 'roll back')) throw error;
    });
  });

  it('leaves an object with a backlog of events unjudged, and never believes a read that skipped one', async () => {
    // The log's own read, standing in for one that found more events since the newest signed one than it takes, or
    // that answered no ID at all: what a thousand events or a bug would show, neither of which the table here can.
    const answering = (latest: ReadonlyMap<string, { readonly kind: 'backlog' }>): AuditTrail => ({
      ...trail,
      latestSignedStates: () => Promise.resolve(latest),
    });
    await withTenant(owner, ORG, async (tx) => {
      const backlogged = await statesAsRead(tx, answering(new Map([[ROW, { kind: 'backlog' }]])), keys, THINGS, ORG, [
        ROW,
      ]);
      expect(backlogged.get(ROW)).toMatchObject({ latest: { kind: 'backlog' }, check: undefined });
      await expect(statesAsRead(tx, answering(new Map()), keys, THINGS, ORG, [ROW])).rejects.toThrow(
        'A signed state was asked for and not read',
      );
    });
  });
});
