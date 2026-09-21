import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type OwnerTamper, tamperAsOwner } from './owner-tamper.ts';
import { createTestDatabase, type TestDatabase, type TestSession } from './test-database.ts';

const server = inject('postgres');
let database: TestDatabase;
let admin: TestSession;
let owner: OwnerTamper;

const ORG = '0199a0f0-0000-7000-8000-00000000a001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000a002';
const ROW = '0199a0f0-0000-7000-8000-00000000b001';
const OTHER_ROW = '0199a0f0-0000-7000-8000-00000000b002';
const TARGET = { table: 'probe.things', subject: 'thing' } as const;
const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const FIXTURE = [
  'create schema probe',
  "create table probe.things (org_id uuid not null, id uuid not null, status text not null, note text not null default '', state_version integer not null default 1, primary key (org_id, id))",
  'alter table probe.things enable row level security',
  'alter table probe.things force row level security',
  `create policy tenant_isolation on probe.things ${TENANT_POLICY}`,
  "create trigger status_guard before insert or update on probe.things for each row execute function state_rules.guard_status('OPEN', 'OPEN>SHUT')",
  'grant usage on schema probe to agentx_app',
  'grant select on probe.things to agentx_app',
];

/** An event row as the chain stores one; its hash and MAC are filler, which none of these scripts read. */
async function addEvent(org: string, seq: number, subjectId: string, details: string): Promise<void> {
  await admin.query(
    `insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
       subject_version, details, prev_hash, hash, mac, mac_key_version)
     values ($1, $2, pg_catalog.gen_random_uuid(), pg_catalog.now(), 'user', 'u', 'thing.changed', 'thing', $3, 1, $4,
       $5, $5, $5, 1)`,
    [org, seq, subjectId, details, Buffer.alloc(32, seq)],
  );
}

const statusOf = async (id: string) =>
  (await admin.query<{ status: string }>('select status from probe.things where org_id = $1 and id = $2', [ORG, id]))[0]
    ?.status;

const guardEnabled = async () =>
  (
    await admin.query<{ enabled: string }>(
      "select tgenabled as enabled from pg_catalog.pg_trigger where tgname = 'status_guard' and tgrelid = 'probe.things'::regclass",
    )
  )[0]?.enabled;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  admin = database.as('admin');
});

afterAll(async () => {
  await database.drop();
});

beforeEach(async () => {
  await admin.query('delete from probe.things');
  await admin.query('delete from audit.events');
  await admin.query('delete from audit.heads');
  await admin.query("insert into probe.things (org_id, id, status, note) values ($1, $2, 'OPEN', 'first')", [ORG, ROW]);
  await admin.query("insert into probe.things (org_id, id, status, note) values ($1, $2, 'OPEN', 'theirs')", [
    OTHER_ORG,
    ROW,
  ]);
  owner = await tamperAsOwner(database, TARGET, ORG);
});

afterEach(async () => {
  await owner.end();
});

describe(`tamperAsOwner, FX-TAMPER's owner (Postgres ${server.version})`, () => {
  it('connects as agentx_owner, set to act inside the one organisation, which row security still binds', async () => {
    const [who] = await owner.query<{ login: string; org: string }>(
      "select session_user::text as login, pg_catalog.current_setting('app.org_id') as org",
    );
    expect(who).toEqual({ login: 'agentx_owner', org: ORG });
    expect(await owner.query('select note from probe.things')).toEqual([{ note: 'first' }]);
  });

  it('sets a column of the row, in its organisation only', async () => {
    await owner.setColumn(ROW, 'note', 'changed');

    expect(await admin.query('select org_id, note from probe.things order by note')).toEqual([
      { org_id: ORG, note: 'changed' },
      { org_id: OTHER_ORG, note: 'theirs' },
    ]);
  });

  it('saves a row and puts every column but the key back', async () => {
    const saved = await owner.saveRow(ROW);
    await owner.query("update probe.things set status = 'SHUT', note = 'later', state_version = 2 where id = $1", [
      ROW,
    ]);
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    expect(await owner.query('select id, status, note, state_version from probe.things')).toEqual([
      { id: ROW, status: 'OPEN', note: 'first', state_version: 1 },
    ]);
  });

  it("refuses to save a row it can't find", async () => {
    await expect(owner.saveRow(OTHER_ROW)).rejects.toThrow('no such row');
  });

  it('switches the status guard off only for the work, and back on even when the work fails', async () => {
    await owner.setColumn(ROW, 'status', 'SHUT');
    await expect(owner.setColumn(ROW, 'status', 'OPEN')).rejects.toThrow();

    await owner.withoutStatusGuard(async () => {
      expect(await guardEnabled()).toBe('D');
      await owner.setColumn(ROW, 'status', 'OPEN');
    });
    expect(await guardEnabled()).toBe('O');
    expect(await statusOf(ROW)).toBe('OPEN');

    await expect(
      owner.withoutStatusGuard(() => {
        throw new Error('the work failed');
      }),
    ).rejects.toThrow('the work failed');
    expect(await guardEnabled()).toBe('O');
  });

  it('deletes the row', async () => {
    await owner.deleteRow(ROW);

    expect(await admin.query('select org_id from probe.things')).toEqual([{ org_id: OTHER_ORG }]);
  });

  it('strips the seal from every event about the row and keeps the rest of their details', async () => {
    await addEvent(ORG, 1, ROW, '{"reason":"x","stateFingerprint":"ab","stateKeyVersion":1}');
    await addEvent(ORG, 2, OTHER_ROW, '{"stateFingerprint":"cd","stateKeyVersion":1}');
    await owner.stripSeals(ROW);

    expect(await admin.query('select seq, details from audit.events order by seq')).toEqual([
      { seq: '1', details: '{"reason": "x"}' },
      { seq: '2', details: '{"stateFingerprint":"cd","stateKeyVersion":1}' },
    ]);
  });

  it("deletes the row's events, and no other", async () => {
    await addEvent(ORG, 1, ROW, '{}');
    await addEvent(ORG, 2, OTHER_ROW, '{}');
    await addEvent(OTHER_ORG, 1, ROW, '{}');
    await owner.deleteEvents(ROW);

    expect(await admin.query('select org_id, seq from audit.events order by org_id, seq')).toEqual([
      { org_id: ORG, seq: '2' },
      { org_id: OTHER_ORG, seq: '1' },
    ]);
  });

  it('winds the chain back: every event past a saved head deleted, and the head put back', async () => {
    await admin.query('insert into audit.heads (org_id, seq, hash, mac, mac_key_version) values ($1, 1, $2, $3, 1)', [
      ORG,
      Buffer.alloc(32, 1),
      Buffer.alloc(32, 9),
    ]);
    await addEvent(ORG, 1, ROW, '{}');
    const saved = await owner.saveHead();
    await addEvent(ORG, 2, ROW, '{}');
    await addEvent(ORG, 3, ROW, '{}');
    await admin.query('update audit.heads set seq = 3, hash = $2, mac = $3, mac_key_version = 2 where org_id = $1', [
      ORG,
      Buffer.alloc(32, 3),
      Buffer.alloc(32, 7),
    ]);
    await owner.windBack(saved);

    expect(await admin.query('select seq from audit.events')).toEqual([{ seq: '1' }]);
    expect(await admin.query('select seq, hash, mac, mac_key_version from audit.heads')).toEqual([
      { seq: '1', hash: Buffer.alloc(32, 1), mac: Buffer.alloc(32, 9), mac_key_version: 1 },
    ]);
  });

  it("refuses to save a head the organisation doesn't have", async () => {
    await expect(owner.saveHead()).rejects.toThrow('no chain head');
  });

  it('hides events from every reader only for the work, and shows them again even when the work fails', async () => {
    await addEvent(ORG, 1, ROW, '{}');
    await addEvent(ORG, 2, ROW, '{}');
    const [first] = await admin.query<{ id: string }>('select id from audit.events where seq = 1');
    if (first === undefined) throw new Error('The test expected an event');
    const seen = async () => (await owner.query<{ seq: string }>('select seq from audit.events order by seq')).length;

    await owner.withEventsHidden([first.id], async () => {
      expect(await seen()).toBe(1);
    });
    expect(await seen()).toBe(2);

    await expect(
      owner.withEventsHidden([first.id], () => {
        throw new Error('the work failed');
      }),
    ).rejects.toThrow('the work failed');
    expect(await seen()).toBe(2);
  });

  it('hides events only from queries whose text contains the word, when asked to', async () => {
    await addEvent(ORG, 1, ROW, '{}');
    await addEvent(ORG, 2, ROW, '{}');
    const [first] = await admin.query<{ id: string }>('select id from audit.events where seq = 1');
    if (first === undefined) throw new Error('The test expected an event');

    await owner.withEventsHidden(
      [first.id],
      async () => {
        expect(await owner.query('select seq from audit.events /* marked */')).toEqual([{ seq: '2' }]);
        expect(await owner.query('select seq from audit.events order by seq')).toEqual([{ seq: '1' }, { seq: '2' }]);
      },
      { fromQueriesContaining: 'marked' },
    );
  });

  it.each([
    ['no events', [], undefined],
    ['an ID that is not a UUID', ["x') or (true"], undefined],
    ['from queries naming a word that is not letters', [ROW], "x') or (true"],
  ])('refuses to hide %s', async (_, ids, word) => {
    await expect(
      owner.withEventsHidden(ids, () => Promise.resolve(), word === undefined ? {} : { fromQueriesContaining: word }),
    ).rejects.toBeInstanceOf(RangeError);
  });

  it.each([
    ['a table named past its schema', { ...TARGET, table: 'probe.things; drop table x' }, ORG],
    ['an organisation that is not a UUID', TARGET, 'org-1'],
  ])('refuses %s', async (_, target, org) => {
    await expect(tamperAsOwner(database, target, org)).rejects.toBeInstanceOf(RangeError);
  });
});
