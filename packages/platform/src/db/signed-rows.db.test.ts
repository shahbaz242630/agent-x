// The signed-state row steps (signed-rows.ts), on stand-in tables built as a
// module would build an authority table. The audit module's signed states
// (verifiedState and record) put them together with the log; its own tests
// prove that whole.
import {
  createTestDatabase,
  LogCapture,
  type TestDatabase,
  type TestSession,
  waitUntilBlocked,
  waitUntilQueued,
} from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase, type Database } from './database.ts';
import {
  pointSignedRow,
  readSignedRow,
  type SignedFieldValues,
  type SignedStateTable,
  writeSignedRow,
} from './signed-rows.ts';
import { TenantContextError, withTenant } from './tenant.ts';

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

/**
 * probe.grants, an authority table with a field of each type; probe.loose,
 * the same after its owner dropped the key and made the pointer text.
 */
const FIXTURE = [
  'create schema probe',
  "create table probe.grants (org_id uuid not null, id uuid not null, status text not null, holder uuid, amount bigint, expires_at timestamptz, role text, label text not null default '', state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))",
  "create table probe.loose (org_id uuid not null, id uuid not null, status text not null, holder uuid, amount bigint, expires_at timestamptz, role text, label text not null default '', state_version integer not null default 1, state_event_id text)",
  ...['probe.grants', 'probe.loose'].flatMap((table) => [
    `alter table ${table} enable row level security`,
    `alter table ${table} force row level security`,
    `create policy tenant_isolation on ${table} ${TENANT_POLICY}`,
  ]),
  'grant usage on schema probe to agentx_app',
  'grant select, insert on probe.grants, probe.loose to agentx_app',
  'grant update (status, holder, amount, expires_at, role, label, state_version, state_event_id) on probe.grants, probe.loose to agentx_app',
];

interface GrantsTable {
  org_id: string;
  id: string;
  status: string;
  holder?: string | null;
  amount?: bigint | null;
  expires_at?: string | null;
  role?: string | null;
  state_version?: number;
  state_event_id?: string | null;
}

interface ProbeTables {
  'probe.grants': GrantsTable;
  'probe.loose': GrantsTable;
}

const FIELDS: SignedStateTable['fields'] = [
  { column: 'status', type: 'text' },
  { column: 'holder', type: 'uuid' },
  { column: 'amount', type: 'integer' },
  { column: 'expires_at', type: 'timestamptz' },
  { column: 'role', type: 'text' },
];
const GRANTS: SignedStateTable = { table: 'probe.grants', subject: 'grant', fields: FIELDS };
const LOOSE: SignedStateTable = { table: 'probe.loose', subject: 'grant', fields: FIELDS };

const server = inject('postgres');
let database: TestDatabase;
let app: Database<ProbeTables>;
/** The server's superuser: past every wall, for setting up and for playing the attacker. */
let admin: TestSession;

const ORG = '0199a0f0-0000-7000-8000-00000000000a';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000000b';
const HOLDER = '0199A0F0-0000-7000-8000-0000000000CC';
const EVENT = '0199a0f0-0000-7000-8000-0000000000e1';
const NEXT_EVENT = '0199a0f0-0000-7000-8000-0000000000e2';
let rowNumber = 0;
/** A new row's ID, so no two tests share a row. */
const newId = (): string => {
  rowNumber += 1;
  return `0199a0f0-0000-7000-8000-${(0x1000 + rowNumber).toString(16).padStart(12, '0')}`;
};

/** A new grant in probe.grants, inserted by the app with every field set, as a module would create one. */
async function newGrant(org = ORG, pointer: string | null = null): Promise<string> {
  const id = newId();
  await withTenant(app, org, (tx) =>
    tx
      .insertInto('probe.grants')
      .values({
        org_id: org,
        id,
        status: 'ACTIVE',
        holder: HOLDER,
        amount: 12_345_678_901_234n,
        expires_at: '2026-09-19 10:11:12.345678+04',
        role: null,
        state_event_id: pointer,
      })
      .execute(),
  );
  return id;
}

const read = (table: SignedStateTable, id: string, org = ORG) =>
  withTenant(app, org, (tx) => readSignedRow(tx, table, { orgId: org, id }, 'share'));

const EXPECTED_FIELDS = [
  ['status', 'ACTIVE'],
  ['holder', HOLDER.toLowerCase()],
  ['amount', '12345678901234'],
  ['expires_at', '2026-09-19T06:11:12.345678Z'],
  ['role', null],
];

/** The expected fields, one of them changed. */
const fieldsWith = (column: string, value: string) =>
  EXPECTED_FIELDS.map(([name, expected]) => [name, name === column ? value : expected]);

async function rowOf(id: string): Promise<Record<string, unknown> | undefined> {
  const rows = await admin.query(
    'select status, label, state_version, state_event_id from probe.grants where org_id = $1 and id = $2',
    [ORG, id],
  );
  return rows[0];
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: new LogCapture(),
  });
  app = createDatabase<ProbeTables>({ ...database.connection('app'), maxConnections: 8 }, logger);
  admin = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe('reading a signed row (ADR-012 §2)', () => {
  it('reads its version, its pointer and each authority field as canonical text, in the fields’ order', async () => {
    const id = await newGrant(ORG, EVENT.toUpperCase());

    expect(await read(GRANTS, id)).toEqual({ outcome: 'found', version: 1, eventId: EVENT, fields: EXPECTED_FIELDS });
  });

  it('reads a new row as pointing nowhere', async () => {
    const id = await newGrant();

    expect(await read(GRANTS, id)).toMatchObject({ outcome: 'found', version: 1, eventId: null });
  });

  it("reads a time the same way whatever the session's time zone and date style", async () => {
    const id = await newGrant();

    const found = await withTenant(app, ORG, async (tx) => {
      await sql`set local time zone 'Asia/Tokyo'`.execute(tx);
      await sql`set local datestyle = 'SQL, DMY'`.execute(tx);
      return readSignedRow(tx, GRANTS, { orgId: ORG, id }, 'share');
    });

    expect(found).toMatchObject({ outcome: 'found', fields: EXPECTED_FIELDS });
  });

  it("reports a row that doesn't exist, or is another organisation's, as missing (SEC-TEN-01)", async () => {
    const theirs = await newGrant(OTHER_ORG);

    expect(await read(GRANTS, newId())).toEqual({ outcome: 'missing' });
    expect(await read(GRANTS, theirs)).toEqual({ outcome: 'missing' });
  });

  it("refuses to read in another organisation's transaction, where the row would look missing", async () => {
    const ours = await newGrant();

    await expect(
      withTenant(app, OTHER_ORG, (tx) => readSignedRow(tx, GRANTS, { orgId: ORG, id: ours }, 'share')),
    ).rejects.toBeInstanceOf(TenantContextError);
  });

  it.each<[string, SignedStateTable]>([
    ['a table not named schema.table', { ...GRANTS, table: 'grants' }],
    ['a table named with quotes', { ...GRANTS, table: 'probe."grants"' }],
    ['no fields', { ...GRANTS, fields: [] }],
    ['a column not in lower-case words', { ...GRANTS, fields: [{ column: 'Status', type: 'text' }] }],
    [
      'a column named twice',
      {
        ...GRANTS,
        fields: [
          { column: 'status', type: 'text' },
          { column: 'status', type: 'text' },
        ],
      },
    ],
    ['the version as a field', { ...GRANTS, fields: [{ column: 'state_version', type: 'integer' }] }],
    ['the pointer as a field', { ...GRANTS, fields: [{ column: 'state_event_id', type: 'uuid' }] }],
    ['a type it has no reading for', { ...GRANTS, fields: [{ column: 'status', type: 'json' as unknown as 'text' }] }],
  ])('refuses a table definition with %s, before any SQL', async (_, table) => {
    const id = await newGrant();

    await expect(read(table, id)).rejects.toBeInstanceOf(RangeError);
  });

  it('refuses a key that is not two UUIDs', async () => {
    await expect(
      withTenant(app, ORG, (tx) => readSignedRow(tx, GRANTS, { orgId: ORG, id: 'not-a-uuid' }, 'share')),
    ).rejects.toBeInstanceOf(RangeError);
  });
});

describe('reading a time as canonical text', () => {
  it.each([
    ['in our era', '2026-09-26 12:00:00+00', '2026-09-26T12:00:00.000000Z'],
    [
      'before year 1, which to_char writes without its era',
      '2026-09-26 12:00:00+00 BC',
      '2026-09-26T12:00:00.000000Z BC',
    ],
    ['as infinity, which to_char has no text for', 'infinity', 'infinity'],
    ['as minus infinity', '-infinity', '-infinity'],
  ])('reads a time %s as text no other time reads as', async (_, stored, text) => {
    const id = await newGrant();
    await admin.query('update probe.grants set expires_at = $3 where org_id = $1 and id = $2', [ORG, id, stored]);

    expect(await read(GRANTS, id)).toMatchObject({ fields: fieldsWith('expires_at', text) });
  });
});

describe('reading a row changed past the app', () => {
  it.each<[string, SignedStateTable['fields']]>([
    ['a time declared as text, whose text the session decides', [{ column: 'expires_at', type: 'text' }]],
    ['text declared as a UUID', [{ column: 'status', type: 'uuid' }]],
    ['a big whole number declared as text', [{ column: 'amount', type: 'text' }]],
  ])("reports a field whose column isn't of its declared type as unreadable: %s", async (_, fields) => {
    const id = await newGrant();

    expect(await read({ ...GRANTS, fields }, id)).toEqual({ outcome: 'unreadable' });
  });

  it('reports a version the app never writes as unreadable', async () => {
    const id = await newGrant();
    await admin.query('update probe.grants set state_version = 0 where org_id = $1 and id = $2', [ORG, id]);

    expect(await read(GRANTS, id)).toEqual({ outcome: 'unreadable' });
  });

  it('reports two rows with one key as unreadable', async () => {
    const id = newId();
    for (let copy = 0; copy < 2; copy += 1) {
      await admin.query("insert into probe.loose (org_id, id, status) values ($1, $2, 'ACTIVE')", [ORG, id]);
    }

    expect(await read(LOOSE, id)).toEqual({ outcome: 'unreadable' });
  });

  it('reports a pointer that is not a UUID as unreadable', async () => {
    const id = newId();
    await admin.query("insert into probe.loose (org_id, id, status, state_event_id) values ($1, $2, 'ACTIVE', 'x')", [
      ORG,
      id,
    ]);

    expect(await read(LOOSE, id)).toEqual({ outcome: 'unreadable' });
  });
});

describe('ADR-006 §6 the lock a read takes', () => {
  /** Holds the row as a change would (FOR NO KEY UPDATE) and changes its status, until `commit`. */
  async function changing(id: string) {
    const writer = await database.connect('admin');
    await writer.query('begin');
    await writer.query('select 1 from probe.grants where org_id = $1 and id = $2 for no key update', [ORG, id]);
    await writer.query("update probe.grants set status = 'SUSPENDED' where org_id = $1 and id = $2", [ORG, id]);
    return writer;
  }

  it('makes a read for a decision (share) wait for a change to commit, then shows it', async () => {
    const id = await newGrant();
    const writer = await changing(id);
    try {
      const reading = withTenant(app, ORG, (tx) => readSignedRow(tx, GRANTS, { orgId: ORG, id }, 'share'));
      await waitUntilQueued(admin, 1);
      await writer.query('commit');

      expect(await reading).toMatchObject({ outcome: 'found', fields: fieldsWith('status', 'SUSPENDED') });
    } finally {
      await writer.end();
    }
  });

  it('holds a row read for a change (FOR NO KEY UPDATE), so a read for a decision waits for it', async () => {
    const id = await newGrant();
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let locked = (): void => undefined;
    const lockTaken = new Promise<void>((resolve) => {
      locked = resolve;
    });
    const holding = withTenant(app, ORG, async (tx) => {
      await readSignedRow(tx, GRANTS, { orgId: ORG, id }, 'change');
      locked();
      await held;
    });
    await lockTaken;
    const reader = await database.connect('admin');
    try {
      const reading = reader.query('select 1 from probe.grants where org_id = $1 and id = $2 for share', [ORG, id]);
      await waitUntilBlocked(admin, reader.pid);
      release();
      await holding;
      expect(await reading).toHaveLength(1);
    } finally {
      release();
      await reader.end();
    }
  });
});

describe('writing a signed row', () => {
  const write = (id: string, from: Parameters<typeof writeSignedRow>[3], set: SignedFieldValues) =>
    withTenant(app, ORG, (tx) => writeSignedRow(tx, GRANTS, { orgId: ORG, id }, from, set));

  it('moves it to its next version, writes the fields named, points it nowhere, and reads back what it wrote', async () => {
    const id = await newGrant(ORG, EVENT);

    const moved = await write(id, { version: 1, eventId: EVENT.toUpperCase() }, { role: 'owner', amount: 7n });

    expect(moved).toEqual({
      row: {
        outcome: 'found',
        version: 2,
        eventId: null,
        fields: EXPECTED_FIELDS.map(([name, value]) => [
          name,
          name === 'role' ? 'owner' : name === 'amount' ? '7' : value,
        ]),
      },
      written: [
        ['amount', '7'],
        ['role', 'owner'],
      ],
    });
    expect(await rowOf(id)).toMatchObject({ state_version: 2, state_event_id: null });
  });

  it('writes every field of a new row, at version 1, each read back as the column reads it', async () => {
    const id = await newGrant();

    const written = await write(id, 'new', {
      status: 'ACTIVE',
      holder: HOLDER,
      amount: 12_345_678_901_234n,
      expires_at: new Date('2026-09-19T06:11:12.345Z'),
      role: null,
    });

    expect(written.row).toMatchObject({ outcome: 'found', version: 1, eventId: null });
    expect(written.written).toEqual([
      ['status', 'ACTIVE'],
      ['holder', HOLDER.toLowerCase()],
      ['amount', '12345678901234'],
      ['expires_at', '2026-09-19T06:11:12.345000Z'],
      ['role', null],
    ]);
    expect(written.row.outcome === 'found' ? written.row.fields : []).toEqual(written.written);
  });

  it.each([
    ['another version', { version: 2, eventId: EVENT }],
    ['another pointer', { version: 1, eventId: NEXT_EVENT }],
    ['new, though it points at an event', 'new' as const],
  ])('leaves a row that holds %s as it is', async (_, from) => {
    const id = await newGrant(ORG, EVENT);
    const every = { status: 'ACTIVE', holder: null, amount: null, expires_at: null, role: 'owner' };

    expect((await write(id, from, every)).row).toEqual({ outcome: 'missing' });
    expect(await rowOf(id)).toMatchObject({ state_version: 1, state_event_id: EVENT });
  });

  const EVERY = { status: 'ACTIVE', holder: null, amount: null, expires_at: null, role: null };
  const NOT_A_VALUE = /written as text, a whole number, a valid time, or null/;

  it.each<[string, SignedFieldValues, RegExp]>([
    ['a field left out of a new row', { status: 'ACTIVE' }, /names every field/],
    ['a column that is not an authority field', { ...EVERY, label: 'x' }, /Only the authority fields/],
    ['a value that is no field value', { ...EVERY, role: {} as unknown as string }, NOT_A_VALUE],
    ['a number with a fraction', { ...EVERY, amount: 1.5 }, NOT_A_VALUE],
    ['a time that is not one', { ...EVERY, expires_at: new Date(Number.NaN) }, NOT_A_VALUE],
  ])('refuses %s, before any SQL', async (_, set, problem) => {
    const id = await newGrant();

    await expect(write(id, 'new', set)).rejects.toThrow(problem);
    expect(await rowOf(id)).toMatchObject({ state_version: 1, state_event_id: null });
  });

  it('points a row at its version’s event only while it points nowhere, and reads it back', async () => {
    const id = await newGrant();
    const point = (version: number, eventId: string) =>
      withTenant(app, ORG, (tx) => pointSignedRow(tx, GRANTS, { orgId: ORG, id }, { version, eventId }));

    expect(await point(2, EVENT)).toEqual({ outcome: 'missing' });
    expect(await point(1, EVENT.toUpperCase())).toEqual({
      outcome: 'found',
      version: 1,
      eventId: EVENT,
      fields: EXPECTED_FIELDS,
    });
    expect(await point(1, NEXT_EVENT)).toEqual({ outcome: 'missing' });
    expect(await rowOf(id)).toMatchObject({ state_version: 1, state_event_id: EVENT });
  });

  it('refuses a bad table or key before any SQL', async () => {
    const id = await newGrant(ORG, EVENT);
    const from = { version: 1, eventId: EVENT };

    await withTenant(app, ORG, async (tx) => {
      await expect(writeSignedRow(tx, { ...GRANTS, table: 'x' }, { orgId: ORG, id }, from, {})).rejects.toThrow(
        RangeError,
      );
      await expect(writeSignedRow(tx, GRANTS, { orgId: ORG, id: 'x' }, from, {})).rejects.toThrow(RangeError);
      await expect(pointSignedRow(tx, { ...GRANTS, fields: [] }, { orgId: ORG, id }, from)).rejects.toThrow(RangeError);
      await expect(pointSignedRow(tx, GRANTS, { orgId: 'x', id }, from)).rejects.toThrow(RangeError);
    });
  });
});
