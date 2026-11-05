// A rehearsal, on a throwaway migrated database, of ADR-005 §9's change to
// `access.requests` when the lawyer answers (PL-42; 4D2e Stage F design,
// "access.requests when the lawyer answers", PR 14): the existing table attached
// as the first partition of a `RANGE (id)` parent, no copy, under forced row
// security. It adds no migration and ships no partition: the statement lists
// below are what the migrations would hold, run by the owner, each list a file of
// its own, since a file runs in one transaction and a lock taken in it stays
// until it ends. The schema guard's words on the result are pinned here as the
// evidence that migration will need: the guard itself is not changed.
//
// A small table keeps CI quick: what the attach does doesn't depend on its size,
// as the scan counts below show.
import { createDatabase, type Database, liveSchemaDrift, SCHEMA_POLICY, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  schemaProblems,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { sql, type Transaction } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { createActivityLog, type OrganisationRequest } from './activity-log.ts';
import { digestOfDay, v7Floor } from './activity-seal.ts';
import type { ActivityTables } from './tables.ts';

const server = inject('postgres');
const ROWS = 2000;
const BIG_TABLE_MS = 30 * 60_000;

const ORG_A = '0199a0f0-0000-7000-8000-00000000f1a1';
const ORG_B = '0199a0f0-0000-7000-8000-00000000f1b2';
const ORG_C = '0199a0f0-0000-7000-8000-00000000f1c3';
const PERSON = '0199a0f0-0000-7000-8000-00000000f1d4';
const CORRELATION = '0199a0f0-0000-7000-8000-00000000f1e5';

/** The bulk rows' first instant, and so their day: 1 October 2026, 500 ms apart. */
const BULK_FROM = Date.UTC(2026, 9, 1);
const BULK_DAY = '2026-10-01';

/** The owner's months: 24 from the cut, then a catch-all for anything past them. */
const MONTHS_AHEAD = 24;
const CUT = v7Floor(Date.UTC(2027, 0, 1));
const startOfMonth = (ahead: number): number => Date.UTC(2027, ahead, 1);
const nameOfMonth = (ahead: number): string =>
  `requests_${new Date(startOfMonth(ahead)).toISOString().slice(0, 7).replace('-', '_')}`;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;
/** The guard as the API runs it (schema-check.ts), so its words here are the ones staging would log. */
const GUARD = {
  ...ROLES,
  authorityTables: AUTHORITY_TABLES,
  statusGuardedTables: AUTHORITY_TABLES.filter((table) => table.rules !== undefined).map(({ table }) => table),
  madeOnceTables: AUTHORITY_TABLES.filter((table) => table.madeOnce === true).map(({ table }) => table),
  fixedAtCreation: Object.fromEntries(
    AUTHORITY_TABLES.flatMap(({ table, fixedAtCreation }) =>
      fixedAtCreation === undefined ? [] : [[table, fixedAtCreation]],
    ),
  ),
};
const WALL = "org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid";

/** The walls a partition doesn't get from its parent: Postgres copies no row security and no grant. */
const walled = (table: string): readonly string[] => [
  `ALTER TABLE access.${table} ENABLE ROW LEVEL SECURITY`,
  `ALTER TABLE access.${table} FORCE ROW LEVEL SECURITY`,
  `CREATE POLICY tenant_isolation ON access.${table} USING (${WALL}) WITH CHECK (${WALL})`,
  `GRANT SELECT ON access.${table} TO agentx_backup`,
];

const monthBounds = (ahead: number): string =>
  `FROM ('${v7Floor(startOfMonth(ahead))}') TO ('${v7Floor(startOfMonth(ahead + 1))}')`;

/** File 1: the first partition's bound, as a check that takes a moment and scans nothing yet. */
const ADD_CUT = [`ALTER TABLE access.requests ADD CONSTRAINT requests_before_cut CHECK (id < '${CUT}') NOT VALID`];
/** File 2: the scan, under a lock that lets writers on, so that the attach needn't scan. */
const VALIDATE_CUT = ['ALTER TABLE access.requests VALIDATE CONSTRAINT requests_before_cut'];

/** File 3, up to the attach: the old table out of the way, and an empty parent with its walls, in the old one's name. */
const BEFORE_ATTACH: readonly string[] = [
  'ALTER TABLE access.requests RENAME TO requests_first',
  'ALTER INDEX access.requests_pkey RENAME TO requests_first_pkey',
  'ALTER INDEX access.requests_by_time RENAME TO requests_first_by_time',
  'ALTER INDEX access.requests_by_actor RENAME TO requests_first_by_actor',
  'CREATE TABLE access.requests (LIKE access.requests_first INCLUDING DEFAULTS INCLUDING CONSTRAINTS) PARTITION BY RANGE (id)',
  // LIKE copied the cut too, which no month could meet: the first partition's bound says it now.
  'ALTER TABLE access.requests DROP CONSTRAINT IF EXISTS requests_before_cut',
  'ALTER TABLE access.requests ADD PRIMARY KEY (org_id, id)',
  'CREATE INDEX requests_by_time ON access.requests (org_id, recorded_at, id)',
  'CREATE INDEX requests_by_actor ON access.requests (org_id, actor_type, actor_id, recorded_at, id)',
  'ALTER TABLE access.requests ENABLE ROW LEVEL SECURITY',
  'ALTER TABLE access.requests FORCE ROW LEVEL SECURITY',
  `CREATE POLICY tenant_isolation ON access.requests USING (${WALL}) WITH CHECK (${WALL})`,
  'GRANT SELECT, INSERT ON access.requests TO agentx_app',
  'GRANT SELECT ON access.requests TO agentx_backup',
  // The operator's exports read the log through its parent alone (PL-57): its right moves there, as its list holds it.
  'GRANT SELECT ON access.requests TO agentx_operator',
  'REVOKE SELECT ON access.requests_first FROM agentx_operator',
];

const ATTACH = [
  `ALTER TABLE access.requests ATTACH PARTITION access.requests_first FOR VALUES FROM (MINVALUE) TO ('${CUT}')`,
];

/** File 3, after the attach: the months and the catch-all, and the app reaching rows through the parent alone. */
const AFTER_ATTACH: readonly string[] = [
  'ALTER TABLE access.requests_first DROP CONSTRAINT requests_before_cut',
  'REVOKE ALL ON access.requests_first FROM agentx_app',
  ...Array.from({ length: MONTHS_AHEAD }, (_, ahead) => [
    `CREATE TABLE access.${nameOfMonth(ahead)} PARTITION OF access.requests FOR VALUES ${monthBounds(ahead)}`,
    ...walled(nameOfMonth(ahead)),
  ]).flat(),
  'CREATE TABLE access.requests_later PARTITION OF access.requests DEFAULT',
  ...walled('requests_later'),
];

let database: TestDatabase;
let app: Database<ActivityTables>;
let owner: Awaited<ReturnType<TestDatabase['connect']>>;
const log = createActivityLog({ ids: new SequentialIds(0xf140_0000) });
/** The log with every row given this one ID: to place a row in a chosen partition. */
const logAs = (id: string) => createActivityLog({ ids: { next: () => id } });

const inOrg =
  (orgId: string) =>
  <T>(work: (tx: Transaction<ActivityTables>) => Promise<T>): Promise<T> =>
    withTenant(app, orgId, work);

const request = (orgId: string, route = '/v1/agents/:id/suspend'): OrganisationRequest => ({
  at: new Date('2026-10-18T10:00:00.000Z'),
  method: 'POST',
  route,
  pathIds: [PERSON],
  status: 200,
  reason: undefined,
  correlationId: CORRELATION,
  durationMs: 12,
  client: {
    ip: '2001:db8::7',
    place: { country: 'AE', city: 'Abu Dhabi' },
    timeZone: { name: 'Asia/Dubai', from: 'organisation' },
  },
  orgId,
  actor: { type: 'user', id: PERSON },
});

/** Each statement in order, on the owner's connection, as a migration file holds them. */
async function runAll(statements: readonly string[]): Promise<void> {
  // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the lists above.
  for (const statement of statements) await owner.query(statement);
}

/** `count` rows of one organisation written behind its wall, their UUIDv7 IDs 500 ms apart from BULK_FROM. */
async function bulkRows(orgId: string, count: number): Promise<void> {
  await owner.query('begin');
  await owner.query("select pg_catalog.set_config('app.org_id', $1, true)", [orgId]);
  await owner.query(
    `insert into access.requests (org_id, id, recorded_at, actor_type, actor_id, method, route, path_ids, status,
       correlation_id, duration_ms)
     select $1::uuid,
            (substr(h, 1, 8) || '-' || substr(h, 9, 4) || '-7000-8000-' || lpad(to_hex(n), 12, '0'))::uuid,
            to_timestamp(($2::bigint + n * 500) / 1000.0), 'user', $3::uuid, 'POST', '/v1/agents/:id/suspend',
            array[$3::uuid], 200, $4::uuid, 12
     from generate_series(1, $5::bigint) as n,
          lateral (select lpad(to_hex($2::bigint + n * 500), 12, '0') as h) as t`,
    [orgId, BULK_FROM, PERSON, CORRELATION, count],
  );
  await owner.query('commit');
}

/** How many rows an organisation's own wall shows the app. */
const rowsOf = async (orgId: string): Promise<number> => {
  const { n } = await inOrg(orgId)((tx) =>
    tx
      .selectFrom('access.requests')
      .select((eb) => eb.fn.countAll<string>().as('n'))
      .executeTakeFirstOrThrow(),
  );
  return Number(n);
};

/** How many full scans of the old table the owner's open transaction makes while `statements` run, whatever its name by then. */
async function scansWhile(statements: readonly string[]): Promise<number> {
  const scans = async () => {
    const [row] = await owner.query<{ scans: string }>(
      'select seq_scan as scans from pg_catalog.pg_stat_xact_all_tables where relid = $1::oid',
      [tableOid],
    );
    return Number(row?.scans);
  };
  const before = await scans();
  await runAll(statements);
  return (await scans()) - before;
}

/** The partition a row is in, read by the backup role, which reads every row. */
const partitionOf = async (id: string): Promise<string | undefined> => {
  const [row] = await database
    .as('backup')
    .query<{ partition: string }>(
      'select tableoid::regclass::text as partition from access.requests where id = $1::uuid',
      [id],
    );
  return row?.partition;
};

/** The table's file on disk, by name: the same file is the same rows, never a copy. */
const fileOf = async (table: string): Promise<string | undefined> => {
  const [row] = await database
    .as('admin')
    .query<{ file: string }>('select pg_catalog.pg_relation_filenode($1::text::regclass)::text as file', [table]);
  return row?.file;
};

let fileBefore: string | undefined;
let tableOid: string | undefined;
let digestBefore: Awaited<ReturnType<typeof digestOfDay>>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<ActivityTables>({ ...database.connection('app'), maxConnections: 3 }, testLogger());
  owner = await database.connect('owner');
  await bulkRows(ORG_A, Math.floor(ROWS / 2));
  await bulkRows(ORG_B, ROWS - Math.floor(ROWS / 2));
  fileBefore = await fileOf('access.requests');
  [{ oid: tableOid } = { oid: undefined }] = await owner.query<{ oid: string }>(
    "select 'access.requests'::regclass::oid::text as oid",
  );
  digestBefore = await digestOfDay(inOrg(ORG_A), ORG_A, BULK_DAY, 500);
}, BIG_TABLE_MS);

afterAll(async () => {
  await owner.end();
  await app.destroy();
  await database.drop();
});

describe(`access.requests attached as its first partition, a rehearsal (ADR-005 §9, PL-42, Postgres ${server.version})`, () => {
  it('starts clean, so what the guard says later is the change alone', async () => {
    expect(await liveSchemaDrift(app, GUARD)).toEqual({ atOnce: [], releaseShaped: [] });
    expect(await schemaProblems(database, SCHEMA_POLICY)).toEqual([]);
  });

  it(
    'without the check first, the attach scans the whole table while it holds it',
    { timeout: BIG_TABLE_MS },
    async () => {
      await owner.query('begin');
      await runAll(BEFORE_ATTACH);
      expect(await scansWhile(ATTACH)).toBe(1);
      await owner.query('rollback');
    },
  );

  it(
    'the check is added, then validated in a file of its own while the app goes on writing',
    { timeout: BIG_TABLE_MS },
    async () => {
      await runAll(ADD_CUT);
      await owner.query('begin');
      await runAll(VALIDATE_CUT);
      // Its lock stays until commit: a write getting through now got through during the scan too.
      await within(10_000, log.recordForOrganisation(app, request(ORG_C, '/v1/while/validating')), 'a write');
      await owner.query('commit');
    },
  );

  it(
    'the swap scans nothing, copies nothing, and a write queued behind it lands in the new table',
    { timeout: BIG_TABLE_MS },
    async () => {
      const counted = { a: await rowsOf(ORG_A), b: await rowsOf(ORG_B), c: await rowsOf(ORG_C) };
      await owner.query('begin');
      const scans = await scansWhile([...BEFORE_ATTACH, ...ATTACH, ...AFTER_ATTACH]);

      const queuedId = '00000000-0000-7000-8000-0000f14a0001';
      const queued = logAs(queuedId).recordForOrganisation(app, request(ORG_C, '/v1/while/swapping'));
      await waitUntilQueued(database.as('admin'), 1);
      await owner.query('commit');
      await within(10_000, queued, 'the queued write');

      expect(scans).toBe(0);
      expect(await fileOf('access.requests_first')).toBe(fileBefore);
      expect(await partitionOf(queuedId)).toBe('access.requests_first');
      expect({ a: await rowsOf(ORG_A), b: await rowsOf(ORG_B), c: await rowsOf(ORG_C) }).toEqual({
        ...counted,
        c: counted.c + 1,
      });
      // The rows from before read alike, so a day sealed over them still holds.
      expect(await digestOfDay(inOrg(ORG_A), ORG_A, BULK_DAY, 500)).toEqual(digestBefore);
    },
  );

  it('keeps the wall: an organisation reads and writes only its own, whichever partition the rows are in', async () => {
    const inMonth = v7Floor(startOfMonth(3)).replace(/.{12}$/, '0000000000f1');
    await logAs(inMonth).recordForOrganisation(app, request(ORG_C));
    expect(await partitionOf(inMonth)).toBe(`access.${nameOfMonth(3)}`);
    const read = (orgId: string) =>
      inOrg(orgId)((tx) => tx.selectFrom('access.requests').select('id').where('id', '=', inMonth).execute());
    expect(await read(ORG_C)).toHaveLength(1);
    expect(await read(ORG_A)).toEqual([]);

    // No organisation set: nothing, through the parent, or as the owner, whom the wall holds too.
    expect(await app.selectFrom('access.requests').select('id').limit(1).execute()).toEqual([]);
    for (const table of ['requests', 'requests_first', nameOfMonth(3), 'requests_later']) {
      // eslint-disable-next-line agentx/no-string-built-sql -- a fixed name from the list just above
      expect(await owner.query(`select id from access.${table} limit 1`)).toEqual([]);
    }

    // Another organisation's row refused on its way in, into the first partition and a month alike.
    for (const id of ['00000000-0000-7000-8000-0000f14a0002', v7Floor(startOfMonth(4))]) {
      const planted = inOrg(ORG_A)((tx) =>
        sql`insert into access.requests (org_id, id, recorded_at, actor_type, actor_id, method, route, path_ids, status, correlation_id, duration_ms)
              values (${ORG_B}::uuid, ${id}::uuid, now(), 'user', ${PERSON}::uuid, 'GET', '/v1/x', '{}', 200, ${CORRELATION}::uuid, 1)`.execute(
          tx,
        ),
      );
      await expect(planted).rejects.toMatchObject({ code: '42501' });
    }

    // One row a place, as the old key held: the same ID twice in one organisation is refused.
    await expect(logAs(inMonth).recordForOrganisation(app, request(ORG_C))).rejects.toMatchObject({ code: '23505' });
  });

  it('keeps the app’s rights: it adds and reads through the parent alone, and changes nothing', async () => {
    const asApp = await database.connect('app');
    await asApp.query('begin');
    await asApp.query("select pg_catalog.set_config('app.org_id', $1, true)", [ORG_C]);
    const refusals = [
      'select id from access.requests_first limit 1',
      'select id from access.requests_2027_01 limit 1',
      'select id from access.requests_later limit 1',
      'insert into access.requests_later select * from access.requests limit 0',
      "update access.requests set route = '/v1/changed'",
      'delete from access.requests',
      'truncate access.requests',
    ];
    for (const statement of refusals) {
      await asApp.query('savepoint try');
      // eslint-disable-next-line agentx/no-string-built-sql -- fixed text from the list just above
      await expect(asApp.query(statement), statement).rejects.toMatchObject({ code: '42501' });
      await asApp.query('rollback to savepoint try');
    }
    await asApp.query('rollback');
    await asApp.end();

    // The parent's own grants are the old table's, exactly.
    const [grants] = await database.as('admin').query<{ app: string[]; backup: string[]; operator: string[] }>(
      `select array(select privilege_type::text from information_schema.role_table_grants
                     where table_schema = 'access' and table_name = 'requests' and grantee = 'agentx_app' order by 1) as app,
              array(select privilege_type::text from information_schema.role_table_grants
                     where table_schema = 'access' and table_name = 'requests' and grantee = 'agentx_backup' order by 1) as backup,
              array(select privilege_type::text from information_schema.role_table_grants
                     where table_schema = 'access' and table_name = 'requests' and grantee = 'agentx_operator' order by 1) as operator`,
    );
    expect(grants).toEqual({ app: ['INSERT', 'SELECT'], backup: ['SELECT'], operator: ['SELECT'] });

    // The backup role reads everything, each partition too, as a logical backup must.
    const backup = database.as('backup');
    const [whole] = await backup.query<{ n: string }>('select count(*) as n from access.requests');
    expect(Number(whole?.n)).toBeGreaterThanOrEqual(ROWS);
    for (const table of ['requests_first', nameOfMonth(0), 'requests_later']) {
      // eslint-disable-next-line agentx/no-string-built-sql -- a fixed name from the list just above
      await backup.query(`select 1 from access.${table} limit 1`);
    }
  });

  it('sends an ID past the months to the catch-all, and a read by ID range to one partition alone', async () => {
    const far = v7Floor(Date.UTC(2100, 0, 1));
    await logAs(far).recordForOrganisation(app, request(ORG_C));
    expect(await partitionOf(far)).toBe('access.requests_later');

    /** The partitions Postgres plans to read for a query on the parent. */
    const partitionsRead = async (where: string): Promise<number> => {
      const backup = database.as('backup');
      // eslint-disable-next-line agentx/no-string-built-sql -- fixed text from the two calls just below
      const [row] = await backup.query(`explain (format json) select id from access.requests where ${where}`);
      return new Set(JSON.stringify(row?.['QUERY PLAN']).match(/"Relation Name":"[^"]+"/g)).size;
    };
    const month = `id >= '${v7Floor(startOfMonth(5))}' and id < '${v7Floor(startOfMonth(5) + 86_400_000)}'`;
    // A seal's read of a day goes by ID: one partition.
    expect(await partitionsRead(`org_id = '${ORG_C}' and ${month}`)).toBe(1);
    // A page by time has no ID to go by: it asks every partition, and that grows with the months kept.
    expect(await partitionsRead(`org_id = '${ORG_C}' and recorded_at > now()`)).toBe(MONTHS_AHEAD + 2);
  });

  it('the next month attaches with the app still writing, and is refused while the catch-all holds a row of it', async () => {
    const standalone = (ahead: number): readonly string[] => [
      `CREATE TABLE access.${nameOfMonth(ahead)} (LIKE access.requests INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES)`,
      ...walled(nameOfMonth(ahead)),
    ];
    const attachMonth = (ahead: number) => [
      `ALTER TABLE access.requests ATTACH PARTITION access.${nameOfMonth(ahead)} FOR VALUES ${monthBounds(ahead)}`,
    ];

    await owner.query('begin');
    await runAll([...standalone(MONTHS_AHEAD), ...attachMonth(MONTHS_AHEAD)]);
    await within(10_000, log.recordForOrganisation(app, request(ORG_C, '/v1/while/attaching')), 'a write');
    await owner.query('commit');

    await logAs(v7Floor(startOfMonth(MONTHS_AHEAD + 1))).recordForOrganisation(app, request(ORG_C));
    await owner.query('begin');
    await runAll(standalone(MONTHS_AHEAD + 1));
    await expect(runAll(attachMonth(MONTHS_AHEAD + 1))).rejects.toMatchObject({ code: '23514' });
    await owner.query('rollback');
  });

  it('the guard: today’s image calls the parent drift at once, and each partition’s checks unknown', async () => {
    const { atOnce, releaseShaped } = await liveSchemaDrift(app, GUARD);
    // The 24 months, the first, the catch-all and the month attached above.
    const PARTITIONS = MONTHS_AHEAD + 3;
    /** Each kind of problem, by how many times it's said: every partition's name one word, the rest exact. */
    const kinds = (problems: readonly string[]) =>
      Object.fromEntries(
        Object.entries(
          Object.groupBy(problems, (problem) => problem.replace(/^access\.requests_\w+/, 'a partition')),
        ).map(([kind, said]) => [kind, said?.length]),
      );
    expect(kinds(atOnce)).toEqual({
      'access.requests is in an inheritance tree': 1,
      'access.requests is no longer a plain table': 1,
      'access.requests is partitioned': 1,
      'a partition is in an inheritance tree': PARTITIONS,
    });
    // The parent's own checks are the migrations' by name; each partition's copy of them is a table it doesn't know.
    expect(kinds(releaseShaped)).toEqual(
      Object.fromEntries(
        [
          'city_with_its_country',
          'key_on_an_agents_row_alone',
          'requests_actor_type_check',
          'requests_city_check',
          'requests_country_check',
          'requests_duration_ms_check',
          'requests_method_check',
          'requests_path_ids_check',
          'requests_reason_check',
          'requests_route_check',
          'requests_status_check',
          'requests_time_zone_check',
          'requests_time_zone_from_check',
          'time_zone_with_its_source',
        ].map((check) => [`a partition's CHECK constraint "${check}" is not one the migrations built`, PARTITIONS]),
      ),
    );
    // CI-06, run on the migrations, says nothing of it.
    expect(await schemaProblems(database, SCHEMA_POLICY)).toEqual([]);
  });
});
