// Proofs for the CI-06 checks (schema-checks.ts): each rule fails on a broken
// fixture, and the shapes ADR-005 asks for pass. Each fixture gets its own
// copy of the migrated database.
//
// Roles and their memberships belong to the whole server, which every test
// file shares while it runs. So a fixture that needs a role makes one of its
// own and lets it connect to its own database only, and no test anywhere
// changes the memberships or attributes of the shared agentx_* roles: the
// checks, which read those, would see it from every other database.
import { afterEach, describe, expect, inject, it } from 'vitest';

import { SCHEMA_POLICY } from '../../../../tooling/schema-policy.ts';
import { type SchemaPolicy, schemaProblems } from './schema-checks.ts';
import { createTenantProbe } from './tenant-probe.ts';
import { createTestDatabase, type TestDatabase, type TestRole } from './test-database.ts';

const server = inject('postgres');
const major = Number(server.version.split('.')[0]);

/**
 * The migrated database's own decisions (tooling/schema-policy.ts), so a
 * fixture starts with no problems. The fixtures' own append-only tables go in
 * schema `journal`, apart from the real audit tables.
 */
const LEDGER = { reason: 'The migration ledger', columns: ['name', 'checksum', 'applied_at'] };
const REAL_EXCEPTIONS = SCHEMA_POLICY.appendOnlyExceptions;
const POLICY: SchemaPolicy = {
  globalTables: { ...SCHEMA_POLICY.globalTables, 'migrations.applied': LEDGER },
  appendOnlySchemas: [...SCHEMA_POLICY.appendOnlySchemas, 'journal'],
  appendOnlyExceptions: REAL_EXCEPTIONS,
};
/** The real global tables but the ledger, for the fixtures about the ledger alone. */
const OTHER_GLOBALS = Object.fromEntries(
  Object.entries(SCHEMA_POLICY.globalTables).filter(([name]) => name !== 'migrations.applied'),
);

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

/** t.items, a tenant table built as ADR-005 requires. */
const TENANT_TABLE = [
  'create schema t',
  'create table t.items (org_id uuid not null, id uuid not null, label text not null, primary key (org_id, id))',
  'alter table t.items enable row level security',
  'alter table t.items force row level security',
  `create policy tenant_isolation on t.items ${TENANT_POLICY}`,
];

/** The statements that give a table the tenant walls, for tables other than t.items. */
const walls = (table: string): string[] => [
  `alter table ${table} enable row level security`,
  `alter table ${table} force row level security`,
  `create policy tenant_isolation on ${table} ${TENANT_POLICY}`,
];

/** Lets a fixture role connect to the fixture's database (and so brings it into the checks' view). */
const letConnect = (role: string): readonly [TestRole, string] => [
  'admin',
  `do $$ begin execute pg_catalog.format('grant connect on database %I to ${role}', pg_catalog.current_database()); end $$`,
];

/** A fixture statement: run as the migration role, or as the role named first. */
type Statement = string | readonly [TestRole, string];

let database: TestDatabase | undefined;
let fixtureRoles: string[] = [];

// The state is taken and cleared first, and the database is dropped whatever
// happens, so one broken fixture can't leave anything for the next test.
afterEach(async () => {
  const [current, roles] = [database, fixtureRoles];
  database = undefined;
  fixtureRoles = [];
  if (current === undefined) return;
  try {
    const admin = current.as('admin');
    const found = await admin.query<{ name: string }>(
      'select rolname::text as name from pg_catalog.pg_roles where rolname = any($1)',
      [roles],
    );
    // In the test's order: dropping a member first removes the memberships another role granted it.
    const existing = roles.filter((role) => found.some((row) => row.name === role));
    for (const role of existing) {
      // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup: the role names are fixed in the tests below, and DROP OWNED can't take a parameter.
      await admin.query(`drop owned by ${role}`);
    }
    for (const role of existing) {
      // eslint-disable-next-line agentx/no-string-built-sql -- As above, for DROP ROLE.
      await admin.query(`drop role ${role}`);
    }
  } finally {
    await current.drop();
  }
});

/** A fresh copy of the migrated database with the fixture applied, one statement at a time. */
async function fixture(statements: readonly Statement[]): Promise<TestDatabase> {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of statements) {
    const [role, text] = typeof statement === 'string' ? (['owner', statement] as const) : statement;
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text in the tests below.
    await database.as(role).query(text);
  }
  return database;
}

const problemsAfter = async (statements: readonly Statement[], policy = POLICY): Promise<string[]> =>
  schemaProblems(await fixture(statements), policy);

describe(`CI-06 what passes (Postgres ${server.version})`, () => {
  it('passes the migrated baseline, with its ledger on the global-table list', async () => {
    expect(await problemsAfter([])).toEqual([]);
  });

  it('passes the tenant probe, so the table the SEC-TEN-02 attack tests use is exactly the tenant policy', async () => {
    const probed = await fixture([]);
    await createTenantProbe(probed);
    expect(await schemaProblems(probed, POLICY)).toEqual([]);
  });

  it('passes tenant tables with org_id in every key, and a foreign key to a listed global table', async () => {
    const policy: SchemaPolicy = {
      ...POLICY,
      globalTables: {
        ...POLICY.globalTables,
        'g.people': { reason: 'A person can belong to several organisations', columns: ['id', 'joined_at'] },
      },
    };
    const statements = [
      ...TENANT_TABLE,
      'create schema g',
      'create table g.people (id uuid primary key, joined_at timestamptz not null)',
      `create table t.notes (
         org_id uuid not null, id uuid not null, item_id uuid not null,
         author uuid not null references g.people (id), body text not null,
         primary key (org_id, id), unique (org_id, body),
         foreign key (org_id, item_id) references t.items (org_id, id))`,
      ...walls('t.notes'),
      "create unique index notes_one_blank_per_item on t.notes (item_id, org_id) where body = ''",
    ];
    expect(await problemsAfter(statements, policy)).toEqual([]);
  });

  it('judges a policy by what it calls: current_setting written without pg_catalog is still Postgres’s own', async () => {
    const unqualified =
      "using (org_id = nullif(current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(current_setting('app.org_id', true), '')::uuid)";
    const statements = [...TENANT_TABLE.slice(0, 4), `create policy tenant_isolation on t.items ${unqualified}`];
    expect(await problemsAfter(statements)).toEqual([]);
  });

  it('passes an append-only table the app may only add to and read, while tenant tables elsewhere allow any DML', async () => {
    const statements = [
      ...TENANT_TABLE,
      'grant usage on schema t to agentx_app',
      'grant select, insert, update, delete on t.items to agentx_app',
      'create schema journal',
      'grant usage on schema journal to agentx_app, agentx_backup',
      'create table journal.events (org_id uuid not null, id uuid not null, body text not null, primary key (org_id, id))',
      ...walls('journal.events'),
      'grant insert, select on journal.events to agentx_app',
      'grant select on journal.events to agentx_backup',
      // Drawing numbers for new rows changes no existing row.
      'create sequence journal.event_numbers',
      'grant usage on sequence journal.event_numbers to agentx_app',
    ];
    expect(await problemsAfter(statements)).toEqual([]);
  });

  it('passes default privileges that let the backup role read new tables', async () => {
    expect(await problemsAfter(['alter default privileges grant select on tables to agentx_backup'])).toEqual([]);
  });

  it('ignores a role with BYPASSRLS that can’t connect to this database', async () => {
    fixtureRoles = ['ci06_elsewhere'];
    expect(await problemsAfter([['admin', 'create role ci06_elsewhere nologin bypassrls']])).toEqual([]);
  });

  it('ignores a dropped column of a global table', async () => {
    const policy: SchemaPolicy = {
      ...POLICY,
      globalTables: { ...POLICY.globalTables, 'g.people': { reason: 'A test person', columns: ['id', 'joined_at'] } },
    };
    const statements = [
      'create schema g',
      'create table g.people (id uuid primary key, joined_at timestamptz not null, nickname text)',
      'alter table g.people drop column nickname',
    ];
    expect(await problemsAfter(statements, policy)).toEqual([]);
  });

  it('ignores another session’s temporary table, which lives in a schema of Postgres’s own', async () => {
    const withScratch = await fixture([]);
    const other = await withScratch.connect('admin');
    await other.query('create temporary table scratch (id int)');
    expect(await schemaProblems(withScratch, POLICY)).toEqual([]);
  });
});

describe('CI-06 each rule fails on a broken fixture', () => {
  describe('SEC-TEN-10 (ADR-005 §2): tenant tables have row-level security, enabled and forced', () => {
    it('fails a tenant table with row-level security off', async () => {
      expect(await problemsAfter([...TENANT_TABLE, 'alter table t.items disable row level security'])).toEqual([
        't.items: row-level security is off (ADR-005 §2)',
      ]);
    });

    it('fails a tenant table whose row-level security is not forced', async () => {
      expect(await problemsAfter([...TENANT_TABLE, 'alter table t.items no force row level security'])).toEqual([
        "t.items: row-level security is enabled but not forced, so the table's owner bypasses it (ADR-005 §2)",
      ]);
    });

    it('fails a view, materialized view or foreign table that is not on the global-table list', async () => {
      const statements: Statement[] = [
        ...TENANT_TABLE,
        'create view t.item_labels as select label from t.items',
        'create materialized view t.item_count as select count(*) as n from t.items',
        // A wrapper with no handler: the foreign table can be declared, never read.
        ['admin', 'create foreign data wrapper ci06_nowhere'],
        ['admin', 'create server ci06_nowhere foreign data wrapper ci06_nowhere'],
        ['admin', 'create foreign table t.remote (id int) server ci06_nowhere'],
      ];
      const unwalled = "can't have forced row-level security, so it must be on the global-table list (ADR-005 §2)";
      expect(await problemsAfter(statements)).toEqual([
        `t.item_count: a materialized view ${unwalled}`,
        `t.item_labels: a view ${unwalled}`,
        `t.remote: a foreign table ${unwalled}`,
      ]);
    });

    const PARTITIONED = [
      'create schema t',
      'create table t.events (org_id uuid not null, id uuid not null, at date not null, primary key (org_id, id, at)) partition by range (at)',
      "create table t.events_2026 partition of t.events for values from ('2026-01-01') to ('2027-01-01')",
    ];

    it('fails a partition without walls of its own, even when its parent has them', async () => {
      // A query can name a partition directly, and then only the partition's own policies apply.
      expect(await problemsAfter([...PARTITIONED, ...walls('t.events')])).toEqual([
        't.events_2026: row-level security is off (ADR-005 §2)',
        't.events_2026: has 0 policies; a tenant table has exactly one, the tenant policy (ADR-005 §2)',
      ]);
    });

    it('fails a partitioned table without walls, even when its partitions have them', async () => {
      expect(await problemsAfter([...PARTITIONED, ...walls('t.events_2026')])).toEqual([
        't.events: row-level security is off (ADR-005 §2)',
        't.events: has 0 policies; a tenant table has exactly one, the tenant policy (ADR-005 §2)',
      ]);
    });

    it('treats a table left off the global-table list as a tenant table', async () => {
      expect(await problemsAfter([], { ...POLICY, globalTables: OTHER_GLOBALS })).toEqual([
        'migrations.applied: row-level security is off (ADR-005 §2)',
        'migrations.applied: a tenant table needs an org_id column (ADR-005 §1)',
        'migrations.applied: has 0 policies; a tenant table has exactly one, the tenant policy (ADR-005 §2)',
        "migrations.applied: unique index applied_pkey leaves out org_id, so it could reveal another organisation's rows (SEC-TEN-05)",
      ]);
    });
  });

  describe('SEC-TEN-10 (ADR-005 §1): tenant tables have org_id uuid NOT NULL', () => {
    it('fails a tenant table with no org_id', async () => {
      const statements = [
        'create schema t',
        'create table t.things (id uuid primary key)',
        'alter table t.things enable row level security',
        'alter table t.things force row level security',
        'create policy tenant_isolation on t.things using (true) with check (true)',
      ];
      expect(await problemsAfter(statements)).toEqual([
        't.things: a tenant table needs an org_id column (ADR-005 §1)',
        't.things: policy tenant_isolation is not the tenant policy (ADR-005 §2): its USING is true; its WITH CHECK is true',
        "t.things: unique index things_pkey leaves out org_id, so it could reveal another organisation's rows (SEC-TEN-05)",
      ]);
    });

    it('fails an org_id that may be null', async () => {
      const statements = [
        'create schema t',
        'create table t.loose (org_id uuid, id uuid not null, unique (org_id, id))',
        ...walls('t.loose'),
      ];
      expect(await problemsAfter(statements)).toEqual(['t.loose: org_id must be uuid NOT NULL (ADR-005 §1)']);
    });

    it('fails an org_id that is not a uuid', async () => {
      const statements = [
        'create schema t',
        'create table t.texty (org_id text not null, id uuid not null, primary key (org_id, id))',
        'alter table t.texty enable row level security',
        'alter table t.texty force row level security',
        "create policy tenant_isolation on t.texty using (org_id = current_setting('app.org_id', true)) with check (org_id = current_setting('app.org_id', true))",
      ];
      const problems = await problemsAfter(statements);
      expect(problems[0]).toBe('t.texty: org_id must be uuid NOT NULL (ADR-005 §1)');
      expect(problems[1]).toMatch(/^t\.texty: policy tenant_isolation is not the tenant policy .*its USING is /);
      expect(problems).toHaveLength(2);
    });

    it('fails an org_id NOT NULL added NOT VALID, which leaves old rows unchecked (Postgres 18; 16 has no such form)', async () => {
      const statements = [
        'create schema t',
        'create table t.late (org_id uuid, id uuid not null, unique (org_id, id))',
        'alter table t.late add constraint late_org_id_not_null not null org_id not valid',
        ...walls('t.late'),
      ];
      if (major >= 18) {
        expect(await problemsAfter(statements)).toEqual(['t.late: org_id must be uuid NOT NULL (ADR-005 §1)']);
      } else {
        await expect(problemsAfter(statements)).rejects.toThrow(/syntax error/);
      }
    });
  });

  describe('SEC-TEN-10 (ADR-005 §2): exactly one policy, the tenant policy', () => {
    it('fails a tenant table with no policy', async () => {
      expect(await problemsAfter([...TENANT_TABLE, 'drop policy tenant_isolation on t.items'])).toEqual([
        't.items: has 0 policies; a tenant table has exactly one, the tenant policy (ADR-005 §2)',
      ]);
    });

    it('fails a second policy, which would widen what a query can see', async () => {
      expect(await problemsAfter([...TENANT_TABLE, 'create policy peek on t.items for select using (true)'])).toEqual([
        't.items: has 2 policies; a tenant table has exactly one, the tenant policy (ADR-005 §2)',
      ]);
    });

    const replaced = (policy: string): string[] => [
      ...TENANT_TABLE,
      'drop policy tenant_isolation on t.items',
      `create policy ${policy}`,
    ];

    it.each([
      ['restrictive', `tenant_isolation on t.items as restrictive ${TENANT_POLICY}`, 'it is restrictive'],
      [
        'for SELECT only',
        "tenant_isolation on t.items for select using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)",
        'it covers SELECT only; its WITH CHECK is missing',
      ],
      [
        'for INSERT only',
        "tenant_isolation on t.items for insert with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)",
        'it covers INSERT only; its USING is missing',
      ],
      [
        'for named roles only',
        `tenant_isolation on t.items to agentx_app ${TENANT_POLICY}`,
        'it applies to named roles only',
      ],
      [
        'with no WITH CHECK',
        "tenant_isolation on t.items using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)",
        'its WITH CHECK is missing',
      ],
      [
        'open to every row',
        'tenant_isolation on t.items using (true) with check (true)',
        'its USING is true; its WITH CHECK is true',
      ],
    ])('fails a policy that is %s', async (_, policy, difference) => {
      expect(await problemsAfter(replaced(policy))).toEqual([
        `t.items: policy tenant_isolation is not the tenant policy (ADR-005 §2): ${difference}`,
      ]);
    });

    it('fails a policy with another name', async () => {
      expect(
        await problemsAfter([...TENANT_TABLE, 'alter policy tenant_isolation on t.items rename to walls']),
      ).toEqual([
        't.items: policy walls is not the tenant policy (ADR-005 §2): it is named walls, not tenant_isolation',
      ]);
    });

    it('fails a policy that calls a look-alike current_setting from another schema', async () => {
      const lookalike =
        "using (org_id = nullif(lookalike.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(lookalike.current_setting('app.org_id', true), '')::uuid)";
      const statements = [
        'create schema lookalike',
        "create function lookalike.current_setting(text, boolean) returns text language sql as $$ select '0199a000-0000-7000-8000-00000000000a' $$",
        ...replaced(`tenant_isolation on t.items ${lookalike}`),
      ];
      const problems = await problemsAfter(statements);
      expect(problems).toHaveLength(1);
      expect(problems[0]).toMatch(
        /^t\.items: policy tenant_isolation is not the tenant policy \(ADR-005 §2\): its USING is .*lookalike\.current_setting.*; its WITH CHECK is .*lookalike\.current_setting/,
      );
    });
  });

  describe('SEC-TEN-10 (TEN-9): nothing acts for the app with the owner’s rights', () => {
    // Found by the security review (S8): two functions a migration could add.
    const OWNER_FUNCTIONS = [
      `create function t.unwall() returns void language plpgsql security definer
         as $$ begin execute 'alter table t.items no force row level security'; end $$`,
      'create function t.read_all() returns setof t.items language sql security definer as $$ select * from t.items $$',
    ];

    it('shows the attack: functions that run as the owner let the app switch the walls off and read every organisation', async () => {
      const attacked = await fixture([
        ...TENANT_TABLE,
        // One row for each of two organisations. Each statement runs in one transaction, so the local setting holds for its insert.
        "select pg_catalog.set_config('app.org_id', '0199a000-0000-7000-8000-00000000000a', true); insert into t.items values ('0199a000-0000-7000-8000-00000000000a', gen_random_uuid(), 'a')",
        "select pg_catalog.set_config('app.org_id', '0199b000-0000-7000-8000-00000000000b', true); insert into t.items values ('0199b000-0000-7000-8000-00000000000b', gen_random_uuid(), 'b')",
        ...OWNER_FUNCTIONS,
        'grant usage on schema t to agentx_app',
        'grant execute on function t.unwall(), t.read_all() to agentx_app',
      ]);
      const app = await attacked.connect('app');
      await app.query("select pg_catalog.set_config('app.org_id', '0199a000-0000-7000-8000-00000000000a', false)");
      const labels = async (): Promise<string[]> =>
        (await app.query<{ label: string }>('select label from t.read_all() order by label')).map((row) => row.label);
      // While row-level security is forced, even the owner's function sees one organisation.
      expect(await labels()).toEqual(['a']);
      await app.query('select t.unwall()');
      expect(await labels()).toEqual(['a', 'b']);
    });

    it('fails a SECURITY DEFINER function, whoever may run it', async () => {
      const definer =
        "runs with its owner's rights (SECURITY DEFINER), which would let its callers act as the owner and reach past the tenant walls (ADR-005)";
      expect(await problemsAfter([...TENANT_TABLE, ...OWNER_FUNCTIONS])).toEqual([
        `function t.read_all(): ${definer}`,
        `function t.unwall(): ${definer}`,
      ]);
    });

    it('fails rewrite rules on a table, global or tenant', async () => {
      const policy: SchemaPolicy = {
        ...POLICY,
        globalTables: { ...POLICY.globalTables, 'g.people': { reason: 'A test person', columns: ['id'] } },
      };
      const statements = [
        ...TENANT_TABLE,
        'create rule items_keep as on delete to t.items do instead nothing',
        'create schema g',
        'create table g.people (id uuid primary key)',
        'create rule people_keep as on delete to g.people do instead nothing',
      ];
      const rules =
        "has rewrite rules, which change what a statement does and act with the table owner's rights (ADR-005)";
      expect(await problemsAfter(statements, policy)).toEqual([`g.people: ${rules}`, `t.items: ${rules}`]);
    });

    it('needn’t look where a migration can’t reach: a pg_ schema, or an event trigger', async () => {
      const owner = (await fixture(['create schema t'])).as('owner');
      await expect(owner.query('create schema pg_hidden')).rejects.toThrow(/unacceptable schema name/);
      await owner.query('create function t.on_ddl() returns event_trigger language plpgsql as $$ begin end $$');
      await expect(
        owner.query('create event trigger ci06_watch on ddl_command_start execute function t.on_ddl()'),
      ).rejects.toThrow(/permission denied to create event trigger/);
    });
  });

  describe('SEC-TEN-05: org_id in every unique key and every foreign key to a tenant table', () => {
    const REVEALS = "so it could reveal another organisation's rows (SEC-TEN-05)";
    const LEAKS = `leaves out org_id, ${REVEALS}`;

    it('fails a unique constraint without org_id', async () => {
      expect(
        await problemsAfter([...TENANT_TABLE, 'alter table t.items add constraint items_label_key unique (label)']),
      ).toEqual([`t.items: unique index items_label_key ${LEAKS}`]);
    });

    it('fails a primary key without org_id', async () => {
      const statements = [
        'create schema t',
        'create table t.solo (org_id uuid not null, id uuid primary key)',
        ...walls('t.solo'),
      ];
      expect(await problemsAfter(statements)).toEqual([`t.solo: unique index solo_pkey ${LEAKS}`]);
    });

    it('fails a unique index that only includes org_id as a stored column', async () => {
      const statements = [...TENANT_TABLE, 'create unique index items_label_incl on t.items (label) include (org_id)'];
      expect(await problemsAfter(statements)).toEqual([`t.items: unique index items_label_incl ${LEAKS}`]);
    });

    it('fails an exclusion constraint without org_id', async () => {
      const statements = [
        'create schema t',
        `create table t.bookings (
           org_id uuid not null, id uuid not null, during tstzrange not null, primary key (org_id, id),
           constraint bookings_no_overlap exclude using gist (during with &&))`,
        ...walls('t.bookings'),
      ];
      expect(await problemsAfter(statements)).toEqual([
        `t.bookings: exclusion constraint bookings_no_overlap doesn't require org_id to be equal, ${REVEALS}`,
      ]);
    });

    it('fails an exclusion constraint that names org_id with another operator, and passes one with =', async () => {
      // btree_gist lets a gist index compare uuids. Its functions land in the
      // schema ext with Postgres's default PUBLIC EXECUTE, which the checks
      // report too; only the table's lines matter here.
      const statements = [
        'create schema ext',
        'create extension btree_gist schema ext',
        'create schema t',
        `create table t.bookings (
           org_id uuid not null, id uuid not null, during tstzrange not null, primary key (org_id, id),
           constraint bookings_across exclude using gist (org_id with <>, during with &&),
           constraint bookings_within exclude using gist (org_id with =, during with &&))`,
        ...walls('t.bookings'),
      ];
      const problems = await problemsAfter(statements);
      expect(problems.filter((problem) => problem.startsWith('t.'))).toEqual([
        `t.bookings: exclusion constraint bookings_across doesn't require org_id to be equal, ${REVEALS}`,
      ]);
    });

    it('fails a foreign key between tenant tables that does not pair org_id with org_id', async () => {
      const statements = [
        ...TENANT_TABLE,
        `create table t.notes (
           org_id uuid not null, id uuid not null, item_org uuid not null, item_id uuid not null,
           primary key (org_id, id),
           constraint notes_item foreign key (item_org, item_id) references t.items (org_id, id))`,
        ...walls('t.notes'),
      ];
      expect(await problemsAfter(statements)).toEqual([
        't.notes: foreign key notes_item points at the tenant table t.items without pairing org_id with its org_id (SEC-TEN-05)',
      ]);
    });

    it('fails a foreign key that names org_id but pairs it with another column', async () => {
      // (org_id, item_id) → (id, org_id): the row's org_id is matched against the item's id, and the other way round.
      const statements = [
        ...TENANT_TABLE,
        `create table t.notes (
           org_id uuid not null, id uuid not null, item_id uuid not null,
           primary key (org_id, id),
           constraint notes_item foreign key (org_id, item_id) references t.items (id, org_id))`,
        ...walls('t.notes'),
      ];
      expect(await problemsAfter(statements)).toEqual([
        't.notes: foreign key notes_item points at the tenant table t.items without pairing org_id with its org_id (SEC-TEN-05)',
      ]);
    });

    it('fails a foreign key from a global table into a tenant table, even one that pairs org_id', async () => {
      // A global row's org_id is whatever its writer put there: no policy checks it.
      const policy: SchemaPolicy = {
        ...POLICY,
        globalTables: {
          ...POLICY.globalTables,
          'g.links': { reason: 'A test link', columns: ['id', 'org_id', 'item_id'] },
        },
      };
      const statements = [
        ...TENANT_TABLE,
        'create schema g',
        `create table g.links (
           id uuid primary key, org_id uuid not null, item_id uuid not null,
           constraint links_item foreign key (org_id, item_id) references t.items (org_id, id))`,
      ];
      expect(await problemsAfter(statements, policy)).toEqual([
        'g.links: foreign key links_item runs from a table without row-level security to the tenant table t.items (SEC-TEN-05)',
      ]);
    });
  });

  describe('SEC-TEN-08: a global table is listed with a reason and exactly its columns', () => {
    it('fails an entry for a table that no longer exists', async () => {
      const policy = {
        ...POLICY,
        globalTables: { ...POLICY.globalTables, 'g.gone': { reason: 'Removed', columns: ['id'] } },
      };
      expect(await problemsAfter([], policy)).toEqual([
        'g.gone: is on the global-table list, but no such table exists',
      ]);
    });

    it('fails an entry with no reason, or a column named twice', async () => {
      const policy = {
        ...POLICY,
        globalTables: {
          ...OTHER_GLOBALS,
          'migrations.applied': { reason: ' ', columns: ['name', 'name', 'checksum', 'applied_at'] },
        },
      };
      expect(await problemsAfter([], policy)).toEqual([
        'migrations.applied: the global-table list gives no reason for it',
        'migrations.applied: the global-table list names a column twice',
      ]);
    });

    it('fails a column the list does not name, and a listed column the table lacks', async () => {
      const policy = {
        ...POLICY,
        globalTables: {
          ...OTHER_GLOBALS,
          'migrations.applied': { ...LEDGER, columns: ['name', 'checksum', 'applied_on'] },
        },
      };
      expect(await problemsAfter([], policy)).toEqual([
        'migrations.applied: column applied_at is not on the global-table list, so no one has reviewed it (SEC-TEN-08)',
        "migrations.applied: the global-table list names column applied_on, which the table doesn't have",
      ]);
    });
  });

  describe('SEC-TEN-10 (ADR-005 §8): no PUBLIC grants', () => {
    it.each([
      ['a table', [...TENANT_TABLE, 'grant select on t.items to public'], 'table t.items: PUBLIC has SELECT'],
      [
        'a column',
        [...TENANT_TABLE, 'grant update (label) on t.items to public'],
        'column t.items.label: PUBLIC has UPDATE',
      ],
      [
        'a sequence',
        ['create schema t', 'create sequence t.counter', 'grant usage on sequence t.counter to public'],
        'sequence t.counter: PUBLIC has USAGE',
      ],
      ['a schema', ['create schema t', 'grant usage on schema t to public'], 'schema t: PUBLIC has USAGE'],
      [
        'a function, by grant',
        [
          'create schema t',
          'create function t.helper() returns int language sql as $$ select 1 $$',
          'grant execute on function t.helper() to public',
        ],
        'function t.helper(): PUBLIC has EXECUTE',
      ],
      [
        // Named with its schema, even the public one.
        'a function in the public schema',
        [
          'create function public.helper() returns int language sql as $$ select 1 $$',
          'grant execute on function public.helper() to public',
        ],
        'function public.helper(): PUBLIC has EXECUTE',
      ],
      [
        // Postgres's built-in default: a null ACL means every role may run it.
        'a function, by the built-in default for a creator the baseline does not cover',
        [
          'create schema t',
          ['admin', 'create function t.helper() returns int language sql as $$ select 1 $$'] as const,
        ],
        'function t.helper(): PUBLIC has EXECUTE',
      ],
      [
        'the default privileges for new tables',
        ['alter default privileges grant select on tables to public'],
        'default privileges of agentx_owner for new tables: PUBLIC has SELECT',
      ],
      [
        'the default privileges for new functions in a schema',
        ['create schema t', 'alter default privileges in schema t grant execute on functions to public'],
        'default privileges of agentx_owner for new functions in schema t: PUBLIC has EXECUTE',
      ],
    ] as const)('fails a PUBLIC grant on %s', async (_, statements, problem) => {
      expect(await problemsAfter(statements)).toEqual([`${problem} (ADR-005 §8)`]);
    });

    it('fails a PUBLIC grant on the database', async () => {
      const statements: Statement[] = [
        "do $$ begin execute pg_catalog.format('grant temporary on database %I to public', pg_catalog.current_database()); end $$",
      ];
      const problems = await problemsAfter(statements);
      expect(problems).toEqual([`database ${database?.name ?? ''}: PUBLIC has TEMPORARY (ADR-005 §8)`]);
    });

    it('fails a database whose rights were never set, which Postgres opens to PUBLIC by default', async () => {
      const statements: Statement[] = [
        ['admin', 'update pg_catalog.pg_database set datacl = null where datname = pg_catalog.current_database()'],
      ];
      const problems = await problemsAfter(statements);
      // Every role on the server may then connect, so the role checks report on all of them too.
      expect(problems.filter((problem) => problem.startsWith('database '))).toEqual([
        `database ${database?.name ?? ''}: PUBLIC has CONNECT (ADR-005 §8)`,
        `database ${database?.name ?? ''}: PUBLIC has TEMPORARY (ADR-005 §8)`,
      ]);
    });
  });

  describe('SEC-TEN-10 (ADR-005 §3): the roles', () => {
    it('fails a role with BYPASSRLS, other than agentx_backup, that can connect', async () => {
      fixtureRoles = ['ci06_bypass'];
      const statements = [['admin', 'create role ci06_bypass nologin bypassrls'] as const, letConnect('ci06_bypass')];
      expect(await problemsAfter(statements)).toEqual([
        'role ci06_bypass has BYPASSRLS; only agentx_backup may (ADR-005 §3)',
      ]);
    });

    it('fails a role that can connect being a member of another role, once however many granted it', async () => {
      fixtureRoles = ['ci06_member', 'ci06_group', 'ci06_granter'];
      const statements = [
        ['admin', 'create role ci06_member nologin'] as const,
        ['admin', 'create role ci06_group nologin'] as const,
        ['admin', 'create role ci06_granter nologin'] as const,
        letConnect('ci06_member'),
        ['admin', 'grant ci06_group to ci06_member'] as const,
        // Postgres keeps a second row for the same membership from a second grantor.
        ['admin', 'grant ci06_group to ci06_granter with admin option'] as const,
        ['admin', 'grant ci06_group to ci06_member granted by ci06_granter'] as const,
      ];
      expect(await problemsAfter(statements)).toEqual([
        "role ci06_member is a member of ci06_group; the database's roles take part in no role memberships (ADR-005 §3)",
      ]);
    });

    it('fails a role that can connect having a member, even one that cannot connect itself', async () => {
      fixtureRoles = ['ci06_outsider', 'ci06_group'];
      const statements = [
        ['admin', 'create role ci06_outsider nologin noinherit'] as const,
        ['admin', 'create role ci06_group nologin'] as const,
        letConnect('ci06_group'),
        ['admin', 'grant ci06_group to ci06_outsider'] as const,
      ];
      expect(await problemsAfter(statements)).toEqual([
        "role ci06_outsider is a member of ci06_group; the database's roles take part in no role memberships (ADR-005 §3)",
      ]);
    });

    it('fails agentx_backup holding anything but read access', async () => {
      const statements = [
        ...TENANT_TABLE,
        'grant usage, create on schema t to agentx_backup',
        'grant select, insert on t.items to agentx_backup',
        'grant update (label) on t.items to agentx_backup',
        'create sequence t.counter',
        'grant usage on sequence t.counter to agentx_backup',
        'create function t.helper() returns int language sql as $$ select 1 $$',
        'grant execute on function t.helper() to agentx_backup',
      ];
      const reads = 'it may only read (ADR-005 §3)';
      expect(await problemsAfter(statements)).toEqual([
        `column t.items.label: agentx_backup has UPDATE; ${reads}`,
        `function t.helper(): agentx_backup has EXECUTE; ${reads}`,
        `schema t: agentx_backup has CREATE; ${reads}`,
        `sequence t.counter: agentx_backup has USAGE; ${reads}`,
        `table t.items: agentx_backup has INSERT; ${reads}`,
      ]);
    });
  });

  describe('SEC-EVD-01: the app role only adds to and reads an append-only table', () => {
    it('fails UPDATE, DELETE or TRUNCATE for the app role on an append-only table, or UPDATE on one of its columns', async () => {
      const statements = [
        'create schema journal',
        'grant usage on schema journal to agentx_app',
        'create table journal.events (org_id uuid not null, id uuid not null, body text not null, primary key (org_id, id))',
        ...walls('journal.events'),
        'grant select, insert, update, delete, truncate on journal.events to agentx_app',
        'grant update (body) on journal.events to agentx_app',
      ];
      const appends = 'on an append-only table; it may only INSERT and SELECT (SEC-EVD-01)';
      expect(await problemsAfter(statements)).toEqual([
        `column journal.events.body: agentx_app has UPDATE ${appends}`,
        `table journal.events: agentx_app has DELETE ${appends}`,
        `table journal.events: agentx_app has TRUNCATE ${appends}`,
        `table journal.events: agentx_app has UPDATE ${appends}`,
      ]);
    });

    const CHAIN_HEADS = [
      'create schema journal',
      'grant usage on schema journal to agentx_app',
      'create table journal.heads (org_id uuid not null, sequence bigint not null, primary key (org_id))',
      ...walls('journal.heads'),
      // The app locks the head FOR NO KEY UPDATE and moves it on (ADR-006 §6), which needs UPDATE.
      'grant select, insert, update on journal.heads to agentx_app',
    ];

    it('lets the app change a table on the exception list, with its reason', async () => {
      const policy = {
        ...POLICY,
        appendOnlyExceptions: { ...REAL_EXCEPTIONS, 'journal.heads': 'One chain head per organisation' },
      };
      expect(await problemsAfter(CHAIN_HEADS, policy)).toEqual([]);
    });

    it('fails the same table off the exception list', async () => {
      expect(await problemsAfter(CHAIN_HEADS)).toEqual([
        'table journal.heads: agentx_app has UPDATE on an append-only table; it may only INSERT and SELECT (SEC-EVD-01)',
      ]);
    });

    it('fails DELETE on a table on the exception list: the app moves a chain head on, never deletes it', async () => {
      const policy = {
        ...POLICY,
        appendOnlyExceptions: { ...REAL_EXCEPTIONS, 'journal.heads': 'One chain head per organisation' },
      };
      expect(await problemsAfter([...CHAIN_HEADS, 'grant delete on journal.heads to agentx_app'], policy)).toEqual([
        'table journal.heads: agentx_app has DELETE on an append-only exception; it may only INSERT, SELECT and UPDATE (SEC-EVD-01)',
      ]);
    });

    it('fails an exception with no reason, for a missing table, or outside an append-only schema', async () => {
      const policy = {
        ...POLICY,
        appendOnlyExceptions: {
          ...REAL_EXCEPTIONS,
          'journal.heads': ' ',
          'journal.gone': 'Removed',
          'migrations.applied': 'Not audit',
        },
      };
      expect(await problemsAfter(CHAIN_HEADS, policy)).toEqual([
        'journal.heads: the append-only exception list gives no reason for it',
        'journal.gone: is on the append-only exception list, but no such table exists',
        "migrations.applied: is on the append-only exception list, but its schema isn't append-only",
      ]);
    });
  });

  describe('SEC-TEN-10 (ADR-005 §3): the app role only reads and writes rows on any other table (A3f-1)', () => {
    it('fails TRUNCATE, TRIGGER, REFERENCES or MAINTAIN for the app role on any other table or its columns (A3f-1)', async () => {
      // MAINTAIN is a right only from Postgres 17.
      const maintain = major >= 17;
      const statements = [
        ...TENANT_TABLE,
        'grant usage on schema t to agentx_app',
        'grant select, insert, update, delete, truncate, trigger, references on t.items to agentx_app',
        'grant references (label) on t.items to agentx_app',
        ...(maintain ? ['grant maintain on t.items to agentx_app'] : []),
      ];
      const rows = 'on a table it may only SELECT, INSERT, UPDATE and DELETE (ADR-005 §3)';
      expect(await problemsAfter(statements)).toEqual([
        `column t.items.label: agentx_app has REFERENCES; ${rows}`,
        ...(maintain ? [`table t.items: agentx_app has MAINTAIN; ${rows}`] : []),
        `table t.items: agentx_app has REFERENCES; ${rows}`,
        `table t.items: agentx_app has TRIGGER; ${rows}`,
        `table t.items: agentx_app has TRUNCATE; ${rows}`,
      ]);
    });
  });
});
