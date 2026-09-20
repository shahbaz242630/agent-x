// Proofs for the authority-table checks (authority-checks.ts): each rule fails
// on a broken fixture, and the shape ADR-012 §2 and ADR-007 §1 ask for passes.
// Each fixture gets its own copy of the migrated database, so the real status
// guard (db/migrations/0004) and the real app role are the ones under test.
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';

import { type AuthorityMachine, type AuthorityTable, authorityProblems } from './authority-checks.ts';
import { createTestDatabase, type TestDatabase, type TestRole } from './test-database.ts';

const server = inject('postgres');

/** The agent machine, as a module's defineStateMachine would give it. */
const MACHINE: AuthorityMachine = {
  name: 'agent',
  states: ['ACTIVE', 'SUSPENDED', 'REVOKED'],
  initial: 'ACTIVE',
  moves: [
    { from: 'ACTIVE', to: 'SUSPENDED' },
    { from: 'SUSPENDED', to: 'ACTIVE' },
    { from: 'ACTIVE', to: 'REVOKED' },
    { from: 'SUSPENDED', to: 'REVOKED' },
  ],
};

/** The table description a module would pass to verifiedState and record. */
const AGENTS: AuthorityTable = {
  table: 't.agents',
  subject: 'agent',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'expires_at', type: 'timestamptz' },
  ],
  status: MACHINE,
};

/** An authority table with no status: a row whose authority is an expiry alone. */
const PASSES: AuthorityTable = {
  table: 't.passes',
  subject: 'pass',
  fields: [{ column: 'expires_at', type: 'timestamptz' }],
};

const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

const walls = (table: string): string[] => [
  `alter table ${table} enable row level security`,
  `alter table ${table} force row level security`,
  `create policy tenant_isolation on ${table} ${TENANT_POLICY}`,
];

const MACHINE_RULES = "'ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE', 'ACTIVE>REVOKED', 'SUSPENDED>REVOKED'";
const MACHINE_STATES = "check (status in ('ACTIVE', 'SUSPENDED', 'REVOKED'))";

const guard = (table: string, rules = MACHINE_RULES): string =>
  `create trigger status_guard before insert or update on ${table}
     for each row execute function state_rules.guard_status(${rules})`;

/** A trigger function that changes nothing, for the fixtures about firing order. */
const TRIGGER_FUNCTION = `create function t.rewrite() returns trigger language plpgsql set search_path = pg_catalog
   as $$ begin return new; end $$`;

/** t.agents, built as A3c requires: the fixtures below break one thing about it at a time. */
const SOUND: string[] = [
  'create schema t',
  'grant usage on schema t to agentx_app',
  `create table t.agents (
     org_id uuid not null,
     id uuid not null,
     status text not null,
     expires_at timestamptz,
     state_version integer not null default 1,
     state_event_id uuid,
     primary key (org_id, id),
     constraint status_is_a_state ${MACHINE_STATES})`,
  ...walls('t.agents'),
  guard('t.agents'),
  'grant select, insert on t.agents to agentx_app',
  'grant update (status, expires_at, state_version, state_event_id) on t.agents to agentx_app',
];

/** t.passes: an authority table with no status, so no machine and no guard. It needs schema t. */
const WITHOUT_STATUS: string[] = [
  `create table t.passes (
     org_id uuid not null,
     id uuid not null,
     expires_at timestamptz,
     state_version integer not null default 1,
     state_event_id uuid,
     primary key (org_id, id))`,
  ...walls('t.passes'),
  'grant select, insert on t.passes to agentx_app',
  'grant update (expires_at, state_version, state_event_id) on t.passes to agentx_app',
];

/** A fixture statement: run as the migration role, or as the role named first. */
type Statement = string | readonly [TestRole, string];

/** Every database a test built, so each one is dropped even when a test builds several. */
let built: TestDatabase[] = [];

afterEach(async () => {
  const open = built;
  built = [];
  // Every one is dropped even if one of them fails (a DROP DATABASE that loses
  // a race with a connection), and the failures are reported together.
  const dropped = await Promise.allSettled(open.map((database) => database.drop()));
  const failed = dropped.flatMap((result) => (result.status === 'rejected' ? [String(result.reason)] : []));
  if (failed.length > 0) throw new Error(`A fixture database was not dropped: ${failed.join('; ')}`);
});

/** A fresh copy of the migrated database with the fixture applied, one statement at a time. */
async function fixture(statements: readonly Statement[]): Promise<TestDatabase> {
  const database = await createTestDatabase(server, { schema: 'migrated' });
  built.push(database);
  for (const statement of statements) {
    const [role, text] = typeof statement === 'string' ? (['owner', statement] as const) : statement;
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text in this file.
    await database.as(role).query(text);
  }
  return database;
}

const problemsAfter = async (
  statements: readonly Statement[],
  tables: readonly AuthorityTable[] = [AGENTS],
): Promise<string[]> => authorityProblems(await fixture(statements), tables);

describe(`A3c what passes (Postgres ${server.version})`, () => {
  it('passes an empty registry on the migrated schema, which has no authority table yet', async () => {
    expect(await problemsAfter([], [])).toEqual([]);
  });

  it('passes a table built for its signed state and its machine', async () => {
    expect(await problemsAfter(SOUND)).toEqual([]);
  });

  it('passes a table with no status, and an integer field kept as a bigint', async () => {
    const statements = [...SOUND, ...WITHOUT_STATUS, 'alter table t.passes add column uses bigint'];
    const counted: AuthorityTable = { ...PASSES, fields: [...PASSES.fields, { column: 'uses', type: 'integer' }] };
    expect(await problemsAfter(statements, [AGENTS, counted])).toEqual([]);
  });

  it('passes another BEFORE ROW trigger that Postgres fires before the guard', async () => {
    const statements = [
      ...SOUND,
      TRIGGER_FUNCTION,
      'create trigger note_first before insert or update on t.agents for each row execute function t.rewrite()',
    ];
    expect(await problemsAfter(statements)).toEqual([]);
  });

  it('passes a table whose name Postgres quotes, guard and all', async () => {
    // `user` is a reserved word, so every catalogue name for it is printed
    // quoted; the registry writes it plainly and the two must still meet.
    const statements = [
      'create schema t',
      `create table t."user" (
         org_id uuid not null, id uuid not null, status text not null, expires_at timestamptz,
         state_version integer not null default 1, state_event_id uuid,
         primary key (org_id, id), constraint status_is_a_state ${MACHINE_STATES})`,
      ...walls('t."user"'),
      guard('t."user"'),
    ];
    const users: AuthorityTable = { ...AGENTS, table: 't.user', subject: 'user' };
    expect(await problemsAfter(statements, [users])).toEqual([]);
  });

  it('passes a time field declared with a precision, which the reader reads the same way', async () => {
    expect(await problemsAfter([...SOUND, 'alter table t.agents alter column expires_at type timestamptz(3)'])).toEqual(
      [],
    );
  });

  it('passes another BEFORE ROW trigger that only fires on DELETE, which has no new row', async () => {
    const statements = [
      ...SOUND,
      TRIGGER_FUNCTION,
      'create trigger zz_on_delete before delete on t.agents for each row execute function t.rewrite()',
    ];
    expect(await problemsAfter(statements)).toEqual([]);
  });

  it('passes two tables whose machines share a name, each against its own states', async () => {
    // The reference objects are kept by table, so t.passes is never judged by
    // t.agents' rules (or the other way round) just because both machines are
    // called `agent`.
    const shorter: AuthorityMachine = {
      name: 'agent',
      states: ['ACTIVE', 'REVOKED'],
      initial: 'ACTIVE',
      moves: [{ from: 'ACTIVE', to: 'REVOKED' }],
    };
    const statements = [
      ...SOUND,
      `create table t.passes (
         org_id uuid not null, id uuid not null, status text not null, expires_at timestamptz,
         state_version integer not null default 1, state_event_id uuid,
         primary key (org_id, id),
         constraint status_is_a_state check (status in ('ACTIVE', 'REVOKED')))`,
      ...walls('t.passes'),
      guard('t.passes', "'ACTIVE', 'ACTIVE>REVOKED'"),
    ];
    const passes: AuthorityTable = {
      table: 't.passes',
      subject: 'pass',
      fields: [
        { column: 'status', type: 'text' },
        { column: 'expires_at', type: 'timestamptz' },
      ],
      status: shorter,
    };
    expect(await problemsAfter(statements, [AGENTS, passes])).toEqual([]);
  });

  it('passes a guard that is always enabled, and a key that leaves the signed-state columns alone', async () => {
    const statements = [
      ...SOUND,
      'alter table t.agents enable always trigger status_guard',
      'create unique index agents_one_expiry_per_row on t.agents (org_id, id, expires_at)',
    ];
    expect(await problemsAfter(statements)).toEqual([]);
  });
});

describe('A3c the registry itself', () => {
  // These rules are judged before the database is read at all
  // (authorityProblems returns the registry's problems without connecting), so
  // one copy of the migrated database serves the whole block.
  let shared: TestDatabase | undefined;

  beforeAll(async () => {
    shared = await createTestDatabase(server, { schema: 'migrated' });
  });

  afterAll(async () => {
    // Guarded, so a database that was never made doesn't hide why with a
    // TypeError of its own.
    if (shared !== undefined) await shared.drop();
  });

  const listProblems = (tables: readonly AuthorityTable[]): Promise<string[]> => {
    if (shared === undefined) throw new Error('The shared fixture database was not made');
    return authorityProblems(shared, tables);
  };

  it('fails a table not named schema.table in lower-case words', async () => {
    expect(await listProblems([{ ...AGENTS, table: 'T.Agents' }])).toEqual([
      'T.Agents: an authority table is named schema.table, in lower-case words',
    ]);
  });

  it('fails the same table listed twice', async () => {
    expect(await listProblems([AGENTS, AGENTS])).toEqual(['t.agents: is on the authority-table registry twice']);
  });

  it('fails two tables recorded as the same subject type', async () => {
    expect(await listProblems([AGENTS, { ...PASSES, subject: 'agent' }])).toEqual([
      "t.passes: records its rows as agent, which t.agents also does; each authority table has its own subject type, or one object's latest signed event could be found for another",
    ]);
  });

  it('fails a subject type that is not lower-case words', async () => {
    expect(await listProblems([{ ...AGENTS, subject: 'Agent Key' }])).toEqual([
      't.agents: the subject type Agent Key must be lower-case words joined by _',
    ]);
  });

  it('fails a table that seals nothing, and a field declared twice', async () => {
    const twice: AuthorityTable = {
      ...AGENTS,
      fields: [...AGENTS.fields, { column: 'expires_at', type: 'timestamptz' }],
    };
    expect(await listProblems([{ ...PASSES, fields: [] }])).toEqual([
      't.passes: an authority table seals at least one field',
    ]);
    expect(await listProblems([twice])).toEqual(['t.agents: the authority field expires_at is declared twice']);
  });

  it('fails a signed-state column or a key column declared as an authority field', async () => {
    expect(await listProblems([{ ...PASSES, fields: [{ column: 'state_event_id', type: 'uuid' }] }])).toEqual([
      't.passes: state_event_id is a signed-state column, not an authority field: sealing it would need the seal it points at',
    ]);
    expect(await listProblems([{ ...PASSES, fields: [{ column: 'org_id', type: 'uuid' }] }])).toEqual([
      "t.passes: org_id names the row, so it is not an authority field: the seal already covers the organisation and the row's ID, and writing it would change the row's key",
    ]);
  });

  it('fails a status that no machine rules, and a machine whose status is not sealed', async () => {
    const unsealed: AuthorityTable = { ...AGENTS, fields: [{ column: 'expires_at', type: 'timestamptz' }] };
    const noMachine: AuthorityTable = { table: AGENTS.table, subject: AGENTS.subject, fields: AGENTS.fields };
    expect(await listProblems([noMachine])).toEqual([
      't.agents: seals a status but names no state machine, so nothing would say which moves the database may allow',
    ]);
    expect(await listProblems([unsealed])).toEqual([
      't.agents: the agent machine rules its status, so status must be one of its authority fields: an unsealed status could be flipped unseen (ADR-012 §2)',
    ]);
  });

  it('fails a machine that starts outside its states, or allows a move to one it has not', async () => {
    expect(await listProblems([{ ...AGENTS, status: { ...MACHINE, initial: 'NEW' } }])).toEqual([
      't.agents: the agent machine starts in NEW, which is not one of its states',
    ]);
    const unknown: AuthorityMachine = { ...MACHINE, moves: [{ from: 'ACTIVE', to: 'LAPSED' }] };
    expect(await listProblems([{ ...AGENTS, status: unknown }])).toEqual([
      "t.agents: the agent machine allows ACTIVE>LAPSED, which names a state it doesn't have",
    ]);
  });

  it('fails a state not written in capitals, which defineStateMachine would never give', async () => {
    // A state no move names, so this pins the way it is written and nothing else.
    const lowered: AuthorityMachine = { ...MACHINE, states: [...MACHINE.states, 'lapsed'] };
    expect(await listProblems([{ ...AGENTS, status: lowered }])).toEqual([
      "t.agents: the agent machine's state lapsed must be words in capitals joined by _",
    ]);
  });

  it('fails a status field declared as anything but text', async () => {
    const asUuid: AuthorityTable = {
      ...AGENTS,
      fields: [
        { column: 'status', type: 'uuid' },
        { column: 'expires_at', type: 'timestamptz' },
      ],
    };
    expect(await listProblems([asUuid])).toEqual(['t.agents: the status field is read as uuid; a status is text']);
  });
});

describe('A3c each rule fails on a broken fixture', () => {
  describe('the table itself', () => {
    it('fails a table that is not there', async () => {
      expect(await problemsAfter([])).toEqual([
        't.agents: is on the authority-table registry, but no such table exists',
      ]);
    });

    it('fails a partitioned table, whose rows move by being deleted and inserted', async () => {
      const statements = [
        'create schema t',
        `create table t.agents (
           org_id uuid not null, id uuid not null, status text not null, expires_at timestamptz,
           state_version integer not null default 1, state_event_id uuid,
           primary key (org_id, id), constraint status_is_a_state ${MACHINE_STATES})
         partition by list (org_id)`,
        "create table t.agents_one partition of t.agents for values in ('00000000-0000-0000-0000-000000000000')",
        ...walls('t.agents'),
        guard('t.agents'),
        'grant select, insert on t.agents to agentx_app',
        'grant update (status, expires_at, state_version, state_event_id) on t.agents to agentx_app',
      ];
      // Exactly one problem: a partition is not an inheritance child for these
      // purposes (its row triggers are cloned from the parent and the parent's
      // row security reaches its rows), so that rule must stay quiet here.
      expect(await problemsAfter(statements)).toEqual([
        't.agents: is partitioned; a row moved between partitions is deleted and inserted, which would start it again at the first status and leave its signed state behind',
      ]);
    });

    it('fails a view in place of a table', async () => {
      const statements = [
        'create schema t',
        'create table t.rows (org_id uuid not null, id uuid not null, expires_at timestamptz)',
        ...walls('t.rows'),
        `create view t.passes as
           select org_id, id, expires_at, 1 as state_version, null::uuid as state_event_id from t.rows`,
      ];
      expect(await problemsAfter(statements, [PASSES])).toContain(
        't.passes: is a view, not a table, so nothing here holds',
      );
    });

    it('passes a table whose inheritance child has been dropped', async () => {
      // pg_class.relhassubclass stays true once a table has ever had a child,
      // and no statement clears it, so the rule reads pg_inherits instead.
      const statements = [...SOUND, 'create table t.agents_old () inherits (t.agents)', 'drop table t.agents_old'];
      expect(await problemsAfter(statements)).toEqual([]);
    });

    it('fails a table with inheritance children, and one that inherits', async () => {
      // A child gets the parent's columns and checks but not its triggers or
      // its row security, and its rows answer a read of the parent.
      const parent = [...SOUND, 'create table t.agents_old () inherits (t.agents)'];
      expect(await problemsAfter(parent)).toContain(
        "t.agents: has table inheritance children; a child gets this table's columns and checks but not its triggers or row security, and its rows answer a read of this table (ADR-005 §2, ADR-012 §2)",
      );
      const child = [
        'create schema t',
        `create table t.rows (org_id uuid not null, id uuid not null, expires_at timestamptz,
           state_version integer not null default 1, state_event_id uuid)`,
        ...walls('t.rows'),
        'create table t.passes (primary key (org_id, id)) inherits (t.rows)',
        ...walls('t.passes'),
      ];
      expect(await problemsAfter(child, [PASSES])).toContain(
        't.passes: inherits from another table, so a read of that table answers with these rows, which its own walls never judged',
      );
    });

    it('fails a table whose row-level security is off, or enabled but not forced', async () => {
      expect(await problemsAfter([...SOUND, 'alter table t.agents disable row level security'])).toEqual([
        't.agents: row-level security is off (ADR-005 §2)',
      ]);
      expect(await problemsAfter([...SOUND, 'alter table t.agents no force row level security'])).toEqual([
        "t.agents: row-level security is enabled but not forced, so the table's owner bypasses it (ADR-005 §2)",
      ]);
    });
  });

  describe('the columns the signed state needs', () => {
    it('fails a row that is not named by its organisation and its own ID', async () => {
      // A table with no org_id can't carry the tenant policy either, so this
      // fixture leaves the walls off and the check names both.
      const without = [
        'create schema t',
        `create table t.passes (id uuid not null primary key, expires_at timestamptz,
           state_version integer not null default 1, state_event_id uuid)`,
      ];
      const asText = [
        'create schema t',
        `create table t.passes (org_id uuid not null, id text not null, expires_at timestamptz,
           state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))`,
        ...walls('t.passes'),
      ];
      // A unique key doesn't make a column NOT NULL in Postgres, so a row
      // could be keyed and still have no ID of its own.
      const nullable = [
        'create schema t',
        `create table t.passes (org_id uuid not null, id uuid, expires_at timestamptz,
           state_version integer not null default 1, state_event_id uuid)`,
        ...walls('t.passes'),
        'create unique index passes_by_id on t.passes (org_id, id)',
      ];
      expect(await problemsAfter(without, [PASSES])).toContain(
        't.passes: has no org_id column; an authority row is named by its organisation and its own ID',
      );
      expect(await problemsAfter(asText, [PASSES])).toContain('t.passes: id must be uuid NOT NULL');
      expect(await problemsAfter(nullable, [PASSES])).toEqual(['t.passes: id must be uuid NOT NULL']);
    });

    it('fails a state_version that is missing, without its default, or takes a null', async () => {
      expect(await problemsAfter([...SOUND, 'alter table t.agents drop column state_version'])).toEqual([
        't.agents: has no state_version column, which holds the version its latest signed event made',
      ]);
      expect(await problemsAfter([...SOUND, 'alter table t.agents alter column state_version drop default'])).toEqual([
        't.agents: state_version must be integer NOT NULL DEFAULT 1, not integer DEFAULT nothing',
      ]);
      expect(await problemsAfter([...SOUND, 'alter table t.agents alter column state_version drop not null'])).toEqual([
        't.agents: state_version must be integer NOT NULL DEFAULT 1, not integer NULL DEFAULT 1',
      ]);
      const [wider] = await problemsAfter([...SOUND, 'alter table t.agents alter column state_version type bigint']);
      expect(wider).toContain('t.agents: state_version must be integer NOT NULL DEFAULT 1, not bigint');
    });

    it('fails a state_event_id that is missing, of another type, or takes no null', async () => {
      const asText = [...SOUND, 'alter table t.agents drop column state_event_id, add column state_event_id text'];
      expect(await problemsAfter([...SOUND, 'alter table t.agents drop column state_event_id'])).toEqual([
        't.agents: has no state_event_id column, which points at that event',
      ]);
      expect(await problemsAfter(asText)).toEqual(['t.agents: state_event_id must be uuid, not text']);
      expect(await problemsAfter([...SOUND, 'alter table t.agents alter column state_event_id set not null'])).toEqual([
        't.agents: state_event_id must take a null: a row is written before the event it will point at is recorded',
      ]);
    });

    it('fails an authority field with no column, or a column of a type it is not read as', async () => {
      const asText: AuthorityTable = {
        ...AGENTS,
        fields: [
          { column: 'status', type: 'text' },
          { column: 'expires_at', type: 'text' },
        ],
      };
      expect(await problemsAfter([...SOUND, 'alter table t.agents drop column expires_at'])).toEqual([
        't.agents: has no expires_at column, which it declares as an authority field',
      ]);
      const asNumber: AuthorityTable = {
        ...AGENTS,
        fields: [
          { column: 'status', type: 'text' },
          { column: 'expires_at', type: 'integer' },
        ],
      };
      expect(await problemsAfter(SOUND, [asText])).toEqual([
        "t.agents: the authority field expires_at is timestamp with time zone, which is not read as text (text): another type's text could read the same for another value",
      ]);
      expect(await problemsAfter(SOUND, [asNumber])).toEqual([
        "t.agents: the authority field expires_at is timestamp with time zone, which is not read as integer (smallint, integer or bigint): another type's text could read the same for another value",
      ]);
    });

    it('fails a column the database computes, which no change could write', async () => {
      const statements = [
        ...SOUND,
        "alter table t.agents add column label text generated always as (status || '-x') stored",
        'grant update (label) on t.agents to agentx_app',
      ];
      const labelled: AuthorityTable = { ...AGENTS, fields: [...AGENTS.fields, { column: 'label', type: 'text' }] };
      expect(await problemsAfter(statements, [labelled])).toEqual([
        't.agents: label is a column the database gives itself (generated or an identity column), so nothing can write it and no row could be created or sealed',
      ]);
    });

    it('fails a key column the database gives itself, which no INSERT of ours can name', async () => {
      const statements = [
        'create schema t',
        `create table t.passes (
           org_id uuid not null,
           id uuid generated always as ('00000000-0000-0000-0000-000000000001'::uuid) stored,
           expires_at timestamptz, state_version integer not null default 1, state_event_id uuid)`,
        ...walls('t.passes'),
        'create unique index passes_by_id on t.passes (org_id, id)',
      ];
      expect(await problemsAfter(statements, [PASSES])).toContain(
        't.passes: id is a column the database gives itself (generated or an identity column), so nothing can write it and no row could be created or sealed',
      );
    });

    it('fails an identity column, which no INSERT or UPDATE of ours can name either', async () => {
      const statements = [...SOUND, 'alter table t.agents add column uses integer generated always as identity'];
      const counted: AuthorityTable = { ...AGENTS, fields: [...AGENTS.fields, { column: 'uses', type: 'integer' }] };
      expect(await problemsAfter(statements, [counted])).toEqual([
        't.agents: uses is a column the database gives itself (generated or an identity column), so nothing can write it and no row could be created or sealed',
      ]);
    });

    it('fails a status column the table does not seal', async () => {
      const statements = [
        ...SOUND,
        ...WITHOUT_STATUS,
        "alter table t.passes add column status text not null default 'ACTIVE'",
      ];
      expect(await problemsAfter(statements, [AGENTS, PASSES])).toEqual([
        "t.passes: has a status column that it doesn't seal; a status that no signed event covers could be flipped unseen (ADR-012 §2)",
      ]);
    });
  });

  describe('the keys', () => {
    it('fails a key that covers a signed-state column', async () => {
      const pointer = [...SOUND, 'create unique index agents_by_event on t.agents (org_id, state_event_id)'];
      const version = [...SOUND, 'create unique index agents_by_version on t.agents (org_id, state_version)'];
      const covers = (key: string, columns: string): string =>
        `t.agents: the unique key ${key} covers ${columns}; moving the pointer would then be a key update, which the row's FOR NO KEY UPDATE lock can't hold (ADR-006 §6)`;
      expect(await problemsAfter(pointer)).toEqual([covers('agents_by_event', 'state_event_id')]);
      expect(await problemsAfter(version)).toEqual([covers('agents_by_version', 'state_version')]);
    });

    it('fails an exclusion constraint over a signed-state column, and says which kind of key it is', async () => {
      const statements = [
        ...SOUND,
        'create extension if not exists btree_gist',
        'alter table t.agents add constraint agents_one_event exclude using gist (state_event_id with =)',
      ];
      expect(await problemsAfter(statements)).toEqual([
        "t.agents: the exclusion constraint agents_one_event covers state_event_id; moving the pointer would then be a key update, which the row's FOR NO KEY UPDATE lock can't hold (ADR-006 §6)",
      ]);
    });

    it('fails a key built on expressions, which this check cannot read', async () => {
      const statements = [...SOUND, 'create unique index agents_lowered on t.agents (org_id, lower(status))'];
      expect(await problemsAfter(statements)).toEqual([
        "t.agents: the unique key agents_lowered is built on expressions; an authority table's keys are over plain columns, so this check can see what they cover",
      ]);
    });

    it('fails a key that is in the catalogue but enforces nothing', async () => {
      // What a failed CREATE UNIQUE INDEX CONCURRENTLY leaves behind: the row
      // is there, and two rows could still share the key.
      const statements: Statement[] = [
        ...SOUND,
        ['admin', "update pg_catalog.pg_index set indisvalid = false where indexrelid = 't.agents_pkey'::regclass"],
      ];
      expect(await problemsAfter(statements)).toEqual([
        't.agents: has no unique key on (org_id, id); without one, two rows could share a key and every read of the row would be unreadable',
      ]);
    });

    it('fails a table with no key on the row, and one whose only key is partial', async () => {
      const statements = [
        'create schema t',
        `create table t.passes (org_id uuid not null, id uuid not null, expires_at timestamptz,
           state_version integer not null default 1, state_event_id uuid)`,
        ...walls('t.passes'),
      ];
      const partial = [
        ...statements,
        'create unique index passes_live on t.passes (org_id, id) where expires_at is not null',
      ];
      const wider = [...statements, 'create unique index passes_wide on t.passes (org_id, id, expires_at)'];
      const elsewhere = [...statements, 'create unique index passes_by_expiry on t.passes (id, expires_at)'];
      const missing =
        't.passes: has no unique key on (org_id, id); without one, two rows could share a key and every read of the row would be unreadable';
      expect(await problemsAfter(statements, [PASSES])).toEqual([missing]);
      expect(await problemsAfter(partial, [PASSES])).toEqual([missing]);
      expect(await problemsAfter(wider, [PASSES])).toEqual([missing]);
      expect(await problemsAfter(elsewhere, [PASSES])).toEqual([missing]);
    });
  });

  describe('what the app role may do', () => {
    it('fails an app role that may delete or empty the table', async () => {
      const refused = (right: string): string =>
        `t.agents: the app role has ${right}, which is not one of the rights the app has on an authority table (SELECT, INSERT, and UPDATE of the sealed columns)`;
      expect(await problemsAfter([...SOUND, 'grant delete on t.agents to agentx_app'])).toEqual([refused('DELETE')]);
      expect(await problemsAfter([...SOUND, 'grant truncate on t.agents to agentx_app'])).toEqual([
        refused('TRUNCATE'),
      ]);
    });

    it('fails an app role that may write triggers of its own on the table', async () => {
      // TRIGGER alone would let the app create the very trigger the guard
      // check exists to forbid: one that fires after status_guard has passed a
      // row. The app's rights are an allow-list for that reason.
      expect(await problemsAfter([...SOUND, 'grant trigger on t.agents to agentx_app'])).toEqual([
        't.agents: the app role has TRIGGER, which is not one of the rights the app has on an authority table (SELECT, INSERT, and UPDATE of the sealed columns)',
      ]);
    });

    it("fails an UPDATE on the whole table, which covers the row's identity", async () => {
      expect(await problemsAfter([...SOUND, 'grant update on t.agents to agentx_app'])).toEqual([
        't.agents: the app role has UPDATE on the whole table, which covers org_id and id; grant UPDATE column by column (status, expires_at, state_version, state_event_id)',
      ]);
    });

    it('fails an UPDATE on a column no signed state covers', async () => {
      expect(await problemsAfter([...SOUND, 'grant update (id) on t.agents to agentx_app'])).toEqual([
        't.agents: the app role has UPDATE on id, which is not an authority field or a signed-state column',
      ]);
    });

    it('fails any right given to PUBLIC, even one the app role may hold', async () => {
      const given = (right: string): string =>
        `t.agents: PUBLIC has ${right}; an authority table grants nothing to PUBLIC, which is every role on the server (ADR-005 §3)`;
      expect(await problemsAfter([...SOUND, 'grant delete on t.agents to public'])).toEqual([given('DELETE')]);
      // SELECT is one of the two the app may hold, and still not PUBLIC's: the
      // backup role may only read what ADR-005 §3 lets it.
      expect(await problemsAfter([...SOUND, 'grant select on t.agents to public'])).toEqual([given('SELECT')]);
    });
  });

  describe('the status, its states and its guard', () => {
    it('fails a status column that is not text NOT NULL', async () => {
      expect(await problemsAfter([...SOUND, 'alter table t.agents alter column status drop not null'])).toEqual([
        't.agents: status must be text NOT NULL, not text NULL',
      ]);
    });

    it("fails states that are not the machine's, and its states in another order", async () => {
      const others = SOUND.map((statement) =>
        statement.replace(MACHINE_STATES, () => "check (status in ('ACTIVE', 'LAPSED'))"),
      );
      const reordered = [
        ...SOUND,
        'alter table t.agents drop constraint status_is_a_state',
        "alter table t.agents add constraint status_is_a_state check (status in ('REVOKED', 'SUSPENDED', 'ACTIVE'))",
      ];
      const wanted = "not the agent machine's states in its own order: CHECK ((status = ANY (ARRAY[";
      const [otherStates] = await problemsAfter(others);
      expect(otherStates).toContain('t.agents: the check constraint status_is_a_state is CHECK');
      expect(otherStates).toContain(wanted);
      const [outOfOrder] = await problemsAfter(reordered);
      expect(outOfOrder).toContain(wanted);
    });

    it('fails a table with no check over its status, or with two', async () => {
      const none = [...SOUND, 'alter table t.agents drop constraint status_is_a_state'];
      const two = [...SOUND, 'alter table t.agents add constraint status_is_short check (length(status) < 20)'];
      // The message quotes the reference constraint as this server prints it,
      // so the test pins the half that can't change with a Postgres version.
      const wanted = "it has exactly one, listing the agent machine's states: CHECK ((status = ANY (ARRAY[";
      const [missing] = await problemsAfter(none);
      const [twice] = await problemsAfter(two);
      expect(missing).toContain(`t.agents: has 0 check constraints over status; ${wanted}`);
      expect(missing).toContain("'ACTIVE'");
      expect(twice).toContain(`t.agents: has 2 check constraints over status; ${wanted}`);
    });

    it('fails a missing guard, and one that carries other rules than the machine', async () => {
      const none = SOUND.filter((statement) => !statement.includes('status_guard'));
      const fewer = [
        ...SOUND,
        'drop trigger status_guard on t.agents',
        guard('t.agents', "'ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE', 'ACTIVE>REVOKED'"),
      ];
      const [missing] = await problemsAfter(none);
      expect(missing).toContain(
        't.agents: has no status_guard trigger (db/migrations/0004): CREATE TRIGGER status_guard',
      );
      expect(missing).toContain(`state_rules.guard_status(${MACHINE_RULES})`);
      const [other] = await problemsAfter(fewer);
      expect(other).toContain('t.agents: the status_guard trigger is CREATE TRIGGER status_guard');
      expect(other).toContain("not the agent machine's rules");
    });

    it('fails a guard that does not fire on writes here', async () => {
      expect(await problemsAfter([...SOUND, 'alter table t.agents disable trigger status_guard'])).toEqual([
        "t.agents: the status_guard trigger doesn't fire on writes here (tgenabled D); it must be enabled",
      ]);
    });

    it('fails a competing BEFORE ROW trigger even when it is switched off', async () => {
      // Switching it back on is one statement that changes no definition and
      // adds nothing for a reviewer to notice.
      const statements = [
        ...SOUND,
        TRIGGER_FUNCTION,
        'create trigger zz_switched_off before insert or update on t.agents for each row execute function t.rewrite()',
        'alter table t.agents disable trigger zz_switched_off',
      ];
      expect(await problemsAfter(statements)).toEqual([
        't.agents: the BEFORE ROW trigger zz_switched_off sorts after status_guard, so Postgres fires it last and it could rewrite a status the guard has passed',
      ]);
    });

    it('fails another BEFORE ROW trigger that Postgres fires after the guard', async () => {
      const statements = [
        ...SOUND,
        TRIGGER_FUNCTION,
        'create trigger zz_rewrite before insert or update on t.agents for each row execute function t.rewrite()',
      ];
      expect(await problemsAfter(statements)).toEqual([
        't.agents: the BEFORE ROW trigger zz_rewrite sorts after status_guard, so Postgres fires it last and it could rewrite a status the guard has passed',
      ]);
    });

    it('fails a BEFORE ROW trigger whose name does not say when it fires', async () => {
      const statements = [
        ...SOUND,
        TRIGGER_FUNCTION,
        'create trigger "Rewrite" before insert or update on t.agents for each row execute function t.rewrite()',
      ];
      expect(await problemsAfter(statements)).toEqual([
        "t.agents: the BEFORE ROW trigger Rewrite isn't named in lower-case words, so which of it and status_guard Postgres fires last can't be read off its name",
      ]);
    });

    it('fails a guard on a table the registry gives no machine', async () => {
      const statements = [...SOUND, ...WITHOUT_STATUS, guard('t.passes')];
      expect(await problemsAfter(statements, [AGENTS, PASSES])).toEqual([
        't.passes: has a status_guard trigger but names no state machine, so nothing says which moves it should allow',
      ]);
    });
  });
});
