// A3e-1b: the live schema guard, against a real migrated database and then
// against each way an owner-level attacker can rewrite it.
//
// Every tamper below is run **as `agentx_owner`**, the role the threat is
// actually about: no superuser, but the owner of the database and every table
// in it. Each one was proven to work on a real server (S32) before the guard
// was written, so these are not hypotheticals — they are the attack, and the
// test is that the guard sees it.
//
// The shape of each case is the same: the migrated database is clean, the
// tamper is applied, the guard names it, the tamper is undone, and the database
// is clean again. Undoing matters — a case that left its damage behind would
// make every later case pass for the wrong reason.
import { readFileSync } from 'node:fs';

import { createTenantProbe, createTestDatabase, type TestDatabase, type TestSession } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { liveSchemaProblems } from './schema-guard.ts';
import { SCHEMA_POLICY } from './schema-policy.ts';
import type { SignedStateTable } from './signed-rows.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;
let owner: TestSession;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

/**
 * 0004's own definition of the status guard, read from the migration rather
 * than copied, so a test that rewrites the function puts back exactly what the
 * migration wrote — a copy here would drift and every later case would fail.
 */
const RESTORE_GUARD =
  /CREATE OR REPLACE FUNCTION state_rules\.guard_status\(\)[\s\S]*?\$\$;/.exec(
    readFileSync(new URL('../../../../db/migrations/0004_state_rules.sql', import.meta.url), 'utf8').replace(
      'CREATE FUNCTION state_rules.guard_status()',
      'CREATE OR REPLACE FUNCTION state_rules.guard_status()',
    ),
  )?.[0] ?? '';

/** The hash schema-guard.ts compares the status guard's body with. */
const GUARD_BODY_HASH = '52692e2d94ac490ceb626cc10024e4bb75fff4484ebd80fdf518cd34405cf246';

const problems = async (): Promise<string[]> => liveSchemaProblems(app, ROLES);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  owner = database.as('owner');
  app = createDatabase(
    { ...database.connection('app'), tls: 'disable' },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'error', eventCapPerMinute: 1000 } },
      destination: { write: () => undefined },
    }),
  );
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** Every case starts from a database the guard is happy with, so a leftover can't hide a miss. */
beforeEach(async () => {
  expect(await problems()).toEqual([]);
});

describe('a migrated database', () => {
  it('has nothing to report', async () => {
    expect(await problems()).toEqual([]);
  });

  it('reads the tenant policy the same way the product writes it', async () => {
    // The guard compares each policy with a constant, because the app role may
    // not build a reference object the way A3c-1 does. This is the test that
    // proves the constant is what this Postgres version really prints: if a
    // future major words it differently, it fails here rather than in
    // production.
    const rows = await owner.query<{ expression: string }>(
      `select pg_catalog.pg_get_expr(p.polqual, p.polrelid) as expression
       from pg_catalog.pg_policy p
       join pg_catalog.pg_class c on c.oid = p.polrelid
       join pg_catalog.pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'audit' and c.relname = 'events'`,
    );
    expect(rows[0]?.expression).toBe("(org_id = (NULLIF(current_setting('app.org_id'::text, true), ''::text))::uuid)");
  });
});

describe('the status guard function', () => {
  it('is the body the migration wrote, pinned, and running with its caller’s rights', async () => {
    // The guard compares the body by hash; this is where that constant is
    // proven against a freshly migrated database, so a change to 0004 fails
    // here rather than on staging.
    const rows = await owner.query<{ body: string; config: string; definer: boolean }>(
      `select pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc, 'UTF8')), 'hex') as body,
              pg_catalog.array_to_string(p.proconfig, ',') as config,
              p.prosecdef as definer
       from pg_catalog.pg_proc p
       join pg_catalog.pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'state_rules' and p.proname = 'guard_status'`,
    );
    expect(rows[0]?.config).toBe('search_path=pg_catalog');
    expect(rows[0]?.definer).toBe(false);
    expect(rows[0]?.body).toBe(GUARD_BODY_HASH);
  });
});

describe('what the database owner can really do', () => {
  it('sees the tenant wall rewritten to let everything through', async () => {
    await owner.query('alter policy tenant_isolation on audit.events using (true)');
    try {
      expect(await problems()).toEqual(
        expect.arrayContaining([
          "audit.events's policy reads differently",
          'the tenant policies no longer all read the same way',
        ]),
      );
    } finally {
      await owner.query(
        `alter policy tenant_isolation on audit.events
         using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)`,
      );
    }
  });

  it('sees row security switched off, and FORCE dropped on its own', async () => {
    await owner.query('alter table audit.events disable row level security');
    expect(await problems()).toContain('audit.events does not have row-level security enabled');
    await owner.query('alter table audit.events enable row level security');

    await owner.query('alter table audit.events no force row level security');
    expect(await problems()).toContain('audit.events does not have row-level security forced');
    await owner.query('alter table audit.events force row level security');
  });

  it('sees a planted trigger', async () => {
    await owner.query(
      `create function audit.sneak() returns trigger language plpgsql
       set search_path = pg_catalog as 'begin return new; end'`,
    );
    await owner.query('create trigger sneak before insert on audit.events for each row execute function audit.sneak()');
    try {
      expect(await problems()).toContain('audit.events carries the trigger "sneak"');
    } finally {
      await owner.query('drop trigger sneak on audit.events');
      await owner.query('drop function audit.sneak()');
    }
  });

  it('sees a trigger given the status guard’s name but calling something else', async () => {
    // The name alone is not enough: 0004's guard is allowed, an impostor wearing
    // its name is not.
    await owner.query(
      `create function audit.impostor() returns trigger language plpgsql
       set search_path = pg_catalog as 'begin return new; end'`,
    );
    await owner.query(
      'create trigger status_guard before insert on audit.events for each row execute function audit.impostor()',
    );
    try {
      expect(await problems()).toContain('audit.events carries the trigger "status_guard"');
    } finally {
      await owner.query('drop trigger status_guard on audit.events');
      await owner.query('drop function audit.impostor()');
    }
  });

  it('sees a planted rewrite rule', async () => {
    await owner.query('create rule hide as on delete to audit.events do instead nothing');
    try {
      expect(await problems()).toContain('audit.events carries the rewrite rule "hide"');
    } finally {
      await owner.query('drop rule hide on audit.events');
    }
  });

  it('sees a widened grant', async () => {
    await owner.query('grant update on audit.events to agentx_app');
    try {
      expect(await problems()).toContain('agentx_app may UPDATE on audit.events');
    } finally {
      await owner.query('revoke update on audit.events from agentx_app');
    }
  });

  it('sees the app role given more than reading and writing rows on a tenant table (A3f-1)', async () => {
    // A tenant table outside the audit schemas, where the app may SELECT,
    // INSERT, UPDATE and DELETE and nothing else; MAINTAIN exists from 17.
    const maintain = Number(server.version.split('.')[0]) >= 17;
    try {
      // Inside the try, so a probe half built is still dropped, and can't fail every later case instead.
      await createTenantProbe(database);
      expect(await problems()).toEqual([]);
      await owner.query('grant truncate, trigger, references on probe.items to agentx_app');
      if (maintain) await owner.query('grant maintain on probe.items to agentx_app');
      expect((await problems()).sort()).toEqual(
        [
          'agentx_app may TRUNCATE on probe.items',
          'agentx_app may TRIGGER on probe.items',
          'agentx_app may REFERENCES on probe.items',
          ...(maintain ? ['agentx_app may MAINTAIN on probe.items'] : []),
        ].sort(),
      );
      await owner.query('revoke truncate, trigger, references on probe.items from agentx_app');
      if (maintain) await owner.query('revoke maintain on probe.items from agentx_app');
      expect(await problems()).toEqual([]);
      // A column grant alone is seen too, though the table-level answer doesn't show it.
      await owner.query('grant references (label) on probe.items to agentx_app');
      expect(await problems()).toEqual(['agentx_app may REFERENCES on probe.items']);
    } finally {
      await owner.query('drop schema if exists probe cascade');
    }
  });

  it('sees a right handed to PUBLIC, even one the app already holds', async () => {
    // The app-role check would pass this: SELECT is allowed for the app. But
    // PUBLIC means every role there is and every role made later.
    await owner.query('grant select on audit.events to public');
    try {
      expect(await problems()).toContain('PUBLIC may SELECT on audit.events');
    } finally {
      await owner.query('revoke select on audit.events from public');
    }
  });

  it('sees the table swapped for a view over a renamed copy', async () => {
    await owner.query('alter table audit.events rename to events_real');
    await owner.query('create view audit.events as select * from audit.events_real');
    try {
      const found = await problems();
      expect(found).toContain('audit.events is no longer a plain table');
    } finally {
      await owner.query('drop view audit.events');
      await owner.query('alter table audit.events_real rename to events');
    }
  });

  it('sees a unique key that leaves org_id out', async () => {
    await owner.query('create unique index sneaky_key on audit.events (id)');
    try {
      expect(await problems()).toContain(`audit.events's unique index "sneaky_key" does not cover org_id`);
    } finally {
      await owner.query('drop index audit.sneaky_key');
    }
  });

  it('sees a setting pinned to the database', async () => {
    await owner.query(
      `do $$ begin execute pg_catalog.format('alter database %I set statement_timeout = 1234', pg_catalog.current_database()); end $$`,
    );
    try {
      expect(await problems()).toContain('a setting is pinned to this database or to a role');
    } finally {
      await owner.query(
        `do $$ begin execute pg_catalog.format('alter database %I reset statement_timeout', pg_catalog.current_database()); end $$`,
      );
    }
  });

  it('sees a new table that carries no tenant wall at all', async () => {
    // A table the policy has never heard of: not a listed global table, so it
    // must carry org_id and the walls, and it carries none of them.
    await owner.query('create table audit.smuggled (id uuid not null)');
    try {
      const found = await problems();
      expect(found).toContain('audit.smuggled does not have row-level security enabled');
      expect(found).toContain('audit.smuggled has no org_id');
    } finally {
      await owner.query('drop table audit.smuggled');
    }
  });
});

it('sees a policy that no longer covers every command', async () => {
  // A policy FOR SELECT leaves insert, update and delete with no policy at
  // all, and forced row security then refuses them — or, worse, another
  // policy could be added to allow them.
  await owner.query('drop policy tenant_isolation on audit.events');
  await owner.query(
    `create policy tenant_isolation on audit.events for select
       using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)`,
  );
  try {
    expect(await problems()).toContain("audit.events's policy no longer covers every command");
  } finally {
    await owner.query('drop policy tenant_isolation on audit.events');
    await owner.query(
      `create policy tenant_isolation on audit.events
         using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)`,
    );
  }
});

it('sees a policy narrowed to named roles, which leaves every other role unwalled', async () => {
  await owner.query('drop policy tenant_isolation on audit.events');
  await owner.query(
    `create policy tenant_isolation on audit.events to agentx_app
       using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)`,
  );
  try {
    expect(await problems()).toContain("audit.events's policy is limited to named roles");
  } finally {
    await owner.query('drop policy tenant_isolation on audit.events');
    await owner.query(
      `create policy tenant_isolation on audit.events
         using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)`,
    );
  }
});

it('sees a policy that reads right but writes anything', async () => {
  await owner.query('alter policy tenant_isolation on audit.events with check (true)');
  try {
    expect(await problems()).toContain("audit.events's policy writes differently");
  } finally {
    await owner.query('drop policy tenant_isolation on audit.events');
    await owner.query(
      `create policy tenant_isolation on audit.events
         using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)`,
    );
  }
});

it('sees a second policy beside the tenant one', async () => {
  await owner.query('create policy extra on audit.events using (true)');
  try {
    expect(await problems()).toContain('audit.events does not have exactly one row-security policy');
  } finally {
    await owner.query('drop policy extra on audit.events');
  }
});

it('sees a policy put on a global table, which has no tenant to check', async () => {
  await owner.query('create policy sneak on platform_controls.audit_head using (true)');
  try {
    expect(await problems()).toContain('platform_controls.audit_head is a global table but carries a policy');
  } finally {
    await owner.query('drop policy sneak on platform_controls.audit_head');
  }
});

it('sees a column added to a global table, whose columns are listed exactly', async () => {
  await owner.query('alter table platform_controls.audit_head add column extra integer');
  try {
    expect(await problems()).toContain('platform_controls.audit_head no longer has exactly its columns');
  } finally {
    await owner.query('alter table platform_controls.audit_head drop column extra');
  }
});

it('sees a listed global table renamed out from under the policy', async () => {
  await owner.query('alter table platform_controls.audit_head rename to audit_head_gone');
  try {
    expect(await problems()).toContain('platform_controls.audit_head is listed as a global table but is not there');
  } finally {
    await owner.query('alter table platform_controls.audit_head_gone rename to audit_head');
  }
});

it('sees a table given a child, which makes it an inheritance parent', async () => {
  // A child inherits the parent's rows but not its policies: reading the
  // parent reads the child too, under whatever walls the child has.
  await owner.query('create table audit.events_child () inherits (audit.events)');
  try {
    expect(await problems()).toContain('audit.events is in an inheritance tree');
  } finally {
    await owner.query('drop table audit.events_child');
  }
});

it('sees a unique key made partial, which enforces nothing outside its condition', async () => {
  await owner.query('create unique index partial_key on audit.events (org_id, id) where seq > 0');
  try {
    expect(await problems()).toContain(`audit.events's unique index "partial_key" is partial`);
  } finally {
    await owner.query('drop index audit.partial_key');
  }
});

it('sees the status guard given arguments that are not a machine', async () => {
  // Fires at the right times, calls the right function, but its moves are not
  // moves. Whether they are the *right* moves for that table's machine is
  // A3c-1's question, which has the machine to compare them with; this is only
  // that they still look like a guard's at all.
  await owner.query(
    `create trigger status_guard before insert or update on audit.events for each row
     execute function state_rules.guard_status('new', 'not-a-move')`,
  );
  try {
    expect(await problems()).toContain("audit.events's status_guard is given other arguments");
  } finally {
    await owner.query('drop trigger status_guard on audit.events');
  }
});

it('accepts the status guard as 0004 installs it, so the rule is not simply always true', async () => {
  await owner.query(
    `create trigger status_guard before insert or update on audit.events for each row
     execute function state_rules.guard_status('new', 'new>done', 'done>archived')`,
  );
  try {
    const found = await problems();
    expect(found).not.toContain("audit.events's status_guard is given other arguments");
    expect(found).not.toContain("audit.events's status_guard fires at other times");
    expect(found).not.toContain('audit.events carries the trigger "status_guard"');
  } finally {
    await owner.query('drop trigger status_guard on audit.events');
  }
});

it('sees the status guard switched off, which Postgres keeps but stops running', async () => {
  // 0004's guard is the one trigger the schema is allowed. Postgres keeps a
  // disabled trigger's row, so a check that only looked for its name would
  // see nothing wrong.
  await owner.query(
    `create trigger status_guard before insert on audit.events for each row
       execute function state_rules.guard_status('new', 'new>done')`,
  );
  await owner.query('alter table audit.events disable trigger status_guard');
  try {
    expect(await problems()).toContain("audit.events's status_guard is switched off");
  } finally {
    await owner.query('drop trigger status_guard on audit.events');
  }
});

it('sees a unique key that only INCLUDEs org_id, which separates nothing', async () => {
  // The payload of an INCLUDE is not part of the key: this index still makes
  // id unique across every organisation. The first draft matched org_id
  // anywhere in indkey and passed it. Found by the A3e-1b review.
  await owner.query('create unique index include_key on audit.events (id) include (org_id)');
  try {
    expect(await problems()).toContain(`audit.events's unique index "include_key" does not cover org_id`);
  } finally {
    await owner.query('drop index audit.include_key');
  }
});

it('sees a grant made on a single column, which the table-level question answers no to', async () => {
  // has_table_privilege says false for a column grant, so the first draft saw
  // nothing while the app could rewrite that column. Found by the A3e-1b
  // review.
  await owner.query('grant update (details) on audit.events to agentx_app');
  try {
    expect(await problems()).toContain('agentx_app may UPDATE on audit.events');
  } finally {
    await owner.query('revoke update (details) on audit.events from agentx_app');
  }
});

it('sees a single column handed to PUBLIC, which the table access list does not carry', async () => {
  await owner.query('grant select (details) on audit.events to public');
  try {
    expect(await problems()).toContain('PUBLIC may SELECT on audit.events');
  } finally {
    await owner.query('revoke select (details) on audit.events from public');
  }
});

it('sees the status guard function rewritten, which touches no table at all', async () => {
  // CREATE OR REPLACE is the owner's to use, and nothing else in the guard
  // would notice: the trigger keeps its name, its timing and its arguments,
  // and simply stops refusing anything. Found by the A3e-1b review.
  await owner.query(
    `create or replace function state_rules.guard_status() returns trigger
       language plpgsql set search_path = pg_catalog as $$ begin return new; end $$`,
  );
  try {
    expect(await problems()).toContain('state_rules.guard_status is not the function the migration wrote');
  } finally {
    // eslint-disable-next-line agentx/no-string-built-sql -- 0004's own text, read from the migration so the restored function is exactly what it wrote.
    await owner.query(RESTORE_GUARD);
  }
});

it('sees the status guard made to run with its owner’s rights', async () => {
  await owner.query('alter function state_rules.guard_status() security definer');
  try {
    expect(await problems()).toContain("state_rules.guard_status runs with its owner's rights");
  } finally {
    await owner.query('alter function state_rules.guard_status() security invoker');
  }
});

it('sees the status guard’s search_path unpinned', async () => {
  await owner.query('alter function state_rules.guard_status() reset search_path');
  try {
    expect(await problems()).toContain('state_rules.guard_status does not pin its search_path');
  } finally {
    await owner.query('alter function state_rules.guard_status() set search_path = pg_catalog');
  }
});

it('sees a function added to one of our schemas', async () => {
  await owner.query(
    `create function audit.helper() returns integer language sql
       set search_path = pg_catalog as 'select 1'`,
  );
  try {
    expect(await problems()).toContain('audit.helper is a function our schemas should not hold');
  } finally {
    await owner.query('drop function audit.helper()');
  }
});

describe('an authority table the product lists (A3f-2)', () => {
  /** A stand-in, described as a module describes one, and built as its migration must build it. */
  const AGENTS = {
    table: 'probe.agents',
    subject: 'agent',
    fields: [
      { column: 'status', type: 'text' },
      { column: 'role', type: 'text' },
    ],
  } as const satisfies SignedStateTable;
  const TENANT_POLICY =
    "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

  const listed = (tables: readonly SignedStateTable[] = [AGENTS]) =>
    liveSchemaProblems(app, { ...ROLES, authorityTables: tables });

  beforeEach(async () => {
    await owner.query('create schema probe');
    await owner.query(
      'create table probe.agents (org_id uuid not null, id uuid not null, status text not null, role text not null, label text not null, state_version integer not null default 1, state_event_id uuid, primary key (org_id, id))',
    );
    await owner.query('alter table probe.agents enable row level security');
    await owner.query('alter table probe.agents force row level security');
    // eslint-disable-next-line agentx/no-string-built-sql -- The policy is the fixed text above.
    await owner.query(`create policy tenant_isolation on probe.agents ${TENANT_POLICY}`);
    await owner.query('grant usage on schema probe to agentx_app');
    await owner.query('grant select, insert on probe.agents to agentx_app');
    await owner.query('grant update (status, role, state_version, state_event_id) on probe.agents to agentx_app');
  });

  afterEach(async () => {
    await owner.query('drop schema if exists probe cascade');
  });

  it('passes one built as its migration must build it', async () => {
    expect(await listed()).toEqual([]);
  });

  it.each([
    [
      'DELETE, which takes a row out of reach of its log',
      'grant delete on probe.agents to agentx_app',
      ['agentx_app may DELETE on probe.agents'],
    ],
    [
      'UPDATE of the whole table, which covers its key',
      'grant update on probe.agents to agentx_app',
      // The guard lists its problems sorted.
      [
        'agentx_app may UPDATE on probe.agents',
        'agentx_app may UPDATE probe.agents\'s column "id"',
        'agentx_app may UPDATE probe.agents\'s column "label"',
        'agentx_app may UPDATE probe.agents\'s column "org_id"',
      ],
    ],
    [
      'UPDATE of a column it never seals',
      'grant update (label) on probe.agents to agentx_app',
      ['agentx_app may UPDATE probe.agents\'s column "label"'],
    ],
    [
      'UPDATE of its key',
      'grant update (id) on probe.agents to agentx_app',
      ['agentx_app may UPDATE probe.agents\'s column "id"'],
    ],
    [
      'a column right it never needs',
      'grant references (role) on probe.agents to agentx_app',
      ['agentx_app may REFERENCES on columns of probe.agents'],
    ],
    [
      'a table right it never needs, once: the same right on its columns is not named again',
      'grant references on probe.agents to agentx_app',
      ['agentx_app may REFERENCES on probe.agents'],
    ],
  ])('names %s', async (_, grant, named) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the table above.
    await owner.query(grant);

    expect(await listed()).toEqual(named);
  });

  it('passes reading and adding granted column by column, as A3c-1 allows in CI', async () => {
    await owner.query('revoke select, insert on probe.agents from agentx_app');
    await owner.query(
      'grant select (org_id, id, status, role), insert (org_id, id, status, role) on probe.agents to agentx_app',
    );

    expect(await listed()).toEqual([]);
  });

  it('finds a listed table named with a reserved word, by the plain name its module and CI use', async () => {
    // Postgres quotes `user` when it prints the name; the module writes probe.user, as A3c-1 reads it.
    await owner.query('alter table probe.agents rename to "user"');
    const USERS = { ...AGENTS, table: 'probe.user' };

    expect(await listed([USERS])).toEqual([]);
    await owner.query('grant delete on probe."user" to agentx_app');
    expect(await listed([USERS])).toEqual(['agentx_app may DELETE on probe."user"']);
  });

  it('holds only a listed table to it: the same DELETE on a table not listed is a tenant table’s right', async () => {
    await owner.query('grant delete on probe.agents to agentx_app');

    expect(await listed([])).toEqual([]);
  });

  it('names a listed table that is not there', async () => {
    expect(await listed([AGENTS, { ...AGENTS, table: 'probe.gone' }])).toEqual([
      'probe.gone is listed as an authority table but is not there',
    ]);
  });
});

describe('a fill-in table the schema policy lists (A5b)', () => {
  /** Every right on the idempotency keys, the table's and each column's, as Postgres records them. */
  const keyRights = async (): Promise<unknown> =>
    owner.query(
      `select '' as column, pg_catalog.pg_get_userbyid(acl.grantee)::text as grantee, acl.privilege_type as privilege
       from pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) acl
       where c.oid = 'idempotency.keys'::pg_catalog.regclass
       union all
       select a.attname::text, pg_catalog.pg_get_userbyid(acl.grantee)::text, acl.privilege_type
       from pg_catalog.pg_attribute a, pg_catalog.aclexplode(a.attacl) acl
       where a.attrelid = 'idempotency.keys'::pg_catalog.regclass and a.attnum > 0 and not a.attisdropped
       order by 1, 2, 3`,
    );
  let migrated: unknown;

  beforeAll(async () => {
    migrated = await keyRights();
  });

  /**
   * Puts back the rights 0006 gives the app, whatever a case changed, and
   * proves they are exactly 0006's: both checkers only allow-list, so a
   * restore that gave back less would pass unseen.
   */
  afterEach(async () => {
    await owner.query('revoke all on idempotency.keys from agentx_app');
    await owner.query('grant select, insert on idempotency.keys to agentx_app');
    await owner.query('grant update (result_status, result_id) on idempotency.keys to agentx_app');
    expect(await keyRights()).toEqual(migrated);
  });

  it.each([
    [
      'DELETE, which would let a retry do its write again',
      'grant delete on idempotency.keys to agentx_app',
      ['agentx_app may DELETE on idempotency.keys'],
    ],
    [
      "UPDATE of a key's hash",
      'grant update (request_hash) on idempotency.keys to agentx_app',
      ['agentx_app may UPDATE idempotency.keys\'s column "request_hash"'],
    ],
    [
      'a column right it never needs',
      'grant references (result_id) on idempotency.keys to agentx_app',
      ['agentx_app may REFERENCES on columns of idempotency.keys'],
    ],
  ])('names %s on the idempotency keys', async (_, grant, named) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the table above.
    await owner.query(grant);

    expect(await problems()).toEqual(named);
  });

  it('names UPDATE of the whole table, and every column it opens but the listed ones', async () => {
    await owner.query('grant update on idempotency.keys to agentx_app');

    // The guard lists its problems sorted.
    expect(await problems()).toEqual([
      'agentx_app may UPDATE idempotency.keys\'s column "client_id"',
      'agentx_app may UPDATE idempotency.keys\'s column "client_kind"',
      'agentx_app may UPDATE idempotency.keys\'s column "created_at"',
      'agentx_app may UPDATE idempotency.keys\'s column "key"',
      'agentx_app may UPDATE idempotency.keys\'s column "operation"',
      'agentx_app may UPDATE idempotency.keys\'s column "org_id"',
      'agentx_app may UPDATE idempotency.keys\'s column "request_hash"',
      'agentx_app may UPDATE idempotency.keys\'s column "request_hash_key_version"',
      'agentx_app may UPDATE on idempotency.keys',
    ]);
  });

  it('passes reading and adding granted column by column, as CI-06 allows', async () => {
    await owner.query('revoke select, insert on idempotency.keys from agentx_app');
    await owner.query(
      'grant select (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at, result_status, result_id), insert (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at) on idempotency.keys to agentx_app',
    );

    expect(await problems()).toEqual([]);
  });

  it('holds a table on both lists to the columns both allow, and names it', async () => {
    // result_id on both lists, result_status on the fill-in list alone, key on the authority list alone.
    const asAuthority = {
      table: 'idempotency.keys',
      subject: 'idempotency-key',
      fields: [
        { column: 'result_id', type: 'uuid' },
        { column: 'key', type: 'text' },
      ],
    } as const satisfies SignedStateTable;
    await owner.query('grant update (key) on idempotency.keys to agentx_app');

    expect(await liveSchemaProblems(app, { ...ROLES, authorityTables: [asAuthority] })).toEqual([
      'agentx_app may UPDATE idempotency.keys\'s column "key"',
      'agentx_app may UPDATE idempotency.keys\'s column "result_status"',
      'idempotency.keys is listed as both an authority table and a fill-in table',
    ]);
  });

  it('finds a listed table named with a reserved word, by the name Postgres quotes', async () => {
    await owner.query('create schema probe');
    try {
      await owner.query(
        'create table probe."user" (org_id uuid not null, id uuid not null, note text, primary key (org_id, id))',
      );
      await owner.query('alter table probe."user" enable row level security');
      await owner.query('alter table probe."user" force row level security');
      await owner.query(
        `create policy tenant_isolation on probe."user"
         using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
         with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)`,
      );
      await owner.query('grant usage on schema probe to agentx_app');
      await owner.query('grant select, insert on probe."user" to agentx_app');
      await owner.query('grant update (note) on probe."user" to agentx_app');
      const policy = {
        ...SCHEMA_POLICY,
        fillInTables: { ...SCHEMA_POLICY.fillInTables, 'probe."user"': { reason: 'Notes', columns: ['note'] } },
      };

      expect(await liveSchemaProblems(app, { ...ROLES, policy })).toEqual([]);
      await owner.query('grant delete on probe."user" to agentx_app');
      expect(await liveSchemaProblems(app, { ...ROLES, policy })).toEqual(['agentx_app may DELETE on probe."user"']);
    } finally {
      await owner.query('drop schema probe cascade');
    }
  });

  it('holds only a listed table to it: off the list, DELETE is a tenant table’s right', async () => {
    await owner.query('grant delete on idempotency.keys to agentx_app');

    expect(await liveSchemaProblems(app, { ...ROLES, policy: { ...SCHEMA_POLICY, fillInTables: {} } })).toEqual([]);
  });

  it('names a listed table that is not there', async () => {
    const policy = {
      ...SCHEMA_POLICY,
      fillInTables: { ...SCHEMA_POLICY.fillInTables, 'probe.gone': { reason: 'Removed', columns: ['result'] } },
    };

    expect(await liveSchemaProblems(app, { ...ROLES, policy })).toEqual([
      'probe.gone is listed as a fill-in table but is not there',
    ]);
  });
});

describe('the directory, and the key the organisations rest on (B1d-1)', () => {
  const DROP_KEY = 'alter table organizations.organizations drop constraint organizations_org_id_fkey';
  const ADD_KEY =
    'alter table organizations.organizations add constraint organizations_org_id_fkey foreign key (org_id) references directory.orgs (org_id)';
  const MISSING = "organizations.organizations's foreign key to directory.orgs is not there";

  /** Puts 0008's foreign key back as the migration made it, whatever a case did to it. */
  afterEach(async () => {
    await owner.query('alter table organizations.organizations drop constraint if exists organizations_org_id_fkey');
    await owner.query(ADD_KEY);
    await owner.query('revoke all on directory.orgs from agentx_app');
    await owner.query('grant select, insert on directory.orgs to agentx_app');
    await owner.query('revoke all on migrations.applied from agentx_app');
  });

  it.each([
    ['DELETE, which would take an organisation off every check', 'grant delete on directory.orgs to agentx_app'],
    ['UPDATE of the whole table', 'grant update on directory.orgs to agentx_app'],
    ['UPDATE of its one column', 'grant update (org_id) on directory.orgs to agentx_app'],
  ])('names %s on the directory’s list, which the app only adds to and reads', async (_, grant) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the table above.
    await owner.query(grant);

    expect(await problems()).toEqual([`agentx_app may ${grant.split(' ')[1]?.toUpperCase() ?? ''} on directory.orgs`]);
  });

  it('names any right on the migration ledger, which the app never touches', async () => {
    await owner.query('grant select on migrations.applied to agentx_app');

    expect(await problems()).toEqual(['agentx_app may SELECT on migrations.applied']);
  });

  it('names the key dropped', async () => {
    await owner.query(DROP_KEY);

    expect(await problems()).toEqual([MISSING]);
  });

  it('names the key re-added NOT VALID, which leaves the rows already there unchecked', async () => {
    await owner.query(DROP_KEY);
    await owner.query(
      'alter table organizations.organizations add constraint organizations_org_id_fkey foreign key (org_id) references directory.orgs (org_id) not valid',
    );

    expect(await problems()).toEqual(["organizations.organizations's foreign key to directory.orgs is not validated"]);
  });

  it.runIf(Number(server.version.split('.')[0]) >= 18)(
    'names the key made NOT ENFORCED, which checks nothing (Postgres 18 on)',
    async () => {
      await owner.query(
        'alter table organizations.organizations alter constraint organizations_org_id_fkey not enforced',
      );

      // Postgres marks a key it no longer enforces not valid, and drops its triggers.
      expect(await problems()).toEqual([
        "organizations.organizations's foreign key to directory.orgs has its triggers missing or switched off",
        "organizations.organizations's foreign key to directory.orgs is not validated",
      ]);
    },
  );

  it.each([
    [
      'at another table',
      'create table directory.shadow (org_id uuid primary key)',
      'alter table organizations.organizations add constraint organizations_org_id_fkey foreign key (org_id) references directory.shadow (org_id)',
    ],
    [
      'from another column',
      'alter table organizations.organizations add column other uuid',
      'alter table organizations.organizations add constraint organizations_org_id_fkey foreign key (other) references directory.orgs (org_id)',
    ],
  ])('names the key pointed %s in its place', async (_, prepare, key) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the table above.
    await owner.query(prepare);
    try {
      await owner.query(DROP_KEY);
      // eslint-disable-next-line agentx/no-string-built-sql -- As above.
      await owner.query(key);

      expect(await problems()).toContain(MISSING);
    } finally {
      await owner.query('alter table organizations.organizations drop constraint if exists organizations_org_id_fkey');
      await owner.query('alter table organizations.organizations drop column if exists other');
      await owner.query('drop table if exists directory.shadow');
    }
  });

  it('passes a second key that holds beside one that doesn’t: one is enough', async () => {
    await owner.query(
      // Named to sort first, so the check can't pass by reading the first key alone.
      'alter table organizations.organizations add constraint a_spare_fkey foreign key (org_id) references directory.orgs (org_id) not valid',
    );
    try {
      expect(await problems()).toEqual([]);
    } finally {
      await owner.query('alter table organizations.organizations drop constraint a_spare_fkey');
    }
  });

  it('names the key’s column made nullable, which lets a row with no directory entry through', async () => {
    // The owner's route (the B1d-1 review): drop the primary key, let org_id
    // be null, and a row with a null org_id passes the key unchecked.
    await owner.query('alter table organizations.organizations drop constraint organizations_pkey');
    await owner.query('alter table organizations.organizations alter column org_id drop not null');
    try {
      expect(await problems()).toContain(
        "organizations.organizations's foreign key to directory.orgs has a column that may be null",
      );
    } finally {
      await owner.query('alter table organizations.organizations alter column org_id set not null');
      await owner.query('alter table organizations.organizations add primary key (org_id, id)');
    }
  });

  it.runIf(Number(server.version.split('.')[0]) >= 18)(
    'names the column’s NOT NULL put back NOT VALID, which leaves the rows already there unchecked (Postgres 18 on)',
    async () => {
      // The primary key holds org_id NOT NULL too, so it goes first, as the owner would take it.
      await owner.query('alter table organizations.organizations drop constraint organizations_pkey');
      await owner.query('alter table organizations.organizations alter column org_id drop not null');
      await owner.query(
        'alter table organizations.organizations add constraint org_id_given not null org_id not valid',
      );
      try {
        expect(await problems()).toContain(
          "organizations.organizations's foreign key to directory.orgs has a column that may be null",
        );
      } finally {
        await owner.query('alter table organizations.organizations drop constraint org_id_given');
        await owner.query('alter table organizations.organizations alter column org_id set not null');
        await owner.query('alter table organizations.organizations add primary key (org_id, id)');
      }
    },
  );

  it('matches a key of several columns in its order, not as a set', async () => {
    await owner.query('create schema probe');
    try {
      await owner.query('create table probe.items (org_id uuid not null, id uuid not null, primary key (org_id, id))');
      await owner.query(
        'create table probe.notes (org_id uuid not null, id uuid not null, item_id uuid not null, primary key (org_id, id))',
      );
      await owner.query(
        'alter table probe.notes add constraint notes_item foreign key (item_id, org_id) references probe.items (id, org_id)',
      );
      const required = (columns: string[], referencedColumns: string[]) => ({
        ...SCHEMA_POLICY,
        requiredForeignKeys: [
          ...SCHEMA_POLICY.requiredForeignKeys,
          { reason: 'A test', table: 'probe.notes', columns, references: 'probe.items', referencedColumns },
        ],
      });
      const named = (policy: ReturnType<typeof required>) =>
        liveSchemaProblems(app, { ...ROLES, policy }).then((found) =>
          found.filter((problem) => problem.startsWith("probe.notes's")),
        );

      const missing = ["probe.notes's foreign key to probe.items is not there"];
      expect(await named(required(['item_id', 'org_id'], ['id', 'org_id']))).toEqual([]);
      // Its columns in another order; the ones it points at in another order; a key longer than the one there.
      expect(await named(required(['org_id', 'item_id'], ['org_id', 'id']))).toEqual(missing);
      expect(await named(required(['item_id', 'org_id'], ['org_id', 'id']))).toEqual(missing);
      expect(await named(required(['item_id', 'org_id', 'id'], ['id', 'org_id', 'org_id']))).toEqual(missing);
    } finally {
      await owner.query('drop schema probe cascade');
    }
  });

  it('names a required key the policy lists that no table has', async () => {
    const policy = {
      ...SCHEMA_POLICY,
      requiredForeignKeys: [
        ...SCHEMA_POLICY.requiredForeignKeys,
        {
          reason: 'A test',
          table: 'idempotency.keys',
          columns: ['org_id'],
          references: 'directory.orgs',
          referencedColumns: ['org_id'],
        },
      ],
    };

    expect(await liveSchemaProblems(app, { ...ROLES, policy })).toEqual([
      "idempotency.keys's foreign key to directory.orgs is not there",
    ]);
  });
});

describe('what only the server admin can do', () => {
  // A role of this file's own to hand things to. The shared agentx_* roles
  // belong to the whole test server, and other files check them while this one
  // runs: main.db.test.ts refuses to start as a backup role that owns anything,
  // and failed that way whenever it ran while audit.events was the backup's.
  beforeAll(async () => {
    await database.as('admin').query('create role schema_guard_fixture nologin');
  });

  afterAll(async () => {
    await database.as('admin').query('drop role if exists schema_guard_fixture');
  });

  it('sees a planted cast, which the database owner is refused', async () => {
    // agentx_owner cannot do this — Postgres answers "must be owner of type
    // bigint or type text" (proven S32) — so the admin stands in for the tier
    // above. The guard watches it because a cast on a built-in type could make
    // a tampered value and the app's value read alike.
    const admin = database.as('admin');
    await admin.query(`create function pg_temp.big2text(bigint) returns text language sql immutable as 'select ''x'''`);
    await admin.query('create cast (bigint as text) with function pg_temp.big2text(bigint) as assignment');
    try {
      // The cast is still installed while the guard runs, which is the point:
      // the first draft asked the database for `count(*)::text` and this very
      // cast answered 'x', so the check for planted casts was blinded by the
      // planted cast. Nothing the guard reads is cast to text any more.
      expect(await problems()).toContain('the database carries a cast Postgres did not ship');
    } finally {
      await admin.query('drop cast (bigint as text)');
      await admin.query('drop function pg_temp.big2text(bigint)');
    }
  });

  it('sees a table handed to another role', async () => {
    // agentx_owner cannot give a table away to a role it is not a member of,
    // so this is the admin's tier — but an owner that *was* made a member of
    // another role could, and the guard should not care how it happened.
    const admin = database.as('admin');
    await admin.query('alter table audit.events owner to schema_guard_fixture');
    try {
      expect(await problems()).toContain('audit.events is owned by another role');
    } finally {
      await admin.query('alter table audit.events owner to agentx_owner');
    }
  });

  it.each([
    [
      'organizations.organizations',
      'alter table organizations.organizations disable trigger all',
      'alter table organizations.organizations enable trigger all',
    ],
    [
      'directory.orgs',
      'alter table directory.orgs disable trigger all',
      'alter table directory.orgs enable trigger all',
    ],
  ])('sees the triggers that enforce the organisations’ key switched off on %s', async (_, disable, enable) => {
    // Postgres enforces a foreign key with triggers on both tables; only a
    // superuser may switch those off.
    const admin = database.as('admin');
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written above.
    await admin.query(disable);
    try {
      expect(await problems()).toContain(
        "organizations.organizations's foreign key to directory.orgs has its triggers missing or switched off",
      );
    } finally {
      // eslint-disable-next-line agentx/no-string-built-sql -- As above.
      await admin.query(enable);
    }
  });

  it('sees a schema handed to another role', async () => {
    const admin = database.as('admin');
    await admin.query('alter schema audit owner to schema_guard_fixture');
    try {
      expect(await problems()).toContain('schema "audit" is owned by another role');
    } finally {
      await admin.query('alter schema audit owner to agentx_owner');
    }
  });
});
