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
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { liveSchemaProblems } from './schema-guard.ts';

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

describe('what only the server admin can do', () => {
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
    await admin.query('alter table audit.events owner to agentx_backup');
    try {
      expect(await problems()).toContain('audit.events is owned by another role');
    } finally {
      await admin.query('alter table audit.events owner to agentx_owner');
    }
  });

  it('sees a schema handed to another role', async () => {
    const admin = database.as('admin');
    await admin.query('alter schema audit owner to agentx_backup');
    try {
      expect(await problems()).toContain('schema "audit" is owned by another role');
    } finally {
      await admin.query('alter schema audit owner to agentx_owner');
    }
  });
});
