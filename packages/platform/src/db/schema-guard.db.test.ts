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
import { createTestDatabase, type TestDatabase, type TestSession } from '@agentx/testing';
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
});
