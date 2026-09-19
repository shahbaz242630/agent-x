// The status change (status.ts) and the database's status guard
// (db/migrations/0004_state_rules.sql), on a stand-in table built as a module
// would build one: a tenant table with a status CHECK and the guard. The
// machine here is written out by hand; the shared-kernel's defineStateMachine
// makes the real ones, and tooling/checks/state-rules.test.ts proves they fit.
import {
  createTestDatabase,
  failures,
  LogCapture,
  successes,
  type TestDatabase,
  type TestSession,
  waitUntilBlocked,
  waitUntilQueued,
} from '@agentx/testing';
import { type Generated, sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase, type Database } from './database.ts';
import { createStatusChanger, StatusChangeFailed, type StatusRules, type StatusTable } from './status.ts';
import { TenantContextError, withTenant } from './tenant.ts';

type State = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
type Event = 'suspend' | 'reactivate' | 'revoke';

const STATES: readonly string[] = ['ACTIVE', 'SUSPENDED', 'REVOKED'];
const EVENTS: Readonly<Record<Event, { readonly from: readonly State[]; readonly to: State }>> = {
  suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
  reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
  revoke: { from: ['ACTIVE', 'SUSPENDED'], to: 'REVOKED' },
};
const isState = (value: string): value is State => STATES.includes(value);

const RULES: StatusRules<State, Event> = {
  name: 'thing',
  transition(from, event) {
    if (!isState(from)) return { ok: false, problem: 'unknown_state' };
    const rule = EVENTS[event];
    return rule.from.includes(from) ? { ok: true, from, to: rule.to } : { ok: false, problem: 'not_allowed', from };
  },
};
const THINGS: StatusTable<State, Event> = { table: 'probe.things', rules: RULES };

/** The guard's arguments for the same machine: the first status, then each move. */
const GUARD_ARGUMENTS = "'ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE', 'ACTIVE>REVOKED', 'SUSPENDED>REVOKED'";
const TENANT_POLICY =
  "using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)";

/** probe.things with a status, and probe.parts, whose rows point at a thing: tenant tables, as a module builds them. */
const FIXTURE = [
  'create schema probe',
  "create table probe.things (org_id uuid not null, id uuid not null, status text not null check (status in ('ACTIVE', 'SUSPENDED', 'REVOKED')), label text not null default '', primary key (org_id, id))",
  'alter table probe.things enable row level security',
  'alter table probe.things force row level security',
  `create policy tenant_isolation on probe.things ${TENANT_POLICY}`,
  `create trigger status_guard before insert or update on probe.things for each row execute function state_rules.guard_status(${GUARD_ARGUMENTS})`,
  'create table probe.parts (org_id uuid not null, id uuid not null, thing_id uuid not null, primary key (org_id, id), foreign key (org_id, thing_id) references probe.things (org_id, id))',
  'alter table probe.parts enable row level security',
  'alter table probe.parts force row level security',
  `create policy tenant_isolation on probe.parts ${TENANT_POLICY}`,
  // As a status table's rights must be (0004's header): no DELETE, and no UPDATE of org_id or id.
  'grant usage on schema probe to agentx_app',
  'grant select, insert on probe.things, probe.parts to agentx_app',
  'grant update (status, label) on probe.things to agentx_app',
];

interface ProbeTables {
  'probe.things': { org_id: string; id: string; status: string; label: Generated<string> };
  'probe.parts': { org_id: string; id: string; thing_id: string };
}

const server = inject('postgres');
let database: TestDatabase;
let app: Database<ProbeTables>;
/** The server's superuser: past every wall, for setting up and for playing the attacker. */
let admin: TestSession;
let capture: LogCapture;
const changer = () => createStatusChanger({ logger: loggerFor(capture) });

function loggerFor(destination: LogCapture) {
  return createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
}

const ORG = '0199a0f0-0000-7000-8000-00000000000a';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000000b';
let thingNumber = 0;
/** A new thing's ID, so no two tests share a row. */
const newId = (): string => {
  thingNumber += 1;
  return `0199a0f0-0000-7000-8000-${(0x1000 + thingNumber).toString(16).padStart(12, '0')}`;
};

/** A new thing, created by the app as ACTIVE, then moved by the admin along a move the guard allows. */
async function thingIn(status: State, org = ORG): Promise<string> {
  const id = newId();
  await withTenant(app, org, (tx) =>
    tx.insertInto('probe.things').values({ org_id: org, id, status: 'ACTIVE' }).execute(),
  );
  if (status !== 'ACTIVE') {
    await admin.query('update probe.things set status = $3 where org_id = $1 and id = $2', [org, id, status]);
  }
  return id;
}

async function statusOf(id: string, org = ORG): Promise<string | undefined> {
  const rows = await admin.query<{ status: string }>('select status from probe.things where org_id = $1 and id = $2', [
    org,
    id,
  ]);
  return rows[0]?.status;
}

const change = (id: string, event: Event, org = ORG) =>
  withTenant(app, org, (tx) => changer().change(tx, THINGS, { orgId: org, id }, event));

const linesNamed = (event: string) => capture.lines().filter((line) => line.event === event);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  for (const statement of FIXTURE) {
    // eslint-disable-next-line agentx/no-string-built-sql -- The fixture statements are fixed text above.
    await database.as('owner').query(statement);
  }
  app = createDatabase<ProbeTables>({ ...database.connection('app'), maxConnections: 12 }, loggerFor(new LogCapture()));
  admin = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe('ADR-007 §1.2 a status change', () => {
  it('makes a move the machine allows, and says so', async () => {
    const id = await thingIn('ACTIVE');

    expect(await change(id, 'suspend')).toEqual({ outcome: 'changed', from: 'ACTIVE', to: 'SUSPENDED' });
    expect(await statusOf(id)).toBe('SUSPENDED');
    expect(linesNamed('status.changed')).toEqual([
      expect.objectContaining({
        level: 'info',
        machine: 'thing',
        event: 'status.changed',
        statusEvent: 'suspend',
        orgId: ORG,
        objectId: id,
        from: 'ACTIVE',
        to: 'SUSPENDED',
      }),
    ]);
  });

  it("refuses a move the machine doesn't allow, and leaves the row as it was", async () => {
    const id = await thingIn('REVOKED');

    expect(await change(id, 'reactivate')).toEqual({ outcome: 'refused', from: 'REVOKED' });
    expect(await statusOf(id)).toBe('REVOKED');
    expect(linesNamed('status.change_refused')).toEqual([
      expect.objectContaining({ level: 'info', machine: 'thing', objectId: id, from: 'REVOKED' }),
    ]);
  });

  it('reports a row that does not exist as missing', async () => {
    const id = newId();

    expect(await change(id, 'suspend')).toEqual({ outcome: 'missing' });
    expect(linesNamed('status.row_missing')).toEqual([expect.objectContaining({ level: 'info', objectId: id })]);
  });

  it("can't reach another organisation's row by its ID (SEC-TEN-01)", async () => {
    const theirs = await thingIn('ACTIVE', OTHER_ORG);

    expect(await change(theirs, 'suspend')).toEqual({ outcome: 'missing' });
    expect(await statusOf(theirs, OTHER_ORG)).toBe('ACTIVE');
  });

  it("refuses to run in another organisation's transaction, where the row would look missing", async () => {
    const ours = await thingIn('ACTIVE');

    await expect(
      withTenant(app, OTHER_ORG, (tx) => changer().change(tx, THINGS, { orgId: ORG, id: ours }, 'suspend')),
    ).rejects.toBeInstanceOf(TenantContextError);
    await expect(
      app.transaction().execute((tx) => changer().change(tx, THINGS, { orgId: ORG, id: ours }, 'suspend')),
    ).rejects.toBeInstanceOf(TenantContextError);
    expect(await statusOf(ours)).toBe('ACTIVE');
  });

  it('changes only the status', async () => {
    const id = await thingIn('ACTIVE');
    await admin.query("update probe.things set label = 'kept' where org_id = $1 and id = $2", [ORG, id]);

    await change(id, 'suspend');

    const rows = await admin.query('select * from probe.things where org_id = $1 and id = $2', [ORG, id]);
    expect(rows).toEqual([{ org_id: ORG, id, status: 'SUSPENDED', label: 'kept' }]);
  });

  it('takes IDs in any case, as Postgres reads a uuid', async () => {
    const id = await thingIn('ACTIVE');

    expect(await change(id.toUpperCase(), 'suspend', ORG)).toEqual({
      outcome: 'changed',
      from: 'ACTIVE',
      to: 'SUSPENDED',
    });
  });

  it('is undone with the transaction it runs in', async () => {
    const id = await thingIn('ACTIVE');
    const undone = new Error('undone');

    await expect(
      withTenant(app, ORG, async (tx) => {
        await changer().change(tx, THINGS, { orgId: ORG, id }, 'suspend');
        throw undone;
      }),
    ).rejects.toBe(undone);
    expect(await statusOf(id)).toBe('ACTIVE');
  });

  it.each([
    ['organisation', { orgId: 'org-1', id: ORG }],
    ['row', { orgId: ORG, id: '42' }],
  ])('refuses a key whose %s ID is not a UUID, before asking the database', async (_which, key) => {
    const refused = withTenant(app, ORG, (tx) => changer().change(tx, THINGS, key, 'suspend'));

    await expect(refused).rejects.toBeInstanceOf(StatusChangeFailed);
    await expect(refused).rejects.toMatchObject({ reason: 'bad_key' });
  });

  it.each(['things', 'probe.things; drop table probe.things', 'Probe.Things', 'probe."things"', 'a.b.c'])(
    'refuses a table name that is not a plain schema.table: %j',
    async (table) => {
      await expect(
        withTenant(app, ORG, (tx) => changer().change(tx, { table, rules: RULES }, { orgId: ORG, id: ORG }, 'suspend')),
      ).rejects.toThrow(new RangeError('A status table is named schema.table, in lower-case words'));
      expect(
        await admin.query("select 1 from pg_catalog.pg_tables where schemaname = 'probe' and tablename = 'things'"),
      ).toHaveLength(1);
    },
  );
});

describe('ADR-006 §6 the lock a status change holds', () => {
  /** Runs the change, then keeps its transaction open until `release` is called. */
  function changeAndHold(id: string, event: Event) {
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let changed = (): void => undefined;
    const done = new Promise<void>((resolve) => {
      changed = resolve;
    });
    const running = withTenant(app, ORG, async (tx) => {
      const outcome = await changer().change(tx, THINGS, { orgId: ORG, id }, event);
      changed();
      await held;
      return outcome;
    });
    return { running, done, release };
  }

  it('makes a status read (FOR SHARE) wait until it commits, then shows the new status', async () => {
    const id = await thingIn('ACTIVE');
    const holding = changeAndHold(id, 'suspend');
    await holding.done;
    const reader = await database.connect('admin');
    try {
      const read = reader.query<{ status: string }>(
        'select status from probe.things where org_id = $1 and id = $2 for share',
        [ORG, id],
      );
      await waitUntilBlocked(admin, reader.pid);
      holding.release();

      await holding.running;
      expect(await read).toEqual([{ status: 'SUSPENDED' }]);
    } finally {
      holding.release();
      await reader.end();
    }
  });

  it("doesn't hold up a foreign-key check on the row (FOR NO KEY UPDATE, never FOR UPDATE)", async () => {
    const id = await thingIn('ACTIVE');
    const holding = changeAndHold(id, 'suspend');
    await holding.done;
    const writer = await database.connect('admin');
    try {
      await writer.query("set lock_timeout = '2s'");
      // A part of the locked thing: its foreign-key check takes a key-share lock on the thing's row.
      await writer.query('insert into probe.parts (org_id, id, thing_id) values ($1, $2, $3)', [ORG, newId(), id]);
    } finally {
      holding.release();
      await holding.running;
      await writer.end();
    }
    expect(await admin.query('select 1 from probe.parts where thing_id = $1', [id])).toHaveLength(1);
  });
});

describe('FX-RACE ADR-007 concurrent transitions: one wins', () => {
  /** Holds the row's lock as the admin until every party is queued behind it, then lets them go. */
  async function raceOn<T>(id: string, parties: readonly (() => Promise<T>)[]): Promise<PromiseSettledResult<T>[]> {
    const holder = await database.connect('admin');
    try {
      await holder.query('begin');
      await holder.query('select 1 from probe.things where org_id = $1 and id = $2 for no key update', [ORG, id]);
      const runs = Promise.allSettled(parties.map((party) => party()));
      await waitUntilQueued(admin, parties.length);
      await holder.query('commit');
      return await runs;
    } finally {
      await holder.end();
    }
  }

  it('lets exactly one of six identical suspensions make the move; the rest see it made and are refused', async () => {
    const id = await thingIn('ACTIVE');

    const outcomes = await raceOn(
      id,
      Array.from({ length: 6 }, () => () => change(id, 'suspend')),
    );

    expect(failures(outcomes)).toEqual([]);
    const settled = successes(outcomes);
    expect(settled.filter((outcome) => outcome.outcome === 'changed')).toEqual([
      { outcome: 'changed', from: 'ACTIVE', to: 'SUSPENDED' },
    ]);
    expect(settled.filter((outcome) => outcome.outcome === 'refused')).toHaveLength(5);
    expect(await statusOf(id)).toBe('SUSPENDED');
  });

  it('runs a revocation and a reactivation one after the other, whichever goes first', async () => {
    const id = await thingIn('SUSPENDED');

    const outcomes = successes(await raceOn(id, [() => change(id, 'revoke'), () => change(id, 'reactivate')]));

    const [revoke, reactivate] = outcomes;
    expect([
      // The revocation first: the reactivation finds the thing revoked.
      [
        { outcome: 'changed', from: 'SUSPENDED', to: 'REVOKED' },
        { outcome: 'refused', from: 'REVOKED' },
      ],
      // The reactivation first: the revocation then revokes the active thing.
      [
        { outcome: 'changed', from: 'ACTIVE', to: 'REVOKED' },
        { outcome: 'changed', from: 'SUSPENDED', to: 'ACTIVE' },
      ],
    ]).toContainEqual([revoke, reactivate]);
    expect(await statusOf(id)).toBe('REVOKED');
  });
});

describe('the status guard (db/migrations/0004): the database refuses what the machine does not allow', () => {
  const guardRefusal = { code: '23514', constraint: 'status_guard' };
  const insert = (status: string) =>
    withTenant(app, ORG, (tx) => tx.insertInto('probe.things').values({ org_id: ORG, id: newId(), status }).execute());
  const setStatus = (id: string, status: string | null) =>
    withTenant(app, ORG, (tx) =>
      sql`update probe.things set status = ${status} where org_id = ${ORG} and id = ${id}`.execute(tx),
    );

  it('lets the app create a row in the first status', async () => {
    await expect(insert('ACTIVE')).resolves.toBeDefined();
  });

  it.each(['SUSPENDED', 'REVOKED'])('refuses a new row born %s', async (status) => {
    await expect(insert(status)).rejects.toMatchObject(guardRefusal);
  });

  it('refuses a move the machine does not list, made by the app with its own UPDATE, past the status change', async () => {
    const id = await thingIn('REVOKED');

    await expect(setStatus(id, 'ACTIVE')).rejects.toMatchObject({
      ...guardRefusal,
      message: "the status of a row in probe.things can't move from REVOKED to ACTIVE",
    });
    expect(await statusOf(id)).toBe('REVOKED');
  });

  it('refuses a status set to nothing, before the NOT NULL does', async () => {
    const id = await thingIn('ACTIVE');

    await expect(setStatus(id, null)).rejects.toMatchObject(guardRefusal);
  });

  it('passes a listed move, an unchanged status and a change to another column', async () => {
    const id = await thingIn('ACTIVE');

    await setStatus(id, 'SUSPENDED');
    await setStatus(id, 'SUSPENDED');
    await withTenant(app, ORG, (tx) =>
      tx.updateTable('probe.things').set({ label: 'renamed' }).where('org_id', '=', ORG).where('id', '=', id).execute(),
    );
    expect(await statusOf(id)).toBe('SUSPENDED');
  });

  it('runs for the app, which holds no right on the function or its schema', async () => {
    const rights = await admin.query<{ execute: boolean; usage: boolean }>(
      "select pg_catalog.has_function_privilege('agentx_app', 'state_rules.guard_status()', 'EXECUTE') as execute, pg_catalog.has_schema_privilege('agentx_app', 'state_rules', 'USAGE') as usage",
    );
    expect(rights).toEqual([{ execute: false, usage: false }]);
  });

  it.each([
    ['switching triggers off for its session', sql`set local session_replication_role = replica`],
    ['disabling the guard', sql`alter table probe.things disable trigger status_guard`],
    ['dropping the guard', sql`drop trigger status_guard on probe.things`],
  ])("can't be switched off by the app: %s", async (_how, statement) => {
    await expect(withTenant(app, ORG, (tx) => statement.execute(tx))).rejects.toMatchObject({ code: '42501' });
  });

  it.each([
    ['id', 'update probe.things set id = $3 where org_id = $1 and id = $2'],
    ['organisation', 'update probe.things set org_id = $3 where org_id = $1 and id = $2'],
  ])('refuses a row given another %s, even by the server admin, past row security', async (_which, statement) => {
    const id = await thingIn('REVOKED');
    const rekey = (): Promise<unknown> =>
      // eslint-disable-next-line agentx/no-string-built-sql -- The statement is one of the fixed texts above.
      admin.query(statement, [ORG, id, newId()]);

    await expect(rekey()).rejects.toMatchObject({
      ...guardRefusal,
      message: 'a row in probe.things keeps its org_id and id',
    });
    await expect(
      withTenant(app, ORG, (tx) =>
        sql`update probe.things set id = ${newId()} where org_id = ${ORG} and id = ${id}`.execute(tx),
      ),
    ).rejects.toMatchObject({ code: '42501' });
    expect(await statusOf(id)).toBe('REVOKED');
  });

  it("runs with its own search_path, pg_catalog, and with its caller's rights", async () => {
    const [facts] = await admin.query<{ config: string[]; definer: boolean }>(
      "select p.proconfig as config, p.prosecdef as definer from pg_catalog.pg_proc p where p.oid = 'state_rules.guard_status()'::pg_catalog.regprocedure",
    );
    expect(facts).toEqual({ config: ['search_path=pg_catalog'], definer: false });
  });

  describe('attached wrongly, it refuses every row rather than pass one', () => {
    const tables: string[] = [];
    afterAll(async () => {
      for (const table of tables) {
        // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup of the fixed table names below.
        await database.as('owner').query(`drop table ${table}`);
      }
    });

    it.each([
      ['as an AFTER trigger', 'after insert', 'row', "'ACTIVE'", '09000'],
      ['for each statement', 'before insert', 'statement', "'ACTIVE'", '09000'],
      ['with no rules', 'before insert', 'row', '', '23514'],
    ])('%s', async (_how, timing, level, args, code) => {
      const table = `probe.wrong_${tables.length + 1}`;
      tables.push(table);
      const owner = database.as('owner');
      // eslint-disable-next-line agentx/no-string-built-sql -- Fixed fixture text built from the table above.
      await owner.query(`create table ${table} (status text not null)`);
      // eslint-disable-next-line agentx/no-string-built-sql -- As above.
      await owner.query(
        `create trigger status_guard ${timing} on ${table} for each ${level} execute function state_rules.guard_status(${args})`,
      );

      // eslint-disable-next-line agentx/no-string-built-sql -- As above.
      await expect(owner.query(`insert into ${table} (status) values ('ACTIVE')`)).rejects.toMatchObject({ code });
    });
  });
});

describe('FX-TAMPER a table changed past the app is refused, not trusted', () => {
  // Each case plays the database owner or admin, holding none of the app's
  // keys, and undoes its change afterwards so the fixture stays whole.
  it('a status the machine does not have, planted with the CHECK and the guard out of the way', async () => {
    const id = await thingIn('ACTIVE');
    await admin.query('alter table probe.things drop constraint things_status_check');
    await admin.query('alter table probe.things disable trigger status_guard');
    try {
      await admin.query("update probe.things set status = 'UNLOCKED' where org_id = $1 and id = $2", [ORG, id]);

      await expect(change(id, 'revoke')).rejects.toMatchObject({ name: 'StatusChangeFailed', reason: 'unreadable' });
      expect(await statusOf(id)).toBe('UNLOCKED');
      expect(linesNamed('status.unreadable')).toEqual([
        expect.objectContaining({ level: 'error', machine: 'thing', objectId: id }),
      ]);
    } finally {
      await admin.query("update probe.things set status = 'REVOKED' where org_id = $1 and id = $2", [ORG, id]);
      await admin.query('alter table probe.things enable trigger status_guard');
      await admin.query(
        "alter table probe.things add constraint things_status_check check (status in ('ACTIVE', 'SUSPENDED', 'REVOKED'))",
      );
    }
  });

  it('a status set to nothing, with the NOT NULL and the guard out of the way', async () => {
    const id = await thingIn('ACTIVE');
    await admin.query('alter table probe.things alter column status drop not null');
    await admin.query('alter table probe.things disable trigger status_guard');
    try {
      await admin.query('update probe.things set status = null where org_id = $1 and id = $2', [ORG, id]);

      await expect(change(id, 'revoke')).rejects.toMatchObject({ reason: 'unreadable' });
    } finally {
      await admin.query("update probe.things set status = 'REVOKED' where org_id = $1 and id = $2", [ORG, id]);
      await admin.query('alter table probe.things enable trigger status_guard');
      await admin.query('alter table probe.things alter column status set not null');
    }
  });

  it('a second row under the same key, with the primary key dropped', async () => {
    const id = await thingIn('ACTIVE');
    await admin.query('alter table probe.parts drop constraint parts_org_id_thing_id_fkey');
    await admin.query('alter table probe.things drop constraint things_pkey');
    try {
      await admin.query("insert into probe.things (org_id, id, status) values ($1, $2, 'ACTIVE')", [ORG, id]);

      await expect(change(id, 'suspend')).rejects.toMatchObject({ reason: 'unreadable' });
      expect(await admin.query('select status from probe.things where id = $1', [id])).toEqual([
        { status: 'ACTIVE' },
        { status: 'ACTIVE' },
      ]);
    } finally {
      await admin.query(
        'delete from probe.things where id = $1 and ctid <> (select min(ctid) from probe.things where id = $1)',
        [id],
      );
      await admin.query('alter table probe.things add primary key (org_id, id)');
      await admin.query(
        'alter table probe.parts add constraint parts_org_id_thing_id_fkey foreign key (org_id, thing_id) references probe.things (org_id, id)',
      );
    }
  });

  it('a second row under the same key, inserted while the change waits for the lock: both would be updated', async () => {
    const id = await thingIn('ACTIVE');
    await admin.query('alter table probe.parts drop constraint parts_org_id_thing_id_fkey');
    await admin.query('alter table probe.things drop constraint things_pkey');
    const holder = await database.connect('admin');
    try {
      await holder.query('begin');
      await holder.query('select 1 from probe.things where org_id = $1 and id = $2 for no key update', [ORG, id]);
      const changing = change(id, 'suspend');
      await waitUntilQueued(admin, 1);
      // Committed while the change waits: its locking read has its snapshot already, its update won't.
      await admin.query("insert into probe.things (org_id, id, status) values ($1, $2, 'ACTIVE')", [ORG, id]);
      await holder.query('commit');

      await expect(changing).rejects.toMatchObject({ reason: 'not_applied' });
      expect(await admin.query('select status from probe.things where id = $1', [id])).toEqual([
        { status: 'ACTIVE' },
        { status: 'ACTIVE' },
      ]);
    } finally {
      await holder.end();
      await admin.query(
        'delete from probe.things where id = $1 and ctid <> (select min(ctid) from probe.things where id = $1)',
        [id],
      );
      await admin.query('alter table probe.things add primary key (org_id, id)');
      await admin.query(
        'alter table probe.parts add constraint parts_org_id_thing_id_fkey foreign key (org_id, thing_id) references probe.things (org_id, id)',
      );
    }
  });

  // Postgres runs a table's BEFORE ROW triggers in name order: `aaa_` before the guard, `zzz_` after it.
  it.each([
    ['swallows the update', 'aaa_planted', 'return null;'],
    ['keeps the old status, before the guard looks', 'aaa_planted', 'new.status := old.status; return new;'],
    ['writes another status, after the guard has looked', 'zzz_planted', "new.status := 'SUSPENDED'; return new;"],
  ])('a trigger planted that %s: the row is not left as decided, which is an error', async (_what, name, body) => {
    const id = await thingIn('ACTIVE');
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed fixture text from the cases above.
    await admin.query(`create function probe.planted() returns trigger language plpgsql as $$ begin ${body} end $$`);
    // eslint-disable-next-line agentx/no-string-built-sql -- As above.
    await admin.query(
      `create trigger ${name} before update on probe.things for each row execute function probe.planted()`,
    );
    try {
      await expect(change(id, 'revoke')).rejects.toMatchObject({ name: 'StatusChangeFailed', reason: 'not_applied' });
      expect(await statusOf(id)).toBe('ACTIVE');
      expect(linesNamed('status.change_not_applied')).toEqual([
        expect.objectContaining({ level: 'error', from: 'ACTIVE', to: 'REVOKED' }),
      ]);
    } finally {
      // eslint-disable-next-line agentx/no-string-built-sql -- As above.
      await admin.query(`drop trigger ${name} on probe.things`);
      await admin.query('drop function probe.planted()');
    }
  });
});
