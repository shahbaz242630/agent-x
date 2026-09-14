import { createTenantProbe, createTestDatabase, type TestDatabase } from '@agentx/testing';
import { type Kysely, sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase } from './database.ts';
import { TenantContextError, withTenant } from './tenant.ts';

interface ProbeSchema {
  'probe.items': { org_id: string; id: string; label: string };
}

const ORG_A = '0199a000-0000-7000-8000-00000000000a';
const ORG_B = '0199b000-0000-7000-8000-00000000000b';
const ITEM = (n: number): string => `0199c000-0000-7000-8000-${String(n).padStart(12, '0')}`;

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<ProbeSchema>;

/** Every label the organisation can see, sorted. */
const labelsSeenBy = (orgId: string): Promise<string[]> =>
  withTenant(app, orgId, async (tx) => {
    const rows = await tx.selectFrom('probe.items').select('label').orderBy('label').execute();
    return rows.map((row) => row.label);
  });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  await createTenantProbe(database);
  app = createDatabase<ProbeSchema>(database.connection('app'));
  await withTenant(app, ORG_A, (tx) =>
    tx
      .insertInto('probe.items')
      .values([
        { org_id: ORG_A, id: ITEM(1), label: 'a1' },
        { org_id: ORG_A, id: ITEM(2), label: 'a2' },
      ])
      .execute(),
  );
  await withTenant(app, ORG_B, (tx) =>
    tx
      .insertInto('probe.items')
      .values({ org_id: ORG_B, id: ITEM(3), label: 'b1' })
      .execute(),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`SEC-TEN-02 row-level security alone keeps organisations apart (Postgres ${server.version})`, () => {
  it('returns only the organisation’s own rows to a query with no org_id filter', async () => {
    expect(await labelsSeenBy(ORG_A)).toEqual(['a1', 'a2']);
    expect(await labelsSeenBy(ORG_B)).toEqual(['b1']);
  });

  it('refuses to write a row for another organisation', async () => {
    await expect(
      withTenant(app, ORG_A, (tx) =>
        tx
          .insertInto('probe.items')
          .values({ org_id: ORG_B, id: ITEM(9), label: 'smuggled' })
          .execute(),
      ),
    ).rejects.toThrow(/row-level security/);
    expect(await labelsSeenBy(ORG_B)).toEqual(['b1']);
  });

  it('never lets an update or delete with no filter reach another organisation’s rows', async () => {
    await expect(
      withTenant(app, ORG_A, async (tx) => {
        const updated = await tx.updateTable('probe.items').set({ label: 'changed' }).executeTakeFirst();
        expect(updated.numUpdatedRows).toBe(2n);
        throw new Error('roll back');
      }),
    ).rejects.toThrow('roll back');
    const deleted = await withTenant(app, ORG_A, (tx) =>
      tx.deleteFrom('probe.items').where('label', '=', 'no such label').executeTakeFirst(),
    );
    expect(deleted.numDeletedRows).toBe(0n);
    expect(await labelsSeenBy(ORG_B)).toEqual(['b1']);
  });

  it('refuses to move a row into another organisation', async () => {
    await expect(
      withTenant(app, ORG_A, (tx) =>
        tx.updateTable('probe.items').set({ org_id: ORG_B }).where('label', '=', 'a1').execute(),
      ),
    ).rejects.toThrow(/row-level security/);
  });
});

describe('SEC-TEN-03 with no tenant context, nothing is visible', () => {
  it('shows the app no rows outside withTenant', async () => {
    expect(await app.selectFrom('probe.items').selectAll().execute()).toEqual([]);
  });

  it('refuses the app a write outside withTenant', async () => {
    await expect(
      app
        .insertInto('probe.items')
        .values({ org_id: ORG_A, id: ITEM(8), label: 'no context' })
        .execute(),
    ).rejects.toThrow(/row-level security/);
  });

  it('binds the table owner too, because row-level security is forced', async () => {
    expect(await database.as('owner').query('select org_id from probe.items')).toEqual([]);
  });

  it('lets only the backup role, the documented exception, read every organisation', async () => {
    const rows = await database
      .as('backup')
      .query<{ org_id: string }>('select org_id from probe.items order by org_id');
    expect(rows.map((row) => row.org_id)).toEqual([ORG_A, ORG_A, ORG_B]);
    await expect(
      database
        .as('backup')
        .query('insert into probe.items (org_id, id, label) values ($1, $2, $3)', [ORG_A, ITEM(7), 'backup write']),
    ).rejects.toThrow(/permission denied/);
  });
});

describe('SEC-TEN-06 a pooled connection never carries a tenant', () => {
  const settingOutside = async (db: Kysely<ProbeSchema>): Promise<string | null> => {
    const { rows } = await sql<{ org_id: string | null }>`
      select pg_catalog.current_setting('app.org_id', true) as org_id
    `.execute(db);
    return rows[0]?.org_id ?? null;
  };

  it('starts a new connection with no setting at all (NULL), which matches no rows', async () => {
    const fresh = createDatabase<ProbeSchema>({ ...database.connection('app'), maxConnections: 1 });
    try {
      expect(await settingOutside(fresh)).toBeNull();
      expect(await fresh.selectFrom('probe.items').selectAll().execute()).toEqual([]);
    } finally {
      await fresh.destroy();
    }
  });

  it('leaves an empty setting behind after a transaction, which nullif turns into no rows', async () => {
    const single = createDatabase<ProbeSchema>({ ...database.connection('app'), maxConnections: 1 });
    try {
      expect(await withTenant(single, ORG_A, async (tx) => (await settingOutside(tx)) === ORG_A)).toBe(true);
      // The same connection, back in the pool: the transaction's setting is gone.
      expect(await settingOutside(single)).toBe('');
      expect(await single.selectFrom('probe.items').selectAll().execute()).toEqual([]);
    } finally {
      await single.destroy();
    }
  });

  it('clears the setting after a transaction that fails, too', async () => {
    const single = createDatabase<ProbeSchema>({ ...database.connection('app'), maxConnections: 1 });
    try {
      await expect(withTenant(single, ORG_B, () => Promise.reject(new Error('work failed')))).rejects.toThrow(
        'work failed',
      );
      expect(await settingOutside(single)).toBe('');
      expect(await single.selectFrom('probe.items').selectAll().execute()).toEqual([]);
    } finally {
      await single.destroy();
    }
  });

  it.each([
    ['the role', (name: string) => `alter role agentx_app in database ${name} set app.org_id = '${ORG_A}'`],
    ['the database', (name: string) => `alter database ${name} set app.org_id = '${ORG_A}'`],
  ])('closes a new connection that %s presets with a tenant, and never uses it', async (_, preset) => {
    // The superuser plays the attacker; the owner could preset the database the same way.
    // eslint-disable-next-line agentx/no-string-built-sql -- Test setup: the database name is generated, and ALTER can't take it as a parameter.
    await database.as('admin').query(preset(database.name));
    const exposed = createDatabase<ProbeSchema>(database.connection('app'));
    try {
      await expect(exposed.selectFrom('probe.items').selectAll().execute()).rejects.toThrow(TenantContextError);
      await expect(exposed.selectFrom('probe.items').selectAll().execute()).rejects.toThrow(/already carries/);
    } finally {
      await exposed.destroy();
      // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
      await database.as('admin').query(`alter role agentx_app in database ${database.name} reset all`);
      // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
      await database.as('admin').query(`alter database ${database.name} reset all`);
    }
  });
});

describe('withTenant', () => {
  it('refuses an organisation ID that is not a UUID, before opening a transaction', async () => {
    for (const orgId of ['', 'org-a', `${ORG_A} `, `{${ORG_A}}`, ORG_A.replaceAll('-', ''), "' or true --"]) {
      await expect(withTenant(app, orgId, () => Promise.resolve('ran'))).rejects.toThrow(TenantContextError);
    }
    expect(await withTenant(app, ORG_A.toUpperCase(), () => Promise.resolve('ran'))).toBe('ran');
  });

  it('commits when the work resolves, and rolls back when it throws', async () => {
    await withTenant(app, ORG_B, (tx) =>
      tx
        .insertInto('probe.items')
        .values({ org_id: ORG_B, id: ITEM(4), label: 'b2' })
        .execute(),
    );
    await expect(
      withTenant(app, ORG_B, async (tx) => {
        await tx
          .insertInto('probe.items')
          .values({ org_id: ORG_B, id: ITEM(5), label: 'b3' })
          .execute();
        throw new Error('changed my mind');
      }),
    ).rejects.toThrow('changed my mind');
    expect(await labelsSeenBy(ORG_B)).toEqual(['b1', 'b2']);
  });

  it('cannot be nested', async () => {
    await expect(
      withTenant(app, ORG_A, (tx) => withTenant<ProbeSchema, string>(tx, ORG_B, () => Promise.resolve('inner'))),
    ).rejects.toThrow(/not supported/);
  });

  it('runs READ COMMITTED even when the role’s default says otherwise (ADR-006)', async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Test setup: the database name is generated, and ALTER can't take it as a parameter.
    await database
      .as('admin')
      .query(`alter role agentx_app in database ${database.name} set default_transaction_isolation = 'serializable'`);
    const strict = createDatabase<ProbeSchema>(database.connection('app'));
    try {
      const outside = await sql<{
        level: string;
      }>`select pg_catalog.current_setting('transaction_isolation') as level`.execute(strict);
      expect(outside.rows[0]?.level).toBe('serializable');
      const inside = await withTenant(strict, ORG_A, async (tx) => {
        const { rows } = await sql<{
          level: string;
        }>`select pg_catalog.current_setting('transaction_isolation') as level`.execute(tx);
        return rows[0]?.level;
      });
      expect(inside).toBe('read committed');
    } finally {
      await strict.destroy();
      // eslint-disable-next-line agentx/no-string-built-sql -- Test cleanup, as above.
      await database.as('admin').query(`alter role agentx_app in database ${database.name} reset all`);
    }
  });
});

describe('APP-02 the app role cannot get round the walls', () => {
  it.each([
    ['switch row-level security off', 'alter table probe.items disable row level security', /must be owner/],
    ['stop forcing row-level security', 'alter table probe.items no force row level security', /must be owner/],
    ['drop the policy', 'drop policy tenant_isolation on probe.items', /must be owner/],
    ['become the owner', 'set role agentx_owner', /permission denied/],
    ['become the backup role', 'set role agentx_backup', /permission denied/],
    ['change its session identity', 'set session authorization agentx_owner', /permission denied/],
    ['create a table in the public schema', 'create table public.planted (id int)', /permission denied/],
    ['create a schema', 'create schema planted', /permission denied/],
    ['create a temporary table', 'create temporary table planted (id int)', /permission denied/],
  ])('cannot %s', async (_, statement, refusal) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text in this table.
    await expect(database.as('app').query(statement)).rejects.toThrow(refusal);
  });
});
