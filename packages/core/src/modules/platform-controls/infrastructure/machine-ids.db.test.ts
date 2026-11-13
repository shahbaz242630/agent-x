// SA3e (0090): Zitadel's machine IDs from the sequence, against a real Postgres: in turn,
// round the 16 bits, and drawn by the app alone, which can't set or rewind the turn.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { nextMachineId } from './machine-ids.ts';
import type { PlatformControlsTables } from './tables.ts';

const server = inject('postgres');

/** What each role given may do with the sequence. */
const RIGHTS = `select r.role,
    pg_catalog.has_sequence_privilege(r.role, 'platform_controls.zitadel_machine_ids', 'USAGE') as usage,
    pg_catalog.has_sequence_privilege(r.role, 'platform_controls.zitadel_machine_ids', 'SELECT') as select,
    pg_catalog.has_sequence_privilege(r.role, 'platform_controls.zitadel_machine_ids', 'UPDATE') as update
  from (values ($1), ($2), ($3)) as r(role) order by r.role`;

/** Any right PUBLIC holds on it. */
const PUBLIC_RIGHTS = `select acl.grantee from pg_catalog.pg_class c cross join pg_catalog.aclexplode(c.relacl) acl
  where c.oid = 'platform_controls.zitadel_machine_ids'::regclass and acl.grantee = 0`;

let database: TestDatabase;
let app: Database<PlatformControlsTables>;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<PlatformControlsTables>(
    { ...database.connection('app'), tls: 'disable', maxConnections: 2 },
    testLogger(),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`Zitadel's machine IDs (Postgres ${server.version})`, () => {
  it('are handed out in turn from 0, and start again at 0 past 65535', async () => {
    expect([await nextMachineId(app), await nextMachineId(app), await nextMachineId(app)]).toEqual([0, 1, 2]);
    await database.as('admin').query("select pg_catalog.setval('platform_controls.zitadel_machine_ids', 65534)");
    expect([await nextMachineId(app), await nextMachineId(app)]).toEqual([65_535, 0]);
  });

  it('never hand two asks at once the same number', async () => {
    const drawn = await Promise.all(Array.from({ length: 20 }, () => nextMachineId(app)));
    expect(new Set(drawn).size).toBe(20);
  });

  it('are drawn by the app alone: it may neither set the turn nor read it, and no other role may draw', async () => {
    const rights = await database
      .as('admin')
      .query<{ role: string; usage: boolean; select: boolean; update: boolean }>(RIGHTS, [
        database.connection('app').user,
        database.connection('backup').user,
        database.connection('operator').user,
      ]);
    const of = (role: 'app' | 'backup' | 'operator') =>
      rights.find((right) => right.role === database.connection(role).user);
    expect(of('app')).toMatchObject({ usage: true, select: false, update: false });
    // A logical backup reads every object, this one's place in the turn included.
    expect(of('backup')).toMatchObject({ usage: false, select: true, update: false });
    expect(of('operator')).toMatchObject({ usage: false, select: false, update: false });
    const publicRights = await database.as('admin').query<{ grantee: number }>(PUBLIC_RIGHTS);
    expect(publicRights).toEqual([]);
    await expect(
      database.as('app').query("select pg_catalog.setval('platform_controls.zitadel_machine_ids', 7)"),
    ).rejects.toThrow(/permission denied/);
    await expect(
      database.as('operator').query("select pg_catalog.nextval('platform_controls.zitadel_machine_ids')"),
    ).rejects.toThrow(/permission denied/);
  });
});
