// 4D2e E10 (PL-29): the role a chain repair writes as, against a real
// Postgres. Only the owner, logged in as itself and unable to bypass the
// tenant wall, may: the repair's statements then stay held to the one
// organisation by the wall, forced on the owner too. The repair itself is
// proven in apps/operator/src/chain-restore.db.test.ts.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger, type TestRole } from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { REPAIR_ROLE, repairRoleProblems } from './chain-repair.ts';
import type { AuditTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
const open: Database<AuditTables>[] = [];

const as = (role: TestRole): Database<AuditTables> => {
  const handle = createDatabase<AuditTables>({ ...database.connection(role), maxConnections: 1 }, testLogger());
  open.push(handle);
  return handle;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await Promise.all(open.map((handle) => handle.destroy()));
  await database.drop();
});

describe("PL-29 the repair's role", () => {
  it('is the owner, logged in as itself', async () => {
    expect(REPAIR_ROLE).toBe('agentx_owner');
    expect(await repairRoleProblems(as('owner'))).toEqual([]);
    expect(await repairRoleProblems(as('operator'))).toEqual(['it is logged in as agentx_operator, not agentx_owner']);
  });

  it('refuses a superuser, and a login switched to the owner (SET ROLE): the login is what is judged', async () => {
    const admin = as('admin');
    expect(await repairRoleProblems(admin)).toEqual([
      expect.stringMatching(/^it is logged in as .+, not agentx_owner$/),
      'it can bypass row-level security',
    ]);
    await sql`set role agentx_owner`.execute(admin);
    expect(await repairRoleProblems(admin)).toEqual([
      expect.stringMatching(/^it is logged in as .+, not agentx_owner$/),
      'the session has switched to another role (SET ROLE)',
      'it can bypass row-level security',
    ]);
  });
});
