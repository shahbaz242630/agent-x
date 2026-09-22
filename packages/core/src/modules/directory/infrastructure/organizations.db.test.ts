// The directory's list of organisations (0007), as the app role.
import { createTestDatabase, LogCapture, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { registerOrganization } from './organizations.ts';
import type { DirectoryTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<DirectoryTables>;

let number = 0;
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x6000 + number).toString(16).padStart(12, '0')}`;
};

const listed = (id: string) => app.selectFrom('directory.orgs').select('org_id').where('org_id', '=', id).execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<DirectoryTables>(
    { ...database.connection('app'), maxConnections: 2 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the directory's list of organisations (Postgres ${server.version})`, () => {
  it('lists an organisation in its own withTenant, where any tenant can then find it', async () => {
    const id = newId();

    await withTenant(app, id, (tx) => registerOrganization(tx, id));

    expect(await listed(id)).toEqual([{ org_id: id }]);
    expect(
      await withTenant(app, newId(), (tx) => tx.selectFrom('directory.orgs').select('org_id').execute()),
    ).toContainEqual({
      org_id: id,
    });
  });

  it("refuses to list one from another organisation's transaction, or from none", async () => {
    const id = newId();

    await expect(withTenant(app, newId(), (tx) => registerOrganization(tx, id))).rejects.toBeInstanceOf(
      TenantContextError,
    );
    await expect(app.transaction().execute((tx) => registerOrganization(tx, id))).rejects.toBeInstanceOf(
      TenantContextError,
    );

    expect(await listed(id)).toEqual([]);
  });

  it('refuses one listed already', async () => {
    const id = newId();
    await withTenant(app, id, (tx) => registerOrganization(tx, id));

    await expect(withTenant(app, id, (tx) => registerOrganization(tx, id))).rejects.toMatchObject({
      code: '23505',
      constraint: 'orgs_pkey',
    });
  });
});
