// B4-1: the directory's list of who belongs where (0015), as the app role.
// The memberships its entries point at are the identity module's
// (memberships.db.test.ts); here, the entries alone.
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { listedMembership, registerMember } from './members.ts';
import { registerOrganization } from './organizations.ts';
import type { DirectoryTables } from './tables.ts';

type Tables = DirectoryTables & { 'identity.users': { id: string; issuer: string; subject: string; created_at: Date } };

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const ids = new SequentialIds(0xc000_0000_0000);
const clock = new FixedClock(new Date('2026-09-25T09:00:00Z'));

const organization = async (): Promise<string> => {
  const id = ids.next();
  await withTenant(app, id, (tx) => registerOrganization(tx, id));
  return id;
};

let subjects = 0;
const person = async (): Promise<string> => {
  subjects += 1;
  const id = ids.next();
  await app
    .insertInto('identity.users')
    .values({ id, issuer: 'https://auth.example.test', subject: `entry-${String(subjects)}`, created_at: clock.now() })
    .execute();
  return id;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(
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

describe(`the directory's list of who belongs where (Postgres ${server.version})`, () => {
  it("lists a person in an organisation by their membership's ID, found only in that organisation", async () => {
    const [org, other] = [await organization(), await organization()];
    const user = await person();
    const membershipId = ids.next();

    await withTenant(app, org, (tx) => registerMember(tx, { orgId: org, userId: user, membershipId }));

    expect(await withTenant(app, org, (tx) => listedMembership(tx, org, user))).toBe(membershipId);
    expect(await withTenant(app, other, (tx) => listedMembership(tx, other, user))).toBeUndefined();
    expect(await withTenant(app, org, (tx) => listedMembership(tx, org, ids.next()))).toBeUndefined();
  });

  it("refuses to list or look up one from another organisation's transaction, or from none", async () => {
    const [org, other] = [await organization(), await organization()];
    const user = await person();

    await expect(
      withTenant(app, other, (tx) => registerMember(tx, { orgId: org, userId: user, membershipId: ids.next() })),
    ).rejects.toBeInstanceOf(TenantContextError);
    await expect(
      app.transaction().execute((tx) => registerMember(tx, { orgId: org, userId: user, membershipId: ids.next() })),
    ).rejects.toBeInstanceOf(TenantContextError);
    await withTenant(app, org, (tx) => registerMember(tx, { orgId: org, userId: user, membershipId: ids.next() }));
    await expect(withTenant(app, other, (tx) => listedMembership(tx, org, user))).rejects.toBeInstanceOf(
      TenantContextError,
    );
  });
});
