// S212 F3 (partner decision 27): the members list an admin is shown names each
// member, composed in the API on the real migrated schema as the app role:
// the names Agent X kept (decision 25) of the organisation's own members
// alone, never another organisation's, and none at all when not asked.
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMembersList, type ListMembers } from './members.ts';
import { keys, mandateWorld, type MandateWorldTables } from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xf3a5_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000f3a50';

let clock: FixedClock;
let listMembers: ListMembers;

const { world, member } = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'members-named' });

/** Keeps a person's name and address as a sign-in does (user-contacts.ts): each bound to its person and its field. */
async function kept(userId: string, name: string, email: string): Promise<void> {
  const sealed = (value: string, field: 'name' | 'email') =>
    keys.encrypt('field-encryption', Buffer.from(value), ['identity.user_contacts', userId, field]);
  const sealedName = sealed(name, 'name');
  const sealedEmail = sealed(email, 'email');
  await app
    .insertInto('identity.user_contacts')
    .values({
      user_id: userId,
      name_ciphertext: sealedName.ciphertext,
      name_key_version: sealedName.keyVersion,
      email_ciphertext: sealedEmail.ciphertext,
      email_key_version: sealedEmail.keyVersion,
      updated_at: clock.now(),
    })
    .execute();
}

const listed = async (orgId: string, named: boolean) => {
  const list = await listMembers(orgId, CORRELATION, named);
  if (list.outcome !== 'listed') throw new Error(`not listed: ${JSON.stringify(list)}`);
  return list;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-11-23T08:00:00Z'));
  listMembers = createMembersList({
    database: app,
    keys,
    ids,
    logger: testLogger(new LogCapture()),
    directory: undefined,
  });
});

describe('SEC-TEN-01 the members list names its own members for an admin (S212 F3, decision 27)', () => {
  it('names each of the organisation’s members from the kept copy, and none of another organisation’s', async () => {
    const w = await world();
    const other = await world();
    const viewer = await member(w.org, 'viewer');
    await kept(w.admin.userId, 'Sara Khan', 'sara@example.com');
    await kept(other.admin.userId, 'Omar Ali', 'omar@example.com');

    const list = await listed(w.org, true);

    expect(list.members.map((one) => one.userId).sort()).toEqual([w.admin.userId, viewer.userId].sort());
    expect(Object.fromEntries(list.names ?? [])).toEqual({
      [`user:${w.admin.userId}`]: { name: 'Sara Khan', email: 'sara@example.com', shownFrom: 'kept_copy' },
      // Kept nothing of the viewer: their ID alone.
      [`user:${viewer.userId}`]: { name: null, email: null, shownFrom: null },
    });
  });

  it('gives another organisation’s admin their own members’ names alone', async () => {
    const w = await world();
    const other = await world();
    await kept(w.admin.userId, 'Sara Khan', 'sara@example.com');
    await kept(other.admin.userId, 'Omar Ali', 'omar@example.com');

    const list = await listed(other.org, true);

    expect(Object.fromEntries(list.names ?? [])).toEqual({
      [`user:${other.admin.userId}`]: { name: 'Omar Ali', email: 'omar@example.com', shownFrom: 'kept_copy' },
    });
  });

  it('names no one when the list is not asked to be named', async () => {
    const w = await world();
    await kept(w.admin.userId, 'Sara Khan', 'sara@example.com');

    const list = await listed(w.org, false);

    expect(list.members.map((one) => one.userId)).toEqual([w.admin.userId]);
    expect(list.names).toBeUndefined();
  });
});
