// A person's kept name and email (0049, decision 25): what the table takes,
// what it refuses, and that the app may refresh a row's values but never
// delete one or move it to another person.
import { randomUUID } from 'node:crypto';

import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider } from '@agentx/platform/keys';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import type { IdentityTables } from './tables.ts';
import { keepUserContact } from './user-contacts.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const AT = new Date('2026-10-17T09:00:00Z');

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** A person, as their first sign-in makes them. */
const aPerson = async () => {
  const id = randomUUID();
  await app
    .insertInto('identity.users')
    .values({ id, issuer: 'https://auth.example.test', subject: id.replaceAll('-', ''), created_at: AT })
    .execute();
  return id;
};

/** A row's values, both fields kept unless a test says otherwise. */
const kept = (userId: string, values: Partial<Omit<IdentityTables['identity.user_contacts'], 'user_id'>> = {}) => ({
  user_id: userId,
  name_ciphertext: Buffer.alloc(40),
  name_key_version: 1,
  email_ciphertext: Buffer.alloc(40),
  email_key_version: 1,
  updated_at: AT,
  ...values,
});

/** Writes a row, in a transaction rolled back if nothing refuses it. */
const written = (row: ReturnType<typeof kept>) =>
  app.transaction().execute(async (tx) => {
    await tx.insertInto('identity.user_contacts').values(row).execute();
    throw new Error('rolled back');
  });

describe('identity.user_contacts', () => {
  it('takes a name, an email, or both, each sealed in 29 to 1,024 bytes with key version 1 or later', async () => {
    const userId = await aPerson();
    for (const row of [
      kept(userId),
      kept(userId, { email_ciphertext: null, email_key_version: null }),
      kept(userId, { name_ciphertext: null, name_key_version: null }),
      kept(userId, { name_ciphertext: Buffer.alloc(29), email_ciphertext: Buffer.alloc(1024) }),
    ]) {
      await expect(written(row)).rejects.toThrow('rolled back');
    }
  });

  it('refuses a value of the wrong size, a key version below 1, or a value without its key', async () => {
    const userId = await aPerson();
    for (const [row, constraint] of [
      [kept(userId, { name_ciphertext: Buffer.alloc(28) }), 'user_contacts_name_ciphertext_check'],
      [kept(userId, { email_ciphertext: Buffer.alloc(1025) }), 'user_contacts_email_ciphertext_check'],
      [kept(userId, { name_key_version: 0 }), 'user_contacts_name_key_version_check'],
      [kept(userId, { email_key_version: 0 }), 'user_contacts_email_key_version_check'],
      [kept(userId, { name_key_version: null }), 'name_with_its_key'],
      [kept(userId, { email_ciphertext: null }), 'email_with_its_key'],
    ] as const) {
      await expect(written(row)).rejects.toMatchObject({ code: '23514', constraint });
    }
  });

  it('refuses a row with neither a name nor an email', async () => {
    const userId = await aPerson();
    const row = kept(userId, {
      name_ciphertext: null,
      name_key_version: null,
      email_ciphertext: null,
      email_key_version: null,
    });
    await expect(written(row)).rejects.toMatchObject({ code: '23514', constraint: 'holds_a_name_or_an_email' });
  });

  it('keeps one row a person, and only for a person Agent X knows', async () => {
    const userId = await aPerson();
    await app.insertInto('identity.user_contacts').values(kept(userId)).execute();
    await expect(app.insertInto('identity.user_contacts').values(kept(userId)).execute()).rejects.toMatchObject({
      code: '23505',
    });
    await expect(written(kept(randomUUID()))).rejects.toMatchObject({ code: '23503' });
  });

  it('lets the app refresh the values, but never move a row to another person or delete one', async () => {
    const userId = await aPerson();
    const other = await aPerson();
    await app.insertInto('identity.user_contacts').values(kept(userId)).execute();

    await app
      .updateTable('identity.user_contacts')
      .set({ name_ciphertext: Buffer.alloc(50), name_key_version: 2, updated_at: new Date(AT.getTime() + 1000) })
      .where('user_id', '=', userId)
      .execute();
    const row = await app
      .selectFrom('identity.user_contacts')
      .selectAll()
      .where('user_id', '=', userId)
      .executeTakeFirstOrThrow();
    expect(row).toMatchObject({ name_key_version: 2, updated_at: new Date(AT.getTime() + 1000) });

    await expect(
      app.updateTable('identity.user_contacts').set({ user_id: other }).where('user_id', '=', userId).execute(),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      app.deleteFrom('identity.user_contacts').where('user_id', '=', userId).execute(),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('keeps nothing the sign-in didn’t vouch for as a name or one address', async () => {
    const userId = await aPerson();
    const keys = createKeyProvider(
      {
        'field-encryption': { current: 1, versions: new Map([[1, Buffer.alloc(32, 9)]]) },
      },
      ['field-encryption'],
    );
    const keep = (name: string | undefined, verifiedEmail: string | undefined) =>
      keepUserContact(app, keys, userId, { name, verifiedEmail }, AT);

    await expect(keep(' ', undefined)).rejects.toThrow("A person's name refused");
    await expect(keep('Sara', 'not an address')).rejects.toThrow("A person's address refused");
    await keep(undefined, undefined);
    expect(
      await app.selectFrom('identity.user_contacts').select('user_id').where('user_id', '=', userId).execute(),
    ).toEqual([]);
  });
});
