// B2-1: the people who sign in (0010), on the real migrated schema, as the app role.
import { createTestDatabase, FixedClock, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider } from '@agentx/platform/keys';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { SignInRefused } from '../domain/sign-in.ts';
import type { IdentityTables } from './tables.ts';
import { isUser, subjectOfUser, userForSubject } from './users.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const ISSUER = 'https://auth.example.test';
const clock = new FixedClock(new Date('2026-09-24T09:00:00Z'));
const ids = new SequentialIds(0x100);
const keys = createKeyProvider({ 'session-mac': { current: 1, versions: new Map([[1, Buffer.alloc(32, 9)]]) } }, [
  'session-mac',
]);
const macs = { keys, logger: testLogger() };
let subjects = 0;
/** A subject no other test has used. */
const newSubject = (): string => {
  subjects += 1;
  return `3387194723948${String(subjects).padStart(5, '0')}`;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the people who sign in (Postgres ${server.version})`, () => {
  it('gives the issuer and subject a user signs in as, by their ID, as the app role (B5-3)', async () => {
    const subject = newSubject();
    const id = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() });
    await expect(subjectOfUser(app, id, macs)).resolves.toEqual({ issuer: ISSUER, subject });
    await expect(subjectOfUser(app, '01a0f000-0000-7000-8000-0000000000ff', macs)).resolves.toBeUndefined();
    await expect(isUser(app, id)).resolves.toBe(true);
    await expect(isUser(app, '01a0f000-0000-7000-8000-0000000000ff')).resolves.toBe(false);
  });

  it('makes a user at their first sign-in and finds the same one at every one after', async () => {
    const subject = newSubject();
    const first = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() });
    const again = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() });

    expect(again).toBe(first);
    expect(await app.selectFrom('identity.users').selectAll().where('subject', '=', subject).execute()).toEqual([
      // Never ended yet (0098, AG10).
      {
        id: first,
        issuer: ISSUER,
        subject,
        created_at: clock.now(),
        sessions_ended_at: null,
        // Its MAC (S205), with the current key.
        mac: expect.any(Buffer) as Buffer,
        mac_key_version: 1,
      },
    ]);
  });

  it('keeps one subject from two issuers apart, and a subject in another case', async () => {
    const subject = `user-${newSubject()}`;
    const here = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() });
    const there = await userForSubject(
      app,
      { issuer: 'https://other.example.test', subject },
      { ids, clock, keys, logger: testLogger() },
    );
    const upper = await userForSubject(
      app,
      { issuer: ISSUER, subject: subject.toUpperCase() },
      { ids, clock, keys, logger: testLogger() },
    );

    expect(new Set([here, there, upper]).size).toBe(3);
  });

  it('makes one user when two first sign-ins come at once', async () => {
    const subject = newSubject();
    const found = await Promise.all(
      Array.from({ length: 4 }, () =>
        userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() }),
      ),
    );

    expect(new Set(found).size).toBe(1);
    expect(await app.selectFrom('identity.users').select('id').where('subject', '=', subject).execute()).toHaveLength(
      1,
    );
  });

  it('refuses a subject it could not store, before any statement', async () => {
    await expect(
      userForSubject(app, { issuer: ISSUER, subject: '' }, { ids, clock, keys, logger: testLogger() }),
    ).rejects.toBeInstanceOf(SignInRefused);
    await expect(
      userForSubject(app, { issuer: '', subject: newSubject() }, { ids, clock, keys, logger: testLogger() }),
    ).rejects.toBeInstanceOf(SignInRefused);
  });

  it('never lets the app change or delete a user', async () => {
    const subject = newSubject();
    const id = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() });

    await expect(
      app.updateTable('identity.users').set({ subject: newSubject() }).where('id', '=', id).execute(),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(app.deleteFrom('identity.users').where('id', '=', id).execute()).rejects.toMatchObject({
      code: '42501',
    });
    await expect(sql`truncate identity.users cascade`.execute(app)).rejects.toMatchObject({ code: '42501' });
  });

  it("SEC-DB-14 never lets the app change a person's MAC, or wipe it, once they are added (0108, S207)", async () => {
    const id = await userForSubject(
      app,
      { issuer: ISSUER, subject: newSubject() },
      { ids, clock, keys, logger: testLogger() },
    );

    await expect(
      app
        .updateTable('identity.users')
        .set({ mac: Buffer.alloc(32, 7) })
        .where('id', '=', id)
        .execute(),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      app.updateTable('identity.users').set({ mac_key_version: 2 }).where('id', '=', id).execute(),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      app.updateTable('identity.users').set({ mac: null, mac_key_version: null }).where('id', '=', id).execute(),
    ).rejects.toMatchObject({ code: '42501' });
    expect(await subjectOfUser(app, id, macs)).toBeDefined();
  });
});
