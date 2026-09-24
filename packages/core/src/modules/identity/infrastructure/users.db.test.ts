// B2-1: the people who sign in (0010), on the real migrated schema, as the app role.
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createLogger } from '@agentx/platform/observability';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { SignInRefused } from '../domain/sign-in.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const ISSUER = 'https://auth.example.test';
const clock = new FixedClock(new Date('2026-09-24T09:00:00Z'));
const ids = new SequentialIds(0x100);
let subjects = 0;
/** A subject no other test has used. */
const newSubject = (): string => {
  subjects += 1;
  return `3387194723948${String(subjects).padStart(5, '0')}`;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>(
    { ...database.connection('app'), maxConnections: 4 },
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

describe(`the people who sign in (Postgres ${server.version})`, () => {
  it('makes a user at their first sign-in and finds the same one at every one after', async () => {
    const subject = newSubject();
    const first = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock });
    const again = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock });

    expect(again).toBe(first);
    expect(await app.selectFrom('identity.users').selectAll().where('subject', '=', subject).execute()).toEqual([
      { id: first, issuer: ISSUER, subject, created_at: clock.now() },
    ]);
  });

  it('keeps one subject from two issuers apart, and a subject in another case', async () => {
    const subject = `user-${newSubject()}`;
    const here = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock });
    const there = await userForSubject(app, { issuer: 'https://other.example.test', subject }, { ids, clock });
    const upper = await userForSubject(app, { issuer: ISSUER, subject: subject.toUpperCase() }, { ids, clock });

    expect(new Set([here, there, upper]).size).toBe(3);
  });

  it('makes one user when two first sign-ins come at once', async () => {
    const subject = newSubject();
    const found = await Promise.all(
      Array.from({ length: 4 }, () => userForSubject(app, { issuer: ISSUER, subject }, { ids, clock })),
    );

    expect(new Set(found).size).toBe(1);
    expect(await app.selectFrom('identity.users').select('id').where('subject', '=', subject).execute()).toHaveLength(
      1,
    );
  });

  it('refuses a subject it could not store, before any statement', async () => {
    await expect(userForSubject(app, { issuer: ISSUER, subject: '' }, { ids, clock })).rejects.toBeInstanceOf(
      SignInRefused,
    );
    await expect(userForSubject(app, { issuer: '', subject: newSubject() }, { ids, clock })).rejects.toBeInstanceOf(
      SignInRefused,
    );
  });

  it('never lets the app change or delete a user', async () => {
    const subject = newSubject();
    const id = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock });

    await expect(
      app.updateTable('identity.users').set({ subject: newSubject() }).where('id', '=', id).execute(),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(app.deleteFrom('identity.users').where('id', '=', id).execute()).rejects.toMatchObject({
      code: '42501',
    });
    await expect(sql`truncate identity.users cascade`.execute(app)).rejects.toMatchObject({ code: '42501' });
  });
});
