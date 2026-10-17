// Decision 25, E10d-4: people who signed in before Agent X kept their names
// get a kept copy from the login service, a hundred a call; one already kept,
// another issuer's, or one the login service no longer has is left as it is;
// a login service that fails ends the run, logged without a name.
import { randomUUID } from 'node:crypto';

import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider } from '@agentx/platform/keys';
import { createTestDatabase, FixedClock, LogCapture, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createContactFill } from './contact-fill.ts';
import { type DirectoryEntry, type DirectoryNames, DirectoryUnavailable, MOST_A_CALL } from './directory-names.ts';
import type { IdentityTables } from './tables.ts';
import { keepUserContact, keptPeopleOf } from './user-contacts.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<IdentityTables>;

const ISSUER = 'https://auth.example.test';
const AT = new Date('2026-10-17T09:00:00Z');
const keys = createKeyProvider({ 'field-encryption': { current: 1, versions: new Map([[1, Buffer.alloc(32, 9)]]) } }, [
  'field-encryption',
]);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<IdentityTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

let subjects = 0;

/** A person who signed in at this issuer, by a subject of their own. */
const aPerson = async (issuer = ISSUER) => {
  subjects += 1;
  const id = randomUUID();
  const subject = String(900_000 + subjects);
  await app.insertInto('identity.users').values({ id, issuer, subject, created_at: AT }).execute();
  return { id, subject };
};

/** A login service that names everyone it is asked about but `gone`, counting its calls. */
const directoryNaming = (gone: ReadonlySet<string> = new Set()) => {
  const asked: string[][] = [];
  const directory: DirectoryNames = {
    issuer: ISSUER,
    entriesOf: (asking) => {
      asked.push([...asking]);
      return Promise.resolve(
        new Map<string, DirectoryEntry>(
          asking
            .filter((subject) => !gone.has(subject))
            .map((subject) => [subject, { name: `Person ${subject}`, email: `p${subject}@example.test` }]),
        ),
      );
    },
  };
  return { directory, asked };
};

describe('filling kept names from the login service (decision 25)', () => {
  it('keeps a copy for each person without one, a hundred a call, leaving the rest as they are', async () => {
    const people = await Promise.all(Array.from({ length: MOST_A_CALL + 1 }, () => aPerson()));
    const kept = await aPerson();
    await keepUserContact(app, keys, kept.id, { name: 'Kept already', verifiedEmail: undefined }, AT);
    const elsewhere = await aPerson('https://other.example.test');
    const gone = await aPerson();
    const { directory, asked } = directoryNaming(new Set([gone.subject]));
    const capture = new LogCapture();

    await createContactFill({ db: app, keys, directory, clock: new FixedClock(AT), logger: testLogger(capture) }).run();

    const found = await keptPeopleOf(
      app,
      keys,
      [...people, kept, elsewhere, gone].map((person) => person.id),
    );
    for (const person of people) {
      expect(found.get(person.id)).toMatchObject({
        name: `Person ${person.subject}`,
        email: `p${person.subject}@example.test`,
      });
    }
    expect(found.get(kept.id)).toMatchObject({ name: 'Kept already', email: undefined });
    expect(found.get(elsewhere.id)).toMatchObject({ name: undefined, email: undefined });
    expect(found.get(gone.id)).toMatchObject({ name: undefined, email: undefined });
    expect(asked.every((call) => call.length <= MOST_A_CALL)).toBe(true);
    expect(asked.flat()).not.toContain(kept.subject);
    expect(asked.flat()).not.toContain(elsewhere.subject);
    const [done] = capture.lines().filter((line) => line.event === 'identity.contact_fill_done');
    expect(done?.kept).toBeGreaterThanOrEqual(MOST_A_CALL + 1);

    // The next run asks only about the one the login service no longer has.
    const again = directoryNaming(new Set([gone.subject]));
    await createContactFill({
      db: app,
      keys,
      directory: again.directory,
      clock: new FixedClock(AT),
      logger: testLogger(),
    }).run();
    expect(again.asked).toEqual([[gone.subject]]);
  });

  it('never changes a copy a sign-in kept meanwhile, counting only those it added', async () => {
    const signedIn = await aPerson();
    const { directory } = directoryNaming();
    // The sign-in keeps its newer name while the fill is asking the login service.
    const racing: DirectoryNames = {
      issuer: ISSUER,
      entriesOf: async (asking) => {
        await keepUserContact(app, keys, signedIn.id, { name: 'Newer name', verifiedEmail: undefined }, AT);
        // Earlier tests' people left without a copy are named by no one here, so the count is this person's alone.
        return directory.entriesOf(asking.filter((subject) => subject === signedIn.subject));
      },
    };
    const capture = new LogCapture();

    await createContactFill({
      db: app,
      keys,
      directory: racing,
      clock: new FixedClock(AT),
      logger: testLogger(capture),
    }).run();

    expect((await keptPeopleOf(app, keys, [signedIn.id])).get(signedIn.id)).toMatchObject({
      name: 'Newer name',
      email: undefined,
    });
    const [done] = capture.lines().filter((line) => line.event === 'identity.contact_fill_done');
    expect(done).toMatchObject({ kept: 0 });
  });

  it('ends the run when the login service fails, logging how many were kept and never a name', async () => {
    const person = await aPerson();
    const capture = new LogCapture();
    const directory: DirectoryNames = {
      issuer: ISSUER,
      entriesOf: () => Promise.reject(new DirectoryUnavailable('the call failed')),
    };

    await createContactFill({ db: app, keys, directory, clock: new FixedClock(AT), logger: testLogger(capture) }).run();

    expect((await keptPeopleOf(app, keys, [person.id])).get(person.id)).toMatchObject({ name: undefined });
    expect(capture.lines()).toEqual([expect.objectContaining({ event: 'identity.contact_fill_failed', kept: 0 })]);
  });

  it('does nothing once stopped', async () => {
    const person = await aPerson();
    const { directory, asked } = directoryNaming();
    const stopped = new AbortController();
    stopped.abort();

    await createContactFill({ db: app, keys, directory, clock: new FixedClock(AT), logger: testLogger() }).run(
      stopped.signal,
    );

    expect(asked).toEqual([]);
    expect((await keptPeopleOf(app, keys, [person.id])).get(person.id)).toMatchObject({ name: undefined });
  });
});
