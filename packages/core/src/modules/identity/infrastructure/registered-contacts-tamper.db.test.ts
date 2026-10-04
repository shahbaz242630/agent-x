// FX-TAMPER on a registered contact (SEC-DB-10, SEC-OPS-06, B6-1a), as the
// database's owner: agentx_owner, the role the migration job logs in as,
// holding none of the app's keys, working inside one organisation through
// @agentx/testing's tamperAsOwner, as an invitation is tested
// (invitations-tamper.db.test.ts).
//
// Each change to a contact's status, admin, start or challenge is denied by
// the row check, with the SEV-1 alarm, and puts the organisation on its
// integrity hold; so is a contact deleted to keep it from being told, found
// by the list's check of every contact the log knows of. The encrypted
// address, which isn't signed, opens only in its own row as it was written.
// The live schema guard, with the product's own list, is clean before and
// after each case, so a leftover can't hide a miss.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { createDatabase, type Database, liveSchemaProblems } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { type AuditTables, type TamperSign, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { contactCountsFrom } from '../domain/registered-contact.ts';
import { addMembership } from './memberships.ts';
import {
  activateContact,
  activeContactsFor,
  contactAddressFor,
  ContactsTampered,
  registeredContactsFor,
  contactChange,
  contactRecord,
  contactsOf,
  contactToActivate,
  ContactUnreadable,
  draftContact,
  REGISTERED_CONTACTS,
} from './registered-contacts.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xc6b00);
const clock = new FixedClock(new Date('2026-09-27T09:00:00Z'));

const loggerFor = (destination: LogCapture) => testLogger(destination);

let capture: LogCapture;
let owner: OwnerTamper;
let org: string;
let admin: string;
let adminUser: string;

const services = () => ({ keys, ids, logger: loggerFor(capture) });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let subjects = 0;

/** A contact asked for in this test's organisation, logging to a capture of its own. */
async function contact(email = 'finance.office@example.test', inside = org, addedBy = admin): Promise<string> {
  const id = ids.next();
  const { change } = contactChange({ orgId: inside, id, email, addedBy });
  await withSignedStates(app, inside, quiet(), (tx, states) =>
    draftContact(tx, states, keys, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    }),
  );
  return id;
}

/** Activates a draft of this test's organisation, logging to a capture of its own. */
const activate = (id: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await contactToActivate(tx, states, keys, { orgId: org, id });
    if (read.outcome !== 'draft') throw new Error(`not a draft: ${read.outcome}`);
    await activateContact(tx, states, {
      orgId: org,
      id,
      state: read.state,
      countsFrom: contactCountsFrom(clock.now()),
      actor: { type: 'user', id: adminUser },
      details: {},
    });
  });

const read = (id: string) => withSignedStates(app, org, services(), (tx, states) => contactRecord(tx, states, org, id));

const list = () => withSignedStates(app, org, services(), (tx, states) => contactsOf(tx, states, keys, org));

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The alarm raised on the contact, and the organisation held for it. */
async function alarmedAndHeld(id: string, sign: TamperSign): Promise<void> {
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      chain: 'organisation',
      reason: sign,
      subjectType: 'registered_contact',
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ orgId: org, reason: sign, subjectType: 'registered_contact' }),
  ]);
}

/** Denied by the row check, and by the list, with the alarm on the contact, and the organisation held for it. */
async function deniedAndHeld(id: string, sign: TamperSign): Promise<void> {
  expect(await read(id)).toEqual({ outcome: 'tampered', sign });
  await alarmedAndHeld(id, sign);
  capture = new LogCapture();
  expect(await list()).toEqual({ outcome: 'tampered', sign });
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  admin = ids.next();
  subjects += 1;
  adminUser = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `tamper-contacts-${String(subjects)}` },
    { ids, clock },
  );
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    await createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR });
    await addMembership(tx, states, {
      orgId: org,
      id: admin,
      userId: adminUser,
      role: 'admin',
      joinedAt: clock.now(),
      actor: OPERATOR,
    });
  });
  owner = await tamperAsOwner(database, REGISTERED_CONTACTS, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  expect(await guard()).toEqual([]);
});

describe(`FX-TAMPER as the owner on a registered contact: denied, and held (Postgres ${server.version})`, () => {
  it('a draft made ACTIVE without its step-up, with a start, a move the status guard allows', async () => {
    const id = await contact();
    await owner.setColumn(id, 'counts_from', '2026-09-28T00:00:00Z');
    await owner.setColumn(id, 'status', 'ACTIVE');

    await deniedAndHeld(id, 'seal');
  });

  it('a new contact made to count at once, its cooling-off cut short', async () => {
    const id = await contact();
    await activate(id);
    await owner.setColumn(id, 'counts_from', '2026-09-27T09:00:01Z');

    await deniedAndHeld(id, 'seal');
  });

  it('put down to another admin', async () => {
    const id = await contact();
    const other = ids.next();
    await withSignedStates(app, org, quiet(), async (tx, states) =>
      addMembership(tx, states, {
        orgId: org,
        id: other,
        userId: await userForSubject(
          app,
          { issuer: 'https://auth.example.test', subject: `tamper-contacts-other-${String(subjects)}` },
          { ids, clock },
        ),
        role: 'admin',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    await owner.setColumn(id, 'added_by', other);

    await deniedAndHeld(id, 'seal');
  });

  it('pointed at another step-up challenge', async () => {
    const id = await contact();
    await owner.setColumn(id, 'step_up_challenge_id', ids.next());

    await deniedAndHeld(id, 'seal');
  });

  it('a removed contact brought back: its saved, validly signed ACTIVE row restored', async () => {
    const id = await contact();
    await activate(id);
    const saved = await owner.saveRow(id);
    await withSignedStates(app, org, quiet(), (tx, states) =>
      states.changeStatus(tx, REGISTERED_CONTACTS, { orgId: org, id }, 'remove', {
        actor: { type: 'user', id: adminUser },
        action: 'registered_contact.removed',
        details: {},
      }),
    );
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    await deniedAndHeld(id, 'pointer');
  });

  it('planted with no event: a contact the app never made', async () => {
    const id = ids.next();
    await owner.query(
      "insert into identity.registered_contacts (org_id, id, status, added_by, counts_from, step_up_challenge_id, created_at, email_ciphertext, email_key_version) values ($1, $2, 'DRAFT', $3, null, $4, now(), $5, 1)",
      [org, id, admin, ids.next(), Buffer.alloc(40)],
    );

    await deniedAndHeld(id, 'unsigned');
  });

  it('its events stripped of their seals', async () => {
    const id = await contact();
    await owner.stripSeals(id);

    await deniedAndHeld(id, 'unsigned');
  });

  it('deleted, which the app role cannot do, to keep it from being told: the list is refused', async () => {
    await contact('kept@example.test');
    const id = await contact();
    await activate(id);
    await owner.deleteRow(id);

    expect(await list()).toEqual({ outcome: 'tampered', sign: 'deleted' });
    await alarmedAndHeld(id, 'deleted');
    capture = new LogCapture();
    expect(await read(id)).toEqual({ outcome: 'tampered', sign: 'deleted' });
    // B6-1b: so a notice to the contacts waits, naming nobody, rather than skip the one deleted.
    await expect(activeContactsFor(app, services(), org)).rejects.toBeInstanceOf(ContactsTampered);
    // B6-1c: the admins' list is withheld, with the request's correlation ID on the alarm.
    capture = new LogCapture();
    expect(await registeredContactsFor(app, services(), org, 'correlation-2')).toEqual({
      outcome: 'tampered',
      sign: 'deleted',
    });
    expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ correlationId: 'correlation-2' })]);
  });

  it('B6-1b a contact’s start moved: its address is not given, and a notice to it waits', async () => {
    const id = await contact();
    await activate(id);
    await owner.setColumn(id, 'counts_from', '2026-09-27T09:00:01Z');

    await expect(contactAddressFor(app, services(), org, id)).rejects.toBeInstanceOf(ContactsTampered);
    await alarmedAndHeld(id, 'seal');
    await expect(activeContactsFor(app, services(), org)).rejects.toBeInstanceOf(ContactsTampered);
  });
});

describe(`FX-TAMPER as the owner on a contact's address: it won't open (Postgres ${server.version})`, () => {
  it('another contact’s address copied into it', async () => {
    const id = await contact('finance.office@example.test');
    const other = await contact('mallory@example.test');
    await owner.query(
      'update identity.registered_contacts set email_ciphertext = (select email_ciphertext from identity.registered_contacts where id = $2) where id = $1',
      [id, other],
    );

    await expect(
      withSignedStates(app, org, services(), (tx, states) => contactToActivate(tx, states, keys, { orgId: org, id })),
    ).rejects.toBeInstanceOf(ContactUnreadable);
    await expect(list()).rejects.toBeInstanceOf(ContactUnreadable);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('another organisation’s address copied into a contact of the same ID', async () => {
    const id = await contact('finance.office@example.test');
    const elsewhere = ids.next();
    const elsewhereAdmin = ids.next();
    await withSignedStates(app, elsewhere, quiet(), async (tx, states) => {
      await createOrganization(tx, states, { id: elsewhere, name: 'Other Trading LLC', actor: OPERATOR });
      await addMembership(tx, states, {
        orgId: elsewhere,
        id: elsewhereAdmin,
        userId: adminUser,
        role: 'admin',
        joinedAt: clock.now(),
        actor: OPERATOR,
      });
      const { change } = contactChange({
        orgId: elsewhere,
        id,
        email: 'mallory@example.test',
        addedBy: elsewhereAdmin,
      });
      await draftContact(tx, states, keys, change, {
        stepUpChallengeId: ids.next(),
        createdAt: clock.now(),
        actor: { type: 'user', id: adminUser },
      });
    });
    // The owner works inside this test's organisation, so the other's value is read as the backup role reads it.
    const [copied] = await database
      .as('backup')
      .query('select email_ciphertext from identity.registered_contacts where org_id = $1 and id = $2', [
        elsewhere,
        id,
      ]);
    await owner.query('update identity.registered_contacts set email_ciphertext = $1 where id = $2', [
      (copied as { email_ciphertext: Buffer }).email_ciphertext,
      id,
    ]);

    await expect(list()).rejects.toBeInstanceOf(ContactUnreadable);
  });
});
