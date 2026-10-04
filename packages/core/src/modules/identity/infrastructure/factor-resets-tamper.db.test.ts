// FX-TAMPER on a factor reset (SEC-DB-10, SEC-OPS-04, B6-3a), as the
// database's owner: agentx_owner, the role the migration job logs in as,
// holding none of the app's keys, working inside one organisation through
// @agentx/testing's tamperAsOwner, as a registered contact is tested
// (registered-contacts-tamper.db.test.ts).
//
// Each change to a reset's status, person, contact, clocks or challenge is
// denied by the row check, with the SEV-1 alarm, and puts the organisation on
// its integrity hold: so a reset can't be pushed on, pointed at someone else,
// or have its cooling-off cut short past the app. The live schema guard, with
// the product's own list, is clean before and after each case, so a leftover
// can't hide a miss.
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
import { resetCoolingOffUntil, resetExpiresAt } from '../domain/factor-reset.ts';
import { contactCountsFrom } from '../domain/registered-contact.ts';
import {
  askContacts,
  confirmReset,
  draftReset,
  FACTOR_RESETS,
  moveReset,
  openResetsFor,
  resetChange,
  resetForChange,
  resetRecord,
} from './factor-resets.ts';
import { addMembership } from './memberships.ts';
import { activateContact, contactChange, contactToActivate, draftContact } from './registered-contacts.ts';
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
const ids = new SequentialIds(0xb63b0);
const clock = new FixedClock(new Date('2026-09-27T09:00:00Z'));

const loggerFor = (destination: LogCapture) => testLogger(destination);

let capture: LogCapture;
let owner: OwnerTamper;
let org: string;
let admin: string;
let adminUser: string;
let person: string;
let contacts: [string, string];

const services = () => ({ keys, ids, logger: loggerFor(capture) });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const API = { type: 'system' as const, id: 'api' };

let subjects = 0;
const newUser = async (name: string): Promise<string> => {
  subjects += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `tamper-resets-${name}-${String(subjects)}` },
    { ids, clock },
  );
};

/** A contact of this test's organisation, made ACTIVE. */
async function activeContact(email: string): Promise<string> {
  const id = ids.next();
  const { change } = contactChange({ orgId: org, id, email, addedBy: admin });
  await withSignedStates(app, org, quiet(), (tx, states) =>
    draftContact(tx, states, keys, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    }),
  );
  await withSignedStates(app, org, quiet(), async (tx, states) => {
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
  return id;
}

/** A reset of this test's organisation, asked for the person, logging to a capture of its own. */
async function reset(forWhom = person): Promise<string> {
  const id = ids.next();
  const { change } = resetChange({
    orgId: org,
    id,
    person: forWhom,
    requestedBy: admin,
    expiresAt: resetExpiresAt(clock.now()),
  });
  await withSignedStates(app, org, quiet(), (tx, states) =>
    draftReset(tx, states, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    }),
  );
  return id;
}

/** Sends it to the contacts, then (when asked) has the first confirm it. */
const onTo = (id: string, { confirmed }: { confirmed: boolean }) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await resetForChange(tx, states, { orgId: org, id });
    if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
    await askContacts(tx, states, keys, {
      orgId: org,
      id,
      contactIds: contacts,
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
      details: {},
    });
    if (!confirmed) return;
    const again = await resetForChange(tx, states, { orgId: org, id });
    if (again.outcome !== 'found') throw new Error(`not found: ${again.outcome}`);
    await confirmReset(tx, states, {
      orgId: org,
      id,
      state: again.state,
      contactId: contacts[0],
      coolingOffUntil: resetCoolingOffUntil(clock.now()),
      details: {},
    });
  });

const read = (id: string) => withSignedStates(app, org, services(), (tx, states) => resetRecord(tx, states, org, id));

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Denied by the row check, with the alarm on the reset, and the organisation held for it. */
async function deniedAndHeld(id: string, sign: TamperSign): Promise<void> {
  expect(await read(id)).toEqual({ outcome: 'tampered', sign });
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      chain: 'organisation',
      reason: sign,
      subjectType: 'factor_reset',
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ orgId: org, reason: sign, subjectType: 'factor_reset' }),
  ]);
}

/** The alarm raised on the reset by a check already made, the organisation held, and a read by ID denied too. */
async function deniedAndHeldAgain(id: string, sign: TamperSign): Promise<void> {
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({ reason: sign, subjectType: 'factor_reset', objectId: id, orgId: org }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  capture = new LogCapture();
  expect(await read(id)).toEqual({ outcome: 'tampered', sign });
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
  person = ids.next();
  adminUser = await newUser('admin');
  const personUser = await newUser('person');
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
    await addMembership(tx, states, {
      orgId: org,
      id: person,
      userId: personUser,
      role: 'approver',
      joinedAt: clock.now(),
      actor: OPERATOR,
    });
  });
  contacts = [await activeContact('finance.office@example.test'), await activeContact('owner@example.test')];
  owner = await tamperAsOwner(database, FACTOR_RESETS, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  expect(await guard()).toEqual([]);
});

describe(`FX-TAMPER as the owner on a factor reset: denied, and held (Postgres ${server.version})`, () => {
  it('a draft pushed on to its cooling-off without a step-up or a contact, a move the status guard allows', async () => {
    const id = await reset();
    await owner.setColumn(id, 'status', 'AWAITING_CONTACT');

    await deniedAndHeld(id, 'seal');
  });

  it('confirmed by no contact: a contact and a cooling-off written in, and moved on', async () => {
    const id = await reset();
    await onTo(id, { confirmed: false });
    // Together, as the table holds them.
    await owner.query(
      "update identity.factor_resets set confirmed_by = $2, cooling_off_until = '2026-09-27T09:00:01Z', status = 'COOLING_OFF' where id = $1",
      [id, contacts[1]],
    );

    await deniedAndHeld(id, 'seal');
  });

  it('its cooling-off cut short, so the factor would be removed before anyone could stop it', async () => {
    const id = await reset();
    await onTo(id, { confirmed: true });
    await owner.setColumn(id, 'cooling_off_until', '2026-09-27T09:00:01Z');

    await deniedAndHeld(id, 'seal');
  });

  it('put down to another contact', async () => {
    const id = await reset();
    await onTo(id, { confirmed: true });
    await owner.setColumn(id, 'confirmed_by', contacts[1]);

    await deniedAndHeld(id, 'seal');
  });

  it('pointed at another person, so their factor would be removed instead', async () => {
    const id = await reset();
    const other = ids.next();
    await withSignedStates(app, org, quiet(), async (tx, states) =>
      addMembership(tx, states, {
        orgId: org,
        id: other,
        userId: await newUser('other'),
        role: 'admin',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    await owner.setColumn(id, 'person', other);

    await deniedAndHeld(id, 'seal');
  });

  it('its lapse moved later, so contacts could confirm it long after', async () => {
    const later = await reset();
    await owner.setColumn(later, 'expires_at', '2027-01-01T00:00:00Z');
    await deniedAndHeld(later, 'seal');
  });

  it('a cancelled reset brought back: its saved, validly signed COOLING_OFF row restored', async () => {
    const id = await reset();
    await onTo(id, { confirmed: true });
    const saved = await owner.saveRow(id);
    await withSignedStates(app, org, quiet(), (tx, states) =>
      moveReset(tx, states, { orgId: org, id, event: 'cancel', actor: API, details: {} }),
    );
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    await deniedAndHeld(id, 'pointer');
  });

  it('planted with no event: a reset the app never made, found too by the person’s open resets', async () => {
    const id = ids.next();
    await owner.query(
      "insert into identity.factor_resets (org_id, id, status, person, requested_by, step_up_challenge_id, expires_at, created_at) values ($1, $2, 'DRAFT', $3, $4, $5, now() + interval '1 day', now())",
      [org, id, person, admin, ids.next()],
    );

    expect(
      await withSignedStates(app, org, services(), (tx, states) => openResetsFor(tx, states, org, person)),
    ).toEqual({ outcome: 'tampered', sign: 'unsigned' });
    capture = new LogCapture();
    expect(await read(id)).toEqual({ outcome: 'tampered', sign: 'unsigned' });
  });

  describe('an open reset hidden from the person’s open resets, so a second could be asked (review)', () => {
    const openFor = () =>
      withSignedStates(app, org, services(), (tx, states) => openResetsFor(tx, states, org, person));

    it('by its status written as CANCELLED', async () => {
      const id = await reset();
      await onTo(id, { confirmed: true });
      await owner.setColumn(id, 'status', 'CANCELLED');

      expect(await openFor()).toEqual({ outcome: 'tampered', sign: 'seal' });
      await deniedAndHeldAgain(id, 'seal');
    });

    it('by its person written as another', async () => {
      const id = await reset();
      const other = ids.next();
      await withSignedStates(app, org, quiet(), async (tx, states) =>
        addMembership(tx, states, {
          orgId: org,
          id: other,
          userId: await newUser('elsewhere'),
          role: 'developer',
          joinedAt: clock.now(),
          actor: OPERATOR,
        }),
      );
      await owner.setColumn(id, 'person', other);

      expect(await openFor()).toEqual({ outcome: 'tampered', sign: 'seal' });
      await deniedAndHeldAgain(id, 'seal');
    });

    it('by its row deleted, which the app role cannot do', async () => {
      const id = await reset();
      await onTo(id, { confirmed: false });
      await owner.query('delete from identity.factor_reset_confirmations where reset_id = $1', [id]);
      await owner.deleteRow(id);

      expect(await openFor()).toEqual({ outcome: 'tampered', sign: 'deleted' });
      await deniedAndHeldAgain(id, 'deleted');
    });
  });

  it('its events stripped of their seals', async () => {
    const id = await reset();
    await owner.stripSeals(id);

    await deniedAndHeld(id, 'unsigned');
  });
});
