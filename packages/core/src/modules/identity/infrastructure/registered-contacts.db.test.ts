// B6-1a: registered contacts (0022), on the real migrated schema, as the app
// role. What the owner can do past the app is registered-contacts-tamper.db.test.ts.
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { contactCountsFrom } from '../domain/registered-contact.ts';
import { addMembership } from './memberships.ts';
import {
  activateContact,
  activeContactsFor,
  contactAddressFor,
  ContactNotChanged,
  contactChange,
  contactRecord,
  contactsOf,
  contactToActivate,
  contactToRemove,
  draftContact,
  MOST_CONTACT_RECORDS,
  REGISTERED_CONTACTS,
  removeContact,
  TooManyContacts,
} from './registered-contacts.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
// Each ID has a hex letter in it, so looking one up in upper case is another string.
const ids = new SequentialIds(0xc6a0_0000_0000);
const clock = new FixedClock(new Date('2026-09-27T09:00:00Z'));

let capture: LogCapture;
const services = () => ({
  keys,
  ids,
  logger: createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  }),
});

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');
const EVIDENCE = { stepUpChallengeId: '0199a0f0-0000-7000-8000-00000000c0de', methods: 'pwd,user,mfa' };

interface Who {
  readonly org: string;
  readonly admin: string;
  readonly adminUser: string;
}

let subjects = 0;
/** A new organisation with an admin in it, as the operator's command and B4-6 make them. */
async function organization(): Promise<Who> {
  const org = ids.next();
  subjects += 1;
  const adminUser = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `contacts-admin-${String(subjects)}` },
    { ids, clock },
  );
  const admin = ids.next();
  await withSignedStates(app, org, services(), async (tx, states) => {
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
  return { org, admin, adminUser };
}

/** Asks for a contact as the admin, a DRAFT, with the challenge's ID given. */
async function draft(
  { org, admin, adminUser }: Who,
  { email = 'Finance.Office@Example.test', inside = org, addedBy = admin } = {},
) {
  const id = ids.next();
  const stepUpChallengeId = ids.next();
  const { change, changeHash } = contactChange({ orgId: org, id, email, addedBy });
  const recorded = await withSignedStates(app, inside, services(), (tx, states) =>
    draftContact(tx, states, keys, change, {
      stepUpChallengeId,
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    }),
  );
  return { id, stepUpChallengeId, change, changeHash, recorded };
}

const record = (org: string, id: string) =>
  withSignedStates(app, org, services(), (tx, states) => contactRecord(tx, states, org, id));

const toActivate = (org: string, id: string) =>
  withSignedStates(app, org, services(), (tx, states) => contactToActivate(tx, states, keys, { orgId: org, id }));

/** Reads the draft for the change and activates it, as the confirm route does once the step-up is consumed. */
const activate = (who: Who, id: string) =>
  withSignedStates(app, who.org, services(), async (tx, states) => {
    const read = await contactToActivate(tx, states, keys, { orgId: who.org, id });
    if (read.outcome !== 'draft') return read;
    await activateContact(tx, states, {
      orgId: who.org,
      id,
      state: read.state,
      countsFrom: contactCountsFrom(clock.now()),
      actor: { type: 'user', id: who.adminUser },
      details: EVIDENCE,
    });
    return { outcome: 'activated' as const };
  });

const toRemove = (org: string, id: string) =>
  withSignedStates(app, org, services(), (tx, states) => contactToRemove(tx, states, { orgId: org, id }));

/** Reads the contact for the change and removes it, as the confirm route does once the step-up is consumed. */
const remove = (who: Who, id: string) =>
  withSignedStates(app, who.org, services(), async (tx, states) => {
    const read = await contactToRemove(tx, states, { orgId: who.org, id });
    if (read.outcome !== 'active') return read;
    await removeContact(tx, states, {
      orgId: who.org,
      id,
      actor: { type: 'user', id: who.adminUser },
      details: EVIDENCE,
    });
    return { outcome: 'removed' as const };
  });

const list = (org: string) => withSignedStates(app, org, services(), (tx, states) => contactsOf(tx, states, keys, org));

/** The organisation's audit events from `seq` on, as the chain holds them. */
const eventsFrom = (org: string, seq: bigint) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['seq', 'actor_id', 'action', 'subject_type', 'subject_id', 'subject_version', 'details'])
      .where('seq', '>=', seq)
      .orderBy('seq')
      .execute(),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(
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

beforeEach(() => {
  capture = new LogCapture();
});

describe(`asking for a contact (B6-1a, Postgres ${server.version})`, () => {
  it('keeps it as a DRAFT with the admin and the challenge, no start, signed, the address encrypted', async () => {
    const who = await organization();

    const { id, stepUpChallengeId, recorded } = await draft(who);

    expect(recorded).toMatchObject({ version: 1, seq: 4n });
    expect(await record(who.org, id)).toEqual({
      outcome: 'found',
      contact: { id, status: 'DRAFT', addedBy: who.admin, countsFrom: null, stepUpChallengeId },
    });
    const row = await withTenant(app, who.org, (tx) =>
      tx.selectFrom('identity.registered_contacts').selectAll().executeTakeFirstOrThrow(),
    );
    expect(row).toMatchObject({
      org_id: who.org,
      id,
      status: 'DRAFT',
      added_by: who.admin,
      counts_from: null,
      step_up_challenge_id: stepUpChallengeId,
      created_at: clock.now(),
      email_key_version: 1,
      state_version: 1,
      state_event_id: recorded.eventId.toLowerCase(),
    });
    // Encrypted: nothing of the address is in the row, in either case.
    expect(row.email_ciphertext.toString('latin1').toLowerCase()).not.toContain('finance');
    expect(row.email_ciphertext.length).toBe(12 + 16 + 'finance.office@example.test'.length);
    const [event] = await eventsFrom(who.org, 4n);
    expect(event).toMatchObject({
      actor_id: who.adminUser,
      action: 'registered_contact.drafted',
      subject_type: 'registered_contact',
      subject_id: id,
      subject_version: 1,
    });
    expect(event?.details.toLowerCase()).not.toContain('finance');
    expect(alarms()).toEqual([]);
  });

  it('gives the same change and hash back for the draft as it was asked with, the address in lower case', async () => {
    const who = await organization();
    const { id, change, changeHash } = await draft(who);

    const read = await toActivate(who.org, id);

    expect(change.email).toBe('finance.office@example.test');
    expect(read).toMatchObject({ outcome: 'draft', change, contact: { id, status: 'DRAFT' } });
    if (read.outcome !== 'draft') throw new Error('not a draft');
    expect(read.changeHash.equals(changeHash)).toBe(true);
  });

  it('finds the draft whatever case its ID is given in', async () => {
    const who = await organization();
    const { id, changeHash } = await draft(who);

    expect(await record(who.org, id.toUpperCase())).toMatchObject({ outcome: 'found', contact: { id } });
    const read = await toActivate(who.org, id.toUpperCase());
    expect(read).toMatchObject({ outcome: 'draft', contact: { id } });
    if (read.outcome !== 'draft') throw new Error('not a draft');
    expect(read.changeHash.equals(changeHash)).toBe(true);
  });

  it('refuses an admin who is a membership of another organisation, by the key to the memberships', async () => {
    const who = await organization();
    const elsewhere = await organization();

    await expect(draft(who, { addedBy: elsewhere.admin })).rejects.toMatchObject({
      code: '23503',
      constraint: 'added_by_a_member',
    });
  });

  it("refuses a transaction that isn't withTenant's for the organisation", async () => {
    const who = await organization();
    const other = await organization();

    // The tenant policy refuses the row before any signed state is written.
    await expect(draft(who, { inside: other.org })).rejects.toMatchObject({ code: '42501' });
  });

  it('is not found from another organisation', async () => {
    const who = await organization();
    const other = await organization();
    const { id } = await draft(who);

    expect(await record(other.org, id)).toEqual({ outcome: 'missing' });
    expect(await toActivate(other.org, id)).toEqual({ outcome: 'missing' });
    expect(await toRemove(other.org, id)).toEqual({ outcome: 'missing' });
    expect(await list(other.org)).toEqual({ outcome: 'listed', contacts: [] });
  });

  it("won't let the app change the address, or delete the contact", async () => {
    const who = await organization();
    const { id } = await draft(who);

    await expect(
      withTenant(app, who.org, (tx) =>
        tx
          .updateTable('identity.registered_contacts')
          .set({ email_ciphertext: Buffer.alloc(40) })
          .where('id', '=', id)
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      withTenant(app, who.org, (tx) => tx.deleteFrom('identity.registered_contacts').where('id', '=', id).execute()),
    ).rejects.toMatchObject({ code: '42501' });
  });
});

describe(`the table's own checks, past the module (B6-1a, Postgres ${server.version})`, () => {
  /** Writes a row past the module, in a transaction rolled back if nothing refuses it. */
  const written = (who: Who, changes: Record<string, unknown>) =>
    withTenant(app, who.org, async (tx) => {
      await tx
        .insertInto('identity.registered_contacts')
        .values({
          org_id: who.org,
          id: ids.next(),
          status: 'DRAFT',
          added_by: who.admin,
          counts_from: null,
          step_up_challenge_id: ids.next(),
          created_at: clock.now(),
          email_ciphertext: Buffer.alloc(29),
          email_key_version: 1,
          ...changes,
        })
        .execute();
      throw new Error('rolled back');
    });

  it('takes a row within every check, so each refusal below is its own', async () => {
    const who = await organization();

    await expect(written(who, {})).rejects.toThrow('rolled back');
    // A DRAFT may hold its start for the moment before it moves, as activating writes it.
    await expect(written(who, { counts_from: contactCountsFrom(clock.now()) })).rejects.toThrow('rolled back');
  });

  it.each([
    ['a status that isn’t one', { status: 'PAUSED' }, 'status_guard'],
    [
      'a new row ACTIVE',
      { status: 'ACTIVE', counts_from: contactCountsFrom(new Date('2026-09-27T09:00:00Z')) },
      'status_guard',
    ],
    [
      'a start no later than when it was added',
      { counts_from: new Date('2026-09-27T09:00:00Z') },
      'counts_after_it_was_added',
    ],
    [
      'an address too short to be sealed',
      { email_ciphertext: Buffer.alloc(28) },
      'registered_contacts_email_ciphertext_check',
    ],
    ['an address too long', { email_ciphertext: Buffer.alloc(1025) }, 'registered_contacts_email_ciphertext_check'],
    ['a key version below 1', { email_key_version: 0 }, 'registered_contacts_email_key_version_check'],
  ])('refuses %s', async (_what, changes, constraint) => {
    const who = await organization();

    await expect(written(who, changes)).rejects.toMatchObject({ code: '23514', constraint });
  });

  it('keeps an address of up to 1,024 sealed bytes', async () => {
    const who = await organization();

    await expect(written(who, { email_ciphertext: Buffer.alloc(1024) })).rejects.toThrow('rolled back');
  });

  it('the backup role reads it, as a logical backup must', async () => {
    const who = await organization();
    const { id } = await draft(who);

    expect(
      await database.as('backup').query('select id from identity.registered_contacts where id = $1', [id]),
    ).toEqual([{ id }]);
  });
});

describe(`activating a contact (B6-1a, Postgres ${server.version})`, () => {
  it('sets its start 7 days on, moves it to ACTIVE and signs the step-up’s evidence on the move', async () => {
    const who = await organization();
    const { id, stepUpChallengeId } = await draft(who);

    expect(await activate(who, id)).toEqual({ outcome: 'activated' });

    expect(await record(who.org, id)).toEqual({
      outcome: 'found',
      contact: {
        id,
        status: 'ACTIVE',
        addedBy: who.admin,
        countsFrom: new Date('2026-10-04T09:00:00Z'),
        stepUpChallengeId,
      },
    });
    const events = await eventsFrom(who.org, 5n);
    expect(events).toMatchObject([
      { action: 'registered_contact.counts_from_set', subject_id: id, subject_version: 2, actor_id: who.adminUser },
      { action: 'registered_contact.activated', subject_id: id, subject_version: 3, actor_id: who.adminUser },
    ]);
    expect(JSON.parse(events[1]?.details ?? '{}')).toMatchObject({
      ...EVIDENCE,
      statusFrom: 'DRAFT',
      statusTo: 'ACTIVE',
    });
    expect(alarms()).toEqual([]);
  });

  it('reads an active contact as no longer a draft, and activates it only once', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await activate(who, id);

    expect(await toActivate(who.org, id)).toEqual({ outcome: 'not_draft' });
    expect(await activate(who, id)).toEqual({ outcome: 'not_draft' });
  });

  it('activates nothing for a contact that doesn’t exist', async () => {
    const who = await organization();

    expect(await activate(who, ids.next())).toEqual({ outcome: 'missing' });
  });

  it('refuses to activate one removed since it was read, rolling its start back', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await activate(who, id);
    await remove(who, id);

    // Past the read: activating a REMOVED contact is not a move its machine has.
    const failed = withSignedStates(app, who.org, services(), async (tx, states) => {
      const state = await states.verifiedState(tx, REGISTERED_CONTACTS, { orgId: who.org, id }, 'change');
      if (state.outcome !== 'verified') throw new Error('not verified');
      await activateContact(tx, states, {
        orgId: who.org,
        id,
        state,
        countsFrom: new Date('2030-01-01T00:00:00Z'),
        actor: { type: 'user', id: who.adminUser },
        details: {},
      });
    });

    await expect(failed).rejects.toBeInstanceOf(ContactNotChanged);
    expect(await record(who.org, id)).toMatchObject({
      contact: { status: 'REMOVED', countsFrom: new Date('2026-10-04T09:00:00Z') },
    });
  });
});

describe(`removing a contact (B6-1a, Postgres ${server.version})`, () => {
  it('reads an ACTIVE contact for removal with a hash of its own, and moves it to REMOVED with the evidence', async () => {
    const who = await organization();
    const first = await draft(who);
    const second = await draft(who, { email: 'owner@example.test' });
    await activate(who, first.id);
    await activate(who, second.id);

    const read = await toRemove(who.org, first.id);
    const again = await toRemove(who.org, first.id);
    const other = await toRemove(who.org, second.id);
    if (read.outcome !== 'active' || again.outcome !== 'active' || other.outcome !== 'active') {
      throw new Error('not active');
    }
    expect(read.changeHash).toHaveLength(32);
    expect(read.changeHash.equals(again.changeHash)).toBe(true);
    expect(read.changeHash.equals(other.changeHash)).toBe(false);
    // Not the hash that added it, which a removal's step-up could otherwise be taken for.
    expect(read.changeHash.equals(first.changeHash)).toBe(false);

    expect(await remove(who, first.id)).toEqual({ outcome: 'removed' });

    expect(await record(who.org, first.id)).toMatchObject({ contact: { status: 'REMOVED' } });
    const [event] = (await eventsFrom(who.org, 1n)).filter((each) => each.action === 'registered_contact.removed');
    expect(event).toMatchObject({ subject_id: first.id, subject_version: 4, actor_id: who.adminUser });
    expect(JSON.parse(event?.details ?? '{}')).toMatchObject({
      ...EVIDENCE,
      statusFrom: 'ACTIVE',
      statusTo: 'REMOVED',
    });
  });

  it('removes only an ACTIVE contact: not a draft, and not one removed already', async () => {
    const who = await organization();
    const { id } = await draft(who);

    expect(await toRemove(who.org, id)).toEqual({ outcome: 'not_active' });
    await activate(who, id);
    await remove(who, id);
    expect(await remove(who, id)).toEqual({ outcome: 'not_active' });
    expect(await toRemove(who.org, ids.next())).toEqual({ outcome: 'missing' });
  });

  it('refuses to remove a draft past the read, changing nothing', async () => {
    const who = await organization();
    const { id } = await draft(who);

    await expect(
      withSignedStates(app, who.org, services(), (tx, states) =>
        removeContact(tx, states, { orgId: who.org, id, actor: { type: 'user', id: who.adminUser }, details: {} }),
      ),
    ).rejects.toMatchObject({ name: 'ContactNotChanged', outcome: 'refused' });
    expect(await record(who.org, id)).toMatchObject({ contact: { status: 'DRAFT' } });
  });
});

describe(`the organisation's contacts (B6-1a, Postgres ${server.version})`, () => {
  it('lists every contact, drafts and removed ones too, in order of ID, each with its address', async () => {
    const who = await organization();
    const first = await draft(who, { email: 'Finance.Office@Example.test' });
    const second = await draft(who, { email: 'owner@example.test' });
    const third = await draft(who, { email: 'ceo@example.test' });
    await activate(who, second.id);
    await activate(who, third.id);
    await remove(who, third.id);

    expect(await list(who.org)).toEqual({
      outcome: 'listed',
      contacts: [
        expect.objectContaining({
          id: first.id,
          status: 'DRAFT',
          email: 'finance.office@example.test',
          countsFrom: null,
        }),
        expect.objectContaining({
          id: second.id,
          status: 'ACTIVE',
          email: 'owner@example.test',
          countsFrom: new Date('2026-10-04T09:00:00Z'),
        }),
        expect.objectContaining({ id: third.id, status: 'REMOVED', email: 'ceo@example.test' }),
      ],
    });
    expect(alarms()).toEqual([]);
  });

  it('B6-1b gives the ACTIVE contacts to tell, counted or not yet, and each one’s address, a removed one’s too', async () => {
    const who = await organization();
    const drafted = await draft(who, { email: 'Finance.Office@Example.test' });
    const active = await draft(who, { email: 'owner@example.test' });
    const removed = await draft(who, { email: 'ceo@example.test' });
    await activate(who, active.id);
    await activate(who, removed.id);
    await remove(who, removed.id);

    expect(await activeContactsFor(app, services(), who.org)).toEqual([active.id]);
    expect(await contactAddressFor(app, services(), who.org, active.id)).toBe('owner@example.test');
    expect(await contactAddressFor(app, services(), who.org, removed.id.toUpperCase())).toBe('ceo@example.test');
    // A draft is never told, and a contact not in the organisation has no address here.
    expect(await contactAddressFor(app, services(), who.org, drafted.id)).toBeUndefined();
    expect(await contactAddressFor(app, services(), (await organization()).org, active.id)).toBeUndefined();
    expect(await activeContactsFor(app, services(), (await organization()).org)).toEqual([]);
    expect(alarms()).toEqual([]);
  });

  it(`reads up to ${String(MOST_CONTACT_RECORDS)} contacts, and refuses to read more rather than cut the list short`, async () => {
    const who = await organization();
    await withSignedStates(app, who.org, services(), async (tx, states) => {
      for (let each = 0; each < MOST_CONTACT_RECORDS; each += 1) {
        const { change } = contactChange({
          orgId: who.org,
          id: ids.next(),
          email: `contact-${String(each)}@example.test`,
          addedBy: who.admin,
        });
        await draftContact(tx, states, keys, change, {
          stepUpChallengeId: ids.next(),
          createdAt: clock.now(),
          actor: { type: 'user', id: who.adminUser },
        });
      }
    });

    const listed = await list(who.org);
    expect(listed.outcome === 'listed' ? listed.contacts.length : 0).toBe(MOST_CONTACT_RECORDS);

    await draft(who);
    await expect(list(who.org)).rejects.toBeInstanceOf(TooManyContacts);
  });
});
