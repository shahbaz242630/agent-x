// B6-3a: resets of a lost second factor (0025), on the real migrated schema,
// as the app role. What the owner can do past the app is
// factor-resets-tamper.db.test.ts. B6-3b: a contact's link, as the sender
// reads it.
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { resetCoolingOffUntil, resetExpiresAt } from '../domain/factor-reset.ts';
import { CONTACT_COOLING_OFF_DAYS, contactCountsFrom } from '../domain/registered-contact.ts';
import {
  askContacts,
  confirmationMatches,
  confirmationSecret,
  ConfirmationUnreadable,
  confirmReset,
  draftReset,
  moveReset,
  openResetsFor,
  resetChange,
  resetForChange,
  resetLinkFor,
  resetRecord,
  ResetNotChanged,
  ResetsTampered,
} from './factor-resets.ts';
import { addMembership } from './memberships.ts';
import {
  activateContact,
  contactChange,
  contactToActivate,
  draftContact,
  removeContact,
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
const ids = new SequentialIds(0xb63a_0000_0000);
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
const API = { type: 'system' as const, id: 'api' };
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');
const EVIDENCE = { stepUpChallengeId: '0199a0f0-0000-7000-8000-00000000c0de', methods: 'pwd,user,mfa' };

interface Who {
  readonly org: string;
  readonly admin: string;
  readonly adminUser: string;
  /** A developer whose second factor is lost. */
  readonly person: string;
  /** Two ACTIVE contacts. */
  readonly contacts: readonly [string, string];
}

let subjects = 0;
const newUser = async (name: string): Promise<string> => {
  subjects += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `resets-${name}-${String(subjects)}` },
    { ids, clock },
  );
};

/** A contact made ACTIVE by the admin, as B6-1c does once stepped up. */
async function activeContact(org: string, admin: string, adminUser: string, email: string): Promise<string> {
  const id = ids.next();
  const { change } = contactChange({ orgId: org, id, email, addedBy: admin });
  await withSignedStates(app, org, services(), async (tx, states) => {
    await draftContact(tx, states, keys, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    });
  });
  await withSignedStates(app, org, services(), async (tx, states) => {
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

/** A new organisation with an admin, a developer and two ACTIVE contacts. */
async function organization(): Promise<Who> {
  const org = ids.next();
  const adminUser = await newUser('admin');
  const personUser = await newUser('person');
  const admin = ids.next();
  const person = ids.next();
  await withSignedStates(app, org, services(), async (tx, states) => {
    await createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR });
    for (const [id, userId, role] of [
      [admin, adminUser, 'admin'],
      [person, personUser, 'developer'],
    ] as const) {
      await addMembership(tx, states, { orgId: org, id, userId, role, joinedAt: clock.now(), actor: OPERATOR });
    }
  });
  const contacts = [
    await activeContact(org, admin, adminUser, 'finance.office@example.test'),
    await activeContact(org, admin, adminUser, 'owner@example.test'),
  ] as const;
  // Past their cooling-off, so they count (B6-3b-3: a contact that doesn't is sent no link).
  clock.advanceBy(CONTACT_COOLING_OFF_DAYS * 86_400_000);
  return { org, admin, adminUser, person, contacts };
}

/** Asks for a reset as the admin, a DRAFT, with the challenge's ID given. */
async function draft({ org, admin, adminUser, person }: Who, { inside = org, forWhom = person } = {}) {
  const id = ids.next();
  const stepUpChallengeId = ids.next();
  const { change, changeHash } = resetChange({
    orgId: org,
    id,
    person: forWhom,
    requestedBy: admin,
    expiresAt: resetExpiresAt(clock.now()),
  });
  const recorded = await withSignedStates(app, inside, services(), (tx, states) =>
    draftReset(tx, states, change, {
      stepUpChallengeId,
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    }),
  );
  return { id, stepUpChallengeId, change, changeHash, recorded };
}

const record = (org: string, id: string) =>
  withSignedStates(app, org, services(), (tx, states) => resetRecord(tx, states, org, id));

/** Sends the draft to the contacts named, as B6-3b does once the admin's step-up is consumed. */
const ask = (who: Who, id: string, contactIds: readonly string[] = who.contacts) =>
  withSignedStates(app, who.org, services(), async (tx, states) => {
    const read = await resetForChange(tx, states, { orgId: who.org, id });
    if (read.outcome !== 'found') return read;
    await askContacts(tx, states, keys, {
      orgId: who.org,
      id,
      contactIds,
      createdAt: clock.now(),
      actor: { type: 'user', id: who.adminUser },
      details: EVIDENCE,
    });
    return { outcome: 'asked' as const };
  });

const secretOf = (org: string, resetId: string, contactId: string) =>
  withTenant(app, org, (tx) => confirmationSecret(tx, keys, { orgId: org, resetId, contactId }));

const matches = (org: string, resetId: string, contactId: string, secret: string) =>
  withTenant(app, org, (tx) => confirmationMatches(tx, keys, { orgId: org, resetId, contactId, secret }));

/** A contact confirms the reset, as B6-3b does once its link matched. */
const confirm = (who: Who, id: string, contactId: string) =>
  withSignedStates(app, who.org, services(), async (tx, states) => {
    const read = await resetForChange(tx, states, { orgId: who.org, id });
    if (read.outcome !== 'found') return read;
    await confirmReset(tx, states, {
      orgId: who.org,
      id,
      state: read.state,
      contactId,
      coolingOffUntil: resetCoolingOffUntil(clock.now()),
      details: {},
    });
    return { outcome: 'confirmed' as const };
  });

const move = (who: Who, id: string, event: 'cancel' | 'expire' | 'complete') =>
  withSignedStates(app, who.org, services(), (tx, states) =>
    moveReset(tx, states, { orgId: who.org, id, event, actor: API, details: {} }),
  );

const ORIGIN = 'https://app.example.test';

/** The contact's link, as the sender reads it at `now`. */
const linkOf = (who: Who, id: string, contactId: string, now = clock.now()) =>
  resetLinkFor(app, services(), { publicOrigin: ORIGIN, clock: { now: () => now } }, who.org, id, contactId);

const openFor = (who: Who, person = who.person) =>
  withSignedStates(app, who.org, services(), (tx, states) => openResetsFor(tx, states, who.org, person));

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

describe(`asking for a reset (B6-3a, Postgres ${server.version})`, () => {
  it('keeps it as a DRAFT naming the person, the admin, the challenge and its lapse, signed', async () => {
    const who = await organization();

    const { id, stepUpChallengeId, recorded } = await draft(who);

    expect(await record(who.org, id)).toEqual({
      outcome: 'found',
      reset: {
        id,
        status: 'DRAFT',
        person: who.person,
        requestedBy: who.admin,
        stepUpChallengeId,
        expiresAt: resetExpiresAt(clock.now()),
        confirmedBy: null,
        coolingOffUntil: null,
      },
    });
    const [event] = await eventsFrom(who.org, recorded.seq);
    expect(event).toMatchObject({
      actor_id: who.adminUser,
      action: 'factor_reset.drafted',
      subject_type: 'factor_reset',
      subject_id: id,
      subject_version: 1,
    });
    expect(alarms()).toEqual([]);
  });

  it('gives the same change and hash back, whatever case its ID is given in', async () => {
    const who = await organization();
    const { id, change, changeHash } = await draft(who);

    const read = await withSignedStates(app, who.org, services(), (tx, states) =>
      resetForChange(tx, states, { orgId: who.org, id: id.toUpperCase() }),
    );

    expect(read).toMatchObject({ outcome: 'found', reset: { id, status: 'DRAFT' } });
    if (read.outcome !== 'found') throw new Error('not found');
    expect(read.change).toEqual({ ...change, id: id.toUpperCase() });
    expect(read.changeHash.equals(changeHash)).toBe(true);
  });

  it('binds the hash to every fact of the change', () => {
    const base = {
      orgId: ids.next(),
      id: ids.next(),
      person: ids.next(),
      requestedBy: ids.next(),
      expiresAt: resetExpiresAt(clock.now()),
    };
    const hash = resetChange(base).changeHash;
    for (const changed of [
      { ...base, orgId: ids.next() },
      { ...base, id: ids.next() },
      { ...base, person: ids.next() },
      { ...base, requestedBy: ids.next() },
      { ...base, expiresAt: new Date(base.expiresAt.getTime() + 1) },
    ]) {
      expect(resetChange(changed).changeHash.equals(hash)).toBe(false);
    }
    expect(resetChange({ ...base, id: base.id.toUpperCase() }).changeHash.equals(hash)).toBe(true);
  });

  it('refuses a reset asked for by the person it is for, in the module and in the table', async () => {
    const who = await organization();

    expect(() =>
      resetChange({
        orgId: who.org,
        id: ids.next(),
        person: who.admin,
        requestedBy: who.admin.toUpperCase(),
        expiresAt: resetExpiresAt(clock.now()),
      }),
    ).toThrow(RangeError);
    await expect(
      withTenant(app, who.org, (tx) =>
        tx
          .insertInto('identity.factor_resets')
          .values({
            org_id: who.org,
            id: ids.next(),
            status: 'DRAFT',
            person: who.admin,
            requested_by: who.admin,
            step_up_challenge_id: ids.next(),
            expires_at: resetExpiresAt(clock.now()),
            confirmed_by: null,
            cooling_off_until: null,
            created_at: clock.now(),
          })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'no_one_resets_their_own' });
  });

  it('refuses a person who is a membership of another organisation, by the key to the memberships', async () => {
    const who = await organization();
    const elsewhere = await organization();

    await expect(draft(who, { forWhom: elsewhere.person })).rejects.toMatchObject({
      code: '23503',
      constraint: 'for_a_member',
    });
  });

  it("refuses a transaction that isn't withTenant's for the organisation, and isn't found from another", async () => {
    const who = await organization();
    const other = await organization();

    await expect(draft(who, { inside: other.org })).rejects.toMatchObject({ code: '42501' });
    const { id } = await draft(who);
    expect(await record(other.org, id)).toEqual({ outcome: 'missing' });
  });

  it('finds the person’s open resets only, each verified, for an ask to refuse or let lapse first', async () => {
    const who = await organization();
    const { id } = await draft(who);

    expect(await openFor(who)).toMatchObject({ outcome: 'found', resets: [{ id, status: 'DRAFT' }] });
    expect(await openFor(who, who.admin)).toEqual({ outcome: 'found', resets: [] });

    await move(who, id, 'expire');
    expect(await openFor(who)).toEqual({ outcome: 'found', resets: [] });
    const next = await draft(who);
    await ask(who, next.id);
    expect(await openFor(who)).toMatchObject({
      outcome: 'found',
      resets: [{ id: next.id, status: 'AWAITING_CONTACT' }],
    });
  });

  it("won't let the app change when it was asked, or delete it (its signed fields are the seal's: the tamper tests)", async () => {
    const who = await organization();
    const { id } = await draft(who);

    await expect(
      withTenant(app, who.org, (tx) =>
        tx.updateTable('identity.factor_resets').set({ created_at: clock.now() }).where('id', '=', id).execute(),
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      withTenant(app, who.org, (tx) => tx.deleteFrom('identity.factor_resets').where('id', '=', id).execute()),
    ).rejects.toMatchObject({ code: '42501' });
  });
});

describe(`sending it to the contacts (B6-3a, Postgres ${server.version})`, () => {
  it('writes one secret for each contact, encrypted, and moves it on with the step-up’s evidence', async () => {
    const who = await organization();
    const { id } = await draft(who);

    expect(await ask(who, id)).toEqual({ outcome: 'asked' });

    expect(await record(who.org, id)).toMatchObject({ outcome: 'found', reset: { status: 'AWAITING_CONTACT' } });
    const [first, second] = who.contacts;
    const secrets = [await secretOf(who.org, id, first), await secretOf(who.org, id, second)];
    for (const secret of secrets) expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(secrets[0]).not.toBe(secrets[1]);
    const rows = await withTenant(app, who.org, (tx) =>
      tx.selectFrom('identity.factor_reset_confirmations').selectAll().orderBy('contact_id').execute(),
    );
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.secret_key_version).toBe(1);
      for (const secret of secrets) expect(row.secret_ciphertext.toString('latin1')).not.toContain(secret);
    }
    const events = await eventsFrom(who.org, 1n);
    expect(events.at(-1)).toMatchObject({ action: 'factor_reset.sent_to_contacts', subject_id: id });
    expect(JSON.parse(events.at(-1)?.details ?? '{}')).toMatchObject({ ...EVIDENCE, contacts: 2 });
  });

  it('refuses no contacts, and a draft sent twice', async () => {
    const who = await organization();
    const { id } = await draft(who);

    await expect(ask(who, id, [])).rejects.toBeInstanceOf(RangeError);
    await ask(who, id);
    await expect(ask(who, id)).rejects.toMatchObject({ code: '23505' });
  });

  it('refuses one no longer a draft, writing no secret for it', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await move(who, id, 'cancel');

    await expect(ask(who, id)).rejects.toBeInstanceOf(ResetNotChanged);
    expect(await secretOf(who.org, id, who.contacts[0])).toBeUndefined();
    expect(await record(who.org, id)).toMatchObject({ reset: { status: 'CANCELLED' } });
  });

  it('matches a link’s secret only for its own reset and contact', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await ask(who, id, [who.contacts[0]]);
    const secret = (await secretOf(who.org, id, who.contacts[0])) ?? '';

    expect(await matches(who.org, id, who.contacts[0], secret)).toBe('matches');
    expect(await matches(who.org, id.toUpperCase(), who.contacts[0].toUpperCase(), secret)).toBe('matches');
    const changed = `${secret.slice(0, -1)}${secret.endsWith('A') ? 'B' : 'A'}`;
    expect(await matches(who.org, id, who.contacts[0], changed)).toBe('wrong');
    expect(await matches(who.org, id, who.contacts[0], secret.slice(0, -1))).toBe('wrong');
    expect(await matches(who.org, id, who.contacts[1], secret)).toBe('no_link');
    expect(await secretOf(who.org, ids.next(), who.contacts[0])).toBeUndefined();
  });

  it('won’t open a secret copied into another contact’s row', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await ask(who, id, [who.contacts[0]]);
    await withTenant(app, who.org, async (tx) => {
      const row = await tx
        .selectFrom('identity.factor_reset_confirmations')
        .selectAll()
        .where('contact_id', '=', who.contacts[0])
        .executeTakeFirstOrThrow();
      await tx
        .insertInto('identity.factor_reset_confirmations')
        .values({ ...row, contact_id: who.contacts[1] })
        .execute();
    });

    await expect(secretOf(who.org, id, who.contacts[1])).rejects.toBeInstanceOf(ConfirmationUnreadable);
    await expect(matches(who.org, id, who.contacts[1], 'anything')).rejects.toBeInstanceOf(ConfirmationUnreadable);
  });

  it("won't let the app change or delete a secret", async () => {
    const who = await organization();
    const { id } = await draft(who);
    await ask(who, id);

    await expect(
      withTenant(app, who.org, (tx) =>
        tx.updateTable('identity.factor_reset_confirmations').set({ secret_key_version: 2 }).execute(),
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      withTenant(app, who.org, (tx) => tx.deleteFrom('identity.factor_reset_confirmations').execute()),
    ).rejects.toMatchObject({ code: '42501' });
  });
});

describe(`a contact confirming it, and its end (B6-3a, Postgres ${server.version})`, () => {
  it('names the contact and sets the cooling-off with the move, on the record', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await ask(who, id);

    expect(await confirm(who, id, who.contacts[1])).toEqual({ outcome: 'confirmed' });

    expect(await record(who.org, id)).toMatchObject({
      outcome: 'found',
      reset: {
        status: 'COOLING_OFF',
        confirmedBy: who.contacts[1],
        coolingOffUntil: resetCoolingOffUntil(clock.now()),
      },
    });
    const events = (await eventsFrom(who.org, 1n)).filter(({ subject_id }) => subject_id === id);
    expect(
      events.slice(-2).map(({ actor_id, action, details }) => [actor_id, action, JSON.parse(details) as unknown]),
    ).toEqual([
      ['api', 'factor_reset.cooling_off_set', expect.objectContaining({ contact: who.contacts[1] })],
      ['api', 'factor_reset.confirmed', expect.objectContaining({ contact: who.contacts[1], statusTo: 'COOLING_OFF' })],
    ]);
    expect(alarms()).toEqual([]);
  });

  it('refuses a confirmation of a draft, or of one confirmed already, changing nothing', async () => {
    const who = await organization();
    const { id } = await draft(who);

    await expect(confirm(who, id, who.contacts[0])).rejects.toBeInstanceOf(ResetNotChanged);
    expect(await record(who.org, id)).toMatchObject({ reset: { status: 'DRAFT', confirmedBy: null } });
    await ask(who, id);
    await confirm(who, id, who.contacts[0]);
    // The cooling-off may be written again by the module's own record, but the move is refused, so it all rolls back.
    await expect(confirm(who, id, who.contacts[1])).rejects.toBeInstanceOf(ResetNotChanged);
    expect(await record(who.org, id)).toMatchObject({ reset: { confirmedBy: who.contacts[0] } });
  });

  it('holds the contact and its cooling-off together in the table, and the contact to the organisation’s', async () => {
    const who = await organization();
    const other = await organization();
    const { id } = await draft(who);

    await expect(
      withTenant(app, who.org, (tx) =>
        tx
          .updateTable('identity.factor_resets')
          .set({ cooling_off_until: resetCoolingOffUntil(clock.now()) })
          .where('id', '=', id)
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'confirmed_with_its_cooling_off' });
    await expect(
      withTenant(app, who.org, (tx) =>
        tx
          .updateTable('identity.factor_resets')
          .set({ confirmed_by: other.contacts[0], cooling_off_until: resetCoolingOffUntil(clock.now()) })
          .where('id', '=', id)
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23503', constraint: 'confirmed_by_a_contact' });
  });

  it('cancels from any open status, completes only after a contact confirmed, lapses only before', async () => {
    const who = await organization();
    const drafted = await draft(who);
    await move(who, drafted.id, 'cancel');
    expect(await record(who.org, drafted.id)).toMatchObject({ reset: { status: 'CANCELLED' } });

    const cooling = await draft(who);
    await ask(who, cooling.id);
    await expect(move(who, cooling.id, 'complete')).rejects.toBeInstanceOf(ResetNotChanged);
    await confirm(who, cooling.id, who.contacts[0]);
    await expect(move(who, cooling.id, 'expire')).rejects.toBeInstanceOf(ResetNotChanged);
    await move(who, cooling.id, 'complete');
    expect(await record(who.org, cooling.id)).toMatchObject({ reset: { status: 'COMPLETED' } });
    await expect(move(who, cooling.id, 'cancel')).rejects.toBeInstanceOf(ResetNotChanged);

    const events = await eventsFrom(who.org, 1n);
    expect(events.filter(({ action }) => action === 'factor_reset.cancelled')).toHaveLength(1);
    expect(events.filter(({ action }) => action === 'factor_reset.completed')).toHaveLength(1);
    expect(alarms()).toEqual([]);
  });
});

describe(`a contact's link, as the sender reads it (B6-3b, Postgres ${server.version})`, () => {
  it('is the confirm page with the organisation, reset, contact and secret after #token=, and the lapse', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await ask(who, id);
    const [first] = who.contacts;
    const secret = await secretOf(who.org, id, first);

    const link = await linkOf({ ...who, org: who.org.toUpperCase() }, id.toUpperCase(), first.toUpperCase());

    expect(link).toEqual({
      url: `${ORIGIN}/factor-resets/confirm#token=${who.org}.${id}.${first}.${secret ?? 'none'}`,
      expiresAt: resetExpiresAt(clock.now()),
    });
    const other = await linkOf(who, id, who.contacts[1]);
    expect(other?.url.startsWith(`${ORIGIN}/factor-resets/confirm#token=${who.org}.${id}.${who.contacts[1]}.`)).toBe(
      true,
    );
    expect(other?.url).not.toContain(secret ?? 'none');
    expect(alarms()).toEqual([]);
  });

  it('is none for a draft, a contact not asked, a reset confirmed or cancelled, or one lapsed', async () => {
    const who = await organization();
    const drafted = await draft(who);
    expect(await linkOf(who, drafted.id, who.contacts[0])).toBeUndefined();
    expect(await linkOf(who, ids.next(), who.contacts[0])).toBeUndefined();

    const asked = await draft(who);
    await ask(who, asked.id, [who.contacts[0]]);
    expect(await linkOf(who, asked.id, who.contacts[1])).toBeUndefined();
    const lapse = resetExpiresAt(clock.now());
    expect(await linkOf(who, asked.id, who.contacts[0], new Date(lapse.getTime() - 1))).toBeDefined();
    expect(await linkOf(who, asked.id, who.contacts[0], lapse)).toBeUndefined();

    // A contact removed since it was asked is sent no link (review of B6-3b-1).
    await withSignedStates(app, who.org, services(), (tx, states) =>
      removeContact(tx, states, { orgId: who.org, id: who.contacts[1], actor: OPERATOR, details: {} }),
    );
    const both = await draft(who);
    await ask(who, both.id);
    expect(await linkOf(who, both.id, who.contacts[1])).toBeUndefined();
    expect(await linkOf(who, both.id, who.contacts[0])).toBeDefined();

    await confirm(who, asked.id, who.contacts[0]);
    expect(await linkOf(who, asked.id, who.contacts[0])).toBeUndefined();

    const cancelled = await draft(who);
    await ask(who, cancelled.id);
    await move(who, cancelled.id, 'cancel');
    expect(await linkOf(who, cancelled.id, who.contacts[0])).toBeUndefined();
  });

  it('throws for a reset that fails its check, raising the alarm, and sends no link', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await ask(who, id);
    await withTenant(app, who.org, (tx) =>
      tx
        .updateTable('identity.factor_resets')
        .set({ expires_at: new Date(clock.now().getTime() + 1_000 * 86_400_000) })
        .where('id', '=', id)
        .execute(),
    );

    await expect(linkOf(who, id, who.contacts[0])).rejects.toBeInstanceOf(ResetsTampered);
    expect(alarms()).not.toEqual([]);
  });
});
