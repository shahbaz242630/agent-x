// B6-1c: adding and removing registered contacts through the use case the
// API's routes call, on the real migrated schema, as the app role: the
// idempotency store, the step-up challenge, the contact and its notices in
// one transaction each (SEC-OPS-06). The routes' answers are apps/api's
// registered-contacts.test.ts; the contact's own table is
// registered-contacts.db.test.ts.
import { createHash } from 'node:crypto';

import { createDatabase, type Database, type IdempotentRequest, lockName, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  holdNamedLock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import { MOST_CONTACTS, MOST_CONTACTS_STARTED_A_DAY } from '../domain/registered-contact.ts';
import { type ContactChanges, type ContactChangeWrite, createContactChanges } from './contact-changes.ts';
import type { InvitingAdmin } from './inviting.ts';
import { addMembership, MEMBERSHIPS } from './memberships.ts';
import { contactChange, draftContact, MOST_CONTACT_RECORDS, REGISTERED_CONTACTS } from './registered-contacts.ts';
import { createSessions } from './sessions.ts';
import { createStepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables & NotificationsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xc6c0_0000_0000);
const START = new Date('2026-09-27T09:00:00Z');
let clock: FixedClock;
let changes: ContactChanges;
let capture: LogCapture;
const challenges = () => createStepUpChallenges({ ids, clock });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';
const EMAIL = 'Finance.Office@Example.test';

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let people = 0;

/** A person with a session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<InvitingAdmin & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `contact-changes-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
}

/** The same person signed in again, with a new session: after the clock has moved past the old one. */
async function signedInAgain<T extends InvitingAdmin>(who: T): Promise<T> {
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, who.userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
  });
  return { ...who, sessionId };
}

async function organization(): Promise<{ org: string; admin: InvitingAdmin & { membershipId: string } }> {
  const org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return { org, admin: await member(org, 'admin') };
}

const keyed = (admin: InvitingAdmin, operation: string, key: string, payload = '{}'): IdempotentRequest => ({
  orgId: admin.orgId,
  client: { kind: 'user', id: admin.userId },
  operation,
  key,
  payload,
});

const add = (admin: InvitingAdmin, email = EMAIL, key = `add-${email}`) =>
  changes.add(admin, keyed(admin, 'contacts.add', key, email), email, CORRELATION);

const confirm = (admin: InvitingAdmin, id: string, key = `confirm-${id}`) =>
  changes.confirm(admin, keyed(admin, 'contacts.add.confirm', key, id), id, CORRELATION);

const remove = (admin: InvitingAdmin, id: string, key = `remove-${id}`) =>
  changes.remove(admin, keyed(admin, 'contacts.remove', key, id), id, CORRELATION);

const removeConfirm = (admin: InvitingAdmin, id: string, challengeId: string, key = `remove-confirm-${id}`) =>
  changes.removeConfirm(
    admin,
    keyed(admin, 'contacts.remove.confirm', key, `${id} ${challengeId}`),
    id,
    challengeId,
    CORRELATION,
  );

/** The admin signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (admin: InvitingAdmin, challengeId: string, amr: readonly string[] = ['pwd', 'user', 'mfa']) =>
  challenges().recordEvidence(app, challengeId, admin.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const written = (write: ContactChangeWrite) => {
  if (write.outcome !== 'written') throw new Error(`not written: ${JSON.stringify(write)}`);
  return write;
};

/** Adds a contact and confirms it with a passkey's step-up: its ID. */
async function added(admin: InvitingAdmin, email = EMAIL): Promise<string> {
  const asked = written(await add(admin, email));
  await stepUp(admin, asked.stepUpChallengeId ?? '');
  written(await confirm(admin, asked.contact.id));
  return asked.contact.id;
}

/** Drafts `count` contacts straight into the organisation's table, two days before START: records, not started today. */
async function oldDrafts(org: string, admin: InvitingAdmin & { membershipId: string }, count: number): Promise<void> {
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, async (tx, states) => {
    for (let each = 0; each < count; each += 1) {
      const { change } = contactChange({
        orgId: org,
        id: ids.next(),
        email: `old-${String(each)}@example.test`,
        addedBy: admin.membershipId,
      });
      await draftContact(tx, states, keys, change, {
        stepUpChallengeId: ids.next(),
        createdAt: new Date(START.getTime() - 2 * DAY_MS),
        actor: { type: 'user', id: admin.userId },
      });
    }
  });
}

/** How many contact records the organisation holds. */
const recordsOf = async (org: string) =>
  (await withTenant(app, org, (tx) => tx.selectFrom('identity.registered_contacts').select('id').execute())).length;

/** The notices the organisation's outbox holds, in the order written. */
const noticesOf = (org: string) =>
  app
    .selectFrom('notifications.outbox')
    .select(['recipient_user_id', 'recipient_contact_id', 'to_contacts', 'kind', 'about_id'])
    .where('org_id', '=', org)
    .orderBy('created_at')
    .orderBy('id')
    .execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(START);
  capture = new LogCapture();
  changes = createContactChanges({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    outbox: createOutbox({ ids, clock }),
    logger: loggerFor(capture),
  });
});

describe(`adding a registered contact (B6-1c, Postgres ${server.version})`, () => {
  it('keeps a DRAFT, and opens a challenge for the admin’s session, bound to the contact’s change', async () => {
    const { org, admin } = await organization();

    const asked = written(await add(admin));

    expect(asked).toMatchObject({
      status: 202,
      contact: { status: 'DRAFT', email: 'finance.office@example.test', countsFrom: null },
    });
    const pending = await challenges().pending(app, asked.stepUpChallengeId ?? '', admin.sessionId);
    const { changeHash } = contactChange({
      orgId: org,
      id: asked.contact.id,
      email: EMAIL,
      addedBy: admin.membershipId,
    });
    expect(pending).toMatchObject({ userId: admin.userId, action: 'contacts.add' });
    expect(pending?.changeHash.equals(changeHash)).toBe(true);
    expect(await noticesOf(org)).toEqual([]);
    // A retry with the same key answers the same draft.
    expect(await add(admin)).toEqual(asked);
  });

  it('SEC-OPS-06 makes it ACTIVE once stepped up with a passkey, counting 7 days on, and tells the admins and the contacts', async () => {
    const { org, admin } = await organization();
    const asked = written(await add(admin));
    await stepUp(admin, asked.stepUpChallengeId ?? '');

    const confirmed = written(await confirm(admin, asked.contact.id));

    expect(confirmed).toMatchObject({
      status: 200,
      contact: { id: asked.contact.id, status: 'ACTIVE', countsFrom: new Date('2026-10-04T09:00:00Z') },
    });
    expect(confirmed.stepUpChallengeId).toBeUndefined();
    expect(await noticesOf(org)).toEqual([
      {
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: false,
        kind: 'contact_added',
        about_id: asked.contact.id,
      },
      {
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: true,
        kind: 'contact_added',
        about_id: asked.contact.id,
      },
    ]);
    const [activated] = await withTenant(app, org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['details'])
        .where('subject_id', '=', asked.contact.id)
        .where('action', '=', 'registered_contact.activated')
        .execute(),
    );
    expect(JSON.parse(activated?.details ?? '{}')).toMatchObject({ stepUpChallengeId: asked.stepUpChallengeId });
    // A retry answers the contact as it stands, and tells no one again.
    expect(await confirm(admin, asked.contact.id)).toEqual(confirmed);
    expect(await noticesOf(org)).toHaveLength(2);
  });

  it('refuses to confirm without the step-up, or with an app code rather than a passkey (SEC-HA-12), changing nothing', async () => {
    const { org, admin } = await organization();
    const asked = written(await add(admin));

    expect(await confirm(admin, asked.contact.id, 'no-step-up')).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    await stepUp(admin, asked.stepUpChallengeId ?? '', ['pwd', 'otp', 'mfa']);
    expect(await confirm(admin, asked.contact.id, 'app-code')).toMatchObject({ code: 'STEP_UP_FAILED' });
    expect(await noticesOf(org)).toEqual([]);
  });

  it('refuses another admin’s confirmation: the step-up is bound to the session that asked', async () => {
    const { org, admin } = await organization();
    const other = await member(org, 'admin');
    const asked = written(await add(admin));
    await stepUp(admin, asked.stepUpChallengeId ?? '');

    expect(await confirm(other, asked.contact.id)).toMatchObject({ code: 'STEP_UP_FAILED' });
  });

  it('refuses an address one of its ACTIVE contacts has, in any case, at the ask and at the confirmation', async () => {
    const { admin } = await organization();
    const second = written(await add(admin, 'FINANCE.office@example.test', 'before'));
    await added(admin);

    expect(await add(admin, 'finance.OFFICE@example.test', 'after')).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'CONTACT_EXISTS',
    });
    await stepUp(admin, second.stepUpChallengeId ?? '');
    expect(await confirm(admin, second.contact.id)).toMatchObject({ code: 'CONTACT_EXISTS' });
  });

  it(`refuses a contact past ${String(MOST_CONTACTS)} ACTIVE ones, at the ask and at the confirmation, and takes one once another is removed`, async () => {
    const { admin } = await organization();
    const late = written(await add(admin, 'late@example.test'));
    const first = await added(admin, 'contact-0@example.test');
    for (let each = 1; each < MOST_CONTACTS; each += 1) await added(admin, `contact-${String(each)}@example.test`);

    expect(await add(admin, 'one-more@example.test')).toMatchObject({ code: 'CONTACTS_FULL' });
    await stepUp(admin, late.stepUpChallengeId ?? '');
    expect(await confirm(admin, late.contact.id)).toMatchObject({ code: 'CONTACTS_FULL' });

    const asked = await remove(admin, first);
    if (asked.outcome !== 'asked') throw new Error('not asked');
    await stepUp(admin, asked.stepUpChallengeId);
    written(await removeConfirm(admin, first, asked.stepUpChallengeId));
    expect(await confirm(admin, late.contact.id, 'once-there-is-room')).toMatchObject({
      outcome: 'written',
      contact: { status: 'ACTIVE' },
    });
  });

  it('refuses to confirm a contact confirmed already, or one not in the organisation', async () => {
    const { org, admin } = await organization();
    const id = await added(admin);
    const elsewhere = await organization();

    expect(await confirm(admin, id, 'again')).toEqual({ outcome: 'refused', status: 409, code: 'CONTACT_CLOSED' });
    expect(await confirm(elsewhere.admin, id)).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect(await noticesOf(org)).toHaveLength(2);
  });

  it('refuses anyone but an active admin, re-read inside the write', async () => {
    const { org } = await organization();
    const approver = await member(org, 'approver');

    expect(await add(approver)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
  });

  it('answers 503 INTEGRITY_FAILED, not a refusal of the admin, when their membership can’t be believed', async () => {
    const { org, admin } = await organization();
    const owner = await tamperAsOwner(database, MEMBERSHIPS, org);
    try {
      await owner.setColumn(admin.membershipId, 'joined_at', '2020-01-01T00:00:00Z');
    } finally {
      await owner.end();
    }

    expect(await add(admin)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('answers 503 INTEGRITY_FAILED when a contact can’t be believed: one deleted is never room made', async () => {
    const { org, admin } = await organization();
    const id = await added(admin);
    const owner = await tamperAsOwner(database, REGISTERED_CONTACTS, org);
    try {
      await owner.deleteRow(id);
    } finally {
      await owner.end();
    }

    expect(await add(admin, 'owner@example.test')).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });

  it('confirms only once it holds the organisation’s contact changes’ lock, so two can’t both take the last place', async () => {
    const { org, admin } = await organization();
    const asked = written(await add(admin));
    await stepUp(admin, asked.stepUpChallengeId ?? '');
    // Another change of the organisation's contacts, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('registered-contacts', org));
      const confirming = within(20_000, confirm(admin, asked.contact.id), 'the confirmation');
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(await confirming).toMatchObject({ outcome: 'written', contact: { status: 'ACTIVE' } });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe(`the confirmation's lock order against the admin's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('holds the admin’s step-up challenges before their membership, so a demotion at the same moment waits, never deadlocks', async () => {
    const { org, admin } = await organization();
    const asked = written(await add(admin));
    const challengeId = asked.stepUpChallengeId ?? '';
    await stepUp(admin, challengeId);
    const confirmed = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: admin.membershipId },
      () => confirm(admin, asked.contact.id),
    );

    expect(confirmed).toMatchObject({ outcome: 'written', contact: { status: 'ACTIVE' } });
  });

  it('a removal’s confirmation holds the admin’s step-up challenges before their membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const { org, admin } = await organization();
    const id = await added(admin);
    const asked = await remove(admin, id);
    if (asked.outcome !== 'asked') throw new Error('not asked');
    await stepUp(admin, asked.stepUpChallengeId);
    const removed = await confirmedWhileDemoted(
      database,
      { challengeId: asked.stepUpChallengeId, orgId: org, membershipId: admin.membershipId },
      () => removeConfirm(admin, id, asked.stepUpChallengeId),
    );

    expect(removed).toMatchObject({ outcome: 'written', contact: { status: 'REMOVED' } });
  });
});

describe(`the organisation's budget of contacts started (B8-2, Postgres ${server.version})`, () => {
  it(`refuses a contact started past ${String(MOST_CONTACTS_STARTED_A_DAY)} in 24 hours, a confirmed one among them, writing nothing, and starts one once 24 hours have passed`, async () => {
    const { org, admin } = await organization();
    await added(admin, 'confirmed@example.test');
    for (let each = 1; each < MOST_CONTACTS_STARTED_A_DAY; each += 1)
      written(await add(admin, `draft-${String(each)}@example.test`));

    expect(await add(admin, 'one-more@example.test')).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'CONTACT_ADDS_SPENT',
    });
    expect(await recordsOf(org)).toBe(MOST_CONTACTS_STARTED_A_DAY);

    clock.advanceBy(DAY_MS - 1);
    const almost = await signedInAgain(admin);
    expect(await add(almost, 'one-more@example.test', 'almost-a-day')).toMatchObject({ code: 'CONTACT_ADDS_SPENT' });
    clock.advanceBy(1);
    const aDayOn = await signedInAgain(admin);
    expect(await add(aDayOn, 'one-more@example.test', 'a-day-on')).toMatchObject({
      outcome: 'written',
      contact: { status: 'DRAFT' },
    });
  });

  it('counts only contacts started in the last 24 hours, not the records held from before', async () => {
    const { org, admin } = await organization();
    await oldDrafts(org, admin, MOST_CONTACTS_STARTED_A_DAY);

    expect(await add(admin)).toMatchObject({ outcome: 'written', contact: { status: 'DRAFT' } });
  });

  it(`warns once the organisation's records reach half of the ${String(MOST_CONTACT_RECORDS)} the list reads`, async () => {
    const { org, admin } = await organization();
    await oldDrafts(org, admin, MOST_CONTACT_RECORDS / 2 - 1);
    written(await add(admin, 'below-half@example.test'));
    expect(capture.lines().filter((line) => line.event === 'identity.records_filling')).toEqual([]);

    written(await add(admin, 'at-half@example.test'));
    expect(capture.lines().filter((line) => line.event === 'identity.records_filling')).toEqual([
      expect.objectContaining({
        level: 'warn',
        records: 'registered_contacts',
        held: MOST_CONTACT_RECORDS / 2,
        most: MOST_CONTACT_RECORDS,
        correlationId: CORRELATION,
      }),
    ]);
  });

  it(`answers 409 TOO_MANY_CONTACTS, not a failure, past the ${String(MOST_CONTACT_RECORDS)} records the list reads`, async () => {
    const { org, admin } = await organization();
    await oldDrafts(org, admin, MOST_CONTACT_RECORDS + 1);

    expect(await add(admin)).toEqual({ outcome: 'refused', status: 409, code: 'TOO_MANY_CONTACTS' });
  });

  it('starts a contact only once it holds the organisation’s contact changes’ lock, so two can’t both take the last one', async () => {
    const { org, admin } = await organization();
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('registered-contacts', org));
      const adding = within(20_000, add(admin), 'the add');
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(await adding).toMatchObject({ outcome: 'written', contact: { status: 'DRAFT' } });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe(`removing a registered contact (B6-1c, Postgres ${server.version})`, () => {
  it('SEC-OPS-06 removes it once stepped up, and tells the admins, the remaining contacts and the contact itself', async () => {
    const { org, admin } = await organization();
    const id = await added(admin);
    await app.deleteFrom('notifications.outbox').where('org_id', '=', org).execute();

    const asked = await remove(admin, id);
    if (asked.outcome !== 'asked') throw new Error('not asked');
    expect(await remove(admin, id)).toEqual(asked);
    const pending = await challenges().pending(app, asked.stepUpChallengeId, admin.sessionId);
    expect(pending).toMatchObject({ action: 'contacts.remove' });
    await stepUp(admin, asked.stepUpChallengeId);

    const removed = written(await removeConfirm(admin, id, asked.stepUpChallengeId));

    expect(removed).toMatchObject({ status: 200, contact: { id, status: 'REMOVED' } });
    expect(await noticesOf(org)).toEqual([
      {
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: false,
        kind: 'contact_removed',
        about_id: id,
      },
      { recipient_user_id: null, recipient_contact_id: null, to_contacts: true, kind: 'contact_removed', about_id: id },
      { recipient_user_id: null, recipient_contact_id: id, to_contacts: false, kind: 'contact_removed', about_id: id },
    ]);
  });

  it('refuses a removal stepped up for another contact, or not stepped up, or with an app code', async () => {
    const { admin } = await organization();
    const id = await added(admin);
    const other = await added(admin, 'owner@example.test');
    const forOther = await remove(admin, other);
    if (forOther.outcome !== 'asked') throw new Error('not asked');
    await stepUp(admin, forOther.stepUpChallengeId);

    expect(await removeConfirm(admin, id, forOther.stepUpChallengeId)).toMatchObject({ code: 'STEP_UP_FAILED' });
    const asked = await remove(admin, id);
    if (asked.outcome !== 'asked') throw new Error('not asked');
    expect(await removeConfirm(admin, id, asked.stepUpChallengeId, 'not-yet')).toMatchObject({
      code: 'STEP_UP_FAILED',
    });
    await stepUp(admin, asked.stepUpChallengeId, ['pwd', 'otp', 'mfa']);
    expect(await removeConfirm(admin, id, asked.stepUpChallengeId, 'app-code')).toMatchObject({
      code: 'STEP_UP_FAILED',
    });
  });

  it('refuses to remove a draft, one removed already, or one not in the organisation', async () => {
    const { admin } = await organization();
    const draft = written(await add(admin, 'draft@example.test'));
    const id = await added(admin);
    const asked = await remove(admin, id);
    if (asked.outcome !== 'asked') throw new Error('not asked');
    await stepUp(admin, asked.stepUpChallengeId);
    written(await removeConfirm(admin, id, asked.stepUpChallengeId));

    expect(await remove(admin, draft.contact.id)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'CONTACT_NOT_ACTIVE',
    });
    expect(await remove(admin, id, 'again')).toMatchObject({ code: 'CONTACT_NOT_ACTIVE' });
    expect(await removeConfirm(admin, id, asked.stepUpChallengeId, 'again')).toMatchObject({
      code: 'CONTACT_NOT_ACTIVE',
    });
    expect(await remove(admin, ids.next())).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect(await removeConfirm(admin, ids.next(), asked.stepUpChallengeId)).toMatchObject({ code: 'NOT_FOUND' });
  });

  it('refuses anyone but an active admin, re-read inside the write', async () => {
    const { org, admin } = await organization();
    const id = await added(admin);
    const developer = await member(org, 'developer');

    expect(await remove(developer, id)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await removeConfirm(developer, id, ids.next())).toMatchObject({ code: 'FORBIDDEN' });
    expect(await confirm(developer, id)).toMatchObject({ code: 'FORBIDDEN' });
  });

  it('removes only once it holds the organisation’s contact changes’ lock, as a confirmation does', async () => {
    const { org, admin } = await organization();
    const id = await added(admin);
    const asked = await remove(admin, id);
    if (asked.outcome !== 'asked') throw new Error('not asked');
    await stepUp(admin, asked.stepUpChallengeId);
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('registered-contacts', org));
      const removing = within(20_000, removeConfirm(admin, id, asked.stepUpChallengeId), 'the removal');
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(await removing).toMatchObject({ outcome: 'written', contact: { status: 'REMOVED' } });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});
