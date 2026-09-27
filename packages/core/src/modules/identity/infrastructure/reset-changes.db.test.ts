// B6-3b: asking for a reset of a member's lost second factor, sending it to
// the registered contacts once stepped up, and cancelling it, through the
// use case the API's routes call, on the real migrated schema, as the app
// role: the idempotency store, the step-up challenge, the reset, its secrets
// and its notices in one transaction each (SEC-OPS-04). The routes' answers
// are apps/api's factor-resets.test.ts; the reset's own table is
// factor-resets.db.test.ts. B6-3b-3: a contact confirming it by its link
// (contact-confirmations.ts).
import { createHash } from 'node:crypto';

import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { RESET_CONFIRM_HOURS, RESET_COOLING_OFF_HOURS, resetExpiresAt } from '../domain/factor-reset.ts';
import type { Role } from '../domain/membership.ts';
import { CONTACT_COOLING_OFF_DAYS, contactCountsFrom } from '../domain/registered-contact.ts';
import { createContactConfirmations } from './contact-confirmations.ts';
import { confirmationSecret, draftReset, FACTOR_RESETS, resetChange } from './factor-resets.ts';
import type { InvitingAdmin } from './inviting.ts';
import { addMembership, MEMBERSHIPS } from './memberships.ts';
import {
  activateContact,
  contactChange,
  contactToActivate,
  draftContact,
  REGISTERED_CONTACTS,
  removeContact,
} from './registered-contacts.ts';
import { createResetChanges, type ResetChanges, type ResetChangeWrite } from './reset-changes.ts';
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
const ids = new SequentialIds(0xb63b_0000_0000);
const START = new Date('2026-09-27T09:00:00Z');
const HOUR_MS = 3_600_000;
let clock: FixedClock;
let changes: ResetChanges;
const challenges = () => createStepUpChallenges({ ids, clock });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const services = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

type Member = InvitingAdmin & { readonly membershipId: string };

interface Org {
  readonly org: string;
  readonly admin: Member;
  /** Another admin, who may cancel. */
  readonly otherAdmin: Member;
  /** A developer whose second factor is lost. */
  readonly person: Member;
  /** Two contacts that count. */
  readonly contacts: readonly [string, string];
}

let people = 0;

const newUser = async (): Promise<string> => {
  people += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `reset-changes-${String(people)}` },
    { ids, clock },
  );
};

/** A session for the person, opened now. */
async function signedIn(userId: string): Promise<string> {
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
  });
  return sessionId;
}

/** A membership of the person in the organisation, and a session opened now. */
async function member(org: string, role: Role, userId?: string): Promise<Member> {
  const user = userId ?? (await newUser());
  const membershipId = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    addMembership(tx, states, {
      orgId: org,
      id: membershipId,
      userId: user,
      role,
      joinedAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return { orgId: org, userId: user, sessionId: await signedIn(user), membershipId };
}

/** Deactivates the membership, as B4-5 does. */
const deactivate = (org: string, membershipId: string) =>
  withSignedStates(app, org, services(), (tx, states) =>
    states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: membershipId }, 'deactivate', {
      actor: OPERATOR,
      action: 'membership.deactivated',
      details: {},
    }),
  );

/** A contact made ACTIVE by the admin now, as B6-1c does once stepped up: it counts 7 days on. */
async function contact(org: string, admin: Member, email: string): Promise<string> {
  const id = ids.next();
  const { change } = contactChange({ orgId: org, id, email, addedBy: admin.membershipId });
  await withSignedStates(app, org, services(), (tx, states) =>
    draftContact(tx, states, keys, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: admin.userId },
    }),
  );
  await withSignedStates(app, org, services(), async (tx, states) => {
    const read = await contactToActivate(tx, states, keys, { orgId: org, id });
    if (read.outcome !== 'draft') throw new Error(`not a draft: ${read.outcome}`);
    await activateContact(tx, states, {
      orgId: org,
      id,
      state: read.state,
      countsFrom: contactCountsFrom(clock.now()),
      actor: { type: 'user', id: admin.userId },
      details: {},
    });
  });
  return id;
}

async function newOrganization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

/**
 * An organisation with two admins and a developer, and two contacts added
 * now; unless `counting` is false, the clock is then moved past their
 * cooling-off, and everyone signed in again.
 */
async function organization({ counting = true } = {}): Promise<Org> {
  const org = await newOrganization();
  const admin = await member(org, 'admin');
  const otherAdmin = await member(org, 'admin');
  const person = await member(org, 'developer');
  const contacts = [
    await contact(org, admin, 'finance.office@example.test'),
    await contact(org, admin, 'owner@example.test'),
  ] as const;
  if (!counting) return { org, admin, otherAdmin, person, contacts };
  clock.advanceBy(CONTACT_COOLING_OFF_DAYS * 24 * HOUR_MS);
  const again = async (who: Member): Promise<Member> => ({ ...who, sessionId: await signedIn(who.userId) });
  return { org, admin: await again(admin), otherAdmin: await again(otherAdmin), person: await again(person), contacts };
}

const keyed = (admin: InvitingAdmin, operation: string, key: string, payload: string): IdempotentRequest => ({
  orgId: admin.orgId,
  client: { kind: 'user', id: admin.userId },
  operation,
  key,
  payload,
});

let keys_ = 0;
const newKey = (what: string) => {
  keys_ += 1;
  return `${what}-${String(keys_)}`;
};

const ask = (admin: InvitingAdmin, membershipId: string, key = newKey('ask')) =>
  changes.ask(admin, keyed(admin, 'resets.ask', key, membershipId), membershipId, CORRELATION);

const confirm = (admin: InvitingAdmin, id: string, key = newKey('confirm')) =>
  changes.confirm(admin, keyed(admin, 'resets.ask.confirm', key, id), id, CORRELATION);

const cancel = (admin: InvitingAdmin, id: string, key = newKey('cancel')) =>
  changes.cancel(admin, keyed(admin, 'resets.cancel', key, id), id, CORRELATION);

/** The admin signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (admin: InvitingAdmin, challengeId: string, amr: readonly string[] = ['pwd', 'user', 'mfa']) =>
  challenges().recordEvidence(app, challengeId, admin.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const written = (write: ResetChangeWrite) => {
  if (write.outcome !== 'written') throw new Error(`not written: ${JSON.stringify(write)}`);
  return write;
};

/** Asks for the person's reset and sends it to the contacts, stepped up with a passkey: its ID. */
async function sent({ admin, person }: Org): Promise<string> {
  const asked = written(await ask(admin, person.membershipId));
  await stepUp(admin, asked.stepUpChallengeId ?? '');
  written(await confirm(admin, asked.reset.id));
  return asked.reset.id;
}

const refused = (status: number, code: string) => ({ outcome: 'refused', status, code });

/** The organisation's notices, in the order written. */
const noticesOf = (org: string) =>
  app
    .selectFrom('notifications.outbox')
    .select(['recipient_user_id', 'recipient_contact_id', 'to_contacts', 'kind', 'about_id'])
    .where('org_id', '=', org)
    .orderBy('created_at')
    .orderBy('id')
    .execute();

const clearNotices = (org: string) => app.deleteFrom('notifications.outbox').where('org_id', '=', org).execute();

const secretsOf = (org: string, resetId: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('identity.factor_reset_confirmations')
      .select('contact_id')
      .where('reset_id', '=', resetId)
      .orderBy('contact_id')
      .execute(),
  );

const lastEvent = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_id', 'details'])
      .orderBy('seq', 'desc')
      .limit(1)
      .executeTakeFirstOrThrow(),
  );

/** The notices telling of a reset: to the person, the admins and, if `contacts`, the contacts. */
const told = (kind: string, personUserId: string, contacts: boolean) => [
  { recipient_user_id: personUserId, recipient_contact_id: null, to_contacts: false, kind, about_id: personUserId },
  { recipient_user_id: null, recipient_contact_id: null, to_contacts: false, kind, about_id: personUserId },
  ...(contacts
    ? [{ recipient_user_id: null, recipient_contact_id: null, to_contacts: true, kind, about_id: personUserId }]
    : []),
];

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
  changes = createResetChanges({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    outbox: createOutbox({ ids, clock }),
    logger: loggerFor(new LogCapture()),
  });
});

describe(`asking for a reset (B6-3b, Postgres ${server.version})`, () => {
  it('keeps a DRAFT for the person, and opens a challenge for the admin’s session, bound to the reset’s change', async () => {
    const { org, admin, person } = await organization();
    const key = newKey('ask');

    const asked = written(await ask(admin, person.membershipId, key));

    expect(asked).toMatchObject({
      status: 202,
      reset: {
        status: 'DRAFT',
        person: person.membershipId,
        requestedBy: admin.membershipId,
        expiresAt: new Date(clock.now().getTime() + RESET_CONFIRM_HOURS * HOUR_MS),
        confirmedBy: null,
        coolingOffUntil: null,
      },
    });
    expect(asked.stepUpChallengeId).toBe(asked.reset.stepUpChallengeId);
    const pending = await challenges().pending(app, asked.stepUpChallengeId ?? '', admin.sessionId);
    const { changeHash } = resetChange({
      orgId: org,
      id: asked.reset.id,
      person: person.membershipId,
      requestedBy: admin.membershipId,
      expiresAt: asked.reset.expiresAt,
    });
    expect(pending).toMatchObject({ userId: admin.userId, action: 'resets.ask' });
    expect(pending?.changeHash.equals(changeHash)).toBe(true);
    expect(await noticesOf(org)).toEqual([]);
    // A retry with the same key answers the same draft.
    expect(await ask(admin, person.membershipId, key)).toEqual(asked);
  });

  it('refuses the admin’s own, another admin’s asking for no one, and anyone but an active admin', async () => {
    const { org, admin, person } = await organization();
    const developer = await member(org, 'developer');
    const outsider = await member(await newOrganization(), 'admin');

    expect(await ask(admin, admin.membershipId)).toEqual(refused(409, 'OWN_RESET'));
    expect(await ask(admin, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
    expect(await ask(developer, person.membershipId)).toEqual(refused(403, 'FORBIDDEN'));
    // An admin of another organisation, naming this one: no membership here.
    expect(await ask({ ...outsider, orgId: org }, person.membershipId)).toEqual(refused(403, 'FORBIDDEN'));
    // An admin deactivated since the access hook read them.
    await deactivate(org, admin.membershipId);
    expect(await ask(admin, person.membershipId)).toEqual(refused(403, 'FORBIDDEN'));
  });

  it('refuses a person deactivated, or in another organisation too: the runbook', async () => {
    const { org, admin, person, otherAdmin } = await organization();
    await deactivate(org, otherAdmin.membershipId);
    const elsewhere = await newOrganization();
    await member(elsewhere, 'viewer', person.userId);

    expect(await ask(admin, otherAdmin.membershipId)).toEqual(refused(409, 'MEMBER_DEACTIVATED'));
    expect(await ask(admin, person.membershipId)).toEqual(refused(409, 'MEMBER_ELSEWHERE'));
  });

  it('refuses an organisation none of whose contacts counts yet: no one could confirm', async () => {
    const { admin, person } = await organization({ counting: false });

    expect(await ask(admin, person.membershipId)).toEqual(refused(409, 'NO_COUNTING_CONTACTS'));
  });

  it('refuses a second reset while one is open, and takes one once it is cancelled', async () => {
    const { admin, otherAdmin, person } = await organization();
    const first = written(await ask(admin, person.membershipId));

    expect(await ask(otherAdmin, person.membershipId)).toEqual(refused(409, 'RESET_OPEN'));
    written(await cancel(otherAdmin, first.reset.id));
    expect(await ask(otherAdmin, person.membershipId)).toMatchObject({
      outcome: 'written',
      reset: { status: 'DRAFT' },
    });
  });

  it('moves a lapsed reset to EXPIRED first, telling of it, then takes the new one', async () => {
    const who = await organization();
    const id = await sent(who);
    await clearNotices(who.org);
    clock.advanceBy(RESET_CONFIRM_HOURS * HOUR_MS);
    const fresh = { ...who.admin, sessionId: await signedIn(who.admin.userId) };

    const next = written(await ask(fresh, who.person.membershipId));

    expect(await changes.list(who.org, CORRELATION)).toEqual({
      outcome: 'listed',
      resets: [
        expect.objectContaining({ id, status: 'EXPIRED' }),
        expect.objectContaining({ id: next.reset.id, status: 'DRAFT' }),
      ],
    });
    expect(await noticesOf(who.org)).toEqual(told('factor_reset_expired', who.person.userId, true));
    expect(await lastEvent(who.org)).toMatchObject({ action: 'factor_reset.drafted' });
  });

  it('asks only once it holds the person’s lock, so two asks can’t both find none open', async () => {
    const { org, admin, otherAdmin, person } = await organization();
    // Another ask for the person, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [
        `agentx.factor-resets:${org}:${person.membershipId}`,
      ]);
      const asking = within(20_000, ask(admin, person.membershipId), 'the ask');
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(await asking).toMatchObject({ outcome: 'written', reset: { status: 'DRAFT' } });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    expect(await ask(otherAdmin, person.membershipId)).toEqual(refused(409, 'RESET_OPEN'));
  });

  it('answers 503 INTEGRITY_FAILED when a reset of the organisation can’t be believed', async () => {
    const { org, admin, otherAdmin, person } = await organization();
    const first = written(await ask(admin, person.membershipId));
    const owner = await tamperAsOwner(database, FACTOR_RESETS, org);
    try {
      await owner.setColumn(first.reset.id, 'status', 'CANCELLED');
    } finally {
      await owner.end();
    }

    expect(await ask(otherAdmin, person.membershipId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await changes.list(org, CORRELATION)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it.each([
    ['the person’s membership', MEMBERSHIPS, 'joined_at', (who: Org) => who.person.membershipId],
    ['a contact', REGISTERED_CONTACTS, 'counts_from', (who: Org) => who.contacts[0]],
  ] as const)('answers 503 INTEGRITY_FAILED when %s can’t be believed', async (_what, table, column, row) => {
    const who = await organization();
    const owner = await tamperAsOwner(database, table, who.org);
    try {
      await owner.setColumn(row(who), column, '2030-01-01T00:00:00Z');
    } finally {
      await owner.end();
    }

    expect(await ask(who.admin, who.person.membershipId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it('refuses past the resets a check reads (TOO_MANY_RESETS), at the ask and the list', async () => {
    const { org, admin, person } = await organization();
    await withSignedStates(app, org, services(), async (tx, states) => {
      for (let count = 0; count < 501; count += 1) {
        const { change } = resetChange({
          orgId: org,
          id: ids.next(),
          person: person.membershipId,
          requestedBy: admin.membershipId,
          expiresAt: resetExpiresAt(clock.now()),
        });
        await draftReset(tx, states, change, {
          stepUpChallengeId: ids.next(),
          createdAt: clock.now(),
          actor: { type: 'user', id: admin.userId },
        });
      }
    });

    expect(await ask(admin, person.membershipId)).toEqual(refused(409, 'TOO_MANY_RESETS'));
    expect(await changes.list(org, CORRELATION)).toEqual(refused(409, 'TOO_MANY_RESETS'));
  }, 60_000);
});

describe(`sending it to the contacts (B6-3b, Postgres ${server.version})`, () => {
  it('SEC-OPS-04 sends it once stepped up with a passkey, to each contact that counts, and tells the person and the admins', async () => {
    const { org, admin, person, contacts } = await organization();
    // A third contact, added now: it doesn't count for 7 days, so it is sent nothing.
    const newcomer = await contact(org, admin, 'new.partner@example.test');
    await clearNotices(org);
    const asked = written(await ask(admin, person.membershipId));
    await stepUp(admin, asked.stepUpChallengeId ?? '');
    const key = newKey('confirm');

    const done = written(await confirm(admin, asked.reset.id, key));

    expect(done).toMatchObject({ status: 200, reset: { id: asked.reset.id, status: 'AWAITING_CONTACT' } });
    expect(done.stepUpChallengeId).toBeUndefined();
    expect((await secretsOf(org, asked.reset.id)).map(({ contact_id }) => contact_id)).toEqual([...contacts].sort());
    const notices = await noticesOf(org);
    expect(notices.slice(0, 2)).toEqual(
      contacts.map((id) => ({
        recipient_user_id: null,
        recipient_contact_id: id,
        to_contacts: false,
        kind: 'factor_reset_link',
        about_id: asked.reset.id,
      })),
    );
    expect(notices.slice(2)).toEqual(told('factor_reset_asked', person.userId, false));
    expect(notices.map(({ recipient_contact_id }) => recipient_contact_id)).not.toContain(newcomer);
    const event = await lastEvent(org);
    expect(event).toMatchObject({ action: 'factor_reset.sent_to_contacts', actor_id: admin.userId });
    expect(JSON.parse(event.details)).toMatchObject({ stepUpChallengeId: asked.stepUpChallengeId, contacts: 2 });
    // A retry with the same key answers as it did, and sends nothing again.
    expect(await confirm(admin, asked.reset.id, key)).toEqual(done);
    expect(await noticesOf(org)).toHaveLength(notices.length);
  });

  it('refuses without the step-up, with an app code rather than a passkey (SEC-HA-12), or from another admin', async () => {
    const { org, admin, otherAdmin, person } = await organization();
    const asked = written(await ask(admin, person.membershipId));

    expect(await confirm(admin, asked.reset.id)).toEqual(refused(403, 'STEP_UP_FAILED'));
    await stepUp(admin, asked.stepUpChallengeId ?? '', ['pwd', 'otp']);
    expect(await confirm(admin, asked.reset.id)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await confirm(otherAdmin, asked.reset.id)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await secretsOf(org, asked.reset.id)).toEqual([]);
    expect(await noticesOf(org)).toEqual([]);
  });

  it('answers 503 INTEGRITY_FAILED to a confirmation or a cancel of a reset that can’t be believed', async () => {
    const { org, admin, person } = await organization();
    const asked = written(await ask(admin, person.membershipId));
    await stepUp(admin, asked.stepUpChallengeId ?? '');
    const owner = await tamperAsOwner(database, FACTOR_RESETS, org);
    try {
      await owner.setColumn(asked.reset.id, 'expires_at', '2030-01-01T00:00:00Z');
    } finally {
      await owner.end();
    }

    expect(await confirm(admin, asked.reset.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await cancel(admin, asked.reset.id)).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(await secretsOf(org, asked.reset.id)).toEqual([]);
  });

  it.each([
    ['the person was deactivated since', 'MEMBER_DEACTIVATED'],
    ['the person joined another organisation since', 'MEMBER_ELSEWHERE'],
    ['no contact counts any more', 'NO_COUNTING_CONTACTS'],
  ] as const)('refuses to send it when %s, changing nothing', async (what, code) => {
    const who = await organization();
    const asked = written(await ask(who.admin, who.person.membershipId));
    await stepUp(who.admin, asked.stepUpChallengeId ?? '');
    if (code === 'MEMBER_DEACTIVATED') await deactivate(who.org, who.person.membershipId);
    if (code === 'MEMBER_ELSEWHERE') await member(await newOrganization(), 'viewer', who.person.userId);
    if (code === 'NO_COUNTING_CONTACTS') {
      for (const id of who.contacts) {
        await withSignedStates(app, who.org, services(), (tx, states) =>
          removeContact(tx, states, { orgId: who.org, id, actor: OPERATOR, details: {} }),
        );
      }
    }

    expect(await confirm(who.admin, asked.reset.id), what).toEqual(refused(409, code));
    expect(await secretsOf(who.org, asked.reset.id)).toEqual([]);
  });

  it('refuses one sent already, one lapsed, and one not in the organisation, changing nothing', async () => {
    const who = await organization();
    const id = await sent(who);
    const lapsing = written(await ask(who.otherAdmin, (await member(who.org, 'viewer')).membershipId));

    expect(await confirm(who.admin, id)).toEqual(refused(409, 'RESET_CLOSED'));
    expect(await confirm(who.admin, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
    clock.advanceBy(RESET_CONFIRM_HOURS * HOUR_MS);
    const fresh = { ...who.otherAdmin, sessionId: await signedIn(who.otherAdmin.userId) };
    expect(await confirm(fresh, lapsing.reset.id)).toEqual(refused(409, 'RESET_CLOSED'));
  });
});

describe(`cancelling it (B6-3b, Postgres ${server.version})`, () => {
  it('lets any admin cancel it with no step-up, telling the person, the admins and the contacts it was sent to', async () => {
    const who = await organization();
    const id = await sent(who);
    await clearNotices(who.org);

    const done = written(await cancel(who.otherAdmin, id));

    expect(done).toMatchObject({ status: 200, reset: { id, status: 'CANCELLED' } });
    expect(await noticesOf(who.org)).toEqual(told('factor_reset_cancelled', who.person.userId, true));
    expect(await lastEvent(who.org)).toMatchObject({
      action: 'factor_reset.cancelled',
      actor_id: who.otherAdmin.userId,
    });
    expect(await cancel(who.admin, id)).toEqual(refused(409, 'RESET_CLOSED'));
  });

  it('lets the person, an admin, stop a reset of their own second factor; tells no contact of a draft', async () => {
    const { org, admin, otherAdmin } = await organization();
    const asked = written(await ask(admin, otherAdmin.membershipId));

    expect(await cancel(otherAdmin, asked.reset.id)).toMatchObject({ reset: { status: 'CANCELLED' } });
    expect(await noticesOf(org)).toEqual(told('factor_reset_cancelled', otherAdmin.userId, false));
  });

  it('refuses anyone but an active admin, and a reset not in the organisation', async () => {
    const { org, admin, person } = await organization();
    const asked = written(await ask(admin, person.membershipId));
    const approver = await member(org, 'approver');

    expect(await cancel(approver, asked.reset.id)).toEqual(refused(403, 'FORBIDDEN'));
    expect(await cancel(admin, ids.next())).toEqual(refused(404, 'NOT_FOUND'));
  });
});

describe(`listing them (B6-3b, Postgres ${server.version})`, () => {
  it('lists every reset of the organisation, open or not, in order of ID', async () => {
    const { org, admin, otherAdmin, person } = await organization();
    const first = written(await ask(admin, person.membershipId));
    written(await cancel(admin, first.reset.id));
    const second = written(await ask(admin, otherAdmin.membershipId));

    expect(await changes.list(org, CORRELATION)).toEqual({
      outcome: 'listed',
      resets: [
        expect.objectContaining({ id: first.reset.id, status: 'CANCELLED' }),
        expect.objectContaining({ id: second.reset.id, status: 'DRAFT' }),
      ],
    });
    expect(await changes.list(await newOrganization(), CORRELATION)).toEqual({ outcome: 'listed', resets: [] });
  });
});

describe(`a contact confirming it by its link (B6-3b-3, Postgres ${server.version})`, () => {
  let capture: LogCapture;
  const confirmations = () => {
    capture = new LogCapture();
    return createContactConfirmations({
      database: app,
      keys,
      ids,
      clock,
      outbox: createOutbox({ ids, clock }),
      logger: loggerFor(capture),
    });
  };

  /** The contact's token, as its link carries it. */
  const tokenOf = async (org: string, resetId: string, contactId: string) => {
    const secret = await withTenant(app, org, (tx) => confirmationSecret(tx, keys, { orgId: org, resetId, contactId }));
    return `${org}.${resetId}.${contactId}.${secret ?? 'none'}`;
  };

  const press = (token: string) => confirmations().confirm(token, CORRELATION);

  it('SEC-OPS-04 starts the cooling-off, names the contact, and tells the person, the admins and the contacts', async () => {
    const who = await organization();
    const id = await sent(who);
    await clearNotices(who.org);
    const token = await tokenOf(who.org, id, who.contacts[1]);
    const until = new Date(clock.now().getTime() + RESET_COOLING_OFF_HOURS * HOUR_MS);

    expect(await press(token)).toEqual({ outcome: 'confirmed', coolingOffUntil: until });

    expect(await changes.list(who.org, CORRELATION)).toMatchObject({
      resets: [{ id, status: 'COOLING_OFF', confirmedBy: who.contacts[1], coolingOffUntil: until }],
    });
    expect(await noticesOf(who.org)).toEqual(told('factor_reset_confirmed', who.person.userId, true));
    expect(await lastEvent(who.org)).toMatchObject({ action: 'factor_reset.confirmed', actor_id: 'api' });
    // Pressed again, later: answered as the first press was, with nothing written.
    clock.advanceBy(HOUR_MS);
    expect(await press(token)).toEqual({ outcome: 'confirmed', coolingOffUntil: until });
    expect(await press(token.toUpperCase().replace(/\.[^.]*$/, token.slice(token.lastIndexOf('.'))))).toEqual({
      outcome: 'confirmed',
      coolingOffUntil: until,
    });
    expect(await noticesOf(who.org)).toHaveLength(3);
    // The other contact's link does nothing now.
    expect(await press(await tokenOf(who.org, id, who.contacts[0]))).toEqual(refused(409, 'RESET_CLOSED'));
  });

  it('answers NOT_FOUND alike to any link that isn’t one we wrote, changing nothing', async () => {
    const who = await organization();
    const id = await sent(who);
    const token = await tokenOf(who.org, id, who.contacts[0]);
    const [org, reset, contact, secret] = token.split('.') as [string, string, string, string];
    const other = await newOrganization();
    const changed = `${secret.slice(0, -1)}${secret.endsWith('A') ? 'B' : 'A'}`;

    for (const link of [
      `${org}.${reset}.${contact}.${changed}`,
      `${org}.${reset}.${who.contacts[1]}.${secret}`,
      `${org}.${ids.next()}.${contact}.${secret}`,
      `${other}.${reset}.${contact}.${secret}`,
      `${org}.${reset}.${contact}`,
      `${org}.${reset}.${contact}.${secret}.more`,
      'not a token',
    ]) {
      expect(await press(link), link).toEqual(refused(404, 'NOT_FOUND'));
    }
    expect(await changes.list(who.org, CORRELATION)).toMatchObject({ resets: [{ id, status: 'AWAITING_CONTACT' }] });
  });

  it('refuses a contact removed since it was asked, and a reset cancelled or lapsed', async () => {
    const who = await organization();
    const removedFor = await sent(who);
    await withSignedStates(app, who.org, services(), (tx, states) =>
      removeContact(tx, states, { orgId: who.org, id: who.contacts[0], actor: OPERATOR, details: {} }),
    );
    expect(await press(await tokenOf(who.org, removedFor, who.contacts[0]))).toEqual(
      refused(409, 'CONTACT_NOT_ACTIVE'),
    );
    written(await cancel(who.admin, removedFor));
    expect(await press(await tokenOf(who.org, removedFor, who.contacts[1]))).toEqual(refused(409, 'RESET_CLOSED'));

    const lapsing = await sent(who);
    clock.advanceBy(RESET_CONFIRM_HOURS * HOUR_MS);
    expect(await press(await tokenOf(who.org, lapsing, who.contacts[1]))).toEqual(refused(409, 'RESET_CLOSED'));
  });

  it('answers 503 INTEGRITY_FAILED when the reset can’t be believed, or its secret won’t open', async () => {
    const who = await organization();
    const id = await sent(who);
    const token = await tokenOf(who.org, id, who.contacts[0]);
    const owner = await tamperAsOwner(database, FACTOR_RESETS, who.org);
    try {
      await owner.setColumn(id, 'expires_at', '2030-01-01T00:00:00Z');
    } finally {
      await owner.end();
    }
    expect(await press(token)).toEqual(refused(503, 'INTEGRITY_FAILED'));

    const planted = await organization();
    const plantedId = await sent(planted);
    const [first, second] = planted.contacts;
    const plantedToken = await tokenOf(planted.org, plantedId, first);
    // The first contact's secret copied over the second's row, past the app: it won't open there.
    const planter = await tamperAsOwner(database, FACTOR_RESETS, planted.org);
    try {
      await planter.query(
        'delete from identity.factor_reset_confirmations where org_id = $1 and reset_id = $2 and contact_id = $3',
        [planted.org, plantedId, second],
      );
      await planter.query(
        `insert into identity.factor_reset_confirmations
           select org_id, reset_id, $4, secret_ciphertext, secret_key_version, created_at
           from identity.factor_reset_confirmations where org_id = $1 and reset_id = $2 and contact_id = $3`,
        [planted.org, plantedId, first, second],
      );
    } finally {
      await planter.end();
    }

    expect(await press(plantedToken.replace(`.${first}.`, `.${second}.`))).toEqual(refused(503, 'INTEGRITY_FAILED'));
    expect(capture.lines().map(({ event }) => event)).toContain('factor_reset.confirmation_unreadable');
  });
});
