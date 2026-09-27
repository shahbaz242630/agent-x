// B6-3c: carrying out the resets whose cooling-off has passed, through the
// job the API runs, on the real migrated schema, as the app role, with a
// stand-in for the login service's removal (idp-factors.ts is tested on its
// own, and against Zitadel in the end-to-end tests): the factors removed,
// every session ended, the reset COMPLETED and told, in one transaction
// (SEC-OPS-04); a person deactivated or in another organisation since not
// reset; a failed removal tried again; an admin's cancel waiting on the job,
// never coming between the removal and its record; a reset whose cooling-off
// was cut short past the app never carried out.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { RESET_COOLING_OFF_HOURS, resetCoolingOffUntil, resetExpiresAt } from '../domain/factor-reset.ts';
import type { Role } from '../domain/membership.ts';
import { CONTACT_COOLING_OFF_DAYS, contactCountsFrom } from '../domain/registered-contact.ts';
import {
  askContacts,
  confirmReset,
  draftReset,
  FACTOR_RESETS,
  resetChange,
  resetForChange,
  resetRecord,
} from './factor-resets.ts';
import { IdpFactorsUnavailable, type SecondFactorRemover } from './idp-factors.ts';
import { addMembership, MEMBERSHIPS } from './memberships.ts';
import { activateContact, contactChange, contactToActivate, draftContact } from './registered-contacts.ts';
import { createResetChanges } from './reset-changes.ts';
import { createResetRemovals } from './reset-removals.ts';
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
const ids = new SequentialIds(0xb63c_0000_0000);
const ISSUER = 'https://auth.example.test';
const START = new Date('2026-09-27T09:00:00Z');
const HOUR_MS = 3_600_000;
let clock: FixedClock;
let capture: LogCapture;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000cc';

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

interface Member {
  readonly userId: string;
  readonly membershipId: string;
  readonly subject: string;
  readonly sessionId: string;
}

interface Org {
  readonly org: string;
  readonly admin: Member;
  /** A developer whose second factor is lost. */
  readonly person: Member;
  readonly contact: string;
}

let people = 0;

/** A person who has signed in with the login service, as its subject: digits, as Zitadel's IDs. */
const newUser = async (issuer = ISSUER): Promise<{ userId: string; subject: string }> => {
  people += 1;
  const subject = String(312_000_000_000_000_000n + BigInt(people));
  return { userId: await userForSubject(app, { issuer, subject }, { ids, clock }), subject };
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

/** A membership of the person (a new one unless given) in the organisation, and a session opened now. */
async function member(org: string, role: Role, who?: { userId: string; subject: string }): Promise<Member> {
  const { userId, subject } = who ?? (await newUser());
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { userId, subject, membershipId, sessionId: await signedIn(userId) };
}

async function newOrganization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

/** A contact made ACTIVE by the admin now. */
async function contact(org: string, admin: Member): Promise<string> {
  const id = ids.next();
  const { change } = contactChange({
    orgId: org,
    id,
    email: 'finance.office@example.test',
    addedBy: admin.membershipId,
  });
  await withSignedStates(app, org, quiet(), (tx, states) =>
    draftContact(tx, states, keys, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: admin.userId },
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
      actor: { type: 'user', id: admin.userId },
      details: {},
    });
  });
  return id;
}

/** An organisation with an admin, a developer and a contact that counts. */
async function organization(): Promise<Org> {
  const org = await newOrganization();
  const admin = await member(org, 'admin');
  const person = await member(org, 'developer');
  const counting = await contact(org, admin);
  clock.advanceBy(CONTACT_COOLING_OFF_DAYS * 24 * HOUR_MS);
  return { org, admin, person, contact: counting };
}

/** Deactivates the person's membership, as B4-5 does. */
const deactivate = ({ org, person }: Org) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: person.membershipId }, 'deactivate', {
      actor: OPERATOR,
      action: 'membership.deactivated',
      details: {},
    }),
  );

/** A reset of the person, asked, sent and confirmed by the contact now, as B6-3b does: its ID. */
async function coolingOff({ org, admin, person, contact: contactId }: Org): Promise<string> {
  const id = ids.next();
  const { change } = resetChange({
    orgId: org,
    id,
    person: person.membershipId,
    requestedBy: admin.membershipId,
    expiresAt: resetExpiresAt(clock.now()),
  });
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    await draftReset(tx, states, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: admin.userId },
    });
  });
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await resetForChange(tx, states, { orgId: org, id });
    if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
    await askContacts(tx, states, keys, {
      orgId: org,
      id,
      contactIds: [contactId],
      createdAt: clock.now(),
      actor: { type: 'user', id: admin.userId },
      details: {},
    });
  });
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await resetForChange(tx, states, { orgId: org, id });
    if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
    await confirmReset(tx, states, {
      orgId: org,
      id,
      state: read.state,
      contactId,
      coolingOffUntil: resetCoolingOffUntil(clock.now()),
      details: {},
    });
  });
  return id;
}

/** A stand-in for the login service's removal: keeps whom it was asked for, and answers as `answer` says. */
function loginService(answer: (subject: string) => Promise<number> = () => Promise.resolve(3)) {
  const asked: string[] = [];
  const factors: SecondFactorRemover = {
    removeAll(subject) {
      asked.push(subject);
      return answer(subject);
    },
  };
  return { asked, factors };
}

const removalsWith = (factors: SecondFactorRemover) => {
  capture = new LogCapture();
  return createResetRemovals({
    database: app,
    factors,
    keys,
    ids,
    clock,
    issuer: ISSUER,
    outbox: createOutbox({ ids, clock }),
    logger: loggerFor(capture),
  });
};

const statusOf = async (org: string, id: string) => {
  const read = await withSignedStates(app, org, quiet(), (tx, states) => resetRecord(tx, states, org, id));
  if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
  return read.reset.status;
};

const sessionsOf = async (userId: string) =>
  (await app.selectFrom('identity.sessions').select('id').where('user_id', '=', userId).execute()).length;

const challengesOf = async (sessionId: string) =>
  (await app.selectFrom('identity.step_up_challenges').select('id').where('session_id', '=', sessionId).execute())
    .length;

const noticesOf = (org: string) =>
  app
    .selectFrom('notifications.outbox')
    .select(['recipient_user_id', 'to_contacts', 'kind', 'about_id'])
    .where('org_id', '=', org)
    .where('kind', 'in', ['factor_reset_completed', 'factor_reset_cancelled'])
    .orderBy('created_at')
    .orderBy('id')
    .execute();

const lastEvent = async (org: string) => {
  const event = await withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_id', 'details'])
      .orderBy('seq', 'desc')
      .limit(1)
      .executeTakeFirstOrThrow(),
  );
  return { ...event, details: JSON.parse(event.details) as unknown };
};

/** The notices telling of a reset: to the person, the admins and the contacts. */
const told = (kind: string, personUserId: string) => [
  { recipient_user_id: personUserId, to_contacts: false, kind, about_id: personUserId },
  { recipient_user_id: null, to_contacts: false, kind, about_id: personUserId },
  { recipient_user_id: null, to_contacts: true, kind, about_id: personUserId },
];

/** The run's lines of this event about the organisation (every test's organisations share the database). */
const lines = (event: string, org: string) =>
  capture.lines().filter((line) => line.event === event && line.orgId === org);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(START);
});

afterEach(async () => {
  // No reset left due for the next test: each one still open is carried out, far on.
  clock.advanceBy(30 * 24 * HOUR_MS);
  await removalsWith(loginService().factors).run();
});

describe(`carrying out a reset whose cooling-off has passed (B6-3c, Postgres ${server.version})`, () => {
  it('SEC-OPS-04 removes the person’s factors, ends their sessions, completes it and tells everyone', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    const other = await signedIn(who.person.userId);
    await createStepUpChallenges({ ids, clock }).open(app, {
      sessionId: other,
      action: 'resets.ask',
      changeHash: Buffer.alloc(32, 7),
    });
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { asked, factors } = loginService();

    await removalsWith(factors).run();

    expect(asked).toEqual([who.person.subject]);
    expect(await statusOf(who.org, id)).toBe('COMPLETED');
    expect(await lastEvent(who.org)).toMatchObject({
      action: 'factor_reset.completed',
      actor_id: 'api',
      details: { factorsRemoved: 3, signInsEnded: 2 },
    });
    expect(await sessionsOf(who.person.userId)).toBe(0);
    expect(await challengesOf(other)).toBe(0);
    // No one else's.
    expect(await sessionsOf(who.admin.userId)).toBe(1);
    expect(await noticesOf(who.org)).toEqual(told('factor_reset_completed', who.person.userId));
    expect(lines('factor_resets.completed', who.org)).toEqual([
      expect.objectContaining({ orgId: who.org, resetId: id }),
    ]);

    // Done once: the next run finds nothing due.
    await removalsWith(factors).run();
    expect(asked).toHaveLength(1);
  });

  it('waits for the cooling-off’s end, and carries it out from that moment', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    const { asked, factors } = loginService();

    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS - 1);
    await removalsWith(factors).run();
    expect(asked).toEqual([]);
    expect(await statusOf(who.org, id)).toBe('COOLING_OFF');
    expect(await sessionsOf(who.person.userId)).toBe(1);

    clock.advanceBy(1);
    await removalsWith(factors).run();
    expect(await statusOf(who.org, id)).toBe('COMPLETED');
  });

  it('leaves the reset due, the sessions and nothing told, when the removal fails, and completes it at a later run', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const failing = loginService(() => Promise.reject(new IdpFactorsUnavailable('removing a factor: it answered 403')));

    await removalsWith(failing.factors).run();

    expect(failing.asked).toEqual([who.person.subject]);
    expect(await statusOf(who.org, id)).toBe('COOLING_OFF');
    expect(await sessionsOf(who.person.userId)).toBe(1);
    expect(await noticesOf(who.org)).toEqual([]);
    expect(lines('factor_resets.removal_failed', who.org)).toEqual([
      expect.objectContaining({ level: 'error', resetId: id }),
    ]);

    await removalsWith(loginService().factors).run();
    expect(await statusOf(who.org, id)).toBe('COMPLETED');
  });

  it('goes on to the next organisation after one whose removal fails', async () => {
    const first = await organization();
    const second = await organization();
    const firstId = await coolingOff(first);
    const secondId = await coolingOff(second);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { asked, factors } = loginService((subject) =>
      subject === first.person.subject
        ? Promise.reject(new IdpFactorsUnavailable('the call failed'))
        : Promise.resolve(1),
    );

    await removalsWith(factors).run();

    expect(asked).toEqual(expect.arrayContaining([first.person.subject, second.person.subject]));
    expect(await statusOf(first.org, firstId)).toBe('COOLING_OFF');
    expect(await statusOf(second.org, secondId)).toBe('COMPLETED');
  });

  it('leaves a deactivated person’s reset an admin cancelled while the job was about to, with nothing logged as failed', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    await deactivate(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    // The job's second read waits on the person's sessions, held here, while the admin cancels.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select id from identity.sessions where user_id = $1 for no key update', [who.person.userId]);
      const running = within(20_000, removalsWith(loginService().factors).run(), 'the run');
      await waitUntilQueued(database.as('admin'), 1);
      const changes = createResetChanges({
        database: app,
        keys,
        ids,
        clock,
        challenges: createStepUpChallenges({ ids, clock }),
        outbox: createOutbox({ ids, clock }),
        logger: loggerFor(new LogCapture()),
      });
      const admin = { orgId: who.org, userId: who.admin.userId, sessionId: who.admin.sessionId };
      expect(
        await changes.cancel(
          admin,
          {
            orgId: who.org,
            client: { kind: 'user', id: admin.userId },
            operation: 'resets.cancel',
            key: 'cancel-3',
            payload: id,
          },
          id,
          CORRELATION,
        ),
      ).toMatchObject({ outcome: 'written', reset: { status: 'CANCELLED' } });
      await holder.query('commit');
      await running;
    } finally {
      await holder.query('rollback');
      await holder.end();
    }

    expect(await lastEvent(who.org)).toMatchObject({ action: 'factor_reset.cancelled', actor_id: who.admin.userId });
    expect(lines('factor_resets.removal_failed', who.org)).toEqual([]);
    expect(lines('factor_resets.cancelled', who.org)).toEqual([]);
  });

  it('cancels, rather than resets, a person deactivated since, removing nothing', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    await deactivate(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { asked, factors } = loginService();

    await removalsWith(factors).run();

    expect(asked).toEqual([]);
    expect(await statusOf(who.org, id)).toBe('CANCELLED');
    expect(await lastEvent(who.org)).toMatchObject({
      action: 'factor_reset.cancelled',
      actor_id: 'api',
      details: { reason: 'member_deactivated' },
    });
    expect(await noticesOf(who.org)).toEqual(told('factor_reset_cancelled', who.person.userId));
    expect(lines('factor_resets.cancelled', who.org)).toEqual([
      expect.objectContaining({ orgId: who.org, resetId: id }),
    ]);
  });

  it('cancels a person who joined another organisation since: their login signs in to both', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    await member(await newOrganization(), 'viewer', who.person);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { asked, factors } = loginService();

    await removalsWith(factors).run();

    expect(asked).toEqual([]);
    expect(await statusOf(who.org, id)).toBe('CANCELLED');
    expect(await lastEvent(who.org)).toMatchObject({
      details: { reason: 'member_elsewhere' },
    });
    expect(await sessionsOf(who.person.userId)).toBe(2);
  });

  it('removes nothing for a person who signs in with another login service', async () => {
    const org = await newOrganization();
    const admin = await member(org, 'admin');
    const person = await member(org, 'developer', await newUser('https://other.example.test'));
    const counting = await contact(org, admin);
    clock.advanceBy(CONTACT_COOLING_OFF_DAYS * 24 * HOUR_MS);
    const id = await coolingOff({ org, admin, person, contact: counting });
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { asked, factors } = loginService();

    await removalsWith(factors).run();

    expect(asked).toEqual([]);
    expect(await statusOf(org, id)).toBe('COOLING_OFF');
    expect(lines('factor_resets.removal_failed', org)).toEqual([expect.objectContaining({ resetId: id })]);
  });

  it.each([
    ['their sessions, as a deactivation under way holds them', 'sessions'],
    ['a step-up challenge of theirs being used', 'challenge'],
  ])('waits for %s before taking their membership, so the two can’t deadlock (level 0b)', async (_, held) => {
    const who = await organization();
    const id = await coolingOff(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const opened = await createStepUpChallenges({ ids, clock }).open(app, {
      sessionId: await signedIn(who.person.userId),
      action: 'resets.ask',
      changeHash: Buffer.alloc(32, 9),
    });
    expect(opened).toBeDefined();
    // The other change part-way: the person's sessions or challenge locked, their membership not yet.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await (held === 'sessions'
        ? holder.query('select id from identity.sessions where user_id = $1 for no key update', [who.person.userId])
        : holder.query(
            'select c.id from identity.step_up_challenges c join identity.sessions s on s.id = c.session_id where s.user_id = $1 for update of c',
            [who.person.userId],
          ));
      const { factors } = loginService();
      const running = within(20_000, removalsWith(factors).run(), 'the run');
      await waitUntilQueued(database.as('admin'), 1);
      // It goes on to the membership: the run holds nothing of it yet, so it isn't kept waiting.
      await holder.query("set local lock_timeout = '5s'");
      await holder.query('select id from identity.memberships where org_id = $1 and id = $2 for no key update', [
        who.org,
        who.person.membershipId,
      ]);
      await holder.query('commit');
      await running;
    } finally {
      await holder.query('rollback');
      await holder.end();
    }

    expect(await statusOf(who.org, id)).toBe('COMPLETED');
  });

  it('holds nothing while the login service removes: an admin lists and cancels at once, and the removal is logged as after a cancel', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { promise: removing, resolve: removingStarted } = Promise.withResolvers<undefined>();
    const { promise: released, resolve: release } = Promise.withResolvers<number>();
    const { factors } = loginService(() => {
      removingStarted(undefined);
      return released;
    });
    const running = within(20_000, removalsWith(factors).run(), 'the run');
    await removing;

    const changes = createResetChanges({
      database: app,
      keys,
      ids,
      clock,
      challenges: createStepUpChallenges({ ids, clock }),
      outbox: createOutbox({ ids, clock }),
      logger: loggerFor(new LogCapture()),
    });
    const admin = { orgId: who.org, userId: who.admin.userId, sessionId: who.admin.sessionId };
    // Each within far less than a statement's 10 s: nothing waits on the removal (review).
    expect(await within(3_000, changes.list(who.org, CORRELATION), 'the list')).toMatchObject({
      resets: [{ id, status: 'COOLING_OFF' }],
    });
    expect(
      await within(
        3_000,
        changes.cancel(
          admin,
          {
            orgId: who.org,
            client: { kind: 'user', id: admin.userId },
            operation: 'resets.cancel',
            key: 'cancel-1',
            payload: id,
          },
          id,
          CORRELATION,
        ),
        'the cancel',
      ),
    ).toMatchObject({ outcome: 'written', reset: { status: 'CANCELLED' } });
    release(2);
    await running;

    expect(await statusOf(who.org, id)).toBe('CANCELLED');
    expect(lines('factor_resets.removed_after_cancel', who.org)).toEqual([
      expect.objectContaining({ level: 'error', resetId: id }),
    ]);
    // Nothing more written: the cancel's own notices only, and the sessions left.
    expect(await noticesOf(who.org)).toEqual(told('factor_reset_cancelled', who.person.userId));
    expect(await sessionsOf(who.person.userId)).toBe(1);
  });

  it('cancels, and logs as after a cancel, a person deactivated while the factors were being removed', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { factors } = loginService(async () => {
      await deactivate(who);
      return 1;
    });

    await removalsWith(factors).run();

    expect(await statusOf(who.org, id)).toBe('CANCELLED');
    expect(await lastEvent(who.org)).toMatchObject({ details: { reason: 'member_deactivated' } });
    expect(lines('factor_resets.removed_after_cancel', who.org)).toEqual([expect.objectContaining({ resetId: id })]);
  });

  it('removes nothing for a membership the directory lists for someone else: the victim’s factors are never touched', async () => {
    // Signed in first, so their ID comes first, and theirs is the entry found for the person's membership.
    const victim = await newUser();
    const who = await organization();
    const id = await coolingOff(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const owner = await tamperAsOwner(database, MEMBERSHIPS, who.org);
    try {
      await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
        victim.userId,
        who.org,
        who.person.membershipId,
      ]);
    } finally {
      await owner.end();
    }
    const { asked, factors } = loginService();

    await removalsWith(factors).run();

    expect(asked).toEqual([]);
    expect(await statusOf(who.org, id)).toBe('COOLING_OFF');
    expect(lines('factor_resets.removal_failed', who.org)).toEqual([expect.objectContaining({ resetId: id })]);
  });

  it('leaves a reset cancelled after the run listed it, its lock read again before any removal', async () => {
    const first = await organization();
    const firstId = await coolingOff(first);
    const second = await member(first.org, 'developer');
    const secondId = await coolingOff({ ...first, person: second });
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const changes = createResetChanges({
      database: app,
      keys,
      ids,
      clock,
      challenges: createStepUpChallenges({ ids, clock }),
      outbox: createOutbox({ ids, clock }),
      logger: loggerFor(new LogCapture()),
    });
    const admin = { orgId: first.org, userId: first.admin.userId, sessionId: first.admin.sessionId };
    // Carried out in order of ID: while the first is removed, an admin cancels the second.
    const [earlier, later] = firstId < secondId ? [firstId, secondId] : [secondId, firstId];
    const { promise: removing, resolve: removingStarted } = Promise.withResolvers<undefined>();
    const { promise: released, resolve: release } = Promise.withResolvers<number>();
    const { asked, factors } = loginService(() => {
      if (asked.length > 1) return Promise.resolve(1);
      removingStarted(undefined);
      return released;
    });
    const running = within(20_000, removalsWith(factors).run(), 'the run');
    await removing;

    expect(
      await changes.cancel(
        admin,
        {
          orgId: first.org,
          client: { kind: 'user', id: admin.userId },
          operation: 'resets.cancel',
          key: 'cancel-2',
          payload: later,
        },
        later,
        CORRELATION,
      ),
    ).toMatchObject({ outcome: 'written', reset: { status: 'CANCELLED' } });
    release(1);
    await running;

    expect(asked).toHaveLength(1);
    expect(await statusOf(first.org, earlier)).toBe('COMPLETED');
    expect(await statusOf(first.org, later)).toBe('CANCELLED');
  });

  it('never carries out a reset whose cooling-off was cut short past the app: the alarm, and the organisation held', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    // Cut to a millisecond after it was asked, which the table's own check allows.
    const owner = await tamperAsOwner(database, FACTOR_RESETS, who.org);
    try {
      await owner.setColumn(id, 'cooling_off_until', new Date(clock.now().getTime() + 1).toISOString());
    } finally {
      await owner.end();
    }
    clock.advanceBy(1_000);
    const { asked, factors } = loginService();

    await removalsWith(factors).run();

    expect(asked).toEqual([]);
    expect(lines('audit.integrity_failed', who.org)).toEqual([
      expect.objectContaining({ subjectType: 'factor_reset', objectId: id }),
    ]);
    expect(lines('factor_resets.unreadable', who.org)).toEqual([expect.objectContaining({ level: 'error' })]);
  });

  it('removes nothing for a person whose membership was changed past the app: the alarm, and the reset left', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const owner = await tamperAsOwner(database, MEMBERSHIPS, who.org);
    try {
      await owner.setColumn(who.person.membershipId, 'role', 'admin');
    } finally {
      await owner.end();
    }
    const { asked, factors } = loginService();

    await removalsWith(factors).run();

    expect(asked).toEqual([]);
    expect(await statusOf(who.org, id)).toBe('COOLING_OFF');
    expect(lines('audit.integrity_failed', who.org)).toEqual([
      expect.objectContaining({ subjectType: 'membership', objectId: who.person.membershipId }),
    ]);
    expect(lines('factor_resets.removal_failed', who.org)).toEqual([expect.objectContaining({ resetId: id })]);
  });

  it('stops before the next reset once the API is stopping', async () => {
    const who = await organization();
    const id = await coolingOff(who);
    clock.advanceBy(RESET_COOLING_OFF_HOURS * HOUR_MS);
    const { asked, factors } = loginService();
    const stopping = new AbortController();
    stopping.abort();

    await removalsWith(factors).run(stopping.signal);

    expect(asked).toEqual([]);
    expect(await statusOf(who.org, id)).toBe('COOLING_OFF');
  });
});
