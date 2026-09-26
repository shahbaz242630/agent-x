// B4-5a: changing a member's role, or deactivating them, through the use case
// the API's routes will call, on the real migrated schema, as the app role
// (ADR-003 §7-§9, SEC-HA-10): the idempotency store, the step-up challenge,
// both memberships and every session of the member, in one transaction.
import { createHash } from 'node:crypto';

import { createDatabase, type Database, type IdempotentRequest } from '@agentx/platform/db';
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
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import type { InvitingAdmin } from './inviting.ts';
import {
  createMembershipChanges,
  DEACTIVATE_CONFIRM_OPERATION,
  DEACTIVATE_OPERATION,
  type MembershipChange,
  type MembershipChanges,
  ROLE_CONFIRM_OPERATION,
  ROLE_OPERATION,
} from './membership-changes.ts';
import { addMembership, membershipFor, MEMBERSHIPS } from './memberships.ts';
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
const ids = new SequentialIds(0xe000_0000_0000);
const START = new Date('2026-09-25T09:00:00Z');
let clock: FixedClock;
let changes: MembershipChanges;
const challenges = () => createStepUpChallenges({ ids, clock });
const sessions = () => createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000bb';
const TO_DEVELOPER: MembershipChange = { kind: 'role', role: 'developer' };
const DEACTIVATE: MembershipChange = { kind: 'deactivate' };
const TO_APPROVER = { kind: 'role', role: 'approver' } as const satisfies MembershipChange;
const TO_ADMIN = { kind: 'role', role: 'admin' } as const satisfies MembershipChange;

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const services = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

let people = 0;
/** A person signed in, with a session. */
async function signedIn(): Promise<{ userId: string; sessionId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `changing-${String(people)}` },
    { ids, clock },
  );
  const { sessionId } = await sessions().open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'otp', 'mfa'],
  });
  return { userId, sessionId };
}

type Member = InvitingAdmin & { membershipId: string };

/** A member of the organisation with this role, signed in. */
async function member(org: string, role: Role): Promise<Member> {
  const who = await signedIn();
  const membershipId = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    addMembership(tx, states, {
      orgId: org,
      id: membershipId,
      userId: who.userId,
      role,
      joinedAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return { orgId: org, ...who, membershipId };
}

async function organization(): Promise<{ org: string; admin: Member }> {
  const org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
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

const operations = (change: MembershipChange) =>
  change.kind === 'role'
    ? { ask: ROLE_OPERATION, confirm: ROLE_CONFIRM_OPERATION }
    : { ask: DEACTIVATE_OPERATION, confirm: DEACTIVATE_CONFIRM_OPERATION };

const ask = (admin: InvitingAdmin, id: string, change: MembershipChange, key = 'ask-1') =>
  changes.ask(
    admin,
    keyed(admin, operations(change).ask, key, `${id} ${JSON.stringify(change)}`),
    id,
    change,
    CORRELATION,
  );
const confirm = (admin: InvitingAdmin, id: string, change: MembershipChange, challengeId: string, key = 'confirm-1') =>
  changes.confirm(
    admin,
    keyed(admin, operations(change).confirm, key, `${id} ${JSON.stringify(change)} ${challengeId}`),
    id,
    change,
    challengeId,
    CORRELATION,
  );

/** The admin signs in again for the challenge, as the step-up's return records it. */
const stepUp = (admin: InvitingAdmin, challengeId: string, amr: readonly string[] = ['pwd', 'user', 'mfa']) =>
  challenges().recordEvidence(app, challengeId, admin.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

/** Asks, and gives back the challenge. */
async function asked(admin: InvitingAdmin, id: string, change: MembershipChange, key = 'ask-1'): Promise<string> {
  const answer = await ask(admin, id, change, key);
  if (answer.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(answer)}`);
  return answer.stepUpChallengeId;
}

/** Asks, signs in again, and gives back the challenge. */
async function steppedUp(admin: InvitingAdmin, id: string, change: MembershipChange, key = 'ask-1') {
  const challengeId = await asked(admin, id, change, key);
  await stepUp(admin, challengeId);
  return challengeId;
}

/** The organisation's notices in the outbox (B5-1b): to whom (null: its admins), of what, about which membership and role. */
const noticesIn = async (org: string) =>
  app
    .selectFrom('notifications.outbox')
    .select(['recipient_user_id as to', 'kind', 'membership_id as membershipId', 'role'])
    .where('org_id', '=', org)
    .orderBy('id')
    .execute();

const sessionsOf = async (userId: string) =>
  (await database.as('backup').query('select id from identity.sessions where user_id = $1', [userId])).length;

/** Changes a column of a membership as the database's owner, past the app. */
async function asOwner(org: string, id: string, column: string, value: string) {
  const owner = await tamperAsOwner(database, MEMBERSHIPS, org);
  try {
    await owner.setColumn(id, column, value);
  } finally {
    await owner.end();
  }
}

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
  changes = createMembershipChanges({
    database: app,
    keys,
    ids,
    challenges: challenges(),
    outbox: createOutbox({ ids, clock }),
    logger: loggerFor(new LogCapture()),
  });
});

describe(`changing a member's role (B4-5a, SEC-HA-10, Postgres ${server.version})`, () => {
  it('opens a step-up for the admin’s own session, bound to the change', async () => {
    const who = await organization();
    const approver = await member(who.org, 'approver');

    const challengeId = await asked(who.admin, approver.membershipId, TO_DEVELOPER);

    expect(await challenges().pending(app, challengeId, who.admin.sessionId)).toMatchObject({
      userId: who.admin.userId,
      action: 'members.role',
    });
    // A retry with the same key answers with the same challenge.
    expect(await ask(who.admin, approver.membershipId, TO_DEVELOPER)).toEqual({
      outcome: 'asked',
      stepUpChallengeId: challengeId,
    });
  });

  it('changes the role once the admin has signed in again, ending every session the member has in the same change', async () => {
    const who = await organization();
    const approver = await member(who.org, 'approver');
    const other = await sessions().open(app, approver.userId, {
      idpSessionId: 'V1_3',
      authTime: clock.now(),
      amr: ['pwd', 'otp', 'mfa'],
    });
    const theirs = await challenges().open(app, {
      sessionId: approver.sessionId,
      action: 'members.approve',
      changeHash: createHash('sha256').update('their own change').digest(),
    });
    const challengeId = await steppedUp(who.admin, approver.membershipId, TO_DEVELOPER);

    const changed = await confirm(who.admin, approver.membershipId, TO_DEVELOPER, challengeId);

    expect(changed).toMatchObject({
      outcome: 'written',
      member: { id: approver.membershipId, userId: approver.userId, role: 'developer', status: 'ACTIVE' },
    });
    expect(await membershipFor(app, services(), who.org, approver.userId)).toMatchObject({
      outcome: 'active',
      role: 'developer',
    });
    // Every session of the member ended, and what went with them; the admin's own stays.
    expect(await sessionsOf(approver.userId)).toBe(0);
    expect(await sessions().use(app, other.cookie)).toBeUndefined();
    expect(await challenges().pending(app, theirs?.challengeId ?? '', approver.sessionId)).toBeUndefined();
    expect(await sessionsOf(who.admin.userId)).toBe(1);

    const events = await database
      .as('backup')
      .query(
        "select actor_id, details from audit.events where subject_id = $1 and action = 'membership.role_changed'",
        [approver.membershipId],
      );
    expect(events).toHaveLength(1);
    const [event] = events as { actor_id: string; details: string }[];
    expect(event?.actor_id).toBe(who.admin.userId);
    expect(JSON.parse(event?.details ?? '{}')).toMatchObject({
      roleFrom: 'approver',
      roleTo: 'developer',
      signInsEnded: 2,
      stepUpChallengeId: challengeId,
      signedInAt: START.toISOString(),
      methods: 'pwd user mfa',
      proofHash: createHash('sha256').update('an ID token').digest('hex'),
      verifiedAt: START.toISOString(),
    });
    expect(JSON.parse(event?.details ?? '{}')).toHaveProperty('changeHash', expect.stringMatching(/^[0-9a-f]{64}$/));
    // Consumed: gone. A retry with the same key answers as the first.
    expect(await challenges().pending(app, challengeId, who.admin.sessionId)).toBeUndefined();
    expect(await confirm(who.admin, approver.membershipId, TO_DEVELOPER, challengeId)).toEqual(changed);
  });

  it.each(['admin', 'approver', 'viewer'] as const)('changes a developer to %s', async (role) => {
    const who = await organization();
    const developer = await member(who.org, 'developer');
    const change = { kind: 'role', role } as const;
    const challengeId = await steppedUp(who.admin, developer.membershipId, change);

    expect(await confirm(who.admin, developer.membershipId, change, challengeId)).toMatchObject({
      outcome: 'written',
      member: { role },
    });
  });

  it('SEC-HA-12 refuses a step-up proved with an app code, not a passkey, changing nothing', async () => {
    const who = await organization();
    const approver = await member(who.org, 'approver');
    const challengeId = await asked(who.admin, approver.membershipId, TO_DEVELOPER);
    await stepUp(who.admin, challengeId, ['pwd', 'otp', 'mfa']);

    expect(await confirm(who.admin, approver.membershipId, TO_DEVELOPER, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await membershipFor(app, services(), who.org, approver.userId)).toMatchObject({ role: 'approver' });
    expect(await sessionsOf(approver.userId)).toBe(1);
  });

  it('refuses before the admin signs in again, changing nothing and ending no session; the same key changes after', async () => {
    const who = await organization();
    const approver = await member(who.org, 'approver');
    const challengeId = await asked(who.admin, approver.membershipId, TO_DEVELOPER);

    expect(await confirm(who.admin, approver.membershipId, TO_DEVELOPER, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await membershipFor(app, services(), who.org, approver.userId)).toMatchObject({ role: 'approver' });
    expect(await sessionsOf(approver.userId)).toBe(1);

    await stepUp(who.admin, challengeId);
    expect(await confirm(who.admin, approver.membershipId, TO_DEVELOPER, challengeId)).toMatchObject({
      outcome: 'written',
    });
  });

  it('refuses another change than the one signed in again for: another role, deactivating, or another member', async () => {
    const who = await organization();
    const approver = await member(who.org, 'approver');
    const viewer = await member(who.org, 'viewer');
    const challengeId = await steppedUp(who.admin, approver.membershipId, TO_DEVELOPER);
    const refused = { outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' };

    expect(
      await confirm(who.admin, approver.membershipId, { kind: 'role', role: 'admin' }, challengeId, 'c-1'),
    ).toEqual(refused);
    expect(await confirm(who.admin, approver.membershipId, DEACTIVATE, challengeId, 'c-2')).toEqual(refused);
    expect(await confirm(who.admin, viewer.membershipId, TO_DEVELOPER, challengeId, 'c-3')).toEqual(refused);
    // Still there for the change it was for.
    expect(await confirm(who.admin, approver.membershipId, TO_DEVELOPER, challengeId, 'c-4')).toMatchObject({
      outcome: 'written',
    });
  });

  it('refuses a change asked for on a membership that has changed since', async () => {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const approver = await member(who.org, 'approver');
    const challengeId = await steppedUp(who.admin, approver.membershipId, { kind: 'role', role: 'admin' });
    // Another admin makes them a viewer meanwhile.
    const theirs = await steppedUp(other, approver.membershipId, { kind: 'role', role: 'viewer' });
    await confirm(other, approver.membershipId, { kind: 'role', role: 'viewer' }, theirs);

    expect(await confirm(who.admin, approver.membershipId, { kind: 'role', role: 'admin' }, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await membershipFor(app, services(), who.org, approver.userId)).toMatchObject({ role: 'viewer' });
  });

  it('refuses a challenge from another organisation, the same admin and session, on a membership of the same ID', async () => {
    const first = await organization();
    const second = ids.next();
    await withSignedStates(app, second, services(), (tx, states) =>
      createOrganization(tx, states, { id: second, name: 'Beta Trading LLC', actor: OPERATOR }),
    );
    const add = (org: string, userId: string, id: string, role: Role) =>
      withSignedStates(app, org, services(), (tx, states) =>
        addMembership(tx, states, { orgId: org, id, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
      );
    await add(second, first.admin.userId, ids.next(), 'admin');
    // Nothing but the ID generator keeps a membership's ID to one organisation.
    const shared = ids.next();
    await add(first.org, (await signedIn()).userId, shared, 'viewer');
    await add(second, (await signedIn()).userId, shared, 'viewer');
    const challengeId = await steppedUp(first.admin, shared, DEACTIVATE);

    expect(await confirm({ ...first.admin, orgId: second }, shared, DEACTIVATE, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
  });

  it('refuses another admin with the first one’s challenge', async () => {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const approver = await member(who.org, 'approver');
    const challengeId = await steppedUp(who.admin, approver.membershipId, TO_DEVELOPER);

    expect(await confirm(other, approver.membershipId, TO_DEVELOPER, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
  });

  it('refuses the role the member holds already as ROLE_UNCHANGED', async () => {
    const who = await organization();
    const developer = await member(who.org, 'developer');

    expect(await ask(who.admin, developer.membershipId, TO_DEVELOPER)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'ROLE_UNCHANGED',
    });
  });
});

describe(`telling the admins of a role granted (B5-1b, ADR-003 §10, Postgres ${server.version})`, () => {
  it.each([
    ['a finance approver', TO_APPROVER],
    ['an admin', TO_ADMIN],
  ] as const)('writes one notice to the admins of a member made %s, in the same transaction', async (_what, change) => {
    const who = await organization();
    const developer = await member(who.org, 'developer');
    const challengeId = await steppedUp(who.admin, developer.membershipId, change);

    await confirm(who.admin, developer.membershipId, change, challengeId);

    expect(await noticesIn(who.org)).toEqual([
      { to: null, kind: 'role_granted', membershipId: developer.membershipId, role: change.role },
    ]);
    // A retry with the same key answers as the first, writing no notice twice.
    await confirm(who.admin, developer.membershipId, change, challengeId);
    expect(await noticesIn(who.org)).toHaveLength(1);
  });

  it('tells no one of a member made a developer or a viewer, or deactivated', async () => {
    const who = await organization();
    await member(who.org, 'admin');
    const approver = await member(who.org, 'approver');
    const viewer = await member(who.org, 'viewer');

    await confirm(
      who.admin,
      approver.membershipId,
      TO_DEVELOPER,
      await steppedUp(who.admin, approver.membershipId, TO_DEVELOPER),
    );
    await confirm(
      who.admin,
      viewer.membershipId,
      DEACTIVATE,
      await steppedUp(who.admin, viewer.membershipId, DEACTIVATE, 'ask-2'),
      'confirm-2',
    );

    expect(await membershipFor(app, services(), who.org, approver.userId)).toMatchObject({ role: 'developer' });
    expect(await noticesIn(who.org)).toEqual([]);
  });

  it('writes no notice for a change refused, rolled back with it', async () => {
    const who = await organization();
    const developer = await member(who.org, 'developer');
    const challengeId = await asked(who.admin, developer.membershipId, TO_APPROVER);
    await stepUp(who.admin, challengeId, ['pwd', 'otp', 'mfa']);

    expect(await confirm(who.admin, developer.membershipId, TO_APPROVER, challengeId)).toMatchObject({
      outcome: 'refused',
      code: 'STEP_UP_FAILED',
    });
    expect(await noticesIn(who.org)).toEqual([]);
  });
});

describe(`deactivating a member (B4-5a, SEC-HA-10, Postgres ${server.version})`, () => {
  it('deactivates once the admin has signed in again, ending every session the member has in the same change', async () => {
    const who = await organization();
    const viewer = await member(who.org, 'viewer');
    const challengeId = await asked(who.admin, viewer.membershipId, DEACTIVATE);
    expect(await challenges().pending(app, challengeId, who.admin.sessionId)).toMatchObject({
      action: 'members.deactivate',
    });
    await stepUp(who.admin, challengeId);

    const done = await confirm(who.admin, viewer.membershipId, DEACTIVATE, challengeId);

    expect(done).toMatchObject({
      outcome: 'written',
      member: { id: viewer.membershipId, role: 'viewer', status: 'DEACTIVATED' },
    });
    expect(await membershipFor(app, services(), who.org, viewer.userId)).toEqual({
      outcome: 'deactivated',
      id: viewer.membershipId,
    });
    expect(await sessionsOf(viewer.userId)).toBe(0);
    const events = await database
      .as('backup')
      .query("select actor_id, details from audit.events where subject_id = $1 and action = 'membership.deactivated'", [
        viewer.membershipId,
      ]);
    expect(events).toHaveLength(1);
    const [event] = events as { actor_id: string; details: string }[];
    expect(event?.actor_id).toBe(who.admin.userId);
    expect(JSON.parse(event?.details ?? '{}')).toMatchObject({
      role: 'viewer',
      signInsEnded: 1,
      stepUpChallengeId: challengeId,
      statusFrom: 'ACTIVE',
      statusTo: 'DEACTIVATED',
    });
    // A retry with the same key answers as the first.
    expect(await confirm(who.admin, viewer.membershipId, DEACTIVATE, challengeId)).toEqual(done);
  });

  it('refuses a member deactivated already as MEMBER_DEACTIVATED, for a role change too', async () => {
    const who = await organization();
    const viewer = await member(who.org, 'viewer');
    await confirm(
      who.admin,
      viewer.membershipId,
      DEACTIVATE,
      await steppedUp(who.admin, viewer.membershipId, DEACTIVATE),
    );
    const closed = { outcome: 'refused', status: 409, code: 'MEMBER_DEACTIVATED' };

    expect(await ask(who.admin, viewer.membershipId, DEACTIVATE, 'ask-2')).toEqual(closed);
    expect(await ask(who.admin, viewer.membershipId, TO_DEVELOPER, 'ask-3')).toEqual(closed);
  });

  it('refuses a deactivated admin', async () => {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const viewer = await member(who.org, 'viewer');
    const challengeId = await steppedUp(other, viewer.membershipId, DEACTIVATE);
    await confirm(
      who.admin,
      other.membershipId,
      DEACTIVATE,
      await steppedUp(who.admin, other.membershipId, DEACTIVATE),
    );

    // Their session ended with the deactivation; one opened since is refused all the same.
    const again = await sessions().open(app, other.userId, {
      idpSessionId: 'V1_4',
      authTime: clock.now(),
      amr: ['pwd', 'otp', 'mfa'],
    });
    expect(
      await confirm({ ...other, sessionId: again.sessionId }, viewer.membershipId, DEACTIVATE, challengeId),
    ).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
  });
});

describe(`who may change a membership, and which (B4-5a, Postgres ${server.version})`, () => {
  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s as FORBIDDEN', async (role) => {
    const who = await organization();
    const caller = await member(who.org, role);
    const viewer = await member(who.org, 'viewer');
    const forbidden = { outcome: 'refused', status: 403, code: 'FORBIDDEN' };

    expect(await ask(caller, viewer.membershipId, DEACTIVATE)).toEqual(forbidden);
    expect(await confirm(caller, viewer.membershipId, DEACTIVATE, ids.next())).toEqual(forbidden);
  });

  it('refuses a person with no membership there as FORBIDDEN', async () => {
    const who = await organization();
    const stranger = { orgId: who.org, ...(await signedIn()) };

    expect(await ask(stranger, who.admin.membershipId, DEACTIVATE)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it('refuses the admin’s own membership as OWN_MEMBERSHIP, so the organisation keeps an admin', async () => {
    const who = await organization();
    const own = { outcome: 'refused', status: 409, code: 'OWN_MEMBERSHIP' };

    expect(await ask(who.admin, who.admin.membershipId, DEACTIVATE)).toEqual(own);
    expect(await ask(who.admin, who.admin.membershipId, TO_DEVELOPER, 'ask-2')).toEqual(own);
    expect(await confirm(who.admin, who.admin.membershipId, DEACTIVATE, ids.next())).toEqual(own);
    expect(await membershipFor(app, services(), who.org, who.admin.userId)).toMatchObject({ role: 'admin' });
    expect(await sessionsOf(who.admin.userId)).toBe(1);
  });

  it('refuses a membership not in the organisation as NOT_FOUND', async () => {
    const who = await organization();
    const elsewhere = await organization();
    const theirs = await member(elsewhere.org, 'viewer');
    const missing = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };

    expect(await ask(who.admin, theirs.membershipId, DEACTIVATE)).toEqual(missing);
    expect(await ask(who.admin, ids.next(), DEACTIVATE, 'ask-2')).toEqual(missing);
    expect(await confirm(who.admin, theirs.membershipId, DEACTIVATE, ids.next())).toEqual(missing);
    expect(await sessionsOf(theirs.userId)).toBe(1);
  });

  it('refuses an ask from a session ended since as UNAUTHENTICATED', async () => {
    const who = await organization();
    const viewer = await member(who.org, 'viewer');
    await app.deleteFrom('identity.sessions').where('id', '=', who.admin.sessionId).execute();

    expect(await ask(who.admin, viewer.membershipId, DEACTIVATE)).toEqual({
      outcome: 'refused',
      status: 401,
      code: 'UNAUTHENTICATED',
    });
  });

  it('refuses the same key for another request', async () => {
    const who = await organization();
    const viewer = await member(who.org, 'viewer');
    await ask(who.admin, viewer.membershipId, DEACTIVATE);

    expect(
      await changes.ask(
        who.admin,
        keyed(who.admin, DEACTIVATE_OPERATION, 'ask-1', 'other'),
        viewer.membershipId,
        DEACTIVATE,
        CORRELATION,
      ),
    ).toEqual({ outcome: 'conflict' });
  });
});

describe(`changing a membership tampered with (B4-5a, Postgres ${server.version})`, () => {
  it('refuses a member whose membership was tampered with, as INTEGRITY_FAILED, ending no session', async () => {
    const who = await organization();
    const viewer = await member(who.org, 'viewer');
    const challengeId = await steppedUp(who.admin, viewer.membershipId, DEACTIVATE);
    await asOwner(who.org, viewer.membershipId, 'role', 'admin');

    expect(await confirm(who.admin, viewer.membershipId, DEACTIVATE, challengeId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    expect(await sessionsOf(viewer.userId)).toBe(1);
  });

  it('refuses an admin whose own membership was tampered with, as INTEGRITY_FAILED', async () => {
    const who = await organization();
    const target = await member(who.org, 'developer');
    const viewer = await member(who.org, 'viewer');
    await asOwner(who.org, viewer.membershipId, 'role', 'admin');

    expect(await ask(viewer, target.membershipId, DEACTIVATE)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });

  it('refuses a membership the directory lists for someone else too as NOT_FOUND, ending no session', async () => {
    const who = await organization();
    // Signed in first, so their ID comes first, and theirs is the entry found.
    const someone = await signedIn();
    const developer = await member(who.org, 'developer');
    const owner = await tamperAsOwner(database, MEMBERSHIPS, who.org);
    try {
      await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
        someone.userId,
        who.org,
        developer.membershipId,
      ]);
    } finally {
      await owner.end();
    }
    const missing = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };

    expect(await ask(who.admin, developer.membershipId, DEACTIVATE)).toEqual(missing);
    expect(await confirm(who.admin, developer.membershipId, DEACTIVATE, ids.next())).toEqual(missing);
    expect(await sessionsOf(developer.userId)).toBe(1);
    expect(await sessionsOf(someone.userId)).toBe(1);
  });

  it('refuses a membership the directory lists but that isn’t there as NOT_FOUND', async () => {
    const who = await organization();
    const someone = await signedIn();
    const made = ids.next();
    const owner = await tamperAsOwner(database, MEMBERSHIPS, who.org);
    try {
      await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
        someone.userId,
        who.org,
        made,
      ]);
    } finally {
      await owner.end();
    }

    expect(await ask(who.admin, made, DEACTIVATE)).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
  });

  it('refuses a person the directory points at an admin’s membership as FORBIDDEN: the membership isn’t theirs', async () => {
    const who = await organization();
    const viewer = await member(who.org, 'viewer');
    const stranger = { orgId: who.org, ...(await signedIn()) };
    const owner = await tamperAsOwner(database, MEMBERSHIPS, who.org);
    try {
      await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
        stranger.userId,
        who.org,
        who.admin.membershipId,
      ]);
    } finally {
      await owner.end();
    }

    expect(await ask(stranger, viewer.membershipId, DEACTIVATE)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it('withholds a retry’s answer when the membership was tampered with since', async () => {
    const who = await organization();
    const viewer = await member(who.org, 'viewer');
    const challengeId = await steppedUp(who.admin, viewer.membershipId, DEACTIVATE);
    await confirm(who.admin, viewer.membershipId, DEACTIVATE, challengeId);
    await asOwner(who.org, viewer.membershipId, 'role', 'admin');

    expect(await confirm(who.admin, viewer.membershipId, DEACTIVATE, challengeId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`changing memberships at the same moment (B4-5a, ADR-006 §6, Postgres ${server.version})`, () => {
  it('lets one of two admins deactivating each other win, with no deadlock, and the organisation keeps an admin', async () => {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const mine = await steppedUp(who.admin, other.membershipId, DEACTIVATE);
    const theirs = await steppedUp(other, who.admin.membershipId, DEACTIVATE);

    const answers = await Promise.all([
      confirm(who.admin, other.membershipId, DEACTIVATE, mine),
      confirm(other, who.admin.membershipId, DEACTIVATE, theirs),
    ]);

    expect(answers.map((answer) => answer.outcome).sort()).toEqual(['refused', 'written']);
    const states = await Promise.all(
      [who.admin.userId, other.userId].map((userId) => membershipFor(app, services(), who.org, userId)),
    );
    expect(states.map((state) => state.outcome).sort()).toEqual(['active', 'deactivated']);
  });

  it('deactivates a member while they step up for their own change, with no deadlock', async () => {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const viewer = await member(who.org, 'viewer');
    const mine = await steppedUp(who.admin, other.membershipId, DEACTIVATE);
    const theirs = await asked(other, viewer.membershipId, DEACTIVATE);

    // The step-up's return, as sign-in-flow.ts does it: a new cookie ID, then the evidence, in one transaction.
    const identity: Kysely<IdentityTables> = app;
    const stepUpReturn = identity.transaction().execute(async (tx) => {
      const rotated = await sessions().rotate(tx, other.sessionId);
      const recorded = await challenges().recordEvidence(tx, theirs, other.sessionId, {
        authTime: clock.now(),
        amr: ['pwd', 'user', 'mfa'],
        idpSessionId: 'V1_2',
        idTokenHash: createHash('sha256').update('an ID token').digest(),
      });
      return rotated !== undefined && recorded;
    });

    const [deactivated, returned] = await Promise.all([
      confirm(who.admin, other.membershipId, DEACTIVATE, mine),
      stepUpReturn,
    ]);

    expect(deactivated).toMatchObject({ outcome: 'written', member: { status: 'DEACTIVATED' } });
    // First or second, it either finished or found the session gone; never a deadlock.
    expect(typeof returned).toBe('boolean');
    expect(await sessionsOf(other.userId)).toBe(0);
  });

  /**
   * Holds a transaction open as another request would, with `first` done in
   * it; starts the deactivation of `other`; waits until it waits on a lock;
   * then does `then` in the held transaction and lets it go. Taken in the
   * order ADR-006 §6 sets, the deactivation waited before taking anything the
   * held transaction needs, so both finish; taken out of order, Postgres
   * finds a deadlock and fails one of them.
   */
  async function heldWhileDeactivating(
    first: (holder: Awaited<ReturnType<TestDatabase['connect']>>, other: Member, theirs: string) => Promise<unknown>,
    then: (holder: Awaited<ReturnType<TestDatabase['connect']>>, other: Member, theirs: string) => Promise<unknown>,
  ) {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const viewer = await member(who.org, 'viewer');
    const mine = await steppedUp(who.admin, other.membershipId, DEACTIVATE);
    const theirs = await asked(other, viewer.membershipId, DEACTIVATE);
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await first(holder, other, theirs);
      const deactivating = within(20_000, confirm(who.admin, other.membershipId, DEACTIVATE, mine), 'the deactivation');
      await waitUntilQueued(database.as('admin'), 1);
      await then(holder, other, theirs);
      await holder.query('commit');

      expect(await deactivating).toMatchObject({ outcome: 'written', member: { status: 'DEACTIVATED' } });
      expect(await sessionsOf(other.userId)).toBe(0);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  }

  it('waits for a step-up’s return under way, at the member’s sessions, before anything it needs', async () => {
    await heldWhileDeactivating(
      // The return gives the session a new cookie ID first...
      (holder, other) =>
        holder.query('update identity.sessions set cookie_hash = $2 where id = $1', [
          other.sessionId,
          createHash('sha256').update('a new cookie').digest(),
        ]),
      // ...then records the evidence on its challenge.
      (holder, _other, theirs) =>
        holder.query('update identity.step_up_challenges set verified_at = verified_at where id = $1', [theirs]),
    );
  });

  it('lets a challenge be opened on the member’s session while it waits for their membership', async () => {
    await heldWhileDeactivating(
      // An ask of the member's own reads their membership for the decision...
      (holder, other) =>
        holder.query('select id from identity.memberships where org_id = $1 and id = $2 for share', [
          other.orgId,
          other.membershipId,
        ]),
      // ...then opens a challenge, whose key check takes a key-share lock on the session.
      (holder, other) =>
        holder.query('select id from identity.sessions where id = $1 for key share', [other.sessionId]),
    );
  });

  it('waits for a challenge being used, at the member’s challenges, before their membership', async () => {
    await heldWhileDeactivating(
      // A change of the member's own uses its challenge first...
      (holder, _other, theirs) => holder.query('delete from identity.step_up_challenges where id = $1', [theirs]),
      // ...then reads their membership for the decision.
      (holder, other) =>
        holder.query('select id from identity.memberships where org_id = $1 and id = $2 for share', [
          other.orgId,
          other.membershipId,
        ]),
    );
  });
});
