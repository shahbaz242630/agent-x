// B4-4c: accepting an invitation through the use case the API's route calls,
// on the real migrated schema, as the app role: the directory's lookup, the
// idempotency store, the invitation and the membership, in the invitation's
// own organisation (SEC-HA-08, SEC-TEN-04). The route's answers are
// apps/api's invitations.test.ts.
import { createHash, randomBytes } from 'node:crypto';

import {
  createDatabase,
  type Database,
  type IdempotentRequest,
  TenantContextError,
  withTenant,
} from '@agentx/platform/db';
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
import { INVITATION_HOURS } from '../domain/invitation.ts';
import type { Role } from '../domain/membership.ts';
import {
  ACCEPT_OPERATION,
  type AcceptingPerson,
  createInvitationAcceptance,
  type InvitationAcceptance,
} from './accepting.ts';
import {
  draftInvitation,
  invitationChange,
  invitationRecord,
  INVITATIONS,
  invitationToOpen,
  inviteFirstAdmin,
  inviteTokenHash,
  openInvitation,
} from './invitations.ts';
import { addMembership, membersFor, membershipFor, MEMBERSHIPS } from './memberships.ts';
import { recordSessionEmail } from './session-emails.ts';
import { createSessions } from './sessions.ts';
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
let capture: LogCapture;
let acceptance: InvitationAcceptance;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';
const INVITED = 'sara.khan@example.test';

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const services = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

let people = 0;
/** A person signed in, with a session holding this verified address, or none. */
/** `null` for none: a default swallows an explicit undefined. */
async function person(email: string | null = INVITED): Promise<AcceptingPerson> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `accepting-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'otp', 'mfa'],
  });
  if (email !== null) await recordSessionEmail(app, keys, sessionId, email);
  return { userId, sessionId };
}

/** An organisation with an admin, as B4-6 will make one. */
async function organization(): Promise<{ org: string; admin: string; adminUser: string }> {
  const org = ids.next();
  const admin = ids.next();
  const { userId: adminUser } = await person(null);
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

/** An open invitation to the organisation, and its token, as the admin's two steps make it. */
async function invitation(
  { org, admin, adminUser }: { org: string; admin: string; adminUser: string },
  role: Role = 'developer',
  email = 'Sara.Khan@Example.test',
): Promise<{ id: string; token: string }> {
  const id = ids.next();
  const { change } = invitationChange({ orgId: org, id, email, role, invitedBy: admin, createdAt: clock.now() });
  const actor = { type: 'user' as const, id: adminUser };
  await withSignedStates(app, org, services(), (tx, states) =>
    draftInvitation(tx, states, keys, change, { stepUpChallengeId: ids.next(), createdAt: clock.now(), actor }),
  );
  const token = await withSignedStates(app, org, services(), async (tx, states) => {
    await invitationToOpen(tx, states, keys, { orgId: org, id, now: clock.now() });
    return openInvitation(tx, states, { orgId: org, id, actor, details: {} });
  });
  return { id, token };
}

/** The key's request, for the organisation the directory named: recorded, so a test sees which. */
let keyedFor: string[] = [];
const keyed =
  (who: AcceptingPerson, key: string, token: string) =>
  (orgId: string): IdempotentRequest => {
    keyedFor.push(orgId);
    return {
      orgId,
      client: { kind: 'user', id: who.userId },
      operation: ACCEPT_OPERATION,
      key,
      payload: JSON.stringify({ token }),
    };
  };

const accept = (who: AcceptingPerson, token: string, key = 'accept-1') =>
  acceptance.accept(who, token, keyed(who, key, token), CORRELATION);

const membershipOfPerson = (org: string, userId: string) => membershipFor(app, services(), org, userId);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
  clock = new FixedClock(START);
  keyedFor = [];
  acceptance = createInvitationAcceptance({
    database: app,
    keys,
    ids,
    clock,
    outbox: createOutbox({ ids, clock }),
    logger: loggerFor(capture),
  });
});

/** The organisation's notices in the outbox (B5-1b): to whom (null: its admins), of what, about which membership and role. */
const noticesIn = async (org: string) =>
  app
    .selectFrom('notifications.outbox')
    .select(['recipient_user_id as to', 'kind', 'membership_id as membershipId', 'role'])
    .where('org_id', '=', org)
    .orderBy('id')
    .execute();

describe(`accepting an invitation (B4-4c, SEC-HA-08, Postgres ${server.version})`, () => {
  it.each(['developer', 'viewer'] as const)(
    'joins a %s at once: the invitation ACCEPTED and the membership added, in its own organisation',
    async (role) => {
      const who = await organization();
      const { id, token } = await invitation(who, role);
      const invitee = await person();

      const accepted = await accept(invitee, token);

      expect(accepted).toMatchObject({
        outcome: 'accepted',
        orgId: who.org,
        invitation: { id, role, status: 'ACCEPTED', acceptedBy: invitee.userId },
      });
      expect(keyedFor).toEqual([who.org]);
      expect(await membershipOfPerson(who.org, invitee.userId)).toMatchObject({ outcome: 'active', role });
      // B5-1b: a developer or viewer joining is told to no one.
      expect(await noticesIn(who.org)).toEqual([]);
    },
  );

  it.each(['admin', 'approver'] as const)(
    'keeps a %s waiting for an admin’s confirmation, with no membership yet',
    async (role) => {
      const who = await organization();
      const { id, token } = await invitation(who, role);
      const invitee = await person();

      expect(await accept(invitee, token)).toMatchObject({
        outcome: 'accepted',
        invitation: { id, role, status: 'AWAITING_CONFIRMATION', acceptedBy: invitee.userId },
      });
      expect(await membershipOfPerson(who.org, invitee.userId)).toEqual({ outcome: 'none' });
    },
  );

  it('matches the address whatever case it was invited and signed in with', async () => {
    const who = await organization();
    const { token } = await invitation(who, 'viewer', 'SARA.KHAN@example.TEST');

    expect(await accept(await person('Sara.Khan@EXAMPLE.test'), token)).toMatchObject({ outcome: 'accepted' });
  });

  it('refuses a token not known as INVITATION_INVALID, asking no organisation for a key', async () => {
    const invitee = await person();

    expect(await accept(invitee, 'x'.repeat(43))).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'INVITATION_INVALID',
    });
    expect(keyedFor).toEqual([]);
  });

  it('refuses a person signed in with another address, or none, alike: INVITATION_INVALID, nothing kept', async () => {
    const who = await organization();
    const { id, token } = await invitation(who);

    for (const invitee of [await person('mallory@example.test'), await person(null)]) {
      expect(await accept(invitee, token)).toEqual({ outcome: 'refused', status: 403, code: 'INVITATION_INVALID' });
      expect(await membershipOfPerson(who.org, invitee.userId)).toEqual({ outcome: 'none' });
    }
    // Still open for the person it is for.
    expect(await accept(await person(), token)).toMatchObject({ invitation: { id, status: 'ACCEPTED' } });
  });

  it('answers a retry with the same key as the first, adding no second membership', async () => {
    const who = await organization();
    const { token } = await invitation(who);
    const invitee = await person();
    const first = await accept(invitee, token);

    expect(await accept(invitee, token)).toEqual(first);
    const entries = await database
      .as('backup')
      .query('select 1 from directory.members where user_id = $1', [invitee.userId]);
    expect(entries).toHaveLength(1);
  });

  it('refuses the same key for another request', async () => {
    const who = await organization();
    const { token } = await invitation(who);
    const invitee = await person();
    await accept(invitee, token);

    const other = await acceptance.accept(
      invitee,
      token,
      (orgId) => ({ ...keyed(invitee, 'accept-1', token)(orgId), payload: '{"token":"another"}' }),
      CORRELATION,
    );

    expect(other).toEqual({ outcome: 'conflict' });
  });

  it('withholds a retry’s answer when the invitation was tampered with since, as INTEGRITY_FAILED', async () => {
    const who = await organization();
    const { id, token } = await invitation(who, 'viewer');
    const invitee = await person();
    await accept(invitee, token);
    const owner = await tamperAsOwner(database, INVITATIONS, who.org);
    try {
      await owner.setColumn(id, 'role', 'admin');
    } finally {
      await owner.end();
    }

    expect(await accept(invitee, token)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('throws on, never answers, a failure that is no refusal: a key claimed for another organisation', async () => {
    const who = await organization();
    const elsewhere = await organization();
    const { token } = await invitation(who);
    const invitee = await person();

    await expect(
      acceptance.accept(invitee, token, () => keyed(invitee, 'accept-1', token)(elsewhere.org), CORRELATION),
    ).rejects.toBeInstanceOf(TenantContextError);
  });

  it('refuses the invitation used once already as INVITATION_CLOSED, to another key or another person', async () => {
    const who = await organization();
    const { token } = await invitation(who);
    const invitee = await person();
    await accept(invitee, token);

    expect(await accept(invitee, token, 'accept-2')).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'INVITATION_CLOSED',
    });
    expect(await accept(await person(), token)).toEqual({ outcome: 'refused', status: 409, code: 'INVITATION_CLOSED' });
  });

  it('refuses it at its end as INVITATION_CLOSED', async () => {
    const who = await organization();
    const { token } = await invitation(who);
    const invitee = await person();
    clock.advanceBy(INVITATION_HOURS * 3_600_000);

    expect(await accept(invitee, token)).toEqual({ outcome: 'refused', status: 409, code: 'INVITATION_CLOSED' });
  });

  it('refuses someone in the organisation already as ALREADY_A_MEMBER, leaving the invitation open', async () => {
    const who = await organization();
    const { id, token } = await invitation(who, 'admin');
    const member = await person();
    await withSignedStates(app, who.org, services(), (tx, states) =>
      addMembership(tx, states, {
        orgId: who.org,
        id: ids.next(),
        userId: member.userId,
        role: 'viewer',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );

    expect(await accept(member, token)).toEqual({ outcome: 'refused', status: 409, code: 'ALREADY_A_MEMBER' });
    const kept = await database.as('backup').query('select status from identity.invitations where id = $1', [id]);
    expect(kept).toEqual([{ status: 'OPEN' }]);
    const keysKept = await database.as('backup').query('select 1 from idempotency.keys where org_id = $1', [who.org]);
    expect(keysKept).toEqual([]);
  });

  it('refuses an invitation tampered with as INTEGRITY_FAILED, and holds its organisation', async () => {
    const who = await organization();
    const { id, token } = await invitation(who, 'viewer');
    const owner = await tamperAsOwner(database, INVITATIONS, who.org);
    try {
      await owner.setColumn(id, 'role', 'admin');
    } finally {
      await owner.end();
    }

    expect(await accept(await person(), token)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    const held = await withSignedStates(app, who.org, services(), (tx, states) =>
      states.integrityHold(tx, who.org, 'none'),
    );
    expect(held).toMatchObject({ outcome: 'held' });
  });

  it('refuses a person whose own membership there was tampered with, as INTEGRITY_FAILED', async () => {
    const who = await organization();
    const { token } = await invitation(who, 'viewer');
    const member = await person();
    const membershipId = ids.next();
    await withSignedStates(app, who.org, services(), (tx, states) =>
      addMembership(tx, states, {
        orgId: who.org,
        id: membershipId,
        userId: member.userId,
        role: 'viewer',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    const owner = await tamperAsOwner(database, MEMBERSHIPS, who.org);
    try {
      await owner.setColumn(membershipId, 'role', 'admin');
    } finally {
      await owner.end();
    }

    expect(await accept(member, token)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('SEC-TEN-04 joins only the organisation the invitation is to, whatever others the person is in', async () => {
    const first = await organization();
    const second = await organization();
    const { token } = await invitation(first, 'viewer');
    const invitee = await person();

    await accept(invitee, token);

    expect(await membershipOfPerson(first.org, invitee.userId)).toMatchObject({ outcome: 'active' });
    expect(await membershipOfPerson(second.org, invitee.userId)).toEqual({ outcome: 'none' });
  });

  it('keeps the token itself nowhere it is looked up: only its SHA-256', async () => {
    const who = await organization();
    const { token } = await invitation(who);

    const rows = await database
      .as('backup')
      .query('select token_hash from directory.invites where org_id = $1', [who.org]);
    expect(rows).toEqual([{ token_hash: createHash('sha256').update(token, 'ascii').digest() }]);
  });
});

describe(`accepting, the harder cases (B4-4c, Postgres ${server.version})`, () => {
  it('gives the new member the moment they accepted as when they joined', async () => {
    const who = await organization();
    const { token } = await invitation(who, 'viewer');
    const invitee = await person();
    clock.advanceBy(60_000);

    await accept(invitee, token);

    const list = await membersFor(app, services(), who.org);
    if (list.outcome !== 'listed') throw new Error('not listed');
    expect(list.members.find((member) => member.userId === invitee.userId)?.joinedAt).toEqual(clock.now());
  });

  it('refuses a token listed for an invitation that isn’t there as INVITATION_INVALID', async () => {
    const who = await organization();
    const invitee = await person();
    const token = 'P'.repeat(43);
    await withTenant(app, who.org, (tx) =>
      tx
        .insertInto('directory.invites')
        .values({
          token_hash: createHash('sha256').update(token, 'ascii').digest(),
          org_id: who.org,
          invitation_id: ids.next(),
        })
        .execute(),
    );

    expect(await accept(invitee, token)).toEqual({ outcome: 'refused', status: 403, code: 'INVITATION_INVALID' });
  });

  /** The person, a viewer there once, deactivated since; their membership's ID. */
  async function deactivatedIn(org: string, member: AcceptingPerson): Promise<string> {
    const membershipId = ids.next();
    await withSignedStates(app, org, services(), async (tx, states) => {
      await addMembership(tx, states, {
        orgId: org,
        id: membershipId,
        userId: member.userId,
        role: 'viewer',
        joinedAt: clock.now(),
        actor: OPERATOR,
      });
    });
    await withSignedStates(app, org, services(), (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );
    return membershipId;
  }

  it('brings a person deactivated there back as a developer: the same membership, the invitation’s role, a new start (B4-5c)', async () => {
    const who = await organization();
    const member = await person();
    const membershipId = await deactivatedIn(who.org, member);
    const { id, token } = await invitation(who, 'developer');
    clock.advanceBy(86_400_000);

    expect(await accept(member, token)).toMatchObject({ outcome: 'accepted', invitation: { id, status: 'ACCEPTED' } });
    expect(await membershipOfPerson(who.org, member.userId)).toEqual({
      outcome: 'active',
      id: membershipId,
      role: 'developer',
    });
    const list = await membersFor(app, services(), who.org);
    expect(list).toMatchObject({
      outcome: 'listed',
      members: expect.arrayContaining([
        expect.objectContaining({ id: membershipId, joinedAt: clock.now() }),
      ]) as unknown,
    });
    const events = await database
      .as('backup')
      .query<{ action: string; details: string }>(
        'select action, details from audit.events where subject_id = $1 order by seq',
        [membershipId],
      );
    expect(events.map(({ action }) => action)).toEqual([
      'membership.created',
      'membership.deactivated',
      'membership.renewed',
      'membership.reactivated',
    ]);
    expect(JSON.parse(events[2]?.details ?? '{}')).toMatchObject({ roleFrom: 'viewer', roleTo: 'developer' });
    expect(JSON.parse(events[3]?.details ?? '{}')).toMatchObject({
      role: 'developer',
      statusFrom: 'DEACTIVATED',
      statusTo: 'ACTIVE',
    });
    // Still one entry, one membership.
    const entries = await database
      .as('backup')
      .query('select 1 from directory.members where user_id = $1', [member.userId]);
    expect(entries).toHaveLength(1);
    // B5-1b: the admins are told of the rejoin, in the same transaction.
    expect(await noticesIn(who.org)).toEqual([{ to: null, kind: 'member_rejoined', membershipId, role: 'developer' }]);
  });

  it('brings a person deactivated there back once when two of their invitations are accepted at the same moment (B4-5c)', async () => {
    const who = await organization();
    const member = await person();
    const membershipId = await deactivatedIn(who.org, member);
    const first = await invitation(who, 'viewer');
    const second = await invitation(who, 'developer');

    const answers = await Promise.all([
      accept(member, first.token, 'accept-a'),
      accept(member, second.token, 'accept-b'),
    ]);

    expect(answers.map((answer) => answer.outcome).sort()).toEqual(['accepted', 'refused']);
    expect(answers).toContainEqual({ outcome: 'refused', status: 409, code: 'ALREADY_A_MEMBER' });
    expect(await membershipOfPerson(who.org, member.userId)).toMatchObject({ outcome: 'active', id: membershipId });
    const reactivations = await database
      .as('backup')
      .query("select 1 from audit.events where subject_id = $1 and action = 'membership.reactivated'", [membershipId]);
    expect(reactivations).toHaveLength(1);
  });

  it('keeps a person deactivated there waiting, invited as an admin, until an admin confirms them (B4-5c)', async () => {
    const who = await organization();
    const member = await person();
    const membershipId = await deactivatedIn(who.org, member);
    const { token } = await invitation(who, 'admin');

    expect(await accept(member, token)).toMatchObject({
      outcome: 'accepted',
      invitation: { status: 'AWAITING_CONFIRMATION' },
    });
    expect(await membershipOfPerson(who.org, member.userId)).toEqual({ outcome: 'deactivated', id: membershipId });
    // Nothing is told until an admin confirms them (confirming.ts tells it then).
    expect(await noticesIn(who.org)).toEqual([]);
  });

  it('joins once when two of a person’s invitations there are accepted at the same moment', async () => {
    const who = await organization();
    const first = await invitation(who, 'viewer');
    const second = await invitation(who, 'developer');
    const invitee = await person();

    const answers = await Promise.all([
      accept(invitee, first.token, 'accept-a'),
      accept(invitee, second.token, 'accept-b'),
    ]);

    expect(answers.map((answer) => answer.outcome).sort()).toEqual(['accepted', 'refused']);
    expect(answers).toContainEqual({ outcome: 'refused', status: 409, code: 'ALREADY_A_MEMBER' });
    const entries = await database
      .as('backup')
      .query('select 1 from directory.members where user_id = $1', [invitee.userId]);
    expect(entries).toHaveLength(1);
  });

  it('gives up on the answer’s read after 10 seconds rather than hold the request', async () => {
    const who = await organization();
    const { token } = await invitation(who, 'viewer');
    const invitee = await person();
    await accept(invitee, token);
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table identity.invitations in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, accept(invitee, token), 'the retry')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe(`the first admin, invited by the operator's command (B4-6a, Postgres ${server.version})`, () => {
  /** An organisation no one belongs to, as the operator's command creates one. */
  async function emptyOrganization(): Promise<string> {
    const org = ids.next();
    await withSignedStates(app, org, services(), (tx, states) =>
      createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
    );
    return org;
  }

  /** The operator's invitation of the first admin: its ID, and the token its link carries, made outside the job. */
  async function firstAdmin(org: string, email = 'Sara.Khan@Example.test'): Promise<{ id: string; token: string }> {
    const id = ids.next();
    const token = randomBytes(32).toString('base64url');
    await withSignedStates(app, org, services(), (tx, states) =>
      inviteFirstAdmin(tx, states, keys, {
        orgId: org,
        id,
        email,
        tokenHash: inviteTokenHash(token),
        createdAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    return { id, token };
  }

  const recordOfInvitation = (org: string, id: string) =>
    withSignedStates(app, org, services(), (tx, states) => invitationRecord(tx, states, org, id));

  it('opens an admin’s invitation at once, naming no member who asked and no step-up, listed by the token’s hash', async () => {
    const org = await emptyOrganization();
    const { id, token } = await firstAdmin(org);

    expect(await recordOfInvitation(org, id)).toMatchObject({
      outcome: 'found',
      invitation: { id, role: 'admin', status: 'OPEN', stepUpChallengeId: null, byOperator: true, acceptedBy: null },
    });
    const listed = await database
      .as('backup')
      .query<{ invitation_id: string }>('select invitation_id from directory.invites where token_hash = $1', [
        inviteTokenHash(token),
      ]);
    expect(listed).toEqual([{ invitation_id: id }]);
    const events = await database
      .as('backup')
      .query<{ action: string; details: string }>(
        'select action, details from audit.events where subject_id = $1 order by seq',
        [id],
      );
    expect(events.map(({ action }) => action)).toEqual(['invitation.drafted', 'invitation.opened']);
    expect(JSON.parse(events[1]?.details ?? '{}')).toMatchObject({ role: 'admin', byOperator: true });
  });

  it('makes the person who accepts it the first admin at once, while no one belongs to the organisation', async () => {
    const org = await emptyOrganization();
    const { id, token } = await firstAdmin(org);
    const invitee = await person();

    expect(await accept(invitee, token)).toMatchObject({
      outcome: 'accepted',
      orgId: org,
      invitation: { id, status: 'ACCEPTED', acceptedBy: invitee.userId },
    });
    expect(await membershipOfPerson(org, invitee.userId)).toMatchObject({ outcome: 'active', role: 'admin' });
    // B5-1b: an admin joining is told to the admins; the sender finds none but them, and tells no one.
    const joined = await membershipOfPerson(org, invitee.userId);
    if (joined.outcome !== 'active') throw new Error(`not joined: ${joined.outcome}`);
    expect(await noticesIn(org)).toEqual([{ to: null, kind: 'role_granted', membershipId: joined.id, role: 'admin' }]);
    // A retry with the same key answers as the first, writing no notice twice.
    await accept(invitee, token);
    expect(await noticesIn(org)).toHaveLength(1);
  });

  it('makes one first admin when two of the operator’s invitations are accepted at the same moment (B4-6a review)', async () => {
    const org = await emptyOrganization();
    const first = await firstAdmin(org, 'first@example.test');
    const second = await firstAdmin(org, 'second@example.test');

    const answers = await Promise.all([
      accept(await person('first@example.test'), first.token, 'accept-a'),
      accept(await person('second@example.test'), second.token, 'accept-b'),
    ]);

    expect(
      answers.map((answer) => (answer.outcome === 'accepted' ? answer.invitation.status : answer.outcome)).sort(),
    ).toEqual(['ACCEPTED', 'AWAITING_CONFIRMATION']);
  });

  it('reads whether the organisation is empty only once it holds the first admin’s lock', async () => {
    const org = await emptyOrganization();
    const { token } = await firstAdmin(org);
    const invitee = await person();
    const someone = await person(null);
    // Another first admin's acceptance, part-way: the lock taken, their directory entry written, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [
        `agentx.first-admin:${org}`,
      ]);
      await holder.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
        someone.userId,
        org,
        ids.next(),
      ]);
      const accepting = within(20_000, accept(invitee, token), 'the acceptance');
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('commit');

      expect(await accepting).toMatchObject({ outcome: 'accepted', invitation: { status: 'AWAITING_CONFIRMATION' } });
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('keeps them waiting for an admin once someone belongs to the organisation', async () => {
    const who = await organization();
    const { token } = await firstAdmin(who.org);
    const invitee = await person();

    expect(await accept(invitee, token)).toMatchObject({
      outcome: 'accepted',
      invitation: { status: 'AWAITING_CONFIRMATION' },
    });
    expect(await membershipOfPerson(who.org, invitee.userId)).toEqual({ outcome: 'none' });
  });

  it('keeps them waiting too when the only member there was deactivated: the organisation isn’t new', async () => {
    const org = await emptyOrganization();
    const earlier = await person(null);
    const membershipId = ids.next();
    await withSignedStates(app, org, services(), async (tx, states) => {
      await addMembership(tx, states, {
        orgId: org,
        id: membershipId,
        userId: earlier.userId,
        role: 'admin',
        joinedAt: clock.now(),
        actor: OPERATOR,
      });
    });
    await withSignedStates(app, org, services(), (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );
    const { token } = await firstAdmin(org);

    expect(await accept(await person(), token)).toMatchObject({ invitation: { status: 'AWAITING_CONFIRMATION' } });
  });

  it('refuses another address, as any invitation does', async () => {
    const org = await emptyOrganization();
    const { token } = await firstAdmin(org);

    expect(await accept(await person('someone.else@example.test'), token)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'INVITATION_INVALID',
    });
  });

  it('refuses an address that isn’t one, and a hash that isn’t 32 bytes, before writing anything', async () => {
    const org = await emptyOrganization();
    const invite = (email: string, tokenHash: Buffer) =>
      withSignedStates(app, org, services(), (tx, states) =>
        inviteFirstAdmin(tx, states, keys, {
          orgId: org,
          id: ids.next(),
          email,
          tokenHash,
          createdAt: clock.now(),
          actor: OPERATOR,
        }),
      );

    await expect(invite('not an address', inviteTokenHash('t'))).rejects.toThrow('the address is not one');
    await expect(invite('sara@example.test', Buffer.alloc(31))).rejects.toThrow('is not 32 bytes');
    const rows = await database.as('backup').query('select 1 from identity.invitations where org_id = $1', [org]);
    expect(rows).toEqual([]);
  });

  it.each([
    ['a viewer’s invitation naming no member who asked', 'viewer', null, null],
    ['an admin’s naming no member but a step-up', 'admin', null, 'step-up'],
    ['an admin’s naming a member but no step-up', 'admin', 'member', null],
  ] as const)('the table refuses %s (0020)', async (_what, role, invitedBy, challenge) => {
    const who = await organization();
    const owner = await tamperAsOwner(database, INVITATIONS, who.org);
    try {
      const insert = owner.query(
        `insert into identity.invitations (org_id, id, role, status, invited_by, expires_at, created_at,
           email_ciphertext, email_key_version, step_up_challenge_id)
         values ($1, $2, $3, 'DRAFT', $4, $5, $6, $7, 1, $8)`,
        [
          who.org,
          ids.next(),
          role,
          invitedBy === null ? null : who.admin,
          new Date(START.getTime() + 3_600_000),
          START,
          Buffer.alloc(40),
          challenge === null ? null : ids.next(),
        ],
      );

      await expect(insert).rejects.toMatchObject({ code: '23514', constraint: 'asked_by_a_member_or_the_operator' });
    } finally {
      await owner.end();
    }
  });

  it('refuses the operator’s invitation put down to a member since, as INTEGRITY_FAILED: who asked is sealed', async () => {
    const who = await organization();
    const { id, token } = await firstAdmin(who.org);
    const owner = await tamperAsOwner(database, INVITATIONS, who.org);
    try {
      // Both at once, as the table's check holds them together (0020).
      await owner.query(
        'update identity.invitations set invited_by = $3, step_up_challenge_id = $4 where org_id = $1 and id = $2',
        [who.org, id, who.admin, ids.next()],
      );
    } finally {
      await owner.end();
    }

    expect(await accept(await person(), token)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });
});
