// B4-4d: confirming or declining who accepted an admin's or approver's
// invitation, through the use case the API's routes call, on the real
// migrated schema, as the app role (ADR-005 §6, SEC-HA-08): the idempotency
// store, the step-up challenge, the invitation and the membership. The
// routes' answers are apps/api's invitations.test.ts.
import { createHash } from 'node:crypto';

import { createDatabase, type Database, type IdempotentRequest, TenantContextError } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import {
  type AcceptanceConfirmations,
  APPROVE_CONFIRM_OPERATION,
  APPROVE_OPERATION,
  createAcceptanceConfirmations,
  DECLINE_OPERATION,
} from './confirming.ts';
import {
  acceptInvitation,
  draftInvitation,
  invitationChange,
  invitationRecord,
  INVITATIONS,
  invitationToOpen,
  openInvitation,
} from './invitations.ts';
import type { InvitingAdmin } from './inviting.ts';
import { addMembership, membershipFor, MEMBERSHIPS } from './memberships.ts';
import { createSessions } from './sessions.ts';
import { createStepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xf000_0000_0000);
const START = new Date('2026-09-25T09:00:00Z');
let clock: FixedClock;
let confirmations: AcceptanceConfirmations;
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

let people = 0;
/** A person signed in, with a session. */
async function signedIn(): Promise<{ userId: string; sessionId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `confirming-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'otp', 'mfa'],
  });
  return { userId, sessionId };
}

/** A member of the organisation with this role, signed in. */
async function member(org: string, role: Role): Promise<InvitingAdmin & { membershipId: string }> {
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

async function organization(): Promise<{ org: string; admin: InvitingAdmin & { membershipId: string } }> {
  const org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return { org, admin: await member(org, 'admin') };
}

/** An invitation for this role, opened and accepted by a new person: waiting for an admin, for the roles that do. */
async function accepted(
  { org, admin }: { org: string; admin: InvitingAdmin & { membershipId: string } },
  role: Role = 'approver',
  by: string | null = null,
): Promise<{ id: string; invitee: string }> {
  const id = ids.next();
  const actor = { type: 'user' as const, id: admin.userId };
  const { change } = invitationChange({
    orgId: org,
    id,
    email: 'sara@example.test',
    role,
    invitedBy: admin.membershipId,
    createdAt: clock.now(),
  });
  const invitee = by ?? (await signedIn()).userId;
  await withSignedStates(app, org, services(), (tx, states) =>
    draftInvitation(tx, states, keys, change, { stepUpChallengeId: ids.next(), createdAt: clock.now(), actor }),
  );
  await withSignedStates(app, org, services(), async (tx, states) => {
    await invitationToOpen(tx, states, keys, { orgId: org, id, now: clock.now() });
    await openInvitation(tx, states, { orgId: org, id, actor, details: {} });
  });
  await withSignedStates(app, org, services(), (tx, states) =>
    acceptInvitation(tx, states, { orgId: org, id, userId: invitee, actor: { type: 'user', id: invitee } }),
  );
  return { id, invitee };
}

const keyed = (admin: InvitingAdmin, operation: string, key: string, payload = '{}'): IdempotentRequest => ({
  orgId: admin.orgId,
  client: { kind: 'user', id: admin.userId },
  operation,
  key,
  payload,
});

const ask = (admin: InvitingAdmin, id: string, key = 'ask-1') =>
  confirmations.ask(admin, keyed(admin, APPROVE_OPERATION, key, id), id, CORRELATION);
const confirm = (admin: InvitingAdmin, id: string, challengeId: string, key = 'confirm-1') =>
  confirmations.confirm(admin, keyed(admin, APPROVE_CONFIRM_OPERATION, key, challengeId), id, challengeId, CORRELATION);
const decline = (admin: InvitingAdmin, id: string, key = 'decline-1') =>
  confirmations.decline(admin, keyed(admin, DECLINE_OPERATION, key, id), id, CORRELATION);

/** The admin signs in again for the challenge, as the step-up's return records it. */
const stepUp = (admin: InvitingAdmin, challengeId: string) =>
  challenges().recordEvidence(app, challengeId, admin.sessionId, {
    authTime: clock.now(),
    amr: ['pwd', 'user', 'mfa'],
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

/** Asks, and gives back the challenge. */
async function asked(admin: InvitingAdmin, id: string): Promise<string> {
  const answer = await ask(admin, id);
  if (answer.outcome !== 'asked') throw new Error(`not asked: ${answer.outcome}`);
  return answer.stepUpChallengeId;
}

const statusOf = async (org: string, id: string) => {
  const read = await withSignedStates(app, org, services(), (tx, states) => invitationRecord(tx, states, org, id));
  return read.outcome === 'found' ? read.invitation.status : read.outcome;
};

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
  confirmations = createAcceptanceConfirmations({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    logger: loggerFor(new LogCapture()),
  });
});

describe(`confirming who accepted an admin's or approver's invitation (B4-4d, SEC-HA-08, Postgres ${server.version})`, () => {
  it('opens a step-up for the admin’s own session, bound to the confirmation', async () => {
    const who = await organization();
    const { id } = await accepted(who);

    const challengeId = await asked(who.admin, id);

    expect(await challenges().pending(app, challengeId, who.admin.sessionId)).toMatchObject({
      userId: who.admin.userId,
      action: 'members.approve',
    });
    // A retry with the same key answers with the same challenge.
    expect(await ask(who.admin, id)).toEqual({ outcome: 'asked', stepUpChallengeId: challengeId });
  });

  it.each(['approver', 'admin'] as const)(
    'adds the %s who accepted once the admin has signed in again, the evidence on the invitation’s event',
    async (role) => {
      const who = await organization();
      const { id, invitee } = await accepted(who, role);
      const challengeId = await asked(who.admin, id);
      await stepUp(who.admin, challengeId);

      const confirmed = await confirm(who.admin, id, challengeId);

      expect(confirmed).toMatchObject({
        outcome: 'written',
        invitation: { id, status: 'ACCEPTED', acceptedBy: invitee },
      });
      expect(await membershipFor(app, services(), who.org, invitee)).toMatchObject({ outcome: 'active', role });
      const events = await database
        .as('backup')
        .query("select actor_id, details from audit.events where subject_id = $1 and action = 'invitation.confirmed'", [
          id,
        ]);
      expect(events).toHaveLength(1);
      const [event] = events as { actor_id: string; details: string }[];
      expect(event?.actor_id).toBe(who.admin.userId);
      expect(JSON.parse(event?.details ?? '{}')).toMatchObject({
        role,
        stepUpChallengeId: challengeId,
        signedInAt: START.toISOString(),
        methods: 'pwd user mfa',
        proofHash: createHash('sha256').update('an ID token').digest('hex'),
        verifiedAt: START.toISOString(),
        statusFrom: 'AWAITING_CONFIRMATION',
        statusTo: 'ACCEPTED',
      });
      expect(JSON.parse(event?.details ?? '{}')).toHaveProperty('changeHash', expect.stringMatching(/^[0-9a-f]{64}$/));
      // Consumed: gone.
      expect(await challenges().pending(app, challengeId, who.admin.sessionId)).toBeUndefined();
      // A retry with the same key answers as the first, adding no second membership.
      expect(await confirm(who.admin, id, challengeId)).toEqual(confirmed);
    },
  );

  it('brings back a person deactivated there, as the approver they were invited as, only once confirmed (B4-5c)', async () => {
    const who = await organization();
    const returning = await member(who.org, 'viewer');
    await withSignedStates(app, who.org, services(), (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: who.org, id: returning.membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );
    const { id } = await accepted(who, 'approver', returning.userId);
    expect(await membershipFor(app, services(), who.org, returning.userId)).toEqual({
      outcome: 'deactivated',
      id: returning.membershipId,
    });
    const challengeId = await asked(who.admin, id);
    await stepUp(who.admin, challengeId);

    expect(await confirm(who.admin, id, challengeId)).toMatchObject({
      outcome: 'written',
      invitation: { status: 'ACCEPTED' },
    });
    expect(await membershipFor(app, services(), who.org, returning.userId)).toEqual({
      outcome: 'active',
      id: returning.membershipId,
      role: 'approver',
    });
  });

  it('refuses a person active there already as ALREADY_A_MEMBER', async () => {
    const who = await organization();
    const already = await member(who.org, 'viewer');
    const { id } = await accepted(who, 'approver', already.userId);
    const challengeId = await asked(who.admin, id);
    await stepUp(who.admin, challengeId);

    expect(await confirm(who.admin, id, challengeId)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'ALREADY_A_MEMBER',
    });
  });

  it('refuses before the admin signs in again, leaving the person waiting; the same key confirms after', async () => {
    const who = await organization();
    const { id, invitee } = await accepted(who);
    const challengeId = await asked(who.admin, id);

    expect(await confirm(who.admin, id, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await statusOf(who.org, id)).toBe('AWAITING_CONFIRMATION');
    expect(await membershipFor(app, services(), who.org, invitee)).toEqual({ outcome: 'none' });

    await stepUp(who.admin, challengeId);
    expect(await confirm(who.admin, id, challengeId)).toMatchObject({ outcome: 'written' });
  });

  it('refuses another admin with the first one’s challenge', async () => {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const { id } = await accepted(who);
    const challengeId = await asked(who.admin, id);
    await stepUp(who.admin, challengeId);

    expect(await confirm(other, id, challengeId)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
  });

  it('refuses a challenge for another invitation', async () => {
    const who = await organization();
    const first = await accepted(who);
    const second = await accepted(who);
    const challengeId = await asked(who.admin, first.id);
    await stepUp(who.admin, challengeId);

    expect(await confirm(who.admin, second.id, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
  });

  it('refuses anyone but an active admin', async () => {
    const who = await organization();
    const approver = await member(who.org, 'approver');
    const { id } = await accepted(who);

    expect(await ask(approver, id)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await decline(approver, id)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await confirm(approver, id, ids.next())).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
  });

  it('refuses one not waiting: still open, or decided already, as INVITATION_CLOSED; one not there as NOT_FOUND', async () => {
    const who = await organization();
    const openId = ids.next();
    const actor = { type: 'user' as const, id: who.admin.userId };
    const { change } = invitationChange({
      orgId: who.org,
      id: openId,
      email: 'sara@example.test',
      role: 'approver',
      invitedBy: who.admin.membershipId,
      createdAt: clock.now(),
    });
    await withSignedStates(app, who.org, services(), (tx, states) =>
      draftInvitation(tx, states, keys, change, { stepUpChallengeId: ids.next(), createdAt: clock.now(), actor }),
    );

    expect(await ask(who.admin, openId)).toEqual({ outcome: 'refused', status: 409, code: 'INVITATION_CLOSED' });
    expect(await ask(who.admin, ids.next(), 'ask-2')).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
  });

  it('declines, with no step-up: DECLINED, no membership, and no confirmation after', async () => {
    const who = await organization();
    const { id, invitee } = await accepted(who);
    const challengeId = await asked(who.admin, id);
    await stepUp(who.admin, challengeId);

    expect(await decline(who.admin, id)).toMatchObject({ outcome: 'written', invitation: { id, status: 'DECLINED' } });
    expect(await confirm(who.admin, id, challengeId)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'INVITATION_CLOSED',
    });
    expect(await membershipFor(app, services(), who.org, invitee)).toEqual({ outcome: 'none' });
    expect(await decline(who.admin, id, 'decline-2')).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'INVITATION_CLOSED',
    });
  });

  it('refuses a person who joined some other way since as ALREADY_A_MEMBER, leaving them waiting', async () => {
    const who = await organization();
    const { id, invitee } = await accepted(who);
    const challengeId = await asked(who.admin, id);
    await stepUp(who.admin, challengeId);
    await withSignedStates(app, who.org, services(), (tx, states) =>
      addMembership(tx, states, {
        orgId: who.org,
        id: ids.next(),
        userId: invitee,
        role: 'viewer',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );

    expect(await confirm(who.admin, id, challengeId)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'ALREADY_A_MEMBER',
    });
    expect(await statusOf(who.org, id)).toBe('AWAITING_CONFIRMATION');
  });

  it('refuses an invitation tampered with as INTEGRITY_FAILED: the person put down to another', async () => {
    const who = await organization();
    const { id } = await accepted(who);
    const other = (await signedIn()).userId;
    const owner = await tamperAsOwner(database, INVITATIONS, who.org);
    try {
      await owner.setColumn(id, 'accepted_by', other);
    } finally {
      await owner.end();
    }

    expect(await ask(who.admin, id)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('refuses the same key for another request', async () => {
    const who = await organization();
    const { id } = await accepted(who);
    await ask(who.admin, id);

    expect(
      await confirmations.ask(who.admin, keyed(who.admin, APPROVE_OPERATION, 'ask-1', 'other'), id, CORRELATION),
    ).toEqual({
      outcome: 'conflict',
    });
  });
});

describe(`confirming, the harder cases (B4-4d, Postgres ${server.version})`, () => {
  /** Changes a column of a row as the database's owner, past the app. */
  async function asOwner(
    table: typeof INVITATIONS | typeof MEMBERSHIPS,
    org: string,
    id: string,
    column: string,
    value: string,
  ) {
    const owner = await tamperAsOwner(database, table, org);
    try {
      await owner.setColumn(id, column, value);
    } finally {
      await owner.end();
    }
  }

  it('refuses an ask from a session ended since as UNAUTHENTICATED', async () => {
    const who = await organization();
    const { id } = await accepted(who);
    await app.deleteFrom('identity.sessions').where('id', '=', who.admin.sessionId).execute();

    expect(await ask(who.admin, id)).toEqual({ outcome: 'refused', status: 401, code: 'UNAUTHENTICATED' });
  });

  it('refuses an admin whose own membership was tampered with, as INTEGRITY_FAILED', async () => {
    const who = await organization();
    const { id } = await accepted(who);
    const viewer = await member(who.org, 'viewer');
    await asOwner(MEMBERSHIPS, who.org, viewer.membershipId, 'role', 'admin');

    expect(await ask(viewer, id)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('refuses to add someone whose membership there was tampered with, as INTEGRITY_FAILED', async () => {
    const who = await organization();
    const { id, invitee } = await accepted(who);
    const challengeId = await asked(who.admin, id);
    await stepUp(who.admin, challengeId);
    const membershipId = ids.next();
    await withSignedStates(app, who.org, services(), (tx, states) =>
      addMembership(tx, states, {
        orgId: who.org,
        id: membershipId,
        userId: invitee,
        role: 'viewer',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    await asOwner(MEMBERSHIPS, who.org, membershipId, 'role', 'admin');

    expect(await confirm(who.admin, id, challengeId)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });

  it('withholds a retry’s answer when the invitation was tampered with since', async () => {
    const who = await organization();
    const { id } = await accepted(who);
    await decline(who.admin, id);
    await asOwner(INVITATIONS, who.org, id, 'role', 'admin');

    expect(await decline(who.admin, id)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('refuses the same key for another confirmation or decline', async () => {
    const who = await organization();
    const { id } = await accepted(who);
    const challengeId = await asked(who.admin, id);
    await stepUp(who.admin, challengeId);
    await confirm(who.admin, id, challengeId);
    const { id: other } = await accepted(who);
    await decline(who.admin, other);

    expect(
      await confirmations.confirm(
        who.admin,
        keyed(who.admin, APPROVE_CONFIRM_OPERATION, 'confirm-1', 'other'),
        id,
        challengeId,
        CORRELATION,
      ),
    ).toEqual({ outcome: 'conflict' });
    expect(
      await confirmations.decline(
        who.admin,
        keyed(who.admin, DECLINE_OPERATION, 'decline-1', 'other'),
        other,
        CORRELATION,
      ),
    ).toEqual({ outcome: 'conflict' });
  });

  it('throws on, never answers, a failure that is no refusal: a key claimed for another organisation', async () => {
    const who = await organization();
    const elsewhere = await organization();
    const { id } = await accepted(who);

    await expect(
      confirmations.ask(
        who.admin,
        { ...keyed(who.admin, APPROVE_OPERATION, 'ask-1', id), orgId: elsewhere.org },
        id,
        CORRELATION,
      ),
    ).rejects.toBeInstanceOf(TenantContextError);
  });
});

describe(`confirming at the same moment (B4-4d, Postgres ${server.version})`, () => {
  it('adds a person once when their two waiting invitations are confirmed at the same moment', async () => {
    const who = await organization();
    const other = await member(who.org, 'admin');
    const first = await accepted(who, 'approver');
    const second = await accepted(who, 'admin', first.invitee);
    const firstChallenge = await asked(who.admin, first.id);
    const secondChallenge = await asked(other, second.id);
    await stepUp(who.admin, firstChallenge);
    await stepUp(other, secondChallenge);

    const answers = await Promise.all([
      confirm(who.admin, first.id, firstChallenge),
      confirm(other, second.id, secondChallenge),
    ]);

    expect(answers.map((answer) => answer.outcome).sort()).toEqual(['refused', 'written']);
    expect(answers).toContainEqual({ outcome: 'refused', status: 409, code: 'ALREADY_A_MEMBER' });
    const entries = await database
      .as('backup')
      .query('select 1 from directory.members where user_id = $1', [first.invitee]);
    expect(entries).toHaveLength(1);
  });
});
