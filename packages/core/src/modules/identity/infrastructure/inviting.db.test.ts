// B4-3b: inviting a member through the use case the API's routes call, on the real migrated
// schema, as the app role: the idempotency store, the step-up challenge and
// the invitation in one transaction each. The routes' answers are
// apps/api's invitations.test.ts; the invitation's own table is invitations.db.test.ts.
import { createHash } from 'node:crypto';

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
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import { invitationChange, INVITATIONS } from './invitations.ts';
import { createInvitationWrites, type InvitationWrites, type InvitingAdmin } from './inviting.ts';
import { addMembership, MEMBERSHIPS } from './memberships.ts';
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
const ids = new SequentialIds(0xd000_0000_0000);
const START = new Date('2026-09-25T09:00:00Z');
let clock: FixedClock;
let capture: LogCapture;
let writes: InvitationWrites;
const challenges = () => createStepUpChallenges({ ids, clock });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';

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
    { issuer: 'https://auth.example.test', subject: `writes-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: ['pwd', 'otp', 'mfa'],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
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

const INVITED = { email: 'Sara@Example.test', role: 'developer' as Role };

const ask = (admin: InvitingAdmin, key = 'ask-1', invited = INVITED) =>
  writes.ask(admin, keyed(admin, 'members.invite', key, JSON.stringify(invited)), invited, CORRELATION);

const confirm = (admin: InvitingAdmin, id: string, key = 'confirm-1') =>
  writes.confirm(admin, keyed(admin, 'members.invite.confirm', key, id), id, CORRELATION);

/** The admin signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (admin: InvitingAdmin, challengeId: string) =>
  challenges().recordEvidence(app, challengeId, admin.sessionId, {
    authTime: clock.now(),
    amr: ['pwd', 'otp', 'mfa'],
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

/** Asks for an invitation, and gives back its ID and challenge. */
async function drafted(admin: InvitingAdmin, key = 'ask-1') {
  const asked = await ask(admin, key);
  if (asked.outcome !== 'written') throw new Error(`not asked: ${asked.outcome}`);
  const challengeId = asked.invitation.stepUpChallengeId;
  if (challengeId === null) throw new Error('a member’s invitation names no step-up');
  return { id: asked.invitation.id, challengeId };
}

const statusOf = async (org: string, id: string) =>
  withTenant(app, org, (tx) =>
    tx.selectFrom('identity.invitations').select('status').where('id', '=', id).executeTakeFirst(),
  );

const eventsAbout = (org: string, id: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_id', 'details'])
      .where('subject_id', '=', id)
      .orderBy('seq')
      .execute(),
  );

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
  writes = createInvitationWrites({
    database: app,
    keys,
    ids,
    clock,
    challenges: challenges(),
    logger: loggerFor(capture),
  });
});

describe(`asking for an invitation (B4-3b, Postgres ${server.version})`, () => {
  it('keeps a DRAFT, and opens a challenge for the admin’s session, bound to the invitation’s change', async () => {
    const { org, admin } = await organization();

    const asked = await ask(admin);

    if (asked.outcome !== 'written') throw new Error(`not asked: ${asked.outcome}`);
    expect(asked).toMatchObject({ status: 202, invitation: { role: 'developer', status: 'DRAFT' } });
    const pending = await challenges().pending(app, asked.invitation.stepUpChallengeId ?? '', admin.sessionId);
    const { changeHash } = invitationChange({
      orgId: org,
      id: asked.invitation.id,
      ...INVITED,
      invitedBy: admin.membershipId,
      createdAt: START,
    });
    expect(pending).toMatchObject({ userId: admin.userId, action: 'members.invite' });
    expect(pending?.changeHash.equals(changeHash)).toBe(true);
    expect(await eventsAbout(org, asked.invitation.id)).toEqual([
      expect.objectContaining({ action: 'invitation.drafted', actor_id: admin.userId }),
    ]);
  });

  it('answers a retry with the same key as the first, keeping one draft', async () => {
    const { org, admin } = await organization();
    const first = await ask(admin);

    const again = await ask(admin);

    expect(again).toEqual(first);
    const rows = await withTenant(app, org, (tx) => tx.selectFrom('identity.invitations').select('id').execute());
    expect(rows).toHaveLength(1);
  });

  it('refuses the same key for another invitation', async () => {
    const { admin } = await organization();
    await ask(admin);

    expect(await ask(admin, 'ask-1', { email: 'other@example.test', role: 'viewer' })).toEqual({ outcome: 'conflict' });
  });

  it('refuses anyone no longer an admin there, writing nothing and keeping no answer for the key', async () => {
    const { org } = await organization();
    const viewer = await member(org, 'viewer');

    expect(await ask(viewer)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });

    const rows = await withTenant(app, org, (tx) => tx.selectFrom('identity.invitations').select('id').execute());
    expect(rows).toEqual([]);
    const kept = await database.as('backup').query('select 1 from idempotency.keys where org_id = $1', [org]);
    expect(kept).toEqual([]);
  });

  it('refuses a session ended since, as UNAUTHENTICATED, writing nothing', async () => {
    const { org, admin } = await organization();
    await app.deleteFrom('identity.sessions').where('id', '=', admin.sessionId).execute();

    expect(await ask(admin)).toEqual({ outcome: 'refused', status: 401, code: 'UNAUTHENTICATED' });
    const rows = await withTenant(app, org, (tx) => tx.selectFrom('identity.invitations').select('id').execute());
    expect(rows).toEqual([]);
  });
});

describe(`confirming an invitation (B4-3b, Postgres ${server.version})`, () => {
  it('opens it once the admin has signed in again, with the token this once and the evidence on its event', async () => {
    const { org, admin } = await organization();
    const { id, challengeId } = await drafted(admin);
    expect(await stepUp(admin, challengeId)).toBe(true);

    const confirmed = await confirm(admin, id);

    if (confirmed.outcome !== 'written') throw new Error(`not confirmed: ${confirmed.outcome}`);
    expect(confirmed).toMatchObject({ status: 200, invitation: { id, status: 'OPEN' } });
    expect(confirmed.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const [entry] = await withTenant(app, org, (tx) =>
      tx.selectFrom('directory.invites').select('token_hash').where('invitation_id', '=', id).execute(),
    );
    expect(
      entry?.token_hash.equals(
        createHash('sha256')
          .update(confirmed.token ?? '', 'ascii')
          .digest(),
      ),
    ).toBe(true);
    const [, opened] = await eventsAbout(org, id);
    expect(opened).toMatchObject({ action: 'invitation.opened', actor_id: admin.userId });
    expect(JSON.parse(opened?.details ?? '{}')).toMatchObject({
      stepUpChallengeId: challengeId,
      signedInAt: START.toISOString(),
      methods: 'pwd otp mfa',
      proofHash: createHash('sha256').update('an ID token').digest('hex'),
      changeHash: invitationChange({
        orgId: org,
        id,
        ...INVITED,
        invitedBy: admin.membershipId,
        createdAt: START,
      }).changeHash.toString('hex'),
      verifiedAt: START.toISOString(),
      statusFrom: 'DRAFT',
      statusTo: 'OPEN',
    });
    // Consumed: gone.
    expect(await challenges().pending(app, challengeId, admin.sessionId)).toBeUndefined();
  });

  it('answers a retry with the same key without the token, and another key as closed', async () => {
    const { admin } = await organization();
    const { id, challengeId } = await drafted(admin);
    await stepUp(admin, challengeId);
    await confirm(admin, id);

    const again = await confirm(admin, id);

    expect(again).toMatchObject({ outcome: 'written', status: 200, invitation: { id, status: 'OPEN' } });
    expect(again).not.toHaveProperty('token');
    expect(await confirm(admin, id, 'confirm-2')).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'INVITATION_CLOSED',
    });
  });

  it('refuses before the admin signs in again, leaving the draft, and confirms with the same key after', async () => {
    const { org, admin } = await organization();
    const { id, challengeId } = await drafted(admin);

    expect(await confirm(admin, id)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect(await statusOf(org, id)).toEqual({ status: 'DRAFT' });

    await stepUp(admin, challengeId);
    expect(await confirm(admin, id)).toMatchObject({ outcome: 'written', invitation: { status: 'OPEN' } });
  });

  it('refuses another admin, who didn’t step up for it in their own session', async () => {
    const { org, admin } = await organization();
    const other = await member(org, 'admin');
    const { id, challengeId } = await drafted(admin);
    await stepUp(admin, challengeId);

    expect(await confirm(other, id)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect(await statusOf(org, id)).toEqual({ status: 'DRAFT' });
  });

  it('refuses the admin once deactivated, though stepped up', async () => {
    const { org, admin } = await organization();
    const { id, challengeId } = await drafted(admin);
    await stepUp(admin, challengeId);
    await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: admin.membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );

    expect(await confirm(admin, id)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
  });

  it('refuses one not in the organisation as NOT_FOUND', async () => {
    const { admin } = await organization();

    expect(await confirm(admin, ids.next())).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
  });

  it('refuses one past its end as closed', async () => {
    const { admin } = await organization();
    const { id, challengeId } = await drafted(admin);
    await stepUp(admin, challengeId);
    clock.advanceBy(72 * 3_600_000);

    expect(await confirm(admin, id)).toEqual({ outcome: 'refused', status: 409, code: 'INVITATION_CLOSED' });
  });
});

describe(`records that can't be believed (B4-3b, Postgres ${server.version})`, () => {
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

  it('refuses to ask as an admin whose membership was tampered with, as INTEGRITY_FAILED', async () => {
    const { org } = await organization();
    const viewer = await member(org, 'viewer');
    await asOwner(MEMBERSHIPS, org, viewer.membershipId, 'role', 'admin');

    expect(await ask(viewer)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('refuses to confirm an invitation whose role was raised, as INTEGRITY_FAILED, leaving the step-up', async () => {
    const { org, admin } = await organization();
    const { id, challengeId } = await drafted(admin);
    await stepUp(admin, challengeId);
    await asOwner(INVITATIONS, org, id, 'role', 'admin');

    expect(await confirm(admin, id)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    // Not consumed: the change it stood for never happened.
    expect(
      await database.as('backup').query('select id from identity.step_up_challenges where id = $1', [challengeId]),
    ).toEqual([{ id: challengeId }]);
    const [left] = await withTenant(app, org, (tx) =>
      tx.selectFrom('directory.invites').select('invitation_id').where('invitation_id', '=', id).execute(),
    );
    expect(left).toBeUndefined();
  });

  it('withholds a retry’s answer when the invitation was tampered with since, as INTEGRITY_FAILED', async () => {
    const { org, admin } = await organization();
    const { id } = await drafted(admin);
    await asOwner(INVITATIONS, org, id, 'role', 'admin');

    expect(await ask(admin)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('throws on, never answers, a failure that is no refusal: a key claimed for another organisation', async () => {
    const { admin } = await organization();
    const elsewhere = await organization();

    await expect(
      writes.ask(admin, { ...keyed(admin, 'members.invite', 'ask-1'), orgId: elsewhere.org }, INVITED, CORRELATION),
    ).rejects.toBeInstanceOf(TenantContextError);
  });
});

describe(`a write's answer gives up after 10 seconds rather than hold the request (B4-3b, Postgres ${server.version})`, () => {
  it('the answer’s read of the invitation, on a retry', async () => {
    const { admin } = await organization();
    await ask(admin);

    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table identity.invitations in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, ask(admin), 'the retry')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});
