// B4-4c: accepting an invitation through the use case the API's route calls,
// on the real migrated schema, as the app role: the directory's lookup, the
// idempotency store, the invitation and the membership, in the invitation's
// own organisation (SEC-HA-08, SEC-TEN-04). The route's answers are
// apps/api's invitations.test.ts.
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
import { INVITATION_HOURS } from '../domain/invitation.ts';
import type { Role } from '../domain/membership.ts';
import {
  ACCEPT_OPERATION,
  type AcceptingPerson,
  createInvitationAcceptance,
  type InvitationAcceptance,
} from './accepting.ts';
import { draftInvitation, invitationChange, INVITATIONS, invitationToOpen, openInvitation } from './invitations.ts';
import { addMembership, membersFor, membershipFor, MEMBERSHIPS } from './memberships.ts';
import { recordSessionEmail } from './session-emails.ts';
import { createSessions } from './sessions.ts';
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
  acceptance = createInvitationAcceptance({ database: app, keys, ids, clock, logger: loggerFor(capture) });
});

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

  it.each(['viewer', 'admin'] as const)(
    'refuses someone whose membership there was deactivated, invited as %s, as ALREADY_A_MEMBER: rejoining is B4-5’s',
    async (role) => {
      const who = await organization();
      const { token } = await invitation(who, role);
      const member = await person();
      const membershipId = ids.next();
      await withSignedStates(app, who.org, services(), async (tx, states) => {
        await addMembership(tx, states, {
          orgId: who.org,
          id: membershipId,
          userId: member.userId,
          role: 'viewer',
          joinedAt: clock.now(),
          actor: OPERATOR,
        });
      });
      await withSignedStates(app, who.org, services(), (tx, states) =>
        states.changeStatus(tx, MEMBERSHIPS, { orgId: who.org, id: membershipId }, 'deactivate', {
          actor: OPERATOR,
          action: 'membership.deactivated',
          details: {},
        }),
      );

      expect(await accept(member, token)).toEqual({ outcome: 'refused', status: 409, code: 'ALREADY_A_MEMBER' });
    },
  );

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
