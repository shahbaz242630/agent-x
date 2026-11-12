// A membership's grant summary (OR1, 0085; ADR-012 §1, SEC-PAY-04), on the
// real migrated schema as the app role: kept with each membership change, read
// by the two-person rule in place of the whole history, built from the
// history for a membership added before it (the backfill), and, as the
// database's owner past the app (FX-TAMPER, tamperAsOwner), never believed
// once changed, deleted or left behind by its membership: the alarm, the
// hold, and nothing decided. The live schema guard, with the product's own
// list, is clean before each case.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { createDatabase, type Database, liveSchemaProblems } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { sql } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import {
  type AuditTables,
  createAuditTrail,
  keepHoldWaitingHere,
  type SignedStates,
  TooManyEventsToRead,
  withSignedStates,
} from '../../audit/index.ts';
import { type DirectoryTables, registerMember } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import { HISTORY_SUBJECTS, twoPersonFacts } from '../domain/two-person.ts';
import { buildGrantSummaries } from './grant-building.ts';
import { grantsBelieved, grantsToChange, keepGrants, MEMBERSHIP_GRANTS, MOST_ACCEPTED } from './membership-grants.ts';
import {
  addMembership,
  changeMembershipRole,
  deactivateMembership,
  memberOf,
  membersOf,
  MEMBERSHIPS,
  type MembershipsTransaction,
  MOST_MEMBERS,
  reactivateMembership,
  TooManyMembers,
} from './memberships.ts';
import type { IdentityTables } from './tables.ts';
import { leftBehind } from '../membership-changes.helper.test.ts';
import { twoPersonFactsOf } from './two-person-facts.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;
/**
 * Where an image from before OR1 writes a membership past its summary: an image that old ran only before 0089, whose
 * trigger refuses that from the app's role (OR1b), so it is played here on the owner's connection, which 0089 lets by.
 */
let oldImage: Database<Tables>;
let owner: OwnerTamper;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb100_0000_0000);
const trail = createAuditTrail({ keys, ids });
const clock = new FixedClock(new Date('2026-10-01T09:00:00Z'));

let capture: LogCapture;
const services = () => ({ keys, ids, logger: testLogger(capture) });

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const userActor = (id: string) => ({ type: 'user' as const, id });
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

let org: string;
let subjects = 0;

/** A new person, as their first sign-in makes them. */
const person = (): Promise<string> => {
  subjects += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `grants-${String(subjects)}` },
    { ids, clock },
  );
};

interface By {
  readonly type: 'user' | 'system';
  readonly id: string;
}

/** A member added with `role` by `by`, as accepting and confirming add one: its summary with it. */
const add = async (role: Role, by: By = OPERATOR, existing?: string) => {
  const userId = existing ?? (await person());
  const id = ids.next();
  await withSignedStates(app, org, services(), (tx: MembershipsTransaction, states) =>
    addMembership(tx, states, { orgId: org, id, userId, role, joinedAt: clock.now(), actor: by }),
  );
  return { id, userId };
};

/** A member added as before 0085: the membership and its signed state, no summary. */
const addBefore = async (role: Role, by: By = OPERATOR, existing?: string) => {
  const userId = existing ?? (await person());
  const id = ids.next();
  await withSignedStates(app, org, services(), async (tx, states) => {
    await registerMember(tx, { orgId: org, userId, membershipId: id });
    const fields = { user_id: userId, role, status: 'ACTIVE', joined_at: clock.now() };
    await tx
      .insertInto('identity.memberships')
      .values({ org_id: org, id, ...fields })
      .execute();
    await states.record(tx, MEMBERSHIPS, { orgId: org, id }, 'new', fields, {
      actor: by,
      action: 'membership.created',
      details: { role },
    });
  });
  return { id, userId };
};

/** An invitation's events, as its flows record them: asked for by `inviter`, accepted by `invitee`. */
const invited = (inviter: string, invitee: string) =>
  withSignedStates(app, org, services(), async (tx) => {
    const subject = { type: 'invitation', id: ids.next(), version: 1 };
    await trail.record(tx, org, { actor: userActor(inviter), action: 'invitation.drafted', subject, details: {} });
    await trail.record(tx, org, {
      actor: userActor(invitee),
      action: 'invitation.acceptance_recorded',
      subject: { ...subject, version: 2 },
      details: {},
    });
  });

/** The member's membership and grant summary read for a change, as membership-changes.ts reads them. */
const changeRead = async (tx: MembershipsTransaction, states: SignedStates, id: string) => {
  const key = { orgId: org, id };
  const read = await memberOf(tx, states, key, 'change');
  if (read.outcome !== 'found') throw new Error('not found');
  return { key, member: read.member, state: read.state, grants: grantsBelieved(await grantsToChange(tx, states, key)) };
};

/**
 * The member's role changed by `by`, as membership-changes.ts changes it. With
 * `granters`, a writer that forgot who changed it (the disagreement case);
 * with `pause`, held open once recorded until let go.
 */
const changeRole = (
  id: string,
  roleTo: Role,
  by: string,
  {
    granters,
    pause,
  }: { granters?: string[]; pause?: { readonly reached: () => void; readonly until: Promise<void> } } = {},
) =>
  withSignedStates(app, org, services(), async (tx, states) => {
    const read = await changeRead(tx, states, id);
    if (granters === undefined) {
      await changeMembershipRole(tx, states, { ...read, actor: userActor(by), evidence: {}, roleTo });
    } else {
      const recorded = await states.record(
        tx,
        MEMBERSHIPS,
        read.key,
        read.state,
        { role: roleTo },
        {
          actor: userActor(by),
          action: 'membership.role_changed',
          details: { roleFrom: read.member.role, roleTo },
        },
      );
      await keepGrants(tx, states, read.grants, read.key, {
        change: { memberUserId: read.member.userId, granters },
        fromVersion: read.state.version,
        membershipVersion: recorded.version,
        actor: userActor(by),
      });
    }
    // Held open, the membership and its summary locked and recorded, until let go.
    pause?.reached();
    await pause?.until;
  });

/** The member deactivated by `by`, as membership-changes.ts deactivates one. */
const deactivate = (id: string, by: string) =>
  withSignedStates(app, org, services(), async (tx, states) =>
    deactivateMembership(tx, states, { ...(await changeRead(tx, states, id)), actor: userActor(by), evidence: {} }),
  );

const facts = () => withSignedStates(app, org, services(), (tx, states) => twoPersonFactsOf(tx, states, org));
const build = (page?: number) =>
  withSignedStates(app, org, services(), (tx, states) => buildGrantSummaries(tx, states, org, page));
const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));
const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

/** The facts as the whole history says, the way the rule read them before the summaries. */
const historyFacts = () =>
  withSignedStates(app, org, services(), async (tx, states) => {
    const members = await membersOf(tx, states, org);
    const history = await states.historyOf(tx, org, { subjectTypes: HISTORY_SUBJECTS, limit: 100_000 });
    if (members.outcome !== 'listed' || history.outcome !== 'read') throw new Error('not read');
    return twoPersonFacts(members.members, history.events);
  });

/** Facts as the rule compares them: who granted each member's role, sorted, and the latest change to a verifier. */
const shape = (read: Awaited<ReturnType<typeof historyFacts>>) => ({
  grantedBy: Object.fromEntries(
    [...read.grantedBy].map(([id, granters]): [string, string[]] => [id, [...granters].sort()]).sort(),
  ),
  lastVerifierChange: read.lastVerifierChange?.toISOString(),
});

/** The summary rows the organisation holds, by membership. */
const summaryRows = async () =>
  owner.query<{ id: string; granted_by: string; membership_version: number }>(
    'select id, granted_by, membership_version from identity.membership_grants where org_id = $1 order by id',
    [org],
  );

/** Denied, the alarm raised on the summary, and the organisation held. */
async function deniedAndHeld(id: string, sign: string): Promise<void> {
  expect(await facts()).toEqual({ outcome: 'tampered', sign });
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      reason: sign,
      subjectType: 'membership_grant',
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  oldImage = createDatabase<Tables>({ ...database.connection('owner'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await oldImage.destroy();
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owner = await tamperAsOwner(database, MEMBERSHIP_GRANTS, org);
});

afterEach(async () => {
  await owner.end();
});

describe(`a membership's grant summary, kept with each change (OR1, Postgres ${server.version})`, () => {
  it('names who added, invited and changed each member, and when a verifier last went: as the history says', async () => {
    expect(await guard()).toEqual([]);
    const alice = await add('admin');
    const bob = await add('viewer', userActor(alice.userId));
    const dave = await add('admin');
    const carolId = await person();
    await invited(dave.userId, carolId);
    // A declined invitation counts as it always has: Erin accepted Alice's, then joined by Dave's.
    const erinId = await person();
    await invited(alice.userId, erinId);
    await invited(dave.userId, erinId);
    const carol = await add('approver', userActor(carolId), carolId);
    const erin = await add('viewer', userActor(erinId), erinId);
    await changeRole(bob.id, 'approver', alice.userId);
    await changeRole(dave.id, 'developer', alice.userId);
    await deactivate(carol.id, alice.userId);

    const read = await facts();

    expect(read.outcome).toBe('read');
    if (read.outcome !== 'read') return;
    expect(shape(read)).toEqual(shape(await historyFacts()));
    const granters = (id: string) => [...(read.grantedBy.get(id) ?? [])].sort();
    expect(granters(alice.id)).toEqual([]);
    expect(granters(bob.id)).toEqual([alice.userId]);
    expect(granters(carol.id)).toEqual([dave.userId]);
    expect(granters(dave.id)).toEqual([alice.userId]);
    expect(granters(erin.id)).toEqual([alice.userId, dave.userId].sort());
    // Carol's deactivation, the latest change to a verifier, from its own event.
    expect(read.lastVerifierChange).toBeInstanceOf(Date);
    expect(await summaryRows()).toHaveLength(5);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('brings a deactivated member back with who confirmed it and every invitation they accepted', async () => {
    const alice = await add('admin');
    const bob = await add('approver');
    await deactivate(bob.id, alice.userId);
    const dave = await add('admin');
    await invited(dave.userId, bob.userId);
    await withSignedStates(app, org, services(), (tx, states) =>
      reactivateMembership(tx, states, {
        orgId: org,
        id: bob.id,
        role: 'approver',
        joinedAt: clock.now(),
        actor: userActor(alice.userId),
      }),
    );

    const read = await facts();

    expect(read.outcome).toBe('read');
    if (read.outcome !== 'read') return;
    expect([...(read.grantedBy.get(bob.id) ?? [])].sort()).toEqual([alice.userId, dave.userId].sort());
    expect(shape(read)).toEqual(shape(await historyFacts()));
  });

  /** Bob, deactivated, brought back by Alice. */
  const bringBack = (bob: { id: string }, alice: { userId: string }) =>
    withSignedStates(app, org, services(), (tx, states) =>
      reactivateMembership(tx, states, {
        orgId: org,
        id: bob.id,
        role: 'approver',
        joinedAt: clock.now(),
        actor: userActor(alice.userId),
      }),
    );

  it('leaves a summary from before 0085 unbuilt through a removal and a return: the job’s history holds both', async () => {
    const alice = await addBefore('admin');
    const bob = await addBefore('approver');
    await deactivate(bob.id, alice.userId);
    await bringBack(bob, alice);

    expect(await summaryRows()).toEqual([]);
    expect(await facts()).toMatchObject({ outcome: 'read' });
    expect(await build()).toEqual({ outcome: 'built', built: 2 });
    const read = await facts();
    if (read.outcome !== 'read') throw new Error('not read');
    expect(shape(read)).toEqual(shape(await historyFacts()));
  });

  it('refuses to bring back a member whose summary was tampered with, its alarm raised', async () => {
    const alice = await add('admin');
    const bob = await add('approver');
    await deactivate(bob.id, alice.userId);
    await owner.setColumn(bob.id, 'granted_by', alice.userId);

    await expect(bringBack(bob, alice)).rejects.toMatchObject({ name: 'SignedStateFailed', reason: 'tampered' });
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'seal', subjectType: 'membership_grant', objectId: bob.id }),
    ]);
  });

  it('refuses to add a member who accepted more invitations there than one read takes, rather than read part', async () => {
    const userId = await person();
    await withSignedStates(app, org, services(), async (tx) => {
      for (let n = 0; n <= MOST_ACCEPTED; n += 1) {
        await trail.record(tx, org, {
          actor: userActor(userId),
          action: 'invitation.acceptance_recorded',
          subject: { type: 'invitation', id: ids.next(), version: 2 },
          details: {},
        });
      }
    });

    await expect(add('viewer', userActor(userId), userId)).rejects.toBeInstanceOf(TooManyEventsToRead);
  });

  it('counts no one for an invitation the operator’s command asked for: only a person grants a role', async () => {
    const userId = await person();
    await withSignedStates(app, org, services(), async (tx) => {
      const subject = { type: 'invitation', id: ids.next(), version: 1 };
      await trail.record(tx, org, { actor: OPERATOR, action: 'invitation.drafted', subject, details: {} });
      await trail.record(tx, org, {
        actor: userActor(userId),
        action: 'invitation.acceptance_recorded',
        subject: { ...subject, version: 2 },
        details: {},
      });
    });
    const admin = await add('admin', userActor(userId), userId);

    expect(await summaryRows()).toEqual([expect.objectContaining({ id: admin.id, granted_by: '' })]);
  });

  it('refuses an organisation whose log made more memberships than a list holds, rather than decide on part', async () => {
    await withSignedStates(app, org, services(), async (tx) => {
      for (let n = 0; n <= MOST_MEMBERS; n += 1) {
        await trail.record(tx, org, {
          actor: OPERATOR,
          action: 'membership.created',
          subject: { type: 'membership', id: ids.next(), version: 1 },
          details: {},
        });
      }
    });

    await expect(facts()).rejects.toBeInstanceOf(TooManyMembers);
  });

  it('reads nine or more members past one gather, in two statements a table, as well', async () => {
    const alice = await add('admin');
    for (let n = 0; n < 9; n += 1) await add('viewer', userActor(alice.userId));

    const read = await facts();

    expect(read).toMatchObject({ outcome: 'read' });
    if (read.outcome !== 'read') return;
    expect(read.members).toHaveLength(10);
    expect(shape(read)).toEqual(shape(await historyFacts()));
  });
});

describe(`a grant summary changed past the app (FX-TAMPER, Postgres ${server.version})`, () => {
  it('denies a summary emptied of who granted the role: the seal', async () => {
    const alice = await add('admin');
    const bob = await add('approver', userActor(alice.userId));
    await owner.setColumn(bob.id, 'granted_by', '');

    await deniedAndHeld(bob.id, 'seal');
  });

  it('denies a summary whose verifier change was taken away: the seal', async () => {
    const alice = await add('admin');
    const bob = await add('approver');
    await deactivate(bob.id, alice.userId);
    await owner.setColumn(bob.id, 'verifier_changed_at', null);

    await deniedAndHeld(bob.id, 'seal');
  });

  it('denies a summary deleted: its signed state finds it', async () => {
    await add('admin');
    const bob = await add('approver');
    await owner.deleteRow(bob.id);

    await deniedAndHeld(bob.id, 'deleted');
  });

  it('denies a summary put back to an earlier signed state', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    const saved = await owner.saveRow(bob.id);
    await changeRole(bob.id, 'approver', alice.userId);
    await owner.restoreRow(saved);

    expect(await facts()).toMatchObject({ outcome: 'tampered' });
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ subjectType: 'membership_grant', objectId: bob.id }),
    ]);
    expect(await hold()).toMatchObject({ outcome: 'held' });
  });

  it('denies, where the history is read, a kept summary that holds less than it says', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    // Alice's change kept with no one named: signed, at the right version, and short of the history.
    await changeRole(bob.id, 'approver', alice.userId, { granters: [] });
    // One member from before the summaries: the history is read, and the two are held to each other.
    await addBefore('viewer');

    await deniedAndHeld(bob.id, 'holding');
  });

  it('denies a summary ahead of its membership, which no image writes: a mismatch', async () => {
    await add('admin');
    const bob = await add('viewer');
    // Sealed with the app's keys at a version its membership never reached, as only a bug could.
    await withSignedStates(app, org, services(), async (tx, states) => {
      const read = grantsBelieved(await grantsToChange(tx, states, { orgId: org, id: bob.id }));
      if (read.outcome !== 'kept') throw new Error('not kept');
      await states.record(
        tx,
        MEMBERSHIP_GRANTS,
        { orgId: org, id: bob.id },
        read.state,
        { membership_version: 9 },
        { actor: OPERATOR, action: 'membership_grant.kept', details: {} },
      );
    });

    await deniedAndHeld(bob.id, 'holding');
  });
});

describe(`a summary left behind its membership: the alarm since 0089 (OR1c, Postgres ${server.version})`, () => {
  /** Bob's role changed past his summary, as only the owner can since 0089 (an image from before OR1 could before it). */
  const changedByOldImage = (bob: { id: string }, alice: { userId: string }, roleFrom: Role, roleTo: Role) =>
    withSignedStates(oldImage, org, services(), async (tx, states) => {
      const state = await states.verifiedState(tx, MEMBERSHIPS, { orgId: org, id: bob.id }, 'change');
      if (state.outcome !== 'verified') throw new Error('not verified');
      await states.record(
        tx,
        MEMBERSHIPS,
        { orgId: org, id: bob.id },
        state,
        { role: roleTo },
        {
          actor: userActor(alice.userId),
          action: 'membership.role_changed',
          details: { roleFrom, roleTo },
        },
      );
    });

  /** The alarm raised `times` times on the member's summary, as a mismatch. */
  const raisedOn = (id: string, times: number) => {
    const raised = lines('audit.integrity_failed');
    expect(raised).toHaveLength(times);
    for (const line of raised) {
      expect(line).toMatchObject({ reason: 'holding', subjectType: 'membership_grant', objectId: id, orgId: org });
    }
  };

  it('denies and holds, deciding nothing; the job raises it too and brings it up to date', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    await changedByOldImage(bob, alice, 'viewer', 'approver');
    await changedByOldImage(bob, alice, 'approver', 'admin');

    await deniedAndHeld(bob.id, 'holding');

    expect(await build()).toEqual({ outcome: 'built', built: 1 });
    raisedOn(bob.id, 2);
    expect(await summaryRows()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: bob.id, granted_by: alice.userId, membership_version: 3 }),
      ]),
    );
    // In step again: decided as the history says, with no new alarm; the hold stands until someone clears it.
    const after = await facts();
    if (after.outcome !== 'read') throw new Error('not read');
    expect(shape(after)).toEqual(shape(await historyFacts()));
    raisedOn(bob.id, 2);
    expect(await hold()).toMatchObject({ outcome: 'held' });
  });

  it('refuses a change by this image to a membership whose summary is behind, nothing moved', async () => {
    const alice = await add('admin');
    const dave = await add('admin');
    const bob = await add('viewer');
    await changedByOldImage(bob, alice, 'viewer', 'developer');

    await expect(changeRole(bob.id, 'approver', dave.userId)).rejects.toMatchObject({
      name: 'SignedStateFailed',
      reason: 'tampered',
    });
    raisedOn(bob.id, 1);
    expect(await hold()).toMatchObject({ outcome: 'held' });
    const read = await withSignedStates(app, org, services(), (tx, states) =>
      memberOf(tx, states, { orgId: org, id: bob.id }, 'share'),
    );
    expect(read).toMatchObject({ outcome: 'found', member: { role: 'developer' }, state: { version: 2 } });
    expect(await summaryRows()).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: bob.id, granted_by: '', membership_version: 1 })]),
    );
  });

  it('refuses to deactivate a member whose summary is behind, nothing moved', async () => {
    const alice = await add('admin');
    const bob = await add('approver');
    await changedByOldImage(bob, alice, 'approver', 'viewer');

    await expect(deactivate(bob.id, alice.userId)).rejects.toMatchObject({
      name: 'SignedStateFailed',
      reason: 'tampered',
    });
    raisedOn(bob.id, 1);
    const read = await withSignedStates(app, org, services(), (tx, states) =>
      memberOf(tx, states, { orgId: org, id: bob.id }, 'share'),
    );
    expect(read).toMatchObject({ outcome: 'found', member: { status: 'ACTIVE' }, state: { version: 2 } });
  });

  it('keeps one hold waiting in the repair’s own transaction, naming the first behind; the hold set takes it', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    const carol = await add('viewer');
    await changedByOldImage(bob, alice, 'viewer', 'approver');
    await changedByOldImage(carol, alice, 'viewer', 'approver');
    const [first] = [bob.id, carol.id].sort();

    const inRepair = await withSignedStates(app, org, services(), async (tx, states) => {
      const built = await buildGrantSummaries(tx, states, org);
      const waiting = await sql<{ subject_type: string; object_id: string; reason: string }>`
        select subject_type, object_id, reason from directory.holds_waiting where org_id = ${org}`.execute(tx);
      return { built, waiting: waiting.rows };
    });

    expect(inRepair).toEqual({
      built: { outcome: 'built', built: 2 },
      waiting: [{ subject_type: 'membership_grant', object_id: first, reason: 'holding' }],
    });
    expect(lines('audit.integrity_failed').map(({ objectId }) => objectId)).toEqual([bob.id, carol.id].sort());
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'holding', subjectType: 'membership_grant' }),
      expect.objectContaining({ reason: 'holding', subjectType: 'membership_grant' }),
    ]);
    // Committed with the repair; the hold then recorded, naming the same first record, which takes its row with it.
    expect(await hold()).toMatchObject({ outcome: 'held' });
    expect(await database.as('backup').query('select 1 from directory.holds_waiting where org_id = $1', [org])).toEqual(
      [],
    );
  });

  it('refuses to bring back a member whose summary is behind, nothing moved', async () => {
    const alice = await add('admin');
    const bob = await add('approver');
    await deactivate(bob.id, alice.userId);
    await changedByOldImage(bob, alice, 'approver', 'viewer');

    const bringBack = withSignedStates(app, org, services(), (tx, states) =>
      reactivateMembership(tx, states, {
        orgId: org,
        id: bob.id,
        role: 'approver',
        joinedAt: clock.now(),
        actor: userActor(alice.userId),
      }),
    );
    await expect(bringBack).rejects.toMatchObject({ name: 'SignedStateFailed', reason: 'tampered' });
    raisedOn(bob.id, 1);
    const read = await withSignedStates(app, org, services(), (tx, states) =>
      memberOf(tx, states, { orgId: org, id: bob.id }, 'share'),
    );
    expect(read).toMatchObject({ outcome: 'found', member: { status: 'DEACTIVATED' }, state: { version: 3 } });
    expect(await summaryRows()).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: bob.id, membership_version: 2 })]),
    );
  });

  it('refuses to keep a summary found ahead of the version the change started from', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');

    await expect(
      withSignedStates(app, org, services(), async (tx, states) => {
        const read = await changeRead(tx, states, bob.id);
        await keepGrants(tx, states, read.grants, read.key, {
          change: { memberUserId: read.member.userId, granters: [alice.userId] },
          fromVersion: 0,
          membershipVersion: 1,
          actor: userActor(alice.userId),
        });
      }),
    ).rejects.toMatchObject({ name: 'SignedStateFailed', reason: 'tampered' });
    raisedOn(bob.id, 1);
  });
});

describe(`the rule past 10,000 events, and the summaries built for members from before them (Postgres ${server.version})`, () => {
  /** `count` events about invitations, as an organisation with years of them holds. */
  const manyInvitationEvents = (by: string, count: number) =>
    withSignedStates(app, org, services(), async (tx) => {
      for (let n = 0; n < count; n += 1) {
        await trail.record(tx, org, {
          actor: userActor(by),
          action: 'invitation.drafted',
          subject: { type: 'invitation', id: ids.next(), version: 1 },
          details: {},
        });
      }
    });

  it('decides for an organisation with more than 10,000 such events, its history read whole only to build', async () => {
    const alice = await add('admin');
    const bob = await addBefore('approver', userActor(alice.userId));
    await manyInvitationEvents(alice.userId, 10_001);

    // Bob's summary not built yet: the history is read, and it is too long to read whole.
    await expect(facts()).rejects.toBeInstanceOf(TooManyEventsToRead);

    expect(await build()).toEqual({ outcome: 'built', built: 1 });
    const read = await facts();

    expect(read).toMatchObject({ outcome: 'read' });
    if (read.outcome !== 'read') return;
    expect([...(read.grantedBy.get(bob.id) ?? [])]).toEqual([alice.userId]);
    expect(lines('audit.integrity_failed')).toEqual([]);

    // Bob's summary left behind its membership, past the app: the alarm, and the job brings it up to date.
    await withSignedStates(oldImage, org, services(), async (tx, states) => {
      const state = await states.verifiedState(tx, MEMBERSHIPS, { orgId: org, id: bob.id }, 'change');
      if (state.outcome !== 'verified') throw new Error('not verified');
      await states.record(
        tx,
        MEMBERSHIPS,
        { orgId: org, id: bob.id },
        state,
        { role: 'admin' },
        {
          actor: userActor(alice.userId),
          action: 'membership.role_changed',
          details: { roleFrom: 'approver', roleTo: 'admin' },
        },
      );
    });
    // Strict (OR1c): the alarm, with no read of the history at all.
    expect(await facts()).toEqual({ outcome: 'tampered', sign: 'holding' });
    expect(lines('audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'holding', objectId: bob.id })]);
    expect(await build()).toEqual({ outcome: 'built', built: 1 });
    // Raised once by the rule's read and once by the build that brought it up to date; none after.
    expect(lines('audit.integrity_failed')).toHaveLength(2);
    expect(await facts()).toMatchObject({ outcome: 'read' });
    expect(lines('audit.integrity_failed')).toHaveLength(2);
  }, 240_000);

  it('builds each unbuilt summary from the history, a page at a time, as the history would decide', async () => {
    const alice = await addBefore('admin');
    const bob = await addBefore('viewer', userActor(alice.userId));
    const dave = await addBefore('admin');
    const carolId = await person();
    await invited(dave.userId, carolId);
    await addBefore('approver', userActor(carolId), carolId);
    // Changes after 0085 to a membership with no summary yet leave it unbuilt: the history holds them.
    await changeRole(bob.id, 'approver', alice.userId);
    await changeRole(dave.id, 'developer', alice.userId);
    const fresh = await add('viewer', userActor(alice.userId));
    const before = await facts();
    expect(before).toMatchObject({ outcome: 'read' });
    expect((await summaryRows()).map(({ id }) => id)).toEqual([fresh.id]);

    expect(await build(3)).toEqual({ outcome: 'built', built: 4 });
    expect(await build(3)).toEqual({ outcome: 'built', built: 0 });

    const after = await facts();
    if (before.outcome !== 'read' || after.outcome !== 'read') throw new Error('not read');
    expect(shape(after)).toEqual(shape(before));
    expect(shape(after)).toEqual(shape(await historyFacts()));
    const built = await owner.query<{ actor_type: string; actor_id: string }>(
      `select actor_type, actor_id from audit.events where org_id = $1 and action = 'membership_grant.built'`,
      [org],
    );
    expect(built).toEqual(Array.from({ length: 4 }, () => ({ actor_type: 'system', actor_id: 'api' })));
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('builds nothing beside a kept summary that holds less than the history says, and raises the alarm', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    await changeRole(bob.id, 'approver', alice.userId, { granters: [] });
    const carol = await addBefore('viewer');

    expect(await build()).toEqual({ outcome: 'tampered', sign: 'holding' });
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'holding', subjectType: 'membership_grant', objectId: bob.id }),
    ]);
    expect((await summaryRows()).map(({ id }) => id)).not.toContain(carol.id);
  });

  it('builds nothing where a membership or a summary was tampered with: the alarm, and nothing built', async () => {
    const alice = await add('admin');
    const bob = await addBefore('viewer');
    await owner.setColumn(alice.id, 'granted_by', bob.userId);

    expect(await build()).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect((await summaryRows()).map(({ id }) => id)).toEqual([alice.id]);

    capture = new LogCapture();
    await owner.query(`update identity.memberships set role = 'admin' where org_id = $1 and id = $2`, [org, bob.id]);
    expect(await build()).toMatchObject({ outcome: 'tampered' });
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ subjectType: 'membership', objectId: bob.id }),
    ]);
  });

  it('builds nothing, and decides nothing, on a history edited past the app', async () => {
    const alice = await add('admin');
    const bobId = await person();
    await invited(alice.userId, bobId);
    await addBefore('viewer', userActor(bobId), bobId);
    await owner.query(`update audit.events set actor_id = $2 where org_id = $1 and action = 'invitation.drafted'`, [
      org,
      bobId,
    ]);

    expect(await facts()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(await build()).toEqual({ outcome: 'tampered', sign: 'log' });
  });

  it('builds nothing, and decides nothing, on a log of who joined edited past the app', async () => {
    await add('admin');
    await owner.query(
      `update audit.events set actor_id = 'someone-else' where org_id = $1 and action = 'membership.created'`,
      [org],
    );

    expect(await facts()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(await build()).toEqual({ outcome: 'tampered', sign: 'log' });
  });

  it('builds nothing for an organisation with no members', async () => {
    expect(await build()).toEqual({ outcome: 'built', built: 0 });
  });
});

describe(`concurrent membership changes, in a forced lock order (ADR-006 §6, Postgres ${server.version})`, () => {
  /** A promise and the function that settles it. */
  const gate = () => {
    let open!: () => void;
    const shut = new Promise<void>((resolve) => {
      open = resolve;
    });
    return { shut, open };
  };

  /** A change that stops, recorded and still holding its locks, until `go` lets it commit. */
  const paused = async (start: (pause: { reached: () => void; until: Promise<void> }) => Promise<unknown>) => {
    const reached = gate();
    const go = gate();
    const done = start({ reached: reached.open, until: go.shut });
    await within(20_000, reached.shut, 'the change recorded');
    return { go: go.open, done };
  };

  it('reads the rule’s facts only once a role change holding the membership ends, at its new version', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    // The change holds Bob's membership and summary, recorded, until let go.
    const changing = await paused((pause) => changeRole(bob.id, 'approver', alice.userId, { pause }));
    const reading = within(20_000, facts(), 'the facts');
    await waitUntilQueued(database.as('admin'), 1);
    changing.go();
    await changing.done;

    const read = await reading;

    expect(read).toMatchObject({ outcome: 'read' });
    if (read.outcome !== 'read') return;
    expect([...(read.grantedBy.get(bob.id) ?? [])]).toEqual([alice.userId]);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  /** A finding on the record in a transaction of its own: its hold is set as that transaction ends. */
  const found = (subjectType: string, id: string) =>
    withSignedStates(app, org, services(), (_tx, states) => {
      states.mismatch(subjectType, { orgId: org, id });
      return Promise.resolve();
    });

  it('the repair writes its waiting row only under the chain head, so a hold holding the head and writing it never deadlocks', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    await leftBehind(oldImage, services(), { orgId: org, id: bob.id }, 'approver', userActor(alice.userId));
    // Held on another record already, so the job's own hold keeps Bob's row waiting rather than taking it.
    await found(MEMBERSHIPS.subject, alice.id);
    const record = { orgId: org, subjectType: MEMBERSHIP_GRANTS.subject, objectId: bob.id };
    // As a hold's transaction does: the chain head's lock first, held until let go, then the row.
    const holding = await paused((pause) =>
      withSignedStates(app, org, services(), async (tx, states) => {
        await states.integrityHold(tx, org, 'head');
        pause.reached();
        await pause.until;
        await keepHoldWaitingHere(tx, record, 'holding');
      }),
    );
    // The job queues on the head at its repair's first record, its row not written yet.
    const building = within(20_000, build(), 'the build');
    await waitUntilQueued(database.as('admin'), 1);
    holding.go();

    // Had the job written its row before the head, the hold's row would wait on it: a deadlock.
    await within(20_000, holding.done, 'the hold');
    expect(await building).toEqual({ outcome: 'built', built: 1 });
    expect(
      await database
        .as('backup')
        .query('select subject_type, object_id from directory.holds_waiting where org_id = $1', [org]),
    ).toEqual([{ subject_type: 'membership_grant', object_id: bob.id }]);
  });

  it('a hold set while the job holds its repair and row waits on the chain head, and every hold is recorded', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    await leftBehind(oldImage, services(), { orgId: org, id: bob.id }, 'approver', userActor(alice.userId));
    // Held on another record already, so each later hold keeps Bob's row waiting (the head's lock, then the row).
    await found(MEMBERSHIPS.subject, alice.id);
    // The repair done and its row written, holding the head's lock and the row, until let go.
    const repairing = await paused((pause) =>
      withSignedStates(app, org, services(), async (tx, states) => {
        const built = await buildGrantSummaries(tx, states, org);
        pause.reached();
        await pause.until;
        return built;
      }),
    );
    const holding = within(20_000, found(MEMBERSHIP_GRANTS.subject, bob.id), 'the other hold');
    const [waiter] = await waitUntilQueued(database.as('admin'), 1);
    const [waiting] = await database
      .as('admin')
      .query<{ query: string }>('select query from pg_catalog.pg_stat_activity where pid = $1', [waiter]);
    // Queued on the hold's lock of the chain head, which the repair took before its row: never on the row itself.
    expect(waiting?.query).toContain('from "audit"."heads"');
    repairing.go();

    expect(await within(20_000, repairing.done, 'the repair')).toEqual({ outcome: 'built', built: 1 });
    await holding;
    expect(lines('audit.integrity_failed').filter((line) => line.check === 'hold')).toEqual([]);
    expect(
      await database
        .as('backup')
        .query('select subject_type, object_id from directory.holds_waiting where org_id = $1', [org]),
    ).toEqual([{ subject_type: 'membership_grant', object_id: bob.id }]);
  });

  it('builds a summary only once a change of its membership in flight ends, from a history that holds it', async () => {
    const alice = await addBefore('admin');
    const bob = await addBefore('viewer');
    const changing = await paused((pause) => changeRole(bob.id, 'approver', alice.userId, { pause }));
    const building = within(20_000, build(), 'the build');
    await waitUntilQueued(database.as('admin'), 1);
    changing.go();
    await changing.done;

    expect(await building).toEqual({ outcome: 'built', built: 2 });
    const read = await facts();
    if (read.outcome !== 'read') throw new Error('not read');
    expect([...(read.grantedBy.get(bob.id) ?? [])]).toEqual([alice.userId]);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('commits a change queued behind a change refused for its summary, at the version the first never made', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    // A change past the summary holds Bob's membership, recorded, until let go; then its commit is refused.
    const refused = await paused((pause) => roleAlone(bob.id, 'developer', alice.userId, pause));
    const queued = within(20_000, changeRole(bob.id, 'approver', alice.userId), 'the queued change');
    await waitUntilQueued(database.as('admin'), 1);
    refused.go();
    await expect(refused.done).rejects.toMatchObject({ constraint: 'grants_in_step' });
    await queued;

    expect(await versions(bob.id)).toEqual({ membership: 2, summary: 2 });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('commits two changes of one membership one after the other, each moving its summary on in step', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    const first = await paused((pause) => changeRole(bob.id, 'developer', alice.userId, { pause }));
    const second = within(20_000, changeRole(bob.id, 'approver', alice.userId), 'the second change');
    await waitUntilQueued(database.as('admin'), 1);
    first.go();
    await first.done;
    await second;

    expect(await versions(bob.id)).toEqual({ membership: 3, summary: 3 });
  });
});

/** The membership's signed version and the one its summary was kept at. */
const versions = async (id: string) => {
  // The owner's session inside the organisation (tamperAsOwner's): the tables' walls bind it too.
  const [row] = await owner.query<{ membership: number; summary: number | null }>(
    'select m.state_version as membership, g.membership_version as summary from identity.memberships m left join identity.membership_grants g on g.org_id = m.org_id and g.id = m.id where m.org_id = $1 and m.id = $2',
    [org, id],
  );
  return row;
};

/**
 * The member's role changed by the app's role and its summary left as it was: what no code of the product does since
 * OR1, and what 0089 refuses at the commit. With `pause`, held open once recorded until let go.
 */
const roleAlone = (
  id: string,
  roleTo: Role,
  by: string,
  pause?: { readonly reached: () => void; readonly until: Promise<void> },
) =>
  withSignedStates(app, org, services(), async (tx, states) => {
    const read = await changeRead(tx, states, id);
    await states.record(
      tx,
      MEMBERSHIPS,
      read.key,
      read.state,
      { role: roleTo },
      { actor: userActor(by), action: 'membership.role_changed', details: { roleFrom: read.member.role, roleTo } },
    );
    pause?.reached();
    await pause?.until;
  });

describe(`OR1b: the database holds each membership change to its summary (0089, Postgres ${server.version})`, () => {
  it('lets every change the product makes commit, each summary in step with its membership', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    expect(await versions(bob.id)).toEqual({ membership: 1, summary: 1 });
    await changeRole(bob.id, 'approver', alice.userId);
    expect(await versions(bob.id)).toEqual({ membership: 2, summary: 2 });
    await deactivate(bob.id, alice.userId);
    expect(await versions(bob.id)).toEqual({ membership: 3, summary: 3 });
    await withSignedStates(app, org, services(), (tx, states) =>
      reactivateMembership(tx, states, {
        orgId: org,
        id: bob.id,
        role: 'viewer',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    // The return records the role and start, then the move: two versions, the summary kept at the last.
    expect(await versions(bob.id)).toEqual({ membership: 5, summary: 5 });
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('refuses at the commit a change of the membership alone, the summary in step before it: nothing is kept', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');

    await expect(roleAlone(bob.id, 'admin', alice.userId)).rejects.toMatchObject({
      code: '23514',
      constraint: 'grants_in_step',
    });

    expect(await versions(bob.id)).toEqual({ membership: 1, summary: 1 });
    const read = await withSignedStates(app, org, services(), (tx, states) =>
      memberOf(tx, states, { orgId: org, id: bob.id }, 'share'),
    );
    expect(read).toMatchObject({ outcome: 'found', member: { role: 'viewer' } });
  });

  it('refuses a summary moved on to a version its membership passed in the same change', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    const changing = withSignedStates(app, org, services(), async (tx, states) => {
      const read = await changeRead(tx, states, bob.id);
      const first = await states.record(
        tx,
        MEMBERSHIPS,
        read.key,
        read.state,
        { role: 'developer' },
        { actor: userActor(alice.userId), action: 'membership.role_changed', details: {} },
      );
      await keepGrants(tx, states, read.grants, read.key, {
        change: { memberUserId: read.member.userId, granters: [alice.userId] },
        fromVersion: read.state.version,
        membershipVersion: first.version,
        actor: userActor(alice.userId),
      });
      // The membership moved once more, its summary left at the version before.
      const again = await states.verifiedState(tx, MEMBERSHIPS, read.key, 'change');
      if (again.outcome !== 'verified') throw new Error('not verified');
      await states.record(
        tx,
        MEMBERSHIPS,
        read.key,
        again,
        { role: 'approver' },
        { actor: userActor(alice.userId), action: 'membership.role_changed', details: {} },
      );
    });

    await expect(changing).rejects.toMatchObject({ constraint: 'grants_in_step' });
    expect(await versions(bob.id)).toEqual({ membership: 1, summary: 1 });
  });

  it('refuses, as the app role in raw SQL, a version moved alone whose organisation setting is cleared before the commit (S187 review)', async () => {
    // The product's own transactions refuse this before the commit (withTenant's TenantContextError); the database
    // holds it too, for a raw-SQL actor on the app's role, where the wall hides both rows from the trigger.
    await add('admin');
    const bob = await add('viewer');
    const changing = app.transaction().execute(async (tx) => {
      await sql`select pg_catalog.set_config('app.org_id', ${org}, true)`.execute(tx);
      await sql`update identity.memberships set state_version = state_version + 1 where org_id = ${org} and id = ${bob.id}`.execute(
        tx,
      );
      await sql`select pg_catalog.set_config('app.org_id', '', true)`.execute(tx);
    });

    await expect(changing).rejects.toMatchObject({ code: '23514', constraint: 'grants_in_step' });
    expect(await versions(bob.id)).toEqual({ membership: 1, summary: 1 });
  });

  it('refuses a summary put ahead of its membership in the same change (S187 review)', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    const changing = withSignedStates(app, org, services(), async (tx, states) => {
      const read = await changeRead(tx, states, bob.id);
      const moved = await states.record(
        tx,
        MEMBERSHIPS,
        read.key,
        read.state,
        { role: 'developer' },
        { actor: userActor(alice.userId), action: 'membership.role_changed', details: {} },
      );
      await keepGrants(tx, states, read.grants, read.key, {
        change: { memberUserId: read.member.userId, granters: [alice.userId] },
        fromVersion: read.state.version,
        membershipVersion: moved.version,
        actor: userActor(alice.userId),
      });
      await sql`update identity.membership_grants set membership_version = 99 where org_id = ${org} and id = ${bob.id}`.execute(
        tx,
      );
    });

    await expect(changing).rejects.toMatchObject({ code: '23514', constraint: 'grants_in_step' });
    expect(await versions(bob.id)).toEqual({ membership: 1, summary: 1 });
  });

  it('lets a membership with no summary yet change alone: built later by the job, OR1c’s to judge', async () => {
    const alice = await add('admin');
    const bob = await addBefore('viewer');
    await roleAlone(bob.id, 'approver', alice.userId);
    expect(await versions(bob.id)).toEqual({ membership: 2, summary: null });
  });

  it('lets a membership whose summary an image from before OR1 left behind change alone: OR1c’s to judge', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    await withSignedStates(oldImage, org, services(), async (tx, states) => {
      const read = await changeRead(tx, states, bob.id);
      await states.record(
        tx,
        MEMBERSHIPS,
        read.key,
        read.state,
        { role: 'developer' },
        { actor: userActor(alice.userId), action: 'membership.role_changed', details: {} },
      );
    });
    // The owner's change (as a state repair writes) committed alone; then the app's, the summary behind before it.
    expect(await versions(bob.id)).toEqual({ membership: 2, summary: 1 });
    await roleAlone(bob.id, 'approver', alice.userId);
    expect(await versions(bob.id)).toEqual({ membership: 3, summary: 1 });
  });
});
