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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import {
  type AuditTables,
  createAuditTrail,
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
  reactivateMembership,
} from './memberships.ts';
import type { IdentityTables } from './tables.ts';
import { twoPersonFactsOf } from './two-person-facts.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;
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
});

afterAll(async () => {
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

  it('denies a summary its membership moved on past: the two disagree', async () => {
    const alice = await add('admin');
    const bob = await add('viewer');
    // A role change recorded on the membership alone, as a writer that skipped the summary would.
    await withSignedStates(app, org, services(), async (tx, states) => {
      const state = await states.verifiedState(tx, MEMBERSHIPS, { orgId: org, id: bob.id }, 'change');
      if (state.outcome !== 'verified') throw new Error('not verified');
      await states.record(
        tx,
        MEMBERSHIPS,
        { orgId: org, id: bob.id },
        state,
        { role: 'approver' },
        {
          actor: userActor(alice.userId),
          action: 'membership.role_changed',
          details: { roleFrom: 'viewer', roleTo: 'approver' },
        },
      );
    });

    await deniedAndHeld(bob.id, 'holding');
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
});
