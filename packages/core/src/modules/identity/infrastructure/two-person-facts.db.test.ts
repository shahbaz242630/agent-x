// The two-person rule's facts (E3-1; ADR-012 §1, SEC-PAY-04), read on the
// real migrated schema as the app role: the members through their signed
// states, and who granted each one's role from the organisation's log. The
// owner, past the app, edits the history: the read raises the alarm.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  type TestSession,
} from '@agentx/testing';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, createAuditTrail, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import { verifierVerdict } from '../domain/two-person.ts';
import { grantsBelieved, grantsToChange } from './membership-grants.ts';
import { addMembership, changeMembershipRole, memberOf, type MembershipsTransaction } from './memberships.ts';
import type { IdentityTables } from './tables.ts';
import { twoPersonFactsOf } from './two-person-facts.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;
/** The FX-TAMPER attacker: the server's superuser, holding none of the app's keys. */
let attacker: TestSession;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb000_0000_0000);
const trail = createAuditTrail({ keys, ids });
const clock = new FixedClock(new Date('2026-10-01T09:00:00Z'));

let capture: LogCapture;
const services = () => ({
  keys,
  ids,
  logger: testLogger(capture),
});

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const userActor = (id: string) => ({ type: 'user' as const, id });
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

let org: string;
let subjects = 0;

/** A new person, as their first sign-in makes them. */
const person = (): Promise<string> => {
  subjects += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `two-${String(subjects)}` },
    { ids, clock },
  );
};

/** A member added with `role`, recorded as `by` adding them: `self` for one who joined by accepting. */
const add = async (role: Role, by: { type: 'user' | 'system'; id: string } | 'self' = OPERATOR, existing?: string) => {
  const userId = existing ?? (await person());
  const id = ids.next();
  const actor = by === 'self' ? userActor(userId) : by;
  await withSignedStates(app, org, services(), (tx: MembershipsTransaction, states) =>
    addMembership(tx, states, { orgId: org, id, userId, role, joinedAt: clock.now(), actor }),
  );
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

/** The member's role changed by `by`, as membership-changes.ts records it, its grant summary with it. */
const changeRole = (id: string, roleTo: Role, by: string) =>
  withSignedStates(app, org, services(), async (tx, states) => {
    const key = { orgId: org, id };
    const read = await memberOf(tx, states, key, 'change');
    if (read.outcome !== 'found') throw new Error('not found');
    const grants = grantsBelieved(await grantsToChange(tx, states, key));
    await changeMembershipRole(tx, states, { key, ...read, grants, actor: userActor(by), evidence: {}, roleTo });
  });

const facts = () => withSignedStates(app, org, services(), (tx, states) => twoPersonFactsOf(tx, states, org));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
  attacker = database.as('admin');
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
});

describe(`the two-person rule's facts, from the log (E3-1, Postgres ${server.version})`, () => {
  it('finds who granted each member’s role, by adding, inviting or changing it, and the latest change to a verifier', async () => {
    const alice = await add('admin');
    const bob = await add('viewer', userActor(alice.userId));
    const dave = await add('admin');
    // Carol joins by accepting Dave's invitation: who asked for it is read as her membership is added.
    const carolId = await person();
    await invited(dave.userId, carolId);
    const carol = await add('approver', 'self', carolId);
    await changeRole(bob.id, 'approver', alice.userId);
    await changeRole(dave.id, 'developer', alice.userId);

    const read = await facts();

    expect(read.outcome).toBe('read');
    if (read.outcome !== 'read') return;
    expect(read.members.map(({ id }) => id).sort()).toEqual([alice.id, bob.id, carol.id, dave.id].sort());
    const granters = (id: string) => [...(read.grantedBy.get(id) ?? [])].sort();
    expect(granters(alice.id)).toEqual([]);
    expect(granters(bob.id)).toEqual([alice.userId]);
    expect(granters(carol.id)).toEqual([dave.userId]);
    expect(granters(dave.id)).toEqual([alice.userId]);
    expect(read.lastVerifierChange).toBeInstanceOf(Date);
    expect(alarms()).toEqual([]);

    // Fourteen days on: Bob, whose role Alice granted, can't verify what she entered; Carol can.
    const later = new Date(clock.now().getTime() + 15 * 86_400_000);
    expect(verifierVerdict(read, { enteredById: alice.id, verifierId: bob.id }, later)).toEqual({
      outcome: 'refused',
      reason: 'VERIFIER_GRANTED_BY_ENTERER',
    });
    expect(verifierVerdict(read, { enteredById: alice.id, verifierId: carol.id }, later)).toEqual({
      outcome: 'two_person',
    });
  });

  it('gives a new organisation with one member no grants and no loss: the single-user path', async () => {
    const alice = await add('admin');

    const read = await facts();

    expect(read).toMatchObject({ outcome: 'read', lastVerifierChange: undefined });
    if (read.outcome !== 'read') return;
    expect(verifierVerdict(read, { enteredById: alice.id, verifierId: alice.id }, clock.now())).toEqual({
      outcome: 'single_user',
    });
  });

  it('raises the alarm on an invitation’s event edited past the app, read as the invited person joins', async () => {
    const alice = await add('admin');
    const bobId = await person();
    await invited(alice.userId, bobId);
    await attacker.query(`update audit.events set actor_id = $2 where org_id = $1 and action = 'invitation.drafted'`, [
      org,
      bobId,
    ]);

    await expect(add('admin', 'self', bobId)).rejects.toMatchObject({ name: 'SignedStateFailed', reason: 'tampered' });
    expect(alarms()).toEqual([
      expect.objectContaining({ reason: 'log', subjectType: 'organisation', objectId: org, orgId: org }),
    ]);
  });

  it('raises the alarm on a member the log made but the list no longer holds: never one admin fewer (H10)', async () => {
    const alice = await add('admin');
    await add('admin');
    // Its row deleted past the app (its grant summary with it): its signed state finds it, before the history is read.
    await attacker.query('delete from identity.memberships where org_id = $1 and id = $2', [org, alice.id]);

    expect(await facts()).toEqual({ outcome: 'tampered', sign: 'deleted' });
    expect(alarms()).toEqual([expect.objectContaining({ subjectType: 'membership', objectId: alice.id })]);
  });

  it('raises the alarm on a member whose directory entry went past the app, its row and seal intact (H10)', async () => {
    const alice = await add('admin');
    await add('admin');
    // The list is read through the directory, so a member it no longer names is skipped there, seal and all:
    // only the history's check finds them. The foreign key that holds the entry is the server's own trigger.
    await attacker.query('alter table directory.members disable trigger all');
    await attacker.query('delete from directory.members where org_id = $1 and membership_id = $2', [org, alice.id]);
    await attacker.query('alter table directory.members enable trigger all');

    expect(await facts()).toEqual({ outcome: 'tampered', sign: 'deleted' });
    expect(alarms()).toEqual([expect.objectContaining({ subjectType: 'membership', objectId: alice.id })]);
  });

  it('raises the alarm on a membership changed past the app, before reading the history', async () => {
    const alice = await add('admin');
    await attacker.query(`update identity.memberships set role = 'viewer' where org_id = $1 and id = $2`, [
      org,
      alice.id,
    ]);

    expect(await facts()).toMatchObject({ outcome: 'tampered' });
    expect(alarms()).toEqual([expect.objectContaining({ subjectType: 'membership', objectId: alice.id })]);
  });
});
