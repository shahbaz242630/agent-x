// FX-TAMPER on a membership (SEC-DB-10, B4-1), as the database's owner:
// agentx_owner, the role the migration job logs in as, holding none of the
// app's keys, working inside one organisation through @agentx/testing's
// tamperAsOwner, as the organisation's own row is tested
// (organizations/infrastructure/owner-tamper.db.test.ts, which also covers
// the hold itself and the chain).
//
// Each change to whose a membership is, its role, its status or when it began
// is denied by the row check, with the SEV-1 alarm, and puts the organisation
// on its integrity hold. The live schema guard, with the product's own list,
// is clean before and after each case, so a leftover can't hide a miss.
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import { createDatabase, type Database, liveSchemaProblems } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { type AuditTables, type TamperSign, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import { addMembership, membershipOf, MEMBERSHIPS } from './memberships.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0x700);
const clock = new FixedClock(new Date('2026-09-25T09:00:00Z'));

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let capture: LogCapture;
let owner: OwnerTamper;
let org: string;

const services = () => ({ keys, ids, logger: loggerFor(capture) });
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let subjects = 0;
const person = (): Promise<string> => {
  subjects += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `tamper-${String(subjects)}` },
    { ids, clock },
  );
};

/** This test's organisation, with a membership for a new person, made logging to a capture of their own. */
async function member(role: Role): Promise<{ user: string; id: string }> {
  const user = await person();
  const id = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    addMembership(tx, states, { orgId: org, id, userId: user, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { user, id };
}

const check = (user: string) =>
  withSignedStates(app, org, services(), (tx, states) => membershipOf(tx, states, org, user));

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

const deactivate = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) =>
    states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id }, 'deactivate', {
      actor: OPERATOR,
      action: 'membership.deactivate',
      details: {},
    }),
  );

const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Denied with the alarm on the membership, and the organisation held for it. */
async function deniedAndHeld(user: string, id: string, sign: TamperSign): Promise<void> {
  expect(await check(user)).toEqual({ outcome: 'tampered', sign });
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      chain: 'organisation',
      check: 'state',
      reason: sign,
      subjectType: 'membership',
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ orgId: org, reason: sign, subjectType: 'membership' }),
  ]);
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owner = await tamperAsOwner(database, MEMBERSHIPS, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  expect(await guard()).toEqual([]);
});

describe(`FX-TAMPER as the owner on a membership: denied by the row check, and held (Postgres ${server.version})`, () => {
  it('a viewer raised to admin', async () => {
    const { user, id } = await member('viewer');
    await owner.setColumn(id, 'role', 'admin');

    await deniedAndHeld(user, id, 'seal');
  });

  it("an admin's membership moved to another person, listed for them too", async () => {
    const { id } = await member('admin');
    const other = await person();
    await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
      other,
      org,
      id,
    ]);
    await owner.setColumn(id, 'user_id', other);

    await deniedAndHeld(other, id, 'seal');
  });

  it('made to look older than it is, as an established verifier would be (ADR-012 §1)', async () => {
    const { user, id } = await member('approver');
    await owner.setColumn(id, 'joined_at', '2020-01-01T00:00:00Z');

    await deniedAndHeld(user, id, 'seal');
  });

  it('a deactivated admin made active again, with the status guard switched off for it', async () => {
    const { user, id } = await member('admin');
    await deactivate(id);
    await owner.withoutStatusGuard(() => owner.setColumn(id, 'status', 'ACTIVE'));

    await deniedAndHeld(user, id, 'seal');
  });

  it('a deactivated admin made active again by rolling the row back to its saved, validly signed state', async () => {
    const { user, id } = await member('admin');
    const saved = await owner.saveRow(id);
    await deactivate(id);
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    await deniedAndHeld(user, id, 'pointer');
  });

  it('deleted, which the app role cannot do', async () => {
    const { user, id } = await member('viewer');
    await owner.deleteRow(id);

    await deniedAndHeld(user, id, 'deleted');
  });

  it('planted with no event: an admin the app never added', async () => {
    const user = await person();
    const id = ids.next();
    await owner.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
      user,
      org,
      id,
    ]);
    await owner.query(
      "insert into identity.memberships (org_id, id, user_id, role, status, joined_at) values ($1, $2, $3, 'admin', 'ACTIVE', now())",
      [org, id, user],
    );

    await deniedAndHeld(user, id, 'unsigned');
  });

  it('its events stripped of their seals', async () => {
    const { user, id } = await member('admin');
    await owner.stripSeals(id);

    await deniedAndHeld(user, id, 'unsigned');
  });

  it('the app role given DELETE on it: the guard names the right', async () => {
    await owner.query('grant delete on identity.memberships to agentx_app');
    try {
      expect(await guard()).toEqual(['agentx_app may DELETE on identity.memberships']);
    } finally {
      await owner.query('revoke delete on identity.memberships from agentx_app');
    }
  });
});
