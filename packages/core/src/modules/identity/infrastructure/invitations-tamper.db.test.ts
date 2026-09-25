// FX-TAMPER on an invitation (SEC-DB-10, B4-3a), as the database's owner:
// agentx_owner, the role the migration job logs in as, holding none of the
// app's keys, working inside one organisation through @agentx/testing's
// tamperAsOwner, as a membership is tested (memberships-tamper.db.test.ts).
//
// Each change to an invitation's role, status, admin, end or challenge is
// denied by the row check, with the SEV-1 alarm, and puts the organisation on
// its integrity hold. The encrypted address, which isn't signed, opens only
// in its own row as it was written: anything else put there is refused. The
// live schema guard, with the product's own list, is clean before and after
// each case, so a leftover can't hide a miss.
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
import {
  draftInvitation,
  invitationChange,
  invitationRecord,
  INVITATIONS,
  invitationToOpen,
  InvitationUnreadable,
  openInvitation,
} from './invitations.ts';
import { addMembership } from './memberships.ts';
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
const ids = new SequentialIds(0xc00);
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
let admin: string;
let adminUser: string;

const services = () => ({ keys, ids, logger: loggerFor(capture) });
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let subjects = 0;

/** An invitation asked for in this test's organisation, logging to a capture of its own. */
async function invitation(role: Role = 'viewer', email = 'sara@example.test'): Promise<string> {
  const id = ids.next();
  const { change } = invitationChange({ orgId: org, id, email, role, invitedBy: admin, createdAt: clock.now() });
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    draftInvitation(tx, states, keys, change, {
      stepUpChallengeId: ids.next(),
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    }),
  );
  return id;
}

const read = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) => invitationRecord(tx, states, org, id));

const toOpen = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) =>
    invitationToOpen(tx, states, keys, { orgId: org, id, now: clock.now() }),
  );

const open = (id: string) =>
  withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    openInvitation(tx, states, { orgId: org, id, actor: { type: 'user', id: adminUser }, details: {} }),
  );

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Denied with the alarm on the invitation, and the organisation held for it. */
async function deniedAndHeld(id: string, sign: TamperSign): Promise<void> {
  expect(await read(id)).toEqual({ outcome: 'tampered', sign });
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      chain: 'organisation',
      check: 'state',
      reason: sign,
      subjectType: 'invitation',
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ orgId: org, reason: sign, subjectType: 'invitation' }),
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
  admin = ids.next();
  subjects += 1;
  adminUser = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `tamper-inviter-${String(subjects)}` },
    { ids, clock },
  );
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, async (tx, states) => {
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
  owner = await tamperAsOwner(database, INVITATIONS, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  expect(await guard()).toEqual([]);
});

describe(`FX-TAMPER as the owner on an invitation: denied by the row check, and held (Postgres ${server.version})`, () => {
  it('a viewer’s invitation raised to admin', async () => {
    const id = await invitation('viewer');
    await owner.setColumn(id, 'role', 'admin');

    await deniedAndHeld(id, 'seal');
  });

  it('an ended invitation given a later end', async () => {
    const id = await invitation();
    await owner.setColumn(id, 'expires_at', '2030-01-01T00:00:00Z');

    await deniedAndHeld(id, 'seal');
  });

  it('put down to another admin', async () => {
    const id = await invitation();
    const other = ids.next();
    await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, async (tx, states) =>
      addMembership(tx, states, {
        orgId: org,
        id: other,
        userId: await userForSubject(
          app,
          { issuer: 'https://auth.example.test', subject: `tamper-other-${String(subjects)}` },
          { ids, clock },
        ),
        role: 'admin',
        joinedAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    await owner.setColumn(id, 'invited_by', other);

    await deniedAndHeld(id, 'seal');
  });

  it('pointed at another step-up challenge', async () => {
    const id = await invitation();
    await owner.setColumn(id, 'step_up_challenge_id', ids.next());

    await deniedAndHeld(id, 'seal');
  });

  it('a draft opened without its step-up, a move the status guard allows', async () => {
    const id = await invitation('admin');
    await owner.setColumn(id, 'status', 'OPEN');

    await deniedAndHeld(id, 'seal');
  });

  it('an open invitation rolled back to its saved, validly signed draft', async () => {
    const id = await invitation();
    const saved = await owner.saveRow(id);
    await open(id);
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    await deniedAndHeld(id, 'pointer');
  });

  it('a viewer’s invitation raised to admin as it is opened: it doesn’t open, and lists no token', async () => {
    const id = await invitation('viewer');
    await owner.setColumn(id, 'role', 'admin');

    await expect(open(id)).rejects.toMatchObject({ name: 'InvitationNotOpened', outcome: 'tampered' });
    expect(await owner.query('select token_hash from directory.invites where invitation_id = $1', [id])).toEqual([]);
    expect(await hold()).toMatchObject({ outcome: 'held' });
  });

  it('planted with no event: an admin’s invitation the app never made', async () => {
    const id = ids.next();
    await owner.query(
      "insert into identity.invitations (org_id, id, role, status, invited_by, expires_at, created_at, email_ciphertext, email_key_version, step_up_challenge_id) values ($1, $2, 'admin', 'DRAFT', $3, now() + interval '1 day', now(), $4, 1, $5)",
      [org, id, admin, Buffer.alloc(40), ids.next()],
    );

    await deniedAndHeld(id, 'unsigned');
  });

  it('deleted, which the app role cannot do', async () => {
    const id = await invitation();
    await owner.deleteRow(id);

    await deniedAndHeld(id, 'deleted');
  });

  it('its events stripped of their seals', async () => {
    const id = await invitation();
    await owner.stripSeals(id);

    await deniedAndHeld(id, 'unsigned');
  });
});

describe(`FX-TAMPER as the owner on an invitation's address: it won't open (Postgres ${server.version})`, () => {
  it('another invitation’s address copied into it', async () => {
    const id = await invitation('viewer', 'sara@example.test');
    const other = await invitation('viewer', 'mallory@example.test');
    await owner.query(
      'update identity.invitations set email_ciphertext = (select email_ciphertext from identity.invitations where id = $2) where id = $1',
      [id, other],
    );

    await expect(toOpen(id)).rejects.toBeInstanceOf(InvitationUnreadable);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('another organisation’s address copied into an invitation of the same ID', async () => {
    const id = await invitation('viewer', 'sara@example.test');
    const elsewhere = ids.next();
    const elsewhereAdmin = ids.next();
    const services = { keys, ids, logger: loggerFor(new LogCapture()) };
    await withSignedStates(app, elsewhere, services, async (tx, states) => {
      await createOrganization(tx, states, { id: elsewhere, name: 'Other Trading LLC', actor: OPERATOR });
      await addMembership(tx, states, {
        orgId: elsewhere,
        id: elsewhereAdmin,
        userId: adminUser,
        role: 'admin',
        joinedAt: clock.now(),
        actor: OPERATOR,
      });
      const { change } = invitationChange({
        orgId: elsewhere,
        id,
        email: 'mallory@example.test',
        role: 'viewer',
        invitedBy: elsewhereAdmin,
        createdAt: clock.now(),
      });
      await draftInvitation(tx, states, keys, change, {
        stepUpChallengeId: ids.next(),
        createdAt: clock.now(),
        actor: { type: 'user', id: adminUser },
      });
    });
    // The owner works inside this test's organisation, so the other's value is read as the backup role reads it.
    const [copied] = await database
      .as('backup')
      .query('select email_ciphertext from identity.invitations where org_id = $1 and id = $2', [elsewhere, id]);
    await owner.query('update identity.invitations set email_ciphertext = $1 where id = $2', [
      (copied as { email_ciphertext: Buffer }).email_ciphertext,
      id,
    ]);

    await expect(toOpen(id)).rejects.toBeInstanceOf(InvitationUnreadable);
  });

  it('a byte of it changed', async () => {
    const id = await invitation();
    await owner.query(
      'update identity.invitations set email_ciphertext = set_byte(email_ciphertext, 30, get_byte(email_ciphertext, 30) # 1) where id = $1',
      [id],
    );

    await expect(toOpen(id)).rejects.toBeInstanceOf(InvitationUnreadable);
  });
});
