// B4-1: memberships and their directory entries (0015), on the real migrated
// schema, as the app role. What the owner can do past the app is
// memberships-tamper.db.test.ts.
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase, within } from '@agentx/testing';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, organizationsOf } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import { addMembership, membershipFor, membershipOf, MEMBERSHIPS, type MembershipsTransaction } from './memberships.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
// Each ID has a hex letter in it, so looking one up in upper case is another string.
const ids = new SequentialIds(0xa000_0000_0000);
const clock = new FixedClock(new Date('2026-09-25T09:00:00Z'));

let capture: LogCapture;
const services = () => ({
  keys,
  ids,
  logger: createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  }),
});

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

/** A new organisation, as the operator's command makes one. */
const organization = async (): Promise<string> => {
  const id = ids.next();
  await withSignedStates(app, id, services(), (tx, states) =>
    createOrganization(tx, states, { id, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return id;
};

let subjects = 0;
/** A new person, as their first sign-in makes them. */
const person = (): Promise<string> => {
  subjects += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `member-${String(subjects)}` },
    { ids, clock },
  );
};

const add = (orgId: string, userId: string, role: Role = 'viewer', inside = orgId) =>
  withSignedStates(app, inside, services(), async (tx: MembershipsTransaction, states) => {
    const id = ids.next();
    const recorded = await addMembership(tx, states, {
      orgId,
      id,
      userId,
      role,
      joinedAt: clock.now(),
      actor: OPERATOR,
    });
    return { id, recorded };
  });

const check = (orgId: string, userId: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => membershipOf(tx, states, orgId, userId));

const deactivate = (orgId: string, id: string) =>
  withSignedStates(app, orgId, services(), (tx, states) =>
    states.changeStatus(tx, MEMBERSHIPS, { orgId, id }, 'deactivate', {
      actor: OPERATOR,
      action: 'membership.deactivate',
      details: {},
    }),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(
    { ...database.connection('app'), maxConnections: 4 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe(`adding a membership (B4-1, Postgres ${server.version})`, () => {
  it('adds it ACTIVE with its role, listed in the directory by its ID, its first signed state on the chain', async () => {
    const org = await organization();
    const user = await person();

    const { id, recorded } = await add(org, user, 'admin');

    expect(recorded).toMatchObject({ version: 1, seq: 3n });
    expect(await check(org, user)).toEqual({ outcome: 'active', id, role: 'admin' });
    const { row, entry, event } = await withTenant(app, org, async (tx) => ({
      row: await tx.selectFrom('identity.memberships').selectAll().executeTakeFirstOrThrow(),
      entry: await tx.selectFrom('directory.members').selectAll().where('org_id', '=', org).execute(),
      event: await tx
        .selectFrom('audit.events')
        .select(['actor_type', 'actor_id', 'action', 'subject_type', 'subject_id', 'subject_version', 'details'])
        .where('seq', '=', 3n)
        .executeTakeFirstOrThrow(),
    }));
    expect(row).toEqual({
      org_id: org,
      id,
      user_id: user,
      role: 'admin',
      status: 'ACTIVE',
      joined_at: clock.now(),
      state_version: 1,
      state_event_id: recorded.eventId.toLowerCase(),
    });
    expect(entry).toEqual([{ user_id: user, org_id: org, membership_id: id }]);
    expect(event).toMatchObject({
      actor_type: 'system',
      actor_id: 'test-operator',
      action: 'membership.created',
      subject_type: 'membership',
      subject_id: id,
      subject_version: 1,
    });
    expect(JSON.parse(event.details)).toMatchObject({ role: 'admin' });
    expect(alarms()).toEqual([]);
  });

  it.each(['admin', 'approver', 'developer', 'viewer'] as const)('holds the role %s as it was given', async (role) => {
    const org = await organization();
    const user = await person();

    await add(org, user, role);

    expect(await check(org, user)).toMatchObject({ outcome: 'active', role });
  });

  it('refuses a second membership for the same person in the same organisation, leaving the first', async () => {
    const org = await organization();
    const user = await person();
    const { id } = await add(org, user, 'viewer');

    await expect(add(org, user, 'admin')).rejects.toMatchObject({ code: '23505', constraint: 'members_pkey' });

    expect(await check(org, user)).toEqual({ outcome: 'active', id, role: 'viewer' });
  });

  it("refuses a transaction that isn't withTenant's for the organisation, writing nothing", async () => {
    const org = await organization();
    const other = await organization();
    const user = await person();

    await expect(add(org, user, 'admin', other)).rejects.toBeInstanceOf(TenantContextError);

    expect(await check(org, user)).toEqual({ outcome: 'none' });
    expect(await organizationsOf(app, user)).toEqual([]);
  });

  it('refuses one in an organisation the directory doesn’t list, by the key to its list', async () => {
    const unlisted = ids.next();

    await expect(add(unlisted, await person())).rejects.toMatchObject({
      code: '23503',
      constraint: 'members_org_id_fkey',
    });
  });

  it('refuses one for someone who has never signed in, by the key to the people', async () => {
    const org = await organization();

    await expect(add(org, ids.next())).rejects.toMatchObject({ code: '23503', constraint: 'members_user_id_fkey' });
  });
});

describe('a person’s membership, read for a decision', () => {
  it('is none for a person with no membership there, even one who is a member elsewhere', async () => {
    const mine = await organization();
    const theirs = await organization();
    const user = await person();
    await add(theirs, user, 'admin');

    expect(await check(mine, user)).toEqual({ outcome: 'none' });
    expect(await check(mine, await person())).toEqual({ outcome: 'none' });
  });

  it('is deactivated once deactivated, whatever its role, and deactivating again is refused', async () => {
    const org = await organization();
    const user = await person();
    const { id } = await add(org, user, 'admin');

    expect(await deactivate(org, id)).toMatchObject({ outcome: 'changed', from: 'ACTIVE', to: 'DEACTIVATED' });
    expect(await check(org, user)).toEqual({ outcome: 'deactivated', id });
    expect(await deactivate(org, id)).toEqual({ outcome: 'refused', from: 'DEACTIVATED' });
    expect(alarms()).toEqual([]);
  });

  it("is none for a person whose entry names someone else's membership: its signed state names who it is", async () => {
    const org = await organization();
    const admin = await person();
    const stranger = await person();
    const { id } = await add(org, admin, 'admin');
    // The app may add an entry; nothing but the membership's own key ties an entry to it.
    await withTenant(app, org, (tx) =>
      tx.insertInto('directory.members').values({ user_id: stranger, org_id: org, membership_id: id }).execute(),
    );

    expect(await check(org, stranger)).toEqual({ outcome: 'none' });
    expect(await check(org, admin)).toMatchObject({ outcome: 'active', id, role: 'admin' });
    expect(alarms()).toEqual([]);
  });

  it('is none for a person whose entry names no membership at all', async () => {
    const org = await organization();
    const user = await person();
    await withTenant(app, org, (tx) =>
      tx.insertInto('directory.members').values({ user_id: user, org_id: org, membership_id: ids.next() }).execute(),
    );

    expect(await check(org, user)).toEqual({ outcome: 'none' });
    expect(alarms()).toEqual([]);
  });

  it('throws on a verified state whose role is none of the four, rather than grant it anything', async () => {
    const org = await organization();
    const user = await person();
    const { id } = await add(org, user, 'admin');

    await expect(
      withSignedStates(app, org, services(), (tx, states) => {
        // A seal can only hold what record wrote, which the table holds to the four: this stands in for a bug there.
        const verifiedState: typeof states.verifiedState = async (...args) => {
          const state = await states.verifiedState(...args);
          return state.outcome === 'verified'
            ? { ...state, fields: new Map([...state.fields, ['role', 'owner']]) }
            : state;
        };
        return membershipOf(tx, { ...states, verifiedState }, org, user);
      }),
    ).rejects.toThrow(`A verified membership holds a role that isn't one: ${id}`);
  });

  it("is refused from another organisation's transaction", async () => {
    const org = await organization();
    const other = await organization();
    const user = await person();
    await add(org, user, 'admin');

    await expect(
      withSignedStates(app, other, services(), (tx, states) => membershipOf(tx, states, org, user)),
    ).rejects.toBeInstanceOf(TenantContextError);
  });

  it('finds the person by their ID whatever its case', async () => {
    const org = await organization();
    const user = await person();
    const { id } = await add(org, user, 'developer');
    expect(user.toUpperCase()).not.toBe(user);

    expect(await check(org, user.toUpperCase())).toMatchObject({ outcome: 'active', id });
  });

  it('is read for a decision, a share lock: two readers of the same membership at once never wait on each other', async () => {
    const org = await organization();
    const user = await person();
    await add(org, user, 'admin');
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let read = (): void => undefined;
    const first = new Promise<void>((resolve) => {
      read = resolve;
    });

    const holder = withSignedStates(app, org, services(), async (tx, states) => {
      const found = await membershipOf(tx, states, org, user);
      read();
      await held;
      return found;
    });
    await first;
    try {
      expect(await within(5_000, check(org, user), 'the second read')).toMatchObject({ outcome: 'active' });
    } finally {
      release();
    }
    expect(await holder).toMatchObject({ outcome: 'active' });
  });

  it("gives a person's organisations from the directory, in order, and none of anyone else's", async () => {
    const [first, second, elsewhere] = [await organization(), await organization(), await organization()];
    const user = await person();
    await add(second, user);
    await add(first, user);
    await add(elsewhere, await person());

    expect(await organizationsOf(app, user)).toEqual([first, second].sort());
  });

  it("keeps a deactivated member's organisation on their list: the list is where to look, never what is found", async () => {
    const org = await organization();
    const user = await person();
    const { id } = await add(org, user);
    await deactivate(org, id);

    expect(await organizationsOf(app, user)).toEqual([org]);
    expect(await check(org, user)).toEqual({ outcome: 'deactivated', id });
  });

  it('gives up on the directory read after 10 seconds, a wait for a lock included, rather than hang', async () => {
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table directory.members in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, organizationsOf(app, ids.next()), 'the read')).rejects.toThrow(/statement timeout/);
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe("a request's lookup of a membership, in a transaction of its own (B4-2a)", () => {
  it('reads it verified, as membershipOf does, in the organisation it names', async () => {
    const org = await organization();
    const other = await organization();
    const user = await person();
    const { id } = await add(org, user, 'approver');

    expect(await membershipFor(app, services(), org, user)).toEqual({ outcome: 'active', id, role: 'approver' });
    expect(await membershipFor(app, services(), other, user)).toEqual({ outcome: 'none' });
    expect(alarms()).toEqual([]);
  });

  it('gives up after 10 seconds, a wait for a lock included, rather than hold the request', async () => {
    const org = await organization();
    const user = await person();
    await add(org, user, 'admin');
    const holder = await database.connect('admin');
    await holder.query('begin');
    await holder.query('lock table directory.members in access exclusive mode');
    try {
      const began = performance.now();
      await expect(within(20_000, membershipFor(app, services(), org, user), 'the lookup')).rejects.toThrow(
        /statement timeout/,
      );
      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe('the walls round a membership', () => {
  it('SEC-TEN-02 another organisation’s memberships are out of sight with no filter at all: row security alone', async () => {
    const mine = await organization();
    const theirs = await organization();
    const me = await person();
    const them = await person();
    const { id } = await add(mine, me);
    await add(theirs, them);

    const seen = await withTenant(app, mine, (tx) => tx.selectFrom('identity.memberships').select(['id']).execute());
    expect(seen).toEqual([{ id }]);
    expect(await app.selectFrom('identity.memberships').select('id').execute()).toEqual([]);
  });

  it('a membership written for another organisation is refused by the policy’s check', async () => {
    const mine = await organization();
    const theirs = await organization();
    const user = await person();

    await expect(
      withTenant(app, mine, async (tx) => {
        const id = ids.next();
        await tx.insertInto('directory.members').values({ user_id: user, org_id: theirs, membership_id: id }).execute();
        await tx
          .insertInto('identity.memberships')
          .values({ org_id: theirs, id, user_id: user, role: 'admin', status: 'ACTIVE', joined_at: clock.now() })
          .execute();
      }),
    ).rejects.toMatchObject({ code: '42501', message: expect.stringContaining('row-level security') as unknown });
  });

  it('the app can’t delete a membership or change its key, nor delete or change its entry', async () => {
    const org = await organization();
    const user = await person();
    const other = await person();
    const { id } = await add(org, user, 'admin');

    const attempts: ((tx: MembershipsTransaction) => Promise<unknown>)[] = [
      (tx) => tx.deleteFrom('identity.memberships').where('id', '=', id).execute(),
      (tx) => tx.updateTable('identity.memberships').set({ org_id: other }).where('id', '=', id).execute(),
      (tx) => tx.updateTable('identity.memberships').set({ id: other }).where('id', '=', id).execute(),
      (tx) => tx.deleteFrom('directory.members').where('user_id', '=', user).execute(),
      (tx) => tx.updateTable('directory.members').set({ user_id: other }).where('user_id', '=', user).execute(),
    ];
    for (const attempt of attempts) {
      await expect(withTenant(app, org, attempt)).rejects.toMatchObject({ code: '42501' });
    }

    expect(await check(org, user)).toEqual({ outcome: 'active', id, role: 'admin' });
  });

  it('a membership moved to another person past record is unsigned, and denied at the next read with the alarm', async () => {
    const org = await organization();
    const admin = await person();
    const other = await person();
    const { id } = await add(org, admin, 'admin');

    await withTenant(app, org, async (tx) => {
      await tx.insertInto('directory.members').values({ user_id: other, org_id: org, membership_id: id }).execute();
      await tx.updateTable('identity.memberships').set({ user_id: other }).where('id', '=', id).execute();
    });

    expect(await check(org, other)).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(alarms()).toEqual([expect.objectContaining({ subjectType: 'membership', objectId: id, reason: 'seal' })]);
  });

  it.each([
    ['with no directory entry', null],
    ['with an entry naming another membership', 'other'],
  ] as const)('a membership %s is refused by its key to the directory', async (_, entry) => {
    const org = await organization();
    const user = await person();

    await expect(
      withTenant(app, org, async (tx) => {
        const id = ids.next();
        if (entry !== null) {
          await tx
            .insertInto('directory.members')
            .values({ user_id: user, org_id: org, membership_id: ids.next() })
            .execute();
        }
        await tx
          .insertInto('identity.memberships')
          .values({ org_id: org, id, user_id: user, role: 'viewer', status: 'ACTIVE', joined_at: clock.now() })
          .execute();
      }),
    ).rejects.toMatchObject({ code: '23503', constraint: 'listed_in_the_directory' });
  });

  it('a role that isn’t one of the four is refused by the table, and a new row starts ACTIVE whatever it says', async () => {
    const org = await organization();
    const user = await person();
    /** Writes the row past the module, with its entry, in a transaction rolled back if nothing refuses it. */
    const written = (role: string, status: string) =>
      withTenant(app, org, async (tx) => {
        const id = ids.next();
        await tx.insertInto('directory.members').values({ user_id: user, org_id: org, membership_id: id }).execute();
        await tx
          .insertInto('identity.memberships')
          .values({ org_id: org, id, user_id: user, role, status, joined_at: clock.now() })
          .execute();
        throw new Error('rolled back');
      });

    for (const role of ['owner', 'Admin', '']) {
      await expect(written(role, 'ACTIVE')).rejects.toMatchObject({
        code: '23514',
        constraint: 'memberships_role_check',
      });
    }
    await expect(written('admin', 'DEACTIVATED')).rejects.toMatchObject({ code: '23514', constraint: 'status_guard' });
    await expect(written('admin', 'ACTIVE')).rejects.toThrow('rolled back');
  });

  it('a deactivated membership is never made active again past the module: the status guard refuses the move', async () => {
    const org = await organization();
    const user = await person();
    const { id } = await add(org, user, 'admin');
    await deactivate(org, id);

    await expect(
      withTenant(app, org, (tx) =>
        tx.updateTable('identity.memberships').set({ status: 'ACTIVE' }).where('id', '=', id).execute(),
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'status_guard' });

    expect(await check(org, user)).toEqual({ outcome: 'deactivated', id });
  });

  it('the backup role reads both tables, every organisation’s rows, as a logical backup must', async () => {
    const org = await organization();
    const user = await person();
    const { id } = await add(org, user, 'approver');
    const backup = database.as('backup');

    expect(await backup.query('select membership_id from directory.members where user_id = $1', [user])).toEqual([
      { membership_id: id },
    ]);
    expect(await backup.query('select role, status from identity.memberships where id = $1', [id])).toEqual([
      { role: 'approver', status: 'ACTIVE' },
    ]);
  });
});
