// 6A1: a person's own organisations, on the real migrated schema, as the app
// role: each organisation the directory lists them in, read in its own
// transaction through the person's verified membership and the organisation's
// verified status. A membership deactivated, or another person's, leaves the
// organisation out; one tampered with leaves it unreadable, with the alarm,
// and the person's other organisations still listed.
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  addMembership,
  type IdentityTables,
  MEMBERSHIPS,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, ORGANIZATIONS, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMyOrganizations } from './my-organizations.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb000_0000_0000);
const clock = new FixedClock(new Date('2026-10-26T09:00:00Z'));
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let capture: LogCapture;
const services = () => ({ keys, ids, logger: testLogger(capture) });

const organization = async (name: string): Promise<string> => {
  const id = ids.next();
  await withSignedStates(app, id, services(), (tx, states) =>
    createOrganization(tx, states, { id, name, actor: OPERATOR }),
  );
  return id;
};

let subjects = 0;
const person = (): Promise<string> => {
  subjects += 1;
  return userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `mine-${String(subjects)}` },
    { ids, clock },
  );
};

const add = (orgId: string, userId: string, role: Role) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const id = ids.next();
    await addMembership(tx, states, { orgId, id, userId, role, joinedAt: clock.now(), actor: OPERATOR });
    return id;
  });

const move = (orgId: string, table: typeof MEMBERSHIPS | typeof ORGANIZATIONS, id: string, event: string) =>
  withSignedStates(app, orgId, services(), (tx, states) =>
    states.changeStatus(tx, table, { orgId, id }, event as never, {
      actor: OPERATOR,
      action: `test.${event}`,
      details: {},
    }),
  );

const listed = () =>
  createMyOrganizations({ database: app, services: (correlationId) => ({ ...services(), correlationId }) });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe(`a person’s own organisations (6A1, Postgres ${server.version})`, () => {
  it('lists each with their role, whether it is frozen and its name, in order of ID', async () => {
    const first = await organization('Staging-Test-Org-1');
    const second = await organization('Glide Logistics LLC');
    const someone = await person();
    await add(first, someone, 'admin');
    await add(second, someone, 'viewer');
    await move(second, ORGANIZATIONS, second, 'freeze');

    expect(await listed()(someone, '0199a0f0-0000-7000-8000-00000000c001')).toEqual({
      organizations: [
        { id: first, name: 'Staging-Test-Org-1', role: 'admin', frozen: false },
        { id: second, name: 'Glide Logistics LLC', role: 'viewer', frozen: true },
      ],
      unreadable: [],
    });
  });

  it('leaves out an organisation the person was removed from, and lists nothing for someone in none', async () => {
    const kept = await organization('Kept LLC');
    const left = await organization('Left LLC');
    const someone = await person();
    await add(kept, someone, 'approver');
    const membership = await add(left, someone, 'developer');
    await move(left, MEMBERSHIPS, membership, 'deactivate');

    expect(await listed()(someone, '0199a0f0-0000-7000-8000-00000000c002')).toEqual({
      organizations: [{ id: kept, name: 'Kept LLC', role: 'approver', frozen: false }],
      unreadable: [],
    });
    expect(await listed()(await person(), '0199a0f0-0000-7000-8000-00000000c003')).toEqual({
      organizations: [],
      unreadable: [],
    });
  });

  it('answers an organisation whose membership was tampered with as unreadable, with the alarm, and lists the rest', async () => {
    const fine = await organization('Fine LLC');
    const forged = await organization('Forged LLC');
    const someone = await person();
    await add(fine, someone, 'viewer');
    const membership = await add(forged, someone, 'viewer');
    const owner = await tamperAsOwner(database, MEMBERSHIPS, forged);
    try {
      await owner.setColumn(membership, 'role', 'admin');
    } finally {
      await owner.end();
    }

    expect(await listed()(someone, '0199a0f0-0000-7000-8000-00000000c004')).toEqual({
      organizations: [{ id: fine, name: 'Fine LLC', role: 'viewer', frozen: false }],
      unreadable: [forged],
    });
    expect(capture.lines().filter((line) => line.event === 'audit.integrity_failed')).toEqual([
      expect.objectContaining({ orgId: forged }),
    ]);
  });

  it('answers an organisation whose own status was tampered with as unreadable', async () => {
    const forged = await organization('Status LLC');
    const someone = await person();
    await add(forged, someone, 'admin');
    const owner = await tamperAsOwner(database, ORGANIZATIONS, forged);
    try {
      await owner.withoutStatusGuard(() => owner.setColumn(forged, 'status', 'FROZEN'));
    } finally {
      await owner.end();
    }

    expect(await listed()(someone, '0199a0f0-0000-7000-8000-00000000c005')).toEqual({
      organizations: [],
      unreadable: [forged],
    });
  });
});
