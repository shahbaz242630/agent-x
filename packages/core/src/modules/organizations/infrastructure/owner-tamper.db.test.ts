// FX-TAMPER on the organisation's row (SEC-DB-10, B1a), as the database's
// owner: agentx_owner, the role the migration job logs in as, holding none of
// the app's keys, working inside one organisation (forced row security binds
// it too) through @agentx/testing's tamperAsOwner, the same scripts A3d proved
// on a stand-in table. Each case is denied by the row check, with the SEV-1
// alarm; the live schema guard, which now holds this table to its own rights,
// is clean before and after each one, so a leftover can't hide a miss.
//
// The integrity hold that a mismatch also sets on the organisation is B1b's.
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import { createDatabase, type Database, liveSchemaProblems, withTenant } from '@agentx/platform/db';
import { createKeyProvider, type KeyMaterial, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import {
  type AuditTables,
  type AuditTrail,
  createAuditTrail,
  createSignedStates,
  type SignedStates,
  type TamperSign,
} from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, ORGANIZATIONS } from './organizations.ts';
import type { OrganizationsTables } from './tables.ts';

type Tables = OrganizationsTables & DirectoryTables & AuditTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ) as unknown as KeyMaterial,
);
const trail: AuditTrail = createAuditTrail({ keys, ids: new SequentialIds(0x500) });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let capture: LogCapture;
let states: SignedStates;
let owner: OwnerTamper;

let number = 0;
/** A new UUID, so no two tests share an organisation. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x5000 + number).toString(16).padStart(12, '0')}`;
};
let org: string;

const change = (action: string) => ({ actor: { type: 'user' as const, id: newId() }, action, details: {} });

const check = (lock: 'share' | 'change' = 'share') =>
  withTenant(app, org, (tx) => states.verifiedState(tx, ORGANIZATIONS, { orgId: org, id: org }, lock));

const freeze = () =>
  withTenant(app, org, (tx) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: org, id: org }, 'freeze', change('organization.freeze')),
  );

/** What the live schema guard reports, as the API runs it: with the product's own list of authority tables. */
const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

/** Denied read for a decision and read for a change, each with its alarm. */
async function deniedWith(sign: TamperSign): Promise<void> {
  expect(await check()).toEqual({ outcome: 'tampered', sign });
  expect(await check('change')).toEqual({ outcome: 'tampered', sign });
  const alarm: unknown = expect.objectContaining({
    level: 'error',
    event: 'audit.integrity_failed',
    chain: 'organisation',
    check: 'state',
    reason: sign,
    subjectType: 'organization',
    objectId: org,
    orgId: org,
  });
  expect(alarms()).toEqual([alarm, alarm]);
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
  states = createSignedStates({ keys, trail, logger: loggerFor(capture) });
  org = newId();
  owner = await tamperAsOwner(database, ORGANIZATIONS, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  expect(await guard()).toEqual([]);
});

/** Creates this test's organisation, as the operator's command will, and clears the log of it. */
async function created(): Promise<void> {
  await withTenant(app, org, (tx) =>
    createOrganization(tx, createSignedStates({ keys, trail, logger: loggerFor(new LogCapture()) }), {
      id: org,
      name: 'Acme Trading LLC',
      actor: { type: 'system', id: 'test-operator' },
    }),
  );
}

describe(`FX-TAMPER as the owner on an organisation's row: denied by the row check (Postgres ${server.version})`, () => {
  it('unfrozen: the status set back to ACTIVE, along a move the status guard allows', async () => {
    await created();
    await freeze();
    await owner.setColumn(org, 'status', 'ACTIVE');

    await deniedWith('seal');
  });

  it('unfrozen by rolling the row back to its saved, validly signed state', async () => {
    await created();
    const saved = await owner.saveRow(org);
    await freeze();
    await owner.restoreRow(saved);

    await deniedWith('pointer');
  });

  it('planted with no event, an organisation the app never created', async () => {
    await owner.query('insert into directory.orgs (org_id) values ($1)', [org]);
    await owner.query(
      "insert into organizations.organizations (org_id, id, name, status) values ($1, $1, 'Planted', 'ACTIVE')",
      [org],
    );

    await deniedWith('unsigned');
  });

  it('deleted, which the app role cannot do', async () => {
    await created();
    await owner.deleteRow(org);

    await deniedWith('deleted');
  });

  it.each([
    ['its events stripped of their seals', (tamper: OwnerTamper, id: string) => tamper.stripSeals(id)],
    ['its events deleted', (tamper: OwnerTamper, id: string) => tamper.deleteEvents(id)],
  ])('%s', async (_, tamper) => {
    await created();
    await freeze();
    await tamper(owner, org);

    await deniedWith('unsigned');
  });

  it('the app role given DELETE on it: the guard names the right', async () => {
    await created();
    await owner.query('grant delete on organizations.organizations to agentx_app');
    try {
      expect(await guard()).toEqual(['agentx_app may DELETE on organizations.organizations']);
    } finally {
      await owner.query('revoke delete on organizations.organizations from agentx_app');
    }
    expect(await check()).toMatchObject({ outcome: 'verified', version: 1 });
  });
});
