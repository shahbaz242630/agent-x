// E3-2a: what verifying a supplier reads of its versions, on the real migrated
// schema as the app role: its first version, and every version since it was
// last verified (from its history in the log), each through its signed
// state; a version removed past the app, or its history edited, is caught.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  type TestSession,
} from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { withSignedStates } from '../../audit/index.ts';
import { createOrganization } from '../../organizations/index.ts';
import type { SupplierDetails } from '../domain/supplier.ts';
import {
  addSupplier,
  addVersion,
  SUPPLIERS,
  supplierOf,
  unverifySupplier,
  verifySupplier,
  versionOf,
  type VersionRecord,
} from './suppliers.ts';
import type { SuppliersTables } from './tables.ts';
import { MOST_VERSIONS_TO_VERIFY, versionsToVerify } from './verifying.ts';

type OrganizationTables = Parameters<typeof createOrganization>[0] extends Transaction<infer T> ? T : never;
type Tables = SuppliersTables & OrganizationTables;

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
const ids = new SequentialIds(0xe320_0000_0000);
const clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: null, tradeLicence: null },
  source: { kind: 'registry', ref: 'DED-REG-88112' },
};

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
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

let org: string;
let supplierId: string;

type Found = Extract<Awaited<ReturnType<typeof supplierOf>>, { outcome: 'found' }>;

/** Work on the supplier, read for change first, as a use case does. */
const onSupplier = <T>(
  work: (tx: Transaction<Tables>, states: Parameters<typeof supplierOf>[1], found: Found) => Promise<T>,
) =>
  withSignedStates(app, org, services(), async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId: org, id: supplierId }, 'change');
    if (found.outcome !== 'found') throw new Error(`No supplier: ${found.outcome}`);
    return work(tx, states, found);
  });

/** A later version made and made current, each entered by a member of its own: its enterer. */
const changed = (version: number) =>
  onSupplier(async (tx, states, found) => {
    const follows = await versionOf(tx, states, { orgId: org, id: found.supplier.currentVersionId }, supplierId);
    if (follows.outcome !== 'found') throw new Error('no current version');
    const id = ids.next();
    const enteredBy = ids.next();
    await addVersion(tx, states, keys, {
      orgId: org,
      id,
      supplierId,
      version,
      supplier: DETAILS,
      enteredBy,
      enteredAt: clock.now(),
      actor: OPERATOR,
      of: found,
      follows: follows.version,
    });
    await states.record(
      tx,
      SUPPLIERS,
      { orgId: org, id: supplierId },
      found.state,
      { current_version_id: id },
      {
        actor: OPERATOR,
        action: 'supplier.test_change',
        details: {},
      },
    );
    return enteredBy;
  });

const verify = () =>
  onSupplier((tx, states, found) =>
    verifySupplier(tx, states, { orgId: org, id: supplierId }, found, { verifiedBy: ids.next(), actor: OPERATOR }),
  );
const unverify = () =>
  onSupplier((tx, states, found) =>
    unverifySupplier(tx, states, { orgId: org, id: supplierId }, found, { actor: OPERATOR }),
  );

/** What verifying reads now, against the supplier's current version (or `current`, standing in for it). */
const toVerify = (current?: VersionRecord) =>
  onSupplier(async (tx, states, found) => {
    const read = await versionOf(tx, states, { orgId: org, id: found.supplier.currentVersionId }, supplierId);
    if (read.outcome !== 'found') throw new Error('no current version');
    return versionsToVerify(tx, states, org, found.supplier, current ?? read.version);
  });

/** The enterers and numbers of what was read. */
const shape = (read: Awaited<ReturnType<typeof toVerify>>) =>
  read.outcome === 'read'
    ? { first: read.first.version, since: read.since.map(({ version, enteredBy }) => [version, enteredBy]) }
    : read;

let firstEnterer: string;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, services().logger);
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
  supplierId = ids.next();
  firstEnterer = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    addSupplier(tx, states, keys, {
      orgId: org,
      id: supplierId,
      versionId: ids.next(),
      supplier: DETAILS,
      enteredBy: firstEnterer,
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
});

describe(`the versions verifying reads (E3-2a, Postgres ${server.version})`, () => {
  it('reads a new supplier’s first version, as its own and as everything entered since', async () => {
    expect(shape(await toVerify())).toEqual({ first: 1, since: [[1, firstEnterer]] });
  });

  it('reads every version of a supplier never verified, in order', async () => {
    const second = await changed(2);
    const third = await changed(3);

    expect(shape(await toVerify())).toEqual({
      first: 1,
      since: [
        [1, firstEnterer],
        [2, second],
        [3, third],
      ],
    });
  });

  it('reads only what was entered since it was last verified, from its history, with its first version', async () => {
    await changed(2);
    await verify();
    await unverify();
    const third = await changed(3);
    const fourth = await changed(4);

    expect(shape(await toVerify())).toEqual({
      first: 1,
      since: [
        [3, third],
        [4, fourth],
      ],
    });
  });

  it('reads the current version alone when nothing newer was entered since it was verified', async () => {
    const second = await changed(2);
    await verify();
    await unverify();

    expect(shape(await toVerify())).toEqual({ first: 1, since: [[2, second]] });
  });

  it('refuses more versions since the last verification than one read takes, before reading any', async () => {
    const read = await toVerify();
    if (read.outcome !== 'read') throw new Error('not read');
    const far = { ...read.first, version: MOST_VERSIONS_TO_VERIFY + 1 };
    expect(await toVerify(far)).toEqual({ outcome: 'too_many' });
    expect(shape(await toVerify({ ...read.first, version: MOST_VERSIONS_TO_VERIFY }))).toMatchObject({
      outcome: 'incomplete',
    });
  });

  it('raises the alarm on a version read edited past the app: the one verified, or one entered since', async () => {
    await changed(2);
    await verify();
    await unverify();
    await changed(3);
    await changed(4);
    // The owner switches the made-once guard off first, as only the owner can (suppliers-tamper.db.test.ts).
    await attacker.query('alter table suppliers.supplier_versions disable trigger made_once');
    for (const version of [2, 3]) {
      capture = new LogCapture();
      await attacker.query(
        `update suppliers.supplier_versions set display_name = display_name || ' X' where org_id = $1 and version = $2`,
        [org, version],
      );

      expect(await toVerify()).toMatchObject({ outcome: 'tampered' });
      expect(alarms()).toEqual([expect.objectContaining({ subjectType: 'supplier_version' })]);
      await attacker.query(
        `update suppliers.supplier_versions set display_name = left(display_name, -2) where org_id = $1 and version = $2`,
        [org, version],
      );
    }
    await attacker.query('alter table suppliers.supplier_versions enable trigger made_once');
  });

  it('finds a version removed past the app: a number with no version', async () => {
    await changed(2);
    await changed(3);
    await attacker.query('delete from suppliers.supplier_versions where org_id = $1 and version = 2', [org]);

    expect(await toVerify()).toEqual({ outcome: 'incomplete' });
  });

  it('raises the alarm on the supplier’s history edited past the app, and reads nothing', async () => {
    await verify();
    await attacker.query(
      `update audit.events set details = replace(details, 'verifiedVersionId', 'verifiedVersionID')
       where org_id = $1 and action = 'supplier.verifier_recorded'`,
      [org],
    );

    expect(await toVerify()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(alarms()).toEqual([expect.objectContaining({ reason: 'log', subjectType: 'organisation' })]);
  });
});
