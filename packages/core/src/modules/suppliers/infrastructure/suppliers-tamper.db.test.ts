// FX-TAMPER on a supplier and its versions (SEC-DB-10, E1-1), as the
// database's owner: agentx_owner, the role the migration job logs in as,
// holding none of the app's keys, working inside one organisation through
// @agentx/testing's tamperAsOwner, as a funding source is tested
// (sources-tamper.db.test.ts).
//
// Each change to what a supplier may be paid on (its status, its current or
// pending version, its cooling-off, its verifier, its payee key) or to what
// a version says (its supplier, its name, the contacts it holds, the
// independent source, who entered it and when, its payee reference) is
// denied by the row check, with the SEV-1 alarm, and puts the organisation
// on its integrity hold. A contact moved to another row or kind won't open
// (SEC-DB-01). The live schema guard, with the product's own list, is clean
// before and after each case.
import { createDatabase, type Database, liveSchemaProblems } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { type TamperSign, withSignedStates } from '../../audit/index.ts';
import { createOrganization } from '../../organizations/index.ts';
import type { SupplierDetails } from '../domain/supplier.ts';
import {
  addSupplier,
  addVersion,
  contactsOf,
  SupplierContactsUnreadable,
  SUPPLIER_VERSIONS,
  SUPPLIERS,
  suppliersPage,
  supplierOf,
  versionOf,
} from './suppliers.ts';
import type { SuppliersTables } from './tables.ts';

// The tables an organisation is made in, as createOrganization takes them: the suppliers module
// may not name the directory's (ADR-004's map), which making one writes to.
type OrganizationTables = Parameters<typeof createOrganization>[0] extends Transaction<infer T> ? T : never;
type Tables = SuppliersTables & OrganizationTables;

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
const ids = new SequentialIds(0xe11f);
const clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: 'accounts@gulfoffice.example', tradeLicence: 'CN-7654321' },
  source: { kind: 'official_website', ref: 'https://gulfoffice.example' },
};

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let capture: LogCapture;
/** The owner at the suppliers' table, and at their versions'. */
let owner: OwnerTamper;
let ownerOfVersions: OwnerTamper;
let org: string;

const services = () => ({ keys, ids, logger: loggerFor(capture) });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

/** A supplier of this test's organisation, with its first version, made logging to a capture of its own. */
async function addedSupplier(details: SupplierDetails = DETAILS): Promise<{ id: string; versionId: string }> {
  const id = ids.next();
  const versionId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addSupplier(tx, states, keys, {
      orgId: org,
      id,
      versionId,
      supplier: details,
      enteredBy: ids.next(),
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return { id, versionId };
}

const readSupplier = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) => supplierOf(tx, states, { orgId: org, id }, 'share'));

const readVersion = (id: string, supplierId: string) =>
  withSignedStates(app, org, services(), (tx, states) => versionOf(tx, states, { orgId: org, id }, supplierId));

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

const suspend = (id: string) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, SUPPLIERS, { orgId: org, id }, 'suspend', {
      actor: OPERATOR,
      action: 'supplier.suspended',
      details: {},
    }),
  );

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Denied with the alarm on the row, and the organisation held for it. */
async function deniedAndHeld(
  read: () => Promise<unknown>,
  { id, subjectType, sign }: { id: string; subjectType: 'supplier' | 'supplier_version'; sign: TamperSign },
): Promise<void> {
  expect(await read()).toEqual({ outcome: 'tampered', sign });
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      chain: 'organisation',
      check: 'state',
      reason: sign,
      subjectType,
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ orgId: org, reason: sign, subjectType }),
  ]);
}

const supplierDenied = (id: string, sign: TamperSign) =>
  deniedAndHeld(() => readSupplier(id), { id, subjectType: 'supplier', sign });

const versionDenied = (versionId: string, supplierId: string, sign: TamperSign) =>
  deniedAndHeld(() => readVersion(versionId, supplierId), { id: versionId, subjectType: 'supplier_version', sign });

/** A second version of the supplier, planted by the owner with no event: one the app never made. */
async function plantedVersion(supplierId: string): Promise<string> {
  const id = ids.next();
  await owner.query(
    `insert into suppliers.supplier_versions (org_id, id, supplier_id, version, display_name, contacts, phone_ciphertext,
       contacts_key_version, phone_since, source_kind, source_ref, entered_by, entered_at)
     select org_id, $2, supplier_id, 2, 'Planted Payee LLC', 'phone', phone_ciphertext, contacts_key_version, phone_since,
       source_kind, source_ref, entered_by, entered_at
       from suppliers.supplier_versions where org_id = $1 and supplier_id = $3 and version = 1`,
    [org, id, supplierId],
  );
  return id;
}

/**
 * The made-once guard refuses the owner's rewrites of a version too, so an
 * owner at a version switches it off first, as a real one would have to: each
 * case below runs with it off, and it is back on before the live guard's
 * check after each (which would name it switched off, or dropped). What the
 * guard itself refuses, and the live guard seeing it tampered with, are cases
 * of their own.
 */
const MADE_ONCE_OFF = 'alter table suppliers.supplier_versions disable trigger made_once';
const MADE_ONCE_ON = 'alter table suppliers.supplier_versions enable trigger made_once';

/** 0032's check that a version's ciphertexts are the contacts it says it holds, put back after a case drops it. */
const RESTORE_CONTACTS_AS_HELD = `alter table suppliers.supplier_versions add constraint contacts_as_held check (
  (email_ciphertext IS NOT NULL) = (contacts IN ('phone email', 'phone email licence'))
  AND (licence_ciphertext IS NOT NULL) = (contacts IN ('phone licence', 'phone email licence')))`;

/** The live guard as the product runs it: every authority table, and each guard the list says a table carries. */
const product = () =>
  liveSchemaProblems(app, {
    ...ROLES,
    authorityTables: AUTHORITY_TABLES,
    statusGuardedTables: AUTHORITY_TABLES.filter((table) => table.rules !== undefined).map(({ table }) => table),
    madeOnceTables: AUTHORITY_TABLES.filter((table) => table.madeOnce === true).map(({ table }) => table),
  });

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
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owner = await tamperAsOwner(database, SUPPLIERS, org);
  ownerOfVersions = await tamperAsOwner(database, SUPPLIER_VERSIONS, org);
  expect(await product()).toEqual([]);
  await ownerOfVersions.query(MADE_ONCE_OFF);
});

afterEach(async () => {
  await ownerOfVersions.query(MADE_ONCE_ON);
  await owner.end();
  await ownerOfVersions.end();
  expect(await product()).toEqual([]);
});

describe(`FX-TAMPER as the owner on a supplier: denied by the row check, and held (Postgres ${server.version})`, () => {
  it('verified past the app, on its current version, as the table’s check asks', async () => {
    const { id } = await addedSupplier();
    await owner.query(
      'update suppliers.suppliers set status = $2, verified_version_id = current_version_id where id = $1',
      [id, 'VERIFIED'],
    );

    await supplierDenied(id, 'seal');
  });

  it('a suspended supplier let go of its brake past the app', async () => {
    const { id } = await addedSupplier();
    await suspend(id);
    await owner.setColumn(id, 'status', 'UNVERIFIED');

    await supplierDenied(id, 'seal');
  });

  it('pointed at a version the app never made', async () => {
    const { id } = await addedSupplier();
    const planted = await plantedVersion(id);
    await owner.setColumn(id, 'current_version_id', planted);

    await supplierDenied(id, 'seal');
  });

  it('given a pending version the app never made', async () => {
    const { id } = await addedSupplier();
    const planted = await plantedVersion(id);
    await owner.setColumn(id, 'pending_version_id', planted);

    await supplierDenied(id, 'seal');
  });

  it.each([
    ['cooling_off_until', '2026-09-01T00:00:00Z'],
    ['verified_by', '01a0f26d-573c-719c-a913-601fdf758b66'],
    ['payee_key', 'planted-payee'],
  ] as const)('its %s set', async (column, value) => {
    const { id } = await addedSupplier();
    await owner.setColumn(id, column, value);

    await supplierDenied(id, 'seal');
  });

  it('given its own version as the one verified, past the app', async () => {
    const { id, versionId } = await addedSupplier();
    await owner.setColumn(id, 'verified_version_id', versionId);

    await supplierDenied(id, 'seal');
  });

  it('its payee key given a key version', async () => {
    const { id } = await addedSupplier();
    await owner.query('update suppliers.suppliers set payee_key = $2, payee_key_version = 1 where id = $1', [
      id,
      'planted-payee',
    ]);

    await supplierDenied(id, 'seal');
  });

  it('a suspended supplier rolled back to its saved, validly signed, unverified state', async () => {
    const { id } = await addedSupplier();
    const saved = await owner.saveRow(id);
    await suspend(id);
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    await supplierDenied(id, 'pointer');
  });

  it('deleted with its version, which the app role cannot do', async () => {
    const { id, versionId } = await addedSupplier();
    // One statement: each row is the other's key, so neither goes alone.
    await owner.query(
      'with gone as (delete from suppliers.suppliers where id = $1 returning id) delete from suppliers.supplier_versions where id = $2',
      [id, versionId],
    );

    await supplierDenied(id, 'deleted');
  });

  it('planted with no event, on a version planted with it', async () => {
    const id = ids.next();
    const versionId = ids.next();
    await owner.query(
      `with supplier as (
         insert into suppliers.suppliers (org_id, id, status, current_version_id, created_at)
         values ($1, $2, 'UNVERIFIED', $3, now()) returning org_id)
       insert into suppliers.supplier_versions (org_id, id, supplier_id, version, display_name, contacts,
         phone_ciphertext, contacts_key_version, phone_since, source_kind, source_ref, entered_by, entered_at)
       select org_id, $3, $2, 1, 'Planted Payee LLC', 'phone', pg_catalog.decode(pg_catalog.repeat('00', 40), 'hex'), 1,
         now(), 'registry', 'planted', $2, now() from supplier`,
      [org, id, versionId],
    );

    await supplierDenied(id, 'unsigned');
  });

  it('its events stripped of their seals', async () => {
    const { id } = await addedSupplier();
    await owner.stripSeals(id);

    await supplierDenied(id, 'unsigned');
  });

  it('a page holding one supplier rewritten: the whole page refused, not the rest shown', async () => {
    await addedSupplier();
    const { id } = await addedSupplier();
    await owner.query(
      'update suppliers.suppliers set status = $2, verified_version_id = current_version_id where id = $1',
      [id, 'VERIFIED'],
    );

    const page = await withSignedStates(app, org, services(), (tx, states) =>
      suppliersPage(tx, states, org, { after: null, limit: 50 }),
    );

    expect(page).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(await hold()).toMatchObject({ outcome: 'held' });
  });

  it('the live guard sees DELETE granted on the suppliers, and their status guard dropped outright', async () => {
    const asOwner = database.as('owner');
    const [trigger] = await asOwner.query<{ definition: string }>(
      `select pg_catalog.pg_get_triggerdef(oid) as definition from pg_catalog.pg_trigger
        where tgrelid = 'suppliers.suppliers'::regclass and tgname = 'status_guard'`,
    );
    await asOwner.query('grant delete on suppliers.suppliers to agentx_app');
    await asOwner.query('drop trigger status_guard on suppliers.suppliers');
    try {
      const found = await product();
      expect(found).toContain('agentx_app may DELETE on suppliers.suppliers');
      expect(found).toContain('suppliers.suppliers carries no status_guard');
    } finally {
      await asOwner.query('revoke delete on suppliers.suppliers from agentx_app');
      // eslint-disable-next-line agentx/no-string-built-sql -- the trigger's own definition, as Postgres wrote it
      await asOwner.query(trigger?.definition ?? '');
    }
    expect(await product()).toEqual(["suppliers.supplier_versions's made_once is switched off"]);
  });

  it('the live guard sees the made-once guard switched off, dropped, or put back firing at other times', async () => {
    const asOwner = database.as('owner');
    await asOwner.query(MADE_ONCE_ON);
    expect(await product()).toEqual([]);
    await asOwner.query(MADE_ONCE_OFF);
    expect(await product()).toContain("suppliers.supplier_versions's made_once is switched off");
    await asOwner.query('drop trigger made_once on suppliers.supplier_versions');
    try {
      expect(await product()).toContain('suppliers.supplier_versions carries no made_once');
      await asOwner.query(
        'create trigger made_once before insert on suppliers.supplier_versions for each row execute function state_rules.guard_made_once()',
      );
      expect(await product()).toContain("suppliers.supplier_versions's made_once fires at other times");
      await asOwner.query('drop trigger made_once on suppliers.supplier_versions');
    } finally {
      await asOwner.query(
        'create trigger made_once before update on suppliers.supplier_versions for each row execute function state_rules.guard_made_once()',
      );
    }
    // Left off, as the other cases have it: afterEach puts it back on.
    await asOwner.query(MADE_ONCE_OFF);
  });
});

describe(`FX-TAMPER as the owner on a supplier's version: denied by the row check, and held (Postgres ${server.version})`, () => {
  it.each([
    ['display_name', 'Someone Else LLC'],
    ['source_kind', 'registry'],
    ['source_ref', 'https://planted.example'],
    ['entered_by', '01a0f26d-573c-719c-a913-601fdf758b66'],
    ['entered_at', '2026-12-01T00:00:00Z'],
    ['phone_since', '2026-08-01T00:00:00Z'],
    ['version', 7],
  ] as const)('its %s changed', async (column, value) => {
    const { id, versionId } = await addedSupplier();
    await ownerOfVersions.setColumn(versionId, column, value);

    await versionDenied(versionId, id, 'seal');
  });

  it('given a payee reference and the registration it came from', async () => {
    const { id, versionId } = await addedSupplier();
    await ownerOfVersions.query(
      'update suppliers.supplier_versions set registration_id = $2, beneficiary_ref = $3, payee_hint = $4 where id = $1',
      [versionId, ids.next(), 'fake-beneficiary-planted', 'AE…0000'],
    );

    await versionDenied(versionId, id, 'seal');
  });

  it('its email taken away, with the contacts it holds rewritten to match', async () => {
    const { id, versionId } = await addedSupplier();
    await ownerOfVersions.query(
      "update suppliers.supplier_versions set email_ciphertext = null, contacts = 'phone licence' where id = $1",
      [versionId],
    );

    await versionDenied(versionId, id, 'seal');
  });

  it('moved to another supplier of the organisation: refused by the key its own supplier rests on', async () => {
    const { versionId } = await addedSupplier();
    const other = await addedSupplier();

    await expect(
      ownerOfVersions.query('update suppliers.supplier_versions set supplier_id = $2, version = 2 where id = $1', [
        versionId,
        other.id,
      ]),
    ).rejects.toThrow(/current_is_its_own/);
  });

  it('moved to another supplier with that key dropped: caught by its seal', async () => {
    const { versionId } = await addedSupplier();
    const other = await addedSupplier();
    await ownerOfVersions.query('alter table suppliers.suppliers drop constraint current_is_its_own');
    try {
      await ownerOfVersions.query(
        'update suppliers.supplier_versions set supplier_id = $2, version = 2 where id = $1',
        [versionId, other.id],
      );

      await versionDenied(versionId, other.id, 'seal');
    } finally {
      await ownerOfVersions.query(
        'update suppliers.supplier_versions set supplier_id = (select id from suppliers.suppliers where current_version_id = $1), version = 1 where id = $1',
        [versionId],
      );
      await ownerOfVersions.query(
        `alter table suppliers.suppliers add constraint current_is_its_own foreign key (org_id, id, current_version_id)
           references suppliers.supplier_versions (org_id, supplier_id, id) deferrable initially deferred`,
      );
    }
  });

  it('its events stripped of their seals', async () => {
    const { id, versionId } = await addedSupplier();
    await ownerOfVersions.stripSeals(versionId);

    await versionDenied(versionId, id, 'unsigned');
  });

  it('a page whose supplier’s version was rewritten: the whole page refused', async () => {
    const { versionId } = await addedSupplier();
    await ownerOfVersions.setColumn(versionId, 'display_name', 'Someone Else LLC');

    const page = await withSignedStates(app, org, services(), (tx, states) =>
      suppliersPage(tx, states, org, { after: null, limit: 50 }),
    );

    expect(page).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(await hold()).toMatchObject({ outcome: 'held' });
  });
});

describe(`a contact moved past the app won't open (SEC-DB-01, Postgres ${server.version})`, () => {
  /** The version's contacts, opened from its verified state. */
  const open = (versionId: string, supplierId: string) =>
    withSignedStates(app, org, services(), async (tx, states) => {
      const version = await versionOf(tx, states, { orgId: org, id: versionId }, supplierId);
      if (version.outcome !== 'found') throw new Error(`No version: ${version.outcome}`);
      return contactsOf(tx, keys, org, version.version);
    });

  it('the phone copied into the email’s place: its kind is in its associated data', async () => {
    const { id, versionId } = await addedSupplier();
    await ownerOfVersions.query(
      'update suppliers.supplier_versions set email_ciphertext = phone_ciphertext where id = $1',
      [versionId],
    );

    await expect(open(versionId, id)).rejects.toBeInstanceOf(SupplierContactsUnreadable);
  });

  it('another supplier’s phone copied in: its row is in its associated data', async () => {
    const { id, versionId } = await addedSupplier();
    const other = await addedSupplier({
      ...DETAILS,
      contacts: { phone: '+971509999999', email: null, tradeLicence: null },
    });
    await ownerOfVersions.query(
      `update suppliers.supplier_versions set phone_ciphertext =
         (select phone_ciphertext from suppliers.supplier_versions where id = $2) where id = $1`,
      [versionId, other.versionId],
    );

    await expect(open(versionId, id)).rejects.toBeInstanceOf(SupplierContactsUnreadable);
  });

  it('a byte of the licence changed: it no longer opens', async () => {
    const { id, versionId } = await addedSupplier();
    await ownerOfVersions.query(
      `update suppliers.supplier_versions
          set licence_ciphertext = pg_catalog.set_byte(licence_ciphertext, 20, (pg_catalog.get_byte(licence_ciphertext, 20) + 1) % 256)
        where id = $1`,
      [versionId],
    );

    await expect(open(versionId, id)).rejects.toBeInstanceOf(SupplierContactsUnreadable);
  });

  it('an earlier version’s phone copied into a later one of the same supplier: its version is in its associated data', async () => {
    const { id, versionId } = await addedSupplier();
    const later = ids.next();
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      const of = await supplierOf(tx, states, { orgId: org, id }, 'change');
      const follows = await versionOf(tx, states, { orgId: org, id: versionId }, id);
      if (of.outcome !== 'found' || follows.outcome !== 'found') throw new Error('No supplier or version');
      await addVersion(tx, states, keys, {
        of,
        follows: follows.version,
        orgId: org,
        id: later,
        supplierId: id,
        version: 2,
        supplier: { ...DETAILS, contacts: { ...DETAILS.contacts, phone: '+971508888888' } },
        enteredBy: ids.next(),
        enteredAt: clock.now(),
        actor: OPERATOR,
      });
    });
    await ownerOfVersions.query(
      `update suppliers.supplier_versions set phone_ciphertext =
         (select phone_ciphertext from suppliers.supplier_versions where id = $2) where id = $1`,
      [later, versionId],
    );

    await expect(open(later, id)).rejects.toBeInstanceOf(SupplierContactsUnreadable);
  });

  it('an email the version says it holds lost, with the table’s check dropped: refused, not shown as none', async () => {
    const { id, versionId } = await addedSupplier();
    await ownerOfVersions.query('alter table suppliers.supplier_versions drop constraint contacts_as_held');
    try {
      await ownerOfVersions.query('update suppliers.supplier_versions set email_ciphertext = null where id = $1', [
        versionId,
      ]);

      await expect(open(versionId, id)).rejects.toBeInstanceOf(SupplierContactsUnreadable);
    } finally {
      await ownerOfVersions.query(
        'update suppliers.supplier_versions set email_ciphertext = licence_ciphertext where id = $1 and email_ciphertext is null',
        [versionId],
      );
      await ownerOfVersions.query(RESTORE_CONTACTS_AS_HELD);
    }
  });

  it('an email planted where the version says it holds none: refused, not shown', async () => {
    const { id, versionId } = await addedSupplier({
      ...DETAILS,
      contacts: { phone: '+971501234567', email: null, tradeLicence: 'CN-7654321' },
    });
    await ownerOfVersions.query('alter table suppliers.supplier_versions drop constraint contacts_as_held');
    try {
      await ownerOfVersions.query(
        'update suppliers.supplier_versions set email_ciphertext = licence_ciphertext where id = $1',
        [versionId],
      );

      await expect(open(versionId, id)).rejects.toBeInstanceOf(SupplierContactsUnreadable);
    } finally {
      await ownerOfVersions.query('update suppliers.supplier_versions set email_ciphertext = null where id = $1', [
        versionId,
      ]);
      await ownerOfVersions.query(RESTORE_CONTACTS_AS_HELD);
    }
  });
});
