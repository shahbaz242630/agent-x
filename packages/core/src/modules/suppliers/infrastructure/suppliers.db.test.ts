// E1-1: suppliers and their versions (0032), on the real migrated schema, as
// the app role. A supplier is added UNVERIFIED with its first version, both
// sealed; its contacts are kept encrypted for their own row and kind, and
// opened only from a verified version; it is found by no other organisation;
// pages of suppliers give each with its current version's name; and the
// tables hold the app to adding rows and moving only what the seal covers.
// What the owner can do past the app is suppliers-tamper.db.test.ts.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  findLeaks,
  LogCapture,
  SequentialIds,
  type TestDatabase,
} from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { withSignedStates } from '../../audit/index.ts';
import { createOrganization } from '../../organizations/index.ts';
import { type SupplierDetails, SupplierDetailsRefused } from '../domain/supplier.ts';
import {
  addSupplier,
  contactsOf,
  MOST_SUPPLIERS_A_PAGE,
  SUPPLIERS,
  suppliersAddedSince,
  suppliersPage,
  supplierOf,
  versionOf,
} from './suppliers.ts';
import type { SuppliersTables } from './tables.ts';

// The tables an organisation is made in, as createOrganization takes them: the suppliers module
// may not name the directory's (ADR-004's map), which making one writes to.
type OrganizationTables = Parameters<typeof createOrganization>[0] extends Transaction<infer T> ? T : never;
type Tables = SuppliersTables & OrganizationTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe110_0000_0000);
const clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
const HOUR_MS = 3_600_000;
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

const PHONE = '+971501234567';
const EMAIL = 'accounts@gulfoffice.example';
const LICENCE = 'CN-7654321';
const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: PHONE, email: EMAIL, tradeLicence: LICENCE },
  source: { kind: 'registry', ref: 'DED-REG-88112' },
};

const services = () => ({
  keys,
  ids,
  logger: createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: new LogCapture(),
  }),
});

const organization = async (): Promise<string> => {
  const id = ids.next();
  await withSignedStates(app, id, services(), (tx, states) =>
    createOrganization(tx, states, { id, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return id;
};

/** A supplier added as E1-2 will, entered by `enteredBy`: its ID, its first version's and who entered it. */
async function added(orgId: string, supplier: SupplierDetails = DETAILS) {
  const id = ids.next();
  const versionId = ids.next();
  const enteredBy = ids.next();
  const recorded = await withSignedStates(app, orgId, services(), (tx, states) =>
    addSupplier(tx, states, keys, {
      orgId,
      id,
      versionId,
      supplier,
      enteredBy,
      createdAt: clock.now(),
      actor: { type: 'user', id: ids.next() },
    }),
  );
  return { id, versionId, enteredBy, recorded };
}

const read = (orgId: string, id: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => supplierOf(tx, states, { orgId, id }, 'share'));

const readVersion = (orgId: string, id: string, supplierId: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => versionOf(tx, states, { orgId, id }, supplierId));

/** The version's contacts, opened in a transaction that read it through its signed state first. */
const contacts = (orgId: string, id: string, supplierId: string) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const version = await versionOf(tx, states, { orgId, id }, supplierId);
    if (version.outcome !== 'found') throw new Error(`No version: ${version.outcome}`);
    return contactsOf(tx, keys, orgId, version.version);
  });

const eventsAbout = (orgId: string, subjectId: string) =>
  database
    .as('backup')
    .query<{ action: string; subject_type: string; details: string }>(
      'select action, subject_type, details::text as details from audit.events where org_id = $1 and subject_id = $2 order by seq',
      [orgId, subjectId],
    );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, services().logger);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`a supplier (E1-1, Postgres ${server.version})`, () => {
  it('is added UNVERIFIED with its first version, every authority field sealed', async () => {
    const org = await organization();
    const { id, versionId, enteredBy, recorded } = await added(org);

    expect(recorded.supplier.version).toBe(1);
    expect(recorded.version.version).toBe(1);
    expect(await read(org, id)).toMatchObject({
      outcome: 'found',
      supplier: {
        id,
        status: 'UNVERIFIED',
        currentVersionId: versionId,
        pendingVersionId: null,
        coolingOffUntil: null,
        verifiedBy: null,
        payeeKey: null,
        payeeKeyVersion: null,
      },
    });
    expect(await readVersion(org, versionId, id)).toEqual({
      outcome: 'found',
      version: {
        id: versionId,
        supplierId: id,
        version: 1,
        displayName: 'Gulf Office Supplies LLC',
        contacts: 'phone email licence',
        source: { kind: 'registry', ref: 'DED-REG-88112' },
        enteredBy,
        enteredAt: clock.now(),
        registrationId: null,
        beneficiaryRef: null,
        payeeHint: null,
      },
    });
  });

  it('keeps its contacts encrypted, opened only from the verified version, each as given', async () => {
    const org = await organization();
    const { id, versionId } = await added(org, {
      ...DETAILS,
      contacts: { phone: PHONE, email: 'Accounts@GulfOffice.Example', tradeLicence: LICENCE },
    });

    expect(await contacts(org, versionId, id)).toEqual({ phone: PHONE, email: EMAIL, tradeLicence: LICENCE });
  });

  it('keeps no optional contact it wasn’t given', async () => {
    const org = await organization();
    const { id, versionId } = await added(org, {
      ...DETAILS,
      contacts: { phone: PHONE, email: null, tradeLicence: null },
    });

    expect(await readVersion(org, versionId, id)).toMatchObject({ version: { contacts: 'phone' } });
    expect(await contacts(org, versionId, id)).toEqual({ phone: PHONE, email: null, tradeLicence: null });
    const [row] = await database
      .as('backup')
      .query<{ email: Buffer | null; licence: Buffer | null }>(
        'select email_ciphertext as email, licence_ciphertext as licence from suppliers.supplier_versions where id = $1',
        [versionId],
      );
    expect(row).toEqual({ email: null, licence: null });
  });

  it('records its adding and its version, never its name, source reference or contacts', async () => {
    const org = await organization();
    const { id, versionId } = await added(org);

    const events = [...(await eventsAbout(org, id)), ...(await eventsAbout(org, versionId))];
    expect(events.map(({ action, subject_type }) => [action, subject_type])).toEqual([
      ['supplier.added', 'supplier'],
      ['supplier_version.made', 'supplier_version'],
    ]);
    const text = events.map(({ details }) => details).join('\n');
    expect(text).toContain('"contacts":"phone email licence"');
    expect(text).toContain('"sourceKind":"registry"');
    expect(findLeaks(text, ['Gulf Office', PHONE, '501234567', EMAIL, LICENCE, 'DED-REG'])).toEqual([]);
  });

  it('writes no contact in the clear: every table the suppliers schema holds, read whole', async () => {
    const org = await organization();
    await added(org);

    const [row] = await database
      .as('backup')
      .query<{ text: string }>(
        "select (select pg_catalog.string_agg(s::text, e'\\n') from suppliers.suppliers s) || (select pg_catalog.string_agg(v::text, e'\\n') from suppliers.supplier_versions v) as text",
      );
    expect(row?.text).toContain('Gulf Office Supplies LLC');
    expect(row?.text).toContain('DED-REG-88112');
    expect(findLeaks(row?.text ?? '', [PHONE, '501234567', EMAIL, 'gulfoffice', LICENCE, '7654321'])).toEqual([]);
  });

  it('is found by no other organisation, nor is its version', async () => {
    const org = await organization();
    const other = await organization();
    const { id, versionId } = await added(org);

    expect(await read(other, id)).toEqual({ outcome: 'missing' });
    expect(await readVersion(other, versionId, id)).toEqual({ outcome: 'missing' });
  });

  it('gives a version only as its own supplier’s: another supplier’s version is none of this one’s', async () => {
    const org = await organization();
    const first = await added(org);
    const second = await added(org);

    expect(await readVersion(org, first.versionId, second.id)).toEqual({ outcome: 'missing' });
    expect(await readVersion(org, first.versionId, first.id.toUpperCase())).toMatchObject({ outcome: 'found' });
  });

  it('refuses details it can’t have before any SQL runs, adding nothing', async () => {
    const org = await organization();
    const id = ids.next();

    await expect(
      withSignedStates(app, org, services(), (tx, states) =>
        addSupplier(tx, states, keys, {
          orgId: org,
          id,
          versionId: ids.next(),
          supplier: { ...DETAILS, contacts: { ...DETAILS.contacts, phone: '050 123 4567' } },
          enteredBy: ids.next(),
          createdAt: clock.now(),
          actor: OPERATOR,
        }),
      ),
    ).rejects.toBeInstanceOf(SupplierDetailsRefused);
    expect(await read(org, id)).toEqual({ outcome: 'missing' });
  });

  it('moves as its machine says: verified, back to unverified, suspended and reactivated verified', async () => {
    const org = await organization();
    const { id } = await added(org);
    const move = (event: 'verify' | 'unverify' | 'suspend' | 'reactivate' | 'reactivate_verified') =>
      withSignedStates(app, org, services(), (tx, states) =>
        states.changeStatus(tx, SUPPLIERS, { orgId: org, id }, event, {
          actor: OPERATOR,
          action: `supplier.${event}`,
          details: {},
        }),
      );

    for (const [event, status] of [
      ['verify', 'VERIFIED'],
      ['unverify', 'UNVERIFIED'],
      ['suspend', 'SUSPENDED'],
      ['reactivate', 'UNVERIFIED'],
      ['verify', 'VERIFIED'],
      ['suspend', 'SUSPENDED'],
      ['reactivate_verified', 'VERIFIED'],
    ] as const) {
      expect(await move(event)).toMatchObject({ outcome: 'changed' });
      expect(await read(org, id)).toMatchObject({ supplier: { status } });
    }
    expect(await move('reactivate')).toMatchObject({ outcome: 'refused' });
  });
});

describe(`a page of an organisation's suppliers (E1-1, Postgres ${server.version})`, () => {
  it('holds its own suppliers alone, in order of ID, each with its current version’s name, a page at a time', async () => {
    const org = await organization();
    const other = await organization();
    await added(other);
    const made = [
      await added(org, { ...DETAILS, displayName: 'First Supplier' }),
      await added(org, { ...DETAILS, displayName: 'Second Supplier' }),
      await added(org, { ...DETAILS, displayName: 'Third Supplier' }),
    ];
    const page = (after: string | null, limit: number) =>
      withSignedStates(app, org, services(), (tx, states) => suppliersPage(tx, states, org, { after, limit }));

    const first = await page(null, 2);
    expect(first).toMatchObject({
      outcome: 'listed',
      suppliers: [
        { id: made[0]?.id, displayName: 'First Supplier', status: 'UNVERIFIED', currentVersionId: made[0]?.versionId },
        { id: made[1]?.id, displayName: 'Second Supplier' },
      ],
      next: made[1]?.id,
    });
    expect(await page(made[1]?.id ?? null, 2)).toMatchObject({
      outcome: 'listed',
      suppliers: [{ id: made[2]?.id, displayName: 'Third Supplier' }],
      next: null,
    });
  });

  it('is empty for an organisation with none', async () => {
    const org = await organization();

    expect(
      await withSignedStates(app, org, services(), (tx, states) =>
        suppliersPage(tx, states, org, { after: null, limit: 10 }),
      ),
    ).toEqual({ outcome: 'listed', suppliers: [], next: null });
  });

  it.each([0, MOST_SUPPLIERS_A_PAGE + 1, 1.5])('refuses a page of %j, before any SQL runs', async (limit) => {
    const org = await organization();

    await expect(
      withSignedStates(app, org, services(), (tx, states) => suppliersPage(tx, states, org, { after: null, limit })),
    ).rejects.toBeInstanceOf(RangeError);
  });
});

describe(`the day's count of suppliers added (E1-1, Postgres ${server.version})`, () => {
  it('counts the organisation’s own, added after the time given', async () => {
    const org = await organization();
    const other = await organization();
    const since = new Date(clock.now().getTime() - HOUR_MS);
    await added(org);
    await added(org);
    await added(other);
    const count = (at: Date) => withSignedStates(app, org, services(), (tx) => suppliersAddedSince(tx, org, at));

    expect(await count(since)).toBe(2);
    expect(await count(clock.now())).toBe(0);
  });
});

describe(`what the app may do to the tables (E1-1, Postgres ${server.version})`, () => {
  it('lets the app neither delete, nor change a key, a creation time, a version’s supplier past the seal, or its contacts', async () => {
    const as = database.as('app');
    await expect(as.query('delete from suppliers.suppliers')).rejects.toThrow('permission denied');
    await expect(as.query('delete from suppliers.supplier_versions')).rejects.toThrow('permission denied');
    await expect(as.query('update suppliers.suppliers set created_at = created_at')).rejects.toThrow(
      'permission denied',
    );
    await expect(as.query('update suppliers.suppliers set id = id')).rejects.toThrow('permission denied');
    await expect(
      as.query('update suppliers.supplier_versions set phone_ciphertext = phone_ciphertext'),
    ).rejects.toThrow('permission denied');
    await expect(
      as.query('update suppliers.supplier_versions set email_ciphertext = email_ciphertext'),
    ).rejects.toThrow('permission denied');
    await expect(
      as.query('update suppliers.supplier_versions set licence_ciphertext = licence_ciphertext'),
    ).rejects.toThrow('permission denied');
    await expect(
      as.query('update suppliers.supplier_versions set contacts_key_version = contacts_key_version'),
    ).rejects.toThrow('permission denied');
    await expect(as.query('update suppliers.supplier_versions set org_id = org_id')).rejects.toThrow(
      'permission denied',
    );
  });

  it('refuses a supplier added in any status but UNVERIFIED (the status guard)', async () => {
    const org = await organization();
    const { versionId } = await added(org);

    await expect(
      withSignedStates(app, org, services(), (tx) =>
        tx
          .insertInto(SUPPLIERS.table)
          .values({
            org_id: org,
            id: ids.next(),
            status: 'VERIFIED',
            current_version_id: versionId,
            created_at: clock.now(),
          })
          .execute(),
      ),
    ).rejects.toThrow();
  });

  it('refuses a supplier whose current version is another supplier’s, or none, at commit', async () => {
    const org = await organization();
    const { versionId } = await added(org);
    const plant = (current: string) =>
      withSignedStates(app, org, services(), (tx) =>
        tx
          .insertInto(SUPPLIERS.table)
          .values({
            org_id: org,
            id: ids.next(),
            status: 'UNVERIFIED',
            current_version_id: current,
            created_at: clock.now(),
          })
          .execute(),
      );

    await expect(plant(versionId)).rejects.toThrow(/current_is_its_own/);
    await expect(plant(ids.next())).rejects.toThrow(/current_is_its_own/);
  });
});
