// E1-1: suppliers and their versions (0032), on the real migrated schema, as
// the app role. A supplier is added UNVERIFIED with its first version, both
// sealed; its contacts are kept encrypted for their own row and kind, and
// opened only from a verified version; it is found by no other organisation;
// it is VERIFIED only on the version verified; a version is made once;
// pages of suppliers give each with its current version's name; and the
// tables hold the app to adding rows and moving only what the seal covers.
// What the owner can do past the app is suppliers-tamper.db.test.ts.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  findLeaks,
  FixedClock,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { HOUR_MS } from '../../../shared-kernel/index.ts';
import { withSignedStates } from '../../audit/index.ts';
import { createOrganization } from '../../organizations/index.ts';
import { type SupplierDetails, SupplierDetailsRefused } from '../domain/supplier.ts';
import {
  addSupplier,
  addVersion,
  contactsOf,
  MOST_SUPPLIERS_A_PAGE,
  reactivateSupplier,
  SUPPLIER_VERSIONS,
  SUPPLIERS,
  suppliersAddedSince,
  suppliersPage,
  supplierOf,
  suspendSupplier,
  unverifySupplier,
  verifySupplier,
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
  logger: testLogger(),
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
        verifiedVersionId: null,
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
        phoneSince: clock.now(),
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
});

/** Work on one supplier read for change, in one transaction: what E3's use cases will do. */
const onSupplier = <T>(
  orgId: string,
  id: string,
  work: (
    tx: Parameters<typeof supplierOf>[0],
    states: Parameters<typeof supplierOf>[1],
    found: Extract<Awaited<ReturnType<typeof supplierOf>>, { outcome: 'found' }>,
  ) => Promise<T>,
) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId, id }, 'change');
    if (found.outcome !== 'found') throw new Error(`No supplier: ${found.outcome}`);
    return work(tx, states, found);
  });

const VERIFIER = 'e1100000-0000-7000-8000-00000000cafe';

const verify = (orgId: string, id: string) =>
  onSupplier(orgId, id, (tx, states, found) =>
    verifySupplier(tx, states, { orgId, id }, found, { verifiedBy: VERIFIER, actor: OPERATOR }),
  );

const suspend = (orgId: string, id: string) =>
  onSupplier(orgId, id, (tx, states, found) => suspendSupplier(tx, states, { orgId, id }, found, { actor: OPERATOR }));

/** Reactivates the supplier, then reads it back as it now stands: reactivateSupplier gives nothing. */
const reactivate = async (orgId: string, id: string) => {
  await onSupplier(orgId, id, (tx, states, found) =>
    reactivateSupplier(tx, states, { orgId, id }, found, { actor: OPERATOR }),
  );
  const now = await read(orgId, id);
  if (now.outcome !== 'found') throw new Error(`No supplier: ${now.outcome}`);
  return now.supplier;
};

/** A later version of the supplier, made after reading it for change and following its current one, as a change will. */
const later = (orgId: string, supplierId: string, version: number, supplier: SupplierDetails) =>
  onSupplier(orgId, supplierId, async (tx, states, found) => {
    const follows = await versionOf(tx, states, { orgId, id: found.supplier.currentVersionId }, supplierId);
    if (follows.outcome !== 'found') throw new Error(`No current version: ${follows.outcome}`);
    const id = ids.next();
    const recorded = await addVersion(tx, states, keys, {
      orgId,
      id,
      supplierId,
      version,
      supplier,
      enteredBy: ids.next(),
      enteredAt: clock.now(),
      actor: OPERATOR,
      of: found,
      follows: follows.version,
    });
    return { id, recorded };
  });

/** Sets the supplier's sealed fields `set`, recorded from its state read for change: what the table's checks must hold. */
const recordOn = (orgId: string, id: string, set: Record<string, string | number | null>) =>
  onSupplier(orgId, id, (tx, states, found) =>
    states.record(tx, SUPPLIERS, { orgId, id }, found.state, set, {
      actor: OPERATOR,
      action: 'supplier.test_change',
      details: {},
    }),
  );

describe(`a supplier's verification (E1-1's review, Postgres ${server.version})`, () => {
  it('is recorded with its verifier and the version verified, then VERIFIED', async () => {
    const org = await organization();
    const { id, versionId } = await added(org);

    expect(await verify(org, id)).toMatchObject({
      status: 'VERIFIED',
      verifiedBy: VERIFIER,
      verifiedVersionId: versionId,
    });
    expect((await eventsAbout(org, id)).map(({ action }) => action)).toEqual([
      'supplier.added',
      'supplier.verifier_recorded',
      'supplier.verify',
    ]);
  });

  it('is cleared when the supplier is unverified, so nothing verified is left to come back to', async () => {
    const org = await organization();
    const { id } = await added(org);
    await verify(org, id);

    expect(
      await onSupplier(org, id, (tx, states, found) =>
        unverifySupplier(tx, states, { orgId: org, id }, found, { actor: OPERATOR }),
      ),
    ).toMatchObject({ status: 'UNVERIFIED', verifiedBy: null, verifiedVersionId: null });
    await suspend(org, id);
    expect(await reactivate(org, id)).toMatchObject({ status: 'UNVERIFIED' });
  });

  it('comes back VERIFIED from its brake while it is still verified', async () => {
    const org = await organization();
    const { id, versionId } = await added(org);
    await verify(org, id);
    await suspend(org, id);

    expect(await reactivate(org, id)).toMatchObject({ status: 'VERIFIED', verifiedVersionId: versionId });
  });

  it('comes back UNVERIFIED when suspended before it was ever verified: the table refuses VERIFIED outright', async () => {
    const org = await organization();
    const { id } = await added(org);
    await suspend(org, id);

    await expect(
      onSupplier(org, id, (tx, states) =>
        states.changeStatus(tx, SUPPLIERS, { orgId: org, id }, 'reactivate_verified', {
          actor: OPERATOR,
          action: 'supplier.reactivate_verified',
          details: {},
        }),
      ),
    ).rejects.toThrow(/verified_rests_on_its_version/);
    expect(await reactivate(org, id)).toMatchObject({ status: 'UNVERIFIED', verifiedVersionId: null });
    // Nothing verified, so no clearing is recorded.
    expect((await eventsAbout(org, id)).map(({ action }) => action)).toEqual([
      'supplier.added',
      'supplier.suspend',
      'supplier.reactivate',
    ]);
  });

  it('comes back UNVERIFIED, its verification cleared, when a new version became current while it was suspended', async () => {
    const org = await organization();
    const { id } = await added(org);
    await verify(org, id);
    await suspend(org, id);
    const second = await later(org, id, 2, DETAILS);
    await recordOn(org, id, { current_version_id: second.id });

    expect(await reactivate(org, id)).toMatchObject({
      status: 'UNVERIFIED',
      currentVersionId: second.id,
      verifiedBy: null,
      verifiedVersionId: null,
    });
  });

  it('holds while VERIFIED: a new current version, or a change waiting, is refused by the table', async () => {
    const org = await organization();
    const { id } = await added(org);
    await verify(org, id);
    const second = await later(org, id, 2, DETAILS);

    await expect(recordOn(org, id, { current_version_id: second.id })).rejects.toThrow(/verified_rests_on_its_version/);
    await expect(recordOn(org, id, { pending_version_id: second.id })).rejects.toThrow(/verified_rests_on_its_version/);
  });

  it('refuses to verify one with a change waiting, or one not UNVERIFIED, before any SQL runs', async () => {
    const org = await organization();
    const { id } = await added(org);
    const second = await later(org, id, 2, DETAILS);
    await recordOn(org, id, { pending_version_id: second.id });

    await expect(verify(org, id)).rejects.toBeInstanceOf(RangeError);
    const other = await added(org);
    await suspend(org, other.id);
    await expect(verify(org, other.id)).rejects.toBeInstanceOf(RangeError);
  });

  it('keeps its verification while suspended, and refuses to suspend one already SUSPENDED (E1-2)', async () => {
    const org = await organization();
    const { id } = await added(org);
    await verify(org, id);

    await suspend(org, id);

    expect(await read(org, id)).toMatchObject({ supplier: { status: 'SUSPENDED', verifiedBy: VERIFIER } });
    await expect(suspend(org, id)).rejects.toBeInstanceOf(RangeError);
  });

  it('refuses to unverify one not VERIFIED, and to reactivate one not SUSPENDED', async () => {
    const org = await organization();
    const { id } = await added(org);

    await expect(
      onSupplier(org, id, (tx, states, found) =>
        unverifySupplier(tx, states, { orgId: org, id }, found, { actor: OPERATOR }),
      ),
    ).rejects.toBeInstanceOf(RangeError);
    await expect(reactivate(org, id)).rejects.toBeInstanceOf(RangeError);
  });
});

describe(`a later version of a supplier's details (E1-1, for E2 and E3; Postgres ${server.version})`, () => {
  it('is made sealed, its contacts encrypted for itself, and the supplier left as it was', async () => {
    const org = await organization();
    const { id, versionId } = await added(org);
    const changed = { ...DETAILS, contacts: { phone: '+971509876543', email: null, tradeLicence: LICENCE } };

    const second = await later(org, id, 2, changed);

    expect(second.recorded.version).toBe(1);
    expect(await readVersion(org, second.id, id)).toMatchObject({
      outcome: 'found',
      version: { supplierId: id, version: 2, contacts: 'phone licence' },
    });
    expect(await contacts(org, second.id, id)).toEqual({ phone: '+971509876543', email: null, tradeLicence: LICENCE });
    expect(await contacts(org, versionId, id)).toEqual({ phone: PHONE, email: EMAIL, tradeLicence: LICENCE });
    expect(await read(org, id)).toMatchObject({ supplier: { currentVersionId: versionId, pendingVersionId: null } });
  });

  it('carries its phone’s time over while the phone is the same, and starts it again from a new phone', async () => {
    const org = await organization();
    const { id } = await added(org);
    const first = clock.now();
    clock.advanceBy(HOUR_MS);
    const kept = await later(org, id, 2, { ...DETAILS, displayName: 'Gulf Office Supplies FZE' });
    clock.advanceBy(HOUR_MS);
    const moved = await later(org, id, 3, { ...DETAILS, contacts: { ...DETAILS.contacts, phone: '+971509876543' } });

    expect(await readVersion(org, kept.id, id)).toMatchObject({ version: { phoneSince: first } });
    expect(await readVersion(org, moved.id, id)).toMatchObject({ version: { phoneSince: clock.now() } });
  });

  it('follows only its own supplier’s current version: an older one, or another supplier’s, is refused before any SQL runs (the #220 review)', async () => {
    const org = await organization();
    const { id, versionId } = await added(org);
    const other = await added(org);
    const second = await later(org, id, 2, DETAILS);
    await recordOn(org, id, { current_version_id: second.id });
    const following = (versionIdToFollow: string, ofSupplier: string, supplierId: string, forSupplier = ofSupplier) =>
      onSupplier(org, ofSupplier, async (tx, states, found) => {
        const follows = await versionOf(tx, states, { orgId: org, id: versionIdToFollow }, supplierId);
        if (follows.outcome !== 'found') throw new Error(`No version: ${follows.outcome}`);
        return addVersion(tx, states, keys, {
          orgId: org,
          id: ids.next(),
          supplierId: forSupplier,
          version: 3,
          supplier: DETAILS,
          enteredBy: ids.next(),
          enteredAt: clock.now(),
          actor: OPERATOR,
          of: found,
          follows: follows.version,
        });
      });

    // Its first version, no longer current: an older phone's time can't be carried.
    await expect(following(versionId, id, id)).rejects.toBeInstanceOf(RangeError);
    // Another supplier's current version, followed for this one.
    await expect(following(other.versionId, id, other.id)).rejects.toBeInstanceOf(RangeError);
    // This supplier's version, made for another supplier's read.
    await expect(following(second.id, other.id, id)).rejects.toBeInstanceOf(RangeError);
    // This supplier's own current version followed, for a version of another supplier: its phone's time would cross over.
    await expect(following(second.id, id, id, other.id)).rejects.toBeInstanceOf(RangeError);
    expect(await readVersion(org, second.id, id)).toMatchObject({ outcome: 'found' });
  });

  it('is refused a number the supplier already has, by the table’s key', async () => {
    const org = await organization();
    const { id } = await added(org);

    await expect(later(org, id, 1, DETAILS)).rejects.toThrow(/one_number_a_version/);
  });

  it('refuses details it can’t have before any SQL runs', async () => {
    const org = await organization();
    const { id } = await added(org);

    await expect(
      later(org, id, 2, { ...DETAILS, source: { kind: 'registry', ref: 'has a space' } }),
    ).rejects.toBeInstanceOf(SupplierDetailsRefused);
  });

  it('is made once: the app changes nothing in a version after its first signed state (made_once)', async () => {
    const org = await organization();
    const { id, versionId } = await added(org);
    const change = (statement: () => Promise<unknown>) => expect(statement()).rejects.toThrow(/made once/);

    await change(() =>
      withSignedStates(app, org, services(), (tx) =>
        tx
          .updateTable(SUPPLIER_VERSIONS.table)
          .set({ display_name: 'Someone Else LLC' })
          .where('id', '=', versionId)
          .execute(),
      ),
    );
    await change(() =>
      withSignedStates(app, org, services(), (tx) =>
        tx.updateTable(SUPPLIER_VERSIONS.table).set({ state_version: 2 }).where('id', '=', versionId).execute(),
      ),
    );
    expect(await readVersion(org, versionId, id)).toMatchObject({
      outcome: 'found',
      version: { displayName: 'Gulf Office Supplies LLC' },
    });
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

  /** A supplier's row put in by the app past addSupplier, naming `current` in `status`: what the table itself refuses. */
  const plant = (orgId: string, current: string, status: string) =>
    withSignedStates(app, orgId, services(), (tx) =>
      tx
        .insertInto(SUPPLIERS.table)
        .values({ org_id: orgId, id: ids.next(), status, current_version_id: current, created_at: clock.now() })
        .execute(),
    );

  it('refuses a supplier added in any status but UNVERIFIED (the status guard)', async () => {
    const org = await organization();
    const { versionId } = await added(org);

    await expect(plant(org, versionId, 'VERIFIED')).rejects.toThrow(/must start as UNVERIFIED/);
  });

  it('refuses a supplier whose current version is another supplier’s, or none, at commit (current_is_its_own)', async () => {
    const org = await organization();
    const { versionId } = await added(org);

    await expect(plant(org, versionId, 'UNVERIFIED')).rejects.toThrow(/current_is_its_own/);
    await expect(plant(org, ids.next(), 'UNVERIFIED')).rejects.toThrow(/current_is_its_own/);
  });

  it('refuses a pending or verified version of another supplier (pending_is_its_own, verified_is_its_own)', async () => {
    const org = await organization();
    const { id } = await added(org);
    const other = await added(org);

    await expect(recordOn(org, id, { pending_version_id: other.versionId })).rejects.toThrow(/pending_is_its_own/);
    await expect(recordOn(org, id, { verified_version_id: other.versionId })).rejects.toThrow(/verified_is_its_own/);
  });

  it('refuses a pending version that is the current one (pending_is_not_current)', async () => {
    const org = await organization();
    const { id, versionId } = await added(org);

    await expect(recordOn(org, id, { pending_version_id: versionId })).rejects.toThrow(/pending_is_not_current/);
  });

  it('refuses a payee key version with no payee key (a_key_version_with_its_key)', async () => {
    const org = await organization();
    const { id } = await added(org);

    await expect(recordOn(org, id, { payee_key_version: 1 })).rejects.toThrow(/a_key_version_with_its_key/);
    await recordOn(org, id, { payee_key: 'fake-payee-1', payee_key_version: 1 });
    expect(await read(org, id)).toMatchObject({ supplier: { payeeKey: 'fake-payee-1', payeeKeyVersion: 1 } });
  });

  /** A version's row put in by the app past addVersion, with `overrides`: what the table itself refuses. */
  const plantVersion = (orgId: string, supplierId: string, overrides: Record<string, unknown>) =>
    withSignedStates(app, orgId, services(), (tx) =>
      tx
        .insertInto(SUPPLIER_VERSIONS.table)
        .values({
          org_id: orgId,
          id: ids.next(),
          supplier_id: supplierId,
          version: 9,
          display_name: 'Planted LLC',
          contacts: 'phone',
          phone_ciphertext: Buffer.alloc(40),
          email_ciphertext: null,
          licence_ciphertext: null,
          contacts_key_version: 1,
          phone_since: clock.now(),
          source_kind: 'registry',
          source_ref: 'planted',
          entered_by: ids.next(),
          entered_at: clock.now(),
          registration_id: null,
          beneficiary_ref: null,
          payee_hint: null,
          ...overrides,
        })
        .execute(),
    );

  it('refuses a version of no supplier (of_a_supplier)', async () => {
    const org = await organization();

    await expect(plantVersion(org, ids.next(), {})).rejects.toThrow(/of_a_supplier/);
  });

  it('refuses a payee reference with no registration, or a hint with no reference (a_reference_with_its_registration)', async () => {
    const org = await organization();
    const { id } = await added(org);

    await expect(plantVersion(org, id, { beneficiary_ref: 'fake-beneficiary-1' })).rejects.toThrow(
      /a_reference_with_its_registration/,
    );
    await expect(plantVersion(org, id, { payee_hint: 'AE…0000' })).rejects.toThrow(/a_reference_with_its_registration/);
  });

  it('refuses a phone held since after the version was entered (phone_since_it_was_entered)', async () => {
    const org = await organization();
    const { id } = await added(org);

    await expect(plantVersion(org, id, { phone_since: new Date(clock.now().getTime() + HOUR_MS) })).rejects.toThrow(
      /phone_since_it_was_entered/,
    );
  });

  it('keys each version by its supplier too, which a supplier’s own versions rest on (its_suppliers_own)', async () => {
    const [key] = await database.as('owner').query<{ definition: string }>(
      `select pg_catalog.pg_get_constraintdef(oid) as definition from pg_catalog.pg_constraint
          where conrelid = 'suppliers.supplier_versions'::regclass and conname = 'its_suppliers_own'`,
    );

    expect(key?.definition).toBe('UNIQUE (org_id, supplier_id, id)');
  });
});
