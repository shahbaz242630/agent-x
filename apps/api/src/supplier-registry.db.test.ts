// E1-2 (BR-04, BR-21, SEC-AG-05, SEC-DB-01): adding the organisation's
// suppliers, within the day's budget under its own lock, and reading them,
// through the use case the routes call, on the real migrated schema, as the
// app role. The routes' answers are suppliers.test.ts; the brake is
// supplier-changes.db.test.ts.
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { addMembership, type IdentityTables, type Role, userForSubject } from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  MOST_SUPPLIERS_ADDED_A_DAY,
  type SupplierDetails,
  SUPPLIER_VERSIONS,
  supplierOf,
  type SuppliersTables,
  verifySupplier,
} from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  ADD_OPERATION,
  createSupplierRegistry,
  type SupplierAddWrite,
  type SupplierRegistry,
} from './supplier-registry.ts';
import type { SupplierMember } from './supplier-work.ts';

type Tables = IdentityTables & SuppliersTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe120_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000ab';
const DAY_MS = 86_400_000;

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: 'Accounts@GulfOffice.example', tradeLicence: 'DED-123456' },
  source: { kind: 'registry', ref: 'DED-123456' },
};

let clock: FixedClock;
let registry: SupplierRegistry;
let capture: LogCapture;

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

let people = 0;

/** A person with a membership in the organisation. */
async function member(org: string, role: Role): Promise<SupplierMember & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `supplier-registry-${String(people)}` },
    { ids, clock },
  );
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, membershipId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

let keysUsed = 0;
const keyed = (who: SupplierMember, key = `key-${String((keysUsed += 1))}`): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation: ADD_OPERATION,
  key,
  payload: '{}',
});

const add = (who: SupplierMember, details: SupplierDetails = DETAILS, key?: string) =>
  registry.add(who, keyed(who, key), details, CORRELATION);

const addedOf = (write: SupplierAddWrite) => {
  if (write.outcome !== 'added') throw new Error(`not added: ${JSON.stringify(write)}`);
  return write;
};

const named = (displayName: string): SupplierDetails => ({ ...DETAILS, displayName });

const suppliersIn = (org: string) =>
  withTenant(app, org, async (tx) =>
    Number(
      (
        await tx
          .selectFrom('suppliers.suppliers')
          .select((eb) => eb.fn.countAll().as('n'))
          .executeTakeFirstOrThrow()
      ).n,
    ),
  );

/** The supplier verified by `verifier`, as E3 will. */
const verified = (org: string, id: string, verifier: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId: org, id }, 'change');
    if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
    return verifySupplier(tx, states, { orgId: org, id }, found, { verifiedBy: verifier, actor: OPERATOR });
  });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
  capture = new LogCapture();
  registry = createSupplierRegistry({ database: app, keys, ids, clock, logger: loggerFor(capture) });
});

describe(`adding a supplier (E1-2, Postgres ${server.version})`, () => {
  it('is one write by an admin: UNVERIFIED, entered by them, its contacts given back as kept', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');

    const added = addedOf(await add(admin));

    expect(added.supplier).toMatchObject({ status: 'UNVERIFIED', pendingVersionId: null, verifiedBy: null });
    expect(added.version).toMatchObject({
      version: 1,
      displayName: 'Gulf Office Supplies LLC',
      source: { kind: 'registry', ref: 'DED-123456' },
      enteredBy: admin.membershipId,
      enteredAt: clock.now(),
      phoneSince: clock.now(),
    });
    expect(added.contacts).toEqual({
      phone: '+971501234567',
      email: 'accounts@gulfoffice.example',
      tradeLicence: 'DED-123456',
    });
    const events = await withTenant(app, org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['action', 'actor_type', 'actor_id'])
        .where('subject_id', '=', added.supplier.id)
        .execute(),
    );
    expect(events).toEqual([{ action: 'supplier.added', actor_type: 'user', actor_id: admin.userId }]);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a%s: FORBIDDEN, adding nothing', async (role) => {
    const org = await organization();

    expect(await add(await member(org, role))).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await suppliersIn(org)).toBe(0);
  });

  it('answers a retry of the same write as the first did, adding one', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = addedOf(await add(admin, DETAILS, 'same'));

    expect(addedOf(await add(admin, DETAILS, 'same'))).toEqual(first);
    expect(await suppliersIn(org)).toBe(1);
  });

  it('answers a key used for another supplier as a conflict', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    await add(admin, DETAILS, 'the-key');

    const other = { ...keyed(admin, 'the-key'), payload: '{"displayName":"Another"}' };
    expect(await registry.add(admin, other, named('Another'), CORRELATION)).toEqual({ outcome: 'conflict' });
  });

  it(`past ${String(MOST_SUPPLIERS_ADDED_A_DAY)} in 24 hours: SUPPLIER_ADDS_SPENT, until a day has passed`, async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    for (let count = 0; count < MOST_SUPPLIERS_ADDED_A_DAY; count += 1) {
      addedOf(await add(admin, named(`Supplier ${String(count)}`)));
    }

    expect(await add(admin, named('One too many'))).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'SUPPLIER_ADDS_SPENT',
    });
    expect(await suppliersIn(org)).toBe(MOST_SUPPLIERS_ADDED_A_DAY);

    clock.advanceBy(DAY_MS);
    expect(addedOf(await add(admin, named('One too many'))).version.displayName).toBe('One too many');
  });

  it('counts each organisation’s budget alone', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    for (let count = 0; count < MOST_SUPPLIERS_ADDED_A_DAY; count += 1) {
      addedOf(await add(admin, named(`Supplier ${String(count)}`)));
    }
    const other = await organization();

    expect(addedOf(await add(await member(other, 'admin'))).supplier.status).toBe('UNVERIFIED');
  });

  it('adds only once it holds the organisation’s lock for adding suppliers, so two can’t both take the day’s last', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    // Another add of the organisation's, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [
        `agentx.suppliers:${org}`,
      ]);
      const adding = within(20_000, add(admin), 'the add');
      await waitUntilQueued(database.as('admin'), 1);
      expect(await suppliersIn(org)).toBe(0);
      await holder.query('commit');

      expect(addedOf(await adding).supplier.status).toBe('UNVERIFIED');
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe(`reading suppliers (E1-2, Postgres ${server.version})`, () => {
  it('lists the organisation’s own, each with its current name, a page at a time', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = addedOf(await add(admin, named('First')));
    const second = addedOf(await add(admin, named('Second')));
    addedOf(await add(await member(await organization(), 'admin'), named('Theirs')));

    const page = await registry.list(org, { after: null, limit: 1 }, CORRELATION);
    expect(page).toMatchObject({ outcome: 'listed', suppliers: [{ id: first.supplier.id, displayName: 'First' }] });
    if (page.outcome !== 'listed') throw new Error('not listed');
    expect(await registry.list(org, { after: page.next, limit: 50 }, CORRELATION)).toMatchObject({
      suppliers: [{ id: second.supplier.id, displayName: 'Second' }],
      next: null,
    });
  });

  it('shows one with its contacts; another organisation’s is NOT_FOUND', async () => {
    const org = await organization();
    const added = addedOf(await add(await member(org, 'admin')));

    const { outcome: _added, ...view } = added;
    expect(await registry.show(org, added.supplier.id, CORRELATION)).toEqual({ outcome: 'found', ...view });
    expect(await registry.show(await organization(), added.supplier.id, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });
  });

  it('refuses one whose contacts won’t open: INTEGRITY_FAILED, logged without naming them', async () => {
    const org = await organization();
    const added = addedOf(await add(await member(org, 'admin')));
    // Past the app, as the database's owner: the email's ciphertext in the phone's place (its kind is in its associated data).
    const owner = await tamperAsOwner(database, SUPPLIER_VERSIONS, org);
    try {
      // 0032's `made_once` stops even the owner, unless they switch it off first.
      await owner.query('alter table suppliers.supplier_versions disable trigger made_once');
      await owner.query('update suppliers.supplier_versions set phone_ciphertext = email_ciphertext where id = $1', [
        added.version.id,
      ]);
    } finally {
      await owner.query('alter table suppliers.supplier_versions enable trigger made_once');
      await owner.end();
    }

    expect(await registry.show(org, added.supplier.id, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
    const logged = capture.lines().filter((line) => line.event === 'suppliers.contacts_unreadable');
    expect(logged).toMatchObject([{ level: 'error', supplierId: added.supplier.id, versionId: added.version.id }]);
    expect(JSON.stringify(capture.lines())).not.toMatch(/\+971501234567|gulfoffice/i);
  });

  it('reads one whose current version was removed past the app as tampered: INTEGRITY_FAILED, the alarm raised (#221’s review)', async () => {
    const org = await organization();
    const added = addedOf(await add(await member(org, 'admin')));
    // As the database's owner: 0032's key dropped, the version removed; then the supplier too, and the key put back.
    const owner = await tamperAsOwner(database, SUPPLIER_VERSIONS, org);
    try {
      await owner.query('alter table suppliers.suppliers drop constraint current_is_its_own');
      await owner.query('alter table suppliers.supplier_versions disable trigger made_once');
      await owner.query('delete from suppliers.supplier_versions where id = $1', [added.version.id]);

      expect(await registry.show(org, added.supplier.id, CORRELATION)).toEqual({
        outcome: 'refused',
        status: 503,
        code: 'INTEGRITY_FAILED',
      });
      // Its events outlive it, so the audit module finds it removed, not merely missing.
      const alarms = capture.lines().filter((line) => line.event === 'audit.integrity_failed');
      expect(alarms).toMatchObject([{ level: 'error', subjectType: 'supplier_version', objectId: added.version.id }]);
    } finally {
      await owner.query('delete from suppliers.suppliers where id = $1', [added.supplier.id]);
      await owner.query('alter table suppliers.supplier_versions enable trigger made_once');
      await owner.query(
        `alter table suppliers.suppliers add constraint current_is_its_own foreign key (org_id, id, current_version_id)
           references suppliers.supplier_versions (org_id, supplier_id, id) deferrable initially deferred`,
      );
      await owner.end();
    }
  });

  it('shows an agent the VERIFIED suppliers alone', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const unverified = addedOf(await add(admin, named('Unverified')));
    const checked = addedOf(await add(admin, named('Verified')));
    await verified(org, checked.supplier.id, admin.membershipId);

    const usable = await registry.usableByAgent(org, { after: null, limit: 50 }, CORRELATION);

    expect(usable).toMatchObject({ outcome: 'listed', suppliers: [{ id: checked.supplier.id, status: 'VERIFIED' }] });
    expect(JSON.stringify(usable)).not.toContain(unverified.supplier.id);
  });
});

describe(`what can't be believed refuses the answer (E1-2, Postgres ${server.version})`, () => {
  it('a membership tampered with: INTEGRITY_FAILED, adding nothing', async () => {
    const org = await organization();
    const viewer = await member(org, 'viewer');
    // Raised to admin past the app: its seal no longer holds.
    await withTenant(app, org, (tx) =>
      tx.updateTable('identity.memberships').set({ role: 'admin' }).where('id', '=', viewer.membershipId).execute(),
    );

    expect(await add(viewer)).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(await suppliersIn(org)).toBe(0);
  });

  it('a supplier tampered with: INTEGRITY_FAILED to members and agents alike', async () => {
    const org = await organization();
    const added = addedOf(await add(await member(org, 'admin')));
    // Its cooling-off moved past the app: its seal no longer holds.
    await withTenant(app, org, (tx) =>
      tx
        .updateTable('suppliers.suppliers')
        .set({ cooling_off_until: clock.now() })
        .where('id', '=', added.supplier.id)
        .execute(),
    );

    const refused = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    expect(await registry.show(org, added.supplier.id, CORRELATION)).toEqual(refused);
    expect(await registry.list(org, { after: null, limit: 50 }, CORRELATION)).toEqual(refused);
    expect(await registry.usableByAgent(org, { after: null, limit: 50 }, CORRELATION)).toEqual(refused);
  });

  it('passes on what isn’t a refusal: a database error is thrown, not answered', async () => {
    const org = await organization();

    await expect(registry.show(org, 'not-a-uuid', CORRELATION)).rejects.toThrow();
  });
});
