// E2-2a (ADR-014 §3, BR-04, SEC-PAY-06, SEC-PAY-08): registering a
// supplier's payee with the partner through its hosted form, through the use
// case the routes call, on the real migrated schema, as the app role, with
// the fake partner in memory. Tx 1 adds the registration before the partner
// is asked; Tx 2 keeps only the partner's server-to-server answer, and puts
// the new version in waiting, the supplier still paying the version it paid.
// The routes' answers are suppliers.test.ts.
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { addMembership, type IdentityTables, type Role, userForSubject } from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createFakeRail, type FakeRail, RailUnavailable, SANDBOX_ACCOUNTS } from '@agentx/core/modules/providers';
import {
  confirmPayeeChange,
  registrationOf,
  type SupplierDetails,
  supplierOf,
  type SuppliersTables,
  startRegistration,
  suspendSupplier,
  verifySupplier,
  versionOf,
  withdrawPayeeChange,
} from '@agentx/core/modules/suppliers';
import type { NotificationsTables } from '@agentx/core/modules/notifications';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  findLeaks,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { ADD_OPERATION, createSupplierRegistry, type SupplierRegistry } from './supplier-registry.ts';
import {
  createSupplierPayees,
  PAYEE_CHECK_OPERATION,
  PAYEE_START_OPERATION,
  type PayeeWrite,
  type SupplierPayees,
} from './supplier-payees.ts';
import type { SupplierMember } from './supplier-work.ts';

type Tables = IdentityTables &
  SuppliersTables &
  OrganizationsTables &
  DirectoryTables &
  AuditTables &
  NotificationsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe22a_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000ad';
const MINUTE_MS = 60_000;
/** A supplier's row held as a check reads it for change, and as a start reads it to decide. */
const HOLD_FOR_CHANGE = 'select id from suppliers.suppliers where org_id = $1 and id = $2 for no key update';
const HOLD_FOR_SHARE = 'select id from suppliers.suppliers where org_id = $1 and id = $2 for share';

const DETAILS: SupplierDetails = {
  displayName: 'Jasmine AI FZ-LLC',
  contacts: { phone: '+971501234567', email: 'accounts@jasmine.example', tradeLicence: null },
  source: { kind: 'registry', ref: 'DED-123456' },
};

/** The sandbox's accounts at the fake bank: the payee's, a second one's, and every number, for the leak checks. */
const IBANS = SANDBOX_ACCOUNTS.flatMap((account) => account.AccountIdentifiers.map((each) => each.Identification));
const [JASMINE, OTHER] = SANDBOX_ACCOUNTS;
const ibanOf = (account: (typeof SANDBOX_ACCOUNTS)[number] | undefined): string =>
  account?.AccountIdentifiers.find((each) => each.SchemeName === 'IBAN')?.Identification ?? '';

let clock: FixedClock;
let rail: FakeRail;
let logs: LogCapture;
let registry: SupplierRegistry;
let payees: SupplierPayees;

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

/** The use case over `withRail`, the partner the test gives, on the same database and clock. */
const payeesWith = (
  withRail: FakeRail | undefined,
  { partner = 'fake', formOrigin }: { partner?: string; formOrigin?: string } = {},
) =>
  createSupplierPayees({
    database: app,
    keys,
    ids,
    clock,
    rail: withRail === undefined || formOrigin === undefined ? withRail : { ...withRail, formOrigin },
    partner,
    logger: loggerFor(logs),
  });

let people = 0;

/** A person with a membership in the organisation. */
async function member(org: string, role: Role): Promise<SupplierMember & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `supplier-payees-${String(people)}` },
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
const nextKey = () => {
  keysUsed += 1;
  return `key-${String(keysUsed)}`;
};
const keyed = (who: SupplierMember, operation: string, key = nextKey()): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload: '{}',
});

/** A supplier added by the admin, as E1-2 adds it. */
async function added(admin: SupplierMember, details = DETAILS): Promise<string> {
  const write = await registry.add(admin, keyed(admin, ADD_OPERATION), details, CORRELATION);
  if (write.outcome !== 'added') throw new Error(`not added: ${JSON.stringify(write)}`);
  return write.supplier.id;
}

const start = (who: SupplierMember, supplierId: string, key?: string, using = payees) =>
  using.start(who, keyed(who, PAYEE_START_OPERATION, key), supplierId, CORRELATION);
const check = (who: SupplierMember, supplierId: string, registrationId: string, key?: string, using = payees) =>
  using.check(who, keyed(who, PAYEE_CHECK_OPERATION, key), supplierId, registrationId, CORRELATION);

const answered = (write: PayeeWrite, outcome: 'started' | 'checked' | 'waiting') => {
  if (write.outcome !== outcome) throw new Error(`not ${outcome}: ${JSON.stringify(write)}`);
  return write;
};

/** The partner's form a start answered, filled in by the admin with the account's details. */
const filled = (org: string, started: { readonly form: { readonly url: string } | null }, iban = ibanOf(JASMINE)) =>
  rail.bank.fillForm(org, started.form?.url ?? '', { name: 'Jasmine AI FZ-LLC', iban });

/** A registration started, its form filled in with the account's details, and checked: REGISTERED, waiting. */
async function registered(admin: SupplierMember, supplierId: string, iban = ibanOf(JASMINE)) {
  const started = answered(await start(admin, supplierId), 'started');
  await filled(admin.orgId, started, iban);
  return answered(await check(admin, supplierId, started.registration.id), 'checked');
}

/** The partner, its first registration call failing: done there and its answer lost, or never done at all. */
const failingOnce = (lost: boolean): FakeRail => {
  let failed = false;
  return {
    ...rail,
    registerBeneficiary: async (input) => {
      if (failed) return rail.registerBeneficiary(input);
      failed = true;
      if (lost) await rail.registerBeneficiary(input);
      throw new RailUnavailable();
    },
  };
};

/** The supplier as its signed state says. */
const supplierNow = (org: string, id: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await supplierOf(tx, states, { orgId: org, id }, 'share');
    if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
    return read.supplier;
  });

/** The version as its signed state says. */
const versionNow = (org: string, supplierId: string, id: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await versionOf(tx, states, { orgId: org, id }, supplierId);
    if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
    return read.version;
  });

/** Runs `work` on the supplier read for change, as E2-2b and E3 will. */
const onSupplier = <T>(
  org: string,
  id: string,
  work: (
    tx: Parameters<typeof supplierOf>[0],
    states: Parameters<typeof supplierOf>[1],
    found: Extract<Awaited<ReturnType<typeof supplierOf>>, { outcome: 'found' }>,
  ) => Promise<T>,
) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId: org, id }, 'change');
    if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
    return work(tx, states, found);
  });

/** The change waiting confirmed, as the admin's step-up will (E2-2b): the supplier then holds its payee key. */
const confirmed = (org: string, id: string, registrationId: string) =>
  onSupplier(org, id, async (tx, states, found) => {
    const registration = await registrationOf(tx, states, { orgId: org, id: registrationId }, id, 'share');
    if (registration.outcome !== 'found') throw new Error(`no registration: ${registration.outcome}`);
    const version = await versionOf(tx, states, { orgId: org, id: registration.registration.versionId }, id);
    const current = await versionOf(tx, states, { orgId: org, id: found.supplier.currentVersionId }, id);
    if (version.outcome !== 'found' || current.outcome !== 'found') throw new Error('no versions');
    return confirmPayeeChange(
      tx,
      states,
      { orgId: org, id },
      found,
      { version: version.version, registration: registration.registration, current: current.version },
      { actor: OPERATOR, coolingOffUntil: new Date('2026-10-03T08:00:00Z') },
    );
  });

/** The organisation's events about a subject, oldest first. */
const actionsAbout = async (org: string, subjectType: string, id: string) =>
  (
    await withTenant(app, org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select('action')
        .where('subject_type', '=', subjectType)
        .where('subject_id', '=', id)
        .orderBy('seq')
        .execute(),
    )
  ).map((event) => event.action);

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
  logs = new LogCapture();
  rail = createFakeRail({ clock, ids });
  registry = createSupplierRegistry({ database: app, keys, ids, clock, logger: loggerFor(new LogCapture()) });
  payees = payeesWith(rail);
});

describe(`registering a payee through the partner's form (E2-2a, Postgres ${server.version})`, () => {
  it('starts with no bank data, sends the admin to the partner’s form, and keeps the payee only from the partner', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    const started = answered(await start(admin, id), 'started');
    expect(started.registration).toMatchObject({ supplierId: id, status: 'STARTED', route: 'hosted', partner: 'fake' });
    expect(started.form?.url.startsWith('https://payees.fake-partner.invalid/form/')).toBe(true);
    expect(started.form?.expiresAt).toEqual(new Date(clock.now().getTime() + 30 * MINUTE_MS));

    // Nothing filled in yet: the check leaves everything as it was, and the same key may ask again.
    const waiting = answered(await check(admin, id, started.registration.id, 'same-key'), 'waiting');
    expect(waiting.registration.status).toBe('STARTED');
    expect(waiting.form).toEqual(started.form);
    expect(await supplierNow(org, id)).toMatchObject({ pendingVersionId: null });

    await filled(org, started);
    const checked = answered(await check(admin, id, started.registration.id, 'same-key'), 'checked');

    expect(checked.form).toBeNull();
    expect(checked.registration).toMatchObject({
      status: 'REGISTERED',
      nameCheck: 'match',
      maskedName: 'J****** A* F*****',
      payeeHint: 'AE…6026',
    });
    expect(checked.registration.payeeKey).toMatch(/^fake-payee-[a-p]{32}$/u);
    // In waiting, inert: the supplier still pays the version it paid, with the payee key it had.
    const supplier = await supplierNow(org, id);
    expect(supplier).toMatchObject({ pendingVersionId: checked.registration.versionId, payeeKey: null });
    const pending = await versionNow(org, id, checked.registration.versionId);
    expect(pending).toMatchObject({
      version: 2,
      displayName: DETAILS.displayName,
      source: DETAILS.source,
      enteredBy: admin.membershipId,
      registrationId: checked.registration.id,
      beneficiaryRef: checked.registration.beneficiaryRef,
      payeeHint: 'AE…6026',
    });
    expect(await actionsAbout(org, 'beneficiary_registration', checked.registration.id)).toEqual([
      'beneficiary_registration.started',
      'beneficiary_registration.answered',
      'beneficiary_registration.registered',
    ]);
    expect(await actionsAbout(org, 'supplier', id)).toEqual(['supplier.added', 'supplier.payee_change_staged']);
    expect(findLeaks(JSON.stringify([started, waiting, checked, supplier, pending]), IBANS)).toEqual([]);
  });

  it('takes a verified supplier back to unverified, since a payee change is verified again', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await onSupplier(org, id, (tx, states, found) =>
      verifySupplier(tx, states, { orgId: org, id }, found, { verifiedBy: admin.membershipId, actor: OPERATOR }),
    );

    const checked = await registered(admin, id);

    expect(await supplierNow(org, id)).toMatchObject({
      status: 'UNVERIFIED',
      verifiedBy: null,
      verifiedVersionId: null,
      pendingVersionId: checked.registration.versionId,
    });
    expect((await actionsAbout(org, 'supplier', id)).slice(-3)).toEqual([
      'supplier.unverify',
      'supplier.verification_cleared',
      'supplier.payee_change_staged',
    ]);
  });

  it('answers a start sent again with the same key with the same registration, and a check of one ended as it stands', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    const first = answered(await start(admin, id, 'start-key'), 'started');
    const again = answered(await start(admin, id, 'start-key'), 'started');
    expect(again.registration.id).toBe(first.registration.id);
    expect(again.form).toEqual(first.form);

    await filled(org, first);
    const checked = answered(await check(admin, id, first.registration.id), 'checked');
    const later = answered(await check(admin, id, first.registration.id), 'checked');
    expect(later.registration).toEqual(checked.registration);
    expect((await actionsAbout(org, 'supplier', id)).filter((action) => action.includes('payee'))).toEqual([
      'supplier.payee_change_staged',
    ]);
  });

  it('numbers a change made after a withdrawn one past it', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const first = await registered(admin, id);
    await onSupplier(org, id, (tx, states, found) =>
      withdrawPayeeChange(tx, states, { orgId: org, id }, found, first.registration.versionId, { actor: OPERATOR }),
    );

    const second = await registered(admin, id);

    expect(await versionNow(org, id, second.registration.versionId)).toMatchObject({ version: 3 });
    expect(await supplierNow(org, id)).toMatchObject({ pendingVersionId: second.registration.versionId });
  });

  it('refuses a payee another supplier is paid to, a suspended one included, ending the registration (SEC-PAY-06)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = await added(admin);
    const held = await registered(admin, first);
    await confirmed(org, first, held.registration.id);
    await onSupplier(org, first, (tx, states, found) =>
      suspendSupplier(tx, states, { orgId: org, id: first }, found, { actor: OPERATOR }),
    );
    const second = await added(admin, { ...DETAILS, displayName: 'Jasmine Trading' });

    const started = answered(await start(admin, second), 'started');
    await filled(org, started);
    const refused = await check(admin, second, started.registration.id);

    expect(refused).toEqual({ outcome: 'refused', status: 409, code: 'SUPPLIER_PAYEE_TAKEN' });
    expect(await supplierNow(org, second)).toMatchObject({ pendingVersionId: null });
    // Ended as the partner holds it, with no version made from it: asked again, the same answer, and nothing staged.
    expect(await actionsAbout(org, 'beneficiary_registration', started.registration.id)).toEqual([
      'beneficiary_registration.started',
      'beneficiary_registration.answered',
      'beneficiary_registration.registered',
    ]);
    expect(await check(admin, second, started.registration.id)).toEqual(refused);
    expect(await actionsAbout(org, 'supplier', second)).toEqual(['supplier.added']);
    // Another account is this supplier's own.
    const other = answered(await start(admin, second), 'started');
    await filled(org, other, ibanOf(OTHER));
    expect(answered(await check(admin, second, other.registration.id), 'checked').registration.status).toBe(
      'REGISTERED',
    );
  });

  it('lets a supplier register its own account again', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const held = await registered(admin, id);
    await confirmed(org, id, held.registration.id);

    const again = await registered(admin, id);

    expect(again.registration.payeeKey).toBe(held.registration.payeeKey);
    expect(await supplierNow(org, id)).toMatchObject({ pendingVersionId: again.registration.versionId });
  });

  it('keeps no payee key where the partner has its form alone and no stable identity (R-13)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = await added(admin);
    const second = await added(admin, { ...DETAILS, displayName: 'Jasmine Trading' });
    rail = createFakeRail({ clock, ids, beneficiaryRoutes: ['hosted'], stablePayeeIdentity: false });
    payees = payeesWith(rail);

    const held = await registered(admin, first);
    await confirmed(org, first, held.registration.id);
    // With no key, one supplier per payee can't be held: the same account is registered for another (R-13).
    const again = await registered(admin, second);

    expect(held.registration).toMatchObject({ status: 'REGISTERED', payeeKey: null, payeeKeyVersion: null });
    expect(await supplierNow(org, first)).toMatchObject({ payeeKey: null });
    expect(await supplierNow(org, second)).toMatchObject({ pendingVersionId: again.registration.versionId });
  });

  it('records why the partner refused it: a form not filled in time', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const started = answered(await start(admin, id), 'started');

    clock.advanceBy(31 * MINUTE_MS);
    const checked = answered(await check(admin, id, started.registration.id), 'checked');

    expect(checked.registration).toMatchObject({ status: 'FAILED', failure: 'expired' });
    expect(checked.form).toBeNull();
    expect(await supplierNow(org, id)).toMatchObject({ pendingVersionId: null });
  });

  it('carries on with a registration still open, rather than opening another', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    const first = answered(await start(admin, id), 'started');
    const second = answered(await start(admin, id), 'started');

    expect(second.registration.id).toBe(first.registration.id);
    expect(second.form).toEqual(first.form);
  });

  it('carries on only with one still open, of this partner: past ended ones, and never another partner’s', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const elsewhere = answered(await start(admin, id, undefined, payeesWith(rail, { partner: 'another' })), 'started');
    const ended = answered(await start(admin, id), 'started');
    expect(ended.registration.id).not.toBe(elsewhere.registration.id);
    clock.advanceBy(31 * MINUTE_MS);
    expect(answered(await check(admin, id, ended.registration.id), 'checked').registration.status).toBe('FAILED');

    const next = answered(await start(admin, id), 'started');
    const again = answered(await start(admin, id), 'started');

    expect([elsewhere.registration.id, ended.registration.id]).not.toContain(next.registration.id);
    expect(again.registration.id).toBe(next.registration.id);
  });

  it('ends one carried on with whose form ran out, so the next start opens another', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const first = answered(await start(admin, id), 'started');
    clock.advanceBy(31 * MINUTE_MS);

    const carried = answered(await start(admin, id), 'started');
    expect(carried).toMatchObject({
      registration: { id: first.registration.id, status: 'FAILED', failure: 'expired' },
      form: null,
    });
    const next = answered(await start(admin, id), 'started');
    expect(next.registration.id).not.toBe(first.registration.id);
    expect(next.form).not.toBeNull();
  });

  it.each([
    ['a start waits behind a check’s hold on the supplier', 'change', 'start'],
    ['a check waits behind a start’s read of the supplier', 'share', 'check'],
  ] as const)('%s (a forced lock order: the supplier’s row serialises them)', async (_, held, waiting) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const started = answered(await start(admin, id), 'started');
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await (held === 'change' ? holder.query(HOLD_FOR_CHANGE, [org, id]) : holder.query(HOLD_FOR_SHARE, [org, id]));
      const asking = within(
        20_000,
        waiting === 'start' ? start(admin, id) : check(admin, id, started.registration.id),
        `the ${waiting}`,
      );
      await waitUntilQueued(database.as('admin'), 1);
      await holder.query('rollback');

      expect((await asking).outcome).toBe(waiting === 'start' ? 'started' : 'waiting');
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('answers a start as it stands when a check ended its registration while the partner was asked', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const first = answered(await start(admin, id), 'started');
    clock.advanceBy(31 * MINUTE_MS);
    // The check lands between the start's question to the partner and its answer being kept.
    const racing: FakeRail = {
      ...rail,
      registerBeneficiary: async (input) => {
        const outcome = await rail.registerBeneficiary(input);
        answered(await check(admin, id, first.registration.id), 'checked');
        return outcome;
      },
    };

    const carried = answered(await start(admin, id, undefined, payeesWith(racing)), 'started');

    expect(carried.registration).toMatchObject({ id: first.registration.id, status: 'FAILED', failure: 'expired' });
    expect(await actionsAbout(org, 'beneficiary_registration', first.registration.id)).toEqual([
      'beneficiary_registration.started',
      'beneficiary_registration.refused',
      'beneficiary_registration.failed',
    ]);
  });

  it('refuses another start, and stages no second change, while one is waiting', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await registered(admin, id);
    // One opened before the rule above, or past the app: its answer is kept, and nothing staged.
    const stale = ids.next();
    await withSignedStates(app, org, quiet(), (tx, states) =>
      startRegistration(tx, states, {
        orgId: org,
        id: stale,
        supplierId: id,
        versionId: ids.next(),
        partner: 'fake',
        route: 'hosted',
        startedBy: admin.membershipId,
        createdAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    const outcome = await rail.registerBeneficiary({ route: 'hosted', organizationId: org, registrationId: stale });
    await filled(org, { form: outcome.kind === 'waiting' ? { url: outcome.formUrl } : null }, ibanOf(OTHER));

    expect(await start(admin, id)).toEqual({ outcome: 'refused', status: 409, code: 'SUPPLIER_CHANGE_WAITING' });
    expect(await check(admin, id, stale)).toEqual({ outcome: 'refused', status: 409, code: 'SUPPLIER_CHANGE_WAITING' });
  });

  it('answers two checks at once once: one keeps the payee, the other answers it as it stands', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const started = answered(await start(admin, id), 'started');
    await filled(org, started);

    const both = await Promise.all([
      check(admin, id, started.registration.id),
      check(admin, id, started.registration.id),
    ]);

    expect(both.map((write) => answered(write, 'checked').registration.status)).toEqual(['REGISTERED', 'REGISTERED']);
    expect((await actionsAbout(org, 'supplier', id)).filter((action) => action.includes('payee'))).toEqual([
      'supplier.payee_change_staged',
    ]);
  });

  it('refuses past the day’s budget of registrations', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    // The day's 100, for another of the organisation's suppliers: the budget is the organisation's.
    const busy = await added(admin, { ...DETAILS, displayName: 'Gulf Trading LLC' });
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      for (let started = 0; started < 100; started += 1) {
        await startRegistration(tx, states, {
          orgId: org,
          id: ids.next(),
          supplierId: busy,
          versionId: ids.next(),
          partner: 'fake',
          route: 'hosted',
          startedBy: admin.membershipId,
          createdAt: clock.now(),
          actor: OPERATOR,
        });
      }
    });

    expect(await start(admin, id)).toEqual({ outcome: 'refused', status: 409, code: 'PAYEE_REGISTRATIONS_SPENT' });
    clock.advanceBy(24 * 60 * MINUTE_MS);
    expect((await start(admin, id)).outcome).toBe('started');
  });

  it('is an admin’s alone, of the organisation’s own suppliers and their own registrations', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const approver = await member(org, 'approver');
    const id = await added(admin);
    const otherId = await added(admin, { ...DETAILS, displayName: 'Gulf Trading LLC' });
    const started = answered(await start(admin, id), 'started');
    const elsewhere = await organization();
    const stranger = await member(elsewhere, 'admin');

    expect(await start(approver, id)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await check(approver, id, started.registration.id)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
    expect(await start(stranger, id)).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect(await check(stranger, id, started.registration.id)).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });
    expect(await check(admin, otherId, started.registration.id)).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });
  });
});

describe(`the partner not answering, or answering what can't be kept (E2-2a, Postgres ${server.version})`, () => {
  it('leaves a start whose answer was lost UNKNOWN, then asks the partner by its ID, never registering again', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    const losing = payeesWith(failingOnce(true));
    expect(await start(admin, id, 'lost-key', losing)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });

    const again = answered(await start(admin, id, 'lost-key', losing), 'started');
    expect(again.registration.status).toBe('UNKNOWN');
    // The partner had it: its form, as it first answered.
    expect(again.form?.url.startsWith('https://payees.fake-partner.invalid/form/')).toBe(true);
    await filled(org, again);
    expect(answered(await check(admin, id, again.registration.id), 'checked').registration.status).toBe('REGISTERED');
    expect(await actionsAbout(org, 'beneficiary_registration', again.registration.id)).toEqual([
      'beneficiary_registration.started',
      'beneficiary_registration.lost',
      'beneficiary_registration.answered',
      'beneficiary_registration.registered',
    ]);
  });

  it('leaves one STARTED the partner doesn’t know yet, which a start then carries on with', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    // Tx 1 committed, the partner not yet asked (a start still on its way, or one that stopped there).
    const waiting = ids.next();
    await withSignedStates(app, org, quiet(), (tx, states) =>
      startRegistration(tx, states, {
        orgId: org,
        id: waiting,
        supplierId: id,
        versionId: ids.next(),
        partner: 'fake',
        route: 'hosted',
        startedBy: admin.membershipId,
        createdAt: clock.now(),
        actor: OPERATOR,
      }),
    );

    expect(answered(await check(admin, id, waiting), 'checked').registration.status).toBe('STARTED');
    const carried = answered(await start(admin, id), 'started');

    expect(carried.registration.id).toBe(waiting);
    expect(carried.form?.url.startsWith('https://payees.fake-partner.invalid/form/')).toBe(true);
  });

  it('records FAILED a registration the partner never got, once it answers again', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    const failing = payeesWith(failingOnce(false));
    expect(await start(admin, id, 'down-key', failing)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });
    // The start sent again asks the partner by its ID: unknown there, so it ends, and the next start opens another.
    const ended = answered(await start(admin, id, 'down-key', failing), 'started');
    expect(ended).toMatchObject({ registration: { status: 'FAILED', failure: 'unknown' }, form: null });
    expect(await actionsAbout(org, 'beneficiary_registration', ended.registration.id)).toEqual([
      'beneficiary_registration.started',
      'beneficiary_registration.lost',
      'beneficiary_registration.refused',
      'beneficiary_registration.failed',
    ]);
    expect(answered(await start(admin, id), 'started').registration.id).not.toBe(ended.registration.id);
  });

  it('answers PARTNER_UNAVAILABLE where no partner is set up, and PAYEE_ROUTE_NOT_OFFERED where its form can’t be used', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    expect(await start(admin, id, undefined, payeesWith(undefined))).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });
    const passThrough = payeesWith(createFakeRail({ clock, ids, beneficiaryRoutes: ['pass_through'] }));
    expect(await start(admin, id, undefined, passThrough)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'PAYEE_ROUTE_NOT_OFFERED',
    });
    // With no stable identity, a partner offering pass-through registers by it alone (ADR-014 §3).
    const noIdentity = payeesWith(createFakeRail({ clock, ids, stablePayeeIdentity: false }));
    expect(await start(admin, id, undefined, noIdentity)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'PAYEE_ROUTE_NOT_OFFERED',
    });
  });

  it('never sends the admin to a form off the partner’s own origin, and logs it', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    const elsewhere = payeesWith(rail, { formOrigin: 'https://payees.example' });

    expect(await start(admin, id, undefined, elsewhere)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });
    expect(logs.lines().map((line) => line.event)).toContain('suppliers.partner_page_refused');
  });

  it('keeps nothing of an answer naming an account number, and never names it (ADR-014 §3)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const started = answered(await start(admin, id), 'started');
    await filled(org, started);
    const leaking: FakeRail = {
      ...rail,
      // A partner's adapter letting the number through in its hint, past the fake's own check.
      getBeneficiaryState: async (ref) => {
        const outcome = await rail.getBeneficiaryState(ref);
        return outcome.kind === 'registered'
          ? { ...outcome, beneficiary: { ...outcome.beneficiary, hint: ibanOf(JASMINE) } }
          : outcome;
      },
    };

    const checked = answered(
      await check(admin, id, started.registration.id, undefined, payeesWith(leaking)),
      'checked',
    );

    expect(checked.registration).toMatchObject({ status: 'FAILED', failure: 'unknown', payeeHint: null });
    expect(await supplierNow(org, id)).toMatchObject({ pendingVersionId: null });
    expect(await actionsAbout(org, 'beneficiary_registration', started.registration.id)).toEqual([
      'beneficiary_registration.started',
      'beneficiary_registration.refused',
      'beneficiary_registration.failed',
    ]);
    expect(logs.lines()).toContainEqual(
      expect.objectContaining({ event: 'suppliers.partner_answer_refused', registrationId: started.registration.id }),
    );
    expect(findLeaks(logs.text + JSON.stringify(checked), IBANS)).toEqual([]);
  });

  it('ends FAILED one whose partner, offering a stable identity, gave none that can be kept', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const started = answered(await start(admin, id), 'started');
    await filled(org, started);
    const broken: FakeRail = {
      ...rail,
      getBeneficiaryState: async (ref) => {
        const outcome = await rail.getBeneficiaryState(ref);
        return outcome.kind === 'registered'
          ? { ...outcome, beneficiary: { ...outcome.beneficiary, payeeIdentity: 'not one' } }
          : outcome;
      },
    };

    const checked = answered(await check(admin, id, started.registration.id, undefined, payeesWith(broken)), 'checked');

    expect(checked.registration).toMatchObject({ status: 'FAILED', failure: 'unknown' });
    expect(await supplierNow(org, id)).toMatchObject({ pendingVersionId: null });
  });

  it('never asks one partner about a registration started with another', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const started = answered(await start(admin, id), 'started');

    expect(
      await check(admin, id, started.registration.id, undefined, payeesWith(rail, { partner: 'another' })),
    ).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });
    expect(logs.lines().map((line) => line.event)).toContain('suppliers.registration_partner_differs');
  });
});
