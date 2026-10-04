// E2-1b: payee storage (0033), on the real migrated schema, as the app role.
// A beneficiary registration is started STARTED and ends REGISTERED or
// FAILED, from STARTED or after a call lost on the way (UNKNOWN), every field
// sealed; the table holds each end to what it needs, and the app to adding
// rows and moving only what the seal covers. A version takes its payee
// reference only from a registration of its own supplier, or carries the one
// it follows; a payee change waits inert, the supplier keeping its key, until
// it is confirmed, when the key moves with the version it pays, one
// supplier's alone in an organisation, suspended ones included; neither step
// waits behind a version's foreign key; confirmations go one at a time under
// the organisation's lock; and starts are counted for the day's budget under
// that same lock. What the owner can do past the app is
// suppliers-tamper.db.test.ts.
import { createDatabase, type Database, lockName } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  findLeaks,
  FixedClock,
  holdNamedLock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { DAY_MS, HOUR_MS } from '../../../shared-kernel/index.ts';
import { withSignedStates } from '../../audit/index.ts';
import { createOrganization } from '../../organizations/index.ts';
import { AccountNumberLeak, type BeneficiaryState } from '../../providers/index.ts';
import type { SupplierDetails } from '../domain/supplier.ts';
import type { PayeeKey } from './payee-key.ts';
import {
  BENEFICIARY_REGISTRATIONS,
  isPayeeTaken,
  MOST_PAYEE_REGISTRATIONS_A_DAY,
  type NewRegistration,
  onePayeeChangeAtATime,
  recordFailed,
  recordLost,
  recordRegistered,
  type RegistrationCheck,
  registrationOf,
  registrationsStartedSince,
  startRegistration,
  supplierWithPayeeKey,
} from './registrations.ts';
import {
  addSupplier,
  addVersion,
  confirmPayeeChange,
  reactivateSupplier,
  stagePayeeChange,
  SUPPLIER_VERSIONS,
  type SupplierCheck,
  supplierOf,
  type SupplierRecord,
  suspendSupplier,
  verifySupplier,
  versionOf,
  withdrawPayeeChange,
} from './suppliers.ts';
import type { SuppliersTables } from './tables.ts';

// The tables an organisation is made in, as createOrganization takes them: the suppliers module
// may not name the directory's (ADR-004's map), which making one writes to.
type OrganizationTables = Parameters<typeof createOrganization>[0] extends Transaction<infer T> ? T : never;
type Tables = SuppliersTables & OrganizationTables;
type Tx = Parameters<typeof supplierOf>[0];
type States = Parameters<typeof supplierOf>[1];

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe210_0000_0000);
const clock = new FixedClock(new Date('2026-10-02T08:00:00Z'));
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
/** When a confirmed change's cooling-off ends, as the use case gives it (E2-2b). */
const COOLED_OFF = new Date('2026-10-03T08:00:00Z');

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: null, tradeLicence: null },
  source: { kind: 'registry', ref: 'DED-REG-88112' },
};
const MASKED_NAME = 'G*** O***** S******* L**';

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

/** A supplier of the organisation, UNVERIFIED, with its first version: its ID and its first version's. */
async function supplier(orgId: string): Promise<{ id: string; versionId: string }> {
  const id = ids.next();
  const versionId = ids.next();
  await withSignedStates(app, orgId, services(), (tx, states) =>
    addSupplier(tx, states, keys, {
      orgId,
      id,
      versionId,
      supplier: DETAILS,
      enteredBy: ids.next(),
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return { id, versionId };
}

/** Tx 1: a registration of the supplier started, for a version to come. */
async function started(orgId: string, supplierId: string, overrides: Partial<NewRegistration> = {}) {
  const registration: NewRegistration = {
    orgId,
    id: ids.next(),
    supplierId,
    versionId: ids.next(),
    partner: 'fake_partner',
    route: 'pass_through',
    startedBy: ids.next(),
    createdAt: clock.now(),
    actor: OPERATOR,
    ...overrides,
  };
  await withSignedStates(app, orgId, services(), (tx, states) => startRegistration(tx, states, registration));
  return registration;
}

const read = (orgId: string, id: string, supplierId: string) =>
  withSignedStates(app, orgId, services(), (tx, states) =>
    registrationOf(tx, states, { orgId, id }, supplierId, 'share'),
  );

/** Work on one registration read for change, in one transaction: what E2-2's Tx 2 will do. */
const onRegistration = <T>(
  orgId: string,
  supplierId: string,
  id: string,
  work: (tx: Tx, states: States, found: Extract<RegistrationCheck, { outcome: 'found' }>) => Promise<T>,
) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const found = await registrationOf(tx, states, { orgId, id }, supplierId, 'change');
    if (found.outcome !== 'found') throw new Error(`No registration: ${found.outcome}`);
    return work(tx, states, found);
  });

/** Work on one supplier read for change, in one transaction. */
const onSupplier = <T>(
  orgId: string,
  supplierId: string,
  work: (tx: Tx, states: States, found: Extract<SupplierCheck, { outcome: 'found' }>) => Promise<T>,
) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const found = await supplierOf(tx, states, { orgId, id: supplierId }, 'change');
    if (found.outcome !== 'found') throw new Error(`No supplier: ${found.outcome}`);
    return work(tx, states, found);
  });

/** The partner's answer for the registration, as its adapter gives it. */
const answer = (
  orgId: string,
  registrationId: string,
  overrides: Partial<BeneficiaryState> = {},
): BeneficiaryState => ({
  organizationId: orgId,
  registrationId,
  beneficiaryRef: `fake-beneficiary-${registrationId}`,
  payeeIdentity: 'fake-payee-1',
  nameCheck: 'partial',
  maskedName: MASKED_NAME,
  hint: 'AE…6026',
  registeredAt: clock.now(),
  ...overrides,
});

const PARTNER_KEY: PayeeKey = { key: 'fake-payee-1', keyVersion: null };

const registeredBy = (orgId: string, supplierId: string, id: string, payee: PayeeKey = PARTNER_KEY) =>
  onRegistration(orgId, supplierId, id, (tx, states, found) =>
    recordRegistered(tx, states, { orgId, id }, found, {
      beneficiary: answer(orgId, id),
      payee,
      actor: OPERATOR,
    }),
  );

const failedBy = (orgId: string, supplierId: string, id: string) =>
  onRegistration(orgId, supplierId, id, (tx, states, found) =>
    recordFailed(tx, states, { orgId, id }, found, { reason: 'invalid_details', actor: OPERATOR }),
  );

const lostBy = (orgId: string, supplierId: string, id: string) =>
  onRegistration(orgId, supplierId, id, (tx, states) => recordLost(tx, states, { orgId, id }, { actor: OPERATOR }));

/** The version, read and verified in the caller's transaction, or a test failure. */
async function versionIn(tx: Tx, states: States, orgId: string, id: string, supplierId: string) {
  const read = await versionOf(tx, states, { orgId, id }, supplierId);
  if (read.outcome !== 'found') throw new Error(`No version: ${read.outcome}`);
  return read.version;
}

/** A payee change, as stagePayeeChange and confirmPayeeChange take it. */
type PayeeChange = Parameters<typeof stagePayeeChange>[4];

/**
 * Tx 2 up to the change: the answer recorded and the version made with its
 * reference (following the current one), in the caller's transaction. Gives
 * the supplier as read for change, and the change.
 */
async function madeIn(
  tx: Tx,
  states: States,
  orgId: string,
  supplierId: string,
  registrationId: string,
  payee: PayeeKey = PARTNER_KEY,
  number: number | null = null,
) {
  const of = await supplierOf(tx, states, { orgId, id: supplierId }, 'change');
  const found = await registrationOf(tx, states, { orgId, id: registrationId }, supplierId, 'change');
  if (of.outcome !== 'found' || found.outcome !== 'found') throw new Error('No supplier or registration');
  const registration = await recordRegistered(tx, states, { orgId, id: registrationId }, found, {
    beneficiary: answer(orgId, registrationId),
    payee,
    actor: OPERATOR,
  });
  const follows = await versionIn(tx, states, orgId, of.supplier.currentVersionId, supplierId);
  await addVersion(tx, states, keys, {
    orgId,
    id: registration.versionId,
    supplierId,
    // The supplier's next number; after a withdrawn change, past the version it left (the caller's to count).
    version: number ?? follows.version + 1,
    supplier: DETAILS,
    enteredBy: registration.startedBy,
    enteredAt: clock.now(),
    actor: OPERATOR,
    of,
    follows,
    registration,
  });
  const version = await versionIn(tx, states, orgId, registration.versionId, supplierId);
  return { of, change: { version, registration, current: follows } satisfies PayeeChange };
}

/**
 * Tx 2 in full, for a supplier with a registration started: madeIn's, then
 * the payee change put in waiting. What E2-2's use case will do. Gives the
 * supplier as staged, and the change.
 */
const tx2 = (orgId: string, supplierId: string, registrationId: string, payee: PayeeKey = PARTNER_KEY) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const { of, change } = await madeIn(tx, states, orgId, supplierId, registrationId, payee);
    const staged = await stagePayeeChange(tx, states, { orgId, id: supplierId }, of, change, { actor: OPERATOR });
    return { staged, change };
  });

/** The payee change waiting confirmed in the caller's transaction, as E2-2 will after the admin's step-up. */
async function confirmIn(tx: Tx, states: States, orgId: string, supplierId: string, registrationId: string) {
  const of = await supplierOf(tx, states, { orgId, id: supplierId }, 'change');
  const found = await registrationOf(tx, states, { orgId, id: registrationId }, supplierId, 'share');
  if (of.outcome !== 'found' || found.outcome !== 'found') throw new Error('No supplier or registration');
  const version = await versionIn(tx, states, orgId, found.registration.versionId, supplierId);
  const current = await versionIn(tx, states, orgId, of.supplier.currentVersionId, supplierId);
  return confirmPayeeChange(
    tx,
    states,
    { orgId, id: supplierId },
    of,
    { version, registration: found.registration, current },
    { actor: OPERATOR, coolingOffUntil: COOLED_OFF },
  );
}

const confirmed = (orgId: string, supplierId: string, registrationId: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => confirmIn(tx, states, orgId, supplierId, registrationId));

/** A supplier with a payee registered, staged and confirmed: Tx 1, Tx 2, then the confirmation. */
async function withPayee(orgId: string, supplierId: string, payee: PayeeKey = PARTNER_KEY) {
  const registration = await started(orgId, supplierId);
  const { staged } = await tx2(orgId, supplierId, registration.id, payee);
  return { registration, staged, confirmed: await confirmed(orgId, supplierId, registration.id) };
}

/** What a promise was refused with, or undefined. */
const refusalOf = (promise: Promise<unknown>): Promise<unknown> =>
  promise.then(
    () => undefined,
    (error: unknown) => error,
  );

const supplierNow = (orgId: string, supplierId: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => supplierOf(tx, states, { orgId, id: supplierId }, 'share'));

const eventsAbout = (orgId: string, subjectId: string) =>
  database
    .as('backup')
    .query<{ action: string; details: string }>(
      'select action, details::text as details from audit.events where org_id = $1 and subject_id = $2 order by seq',
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

describe(`a beneficiary registration (E2-1b, Postgres ${server.version})`, () => {
  it('is started STARTED, naming its supplier, version, partner, route and starter, every field sealed', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const registration = await started(org, supplierId, { partner: 'fake_partner', route: 'hosted' });

    expect(await read(org, registration.id, supplierId)).toMatchObject({
      outcome: 'found',
      registration: {
        id: registration.id,
        supplierId,
        versionId: registration.versionId,
        partner: 'fake_partner',
        route: 'hosted',
        startedBy: registration.startedBy,
        status: 'STARTED',
        beneficiaryRef: null,
        payeeKey: null,
        payeeKeyVersion: null,
        nameCheck: null,
        maskedName: null,
        payeeHint: null,
        registeredAt: null,
        failure: null,
      },
    });
    expect((await eventsAbout(org, registration.id)).map(({ action }) => action)).toEqual([
      'beneficiary_registration.started',
    ]);
  });

  it('ends REGISTERED with the partner’s answer, its masked name and reference never put in an event', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { id } = await started(org, supplierId);

    const fingerprint = { key: 'f'.repeat(64), keyVersion: 1 };
    const returned = await registeredBy(org, supplierId, id, fingerprint);

    const expected = {
      status: 'REGISTERED',
      beneficiaryRef: `fake-beneficiary-${id}`,
      payeeKey: 'f'.repeat(64),
      payeeKeyVersion: 1,
      nameCheck: 'partial',
      maskedName: MASKED_NAME,
      payeeHint: 'AE…6026',
      registeredAt: clock.now(),
      failure: null,
    };
    expect(returned).toMatchObject(expected);
    expect(await read(org, id, supplierId)).toMatchObject({ outcome: 'found', registration: expected });
    const events = await eventsAbout(org, id);
    expect(events.map(({ action }) => action)).toEqual([
      'beneficiary_registration.started',
      'beneficiary_registration.answered',
      'beneficiary_registration.registered',
    ]);
    const text = events.map(({ details }) => details).join('\n');
    expect(findLeaks(text, [MASKED_NAME, 'fake-beneficiary', 'f'.repeat(64)])).toEqual([]);
  });

  it('ends REGISTERED or FAILED after a call lost on the way (UNKNOWN), and FAILED from STARTED with why', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const [lostThenRegistered, lostThenFailed, failed] = [
      await started(org, supplierId),
      await started(org, supplierId),
      await started(org, supplierId),
    ];

    await lostBy(org, supplierId, lostThenRegistered.id);
    await lostBy(org, supplierId, lostThenFailed.id);
    expect(await read(org, lostThenRegistered.id, supplierId)).toMatchObject({ registration: { status: 'UNKNOWN' } });
    await registeredBy(org, supplierId, lostThenRegistered.id);
    await failedBy(org, supplierId, lostThenFailed.id);
    await failedBy(org, supplierId, failed.id);

    expect(await read(org, lostThenRegistered.id, supplierId)).toMatchObject({
      registration: { status: 'REGISTERED' },
    });
    for (const { id } of [lostThenFailed, failed]) {
      expect(await read(org, id, supplierId)).toMatchObject({
        registration: { status: 'FAILED', failure: 'invalid_details', beneficiaryRef: null },
      });
    }
  });

  it('refuses a move its machine doesn’t allow, before any SQL runs, leaving it as it was', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const registered = await started(org, supplierId);
    const failed = await started(org, supplierId);
    const lost = await started(org, supplierId);
    await registeredBy(org, supplierId, registered.id);
    await failedBy(org, supplierId, failed.id);
    await lostBy(org, supplierId, lost.id);

    await expect(registeredBy(org, supplierId, registered.id)).rejects.toBeInstanceOf(RangeError);
    await expect(failedBy(org, supplierId, registered.id)).rejects.toBeInstanceOf(RangeError);
    await expect(registeredBy(org, supplierId, failed.id)).rejects.toBeInstanceOf(RangeError);
    await expect(lostBy(org, supplierId, lost.id)).rejects.toBeInstanceOf(RangeError);
    await expect(lostBy(org, supplierId, registered.id)).rejects.toBeInstanceOf(RangeError);
    expect((await eventsAbout(org, registered.id)).map(({ action }) => action)).toHaveLength(3);
    expect(await read(org, failed.id, supplierId)).toMatchObject({ registration: { status: 'FAILED' } });
    expect(await read(org, lost.id, supplierId)).toMatchObject({ registration: { status: 'UNKNOWN' } });
  });

  it('refuses the partner’s answer for another organisation or another registration, and a reason that isn’t one (SEC-PAY-08)', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { id } = await started(org, supplierId);
    const answered = (beneficiary: BeneficiaryState) =>
      onRegistration(org, supplierId, id, (tx, states, found) =>
        recordRegistered(tx, states, { orgId: org, id }, found, { beneficiary, payee: PARTNER_KEY, actor: OPERATOR }),
      );

    await expect(answered(answer(ids.next(), id))).rejects.toBeInstanceOf(RangeError);
    await expect(answered(answer(org, ids.next()))).rejects.toBeInstanceOf(RangeError);
    await expect(
      onRegistration(org, supplierId, id, (tx, states, found) =>
        recordFailed(tx, states, { orgId: org, id }, found, {
          reason: 'gone' as 'expired',
          actor: OPERATOR,
        }),
      ),
    ).rejects.toBeInstanceOf(RangeError);
    // The same answer, in other case, is this one's.
    await answered(answer(org.toUpperCase(), id.toUpperCase()));
    expect(await read(org, id, supplierId)).toMatchObject({ registration: { status: 'REGISTERED' } });
  });

  it('refuses a hint holding an account number, never naming it, before any SQL runs (ADR-014 §3)', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { id } = await started(org, supplierId);
    const iban = 'AE070331234567890123456';

    for (const hint of [iban, 'AE07 0331 2345 6789 0123 456', 'Acct 0123-4567-89']) {
      const refused = await refusalOf(
        onRegistration(org, supplierId, id, (tx, states, found) =>
          recordRegistered(tx, states, { orgId: org, id }, found, {
            beneficiary: answer(org, id, { hint }),
            payee: PARTNER_KEY,
            actor: OPERATOR,
          }),
        ),
      );
      expect(refused).toBeInstanceOf(AccountNumberLeak);
      expect(findLeaks(String(refused), [iban, '0123'])).toEqual([]);
    }
    expect(await read(org, id, supplierId)).toMatchObject({ registration: { status: 'STARTED', payeeHint: null } });
  });

  it('refuses a partner identity holding an account number, however the key was built; keeps our fingerprint', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { id } = await started(org, supplierId);
    const registering = (payee: PayeeKey) =>
      onRegistration(org, supplierId, id, (tx, states, found) =>
        recordRegistered(tx, states, { orgId: org, id }, found, {
          beneficiary: answer(org, id),
          payee,
          actor: OPERATOR,
        }),
      );

    // An identity a partner might give: built at run time, so no scanner reads it as a credential.
    const identity = ['acct', '0123456789'].join('-');
    const refused = await refusalOf(registering({ key: identity, keyVersion: null }));
    expect(refused).toBeInstanceOf(AccountNumberLeak);
    expect(findLeaks(String(refused), ['0123456789'])).toEqual([]);
    // A fingerprint is a MAC, digit runs and all, and is kept as it is.
    const fingerprint = { key: '0123456789'.repeat(7).slice(0, 64), keyVersion: 1 };
    expect(await registering(fingerprint)).toMatchObject({ payeeKey: fingerprint.key, payeeKeyVersion: 1 });
  });

  it('is found only as its own supplier’s, and by no other organisation', async () => {
    const org = await organization();
    const other = await organization();
    const { id: supplierId } = await supplier(org);
    const { id: otherSupplier } = await supplier(org);
    const { id } = await started(org, supplierId);

    expect(await read(org, id, otherSupplier)).toEqual({ outcome: 'missing' });
    expect(await read(other, id, supplierId)).toEqual({ outcome: 'missing' });
    expect(await read(org, id, supplierId.toUpperCase())).toMatchObject({ outcome: 'found' });
  });

  it('refuses a partner’s name or a route that isn’t one before any SQL runs; the table, a version started for twice, or no supplier', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const first = await started(org, supplierId);

    await expect(started(org, supplierId, { partner: 'Fake Partner' })).rejects.toBeInstanceOf(RangeError);
    await expect(started(org, supplierId, { route: 'email' as 'hosted' })).rejects.toBeInstanceOf(RangeError);
    await expect(started(org, supplierId, { versionId: first.versionId })).rejects.toThrow(
      /one_registration_a_version/,
    );
    await expect(started(org, ids.next())).rejects.toThrow(/for_a_supplier/);
  });
});

describe(`what the table holds the app to (0033, Postgres ${server.version})`, () => {
  /** A registration's row put in by the app past startRegistration, with `overrides`: what the table itself refuses. */
  const plant = (orgId: string, supplierId: string, overrides: Record<string, unknown> = {}) =>
    withSignedStates(app, orgId, services(), (tx) =>
      tx
        .insertInto(BENEFICIARY_REGISTRATIONS.table)
        .values({
          org_id: orgId,
          id: ids.next(),
          supplier_id: supplierId,
          version_id: ids.next(),
          partner: 'fake_partner',
          route: 'hosted',
          started_by: ids.next(),
          status: 'STARTED',
          created_at: clock.now(),
          ...overrides,
        })
        .execute(),
    );

  /** A registration planted, then moved to `status` past the app with `set`: what each end needs. */
  const plantedThenMoved = async (orgId: string, supplierId: string, status: string, set: Record<string, unknown>) => {
    const id = ids.next();
    await plant(orgId, supplierId, { id });
    return withSignedStates(app, orgId, services(), (tx) =>
      tx
        .updateTable(BENEFICIARY_REGISTRATIONS.table)
        .set({ status, ...set })
        .where('id', '=', id)
        .execute(),
    );
  };

  const REGISTERED = {
    beneficiary_ref: 'fake-beneficiary-1',
    name_check: 'match',
    payee_hint: 'AE…6026',
    registered_at: clock.now(),
  };

  it('refuses one added in any status but STARTED, and every move its machine doesn’t list (the status guard)', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    await expect(plant(org, supplierId, { status: 'REGISTERED', ...REGISTERED })).rejects.toThrow(
      /must start as STARTED/,
    );
    const registered = await started(org, supplierId);
    await registeredBy(org, supplierId, registered.id);
    const failed = await started(org, supplierId);
    await failedBy(org, supplierId, failed.id);
    const lost = await started(org, supplierId);
    await lostBy(org, supplierId, lost.id);
    // The guard runs before the table's checks, so it speaks first whatever else the row holds.
    const moved = (id: string, status: string) =>
      withSignedStates(app, org, services(), (tx) =>
        tx.updateTable(BENEFICIARY_REGISTRATIONS.table).set({ status }).where('id', '=', id).execute(),
      );

    for (const [id, status] of [
      [registered.id, 'STARTED'],
      [registered.id, 'FAILED'],
      [registered.id, 'UNKNOWN'],
      [failed.id, 'STARTED'],
      [failed.id, 'UNKNOWN'],
      [lost.id, 'STARTED'],
    ] as const) {
      await expect(moved(id, status)).rejects.toThrow(/can't move from/);
    }
    // FAILED > REGISTERED: refused whatever the row holds.
    await expect(
      withSignedStates(app, org, services(), (tx) =>
        tx
          .updateTable(BENEFICIARY_REGISTRATIONS.table)
          .set({ status: 'REGISTERED', ...REGISTERED, failure: null })
          .where('id', '=', failed.id)
          .execute(),
      ),
    ).rejects.toThrow(/can't move from FAILED to REGISTERED/);
  });

  it('holds a REGISTERED row to its reference, name check, hint and time, and a FAILED one to why', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);

    for (const column of Object.keys(REGISTERED)) {
      await expect(plantedThenMoved(org, supplierId, 'REGISTERED', { ...REGISTERED, [column]: null })).rejects.toThrow(
        /registered_with_its_reference/,
      );
    }
    await expect(plantedThenMoved(org, supplierId, 'FAILED', {})).rejects.toThrow(/failed_with_its_reason/);
    // Each with all it needs moves: the checks are not simply always false.
    await plantedThenMoved(org, supplierId, 'REGISTERED', REGISTERED);
    await plantedThenMoved(org, supplierId, 'FAILED', { failure: 'expired' });
    await plantedThenMoved(org, supplierId, 'UNKNOWN', {});
  });

  it.each([
    ['a_reference_or_a_failure', { beneficiary_ref: 'fake-beneficiary-1', failure: 'unknown' }],
    ['a_key_version_with_its_key', { payee_key_version: 1 }],
    ['partner', { partner: 'Fake Partner' }],
    ['partner', { partner: `p${'a'.repeat(32)}` }],
    ['route', { route: 'email' }],
    ['beneficiary_ref', { beneficiary_ref: 'has a space' }],
    ['beneficiary_ref', { beneficiary_ref: 'r'.repeat(129) }],
    ['payee_key', { payee_key: '' }],
    ['payee_key', { payee_key: 'k'.repeat(129) }],
    ['payee_key_version', { payee_key: 'k', payee_key_version: 0 }],
    ['name_check', { name_check: 'maybe' }],
    ['masked_name', { masked_name: '' }],
    ['masked_name', { masked_name: 'n'.repeat(141) }],
    ['masked_name', { masked_name: 'G*** \u0007' }],
    ['payee_hint', { payee_hint: 'h'.repeat(41) }],
    ['payee_hint', { payee_hint: 'AE…\n6026' }],
    ['registered_at', { registered_at: 'infinity' }],
    ['failure', { failure: 'lost' }],
    ['created_at', { created_at: '-infinity' }],
  ])('refuses %s as the table’s check holds it: %j', async (check, overrides) => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);

    await expect(plant(org, supplierId, overrides)).rejects.toThrow(
      new RegExp(`violates check constraint "[a-z_]*${check}[a-z_]*"`),
    );
  });

  it('bounds a masked name by characters, so 140 of four bytes each fit, and a 141st doesn’t', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const wide = '\u{1D400}';

    await plant(org, supplierId, { masked_name: wide.repeat(140) });
    await expect(plant(org, supplierId, { masked_name: wide.repeat(141) })).rejects.toThrow(/masked_name/);
  });

  it('lets the app neither delete, nor change a key or a creation time', async () => {
    const as = database.as('app');
    await expect(as.query('delete from suppliers.beneficiary_registrations')).rejects.toThrow('permission denied');
    for (const column of ['org_id', 'id', 'created_at']) {
      // eslint-disable-next-line agentx/no-string-built-sql -- the column names are fixed just above
      await expect(as.query(`update suppliers.beneficiary_registrations set ${column} = ${column}`)).rejects.toThrow(
        'permission denied',
      );
    }
  });

  it('walls each organisation’s registrations off from the others (RLS)', async () => {
    const org = await organization();
    const other = await organization();
    const { id: supplierId } = await supplier(org);
    await started(org, supplierId);

    const seen = await withSignedStates(app, other, services(), (tx) =>
      tx.selectFrom(BENEFICIARY_REGISTRATIONS.table).select('id').execute(),
    );
    expect(seen).toEqual([]);
    await expect(
      withSignedStates(app, other, services(), (tx) =>
        tx
          .insertInto(BENEFICIARY_REGISTRATIONS.table)
          .values({
            org_id: org,
            id: ids.next(),
            supplier_id: supplierId,
            version_id: ids.next(),
            partner: 'fake_partner',
            route: 'hosted',
            started_by: ids.next(),
            status: 'STARTED',
            created_at: clock.now(),
          })
          .execute(),
      ),
    ).rejects.toThrow(/row-level security/);
  });
});

describe(`a version's payee reference (0033's payee_from_its_suppliers_registration, Postgres ${server.version})`, () => {
  it('is the registration’s, on the version it was started for; the change waits inert, the key unmoved, until confirmed', async () => {
    const org = await organization();
    const { id: supplierId, versionId: first } = await supplier(org);
    const registration = await started(org, supplierId);

    const { staged } = await tx2(org, supplierId, registration.id, { key: 'f'.repeat(64), keyVersion: 1 });

    expect(staged).toMatchObject({
      currentVersionId: first,
      pendingVersionId: registration.versionId,
      payeeKey: null,
      payeeKeyVersion: null,
    });
    expect(await supplierNow(org, supplierId)).toMatchObject({ supplier: staged });
    const done = await confirmed(org, supplierId, registration.id);
    expect(done).toMatchObject({
      currentVersionId: registration.versionId,
      pendingVersionId: null,
      payeeKey: 'f'.repeat(64),
      payeeKeyVersion: 1,
    });
    expect(await supplierNow(org, supplierId)).toMatchObject({ supplier: done });
    expect((await eventsAbout(org, supplierId)).map(({ action }) => action)).toEqual([
      'supplier.added',
      'supplier.payee_change_staged',
      'supplier.payee_change_confirmed',
    ]);
    expect(
      await withSignedStates(app, org, services(), (tx, states) =>
        versionOf(tx, states, { orgId: org, id: registration.versionId }, supplierId),
      ),
    ).toMatchObject({
      version: {
        version: 2,
        registrationId: registration.id,
        beneficiaryRef: `fake-beneficiary-${registration.id}`,
        payeeHint: 'AE…6026',
      },
    });
  });

  it('is carried forward from the version it follows, when a version comes with no registration', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { registration } = await withPayee(org, supplierId);
    const third = ids.next();
    // Its payee change confirmed and current, so the third follows it.
    const carried = await withSignedStates(app, org, services(), async (tx, states) => {
      const of = await supplierOf(tx, states, { orgId: org, id: supplierId }, 'change');
      if (of.outcome !== 'found') throw new Error('No supplier');
      const follows = await versionIn(tx, states, org, registration.versionId, supplierId);
      await addVersion(tx, states, keys, {
        orgId: org,
        id: third,
        supplierId,
        version: 3,
        supplier: { ...DETAILS, displayName: 'Gulf Office Supplies FZE' },
        enteredBy: ids.next(),
        enteredAt: clock.now(),
        actor: OPERATOR,
        of,
        follows,
      });
      return versionIn(tx, states, org, third, supplierId);
    });

    expect(carried).toMatchObject({
      registrationId: registration.id,
      beneficiaryRef: `fake-beneficiary-${registration.id}`,
    });
    // A version carrying the payee forward is no payee change of its own.
    await expect(
      withSignedStates(app, org, services(), async (tx, states) => {
        const of = await supplierOf(tx, states, { orgId: org, id: supplierId }, 'change');
        const found = await registrationOf(tx, states, { orgId: org, id: registration.id }, supplierId, 'share');
        if (of.outcome !== 'found' || found.outcome !== 'found') throw new Error('No supplier or registration');
        const current = await versionIn(tx, states, org, of.supplier.currentVersionId, supplierId);
        const change = { version: carried, registration: found.registration, current };
        return stagePayeeChange(tx, states, { orgId: org, id: supplierId }, of, change, { actor: OPERATOR });
      }),
    ).rejects.toBeInstanceOf(RangeError);
  });

  it('refuses a registration not REGISTERED, of another supplier, or started for another version, before any SQL runs', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { id: otherSupplier } = await supplier(org);
    const notYet = await started(org, supplierId);
    const ours = await started(org, supplierId);
    const theirs = await started(org, otherSupplier);
    await registeredBy(org, supplierId, ours.id);
    await registeredBy(org, otherSupplier, theirs.id);
    const madeWith = (registrationId: string, ofSupplier: string, versionId: string) =>
      withSignedStates(app, org, services(), async (tx, states) => {
        const of = await supplierOf(tx, states, { orgId: org, id: supplierId }, 'change');
        const found = await registrationOf(tx, states, { orgId: org, id: registrationId }, ofSupplier, 'share');
        if (of.outcome !== 'found' || found.outcome !== 'found') throw new Error('No supplier or registration');
        const follows = await versionOf(tx, states, { orgId: org, id: of.supplier.currentVersionId }, supplierId);
        if (follows.outcome !== 'found') throw new Error('No version');
        return addVersion(tx, states, keys, {
          orgId: org,
          id: versionId,
          supplierId,
          version: 2,
          supplier: DETAILS,
          enteredBy: ids.next(),
          enteredAt: clock.now(),
          actor: OPERATOR,
          of,
          follows: follows.version,
          registration: found.registration,
        });
      });

    await expect(madeWith(notYet.id, supplierId, notYet.versionId)).rejects.toBeInstanceOf(RangeError);
    await expect(madeWith(theirs.id, otherSupplier, theirs.versionId)).rejects.toBeInstanceOf(RangeError);
    await expect(madeWith(ours.id, supplierId, ids.next())).rejects.toBeInstanceOf(RangeError);
    await madeWith(ours.id, supplierId, ours.versionId.toUpperCase());
  });

  /** A version's row put in by the app past addVersion, naming `registrationId`: what the key refuses. */
  const plantVersion = (orgId: string, supplierId: string, registrationId: string | null) =>
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
          contacts_key_version: 1,
          phone_since: clock.now(),
          source_kind: 'registry',
          source_ref: 'planted',
          entered_by: ids.next(),
          entered_at: clock.now(),
          registration_id: registrationId,
          beneficiary_ref: registrationId === null ? null : 'fake-beneficiary-planted',
        })
        .execute(),
    );

  it('is refused past the app from another supplier’s registration, or another organisation’s; none at all is fine', async () => {
    const org = await organization();
    const other = await organization();
    const { id: supplierId } = await supplier(org);
    const { id: otherSupplier } = await supplier(org);
    const theirs = await started(org, otherSupplier);
    const { id: elsewhere } = await started(other, (await supplier(other)).id);

    await expect(plantVersion(org, supplierId, theirs.id)).rejects.toThrow(/payee_from_its_suppliers_registration/);
    await expect(plantVersion(org, supplierId, elsewhere)).rejects.toThrow(/payee_from_its_suppliers_registration/);
    await plantVersion(org, supplierId, null);
    await plantVersion(org, otherSupplier, theirs.id);
  });

  it('is never written onto a version already made (made_once)', async () => {
    const org = await organization();
    const { id: supplierId, versionId } = await supplier(org);
    const { id } = await started(org, supplierId);
    await registeredBy(org, supplierId, id);

    await expect(
      withSignedStates(app, org, services(), (tx) =>
        tx
          .updateTable(SUPPLIER_VERSIONS.table)
          .set({ registration_id: id, beneficiary_ref: 'fake-beneficiary-late', payee_hint: 'AE…6026' })
          .where('id', '=', versionId)
          .execute(),
      ),
    ).rejects.toThrow(/made once/);
  });
});

describe(`one supplier per payee key (0033's one_supplier_a_payee, Postgres ${server.version})`, () => {
  it('refuses a second supplier the key another holds at confirmation, a suspended one too: isPayeeTaken', async () => {
    const org = await organization();
    const { id: holder } = await supplier(org);
    const { id: second } = await supplier(org);
    const { id: third } = await supplier(org);
    await withPayee(org, holder);

    // Staged, it waits; confirmed, it is refused, and still waits.
    const refused = await refusalOf(withPayee(org, second));
    expect(isPayeeTaken(refused)).toBe(true);
    expect(await supplierNow(org, second)).toMatchObject({ supplier: { payeeKey: null } });
    await onSupplier(org, holder, (tx, states, found) =>
      suspendSupplier(tx, states, { orgId: org, id: holder }, found, { actor: OPERATOR }),
    );
    expect(isPayeeTaken(await refusalOf(withPayee(org, third)))).toBe(true);
  });

  it('keeps the key on the supplier paying it while a change of its payee waits, so no other takes it meanwhile', async () => {
    const org = await organization();
    const { id: holder } = await supplier(org);
    const { id: other } = await supplier(org);
    await withPayee(org, holder);
    const moving = await started(org, holder);
    await tx2(org, holder, moving.id, { key: 'fake-payee-2', keyVersion: null });

    expect(await supplierNow(org, holder)).toMatchObject({
      supplier: { pendingVersionId: moving.versionId, payeeKey: 'fake-payee-1' },
    });
    const taking = await started(org, other);
    await tx2(org, other, taking.id);
    expect(isPayeeTaken(await refusalOf(confirmed(org, other, taking.id)))).toBe(true);
    // Confirmed, the key moves with the version it pays, and the old one is free.
    await confirmed(org, holder, moving.id);
    expect(await supplierNow(org, holder)).toMatchObject({
      supplier: { currentVersionId: moving.versionId, pendingVersionId: null, payeeKey: 'fake-payee-2' },
    });
    expect(await confirmed(org, other, taking.id)).toMatchObject({ payeeKey: 'fake-payee-1' });
  });

  it('lets many suppliers hold no key, and another organisation hold the same key', async () => {
    const org = await organization();
    const other = await organization();
    const { id: holder } = await supplier(org);
    await supplier(org);
    await supplier(org);
    await withPayee(org, holder);
    const { id: theirs } = await supplier(other);

    await withPayee(other, theirs);
    expect(await withSignedStates(app, org, services(), (tx) => supplierWithPayeeKey(tx, org, 'fake-payee-1'))).toBe(
      holder,
    );
    expect(
      await withSignedStates(app, org, services(), (tx) => supplierWithPayeeKey(tx, org, 'fake-payee-2')),
    ).toBeNull();
    expect(
      await withSignedStates(app, other, services(), (tx) => supplierWithPayeeKey(tx, other, 'fake-payee-1')),
    ).toBe(theirs);
  });

  it('takes no other refusal for it', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { versionId } = await started(org, supplierId);
    const twice = await refusalOf(started(org, supplierId, { versionId }));

    expect(twice).toMatchObject({ code: '23505', constraint: 'one_registration_a_version' });
    expect(isPayeeTaken(twice)).toBe(false);
    expect(isPayeeTaken(null)).toBe(false);
    expect(isPayeeTaken('one_supplier_a_payee')).toBe(false);
    expect(isPayeeTaken({ code: '23514', constraint: 'one_supplier_a_payee' })).toBe(false);
  });
});

describe(`a payee change put in waiting, then confirmed (stagePayeeChange, confirmPayeeChange, Postgres ${server.version})`, () => {
  /**
   * The change with one thing wrong each: a version not made from that
   * registration, REGISTERED, of this supplier, or no newer than the one paid now.
   */
  const notMadeFromIt = ({ version, registration, current }: PayeeChange): PayeeChange[] => [
    { version, registration: { ...registration, status: 'STARTED' }, current },
    { version, registration: { ...registration, supplierId: ids.next() }, current },
    { version: { ...version, supplierId: ids.next() }, registration, current },
    { version: { ...version, id: ids.next() }, registration, current },
    { version: { ...version, registrationId: ids.next() }, registration, current },
    { version, registration, current: { ...current, id: ids.next() } },
    { version, registration, current: { ...current, version: version.version } },
  ];

  /** A registration of the supplier started, and its version made (madeIn), nothing staged: the change. */
  const madeFor = async (
    orgId: string,
    supplierId: string,
    payee: PayeeKey = PARTNER_KEY,
    number: number | null = null,
  ) => {
    const { id } = await started(orgId, supplierId);
    return withSignedStates(app, orgId, services(), async (tx, states) => {
      const { change } = await madeIn(tx, states, orgId, supplierId, id, payee, number);
      return change;
    });
  };

  /** The supplier read for change (as it stands, but for `as`), then `step` taken with `change`; a confirmation's cooling-off ending `until`. */
  const taking =
    (step: typeof confirmPayeeChange) =>
    (orgId: string, supplierId: string, change: PayeeChange, as: Partial<SupplierRecord> = {}, until = COOLED_OFF) =>
      onSupplier(orgId, supplierId, (tx, states, of) =>
        step(tx, states, { orgId, id: supplierId }, { ...of, supplier: { ...of.supplier, ...as } }, change, {
          actor: OPERATOR,
          coolingOffUntil: until,
        }),
      );
  const staging = taking(stagePayeeChange);
  const confirming = taking(confirmPayeeChange);

  it('refuses to stage a change not made from its registration, or a second one, before any SQL runs', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const change = await madeFor(org, supplierId);

    for (const wrong of notMadeFromIt(change)) {
      await expect(staging(org, supplierId, wrong)).rejects.toBeInstanceOf(RangeError);
    }
    expect((await eventsAbout(org, supplierId)).map(({ action }) => action)).toEqual(['supplier.added']);
    // The change itself is staged, so the checks are not simply always a refusal; then a second waits for none.
    await staging(org, supplierId, change);
    await expect(staging(org, supplierId, change)).rejects.toBeInstanceOf(RangeError);
    expect(await supplierNow(org, supplierId)).toMatchObject({
      supplier: { pendingVersionId: change.version.id, payeeKey: null },
    });
  });

  it('withdraws only the change waiting, its payee untouched, so another may be staged; none waiting is refused', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const first = await madeFor(org, supplierId);
    const withdrawing = (pendingVersionId: string) =>
      onSupplier(org, supplierId, (tx, states, found) =>
        withdrawPayeeChange(tx, states, { orgId: org, id: supplierId }, found, pendingVersionId, { actor: OPERATOR }),
      );

    await expect(withdrawing(first.version.id)).rejects.toBeInstanceOf(RangeError);
    await staging(org, supplierId, first);
    await expect(withdrawing(ids.next())).rejects.toBeInstanceOf(RangeError);
    expect(await withdrawing(first.version.id.toUpperCase())).toMatchObject({ pendingVersionId: null, payeeKey: null });
    expect((await eventsAbout(org, supplierId)).map(({ action }) => action)).toEqual([
      'supplier.added',
      'supplier.payee_change_staged',
      'supplier.payee_change_withdrawn',
    ]);
    // Stuck no more: another change is staged and confirmed.
    const second = await madeFor(org, supplierId, PARTNER_KEY, first.version.version + 1);
    await staging(org, supplierId, second);
    expect(await confirming(org, supplierId, second)).toMatchObject({ currentVersionId: second.version.id });
    // The withdrawn change is done with: staged again over the newer one it would roll back, it is refused.
    await expect(staging(org, supplierId, { ...first, current: second.version })).rejects.toBeInstanceOf(RangeError);
    // A withdrawal leaves the payee paid now as it is.
    const third = await madeFor(org, supplierId, PARTNER_KEY, second.version.version + 1);
    await staging(org, supplierId, third);
    expect(await withdrawing(third.version.id)).toMatchObject({
      currentVersionId: second.version.id,
      payeeKey: 'fake-payee-1',
      payeeKeyVersion: null,
    });
  });

  it('refuses to stage a change for a VERIFIED supplier; a suspended one stages and confirms, and comes back UNVERIFIED', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const key = { orgId: org, id: supplierId };
    await onSupplier(org, supplierId, (tx, states, found) =>
      verifySupplier(tx, states, key, found, { verifiedBy: ids.next(), actor: OPERATOR }),
    );
    const change = await madeFor(org, supplierId);

    await expect(staging(org, supplierId, change)).rejects.toBeInstanceOf(RangeError);
    await onSupplier(org, supplierId, (tx, states, found) =>
      suspendSupplier(tx, states, key, found, { actor: OPERATOR }),
    );
    await staging(org, supplierId, change);
    expect(await confirming(org, supplierId, change)).toMatchObject({
      status: 'SUSPENDED',
      currentVersionId: change.version.id,
      payeeKey: 'fake-payee-1',
    });
    const back = await onSupplier(org, supplierId, async (tx, states, found) => {
      await reactivateSupplier(tx, states, key, found, { actor: OPERATOR });
      return supplierOf(tx, states, key, 'share');
    });
    expect(back).toMatchObject({
      outcome: 'found',
      supplier: { status: 'UNVERIFIED', verifiedBy: null, verifiedVersionId: null },
    });
  });

  it('refuses to confirm a change not the one waiting, not made from its registration, or for a VERIFIED supplier, before any SQL runs', async () => {
    const org = await organization();
    const { id: supplierId, versionId: first } = await supplier(org);
    const change = await madeFor(org, supplierId);
    const elsewhere = ids.next();
    const another = {
      version: { ...change.version, id: elsewhere },
      registration: { ...change.registration, versionId: elsewhere },
      current: change.current,
    };

    // Nothing waiting yet.
    await expect(confirming(org, supplierId, change)).rejects.toBeInstanceOf(RangeError);
    await staging(org, supplierId, change);
    for (const wrong of [another, ...notMadeFromIt(change)]) {
      await expect(confirming(org, supplierId, wrong)).rejects.toBeInstanceOf(RangeError);
    }
    await expect(confirming(org, supplierId, change, { status: 'VERIFIED' })).rejects.toBeInstanceOf(RangeError);
    await expect(confirming(org, supplierId, change, {}, new Date(Number.NaN))).rejects.toBeInstanceOf(RangeError);
    expect(await supplierNow(org, supplierId)).toMatchObject({
      supplier: { currentVersionId: first, pendingVersionId: change.version.id, payeeKey: null, coolingOffUntil: null },
    });
    // Its cooling-off starts with the confirmation, signed with the rest.
    expect(await confirming(org, supplierId, change)).toMatchObject({
      currentVersionId: change.version.id,
      coolingOffUntil: COOLED_OFF,
    });
    expect(await supplierNow(org, supplierId)).toMatchObject({ supplier: { coolingOffUntil: COOLED_OFF } });
  });

  it('never waits behind the KEY SHARE a version’s foreign key holds on its supplier: the payee key is no key column', async () => {
    const org = await organization();
    const { id: supplierId } = await supplier(org);
    const { id } = await started(org, supplierId);
    // A transaction part-way through adding a row that points at the supplier, as a version's or a registration's key does.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select 1 from suppliers.suppliers where id = $1 for key share', [supplierId]);
      // The lock really is held: a whole-row lock can't be had beside it.
      const other = await database.connect('admin');
      try {
        await expect(
          other.query('select 1 from suppliers.suppliers where id = $1 for update nowait', [supplierId]),
        ).rejects.toThrow(/could not obtain lock/);
      } finally {
        await other.end();
      }

      await within(10_000, tx2(org, supplierId, id), 'the payee change staged');
      const done = await within(10_000, confirmed(org, supplierId, id), 'the payee change confirmed');
      expect(done.payeeKey).toBe('fake-payee-1');
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });

  it('confirms one at a time under the organisation’s lock for payee changes: the second, queued behind it, finds the key taken', async () => {
    const org = await organization();
    const { id: first } = await supplier(org);
    const { id: second } = await supplier(org);
    const firstStarted = await started(org, first);
    const secondStarted = await started(org, second);
    await tx2(org, first, firstStarted.id);
    await tx2(org, second, secondStarted.id);
    const confirmedUnderLock = (supplierId: string, registrationId: string, pause?: () => Promise<void>) =>
      withSignedStates(app, org, services(), async (tx, states) => {
        await onePayeeChangeAtATime(tx, org);
        const done = await confirmIn(tx, states, org, supplierId, registrationId);
        await pause?.();
        return done;
      });
    // The first confirmation, part-way: its lock taken and the key recorded, not yet committed.
    let reached = (): void => undefined;
    let release = (): void => undefined;
    const atPause = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const firstConfirmed = confirmedUnderLock(first, firstStarted.id, () => {
      reached();
      return held;
    });
    await within(10_000, atPause, 'the first confirmation');
    const secondRefused = refusalOf(within(20_000, confirmedUnderLock(second, secondStarted.id), 'the second'));
    await waitUntilQueued(database.as('admin'), 1);
    // Queued on the lock, not on the index: it hasn't written yet.
    expect(
      await database.as('admin').query("select 1 from pg_catalog.pg_locks where locktype = 'advisory' and not granted"),
    ).toHaveLength(1);
    release();

    expect(await firstConfirmed).toMatchObject({ payeeKey: 'fake-payee-1' });
    expect(isPayeeTaken(await secondRefused)).toBe(true);
  });
});

describe(`the day's budget of payee registrations (E2-1b, Postgres ${server.version})`, () => {
  it('is 100 an organisation (partner, S71)', () => {
    expect(MOST_PAYEE_REGISTRATIONS_A_DAY).toBe(100);
  });

  it('counts the organisation’s own, started after the time given and not at it', async () => {
    const org = await organization();
    const other = await organization();
    const { id: supplierId } = await supplier(org);
    const since = clock.now();
    await started(org, supplierId);
    clock.advanceBy(1);
    await started(org, supplierId);
    await started(org, supplierId);
    await started(other, (await supplier(other)).id);
    const count = (at: Date) => withSignedStates(app, org, services(), (tx) => registrationsStartedSince(tx, org, at));

    expect(await count(new Date(since.getTime() - 1))).toBe(3);
    expect(await count(since)).toBe(2);
    expect(await count(clock.now())).toBe(0);
    clock.advanceBy(HOUR_MS);
  });

  it('is counted under the organisation’s own lock for payee changes, which another organisation doesn’t wait for', async () => {
    const org = await organization();
    const other = await organization();
    const { id: supplierId } = await supplier(org);
    const { id: theirs } = await supplier(other);
    const startedUnderLock = (orgId: string, ofSupplier: string) =>
      withSignedStates(app, orgId, services(), async (tx, states) => {
        await onePayeeChangeAtATime(tx, orgId.toUpperCase());
        const since = new Date(clock.now().getTime() - DAY_MS);
        const before = await registrationsStartedSince(tx, orgId, since);
        await startRegistration(tx, states, {
          orgId,
          id: ids.next(),
          supplierId: ofSupplier,
          versionId: ids.next(),
          partner: 'fake_partner',
          route: 'hosted',
          startedBy: ids.next(),
          createdAt: clock.now(),
          actor: OPERATOR,
        });
        return before;
      });
    // Another start of the organisation's, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('payees', org));
      const starting = within(20_000, startedUnderLock(org, supplierId), 'the start');
      await waitUntilQueued(database.as('admin'), 1);
      // Another organisation's lock is its own.
      expect(await within(10_000, startedUnderLock(other, theirs), 'the other start')).toBe(0);
      await holder.query('commit');

      expect(await starting).toBe(0);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe(`the module's description of the table (E2-1b, Postgres ${server.version})`, () => {
  it('seals every column but its keys, creation time and signed-state columns', async () => {
    const columns = await database.as('owner').query<{ name: string }>(
      `select attname::text as name from pg_catalog.pg_attribute
          where attrelid = 'suppliers.beneficiary_registrations'::regclass and attnum > 0 and not attisdropped
          order by attnum`,
    );
    const unsealed = ['org_id', 'id', 'created_at', 'state_version', 'state_event_id'];

    expect(new Set(BENEFICIARY_REGISTRATIONS.fields.map(({ column }) => column))).toEqual(
      new Set(columns.map(({ name }) => name).filter((name) => !unsealed.includes(name))),
    );
  });
});
