// E3-2b (ADR-012 §1: "supplier contact changes are sensitive too: step-up,
// notification to everyone, and the supplier becomes unverified"; SEC-PAY-07,
// SEC-HA-12): a supplier's details changed by an admin with a passkey,
// through the use case the routes call, on the real migrated schema, as the
// app role: a new version made current with its payee kept, the supplier
// back to UNVERIFIED, everyone told; and verifying it again then holds to
// the new phone's 30 days and keeps its enterer apart (E3-2a). The routes'
// answers are suppliers.test.ts.
import { createHash } from 'node:crypto';

import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  addMembership,
  createSessions,
  createStepUpChallenges,
  type IdentityTables,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOutbox, type NotificationsTables } from '@agentx/core/modules/notifications';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createFakeRail, type FakeRail, SANDBOX_ACCOUNTS } from '@agentx/core/modules/providers';
import {
  addSupplier,
  addVersion,
  nextVersionNumber,
  PAYEE_COOLING_OFF_MS,
  type SupplierDetails,
  supplierDetails,
  supplierOf,
  type SuppliersTables,
  versionOf,
} from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createSupplierPayeeChanges,
  PAYEE_APPROVE_CONFIRM_OPERATION,
  PAYEE_APPROVE_OPERATION,
  type SupplierPayeeChanges,
} from './supplier-payee-changes.ts';
import {
  createSupplierPayees,
  PAYEE_CHECK_OPERATION,
  PAYEE_START_OPERATION,
  type SupplierPayees,
} from './supplier-payees.ts';
import {
  createSupplierChanges,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  type SupplierChanges,
  SUSPEND_OPERATION,
} from './supplier-changes.ts';
import { ADD_OPERATION, createSupplierRegistry, type SupplierRegistry } from './supplier-registry.ts';
import {
  createSupplierDetailsChanges,
  DETAILS_CONFIRM_OPERATION,
  DETAILS_OPERATION,
  MOST_CHANGES_A_DAY,
  type SupplierDetailsChanges,
} from './supplier-details.ts';
import {
  createSupplierVerifications,
  type SupplierVerifications,
  VERIFY_CONFIRM_OPERATION,
  VERIFY_OPERATION,
} from './supplier-verifications.ts';
import type { SessionMember, SupplierChangeWrite } from './supplier-work.ts';

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
const ids = new SequentialIds(0xe32b_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000ae';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const DAY_MS = 86_400_000;

const [JASMINE, OTHER] = SANDBOX_ACCOUNTS;
type Account = (typeof SANDBOX_ACCOUNTS)[number] | undefined;
const ibanOf = (account: Account): string =>
  account?.AccountIdentifiers.find((each) => each.SchemeName === 'IBAN')?.Identification ?? '';
const holderOf = (account: Account): string => account?.AccountHolderName ?? '';
const HOLDER = holderOf(JASMINE);
const DETAILS: SupplierDetails = {
  displayName: 'Jasmine AI FZ-LLC',
  contacts: { phone: '+971501234567', email: null, tradeLicence: null },
  source: { kind: 'registry', ref: 'DED-123456' },
};

let clock: FixedClock;
let rail: FakeRail;
let registry: SupplierRegistry;
let payees: SupplierPayees;
let payeeChanges: SupplierPayeeChanges;
let verifications: SupplierVerifications;
let detailsChanges: SupplierDetailsChanges;
let changes: SupplierChanges;
const challenges = () => createStepUpChallenges({ ids, clock });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

interface Person {
  readonly orgId: string;
  readonly userId: string;
  readonly membershipId: string;
}

let people = 0;

/** A person with a membership in the organisation from now, added by the operator. */
async function member(org: string, role: Role): Promise<Person> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `supplier-details-${String(people)}` },
    { ids, clock },
  );
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, membershipId };
}

/** The person signed in now, with a passkey. */
async function signedIn(who: Person): Promise<SessionMember> {
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, who.userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  return { orgId: who.orgId, userId: who.userId, sessionId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

let keysUsed = 0;
const keyed = (who: SessionMember, operation: string, key?: string): IdempotentRequest => {
  keysUsed += 1;
  return {
    orgId: who.orgId,
    client: { kind: 'user', id: who.userId },
    operation,
    key: key ?? `key-${String(keysUsed)}`,
    payload: '{}',
  };
};

/** The member signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (who: SessionMember, challengeId: string, amr: readonly string[] = PASSKEY) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const askedFor = (write: SupplierChangeWrite): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

/** A supplier added by the admin, its bank details registered, checked and confirmed with their passkey: its 24 h cooling-off begun. */
async function payable(adminPerson: Person): Promise<string> {
  const admin = await signedIn(adminPerson);
  const added = await registry.add(admin, keyed(admin, ADD_OPERATION), DETAILS, CORRELATION);
  if (added.outcome !== 'added') throw new Error(`not added: ${JSON.stringify(added)}`);
  const supplierId = added.supplier.id;
  const started = await payees.start(admin, keyed(admin, PAYEE_START_OPERATION), supplierId, CORRELATION);
  if (started.outcome !== 'started') throw new Error(`not started: ${JSON.stringify(started)}`);
  await rail.bank.fillForm(admin.orgId, started.form?.url ?? '', { name: HOLDER, iban: ibanOf(JASMINE) });
  const checked = await payees.check(
    admin,
    keyed(admin, PAYEE_CHECK_OPERATION),
    supplierId,
    started.registration.id,
    CORRELATION,
  );
  if (checked.outcome !== 'checked') throw new Error(`not checked: ${JSON.stringify(checked)}`);
  const challengeId = askedFor(
    await payeeChanges.approve(admin, keyed(admin, PAYEE_APPROVE_OPERATION), supplierId, CORRELATION),
  );
  await stepUp(admin, challengeId);
  const confirmed = await payeeChanges.approveConfirm(
    admin,
    keyed(admin, PAYEE_APPROVE_CONFIRM_OPERATION),
    supplierId,
    challengeId,
    CORRELATION,
  );
  if (confirmed.outcome !== 'changed') throw new Error(`not confirmed: ${JSON.stringify(confirmed)}`);
  return supplierId;
}

const ask = (who: SessionMember, id: string) =>
  verifications.verify(who, keyed(who, VERIFY_OPERATION), id, { note: null }, CORRELATION);

/** Asked, stepped up with a passkey, then confirmed (E3-2a). */
async function verified(person: Person, id: string) {
  const who = await signedIn(person);
  const challengeId = askedFor(await ask(who, id));
  await stepUp(who, challengeId);
  return verifications.verifyConfirm(
    who,
    keyed(who, VERIFY_CONFIRM_OPERATION),
    id,
    { stepUpChallengeId: challengeId, note: null },
    CORRELATION,
  );
}

/** The supplier as its signed state says. */
const supplierNow = (org: string, id: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await supplierOf(tx, states, { orgId: org, id }, 'share');
    if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
    return read.supplier;
  });

const refusedWith = (code: string, status: number) =>
  expect.objectContaining({ outcome: 'refused', code, status }) as unknown;

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
  rail = createFakeRail({ clock, ids });
  const services = { database: app, keys, ids, clock, logger: loggerFor(new LogCapture()) };
  registry = createSupplierRegistry(services);
  payees = createSupplierPayees({ ...services, rail, partner: 'fake' });
  const outbox = createOutbox({ ids, clock });
  payeeChanges = createSupplierPayeeChanges({ ...services, challenges: challenges(), outbox });
  verifications = createSupplierVerifications({ ...services, challenges: challenges(), outbox });
  detailsChanges = createSupplierDetailsChanges({ ...services, challenges: challenges(), outbox });
  changes = createSupplierChanges({ ...services, challenges: challenges(), outbox });
});

/** An organisation whose admin Alice and approver Bob have been members 15 days. */
async function team() {
  const org = await organization();
  const alice = await member(org, 'admin');
  const bob = await member(org, 'approver');
  clock.advanceBy(15 * DAY_MS);
  return { org, alice, bob };
}

/** The team, with a supplier Alice made payable, cooled off since. */
async function established() {
  const { org, alice, bob } = await team();
  const supplierId = await payable(alice);
  clock.advanceBy(PAYEE_COOLING_OFF_MS);
  return { org, alice, bob, supplierId };
}

const NEW_PHONE: SupplierDetails = { ...DETAILS, contacts: { ...DETAILS.contacts, phone: '+971509876543' } };

/** Asked with `details`, stepped up with `amr`, then confirmed with `confirmDetails`. */
async function changed(
  person: Person,
  id: string,
  details: SupplierDetails,
  { confirmDetails = details, amr = PASSKEY }: { confirmDetails?: SupplierDetails; amr?: readonly string[] } = {},
) {
  const who = await signedIn(person);
  const asked = await detailsChanges.change(who, keyed(who, DETAILS_OPERATION), id, details, CORRELATION);
  if (asked.outcome !== 'asked') return asked;
  await stepUp(who, asked.stepUpChallengeId, amr);
  return detailsChanges.changeConfirm(
    who,
    keyed(who, DETAILS_CONFIRM_OPERATION),
    id,
    { details: confirmDetails, stepUpChallengeId: asked.stepUpChallengeId },
    CORRELATION,
  );
}

/** The organisation's notices of a details change in the outbox. */
const changedNotices = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['kind', 'to_contacts', 'about_id'])
      .where('org_id', '=', org)
      .where('kind', '=', 'supplier_details_changed')
      .orderBy('to_contacts')
      .execute(),
  );

describe(`changing a supplier's details, with an admin's passkey (E3-2b, Postgres ${server.version})`, () => {
  it('SEC-PAY-07 makes the new details current, its payee kept, the supplier UNVERIFIED, and tells everyone', async () => {
    const { org, alice, bob, supplierId } = await established();
    expect(await verified(bob, supplierId)).toMatchObject({ supplier: { status: 'VERIFIED' } });
    const before = await supplierNow(org, supplierId);

    const answer = await changed(alice, supplierId, NEW_PHONE);

    expect(answer).toMatchObject({
      outcome: 'changed',
      supplier: { status: 'UNVERIFIED', verifiedBy: null, verifiedVersionId: null, payeeKey: before.payeeKey },
      contacts: { phone: '+971509876543' },
      version: { enteredBy: alice.membershipId, phoneSince: clock.now() },
    });
    if (answer.outcome !== 'changed') return;
    expect(answer.supplier.currentVersionId).not.toBe(before.currentVersionId);
    expect(answer.version.beneficiaryRef).not.toBeNull();
    expect(await changedNotices(org)).toEqual([
      { kind: 'supplier_details_changed', to_contacts: false, about_id: supplierId },
      { kind: 'supplier_details_changed', to_contacts: true, about_id: supplierId },
    ]);
  });

  it('then holds verifying it to the new phone’s 30 days, and keeps whoever changed it apart (E3-2a)', async () => {
    const { org, alice, bob, supplierId } = await established();
    const carol = await member(org, 'approver');
    clock.advanceBy(15 * DAY_MS);
    await changed(alice, supplierId, NEW_PHONE);

    expect(await ask(await signedIn(bob), supplierId)).toEqual(refusedWith('SUPPLIER_PHONE_TOO_NEW', 409));
    clock.advanceBy(30 * DAY_MS);
    expect(await ask(await signedIn(alice), supplierId)).toEqual(refusedWith('VERIFIER_ENTERED_DETAILS', 403));
    expect(await verified(carol, supplierId)).toMatchObject({ supplier: { status: 'VERIFIED' } });
  });

  it('keeps the phone’s start when only another field changes', async () => {
    const { alice, supplierId } = await established();
    const added = clock.now().getTime() - PAYEE_COOLING_OFF_MS;

    const answer = await changed(alice, supplierId, { ...DETAILS, displayName: 'Jasmine AI Trading FZ-LLC' });

    expect(answer).toMatchObject({ outcome: 'changed', version: { displayName: 'Jasmine AI Trading FZ-LLC' } });
    if (answer.outcome !== 'changed') return;
    expect(answer.version.phoneSince.getTime()).toBeLessThanOrEqual(added);
  });

  it('refuses details that change nothing, a change waiting, and a finance approver', async () => {
    const { org, alice, bob, supplierId } = await established();
    const admin = await signedIn(alice);

    expect(await changed(alice, supplierId, DETAILS)).toEqual(refusedWith('SUPPLIER_DETAILS_UNCHANGED', 409));
    expect(await changed(bob, supplierId, NEW_PHONE)).toEqual(refusedWith('FORBIDDEN', 403));
    const started = await payees.start(admin, keyed(admin, PAYEE_START_OPERATION), supplierId, CORRELATION);
    if (started.outcome !== 'started') throw new Error('not started');
    await rail.bank.fillForm(org, started.form?.url ?? '', { name: HOLDER, iban: ibanOf(OTHER) });
    await payees.check(admin, keyed(admin, PAYEE_CHECK_OPERATION), supplierId, started.registration.id, CORRELATION);
    expect(await changed(alice, supplierId, NEW_PHONE)).toEqual(refusedWith('SUPPLIER_CHANGE_WAITING', 409));
  });

  it('SEC-HA-12 refuses a step-up with an app code, and binds it to the details asked for', async () => {
    const { org, alice, supplierId } = await established();
    const before = await supplierNow(org, supplierId);

    expect(await changed(alice, supplierId, NEW_PHONE, { amr: APP_CODE })).toEqual(refusedWith('STEP_UP_FAILED', 403));
    const other = { ...NEW_PHONE, contacts: { ...NEW_PHONE.contacts, phone: '+971501111111' } };
    expect(await changed(alice, supplierId, NEW_PHONE, { confirmDetails: other })).toEqual(
      refusedWith('STEP_UP_FAILED', 403),
    );
    expect((await supplierNow(org, supplierId)).currentVersionId).toBe(before.currentVersionId);
    expect(await changedNotices(org)).toEqual([]);
  });

  it('keeps a suspended supplier suspended, and it comes back UNVERIFIED', async () => {
    const { org, alice, bob, supplierId } = await established();
    await verified(bob, supplierId);
    const admin = await signedIn(alice);
    await changes.suspend(admin, keyed(admin, SUSPEND_OPERATION), supplierId, CORRELATION);

    expect(await changed(alice, supplierId, NEW_PHONE)).toMatchObject({ supplier: { status: 'SUSPENDED' } });
    const asked = await changes.reactivate(admin, keyed(admin, REACTIVATE_OPERATION), supplierId, CORRELATION);
    if (asked.outcome !== 'asked') throw new Error('not asked');
    await stepUp(admin, asked.stepUpChallengeId);
    expect(
      await changes.reactivateConfirm(
        admin,
        keyed(admin, REACTIVATE_CONFIRM_OPERATION),
        supplierId,
        asked.stepUpChallengeId,
        CORRELATION,
      ),
    ).toMatchObject({ supplier: { status: 'UNVERIFIED', verifiedBy: null } });
    expect((await supplierNow(org, supplierId)).status).toBe('UNVERIFIED');
  });

  it('refuses SUPPLIER_CHANGES_SPENT past the day’s changes, never counting suppliers added, and takes them a day on', async () => {
    const { org, alice, supplierId } = await established();
    const added = async (count: number) =>
      withSignedStates(app, org, quiet(), async (tx, states) => {
        for (let at = 0; at < count; at += 1) {
          await addSupplier(tx, states, keys, {
            orgId: org,
            id: ids.next(),
            versionId: ids.next(),
            supplier: { ...DETAILS, displayName: `Filler ${String(at)} LLC` },
            enteredBy: alice.membershipId,
            createdAt: clock.now(),
            actor: OPERATOR,
          });
        }
      });
    // A busy day of suppliers added counts for nothing (the review's medium).
    await added(MOST_CHANGES_A_DAY);
    expect(await changed(alice, supplierId, NEW_PHONE)).toMatchObject({ outcome: 'changed' });
    // The day's changes entered straight, as payee registrations would: later versions, up to the budget.
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      const found = await supplierOf(tx, states, { orgId: org, id: supplierId }, 'change');
      if (found.outcome !== 'found') throw new Error('not found');
      const follows = await versionOf(tx, states, { orgId: org, id: found.supplier.currentVersionId }, supplierId);
      if (follows.outcome !== 'found') throw new Error('no version');
      for (let at = 0; at < MOST_CHANGES_A_DAY - 1; at += 1) {
        await addVersion(tx, states, keys, {
          orgId: org,
          id: ids.next(),
          supplierId,
          version: await nextVersionNumber(tx, org, supplierId),
          supplier: NEW_PHONE,
          enteredBy: alice.membershipId,
          enteredAt: clock.now(),
          actor: OPERATOR,
          of: found,
          follows: follows.version,
        });
      }
    });

    expect(await changed(alice, supplierId, DETAILS)).toEqual(refusedWith('SUPPLIER_CHANGES_SPENT', 409));
    clock.advanceBy(DAY_MS);
    expect(await changed(alice, supplierId, DETAILS)).toMatchObject({ outcome: 'changed' });
  }, 120_000);

  it('restarts the phone’s start at each change of it, back to an earlier phone too (the review)', async () => {
    const { alice, supplierId } = await established();
    const changedAt = async (details: SupplierDetails) => {
      clock.advanceBy(DAY_MS);
      const answer = await changed(alice, supplierId, details);
      if (answer.outcome !== 'changed') throw new Error(`not changed: ${JSON.stringify(answer)}`);
      return answer.version.phoneSince.getTime();
    };

    expect(await changedAt(NEW_PHONE)).toBe(clock.now().getTime());
    expect(await changedAt(DETAILS)).toBe(clock.now().getTime());
  });

  it('takes an email differing only in its letters’ case as unchanged', async () => {
    const { alice, supplierId } = await established();
    const withEmail = { ...DETAILS, contacts: { ...DETAILS.contacts, email: 'accounts@jasmine.example' } };
    await changed(alice, supplierId, withEmail);
    const shouted = { ...DETAILS, contacts: { ...DETAILS.contacts, email: 'Accounts@JASMINE.example' } };

    expect(await changed(alice, supplierId, supplierDetails(shouted))).toEqual(
      refusedWith('SUPPLIER_DETAILS_UNCHANGED', 409),
    );
  });
});
