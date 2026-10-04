// E2-2b (ADR-014 §3 step 4, ADR-012 §1, ADR-003 §9, SEC-PAY-03, SEC-HA-12):
// the payee change E2-2a left waiting, confirmed by the admin who registered
// it with a passkey step-up, or withdrawn, through the use case the routes
// call, on the real migrated schema, as the app role, with the fake partner
// in memory. Only the confirmation makes the change current, starts its
// cooling-off and tells everyone. The routes' answers are suppliers.test.ts;
// who the sender tells, sender.db.test.ts.
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
  PAYEE_COOLING_OFF_MS,
  SUPPLIER_VERSIONS,
  type SupplierDetails,
  supplierOf,
  type SuppliersTables,
  suspendSupplier,
} from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createSupplierPayeeChanges,
  PAYEE_APPROVE_CONFIRM_OPERATION,
  PAYEE_APPROVE_OPERATION,
  PAYEE_WITHDRAW_OPERATION,
  type SupplierPayeeChanges,
} from './supplier-payee-changes.ts';
import {
  createSupplierPayees,
  PAYEE_CHECK_OPERATION,
  PAYEE_START_OPERATION,
  type PayeeWrite,
  type SupplierPayees,
} from './supplier-payees.ts';
import { ADD_OPERATION, createSupplierRegistry, type SupplierRegistry } from './supplier-registry.ts';
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
const ids = new SequentialIds(0xe22b_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000ae';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

const DETAILS: SupplierDetails = {
  displayName: 'Jasmine AI FZ-LLC',
  contacts: { phone: '+971501234567', email: null, tradeLicence: null },
  source: { kind: 'registry', ref: 'DED-123456' },
};

const [JASMINE, OTHER] = SANDBOX_ACCOUNTS;
const ibanOf = (account: (typeof SANDBOX_ACCOUNTS)[number] | undefined): string =>
  account?.AccountIdentifiers.find((each) => each.SchemeName === 'IBAN')?.Identification ?? '';

let clock: FixedClock;
let rail: FakeRail;
let registry: SupplierRegistry;
let payees: SupplierPayees;
let changes: SupplierPayeeChanges;
const challenges = () => createStepUpChallenges({ ids, clock });

const quiet = () => ({ keys, ids, logger: testLogger() });

let people = 0;

/** A person with a passkey session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<SessionMember & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `supplier-payee-changes-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
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
const keyed = (who: SessionMember, operation: string, key = nextKey()): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload: '{}',
});

/** A supplier added by the admin, as E1-2 adds it. */
async function added(admin: SessionMember): Promise<string> {
  const write = await registry.add(admin, keyed(admin, ADD_OPERATION), DETAILS, CORRELATION);
  if (write.outcome !== 'added') throw new Error(`not added: ${JSON.stringify(write)}`);
  return write.supplier.id;
}

const answered = (write: PayeeWrite, outcome: 'started' | 'checked') => {
  if (write.outcome !== outcome) throw new Error(`not ${outcome}: ${JSON.stringify(write)}`);
  return write;
};

/** A registration started by the admin, its form filled in with the account, and checked: the change waiting (E2-2a). */
async function waiting(admin: SessionMember, supplierId: string, iban = ibanOf(JASMINE)) {
  const started = answered(
    await payees.start(admin, keyed(admin, PAYEE_START_OPERATION), supplierId, CORRELATION),
    'started',
  );
  await rail.bank.fillForm(admin.orgId, started.form?.url ?? '', { name: 'Jasmine AI FZ-LLC', iban });
  return answered(
    await payees.check(admin, keyed(admin, PAYEE_CHECK_OPERATION), supplierId, started.registration.id, CORRELATION),
    'checked',
  ).registration;
}

const approve = (who: SessionMember, id: string) =>
  changes.approve(who, keyed(who, PAYEE_APPROVE_OPERATION), id, CORRELATION);
const confirm = (who: SessionMember, id: string, challengeId: string, key?: string) =>
  changes.approveConfirm(who, keyed(who, PAYEE_APPROVE_CONFIRM_OPERATION, key), id, challengeId, CORRELATION);
const withdraw = (who: SessionMember, id: string, key?: string) =>
  changes.withdraw(who, keyed(who, PAYEE_WITHDRAW_OPERATION, key), id, CORRELATION);

/** The member signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (who: SessionMember, challengeId: string, amr: readonly string[] = PASSKEY) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const changedOf = (write: SupplierChangeWrite) => {
  if (write.outcome !== 'changed') throw new Error(`not changed: ${JSON.stringify(write)}`);
  return write;
};

const askedFor = (write: SupplierChangeWrite): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

/** Asked, stepped up with `amr`, then confirmed. */
async function confirmed(who: SessionMember, id: string, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await approve(who, id));
  await stepUp(who, challengeId, amr);
  return confirm(who, id, challengeId);
}

/** The supplier as its signed state says. */
const supplierNow = (org: string, id: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await supplierOf(tx, states, { orgId: org, id }, 'share');
    if (read.outcome !== 'found') throw new Error(`not found: ${read.outcome}`);
    return read.supplier;
  });

/** The organisation's notices in the outbox (a table of every organisation's), about anything. */
const notices = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['kind', 'recipient_user_id', 'recipient_contact_id', 'to_contacts', 'about_id'])
      .where('org_id', '=', org)
      .orderBy('to_contacts')
      .execute(),
  );

/** The organisation's events about the supplier, oldest first. */
const eventsAbout = (org: string, id: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_type', 'actor_id', 'details'])
      .where('subject_type', '=', 'supplier')
      .where('subject_id', '=', id)
      .orderBy('seq')
      .execute(),
  );

const actions = async (org: string, id: string) => (await eventsAbout(org, id)).map((event) => event.action);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
  rail = createFakeRail({ clock, ids });
  const services = { database: app, keys, ids, clock, logger: testLogger() };
  registry = createSupplierRegistry(services);
  payees = createSupplierPayees({ ...services, rail, partner: 'fake' });
  changes = createSupplierPayeeChanges({
    ...services,
    challenges: challenges(),
    outbox: createOutbox({ ids, clock }),
  });
});

describe(`confirming a payee change waiting, with the admin's passkey (E2-2b, Postgres ${server.version})`, () => {
  it('ADR-014 §3 makes it current with its payee key, starts its 24 h cooling-off and tells every member and the contacts', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const registration = await waiting(admin, id);
    const before = await supplierNow(org, id);
    expect(await notices(org)).toEqual([]);

    const done = changedOf(await confirmed(admin, id));

    expect(done.supplier).toMatchObject({
      status: 'UNVERIFIED',
      currentVersionId: registration.versionId,
      pendingVersionId: null,
      coolingOffUntil: new Date(clock.now().getTime() + PAYEE_COOLING_OFF_MS),
      payeeKey: registration.payeeKey,
    });
    expect(PAYEE_COOLING_OFF_MS).toBe(24 * 3_600_000);
    expect(before).toMatchObject({ pendingVersionId: registration.versionId, payeeKey: null });
    // What the call-back confirms: the partner's description of the payee now paid, nothing waiting.
    expect(done.payee).toEqual({
      registrationId: registration.id,
      payeeHint: registration.payeeHint,
      nameCheck: registration.nameCheck,
      maskedName: registration.maskedName,
    });
    expect(done.pending).toBeNull();
    // Found by the sender as it sends: every active member, and the contacts that count.
    expect(await notices(org)).toEqual([
      {
        kind: 'supplier_payee_changed',
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: false,
        about_id: id,
      },
      {
        kind: 'supplier_payee_changed',
        recipient_user_id: null,
        recipient_contact_id: null,
        to_contacts: true,
        about_id: id,
      },
    ]);
    const last = (await eventsAbout(org, id)).at(-1);
    expect(last).toMatchObject({
      action: 'supplier.payee_change_confirmed',
      actor_type: 'user',
      actor_id: admin.userId,
    });
    expect(JSON.parse(String(last?.details))).toMatchObject({
      registrationId: registration.id,
      methods: 'pwd user mfa',
    });
  });

  it('shows the change waiting, with the payee the partner described, until it is confirmed', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const registration = await waiting(admin, id);

    const shown = await registry.show(org, id, CORRELATION);

    expect(shown).toMatchObject({
      payee: null,
      pending: {
        version: { id: registration.versionId, version: 2 },
        payee: { registrationId: registration.id, payeeHint: registration.payeeHint },
      },
    });
  });

  it('refuses another admin (PAYEE_CHANGE_NOT_YOURS), an approver, and a supplier with nothing waiting, asking nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const otherAdmin = await member(org, 'admin');
    const approver = await member(org, 'approver');
    const id = await added(admin);

    expect(await approve(admin, id)).toEqual({ outcome: 'refused', status: 409, code: 'SUPPLIER_NO_CHANGE_WAITING' });
    await waiting(admin, id);
    expect(await approve(otherAdmin, id)).toEqual({ outcome: 'refused', status: 403, code: 'PAYEE_CHANGE_NOT_YOURS' });
    expect(await approve(approver, id)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    // The enterer's own challenge, confirmed by another admin in their session, is never theirs.
    const challengeId = askedFor(await approve(admin, id));
    await stepUp(admin, challengeId);
    expect(await confirm(otherAdmin, id, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'PAYEE_CHANGE_NOT_YOURS',
    });
    expect((await supplierNow(org, id)).payeeKey).toBeNull();
    expect(await notices(org)).toEqual([]);
  });

  it('refuses a session ended since, as UNAUTHENTICATED, opening no step-up', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await waiting(admin, id);
    await app.deleteFrom('identity.sessions').where('id', '=', admin.sessionId).execute();

    expect(await approve(admin, id)).toEqual({ outcome: 'refused', status: 401, code: 'UNAUTHENTICATED' });
  });

  it('SEC-HA-12 refuses a step-up made with an app code, changing nothing and telling no one', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const { versionId } = await waiting(admin, id);

    expect(await confirmed(admin, id, APP_CODE)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect(await supplierNow(org, id)).toMatchObject({
      pendingVersionId: versionId,
      payeeKey: null,
      coolingOffUntil: null,
    });
    expect(await notices(org)).toEqual([]);
  });

  it('binds the step-up to the very change waiting: one withdrawn and registered again needs another', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await waiting(admin, id);
    const challengeId = askedFor(await approve(admin, id));
    await stepUp(admin, challengeId);
    changedOf(await withdraw(admin, id));
    const again = await waiting(admin, id, ibanOf(OTHER));

    expect(await confirm(admin, id, challengeId)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect((await supplierNow(org, id)).pendingVersionId).toBe(again.versionId);
    expect(changedOf(await confirmed(admin, id)).supplier.currentVersionId).toBe(again.versionId);
  });

  it('confirms one for a suspended supplier, which stays suspended, its payee changed beneath the brake', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const { versionId } = await waiting(admin, id);
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      const found = await supplierOf(tx, states, { orgId: org, id }, 'change');
      if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
      await suspendSupplier(tx, states, { orgId: org, id }, found, { actor: OPERATOR });
    });

    expect(changedOf(await confirmed(admin, id)).supplier).toMatchObject({
      status: 'SUSPENDED',
      currentVersionId: versionId,
      pendingVersionId: null,
    });
  });

  it('answers a retry of the same confirmation as it stands, telling no one twice', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const { versionId } = await waiting(admin, id);
    const challengeId = askedFor(await approve(admin, id));
    await stepUp(admin, challengeId);

    const first = changedOf(await confirm(admin, id, challengeId, 'the-same-key'));
    const retried = changedOf(await confirm(admin, id, challengeId, 'the-same-key'));

    expect(retried.supplier).toEqual(first.supplier);
    expect(first.supplier.currentVersionId).toBe(versionId);
    expect(await notices(org)).toHaveLength(2);
    expect((await actions(org, id)).filter((action) => action === 'supplier.payee_change_confirmed')).toHaveLength(1);
  });

  it('SEC-PAY-06 answers SUPPLIER_PAYEE_TAKEN when another supplier was confirmed to that payee first, keeping nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = await added(admin);
    const second = await added(admin);
    await waiting(admin, first);
    const { versionId } = await waiting(admin, second);
    changedOf(await confirmed(admin, first));
    const challengeId = askedFor(await approve(admin, second));
    await stepUp(admin, challengeId);

    expect(await confirm(admin, second, challengeId)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'SUPPLIER_PAYEE_TAKEN',
    });
    expect(await supplierNow(org, second)).toMatchObject({ pendingVersionId: versionId, payeeKey: null });
    expect((await notices(org)).filter(({ about_id }) => about_id === second)).toEqual([]);
    // Everything rolled back, the challenge's use included; the change is left for a withdrawal.
    expect(changedOf(await withdraw(admin, second)).supplier.pendingVersionId).toBeNull();
  });
});

describe(`the confirmation's lock order against the confirmer's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('a payee change holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const registration = await waiting(admin, id);
    const challengeId = askedFor(await approve(admin, id));
    await stepUp(admin, challengeId);

    const done = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: admin.membershipId },
      () => confirm(admin, id, challengeId),
    );

    expect(changedOf(done).supplier).toMatchObject({
      currentVersionId: registration.versionId,
      payeeKey: registration.payeeKey,
    });
  });
});

describe(`a registration tampered with (E2-2b, Postgres ${server.version})`, () => {
  it('refuses the supplier’s view and the confirmation: INTEGRITY_FAILED, nothing confirmed', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const registration = await waiting(admin, id);
    // The masked name the call-back is read against, moved past the app: its seal no longer holds.
    await withTenant(app, org, (tx) =>
      tx
        .updateTable('suppliers.beneficiary_registrations')
        .set({ masked_name: 'S***** E***' })
        .where('id', '=', registration.id)
        .execute(),
    );

    const refused = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    expect(await registry.show(org, id, CORRELATION)).toEqual(refused);
    expect(await approve(admin, id)).toEqual(refused);
    expect((await supplierNow(org, id)).payeeKey).toBeNull();
  });
});

describe(`a version waiting tampered with (E2-2b, Postgres ${server.version})`, () => {
  it('refuses the supplier’s view and the confirmation: INTEGRITY_FAILED, nothing confirmed', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const { versionId } = await waiting(admin, id);
    // Past the app, as the database's owner: the hint the call-back reads, changed.
    const owner = await tamperAsOwner(database, SUPPLIER_VERSIONS, org);
    try {
      // 0032's `made_once` stops even the owner, unless they switch it off first.
      await owner.query('alter table suppliers.supplier_versions disable trigger made_once');
      await owner.query("update suppliers.supplier_versions set payee_hint = 'AE…9999' where id = $1", [versionId]);
    } finally {
      await owner.query('alter table suppliers.supplier_versions enable trigger made_once');
      await owner.end();
    }

    const refused = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    expect(await registry.show(org, id, CORRELATION)).toEqual(refused);
    expect(await approve(admin, id)).toEqual(refused);
    expect((await supplierNow(org, id)).payeeKey).toBeNull();
  });
});

describe(`withdrawing a payee change waiting: a brake, with no step-up (E2-2b, Postgres ${server.version})`, () => {
  it.each(['admin', 'approver'] as const)('drops it at once for an %s, the payee paid now untouched', async (role) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await waiting(admin, id);
    changedOf(await confirmed(admin, id));
    const paid = await supplierNow(org, id);
    await waiting(admin, id, ibanOf(OTHER));
    const who = role === 'admin' ? admin : await member(org, role);

    const done = changedOf(await withdraw(who, id));

    expect(done.supplier).toEqual({ ...paid, pendingVersionId: null });
    expect(done.pending).toBeNull();
    expect(await actions(org, id)).toContain('supplier.payee_change_withdrawn');
    // Only the confirmation tells anyone.
    expect(await notices(org)).toHaveLength(2);
  });

  it('refuses a viewer or a developer, and a supplier with nothing waiting', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    expect(await withdraw(admin, id)).toEqual({ outcome: 'refused', status: 409, code: 'SUPPLIER_NO_CHANGE_WAITING' });
    await waiting(admin, id);
    for (const role of ['viewer', 'developer'] as const) {
      expect(await withdraw(await member(org, role), id)).toEqual({
        outcome: 'refused',
        status: 403,
        code: 'FORBIDDEN',
      });
    }
    expect((await supplierNow(org, id)).pendingVersionId).not.toBeNull();
  });

  it('answers a retry of the same withdrawal as it stands, with no second event', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await waiting(admin, id);

    changedOf(await withdraw(admin, id, 'withdraw-once'));
    changedOf(await withdraw(admin, id, 'withdraw-once'));

    expect((await actions(org, id)).filter((action) => action === 'supplier.payee_change_withdrawn')).toHaveLength(1);
  });
});
