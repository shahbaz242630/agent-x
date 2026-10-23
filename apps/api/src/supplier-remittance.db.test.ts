// Phase 4 C2a (partner decision 34b and 34d, Rule Book §1.9): whether a
// supplier is emailed when it is paid, chosen as it is added and changed after
// by an admin with a passkey step-up, everyone told, through the use cases the
// routes call, on the real migrated schema, as the app role. The setting is
// signed and checked, and never touches the supplier's verification. The
// routes' answers are suppliers.test.ts; the module's reads of a supplier
// added before 0061 are remittance.db.test.ts's.
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
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { createOutbox, type NotificationsTables } from '@agentx/core/modules/notifications';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import type { SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import {
  addSupplierUnset,
  type RemittanceEmail,
  type SupplierDetails,
  supplierOf,
  type SuppliersTables,
  verifySupplier,
} from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  SequentialIds,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { ADD_OPERATION, createSupplierRegistry, type SupplierRegistry } from './supplier-registry.ts';
import {
  createSupplierRemittance,
  REMITTANCE_CONFIRM_OPERATION,
  REMITTANCE_OPERATION,
  type SupplierRemittance,
} from './supplier-remittance.ts';
import type { SessionMember, SupplierChangeWrite } from './supplier-work.ts';

type Tables = IdentityTables &
  SuppliersTables &
  OrganizationsTables &
  DirectoryTables &
  AuditTables &
  NotificationsTables &
  LimitReservationsTables &
  SpendRequestsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xc2a0_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000c2';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: 'accounts@gulfoffice.example', tradeLicence: null },
  source: { kind: 'official_website', ref: 'https://gulfoffice.example' },
};

let clock: FixedClock;
let registry: SupplierRegistry;
let remittance: SupplierRemittance;
const challenges = () => createStepUpChallenges({ ids, clock });

const quiet = () => ({ keys, ids, logger: testLogger() });

let people = 0;

/** A person with a session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<SessionMember & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `supplier-remittance-${String(people)}` },
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
const keyed = (who: SessionMember, operation: string): IdempotentRequest => {
  keysUsed += 1;
  return {
    orgId: who.orgId,
    client: { kind: 'user', id: who.userId },
    operation,
    key: `key-${String(keysUsed)}`,
    payload: '{}',
  };
};

/** A supplier added by the admin with their choice, as the route adds it. */
async function added(admin: SessionMember, remittanceEmail: RemittanceEmail): Promise<string> {
  const write = await registry.add(
    admin,
    keyed(admin, ADD_OPERATION),
    { details: DETAILS, remittanceEmail },
    CORRELATION,
  );
  if (write.outcome !== 'added') throw new Error(`not added: ${JSON.stringify(write)}`);
  return write.supplier.id;
}

const ask = (who: SessionMember, id: string, choice: RemittanceEmail) =>
  remittance.ask(who, keyed(who, REMITTANCE_OPERATION), id, choice, CORRELATION);
const confirm = (who: SessionMember, id: string, stepUpChallengeId: string, choice: RemittanceEmail) =>
  remittance.confirm(
    who,
    keyed(who, REMITTANCE_CONFIRM_OPERATION),
    id,
    { stepUpChallengeId, remittanceEmail: choice },
    CORRELATION,
  );

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

const changedOf = (write: SupplierChangeWrite) => {
  if (write.outcome !== 'changed') throw new Error(`not changed: ${JSON.stringify(write)}`);
  return write;
};

/** Asked, signed in again with a passkey, and confirmed: the change as the routes make it. */
async function changed(who: SessionMember, id: string, choice: RemittanceEmail) {
  const challengeId = askedFor(await ask(who, id, choice));
  await stepUp(who, challengeId);
  return changedOf(await confirm(who, id, challengeId, choice));
}

/** The organisation's events about the supplier's setting, oldest first. */
const settingEvents = (org: string, id: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_type', 'actor_id', 'details'])
      .where('subject_type', '=', 'supplier_remittance')
      .where('subject_id', '=', id)
      .orderBy('seq')
      .execute(),
  );

/** The supplier's own events, by action: the setting never adds one. */
const supplierActions = async (org: string, id: string) =>
  (
    await withTenant(app, org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select('action')
        .where('subject_type', '=', 'supplier')
        .where('subject_id', '=', id)
        .orderBy('seq')
        .execute(),
    )
  ).map((event) => event.action);

/** The organisation's notices of a changed setting, the members' first, then the contacts'. */
const noticesOf = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['kind', 'to_contacts', 'about_id'])
      .where('org_id', '=', org)
      .where('kind', '=', 'supplier_remittance_changed')
      .orderBy('to_contacts')
      .execute(),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-23T08:00:00Z'));
  const services = { database: app, keys, ids, clock, logger: testLogger() };
  registry = createSupplierRegistry(services);
  remittance = createSupplierRemittance({
    ...services,
    challenges: challenges(),
    outbox: createOutbox({ ids, clock }),
  });
});

describe(`a supplier's remittance email (C2a, Postgres ${server.version})`, () => {
  it.each(['on', 'off'] as const)('is added with the admin’s choice of %s, signed as theirs', async (choice) => {
    const org = await organization();
    const admin = await member(org, 'admin');

    const id = await added(admin, choice);

    expect(await registry.show(org, id, CORRELATION)).toMatchObject({ outcome: 'found', remittanceEmail: choice });
    expect(await settingEvents(org, id)).toMatchObject([
      { action: 'supplier_remittance.chosen', actor_type: 'user', actor_id: admin.userId },
    ]);
  });

  it('is changed by an admin with a passkey, everyone told, its supplier’s verification and events untouched', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin, 'on');
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      const found = await supplierOf(tx, states, { orgId: org, id }, 'change');
      if (found.outcome !== 'found') throw new Error(found.outcome);
      await verifySupplier(tx, states, { orgId: org, id }, found, { verifiedBy: admin.membershipId, actor: OPERATOR });
    });
    const before = await supplierActions(org, id);

    const challengeId = askedFor(await ask(admin, id, 'off'));
    expect(await registry.show(org, id, CORRELATION)).toMatchObject({ remittanceEmail: 'on' });
    await stepUp(admin, challengeId);
    const off = changedOf(await confirm(admin, id, challengeId, 'off'));

    expect(off).toMatchObject({
      remittanceEmail: 'off',
      supplier: { status: 'VERIFIED', verifiedBy: admin.membershipId },
    });
    const events = await settingEvents(org, id);
    expect(events.map((event) => event.action)).toEqual(['supplier_remittance.chosen', 'supplier_remittance.changed']);
    expect(JSON.parse(String(events.at(-1)?.details))).toMatchObject({ stepUpChallengeId: challengeId });
    expect(await supplierActions(org, id)).toEqual(before);
    expect(await noticesOf(org)).toEqual([
      { kind: 'supplier_remittance_changed', to_contacts: false, about_id: id },
      { kind: 'supplier_remittance_changed', to_contacts: true, about_id: id },
    ]);
    expect(await changed(admin, id, 'on')).toMatchObject({ remittanceEmail: 'on' });
  });

  it('changed first for a supplier added before 0061: read as on, its row added and sealed with the step-up', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = ids.next();
    await withSignedStates(app, org, quiet(), (tx, states) =>
      addSupplierUnset(tx, states, keys, {
        orgId: org,
        id,
        versionId: ids.next(),
        supplier: DETAILS,
        enteredBy: admin.membershipId,
        createdAt: clock.now(),
        actor: OPERATOR,
      }),
    );
    expect(await registry.show(org, id, CORRELATION)).toMatchObject({ remittanceEmail: 'on' });
    expect(await ask(admin, id, 'on')).toMatchObject({ status: 409, code: 'SUPPLIER_REMITTANCE_UNCHANGED' });
    const stale = askedFor(await ask(admin, id, 'off'));
    await stepUp(admin, stale);

    const challengeId = askedFor(await ask(admin, id, 'off'));
    await stepUp(admin, challengeId);
    expect(changedOf(await confirm(admin, id, challengeId, 'off'))).toMatchObject({ remittanceEmail: 'off' });

    const events = await settingEvents(org, id);
    expect(events).toMatchObject([
      { action: 'supplier_remittance.chosen', actor_type: 'user', actor_id: admin.userId },
    ]);
    expect(JSON.parse(String(events[0]?.details))).toMatchObject({ stepUpChallengeId: challengeId });
    expect(await noticesOf(org)).toHaveLength(2);
    // Asked from no setting at all: once it has one, back at `on`, the step-up no longer names where it stands.
    await changed(admin, id, 'on');
    expect(await confirm(admin, id, stale, 'off')).toMatchObject({ status: 403, code: 'STEP_UP_FAILED' });
  });

  it('already as asked is refused before any step-up, SUPPLIER_REMITTANCE_UNCHANGED, recording nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin, 'off');

    expect(await ask(admin, id, 'off')).toMatchObject({ status: 409, code: 'SUPPLIER_REMITTANCE_UNCHANGED' });
    expect(await settingEvents(org, id)).toHaveLength(1);
  });

  it('refuses a confirm signed in again with an app code, not a passkey, changing nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin, 'on');
    const challengeId = askedFor(await ask(admin, id, 'off'));
    await stepUp(admin, challengeId, APP_CODE);

    expect(await confirm(admin, id, challengeId, 'off')).toMatchObject({ status: 403, code: 'STEP_UP_FAILED' });
    expect(await registry.show(org, id, CORRELATION)).toMatchObject({ remittanceEmail: 'on' });
    expect(await noticesOf(org)).toEqual([]);
  });

  it('refuses a step-up asked for another supplier, or from where the setting no longer stands', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin, 'on');
    const other = await added(admin, 'on');
    const forOther = askedFor(await ask(admin, other, 'off'));
    await stepUp(admin, forOther);

    expect(await confirm(admin, id, forOther, 'off')).toMatchObject({ status: 403, code: 'STEP_UP_FAILED' });

    // Asked from `on`; then switched off and on again by other step-ups: it no longer names where it stands.
    const stale = askedFor(await ask(admin, id, 'off'));
    await stepUp(admin, stale);
    await changed(admin, id, 'off');
    await changed(admin, id, 'on');
    expect(await confirm(admin, id, stale, 'off')).toMatchObject({ status: 403, code: 'STEP_UP_FAILED' });
    expect(await registry.show(org, id, CORRELATION)).toMatchObject({ remittanceEmail: 'on' });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('is refused to an %s, 403', async (role) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin, 'on');

    expect(await ask(await member(org, role), id, 'off')).toMatchObject({ status: 403, code: 'FORBIDDEN' });
    expect(await settingEvents(org, id)).toHaveLength(1);
  });

  it('answers 404 for a supplier not the organisation’s', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const elsewhere = await organization();
    const theirs = await added(await member(elsewhere, 'admin'), 'on');

    expect(await ask(admin, theirs, 'off')).toMatchObject({ status: 404, code: 'NOT_FOUND' });
    expect(await ask(admin, ids.next(), 'off')).toMatchObject({ status: 404, code: 'NOT_FOUND' });
  });

  it('changed past the app, refuses its supplier’s answer and its setting, 503 INTEGRITY_FAILED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin, 'on');

    await database
      .as('admin')
      .query("update suppliers.remittance_settings set remittance_email = 'off' where id = $1", [id]);

    expect(await registry.show(org, id, CORRELATION)).toMatchObject({ status: 503, code: 'INTEGRITY_FAILED' });
    expect(await ask(admin, id, 'on')).toMatchObject({ status: 503, code: 'INTEGRITY_FAILED' });
  });

  it('FX-RACE confirmed by two admins at once: they take turns on the supplier, the second finds it changed', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const other = await member(org, 'admin');
    const id = await added(admin, 'on');
    const mine = askedFor(await ask(admin, id, 'off'));
    const theirs = askedFor(await ask(other, id, 'off'));
    await stepUp(admin, mine);
    await stepUp(other, theirs);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The supplier held for change, so both confirms queue on it and go from the same start, `on`.
    const holder = withTenant(app, org, async (tx) => {
      await tx.selectFrom('suppliers.suppliers').select('id').where('id', '=', id).forNoKeyUpdate().execute();
      holding(undefined);
      await gate;
    });
    await held;

    const both = Promise.all([confirm(admin, id, mine, 'off'), confirm(other, id, theirs, 'off')]);
    await waitUntilQueued(database.as('admin'), 2);
    open(undefined);
    await holder;

    const answers = await both;
    expect(answers.filter((write) => write.outcome === 'changed')).toHaveLength(1);
    expect(answers.filter((write) => write.outcome !== 'changed')).toEqual([
      { outcome: 'refused', status: 409, code: 'SUPPLIER_REMITTANCE_UNCHANGED' },
    ]);
    expect((await settingEvents(org, id)).map((event) => event.action)).toEqual([
      'supplier_remittance.chosen',
      'supplier_remittance.changed',
    ]);
    expect(await noticesOf(org)).toHaveLength(2);
  });
});
