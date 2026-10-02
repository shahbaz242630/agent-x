// E3-2a (ADR-012 §1, ADR-014 §3, ADR-003 §9; SEC-PAY-03, SEC-PAY-04,
// SEC-PAY-07, SEC-HA-12): a supplier verified by a second person, with a
// passkey, through the use case the routes call, on the real migrated schema,
// as the app role, with the fake partner in memory: its payee confirmed and
// cooled off, the partner's name check, the call-back's note and phone, the
// two-person rule over everyone who entered its details, and everyone told.
// The routes' answers are suppliers.test.ts; the rule's own cases,
// identity's two-person tests.
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
  MOST_VERIFICATIONS_READ,
  PAYEE_COOLING_OFF_MS,
  SUPPLIERS,
  type SupplierDetails,
  supplierOf,
  type SuppliersTables,
  VERIFIER_RECORDED,
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
import { ADD_OPERATION, createSupplierRegistry, type SupplierRegistry } from './supplier-registry.ts';
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
const ids = new SequentialIds(0xe32a_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000ae';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;
const DAY_MS = 86_400_000;
const NOTE = 'Spoke to Sara in accounts on the registry number; she confirmed the account';

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
    { issuer: 'https://auth.example.test', subject: `supplier-verifications-${String(people)}` },
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

/**
 * A supplier added (by `adder`, or the admin), its bank details (`account`)
 * registered by `admin` through the partner's form typed as `name`, checked
 * (by `checker`, or the admin) and confirmed with the admin's passkey: its
 * 24 h cooling-off begun.
 */
async function payable(
  adminPerson: Person,
  name = HOLDER,
  account: Account = JASMINE,
  { adder = adminPerson, checker = adminPerson }: { adder?: Person; checker?: Person } = {},
): Promise<string> {
  const admin = await signedIn(adminPerson);
  const adding = await signedIn(adder);
  const checking = await signedIn(checker);
  const added = await registry.add(adding, keyed(adding, ADD_OPERATION), DETAILS, CORRELATION);
  if (added.outcome !== 'added') throw new Error(`not added: ${JSON.stringify(added)}`);
  const supplierId = added.supplier.id;
  const started = await payees.start(admin, keyed(admin, PAYEE_START_OPERATION), supplierId, CORRELATION);
  if (started.outcome !== 'started') throw new Error(`not started: ${JSON.stringify(started)}`);
  await rail.bank.fillForm(admin.orgId, started.form?.url ?? '', { name, iban: ibanOf(account) });
  const checked = await payees.check(
    checking,
    keyed(checking, PAYEE_CHECK_OPERATION),
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

const ask = (who: SessionMember, id: string, note: string | null = null) =>
  verifications.verify(who, keyed(who, VERIFY_OPERATION), id, { note }, CORRELATION);

/** Asked with `note`, stepped up with `amr`, then confirmed with `confirmNote`. */
async function verified(
  person: Person,
  id: string,
  {
    note = null,
    confirmNote = note,
    amr = PASSKEY,
    key,
  }: { note?: string | null; confirmNote?: string | null; amr?: readonly string[]; key?: string } = {},
) {
  const who = await signedIn(person);
  const challengeId = askedFor(await ask(who, id, note));
  await stepUp(who, challengeId, amr);
  return verifications.verifyConfirm(
    who,
    keyed(who, VERIFY_CONFIRM_OPERATION, key),
    id,
    { stepUpChallengeId: challengeId, note: confirmNote },
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

/** The organisation's notices of a verification in the outbox. */
const verifiedNotices = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('notifications.outbox')
      .select(['kind', 'recipient_user_id', 'to_contacts', 'about_id'])
      .where('org_id', '=', org)
      .where('kind', '=', 'supplier_verified')
      .orderBy('to_contacts')
      .execute(),
  );

/** The supplier's record of its verification: who verified it, and the details kept. */
const recordedOf = async (org: string, id: string) => {
  const row = await withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['actor_id', 'details'])
      .where('subject_type', '=', 'supplier')
      .where('subject_id', '=', id)
      .where('action', '=', VERIFIER_RECORDED)
      .executeTakeFirst(),
  );
  return { actorId: row?.actor_id, details: JSON.parse(row?.details ?? '{}') as unknown };
};

const refusedWith = (code: string, status?: number) =>
  expect.objectContaining({ outcome: 'refused', code, ...(status === undefined ? {} : { status }) }) as unknown;

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

describe(`verifying a supplier, with the verifier's passkey (E3-2a, Postgres ${server.version})`, () => {
  it('SEC-PAY-04 makes it VERIFIED by a second person, records how, and tells every member and the contacts', async () => {
    const { org, bob, supplierId } = await established();

    const answer = await verified(bob, supplierId);

    expect(answer).toMatchObject({
      outcome: 'changed',
      supplier: { status: 'VERIFIED', verifiedBy: bob.membershipId },
    });
    const supplier = await supplierNow(org, supplierId);
    expect(supplier).toMatchObject({ status: 'VERIFIED', verifiedBy: bob.membershipId });
    expect(supplier.verifiedVersionId).toBe(supplier.currentVersionId);
    const recorded = await recordedOf(org, supplierId);
    expect(recorded.actorId).toBe(bob.userId);
    expect(recorded.details).toMatchObject({
      path: 'two_person',
      calledBack: true,
      nameCheck: 'match',
      stepUpChallengeId: expect.any(String) as string,
    });
    expect(await verifiedNotices(org)).toEqual([
      { kind: 'supplier_verified', recipient_user_id: null, to_contacts: false, about_id: supplierId },
      { kind: 'supplier_verified', recipient_user_id: null, to_contacts: true, about_id: supplierId },
    ]);
  });

  it('refuses the member who entered its details while a second person may, asking nothing', async () => {
    const { org, alice, supplierId } = await established();

    expect(await ask(await signedIn(alice), supplierId)).toEqual(refusedWith('VERIFIER_ENTERED_DETAILS', 403));
    expect(await supplierNow(org, supplierId)).toMatchObject({ status: 'UNVERIFIED' });
  });

  it('holds apart everyone who entered its details: who added it, and who started its payee, whoever checked (the review)', async () => {
    const { org, alice } = await team();
    const carol = await member(org, 'admin');
    const dan = await member(org, 'admin');
    clock.advanceBy(15 * DAY_MS);
    const supplierId = await payable(alice, HOLDER, JASMINE, { adder: carol, checker: dan });
    clock.advanceBy(PAYEE_COOLING_OFF_MS);

    for (const enterer of [alice, carol]) {
      expect(await ask(await signedIn(enterer), supplierId)).toEqual(refusedWith('VERIFIER_ENTERED_DETAILS', 403));
    }
    expect(await verified(dan, supplierId)).toMatchObject({ supplier: { status: 'VERIFIED' } });
  });

  it('takes the single-user path in an organisation of one: its own admin, once cooled off', async () => {
    const org = await organization();
    const alice = await member(org, 'admin');
    const supplierId = await payable(alice);
    clock.advanceBy(PAYEE_COOLING_OFF_MS);

    expect(await verified(alice, supplierId)).toMatchObject({ outcome: 'changed', supplier: { status: 'VERIFIED' } });
    expect((await recordedOf(org, supplierId)).details).toMatchObject({ path: 'single_user' });
  });

  it('refuses a member under 14 days while another is eligible, and a viewer or developer at all', async () => {
    const { org, supplierId } = await established();
    const young = await member(org, 'admin');
    clock.advanceBy(13 * DAY_MS);

    expect(await ask(await signedIn(young), supplierId)).toEqual(refusedWith('VERIFIER_TOO_NEW', 403));
    for (const role of ['viewer', 'developer'] as const) {
      expect(await ask(await signedIn(await member(org, role)), supplierId)).toEqual(refusedWith('FORBIDDEN', 403));
    }
  });

  it('refuses one still cooling off, to the millisecond, and one with no bank details', async () => {
    const { alice, bob } = await team();
    const supplierId = await payable(alice);
    clock.advanceBy(PAYEE_COOLING_OFF_MS - 1);
    const signedBob = await signedIn(bob);

    expect(await ask(signedBob, supplierId)).toEqual(refusedWith('SUPPLIER_COOLING_OFF', 409));
    clock.advanceBy(1);
    expect(askedFor(await ask(signedBob, supplierId))).toEqual(expect.any(String));

    const admin = await signedIn(alice);
    const bare = await registry.add(admin, keyed(admin, ADD_OPERATION), DETAILS, CORRELATION);
    if (bare.outcome !== 'added') throw new Error('not added');
    expect(await ask(signedBob, bare.supplier.id)).toEqual(refusedWith('SUPPLIER_NO_PAYEE', 409));
  });

  it('refuses a "no match" name check whatever the note, and needs a note for a partial one (partner, S69, S74)', async () => {
    const { org, alice, bob } = await team();
    const [first = ''] = holderOf(OTHER).split(' ');
    const mismatched = await payable(alice, 'Zeta Trading LLC');
    const partial = await payable(alice, `${first} Somebody Else`, OTHER);
    clock.advanceBy(PAYEE_COOLING_OFF_MS);
    const signedBob = await signedIn(bob);

    expect(await ask(signedBob, mismatched, NOTE)).toEqual(refusedWith('SUPPLIER_NAME_MISMATCH', 409));
    expect(await ask(signedBob, partial)).toEqual(refusedWith('SUPPLIER_CALL_NOTE_NEEDED', 409));
    expect(await verified(bob, partial, { note: NOTE })).toMatchObject({ supplier: { status: 'VERIFIED' } });
    expect((await recordedOf(org, partial)).details).toMatchObject({ nameCheck: 'partial', callBackNote: NOTE });
  });

  it('SEC-HA-12 refuses a step-up made with an app code, verifying nothing and telling no one', async () => {
    const { org, bob, supplierId } = await established();

    expect(await verified(bob, supplierId, { amr: APP_CODE })).toEqual(refusedWith('STEP_UP_FAILED', 403));
    expect(await supplierNow(org, supplierId)).toMatchObject({ status: 'UNVERIFIED' });
    expect(await verifiedNotices(org)).toEqual([]);
  });

  it('binds the step-up to the note asked with: another note at the confirm verifies nothing', async () => {
    const { org, bob, supplierId } = await established();

    expect(await verified(bob, supplierId, { note: NOTE, confirmNote: `${NOTE}, and more` })).toEqual(
      refusedWith('STEP_UP_FAILED', 403),
    );
    expect(await supplierNow(org, supplierId)).toMatchObject({ status: 'UNVERIFIED' });
  });

  it('answers a retry of the same verification as it stands, telling no one twice; a verified one has nothing left', async () => {
    const { org, bob, supplierId } = await established();
    const first = await verified(bob, supplierId, { key: 'same' });
    const signedBob = await signedIn(bob);

    const again = await verifications.verifyConfirm(
      signedBob,
      keyed(signedBob, VERIFY_CONFIRM_OPERATION, 'same'),
      supplierId,
      { stepUpChallengeId: ids.next(), note: null },
      CORRELATION,
    );

    expect(first).toMatchObject({ supplier: { status: 'VERIFIED' } });
    expect(again).toMatchObject({ outcome: 'changed', supplier: { status: 'VERIFIED' } });
    expect(await verifiedNotices(org)).toHaveLength(2);
    expect(await ask(signedBob, supplierId)).toEqual(refusedWith('SUPPLIER_NOT_UNVERIFIED', 409));
  });
});

describe(`verifying over what can't be believed, or read whole (E3-2a, Postgres ${server.version})`, () => {
  it('refuses INTEGRITY_FAILED for an earlier version of the supplier edited past the app', async () => {
    const { org, bob, supplierId } = await established();
    const admin = database.as('admin');
    await admin.query('alter table suppliers.supplier_versions disable trigger made_once');
    await admin.query(
      `update suppliers.supplier_versions set display_name = 'Planted LLC' where org_id = $1 and version = 1`,
      [org],
    );
    await admin.query('alter table suppliers.supplier_versions enable trigger made_once');

    expect(await ask(await signedIn(bob), supplierId)).toEqual(refusedWith('INTEGRITY_FAILED', 503));
  });

  it('refuses INTEGRITY_FAILED for a version removed past the app, and logs it by IDs alone', async () => {
    const { org, bob, supplierId } = await established();
    await database
      .as('admin')
      .query('delete from suppliers.supplier_versions where org_id = $1 and version = 1', [org]);
    const logs = new LogCapture();
    verifications = createSupplierVerifications({
      database: app,
      keys,
      ids,
      clock,
      logger: loggerFor(logs),
      challenges: challenges(),
      outbox: createOutbox({ ids, clock }),
    });

    expect(await ask(await signedIn(bob), supplierId)).toEqual(refusedWith('INTEGRITY_FAILED', 503));
    expect(logs.lines()).toContainEqual(
      expect.objectContaining({ event: 'suppliers.version_missing', supplierId, orgId: org }),
    );
  });

  it('refuses INTEGRITY_FAILED for another member’s role raised past the app', async () => {
    const { org, bob, supplierId } = await established();
    const viewer = await member(org, 'viewer');
    await database
      .as('admin')
      .query(`update identity.memberships set role = 'admin' where org_id = $1 and id = $2`, [
        org,
        viewer.membershipId,
      ]);

    expect(await ask(await signedIn(bob), supplierId)).toEqual(refusedWith('INTEGRITY_FAILED', 503));
  });

  // Only its verification records are read (the review): that a read names its actions is audit-trail.db.test.ts's.
  it('refuses HISTORY_TOO_LONG for a supplier with more verification records than one read takes', async () => {
    const { org, bob, supplierId } = await established();
    // Recorded straight, one past the read's cap: a stand-in for years of the supplier's verifications.
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      for (let event = 0; event <= MOST_VERIFICATIONS_READ; event += 1) {
        const read = await supplierOf(tx, states, { orgId: org, id: supplierId }, 'change');
        if (read.outcome !== 'found') throw new Error('not found');
        await states.record(
          tx,
          SUPPLIERS,
          { orgId: org, id: supplierId },
          read.state,
          {},
          {
            actor: OPERATOR,
            action: VERIFIER_RECORDED,
            details: {},
          },
        );
      }
    });

    expect(await ask(await signedIn(bob), supplierId)).toEqual(refusedWith('HISTORY_TOO_LONG', 409));
  }, 120_000);
});
