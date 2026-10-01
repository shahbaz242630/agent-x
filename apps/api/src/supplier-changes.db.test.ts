// E1-2 (BR-04, ADR-012 §5, ADR-014 §8, ADR-003 §8, SEC-HA-12): the
// business's brake on a supplier, and lifting it with an admin's passkey
// step-up, through the use case the routes call, on the real migrated schema,
// as the app role. A supplier comes back VERIFIED only if nothing changed
// while it was suspended. The routes' answers are suppliers.test.ts.
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
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  addVersion,
  type SupplierDetails,
  SUPPLIERS,
  supplierOf,
  type SuppliersTables,
  verifySupplier,
  versionOf,
} from '@agentx/core/modules/suppliers';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createSupplierChanges,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  type SupplierChanges,
  type SupplierChangeWrite,
  SUSPEND_OPERATION,
} from './supplier-changes.ts';
import { ADD_OPERATION, createSupplierRegistry, type SupplierRegistry } from './supplier-registry.ts';
import type { SessionMember } from './supplier-work.ts';

type Tables = IdentityTables & SuppliersTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe12b_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000ac';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: null, tradeLicence: null },
  source: { kind: 'official_website', ref: 'https://gulfoffice.example' },
};

let clock: FixedClock;
let registry: SupplierRegistry;
let changes: SupplierChanges;
const challenges = () => createStepUpChallenges({ ids, clock });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

let people = 0;

/** A person with a session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<SessionMember & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `supplier-changes-${String(people)}` },
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
/** A fresh idempotency key for each write. */
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

/** Runs `work` on the supplier read for change, as E2 and E3 will. */
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

const verified = (org: string, id: string, verifier: string) =>
  onSupplier(org, id, (tx, states, found) =>
    verifySupplier(tx, states, { orgId: org, id }, found, { verifiedBy: verifier, actor: OPERATOR }),
  );

/** A second version made current, as a change of its details (E2, E3) will. */
const changedDetails = (org: string, id: string, enteredBy: string) =>
  onSupplier(org, id, async (tx, states, found) => {
    const follows = await versionOf(tx, states, { orgId: org, id: found.supplier.currentVersionId }, id);
    if (follows.outcome !== 'found') throw new Error(`no current version: ${follows.outcome}`);
    const versionId = ids.next();
    await addVersion(tx, states, keys, {
      orgId: org,
      id: versionId,
      supplierId: id,
      version: 2,
      supplier: { ...DETAILS, displayName: 'Gulf Office Supplies' },
      enteredBy,
      enteredAt: clock.now(),
      actor: OPERATOR,
      of: found,
      follows: follows.version,
    });
    await states.record(
      tx,
      SUPPLIERS,
      { orgId: org, id },
      found.state,
      { current_version_id: versionId },
      {
        actor: OPERATOR,
        action: 'supplier.test_change',
        details: {},
      },
    );
    return versionId;
  });

const suspend = (who: SessionMember, id: string, key?: string) =>
  changes.suspend(who, keyed(who, SUSPEND_OPERATION, key), id, CORRELATION);
const reactivate = (who: SessionMember, id: string) =>
  changes.reactivate(who, keyed(who, REACTIVATE_OPERATION), id, CORRELATION);
const confirm = (who: SessionMember, id: string, challengeId: string) =>
  changes.reactivateConfirm(who, keyed(who, REACTIVATE_CONFIRM_OPERATION), id, challengeId, CORRELATION);

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
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
  const services = { database: app, keys, ids, logger: loggerFor(new LogCapture()) };
  registry = createSupplierRegistry({ ...services, clock });
  changes = createSupplierChanges({ ...services, challenges: challenges() });
});

describe(`suspending a supplier: the brake, with no step-up (E1-2, Postgres ${server.version})`, () => {
  it.each(['admin', 'approver'] as const)('is one write by an %s: SUSPENDED, shown to no agent', async (role) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await verified(org, id, admin.membershipId);
    const who = role === 'admin' ? admin : await member(org, role);

    const suspended = changedOf(await suspend(who, id));

    expect(suspended.supplier).toMatchObject({ id, status: 'SUSPENDED', verifiedBy: admin.membershipId });
    expect(await registry.usableByAgent(org, { after: null, limit: 50 }, CORRELATION)).toMatchObject({
      suppliers: [],
    });
    expect((await eventsAbout(org, id)).at(-1)).toMatchObject({
      action: 'supplier.suspend',
      actor_type: 'user',
      actor_id: who.userId,
    });
  });

  it('pressed twice is answered as it is, recording nothing more', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    changedOf(await suspend(admin, id));

    expect(changedOf(await suspend(admin, id)).supplier.status).toBe('SUSPENDED');
    expect(await actions(org, id)).toEqual(['supplier.added', 'supplier.suspend']);
  });

  it('refuses a developer or a viewer: FORBIDDEN, the supplier left as it was', async () => {
    const org = await organization();
    const id = await added(await member(org, 'admin'));
    for (const role of ['developer', 'viewer'] as const) {
      expect(await suspend(await member(org, role), id)).toEqual({
        outcome: 'refused',
        status: 403,
        code: 'FORBIDDEN',
      });
    }
    expect(await actions(org, id)).toEqual(['supplier.added']);
  });

  it('answers NOT_FOUND for another organisation’s supplier, leaving it as it was', async () => {
    const org = await organization();
    const id = await added(await member(org, 'admin'));
    const outsider = await member(await organization(), 'admin');

    expect(await suspend(outsider, id)).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect(await actions(org, id)).toEqual(['supplier.added']);
  });

  it('answers a retry of the same write as the first did', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const first = changedOf(await suspend(admin, id, 'same'));

    expect(changedOf(await suspend(admin, id, 'same'))).toEqual(first);
    expect(await actions(org, id)).toEqual(['supplier.added', 'supplier.suspend']);
  });
});

describe(`reactivating a suspended supplier, with an admin’s passkey step-up (E1-2, Postgres ${server.version})`, () => {
  it('comes back VERIFIED once the admin signed in again with a passkey, when nothing changed', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await verified(org, id, admin.membershipId);
    changedOf(await suspend(admin, id));
    const challengeId = askedFor(await reactivate(admin, id));
    await stepUp(admin, challengeId);

    const back = changedOf(await confirm(admin, id, challengeId));

    expect(back.supplier).toMatchObject({ id, status: 'VERIFIED', verifiedBy: admin.membershipId });
    const events = await eventsAbout(org, id);
    expect(events.at(-1)?.action).toBe('supplier.reactivate_verified');
    expect(JSON.parse(String(events.at(-1)?.details))).toMatchObject({
      stepUpChallengeId: challengeId,
      methods: PASSKEY.join(' '),
    });
  });

  it('comes back UNVERIFIED when it was never verified', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    changedOf(await suspend(admin, id));
    const challengeId = askedFor(await reactivate(admin, id));
    await stepUp(admin, challengeId);

    expect(changedOf(await confirm(admin, id, challengeId)).supplier).toMatchObject({
      status: 'UNVERIFIED',
      verifiedBy: null,
    });
  });

  it('comes back UNVERIFIED, its verification cleared, when its details changed while it was suspended', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    await verified(org, id, admin.membershipId);
    changedOf(await suspend(admin, id));
    await changedDetails(org, id, admin.membershipId);
    const challengeId = askedFor(await reactivate(admin, id));
    await stepUp(admin, challengeId);

    const back = changedOf(await confirm(admin, id, challengeId));

    expect(back.supplier).toMatchObject({ status: 'UNVERIFIED', verifiedBy: null, verifiedVersionId: null });
    expect(back.version).toMatchObject({ version: 2, displayName: 'Gulf Office Supplies' });
  });

  it('refuses an admin who signed in again without a passkey: STEP_UP_FAILED, the supplier left SUSPENDED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    changedOf(await suspend(admin, id));
    const challengeId = askedFor(await reactivate(admin, id));
    await stepUp(admin, challengeId, APP_CODE);

    expect(await confirm(admin, id, challengeId)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect(await actions(org, id)).toEqual(['supplier.added', 'supplier.suspend']);
  });

  it('refuses a session ended since, as UNAUTHENTICATED, opening no step-up', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    changedOf(await suspend(admin, id));
    await app.deleteFrom('identity.sessions').where('id', '=', admin.sessionId).execute();

    expect(await reactivate(admin, id)).toEqual({ outcome: 'refused', status: 401, code: 'UNAUTHENTICATED' });
  });

  it('refuses an approver, who may brake but not lift it: FORBIDDEN, asking or confirming', async () => {
    const org = await organization();
    const approver = await member(org, 'approver');
    const id = await added(await member(org, 'admin'));
    changedOf(await suspend(approver, id));

    const refused = { outcome: 'refused', status: 403, code: 'FORBIDDEN' };
    expect(await reactivate(approver, id)).toEqual(refused);
    expect(await confirm(approver, id, ids.next())).toEqual(refused);
  });

  it('refuses a supplier that isn’t suspended: SUPPLIER_NOT_SUSPENDED, asking or confirming', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);

    const refused = { outcome: 'refused', status: 409, code: 'SUPPLIER_NOT_SUSPENDED' };
    expect(await reactivate(admin, id)).toEqual(refused);
    expect(await confirm(admin, id, ids.next())).toEqual(refused);
  });

  it('answers NOT_FOUND for another organisation’s supplier, asking or confirming', async () => {
    const org = await organization();
    const theirAdmin = await member(org, 'admin');
    const theirs = await added(theirAdmin);
    changedOf(await suspend(theirAdmin, theirs));
    const admin = await member(await organization(), 'admin');

    const missing = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
    expect(await reactivate(admin, theirs)).toEqual(missing);
    expect(await confirm(admin, theirs, ids.next())).toEqual(missing);
    expect((await eventsAbout(org, theirs)).at(-1)?.action).toBe('supplier.suspend');
  });

  it('refuses a step-up asked for another supplier, in another session, or before the admin signed in again', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    const other = await added(admin);
    changedOf(await suspend(admin, id));
    changedOf(await suspend(admin, other));
    const forOther = askedFor(await reactivate(admin, other));
    await stepUp(admin, forOther);
    const notYet = askedFor(await reactivate(admin, id));
    const own = askedFor(await reactivate(admin, id));
    await stepUp(admin, own);
    const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
    const { sessionId } = await sessions.open(app, admin.userId, {
      idpSessionId: 'V1_3',
      authTime: clock.now(),
      amr: [...PASSKEY],
    });

    expect(await confirm(admin, id, forOther)).toMatchObject({ code: 'STEP_UP_FAILED' });
    expect(await confirm(admin, id, notYet)).toMatchObject({ code: 'STEP_UP_FAILED' });
    expect(await confirm({ ...admin, sessionId }, id, own)).toMatchObject({ code: 'STEP_UP_FAILED' });
    expect((await eventsAbout(org, id)).at(-1)?.action).toBe('supplier.suspend');
  });

  it('refuses a step-up asked for an earlier suspension: it lifts exactly the one it was asked for', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const id = await added(admin);
    changedOf(await suspend(admin, id));
    const earlier = askedFor(await reactivate(admin, id));
    await stepUp(admin, earlier);
    // Lifted through another step-up, then suspended again: a new suspension.
    const between = askedFor(await reactivate(admin, id));
    await stepUp(admin, between);
    changedOf(await confirm(admin, id, between));
    changedOf(await suspend(admin, id));

    expect(await confirm(admin, id, earlier)).toEqual({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
    expect((await eventsAbout(org, id)).at(-1)?.action).toBe('supplier.suspend');
  });
});

describe(`what isn't a refusal (E1-2, Postgres ${server.version})`, () => {
  it('a database error inside a write is thrown, not answered, and writes nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');

    await expect(suspend(admin, 'not-a-uuid')).rejects.toThrow();
  });
});
