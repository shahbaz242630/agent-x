// PL-29 follow-up (Carry-Forward S175): an organisation's authority rows
// planned and repaired from the drill's copy, against a real Postgres. The
// copy is made as a restore makes one (TestDatabase.copy); the rows are
// tampered with as the database's owner would (@agentx/testing's
// tamperAsOwner), holding none of the app's keys. The plan reads both sides
// read-only as the owner; the repair writes as the owner, in one
// transaction, only the copy's original rows, and judges every row again with
// the app's own verifier before it commits. No event is forged here: every
// event on either chain is one the app or the operator recorded.
import { AUTHORITY_TABLES } from '@agentx/core/authority-tables';
import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { AGENT_KEYS, AGENTS } from '@agentx/core/modules/agents';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { INVITATIONS, MEMBERSHIPS } from '@agentx/core/modules/identity';
import { MANDATE_VERSIONS, MANDATES } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import { SUPPLIER_VERSIONS, SUPPLIERS } from '@agentx/core/modules/suppliers';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, readSignedRows, type SignedStateTable } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  tamperAsOwner,
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, afterEach, beforeEach, describe, expect, inject, it, vi } from 'vitest';

import { createOrganizationAsOperator } from './create-organization.ts';
import { type FirstAdminTables, inviteFirstAdminAsOperator } from './invite-first-admin.ts';
import { planStateRecovery, type StatePlan, statePlanDigest, statePlanFile } from './state-recovery.ts';
import {
  restoreStates,
  type StateRestoreOutcome,
  type StateRestoreSides,
  stateOutcomeLine,
  stateRestoreFile,
} from './state-restore.ts';

/**
 * Faults a test turns on, each standing for what the database alone can't be made to do here: a guard not switched on
 * again, a write failing for something other than a constraint, the verifier finding a row written still tampered (one
 * row, or the whole check of the tables written), the chain failing its check, the log answering an object's latest
 * signed event as broken, and the latest signed event moving between the plan and the repair's lock.
 */
const faults = vi.hoisted(() => ({
  guardsLeftOff: false,
  writeFails: undefined as Error | undefined,
  verifierRefuses: false,
  wholeFails: undefined as string | undefined,
  chainFails: false,
  latestBroken: undefined as string | undefined,
  /** Trails made past this many answer every signed event by another ID: the plan's own is the first. */
  latestMovesAfter: undefined as number | undefined,
  trailsMade: 0,
}));

/** An event ID no event has: what a moved latest signed event is answered as. */
const ANOTHER_EVENT = '0199a0f0-0000-7000-8000-0000000000ee';

vi.mock('@agentx/core/modules/audit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/core/modules/audit')>();
  return {
    ...actual,
    // The chain's check as the repair makes it before any table's lock, and the log's latest signed events.
    createAuditTrail: (...args: Parameters<typeof actual.createAuditTrail>) => {
      const trail = actual.createAuditTrail(...args);
      faults.trailsMade += 1;
      const broken = { ok: false as const, problem: { reason: 'link' as const, seq: 1n } };
      const moved = faults.latestMovesAfter !== undefined && faults.trailsMade > faults.latestMovesAfter;
      const latestSignedStates: typeof trail.latestSignedStates = async (...asked) =>
        new Map(
          [...(await trail.latestSignedStates(...asked))].map(([id, latest]) => {
            if (id === faults.latestBroken) return [id, { kind: 'broken' as const }];
            return [id, moved && latest.kind === 'signed' ? { ...latest, id: ANOTHER_EVENT } : latest];
          }),
        );
      return {
        ...trail,
        latestSignedStates,
        ...(faults.chainFails ? { verify: () => Promise.resolve(broken) } : {}),
      };
    },
    guardsOn: (...args: Parameters<typeof actual.guardsOn>) =>
      faults.guardsLeftOff ? Promise.resolve() : actual.guardsOn(...args),
    writeStateRow: (...args: Parameters<typeof actual.writeStateRow>) =>
      faults.writeFails === undefined ? actual.writeStateRow(...args) : Promise.reject(faults.writeFails),
    withRepairStates: <Result>(...[db, org, services, work]: Parameters<typeof actual.withRepairStates<Result>>) =>
      actual.withRepairStates(db, org, services, (tx, states) =>
        work(tx, {
          ...states,
          verifiedStates: async (...args: Parameters<typeof states.verifiedStates>) => {
            const checks = await states.verifiedStates(...args);
            if (!faults.verifierRefuses) return checks;
            return new Map(
              [...checks.keys()].map((id) => [id, { outcome: 'tampered' as const, sign: 'seal' as const }]),
            );
          },
          // The whole check of the tables written, failing on the one that names the table faulted.
          verifyAll: (async (...args: Parameters<typeof states.verifyAll>) => {
            const [, org, tables] = args;
            if (faults.wholeFails === undefined || !tables.some(({ table }) => table === faults.wholeFails)) {
              return states.verifyAll(...args);
            }
            return {
              outcome: 'tampered',
              findings: [{ orgId: org, subjectType: 'invitation', objectId: ANOTHER_EVENT, sign: 'seal' }],
            };
          }) as typeof states.verifyAll,
        }),
      ),
  };
});

afterEach(() => {
  faults.guardsLeftOff = false;
  faults.writeFails = undefined;
  faults.verifierRefuses = false;
  faults.wholeFails = undefined;
  faults.chainFails = false;
  faults.latestBroken = undefined;
  faults.latestMovesAfter = undefined;
});

const server = inject('postgres');
const keyFiles = writeTestKeys(['audit-mac', 'field-encryption', 'operator-signing']);
const keys = loadKeys({ directory: keyFiles.directory, current: {} }, [
  'audit-mac',
  'field-encryption',
  'operator-signing',
]);

let live: TestDatabase;
let copy: TestDatabase | undefined;
let orgId: string;
let invitationId: string;
let owner: OwnerTamper | undefined;
const open: Database<FirstAdminTables>[] = [];

type Role = 'app' | 'operator' | 'owner';

function on(database: TestDatabase, role: Role, readOnly = false): Database<FirstAdminTables> {
  const handle = createDatabase<FirstAdminTables>(
    { ...database.connection(role), maxConnections: 1, readOnly },
    testLogger(),
  );
  open.push(handle);
  return handle;
}

function theCopy(): TestDatabase {
  if (copy === undefined) throw new Error('No copy made yet.');
  return copy;
}

/** The audit trail the app records with. */
const actualTrail = () => createAuditTrail({ keys, ids: uuidV7Ids });

const services = (capture?: LogCapture) => ({ keys, ids: uuidV7Ids, logger: testLogger(capture) });

async function closeAll(): Promise<void> {
  await owner?.end();
  owner = undefined;
  await Promise.all(open.splice(0).map((handle) => handle.destroy()));
}

/** The owner, inside the organisation, on one authority table: the attacker. */
async function ownerOn(table: { table: string; subject: string }): Promise<OwnerTamper> {
  await owner?.end();
  owner = await tamperAsOwner(live, table, orgId);
  return owner;
}

/** The copy, as the drill's restore makes it: the organisation and its first admin's invitation, untouched. */
async function copied(): Promise<void> {
  await closeAll();
  copy = await live.copy();
}

/** Every authority object of the organisation, as clearing the hold checks them: the app's own verifier. */
const verifiedNow = () =>
  withSignedStates(on(live, 'app'), orgId, services(), (tx, states) =>
    states.verifyAll(tx, orgId, AUTHORITY_TABLES, 10_000, { counted: () => undefined }),
  );

/** The hold as its newest signed event holds it. */
const holdNow = () =>
  withSignedStates(on(live, 'app'), orgId, services(), (tx, states) => states.holdRecord(tx, orgId));

/** The plan as the operator reads it: the owner, read-only on both sides. */
function planned(): Promise<StatePlan> {
  return planStateRecovery({
    copy: on(theCopy(), 'owner', true),
    live: on(live, 'owner', true),
    keys,
    orgId,
    anchor: undefined,
  });
}

const digestNow = async (): Promise<string> => statePlanDigest(await planned(), orgId, undefined);

/** The repair as its job runs it: the copy read-only, the live server as the owner. */
function restore(digest: string, more: Partial<StateRestoreSides> = {}): Promise<StateRestoreOutcome> {
  return restoreStates({
    copy: on(theCopy(), 'owner', true),
    live: on(live, 'owner'),
    keys,
    orgId,
    anchor: undefined,
    digest,
    logger: testLogger(),
    ...more,
  });
}

/** A row as the owner reads it: Postgres's JSON text of it, or undefined where it is gone. */
async function rowOf(table: string, id: string): Promise<string | undefined> {
  const tamper = await ownerOn({ table, subject: 'probe' });
  // One fixed text for the three tables the tests touch, the table named as a value.
  const rows = await tamper.query<{ row: string }>(
    `select r.row from (
       select 'identity.invitations' as name, pg_catalog.to_jsonb(t)::text as row, t.org_id, t.id
       from identity.invitations t
       union all select 'organizations.organizations', pg_catalog.to_jsonb(t)::text, t.org_id, t.id
       from organizations.organizations t
       union all select 'identity.memberships', pg_catalog.to_jsonb(t)::text, t.org_id, t.id
       from identity.memberships t
     ) r where r.name = $3 and r.org_id = $1 and r.id = $2`,
    [orgId, id, table],
  );
  return rows[0]?.row;
}

/** Every trigger of a table, on or off: none is left off by a repair. */
async function triggersOn(table: string): Promise<Record<string, string>> {
  const tamper = await ownerOn({ table, subject: 'probe' });
  const rows = await tamper.query<{ name: string; enabled: string }>(
    `select tgname::text as name, tgenabled::text as enabled from pg_catalog.pg_trigger
     where tgrelid = $1::regclass and not tgisinternal`,
    [table],
  );
  return Object.fromEntries(rows.map(({ name, enabled }) => [name, enabled]));
}

/** Expiry times no invitation is made with: a sealed field changed past the app. */
const LATER = '2099-01-01T00:00:00Z';
const LATER_JSON = '2099-01-01T00:00:00+00:00';
const LATER_STILL = '2098-01-01T00:00:00Z';

const ADMIN = { type: 'user' as const, id: '0199a0f0-0000-7000-8000-0000000000ad' };
const STEP_UP = {
  stepUpChallengeId: '0199a0f0-0000-7000-8000-0000000000c1',
  changeHash: 'ab'.repeat(32),
  methods: 'pwd user mfa',
};

/** The admin's clearing, as the hold-clearing use case makes it: an investigation recorded, then the clear. */
async function clearAsAdmin() {
  const investigationId = uuidV7Ids.next();
  const recorded = await withSignedStates(on(live, 'app'), orgId, services(), (tx, states) =>
    states.recordInvestigation(tx, orgId, {
      id: investigationId,
      actor: ADMIN,
      conclusion: 'CAUSE_REMOVED',
      reference: 'INC-1',
    }),
  );
  if (recorded.outcome !== 'recorded') throw new Error('the hold should be HELD');
  return withSignedStates(on(live, 'app'), orgId, services(), async (tx, states) => {
    const whole = await states.verifyAll(tx, orgId, AUTHORITY_TABLES, 10_000, { counted: () => undefined });
    if (whole.outcome !== 'verified') return whole;
    return states.clearIntegrityHold(tx, orgId, {
      actor: ADMIN,
      holdEventId: recorded.investigation.holdEventId,
      investigationId,
      stepUp: STEP_UP,
    });
  });
}

beforeEach(async () => {
  live = await createTestDatabase(server, { schema: 'migrated' });
  orgId = uuidV7Ids.next();
  invitationId = uuidV7Ids.next();
  const operator = on(live, 'operator');
  await createOrganizationAsOperator(operator, services(), {
    orgId,
    name: `State Restore Test ${orgId.slice(-6)}`,
    release: 'r-1',
    run: null,
  });
  await inviteFirstAdminAsOperator(operator, services(), {
    orgId,
    invitationId,
    email: 'first.admin@example.com',
    tokenHash: Buffer.alloc(32, 7),
    release: 'r-1',
    run: null,
  });
});

afterEach(async () => {
  await closeAll();
  await copy?.drop();
  copy = undefined;
  await live.drop();
});

afterAll(() => {
  keyFiles.remove();
});

describe('PL-29 follow-up: authority rows planned and repaired from the copy, original rows alone', () => {
  it('puts back a changed row past the status guard, keeps the hold, and the admin then clears it', async () => {
    await copied();
    const original = await rowOf(INVITATIONS.table, invitationId);
    const tamper = await ownerOn(INVITATIONS);
    // A status the machine can't move back from (ACCEPTED is an end): only the guard switched off lets it back.
    await tamper.withoutStatusGuard(() => tamper.setColumn(invitationId, 'status', 'ACCEPTED'));
    await tamper.setColumn(invitationId, 'expires_at', LATER);
    expect(await verifiedNow()).toMatchObject({ outcome: 'tampered' });
    expect(await holdNow()).toMatchObject({ outcome: 'held' });
    const plan = await planned();
    expect(plan).toMatchObject({
      ok: true,
      rows: [{ action: 'put_back', id: invitationId, sign: 'seal', copy: original }],
    });
    const outcome = await restore(statePlanDigest(plan, orgId, undefined));
    expect(outcome).toMatchObject({ ok: true });
    expect(await rowOf(INVITATIONS.table, invitationId)).toBe(original);
    expect(await triggersOn(INVITATIONS.table)).toMatchObject({ status_guard: 'O' });
    expect(await verifiedNow()).toMatchObject({ outcome: 'verified' });
    // The hold stays until its admin clears it, with a step-up, once the investigation is recorded.
    expect(await holdNow()).toMatchObject({ outcome: 'held' });
    expect(await clearAsAdmin()).toMatchObject({ outcome: 'cleared' });
    expect(await holdNow()).toMatchObject({ outcome: 'clear' });
  });

  it('puts back a deleted row, in a status the guard would refuse a new row', async () => {
    await copied();
    const original = await rowOf(INVITATIONS.table, invitationId);
    expect(JSON.parse(String(original))).not.toMatchObject({ status: 'DRAFT' });
    await (await ownerOn(INVITATIONS)).deleteRow(invitationId);
    const plan = await planned();
    expect(plan).toMatchObject({ ok: true, rows: [{ action: 'put_back', sign: 'deleted', live: null }] });
    expect(await restore(statePlanDigest(plan, orgId, undefined))).toMatchObject({ ok: true });
    expect(await rowOf(INVITATIONS.table, invitationId)).toBe(original);
    expect(await verifiedNow()).toMatchObject({ outcome: 'verified' });
  });

  it('removes a planted row nothing signed ever made, keeping it whole in the plan', async () => {
    await copied();
    const planted = uuidV7Ids.next();
    const tamper = await ownerOn(INVITATIONS);
    await tamper.query(
      `insert into identity.invitations
       select * from pg_catalog.jsonb_populate_record(null::identity.invitations, (
         select pg_catalog.to_jsonb(i) || pg_catalog.jsonb_build_object('id', $3::text, 'status', 'DRAFT',
           'state_event_id', null, 'state_version', 1)
         from identity.invitations i where i.org_id = $1 and i.id = $2))`,
      [orgId, invitationId, planted],
    );
    const stored = await rowOf(INVITATIONS.table, planted);
    const plan = await planned();
    expect(plan).toMatchObject({
      ok: true,
      rows: [{ action: 'remove', id: planted, sign: 'unsigned', liveEventId: null, live: stored, copy: null }],
    });
    // The plan's file keeps the planted row whole, as evidence.
    const file = statePlanFile(plan, { planId: uuidV7Ids.next(), orgId, release: 'r-1', run: null, anchor: undefined });
    expect(file.toString('utf8').split('\n')[1]).toContain(JSON.stringify(stored));
    expect(await restore(statePlanDigest(plan, orgId, undefined))).toMatchObject({ ok: true });
    expect(await rowOf(INVITATIONS.table, planted)).toBeUndefined();
    expect(await verifiedNow()).toMatchObject({ outcome: 'verified' });
  });

  it('puts back the organisation and an invitation together, in one plan', async () => {
    await copied();
    await (await ownerOn(ORGANIZATIONS)).setColumn(orgId, 'status', 'FROZEN');
    await (await ownerOn(INVITATIONS)).deleteRow(invitationId);
    const plan = await planned();
    expect(plan).toMatchObject({
      ok: true,
      rows: [
        { action: 'put_back', table: ORGANIZATIONS },
        { action: 'put_back', table: INVITATIONS },
      ],
    });
    const outcome = await restore(statePlanDigest(plan, orgId, undefined));
    expect(outcome.ok && stateOutcomeLine(outcome)).toMatchObject({ ok: true, putBack: 2, removed: 0 });
    expect(await verifiedNow()).toMatchObject({ outcome: 'verified' });
  });

  it('plans nothing for an organisation whose rows all verify', async () => {
    await copied();
    const plan = await planned();
    expect(plan).toMatchObject({ ok: true, rows: [] });
    expect(plan.ok && plan.objects).toBeGreaterThanOrEqual(2);
    expect(await restore(statePlanDigest(plan, orgId, undefined))).toMatchObject({ ok: true });
  });
});

describe('PL-29 follow-up: refused, never bent', () => {
  it('refuses a row the live log signed after the copy: restore a later copy', async () => {
    await copied();
    const app = on(live, 'app');
    await withSignedStates(app, orgId, services(), (tx, states) =>
      states.changeStatus(tx, ORGANIZATIONS, { orgId, id: orgId }, 'freeze', {
        actor: ADMIN,
        action: 'organization.frozen',
        details: {},
      }),
    );
    // Frozen since the copy, then put back to ACTIVE past the app: the copy's ACTIVE row is no longer the latest.
    await (await ownerOn(ORGANIZATIONS)).setColumn(orgId, 'status', 'ACTIVE');
    const plan = await planned();
    expect(plan).toEqual({
      ok: false,
      reason: 'newer_than_copy',
      subjectType: ORGANIZATIONS.subject,
      objectId: orgId,
      sign: 'seal',
    });
    expect(await restore(statePlanDigest(plan, orgId, undefined))).toMatchObject({ ok: false, reason: 'plan' });
  });

  it('refuses a stale digest, writing nothing', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER_STILL);
    const before = await rowOf(INVITATIONS.table, invitationId);
    const outcome = await restore(digest);
    expect(outcome).toMatchObject({ ok: false, reason: 'stale' });
    expect(outcome.ok ? undefined : outcome.reason === 'stale' && outcome.digest).toBe(await digestNow());
    expect(await rowOf(INVITATIONS.table, invitationId)).toBe(before);
  });

  it('rolls everything back when a write is refused part-way, the guards on again', async () => {
    await copied();
    await (await ownerOn(ORGANIZATIONS)).setColumn(orgId, 'status', 'FROZEN');
    await (await ownerOn(INVITATIONS)).deleteRow(invitationId);
    const digest = await digestNow();
    const frozen = await rowOf(ORGANIZATIONS.table, orgId);
    // A trigger planted past the app that refuses the invitation's insert, after the organisation is written.
    const tamper = await ownerOn(INVITATIONS);
    await tamper.query('create schema tamper');
    await tamper.query(`create function tamper.refuse_insert() returns trigger language plpgsql as $$
      begin raise exception 'refused' using errcode = 'check_violation'; end $$`);
    await tamper.query(
      'create trigger zz_refuse before insert on identity.invitations for each row execute function tamper.refuse_insert()',
    );
    const outcome = await restore(digest);
    expect(outcome).toEqual({
      ok: false,
      reason: 'write_refused',
      subjectType: INVITATIONS.subject,
      objectId: invitationId,
      code: '23514',
    });
    expect(await rowOf(ORGANIZATIONS.table, orgId)).toBe(frozen);
    expect(await rowOf(INVITATIONS.table, invitationId)).toBeUndefined();
    expect(await triggersOn(ORGANIZATIONS.table)).toMatchObject({ status_guard: 'O' });
    expect(await triggersOn(INVITATIONS.table)).toMatchObject({ status_guard: 'O', zz_refuse: 'O' });
  });

  it('rolls back a row a planted trigger changed as it was written: not the copy’s', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    const tamper = await ownerOn(INVITATIONS);
    await tamper.query('create schema tamper');
    await tamper.query(`create function tamper.raise_role() returns trigger language plpgsql as $$
      begin new.expires_at := new.expires_at + interval '1 day'; return new; end $$`);
    await tamper.query(
      'create trigger aa_raise before update on identity.invitations for each row execute function tamper.raise_role()',
    );
    expect(await restore(digest)).toEqual({
      ok: false,
      reason: 'unverified',
      check: 'written',
      subjectType: INVITATIONS.subject,
      objectId: invitationId,
    });
    expect(JSON.parse(String(await rowOf(INVITATIONS.table, invitationId)))).toMatchObject({ expires_at: LATER_JSON });
  });

  it('refuses a row changed after the plan was made again, under the table’s lock', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    // Another of the owner's sessions changes the row and holds it: the repair's lock on the table waits for it.
    const other: TestClient = await live.connect('owner');
    const monitor: TestClient = await live.connect('admin');
    try {
      await other.query("select pg_catalog.set_config('app.org_id', $1, false)", [orgId]);
      await other.query('begin');
      await other.query('update identity.invitations set expires_at = $3 where org_id = $1 and id = $2', [
        orgId,
        invitationId,
        LATER_STILL,
      ]);
      const repairing = restore(digest);
      await waitUntilQueued(monitor, 1);
      await other.query('commit');
      expect(await repairing).toEqual({
        ok: false,
        reason: 'moved',
        subjectType: INVITATIONS.subject,
        objectId: invitationId,
      });
    } finally {
      await other.end();
      await monitor.end();
    }
  });

  it('refuses while the live chain fails its check: the chain is repaired first', async () => {
    await copied();
    const tamper = await ownerOn(INVITATIONS);
    await tamper.query('delete from audit.events where org_id = $1 and seq = 2', [orgId]);
    expect(await planned()).toMatchObject({ ok: false, reason: 'chain_broken' });
  });

  it('refuses a copy whose chain fails its own check', async () => {
    await copied();
    const broken = await tamperAsOwner(theCopy(), INVITATIONS, orgId);
    await broken.query('delete from audit.events where org_id = $1 and seq = 2', [orgId]);
    await broken.end();
    expect(await planned()).toMatchObject({ ok: false, reason: 'copy_broken' });
  });

  it('refuses a copy that is not an earlier state of the live chain', async () => {
    await copied();
    // The copy grows on its own: its head is then no place on the live chain.
    await withSignedStates(on(theCopy(), 'app'), orgId, services(), (tx, states) =>
      states.changeStatus(tx, ORGANIZATIONS, { orgId, id: orgId }, 'freeze', {
        actor: ADMIN,
        action: 'organization.frozen',
        details: {},
      }),
    );
    await closeAll();
    expect(await planned()).toMatchObject({ ok: false, reason: 'not_grown_from_copy' });
  });

  it('refuses a row the copy can’t vouch for, though nothing newer was signed', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const onCopy = await tamperAsOwner(theCopy(), INVITATIONS, orgId);
    await onCopy.setColumn(invitationId, 'expires_at', LATER_STILL);
    await onCopy.end();
    expect(await planned()).toMatchObject({ ok: false, reason: 'copy_differs', objectId: invitationId });
  });

  it('refuses a planted row the copy holds too', async () => {
    const planted = uuidV7Ids.next();
    const tamper = await ownerOn(INVITATIONS);
    await tamper.query(
      `insert into identity.invitations
       select * from pg_catalog.jsonb_populate_record(null::identity.invitations, (
         select pg_catalog.to_jsonb(i) || pg_catalog.jsonb_build_object('id', $3::text, 'status', 'DRAFT',
           'state_event_id', null, 'state_version', 1)
         from identity.invitations i where i.org_id = $1 and i.id = $2))`,
      [orgId, invitationId, planted],
    );
    await copied();
    expect(await planned()).toMatchObject({ ok: false, reason: 'unrepairable', objectId: planted, sign: 'unsigned' });
  });

  it('refuses a copy whose table has other columns than the live one', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const onCopy = await tamperAsOwner(theCopy(), INVITATIONS, orgId);
    await onCopy.query('alter table identity.invitations add column note text');
    await onCopy.end();
    expect(await planned()).toMatchObject({ ok: false, reason: 'schema_differs', objectId: invitationId });
  });

  it('refuses a plan wider than one plan writes', async () => {
    await copied();
    await (await ownerOn(ORGANIZATIONS)).setColumn(orgId, 'status', 'FROZEN');
    await (await ownerOn(INVITATIONS)).deleteRow(invitationId);
    const plan = await planStateRecovery({
      copy: on(theCopy(), 'owner', true),
      live: on(live, 'owner', true),
      keys,
      orgId,
      anchor: undefined,
      mostRows: 1,
      pageSize: 1,
    });
    expect(plan).toMatchObject({ ok: false, reason: 'too_large', objectId: invitationId });
  });
});

describe('PL-29 follow-up: the plan’s and repair’s records', () => {
  it('a refused plan’s file is its summary alone, naming why', () => {
    const file = statePlanFile(
      { ok: false, reason: 'chain_broken', problem: 'link at 2' },
      { planId: 'p', orgId: 'o', release: 'r', run: null, anchor: undefined },
    );
    const lines = file.toString('utf8').trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(String(lines[0]))).toMatchObject({ k: 'state_plan', ok: false, reason: 'chain_broken' });
  });

  it.each<[StateRestoreOutcome, Record<string, unknown>]>([
    [
      { ok: false, reason: 'stale', digest: 'ab' },
      { reason: 'stale', digestNow: 'ab' },
    ],
    [
      { ok: false, reason: 'moved', subjectType: 'agent', objectId: 'x' },
      { reason: 'moved', objectId: 'x' },
    ],
    [
      { ok: false, reason: 'busy' },
      { reason: 'busy', subjectType: null },
    ],
    [
      { ok: false, reason: 'write_refused', subjectType: 'agent', objectId: 'x', code: '23503' },
      { reason: 'write_refused', code: '23503' },
    ],
    [
      { ok: false, reason: 'unverified', check: 'chain' },
      { reason: 'unverified', check: 'chain', subjectType: null, sign: null },
    ],
    [
      { ok: false, reason: 'plan', plan: { ok: false, reason: 'backlog', subjectType: 'agent', objectId: 'x' } },
      { reason: 'plan', planRefused: 'backlog', sign: null, problem: null },
    ],
  ])('says %o in plain facts', (outcome, line) => {
    expect(stateOutcomeLine(outcome)).toMatchObject({ ok: false, ...line });
    const facts = { restoreId: 'r', planId: 'p', orgId: 'o', digest: 'd', release: 'r-1', run: null };
    expect(JSON.parse(stateRestoreFile(outcome, facts).toString('utf8'))).toMatchObject({
      k: 'state_restore',
      ...line,
    });
  });

  it('removes a planted member and puts back an invitation, in one repair', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const memberId = uuidV7Ids.next();
    const planter = await ownerOn(MEMBERSHIPS);
    await planter.query(
      "insert into identity.users (id, issuer, subject, created_at) values ($1, 'https://idp.example', 'planted', now())",
      [ADMIN.id],
    );
    await planter.query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
      ADMIN.id,
      orgId,
      memberId,
    ]);
    await planter.query(
      `insert into identity.memberships (org_id, id, user_id, role, status, joined_at)
       values ($1, $2, $3, 'admin', 'ACTIVE', now())`,
      [orgId, memberId, ADMIN.id],
    );
    const plan = await planned();
    expect(plan).toMatchObject({
      ok: true,
      rows: [
        { action: 'put_back', table: INVITATIONS, id: invitationId },
        { action: 'remove', table: MEMBERSHIPS, id: memberId },
      ],
    });
    expect(await restore(statePlanDigest(plan, orgId, undefined))).toMatchObject({ ok: true });
    expect(await rowOf(MEMBERSHIPS.table, memberId)).toBeUndefined();
    expect(await verifiedNow()).toMatchObject({ outcome: 'verified' });
  });

  it('checks the tables it leaves alone before it locks any, and a failure there touches no hold', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    const capture = new LogCapture();
    // Its own session: rowOf below ends the shared one.
    const watcher = await tamperAsOwner(live, INVITATIONS, orgId);
    const counts = async () =>
      (
        await watcher.query<{ events: string; waiting: string }>(
          `select (select pg_catalog.count(*) from audit.events where org_id = $1)::text as events,
                  (select pg_catalog.count(*) from directory.holds_waiting where org_id = $1)::text as waiting`,
          [orgId],
        )
      )[0];
    const before = await counts();
    // The organisation's row, which the plan leaves alone, tampered with in another session and held: the repair's
    // check of the tables it leaves alone waits for it, and holds no table's lock while it waits.
    const other: TestClient = await live.connect('owner');
    const monitor: TestClient = await live.connect('admin');
    try {
      await other.query("select pg_catalog.set_config('app.org_id', $1, false)", [orgId]);
      await other.query('begin');
      await other.query("update organizations.organizations set status = 'FROZEN' where org_id = $1 and id = $1", [
        orgId,
      ]);
      const repairing = restore(digest, { logger: testLogger(capture) });
      const [waiting] = await waitUntilQueued(monitor, 1);
      const tableLocks = await monitor.query<{ mode: string }>(
        `select l.mode from pg_catalog.pg_locks l
         where l.pid = $1 and l.relation = 'identity.invitations'::regclass and l.mode = 'ShareRowExclusiveLock'`,
        [waiting],
      );
      expect(tableLocks).toEqual([]);
      await other.query('commit');
      expect(await repairing).toEqual({
        ok: false,
        reason: 'unverified',
        check: 'untouched',
        subjectType: ORGANIZATIONS.subject,
        objectId: orgId,
        sign: 'seal',
      });
    } finally {
      await other.end();
      await monitor.end();
    }
    expect(JSON.parse(String(await rowOf(INVITATIONS.table, invitationId)))).toMatchObject({ expires_at: LATER_JSON });
    // The alarm line is the record; no hold event and no row of the holds waiting were written.
    expect(capture.lines().some((line) => line.event === 'audit.integrity_failed')).toBe(true);
    expect(await counts()).toEqual(before);
    await watcher.end();
  });

  it('refuses as busy a row another session holds for update in a table it writes, though the plan leaves it alone', async () => {
    // A second invitation, signed as the first: the plan touches only the first.
    const second = uuidV7Ids.next();
    await inviteFirstAdminAsOperator(on(live, 'operator'), services(), {
      orgId,
      invitationId: second,
      email: 'second.admin@example.com',
      tokenHash: Buffer.alloc(32, 8),
      release: 'r-1',
      run: null,
    });
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const plan = await planned();
    expect(plan).toMatchObject({ ok: true, rows: [{ id: invitationId }] });
    // The untouched row locked for update: the repair's check of the table it wrote waits for it past its second.
    const other: TestClient = await live.connect('owner');
    try {
      await other.query("select pg_catalog.set_config('app.org_id', $1, false)", [orgId]);
      await other.query('begin');
      await other.query('select 1 from identity.invitations where org_id = $1 and id = $2 for update', [orgId, second]);
      const started = Date.now();
      const outcome = await restore(statePlanDigest(plan, orgId, undefined));
      expect(outcome).toEqual({ ok: false, reason: 'busy' });
      expect(Date.now() - started).toBeLessThan(5000);
      // What its outcome record holds: the refusal in plain facts.
      const facts = { restoreId: 'r', planId: 'p', orgId, digest: 'd', release: 'r-1', run: null };
      expect(JSON.parse(stateRestoreFile(outcome, facts).toString('utf8'))).toMatchObject({
        k: 'state_restore',
        ok: false,
        reason: 'busy',
        subjectType: null,
      });
    } finally {
      await other.query('rollback');
      await other.end();
    }
    expect(await triggersOn(INVITATIONS.table)).toMatchObject({ status_guard: 'O' });
    expect(JSON.parse(String(await rowOf(INVITATIONS.table, invitationId)))).toMatchObject({ expires_at: LATER_JSON });
  });

  it('refuses as busy, within a few seconds, a table another organisation is writing', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    // A write in progress on the table, whatever its organisation: it holds the table's ROW EXCLUSIVE lock.
    const other: TestClient = await live.connect('owner');
    try {
      await other.query('begin');
      await other.query('lock table identity.invitations in row exclusive mode');
      const started = Date.now();
      expect(await restore(digest)).toEqual({ ok: false, reason: 'busy', subjectType: INVITATIONS.subject });
      expect(Date.now() - started).toBeLessThan(5000);
    } finally {
      await other.query('rollback');
      await other.end();
    }
    expect(await triggersOn(INVITATIONS.table)).toMatchObject({ status_guard: 'O' });
  });
});

describe('PL-29 follow-up: what the database alone does not show here', () => {
  it('rolls back a repair that would leave a guard off', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    faults.guardsLeftOff = true;
    expect(await restore(digest)).toEqual({
      ok: false,
      reason: 'unverified',
      check: 'guards',
      subjectType: INVITATIONS.subject,
    });
    faults.guardsLeftOff = false;
    expect(await triggersOn(INVITATIONS.table)).toMatchObject({ status_guard: 'O' });
    expect(JSON.parse(String(await rowOf(INVITATIONS.table, invitationId)))).toMatchObject({ expires_at: LATER_JSON });
  });

  it('throws a write’s failure that is not the database refusing it, writing nothing', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    faults.writeFails = new Error('the connection was lost');
    await expect(restore(digest)).rejects.toThrow('the connection was lost');
  });

  it('rolls back a row the verifier still reads tampered with, naming its sign', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    faults.verifierRefuses = true;
    expect(await restore(digest)).toEqual({
      ok: false,
      reason: 'unverified',
      check: 'state',
      subjectType: INVITATIONS.subject,
      objectId: invitationId,
      sign: 'seal',
    });
  });

  it('refuses, writing nothing, when the chain fails its check before any table is locked', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    faults.chainFails = true;
    expect(await restore(digest)).toEqual({ ok: false, reason: 'unverified', check: 'chain' });
    faults.chainFails = false;
    expect(JSON.parse(String(await rowOf(INVITATIONS.table, invitationId)))).toMatchObject({ expires_at: LATER_JSON });
  });

  it('rolls back when the whole check of the tables written finds a record tampered with', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    faults.wholeFails = INVITATIONS.table;
    expect(await restore(digest)).toEqual({
      ok: false,
      reason: 'unverified',
      check: 'whole',
      subjectType: 'invitation',
      objectId: ANOTHER_EVENT,
      sign: 'seal',
    });
    faults.wholeFails = undefined;
    expect(JSON.parse(String(await rowOf(INVITATIONS.table, invitationId)))).toMatchObject({ expires_at: LATER_JSON });
    expect(await triggersOn(INVITATIONS.table)).toMatchObject({ status_guard: 'O' });
  });

  it('refuses a plan where the live log answers the tampered object as broken', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    faults.latestBroken = invitationId;
    expect(await planned()).toEqual({
      ok: false,
      reason: 'unrepairable',
      subjectType: INVITATIONS.subject,
      objectId: invitationId,
      sign: 'log',
    });
  });

  it('refuses as moved when the latest signed event changes between the plan and the repair', async () => {
    await copied();
    await (await ownerOn(INVITATIONS)).setColumn(invitationId, 'expires_at', LATER);
    const digest = await digestNow();
    // The repair's plan made again uses the next trail; every trail after it answers the event by another ID.
    faults.trailsMade = 0;
    faults.latestMovesAfter = 1;
    expect(await restore(digest)).toEqual({
      ok: false,
      reason: 'moved',
      subjectType: INVITATIONS.subject,
      objectId: invitationId,
    });
    faults.latestMovesAfter = undefined;
    expect(JSON.parse(String(await rowOf(INVITATIONS.table, invitationId)))).toMatchObject({ expires_at: LATER_JSON });
  });
});

describe('PL-29 follow-up: an object the app refuses to judge', () => {
  it('refuses a plan with an object that has a backlog of events since its newest signed one', async () => {
    // More events about the invitation than one read of its latest signed state takes: the app refuses to judge it.
    const trail = actualTrail();
    await withSignedStates(on(live, 'app'), orgId, services(), async (tx) => {
      for (let step = 1; step <= 1001; step += 1) {
        await trail.record(tx, orgId, {
          actor: ADMIN,
          action: 'invitation.viewed',
          subject: { type: INVITATIONS.subject, id: invitationId, version: 1 },
          details: { step },
        });
      }
    });
    await copied();
    expect(await planned()).toEqual({
      ok: false,
      reason: 'backlog',
      subjectType: INVITATIONS.subject,
      objectId: invitationId,
    });
  }, 120_000);
});

/** A row the world below seeds, by its table and ID. */
type Seeded = readonly [SignedStateTable, string];

/**
 * An agent, its key, a funding source, a supplier and its version, a mandate
 * with two versions, and an approved spend request, made past the app as the
 * core's tests make them (seed-rows.helper.test.ts), each then signed as the
 * app signs a new row (record from `new`, its fields as they stand), so every
 * one verifies: the tables whose guards an original put back meets beyond the
 * status guard (made_once, fixed_at_creation, decided_move, carried_version).
 */
async function seededWorld() {
  const admin = live.as('admin');
  const at = new Date('2026-11-01T08:00:00Z');
  const id = () => uuidV7Ids.next();
  const world = {
    agent: id(),
    key: id(),
    link: id(),
    source: id(),
    supplier: id(),
    supplierVersion: id(),
    mandate: id(),
    version: id(),
    later: id(),
    request: id(),
  };
  await admin.query(
    `insert into agents.agents (org_id, id, name, owner, status, scopes, created_at)
     values ($1, $2, 'Purchasing agent', $3, 'ACTIVE', 'requests:write', $4)`,
    [orgId, world.agent, id(), at],
  );
  await admin.query('insert into directory.agent_keys (key_id, org_id) values ($1, $2)', [world.key, orgId]);
  await admin.query(
    `insert into agents.agent_keys (org_id, id, agent_id, status, scopes, secret_mac, secret_key_version, expires_at,
       created_at)
     values ($1, $2, $3, 'ACTIVE', 'requests:write', $4, 1, '2027-10-08T08:00:00Z', $5)`,
    [orgId, world.key, world.agent, 'c'.repeat(64), at],
  );
  await admin.query(
    `insert into funding_sources.links (org_id, id, started_by, partner, session_ref, expires_at, created_at)
     values ($1, $2, $3, 'fake', 'session-1', $5, $4)`,
    [orgId, world.link, id(), at, new Date(at.getTime() + 86_400_000)],
  );
  await admin.query(
    `insert into funding_sources.sources (org_id, id, link_id, partner, external_ref, status, availability,
       consent_status, account_consent_id, consent_expires_at, currency, limit_period, max_payment_minor,
       max_period_minor, max_period_payments, holder_name, account_type, hint, partner_changed_at, created_at)
     values ($1, $2, $3, 'fake', $4, 'ACTIVE', 'ACTIVE', 'Authorized', 'consent-1', '2027-10-06T08:00:00Z', 'AED',
       'month', 5000000, 20000000, 100, 'Acme Trading LLC', 'sme', 'AE…1234', $5, $5)`,
    [orgId, world.source, world.link, `acct-${world.source}`, at],
  );
  await admin.query(
    `with supplier as (
       insert into suppliers.suppliers (org_id, id, status, current_version_id, created_at)
       values ($1, $2, 'UNVERIFIED', $3, $4) returning org_id)
     insert into suppliers.supplier_versions (org_id, id, supplier_id, version, display_name, contacts,
       phone_ciphertext, contacts_key_version, phone_since, source_kind, source_ref, entered_by, entered_at)
     select org_id, $3, $2, 1, 'Gulf Office Supplies LLC', 'phone',
       pg_catalog.decode(pg_catalog.repeat('00', 40), 'hex'), 1, $4, 'registry', 'trade-licence-1', $2, $4
     from supplier`,
    [orgId, world.supplier, world.supplierVersion, at],
  );
  // The mandate and its first version in one statement, as each names the other; its second version beside it.
  await admin.query(
    `with mandate as (
       insert into mandates.mandates (org_id, id, agent_id, time_zone, split_window_hours, status, pending_version_id,
         created_at)
       values ($1, $2, $3, 'Asia/Dubai', 24, 'PENDING_ACCEPTANCE', $4, $9) returning org_id)
     insert into mandates.versions (org_id, id, mandate_id, version, purpose, currency, per_order_limit_minor,
       monthly_limit_minor, approval_threshold_minor, supplier_ids, funding_source_id, split_check, consent_limits,
       terms_hash, drafted_by, drafted_at)
     select org_id, $4::uuid, $2::uuid, 1, 'Office supplies', 'AED', 500000, 2000000, 100000, $6::text, $7::uuid, 'on',
       'strict', $8::text, $3::uuid, $9::timestamptz from mandate
     union all
     select org_id, $5::uuid, $2::uuid, 2, 'Office supplies', 'AED', 500000, 2000000, 100000, $6::text, $7::uuid, 'on',
       'strict', $8::text, $3::uuid, $9::timestamptz from mandate`,
    [orgId, world.mandate, world.agent, world.version, world.later, world.supplier, world.source, 'a'.repeat(64), at],
  );
  await admin.query(
    `insert into spend_requests.requests (org_id, id, agent_id, agent_key_id, mandate_id, mandate_version_id,
       supplier_id, supplier_version_id, funding_source_id, amount_minor, currency, purpose, order_reference,
       idempotency_key, input_hash, input_hash_key_version, decision, reason_codes, status, created_at)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 25000, 'AED', 'Printer paper', 'PO-1', $10, $11, 1, 'ALLOW', null,
       'VALIDATING', $12)`,
    [
      orgId,
      world.request,
      world.agent,
      world.key,
      world.mandate,
      world.version,
      world.supplier,
      world.supplierVersion,
      world.source,
      id(),
      'd'.repeat(64),
      at,
    ],
  );
  // Allowed, as its decision says: the request a payment would follow.
  await admin.query("update spend_requests.requests set status = 'APPROVED' where org_id = $1 and id = $2", [
    orgId,
    world.request,
  ]);
  const rows: readonly Seeded[] = [
    [AGENTS, world.agent],
    [AGENT_KEYS, world.key],
    [SOURCES, world.source],
    [SUPPLIERS, world.supplier],
    [SUPPLIER_VERSIONS, world.supplierVersion],
    [MANDATES, world.mandate],
    [MANDATE_VERSIONS, world.version],
    [MANDATE_VERSIONS, world.later],
    [SPEND_REQUESTS, world.request],
  ];
  // Each in a transaction of its own: recording takes the chain head's lock, after which no row is locked.
  for (const [table, rowId] of rows) {
    await withSignedStates(on(live, 'app'), orgId, services(), async (tx, states) => {
      const read = (await readSignedRows(tx, table, orgId, [rowId], 'none')).get(rowId);
      if (read?.outcome !== 'found') throw new Error(`The seeded ${table.subject} can't be read`);
      await states.record(tx, table, { orgId, id: rowId }, 'new', Object.fromEntries(read.fields), {
        actor: ADMIN,
        action: `${table.subject}.created`,
        details: {},
      });
    });
  }
  return world;
}

/** Changes a row as the owner, every trigger of its table off as an attacker would have them: the statement given. */
async function tamperedPastEveryGuard(table: string, statement: string, values: readonly unknown[]): Promise<void> {
  const owner = await live.connect('owner');
  try {
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [orgId]);
    await owner.query('begin');
    // The table is one of the product's own constants, quoted part by part.
    const quoted = table
      .split('.')
      .map((part) => `"${part}"`)
      .join('.');
    // eslint-disable-next-line agentx/no-string-built-sql -- The table is a fixed constant, quoted above.
    await owner.query(`alter table ${quoted} disable trigger user`);
    // eslint-disable-next-line agentx/no-string-built-sql -- The caller's statement is fixed text with bound values.
    await owner.query(statement, values);
    // eslint-disable-next-line agentx/no-string-built-sql -- The table is a fixed constant, quoted above.
    await owner.query(`alter table ${quoted} enable trigger user`);
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

/** A row of the world as Postgres's JSON text of it, read as the owner. */
async function worldRow(table: string, rowId: string): Promise<string | undefined> {
  const tamper = await ownerOn({ table, subject: 'probe' });
  const rows = await tamper.query<{ row: string }>(
    `select r.row from (
       select 'mandates.versions' as name, pg_catalog.to_jsonb(t)::text as row, t.org_id, t.id from mandates.versions t
       union all select 'mandates.mandates', pg_catalog.to_jsonb(t)::text, t.org_id, t.id from mandates.mandates t
       union all select 'spend_requests.requests', pg_catalog.to_jsonb(t)::text, t.org_id, t.id
       from spend_requests.requests t
     ) r where r.name = $3 and r.org_id = $1 and r.id = $2`,
    [orgId, rowId, table],
  );
  return rows[0]?.row;
}

describe('PL-29 follow-up: originals put back past every guard the database holds', () => {
  it('puts back a made-once mandate version, a mandate fixed at creation, and a decided, carried spend request', async () => {
    const world = await seededWorld();
    expect(await verifiedNow()).toMatchObject({ outcome: 'verified' });
    await copied();
    const originals = {
      version: await worldRow(MANDATE_VERSIONS.table, world.version),
      mandate: await worldRow(MANDATES.table, world.mandate),
      request: await worldRow(SPEND_REQUESTS.table, world.request),
    };
    // A made-once version's limit raised; a mandate's time zone, fixed when it was made, moved; a request moved
    // back to deciding, its decision a denial and its version another of its mandate's. Put back, each meets its
    // guards: made_once; fixed_at_creation; and the request's status guard, decided_move, fixed_at_creation and
    // carried_version together.
    await tamperedPastEveryGuard(
      MANDATE_VERSIONS.table,
      'update mandates.versions set per_order_limit_minor = 1500000 where org_id = $1 and id = $2',
      [orgId, world.version],
    );
    await tamperedPastEveryGuard(
      MANDATES.table,
      "update mandates.mandates set time_zone = 'Europe/London' where org_id = $1 and id = $2",
      [orgId, world.mandate],
    );
    await tamperedPastEveryGuard(
      SPEND_REQUESTS.table,
      `update spend_requests.requests set status = 'VALIDATING', decision = 'DENY', reason_codes = 'APPROVAL_THRESHOLD',
       mandate_version_id = $3
       where org_id = $1 and id = $2`,
      [orgId, world.request, world.later],
    );
    expect(await verifiedNow()).toMatchObject({ outcome: 'tampered' });
    const plan = await planned();
    expect(plan).toMatchObject({
      ok: true,
      rows: [
        { action: 'put_back', table: MANDATES, id: world.mandate },
        { action: 'put_back', table: MANDATE_VERSIONS, id: world.version },
        { action: 'put_back', table: SPEND_REQUESTS, id: world.request },
      ],
    });
    expect(await restore(statePlanDigest(plan, orgId, undefined))).toMatchObject({ ok: true });
    expect(await worldRow(MANDATE_VERSIONS.table, world.version)).toBe(originals.version);
    expect(await worldRow(MANDATES.table, world.mandate)).toBe(originals.mandate);
    expect(await worldRow(SPEND_REQUESTS.table, world.request)).toBe(originals.request);
    expect(await verifiedNow()).toMatchObject({ outcome: 'verified' });
    for (const table of [MANDATE_VERSIONS.table, MANDATES.table, SPEND_REQUESTS.table]) {
      const triggers = await triggersOn(table);
      expect(Object.values(triggers).every((state) => state === 'O')).toBe(true);
    }
  });
});
