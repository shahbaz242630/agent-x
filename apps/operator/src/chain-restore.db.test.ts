// 4D2e E10 (PL-29): a chain repaired from its recovery plan, against a real
// Postgres. The copy is made as a restore makes one (TestDatabase.copy), the
// live chain damaged as the database's superuser would, past every wall and
// holding none of the app's keys; the repair writes as the owner. It writes
// only the copy's original rows, in one transaction, onto the live chain as
// the plan read it, and checks the whole chain before it commits. Every race
// here is lined up with a held lock (waitUntilQueued), never left to chance.
import { type AuditEvent, chainRowsAlone, createAuditTrail } from '@agentx/core/modules/audit';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import {
  createTestDatabase,
  type TestClient,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { fingerprintOf, planChainRecovery, planDigest, type RecoveryPlan } from './chain-recovery.ts';
import { outcomeLine, restoreChain, type RestoreOutcome, restoreFile, type RestoreSides } from './chain-restore.ts';
import { createOrganizationAsOperator, type OperatorTables } from './create-organization.ts';

const server = inject('postgres');
const keyFiles = writeTestKeys(['audit-mac', 'field-encryption', 'operator-signing']);
const keys = loadKeys({ directory: keyFiles.directory, current: {} }, [
  'audit-mac',
  'field-encryption',
  'operator-signing',
]);
const trail = createAuditTrail({ keys, ids: uuidV7Ids });

let live: TestDatabase;
let copy: TestDatabase | undefined;
let orgId: string;
const open: Database<OperatorTables>[] = [];

type Role = 'app' | 'operator' | 'owner';

function on(database: TestDatabase, role: Role, readOnly = false): Database<OperatorTables> {
  const handle = createDatabase<OperatorTables>(
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

const USER = '0199a0f0-0000-7000-8000-0000000000aa';
const probe = (step: number): AuditEvent => ({
  actor: { type: 'user', id: USER },
  action: 'probe.stepped',
  subject: { type: 'probe', id: USER, version: step },
  details: { step },
});

async function record(database: TestDatabase, count: number, org = orgId): Promise<void> {
  await withTenant(on(database, 'app'), org, async (tx) => {
    for (let step = 1; step <= count; step += 1) await trail.record(tx, org, probe(step));
  });
}

async function tamper(database: TestDatabase, change: (admin: TestClient) => Promise<unknown>): Promise<void> {
  const admin = await database.connect('admin');
  try {
    await admin.query('set session_replication_role = replica');
    await change(admin);
  } finally {
    await admin.end();
  }
}

interface HeadRow {
  readonly seq: string;
  readonly hash: Buffer;
  readonly mac: Buffer;
  readonly mac_key_version: number;
}

async function headOf(database: TestDatabase, org = orgId): Promise<HeadRow> {
  let row: HeadRow | undefined;
  await tamper(database, async (admin) => {
    [row] = await admin.query<HeadRow>('select seq, hash, mac, mac_key_version from audit.heads where org_id = $1', [
      org,
    ]);
  });
  if (row === undefined) throw new Error('The chain has no head');
  return row;
}

async function windBack(earlier: HeadRow): Promise<void> {
  await tamper(live, async (admin) => {
    await admin.query('delete from audit.events where org_id = $1 and seq > $2', [orgId, earlier.seq]);
    await admin.query('update audit.heads set seq = $2, hash = $3, mac = $4, mac_key_version = $5 where org_id = $1', [
      orgId,
      earlier.seq,
      earlier.hash,
      earlier.mac,
      earlier.mac_key_version,
    ]);
  });
}

const deleteEvent = (database: TestDatabase, seq: bigint, org = orgId) =>
  tamper(database, (admin) => admin.query('delete from audit.events where org_id = $1 and seq = $2', [org, seq]));

const editEvent = (database: TestDatabase, seq: bigint) =>
  tamper(database, (admin) =>
    admin.query(`update audit.events set details = '{"step":99}' where org_id = $1 and seq = $2`, [orgId, seq]),
  );

async function closeAll(): Promise<void> {
  await Promise.all(open.splice(0).map((handle) => handle.destroy()));
}

async function copied(events: number): Promise<bigint> {
  await record(live, events);
  await closeAll();
  copy = await live.copy();
  return BigInt((await headOf(live)).seq);
}

/** The plan as the operator reads it: the app's role, read-only on both sides. */
function planned(discardFork = false): Promise<RecoveryPlan> {
  return planChainRecovery({
    copy: on(theCopy(), 'operator', true),
    live: on(live, 'operator', true),
    keys,
    orgId,
    anchor: undefined,
    discardFork,
  });
}

/** The digest of the plan the operator reads now. */
async function digestNow(discardFork = false): Promise<string> {
  return planDigest(await planned(discardFork), orgId, undefined);
}

/** The repair as its job runs it: the copy read-only, the live server as the owner. */
function restore(digest: string, more: Partial<RestoreSides> = {}): Promise<RestoreOutcome> {
  return restoreChain({
    copy: on(theCopy(), 'owner', true),
    live: on(live, 'owner'),
    keys,
    orgId,
    anchor: undefined,
    digest,
    discardFork: false,
    ...more,
  });
}

/** Every row of the chain and its head, as stored: whether anything at all was written. */
const snapshot = (database: TestDatabase, org = orgId) => fingerprintOf({ keys }, on(database, 'operator', true), org);

const verifiedLive = (org = orgId) => trail.verifyAlone(on(live, 'operator', true), org, undefined);

beforeEach(async () => {
  live = await createTestDatabase(server, { schema: 'migrated' });
  orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    on(live, 'operator'),
    { keys, ids: uuidV7Ids, logger: testLogger() },
    { orgId, name: `Chain Restore Test ${orgId.slice(-6)}`, release: 'r-1', run: null },
  );
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

describe('SEC-DB-12 PL-29 a chain repaired from its plan, original rows alone', () => {
  it('puts back a row deleted from the middle: the chain whole again, the copy’s row exactly', async () => {
    await copied(3);
    await deleteEvent(live, 2n);
    expect(await verifiedLive()).toMatchObject({ ok: false });
    const outcome = await restore(await digestNow());
    expect(outcome).toMatchObject({ ok: true });
    // The repaired head, by its number and hash: the place a rebase names (4D2e E11).
    expect(outcome.ok && outcomeLine(outcome)).toMatchObject({
      putBack: 1,
      replaced: 0,
      removed: 0,
      endsAt: outcome.ok ? outcome.plan.endsAt.seq.toString() : '',
      endsAtHash: outcome.ok ? outcome.plan.endsAt.hash.toString('hex') : '',
    });
    expect(outcome.ok && outcome.plan.endsAt.hash.toString('hex')).toMatch(/^[0-9a-f]{64}$/);
    expect(await verifiedLive()).toMatchObject({ ok: true });
    expect(await snapshot(live)).toBe(await snapshot(theCopy()));
  });

  it('puts the original in place of an edited row, and back the events and head of a chain wound back', async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(3);
    await editEvent(live, 1n);
    await windBack(earlier);
    const outcome = await restore(await digestNow());
    expect(outcome.ok && outcomeLine(outcome)).toMatchObject({ putBack: 3, replaced: 1, headReplaced: true });
    expect(await verifiedLive()).toMatchObject({ ok: true });
    expect(await snapshot(live)).toBe(await snapshot(theCopy()));
  });

  it("puts back an operator's signature deleted, as the copy holds it", async () => {
    await copied(1);
    await tamper(live, (admin) =>
      admin.query('delete from audit.operator_signatures where org_id = $1 and seq = 1', [orgId]),
    );
    expect(await verifiedLive()).toMatchObject({ ok: false });
    expect(await restore(await digestNow())).toMatchObject({ ok: true });
    expect(await verifiedLive()).toMatchObject({ ok: true });
    expect(await snapshot(live)).toBe(await snapshot(theCopy()));
  });

  it("takes away a stray signature where the copy's event has none (an operator's event from before signing)", async () => {
    // As if 0079 ran with this chain past its first event, which the operator recorded unsigned.
    await tamper(live, async (admin) => {
      await admin.query('insert into audit.operator_signing_starts (org_id, signed_from) values ($1, 2)', [orgId]);
      await admin.query('delete from audit.operator_signatures where org_id = $1 and seq = 1', [orgId]);
    });
    await copied(1);
    expect(await verifiedLive()).toMatchObject({ ok: true });
    // A signature that isn't the operator's, put beside it: now it reads as unsealed.
    await tamper(live, (admin) =>
      admin.query('insert into audit.operator_signatures (org_id, seq, signature, key_version) values ($1, 1, $2, 1)', [
        orgId,
        Buffer.alloc(64, 7),
      ]),
    );
    expect(await verifiedLive()).toMatchObject({ ok: false });
    expect(await restore(await digestNow())).toMatchObject({ ok: true });
    expect(await verifiedLive()).toMatchObject({ ok: true });
    expect(await snapshot(live)).toBe(await snapshot(theCopy()));
  });

  it('removes rows that were never the app’s, past a whole head', async () => {
    const head = await copied(2);
    await tamper(live, (admin) =>
      admin.query(
        `insert into audit.events
         select org_id, $2, gen_random_uuid(), recorded_at, actor_type, actor_id, action, subject_type, subject_id,
                subject_version, details, prev_hash, hash, mac, mac_key_version
         from audit.events where org_id = $1 and seq = 2`,
        [orgId, head + 1n],
      ),
    );
    const outcome = await restore(await digestNow());
    expect(outcome.ok && outcomeLine(outcome)).toMatchObject({ putBack: 0, replaced: 0, removed: 1 });
    expect(await snapshot(live)).toBe(await snapshot(theCopy()));
  });

  it('repairs organisation A alone: B, damaged too, is left exactly as it was', async () => {
    const other = uuidV7Ids.next();
    await createOrganizationAsOperator(
      on(live, 'operator'),
      { keys, ids: uuidV7Ids, logger: testLogger() },
      { orgId: other, name: `Chain Restore Other ${other.slice(-6)}`, release: 'r-1', run: null },
    );
    await record(live, 3, other);
    await copied(3);
    await deleteEvent(live, 2n);
    await deleteEvent(live, 2n, other);
    const before = await snapshot(live, other);
    expect(await restore(await digestNow())).toMatchObject({ ok: true });
    expect(await verifiedLive()).toMatchObject({ ok: true });
    expect(await snapshot(live, other)).toBe(before);
    expect(await verifiedLive(other)).toMatchObject({ ok: false });
  });
});

describe('SEC-DB-12 PL-29 the repair refuses, writing nothing', () => {
  it('a plan gone stale: the live chain changed after the operator read it', async () => {
    await copied(3);
    await deleteEvent(live, 2n);
    const digest = await digestNow();
    await record(live, 1);
    const before = await snapshot(live);
    const outcome = await restore(digest);
    expect(outcome).toMatchObject({ ok: false, reason: 'stale' });
    expect(outcome).not.toMatchObject({ digest });
    expect(await snapshot(live)).toBe(before);
  });

  it('a digest that is no plan’s', async () => {
    await copied(1);
    await deleteEvent(live, 1n);
    expect(await restore('0'.repeat(64))).toMatchObject({ ok: false, reason: 'stale' });
  });

  it('the live chain moved between the plan and the head’s lock: an event the app added while it waited', async () => {
    await copied(3);
    await deleteEvent(live, 2n);
    const digest = await digestNow();
    const before = await snapshot(live);
    // The app's writer holds the head's lock with its event written, uncommitted, before the repair starts.
    let release = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let locked = (): void => undefined;
    const lockTaken = new Promise<void>((resolve) => {
      locked = resolve;
    });
    const writer = withTenant(on(live, 'app'), orgId, async (tx) => {
      await trail.record(tx, orgId, probe(9));
      locked();
      await held;
    });
    await lockTaken;
    const repairing = restore(digest);
    await waitUntilQueued(live.as('admin'), 1);
    release();
    await writer;
    expect(await repairing).toEqual({ ok: false, reason: 'moved' });
    // The writer's event alone is new: nothing of the plan's was written.
    expect(await snapshot(live)).not.toBe(before);
    expect((await chainRowsAlone(on(live, 'operator', true), keys, orgId, 1n, 1)).rows[0]?.seq).toBe(3n);
  });

  it('a fork, without the named flag', async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(3);
    await windBack(earlier);
    await record(live, 2);
    const before = await snapshot(live);
    const outcome = await restore('0'.repeat(64));
    expect(outcome).toEqual({
      ok: false,
      reason: 'plan',
      plan: { ok: false, reason: 'fork', seq: BigInt(earlier.seq) + 1n },
    });
    expect(await snapshot(live)).toBe(before);
  });

  it("an event edited under the head's lock, the head untouched: the live chain read again tells it apart", async () => {
    await copied(3);
    await deleteEvent(live, 2n);
    const digest = await digestNow();
    const before = await snapshot(live);
    // Someone past the app holds the head's lock and edits an earlier event, uncommitted, before the repair starts.
    const admin = await live.connect('admin');
    try {
      await admin.query('begin');
      await admin.query('select seq from audit.heads where org_id = $1 for update', [orgId]);
      await admin.query(`update audit.events set details = '{"step":99}' where org_id = $1 and seq = 3`, [orgId]);
      const repairing = restore(digest);
      await waitUntilQueued(live.as('admin'), 1);
      await admin.query('commit');
      // Refused before a write, not only by the whole check after one.
      expect(await repairing).toEqual({ ok: false, reason: 'moved' });
    } finally {
      await admin.end();
    }
    expect(await snapshot(live)).not.toBe(before);
    expect((await chainRowsAlone(on(live, 'operator', true), keys, orgId, 1n, 1)).rows[0]?.seq).toBe(3n);
  });

  it("where signing starts moved on the live server after the plan read it: refused under the head's lock", async () => {
    await copied(2);
    await deleteEvent(live, 2n);
    const digest = await digestNow();
    const before = await snapshot(live);
    // Someone past the app holds the head's lock and writes a start, uncommitted, before the repair starts.
    const admin = await live.connect('admin');
    try {
      await admin.query('begin');
      await admin.query('select seq from audit.heads where org_id = $1 for update', [orgId]);
      await admin.query('insert into audit.operator_signing_starts (org_id, signed_from) values ($1, 99)', [orgId]);
      const repairing = restore(digest);
      await waitUntilQueued(live.as('admin'), 1);
      await admin.query('commit');
      expect(await repairing).toEqual({ ok: false, reason: 'signing_start', copyStart: null, liveStart: '99' });
    } finally {
      await admin.end();
    }
    expect(await snapshot(live)).toBe(before);
  });

  it('where signing starts differs before the plan: the plan itself refuses', async () => {
    await copied(2);
    await deleteEvent(live, 2n);
    await tamper(live, (admin) =>
      admin.query('insert into audit.operator_signing_starts (org_id, signed_from) values ($1, 99)', [orgId]),
    );
    expect(await restore('0'.repeat(64))).toMatchObject({
      ok: false,
      reason: 'plan',
      plan: { reason: 'copy_broken', problem: 'signing_start' },
    });
  });
});

describe('SEC-DB-12 PL-29 a forged row is never written', () => {
  it('a copy holding a row with a wrong MAC: its plan refused', async () => {
    await copied(3);
    await tamper(theCopy(), (admin) =>
      admin.query("update audit.events set mac = '\\x00' where org_id = $1 and seq = 2", [orgId]),
    );
    await deleteEvent(live, 2n);
    const before = await snapshot(live);
    expect(await restore('0'.repeat(64))).toMatchObject({
      ok: false,
      reason: 'plan',
      plan: { reason: 'copy_broken', seq: 2n },
    });
    expect(await snapshot(live)).toBe(before);
  });

  it("a copy holding an operator's event past the cut-over without its signature: its plan refused", async () => {
    await copied(1);
    await tamper(theCopy(), (admin) =>
      admin.query('delete from audit.operator_signatures where org_id = $1 and seq = 1', [orgId]),
    );
    await deleteEvent(live, 1n);
    expect(await restore('0'.repeat(64))).toMatchObject({
      ok: false,
      reason: 'plan',
      plan: { reason: 'copy_broken', seq: 1n },
    });
  });

  it('rows that land otherwise than planned fail the check: everything rolled back', async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(3);
    await windBack(earlier);
    const digest = await digestNow();
    const before = await snapshot(live);
    // Something past the app spoils each event's MAC as it is written: the plan's rows don't land as read.
    await tamper(live, async (admin) => {
      await admin.query(`create function public.spoil() returns trigger language plpgsql as $$
        begin new.mac := '\\x00'::bytea; return new; end $$`);
      await admin.query(
        'create trigger spoil before insert on audit.events for each row execute function public.spoil()',
      );
    });
    expect(await restore(digest)).toMatchObject({ ok: false, reason: 'unverified', problem: { reason: 'mac' } });
    await tamper(live, (admin) => admin.query('drop trigger spoil on audit.events'));
    // Not one row, nor the head, was kept.
    expect(await snapshot(live)).toBe(before);
  });

  it('a chain that checks whole but ends elsewhere than planned: rolled back', async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(2);
    await deleteEvent(live, 2n);
    const digest = await digestNow();
    const before = await snapshot(live);
    // Something past the app winds the chain back to an earlier sealed head as the repair writes: whole, but short.
    await tamper(live, async (admin) => {
      await admin.query('create table public.earlier as select * from audit.heads where org_id = $1', [orgId]);
      await admin.query('update public.earlier set seq = $1, hash = $2, mac = $3', [
        earlier.seq,
        earlier.hash,
        earlier.mac,
      ]);
      await admin.query(`create function public.shorten() returns trigger language plpgsql security definer as $$
        begin
          delete from audit.events e using public.earlier p where e.org_id = p.org_id and e.seq > p.seq;
          update audit.heads h set seq = p.seq, hash = p.hash, mac = p.mac from public.earlier p
          where h.org_id = p.org_id;
          return null;
        end $$`);
      await admin.query(
        'create trigger shorten after insert on audit.events for each statement execute function public.shorten()',
      );
    });
    expect(await restore(digest)).toEqual({
      ok: false,
      reason: 'unverified',
      problem: { reason: 'end', seq: BigInt(earlier.seq) },
    });
    await tamper(live, (admin) => admin.query('drop trigger shorten on audit.events'));
    expect(await snapshot(live)).toBe(before);
  });
});

describe('PL-29 a failure while writing', () => {
  it('is thrown as it is, and nothing is kept', async () => {
    await copied(3);
    await deleteEvent(live, 2n);
    const digest = await digestNow();
    const before = await snapshot(live);
    await tamper(live, async (admin) => {
      await admin.query(`create function public.refuse() returns trigger language plpgsql as $$
        begin raise exception 'refused by a trigger'; end $$`);
      await admin.query(
        'create trigger refuse before insert on audit.events for each row execute function public.refuse()',
      );
    });
    await expect(restore(digest)).rejects.toThrow('refused by a trigger');
    await tamper(live, (admin) => admin.query('drop trigger refuse on audit.events'));
    expect(await snapshot(live)).toBe(before);
  });
});

describe("the live chain's fingerprint", () => {
  it('is no fingerprint when the head moved between its pages', async () => {
    await record(live, 3);
    let first = true;
    const moved = await fingerprintOf(
      {
        keys,
        pageSize: 1,
        readPage: async (db, withKeys, org, after, limit) => {
          if (!first) return chainRowsAlone(db, withKeys, org, after, limit);
          first = false;
          const page = await chainRowsAlone(db, withKeys, org, after, limit);
          await record(live, 1);
          return page;
        },
      },
      on(live, 'operator', true),
      orgId,
    );
    expect(moved).toBeNull();
  });

  it('throws what stopped a read', async () => {
    const failed = new Error('the read failed');
    await expect(
      fingerprintOf({ keys, readPage: () => Promise.reject(failed) }, on(live, 'operator', true), orgId),
    ).rejects.toBe(failed);
  });
});

describe('a fork, with the named flag', () => {
  it("discards the live branch: the copy's events and head put back, the branch kept as evidence", async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(2);
    await windBack(earlier);
    await record(live, 3);
    const plan = await planned(true);
    expect(plan).toMatchObject({ ok: true, forkDiscarded: true });
    if (!plan.ok) throw new Error('refused');
    const from = BigInt(earlier.seq);
    expect(plan.rows.map((row) => [row.action, row.seq])).toEqual([
      ['replace', from + 1n],
      ['replace', from + 2n],
      ['remove', from + 3n],
    ]);
    // The branch's own rows, every column as live held them, kept as evidence in the plan.
    const branch = await chainRowsAlone(on(live, 'operator', true), keys, orgId, from, 10);
    expect(plan.rows.map((row) => (row.action === 'remove' ? row.stored : 'replaced' in row && row.replaced))).toEqual(
      branch.rows.map((row) => row.stored),
    );
    // Its digest differs from the plan made without the flag, which is refused.
    expect(await restore(planDigest(plan, orgId, undefined))).toMatchObject({ ok: false, reason: 'plan' });
    expect(await restore(planDigest(plan, orgId, undefined), { discardFork: true })).toMatchObject({ ok: true });
    expect(await verifiedLive()).toMatchObject({ ok: true });
    expect(await snapshot(live)).toBe(await snapshot(theCopy()));
  });
});

describe("the repair's record", () => {
  it('names the run, the plan and the outcome, and no row', () => {
    const facts = {
      restoreId: uuidV7Ids.next(),
      planId: uuidV7Ids.next(),
      orgId: uuidV7Ids.next(),
      digest: 'ab'.repeat(32),
      discardFork: false,
      release: 'r-1',
      run: null,
    };
    const outcomes: RestoreOutcome[] = [
      { ok: false, reason: 'plan', plan: { ok: false, reason: 'fork', seq: 4n } },
      { ok: false, reason: 'plan', plan: { ok: false, reason: 'copy_broken', seq: 2n, problem: 'mac' } },
      { ok: false, reason: 'stale', digest: 'cd'.repeat(32) },
      { ok: false, reason: 'signing_start', copyStart: '3', liveStart: null },
      { ok: false, reason: 'moved' },
      { ok: false, reason: 'unverified', problem: { reason: 'end', seq: 5n } },
    ];
    expect(outcomes.map((outcome) => JSON.parse(restoreFile(outcome, facts).toString()) as unknown)).toEqual([
      { k: 'restore', ...facts, ok: false, reason: 'plan', planRefused: 'fork', seq: '4', problem: null },
      { k: 'restore', ...facts, ok: false, reason: 'plan', planRefused: 'copy_broken', seq: '2', problem: 'mac' },
      { k: 'restore', ...facts, ok: false, reason: 'stale', digestNow: 'cd'.repeat(32) },
      { k: 'restore', ...facts, ok: false, reason: 'signing_start', copyStart: '3', liveStart: null },
      { k: 'restore', ...facts, ok: false, reason: 'moved' },
      { k: 'restore', ...facts, ok: false, reason: 'unverified', problem: 'end', seq: '5' },
    ]);
  });
});
