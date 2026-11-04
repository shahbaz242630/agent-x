// 4D2e E9 (PL-29): the chain recovery plan against a real Postgres. The copy is
// made as a restore makes one (TestDatabase.copy), then the live chain is
// damaged as the database's superuser would, past every wall and holding none
// of the app's keys: wound back, an event deleted or edited, grown again on a
// wound-back head. The plan puts back only the copy's original rows, and
// refuses whatever would need a new MAC.
import { type AuditEvent, chainRowsAlone, createAuditTrail } from '@agentx/core/modules/audit';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import type { CheckedPoint } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { createTestDatabase, type TestClient, type TestDatabase, testLogger, writeTestKeys } from '@agentx/testing';
import { afterAll, afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { planChainRecovery, type PlannedRow, planFile, type RecoverySides } from './chain-recovery.ts';
import { createOrganizationAsOperator, type OperatorTables } from './create-organization.ts';

const server = inject('postgres');
const keyFiles = writeTestKeys(['audit-mac', 'field-encryption']);
const keys = loadKeys({ directory: keyFiles.directory, current: {} }, ['audit-mac', 'field-encryption']);
const trail = createAuditTrail({ keys, ids: uuidV7Ids });

let live: TestDatabase;
let copy: TestDatabase | undefined;
let orgId: string;
const open: Database<OperatorTables>[] = [];

/** The app's role on a test database, read-only as the plan connects, or not, to write. */
function appOn(database: TestDatabase, readOnly: boolean): Database<OperatorTables> {
  const handle = createDatabase<OperatorTables>(
    { ...database.connection('app'), maxConnections: 1, readOnly },
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

/** Records `count` events on the organisation's chain, as the app would. */
async function record(database: TestDatabase, count: number): Promise<void> {
  const writer = appOn(database, false);
  await withTenant(writer, orgId, async (tx) => {
    for (let step = 1; step <= count; step += 1) await trail.record(tx, orgId, probe(step));
  });
}

/** Changes a database as its superuser with every trigger off: what someone past the app could do. */
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

async function headOf(database: TestDatabase): Promise<HeadRow> {
  let row: HeadRow | undefined;
  await tamper(database, async (admin) => {
    [row] = (await admin.query('select seq, hash, mac, mac_key_version from audit.heads where org_id = $1', [
      orgId,
    ])) as HeadRow[];
  });
  if (row === undefined) throw new Error('The chain has no head');
  return row;
}

/** Winds the live chain back: every event past the earlier head deleted, and the head set to it. */
function windBack(earlier: HeadRow): Promise<void> {
  return tamper(live, async (admin) => {
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

const deleteEvent = (database: TestDatabase, seq: bigint) =>
  tamper(database, (admin) => admin.query('delete from audit.events where org_id = $1 and seq = $2', [orgId, seq]));

const editEvent = (database: TestDatabase, seq: bigint) =>
  tamper(database, (admin) =>
    admin.query(`update audit.events set details = '{"step":99}' where org_id = $1 and seq = $2`, [orgId, seq]),
  );

/** Closes every handle: a database is copied only once no one is connected to it. */
async function closeAll(): Promise<void> {
  await Promise.all(open.splice(0).map((handle) => handle.destroy()));
}

/** The organisation with `events` probes after its creation, then the copy made: its head's number. */
async function copied(events: number): Promise<bigint> {
  await record(live, events);
  await closeAll();
  copy = await live.copy();
  return BigInt((await headOf(live)).seq);
}

function plan(more: Partial<RecoverySides> = {}) {
  return planChainRecovery({
    copy: appOn(theCopy(), true),
    live: appOn(live, true),
    keys,
    orgId,
    anchor: undefined,
    ...more,
  });
}

const actions = (rows: readonly PlannedRow[]) => rows.map((row) => [row.action, row.seq]);

beforeEach(async () => {
  live = await createTestDatabase(server, { schema: 'migrated' });
  orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    appOn(live, false),
    { keys, ids: uuidV7Ids, logger: testLogger() },
    { orgId, name: `Chain Recovery Test ${orgId.slice(-6)}`, release: 'r-1', run: null },
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

describe('PL-29 the chain recovery plan puts back only original rows', () => {
  it('plans nothing for a chain the copy holds whole', async () => {
    const head = await copied(3);
    const planned = await plan();
    expect(planned).toMatchObject({ ok: true, copySeq: head, rows: [], head: undefined, keptPastCopy: 0n });
  });

  it('a chain wound back: the copy puts back the events and the head', async () => {
    await record(live, 2);
    const earlier = await headOf(live);
    const head = await copied(3);
    await windBack(earlier);

    const planned = await plan();
    if (!planned.ok) throw new Error(`refused: ${planned.reason}`);
    const from = BigInt(earlier.seq);
    expect(actions(planned.rows)).toEqual([
      ['put_back', from + 1n],
      ['put_back', from + 2n],
      ['put_back', from + 3n],
    ]);
    // Every row exactly as the copy holds it, its original MAC with it.
    const onCopy = await chainRowsAlone(appOn(theCopy(), true), orgId, from, 10);
    expect(planned.rows.map((row) => ('columns' in row ? row.columns : undefined))).toEqual(
      onCopy.rows.map((row) => row.read?.columns),
    );
    const copyHead = await headOf(theCopy());
    expect(planned.head).toEqual({
      seq: head,
      hash: copyHead.hash,
      mac: copyHead.mac,
      macKeyVersion: copyHead.mac_key_version,
    });
    expect(planned.endsAt.seq).toBe(head);
  });

  it('an event deleted from the middle: put back, the head left as it is', async () => {
    await copied(3);
    await deleteEvent(live, 2n);
    const planned = await plan();
    expect(planned).toMatchObject({ ok: true, head: undefined });
    expect(planned.ok && actions(planned.rows)).toEqual([['put_back', 2n]]);
  });

  it('an event edited: the original in its place', async () => {
    await copied(3);
    await editEvent(live, 3n);
    const planned = await plan();
    expect(planned.ok && actions(planned.rows)).toEqual([['replace', 3n]]);
  });

  it("an event whose row can't be read as the app writes one: the original in its place", async () => {
    await copied(2);
    // A time the app never writes, to the microsecond.
    await tamper(live, (admin) =>
      admin.query(
        `update audit.events set recorded_at = recorded_at + interval '1 microsecond' where org_id = $1 and seq = 2`,
        [orgId],
      ),
    );
    const planned = await plan();
    expect(planned.ok && actions(planned.rows)).toEqual([['replace', 2n]]);
  });

  it("the head deleted, or of the wrong type: the copy's head in its place", async () => {
    const head = await copied(2);
    await tamper(live, (admin) => admin.query('delete from audit.heads where org_id = $1', [orgId]));
    expect(await plan()).toMatchObject({ ok: true, rows: [], head: { seq: head } });
    await tamper(live, (admin) => admin.query('alter table audit.heads alter column mac_key_version type bigint'));
    expect(await plan()).toMatchObject({ ok: true, rows: [], head: { seq: head } });
  });

  it("throws what stopped a read, and a row with no number the chain's way", async () => {
    await copied(1);
    const failed = new Error('the read failed');
    await expect(plan({ readPage: () => Promise.reject(failed) })).rejects.toBe(failed);
    await tamper(live, (admin) => admin.query('alter table audit.events alter column seq type numeric'));
    await expect(plan()).rejects.toThrow('it read an event with no number');
  });

  it('keeps the live chain grown on whole from the copy, and its head', async () => {
    const head = await copied(3);
    await record(live, 2);
    await deleteEvent(live, 2n);
    const planned = await plan();
    expect(planned).toMatchObject({ ok: true, copySeq: head, head: undefined, keptPastCopy: 2n });
    expect(planned.ok && actions(planned.rows)).toEqual([['put_back', 2n]]);
    expect(planned.ok && planned.endsAt.seq).toBe(head + 2n);
  });

  it('removes rows that were never the app’s: one numbered 0, and one past a whole head', async () => {
    const head = await copied(2);
    await tamper(live, async (admin) => {
      // The table's own rule refuses a number below 1: the owner can take it away.
      await admin.query('alter table audit.events drop constraint events_seq_check');
      for (const seq of [0n, head + 1n]) {
        await admin.query(
          `insert into audit.events
           select org_id, $2, gen_random_uuid(), recorded_at, actor_type, actor_id, action, subject_type, subject_id,
                  subject_version, details, prev_hash, hash, mac, mac_key_version
           from audit.events where org_id = $1 and seq = 1`,
          [orgId, seq],
        );
      }
    });
    const planned = await plan();
    expect(planned.ok && actions(planned.rows)).toEqual([
      ['remove', 0n],
      ['remove', head + 1n],
    ]);
  });
});

describe('PL-29 the plan refuses what original rows cannot mend', () => {
  it('a fork: events written on a wound-back head, which the copy holds others in place of', async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(3);
    await windBack(earlier);
    await record(live, 2);
    expect(await plan()).toEqual({ ok: false, reason: 'fork', seq: BigInt(earlier.seq) + 1n });
  });

  it('a copy that fails its own check', async () => {
    await copied(3);
    await editEvent(theCopy(), 2n);
    expect(await plan()).toEqual({ ok: false, reason: 'copy_broken', seq: 2n, problem: 'hash' });
  });

  it('a copy that holds no chain for the organisation', async () => {
    await copied(1);
    expect(await plan({ orgId: uuidV7Ids.next() })).toEqual({
      ok: false,
      reason: 'copy_broken',
      seq: 0n,
      problem: 'head',
    });
  });

  it('an event past the copy deleted: no original row holds it, so it would need a new MAC', async () => {
    const head = await copied(2);
    await record(live, 3);
    await deleteEvent(live, head + 2n);
    expect(await plan()).toEqual({ ok: false, reason: 'new_seal', seq: head + 2n });
  });

  it('an event past the copy edited', async () => {
    const head = await copied(2);
    await record(live, 2);
    await editEvent(live, head + 1n);
    expect(await plan()).toEqual({ ok: false, reason: 'new_seal', seq: head + 1n });
  });

  it("an event past the copy whose row can't be read", async () => {
    const head = await copied(2);
    await record(live, 2);
    await tamper(live, (admin) =>
      admin.query(
        `update audit.events set recorded_at = recorded_at + interval '1 microsecond' where org_id = $1 and seq = $2`,
        [orgId, head + 2n],
      ),
    );
    expect(await plan()).toEqual({ ok: false, reason: 'new_seal', seq: head + 2n });
  });

  it('events past the copy left behind a head wound back to it: no original head stands at their end', async () => {
    const head = await copied(2);
    const atCopy = await headOf(live);
    await record(live, 2);
    await tamper(live, (admin) =>
      admin.query('update audit.heads set seq = $2, hash = $3, mac = $4 where org_id = $1', [
        orgId,
        atCopy.seq,
        atCopy.hash,
        atCopy.mac,
      ]),
    );
    expect(await plan()).toEqual({ ok: false, reason: 'new_seal', seq: head + 2n });
  });

  it('the live tail past the copy deleted under its sealed head: those events are lost', async () => {
    const head = await copied(2);
    await record(live, 2);
    await tamper(live, (admin) =>
      admin.query('delete from audit.events where org_id = $1 and seq > $2', [orgId, head]),
    );
    expect(await plan()).toEqual({ ok: false, reason: 'new_seal', seq: head + 1n });
  });

  it("checks the store's anchor: one past where the plan ends, and one at an event it doesn't hold", async () => {
    const head = await copied(2);
    const copyEnd = await plan();
    if (!copyEnd.ok) throw new Error('The intact plan should pass');
    const past: CheckedPoint = { ...copyEnd.endsAt, seq: head + 5n };
    expect(await plan({ anchor: past })).toEqual({ ok: false, reason: 'behind_anchor', seq: head + 5n });
    const other: CheckedPoint = { ...copyEnd.endsAt, hash: Buffer.alloc(32, 7) };
    expect(await plan({ anchor: other })).toEqual({ ok: false, reason: 'anchor', seq: head });
    const otherKey: CheckedPoint = { ...copyEnd.endsAt, macKeyVersion: 2 };
    expect(await plan({ anchor: otherKey })).toEqual({ ok: false, reason: 'anchor', seq: head });
    expect(await plan({ anchor: copyEnd.endsAt })).toMatchObject({ ok: true });
    expect(await plan({ anchor: { ...copyEnd.endsAt, seq: 0n } })).toMatchObject({ ok: true });
  });

  it('holds an anchor on the live events grown on past the copy', async () => {
    const head = await copied(2);
    await record(live, 2);
    const grown = await plan();
    if (!grown.ok) throw new Error('The grown plan should pass');
    expect(await plan({ anchor: grown.endsAt })).toMatchObject({ ok: true, keptPastCopy: 2n });
    expect(await plan({ anchor: { ...grown.endsAt, hash: Buffer.alloc(32) } })).toEqual({
      ok: false,
      reason: 'anchor',
      seq: head + 2n,
    });
  });

  it('more rows than one plan writes', async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(3);
    await windBack(earlier);
    expect(await plan({ mostRows: 2 })).toEqual({ ok: false, reason: 'too_large', seq: BigInt(earlier.seq) + 3n });
  });

  it('a live chain that moved between two pages of its read', async () => {
    await copied(4);
    const reader = appOn(live, true);
    let livePages = 0;
    const moved = await plan({
      live: reader,
      pageSize: 2,
      readPage: async (db, org, after, limit) => {
        // The live chain's first page read, an event is recorded before its second.
        if (db === reader && (livePages += 1) === 2) await record(live, 1);
        return chainRowsAlone(db, org, after, limit);
      },
    });
    expect(moved).toEqual({ ok: false, reason: 'moved', seq: 0n });
  });

  it('a copy that moved between its check and its read', async () => {
    const head = await copied(2);
    let first = true;
    const moved = await plan({
      readPage: async (db, org, after, limit) => {
        if (first) {
          first = false;
          await record(theCopy(), 1);
        }
        return chainRowsAlone(db, org, after, limit);
      },
    });
    expect(moved).toEqual({ ok: false, reason: 'moved', seq: head });
  });
});

describe("the plan's file", () => {
  it('names the plan, then each row, then the head it puts back', async () => {
    await record(live, 1);
    const earlier = await headOf(live);
    await copied(1);
    await windBack(earlier);
    const planned = await plan();
    const facts = { planId: uuidV7Ids.next(), orgId, release: 'r-1', run: null, anchor: undefined };
    const lines = planFile(planned, facts)
      .toString()
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(lines.map((line) => line.k)).toEqual(['plan', 'row', 'head']);
    expect(lines[0]).toMatchObject({ ok: true, rows: 1, headReplaced: true, anchor: null, orgId });
    expect(lines[1]).toMatchObject({ action: 'put_back', seq: String(BigInt(earlier.seq) + 1n) });
  });

  it('says why a plan was refused, and nothing more', () => {
    const facts = { planId: uuidV7Ids.next(), orgId: uuidV7Ids.next(), release: 'r-1', run: null, anchor: undefined };
    const file = planFile({ ok: false, reason: 'fork', seq: 4n }, facts).toString();
    expect(file.split('\n')).toHaveLength(2);
    expect(JSON.parse(file)).toMatchObject({ k: 'plan', ok: false, reason: 'fork', seq: '4' });
  });
});
