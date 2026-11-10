// PL-29 follow-up (Carry-Forward S175): an organisation's authority rows
// repaired from a restored copy (apps/operator/src/state-recovery.ts plans,
// state-restore.ts applies), as chain-repair.ts repairs its chain. The steps
// that reach an authority table's rows by its name live here, in the audit
// module, beside the signed states that judge them (ADR-012 §2).
//
// What is read is each row whole, as Postgres's own JSON of it, and what is
// written is only such a row as the copy holds it: nothing here makes a seal,
// a MAC or a hash, nor takes a key. A row is judged only as verifiedState
// judges it (judgeSignedRow), and the repair checks every row it wrote again
// through verifiedState before it commits.
//
// The database's guards (the status guard, 0004; made-once, 0032;
// fixed-at-creation, 0035; a request's decided move and carried version,
// 0039, 0047) bind the owner too, and refuse an original put back: a status
// can't move back along a move the machine lacks, a deleted row can't be
// inserted past its first status, a made-once row can't change at all. So
// the repair switches those guards alone off on the tables it writes, inside
// its one transaction, and on again before it checks and commits: ALTER TABLE
// takes the table's SHARE ROW EXCLUSIVE lock, so no other session writes the
// table, or sees the guard off, until it commits with the guard on again. Every
// organisation's writes to that table wait for it, so the repair waits for the
// lock a second at most (shortLockWait) and keeps the window to its writes and
// their own checks: everything else it checks before.
// Every other trigger stays on, and whatever a planted one did would fail the
// check that the row as written is the copy's exactly.
import type { SignedRow, SignedRowKey, SignedStateTable } from '@agentx/platform/db';
import { assertTenant, readSignedRows, signedRowIds, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { IdGenerator } from '../../../shared-kernel/index.ts';
import { type AuditTrail, createAuditTrail, type LatestSignedState } from './audit-trail.ts';
import { createSignedStates, judgeSignedRow, type SignedStates, type StateCheck } from './signed-states.ts';
import type { AuditTables } from './tables.ts';

/**
 * A state repair's one transaction, withTenant's for the organisation, each
 * statement limited, with signed states of its own that hand nothing on to
 * the hold: a repair that finds a record still tampered with rolls back, and
 * its outcome and the verifier's alarm line are the record, so a failed repair
 * never adds a hold event or a row of the holds waiting, nor moves the chain's
 * head under its plan. The hold is left as it is, as by the chain's repair.
 */
export function withRepairStates<Result>(
  db: Kysely<AuditTables>,
  orgId: string,
  services: { readonly keys: KeyProvider; readonly ids: IdGenerator; readonly logger: Logger },
  work: (tx: Transaction<AuditTables>, states: SignedStates) => Promise<Result>,
): Promise<Result> {
  const states = createSignedStates({
    keys: services.keys,
    trail: createAuditTrail({ keys: services.keys, ids: services.ids }),
    logger: services.logger,
    onTamper: () => undefined,
    // It reads no hold: nothing waiting could change what it does.
    unrecorded: () => undefined,
  });
  return withTenant(db, orgId, (tx) => work(tx, states), { limited: true });
}

/**
 * From here to the end of the transaction, a lock is waited for a second at
 * most: the repair's tables' locks hold every organisation's writes to them,
 * so a table some other write holds refuses the repair (busy) rather than
 * queueing everyone behind it. Nothing after needs longer: every row it then
 * locks is in a table it already holds.
 */
export async function shortLockWait(tx: Transaction<AuditTables>): Promise<void> {
  await sql`set local lock_timeout = '1s'`.execute(tx);
}

/** Whether an error is Postgres giving up on a lock (55P03, lock_not_available). */
export const lockNotAvailable = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && error.code === '55P03';

/** The most objects one read here takes: readSignedRows' and latestSignedStates' limit alike. */
export const STATES_READ_AT_ONCE = 500;

/** A row as one server holds it, read with no lock: its signed state's parts, its latest signed event, and the verdict. */
export interface StateAsRead {
  readonly row: SignedRow;
  readonly latest: LatestSignedState | { readonly kind: 'backlog' };
  /** As verifiedState would judge it; undefined for an object with a backlog of events, which it refuses (TooManyEventsAboutObject). */
  readonly check: StateCheck | undefined;
}

/**
 * The organisation's objects of one table after `after` (null from the start),
 * at most `size`: its rows and every object the log holds an event about, as
 * verifyAll lists them, so a deleted row is listed too; and the ID to go on
 * after, or null for the last. Read with no lock.
 */
export async function stateObjectIds(
  tx: Transaction<AuditTables>,
  trail: AuditTrail,
  table: SignedStateTable,
  orgId: string,
  after: string | null,
  size: number,
): Promise<{ readonly ids: readonly string[]; readonly next: string | null }> {
  const rowIds = await signedRowIds(tx, table, orgId, size, after);
  const loggedIds = await trail.subjectIds(tx, orgId, table.subject, size, after);
  // Each list holds one more than `size` at most, so its first `size` of the two together are the next ones.
  const listed = [...new Set([...rowIds, ...loggedIds])].sort();
  const ids = listed.slice(0, size);
  // Past `size`, the last ID kept is where the next page starts after.
  return { ids, next: listed.length > size ? String(ids[size - 1]) : null };
}

/**
 * Each object's row and latest signed event, read with no lock in the
 * caller's transaction (withTenant's for the organisation, read-only or not),
 * and judged as verifiedState judges them, raising no alarm (judgeSignedRow).
 * At most STATES_READ_AT_ONCE.
 */
export async function statesAsRead(
  tx: Transaction<AuditTables>,
  trail: AuditTrail,
  keys: KeyProvider,
  table: SignedStateTable,
  orgId: string,
  ids: readonly string[],
): Promise<ReadonlyMap<string, StateAsRead>> {
  const rows = await readSignedRows(tx, table, orgId, ids, 'none');
  const latest = await trail.latestSignedStates(tx, orgId, table.subject, ids);
  const read = new Map<string, StateAsRead>();
  for (const [id, row] of rows) {
    const last = latest.get(id);
    // Both reads answer every ID asked; one that didn't would be a bug, never a row to believe.
    if (last === undefined) throw new Error('A signed state was asked for and not read');
    const key: SignedRowKey = { orgId, id };
    const check = last.kind === 'backlog' ? undefined : judgeSignedRow(keys, table, key, row, last);
    read.set(id, { row, latest: last, check });
  }
  return read;
}

/**
 * Sets the transaction's own TimeZone and IntervalStyle, which a row's JSON
 * writes its times and intervals in, so a row reads as the same text on the
 * copy and the live server whatever either's defaults: two reads of one row
 * are compared as text.
 */
export async function readRowsAlike(tx: Transaction<AuditTables>): Promise<void> {
  await sql`set local TimeZone = 'UTC'`.execute(tx);
  await sql`set local IntervalStyle = 'postgres'`.execute(tx);
}

/**
 * Each row whole, as Postgres's JSON of it (every column, the generated ones
 * too), by its ID in lower case: none for an ID with no row. With `change`,
 * each row is locked for a change (`FOR UPDATE`: a repair may delete it), in
 * ID order. Only in withTenant's transaction for the organisation.
 */
export async function rowsAsStored(
  tx: Transaction<AuditTables>,
  table: SignedStateTable,
  orgId: string,
  ids: readonly string[],
  lock: 'none' | 'change' = 'none',
): Promise<ReadonlyMap<string, string>> {
  if (ids.length === 0) return new Map();
  await assertTenant(tx, orgId);
  const { rows } = await sql<{ id: string; stored: string }>`
    select t.id::text as id, pg_catalog.to_jsonb(t)::text as stored from ${sql.table(table.table)} as t
    where t.org_id = ${orgId.toLowerCase()} and t.id = any(${ids.map((id) => id.toLowerCase())}::uuid[])
    order by t.id
    ${lock === 'change' ? sql`for update` : sql``}
  `.execute(tx);
  return new Map(rows.map(({ id, stored }) => [id, stored]));
}

/** The table's columns, in order, but those dropped; with `written`, only those a write may set (no generated one). */
export async function columnsOf(
  tx: Transaction<AuditTables>,
  table: SignedStateTable,
  written = false,
): Promise<readonly string[]> {
  const { rows } = await sql<{ name: string }>`
    select a.attname::text as name from pg_catalog.pg_attribute a
    where a.attrelid = ${table.table}::regclass and a.attnum > 0 and not a.attisdropped
      ${written ? sql`and a.attgenerated = ''` : sql``}
    order by a.attnum
  `.execute(tx);
  return rows.map(({ name }) => name);
}

/** The guards a repair switches off while it writes, by name: each refuses an original put back (the file's head). */
const GUARD_TRIGGERS: readonly string[] = [
  'status_guard',
  'made_once',
  'fixed_at_creation',
  'decided_move',
  'carried_version',
];

/** Every trigger of the table that isn't Postgres's own, by name, with whether it is on (`O`) or how it is off. */
export async function triggersOf(
  tx: Transaction<AuditTables>,
  table: SignedStateTable,
): Promise<ReadonlyMap<string, string>> {
  const { rows } = await sql<{ name: string; enabled: string }>`
    select t.tgname::text as name, t.tgenabled::text as enabled from pg_catalog.pg_trigger t
    where t.tgrelid = ${table.table}::regclass and not t.tgisinternal
    order by t.tgname
  `.execute(tx);
  return new Map(rows.map(({ name, enabled }) => [name, enabled]));
}

/**
 * Switches the table's guards off for the rest of the caller's transaction,
 * which must switch them on again (guardsOn) before it commits: the ones the
 * table has and has on. Takes the table's SHARE ROW EXCLUSIVE lock. The names
 * switched off.
 */
export async function guardsOff(tx: Transaction<AuditTables>, table: SignedStateTable): Promise<readonly string[]> {
  const triggers = await triggersOf(tx, table);
  const off = GUARD_TRIGGERS.filter((name) => triggers.get(name) === 'O');
  for (const name of off) await sql`alter table ${sql.table(table.table)} disable trigger ${sql.id(name)}`.execute(tx);
  return off;
}

/**
 * Runs every check and trigger the transaction's writes left for its commit
 * now (a deferred foreign key, a mark of work for the jobs): a table with
 * events still pending can't have its guards switched on again, and a check
 * that would refuse the commit refuses here, where the repair can name it.
 */
export async function firePendingChecks(tx: Transaction<AuditTables>): Promise<void> {
  await sql`set constraints all immediate`.execute(tx);
}

/** Switches the guards guardsOff switched off on again. */
export async function guardsOn(
  tx: Transaction<AuditTables>,
  table: SignedStateTable,
  names: readonly string[],
): Promise<void> {
  for (const name of names) await sql`alter table ${sql.table(table.table)} enable trigger ${sql.id(name)}`.execute(tx);
}

/** A row a repair writes: the copy's original put back (`stored`, its JSON as read), or the live row removed. */
export type StateRepairRow =
  | {
      readonly action: 'put_back';
      readonly table: SignedStateTable;
      readonly id: string;
      readonly stored: string;
      readonly exists: boolean;
    }
  | { readonly action: 'remove'; readonly table: SignedStateTable; readonly id: string };

/** A write that reached no row, or more than one: the repair rolls back. */
export class StateWriteMissed extends Error {
  readonly table: string;

  constructor(table: string) {
    super(`A state repair's write in ${table} reached no row, or more than one`);
    this.name = 'StateWriteMissed';
    this.table = table;
  }
}

/**
 * Writes one row of a repair in the caller's transaction, withTenant's for the
 * organisation, as the owner, with the table's guards off (guardsOff): an
 * original put back over the live row, or inserted where none is left, every
 * column but the generated ones from the copy's JSON exactly as read; or the
 * live row deleted. `columns`: the table's written columns (columnsOf).
 */
export async function writeStateRow(
  tx: Transaction<AuditTables>,
  orgId: string,
  row: StateRepairRow,
  columns: readonly string[],
): Promise<void> {
  const org = orgId.toLowerCase();
  await assertTenant(tx, org);
  const table = sql.table(row.table.table);
  const id = row.id.toLowerCase();
  const { numAffectedRows } = await (
    row.action === 'remove'
      ? sql`delete from ${table} as t where t.org_id = ${org} and t.id = ${id}`
      : originalWritten(row, columns, org, id)
  ).execute(tx);
  if (numAffectedRows !== 1n) throw new StateWriteMissed(row.table.table);
}

/** The statement that puts an original back over the live row, or inserts it, only where its JSON names this key. */
function originalWritten(
  row: Extract<StateRepairRow, { action: 'put_back' }>,
  columns: readonly string[],
  org: string,
  id: string,
) {
  const table = sql.table(row.table.table);
  // The key stays as it is on a row put back over: it is the same key, which the guard would hold anyway.
  const set = row.exists ? columns.filter((column) => column !== 'org_id' && column !== 'id') : columns;
  const names = sql.join(set.map((column) => sql.id(column)));
  const values = sql.join(set.map((column) => sql.ref(`r.${column}`)));
  const original = sql`pg_catalog.jsonb_populate_record(null::${table}, ${row.stored}::jsonb)`;
  return row.exists
    ? sql`update ${table} as t set (${names}) = row(${values}) from ${original} as r
        where t.org_id = ${org} and t.id = ${id} and r.org_id = ${org} and r.id = ${id}`
    : sql`insert into ${table} (${names}) select ${values} from ${original} as r
        where r.org_id = ${org} and r.id = ${id}`;
}
