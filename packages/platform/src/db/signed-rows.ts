// Signed-state rows (ADR-012 §2), the row's side. A table whose fields grant,
// restore or limit authority (a status, a role, a limit, an expiry) keeps two
// columns beside them:
//
//   state_version  integer NOT NULL  the version its latest signed event made, from 1
//   state_event_id uuid              that event's ID; NULL only inside the
//                                    transaction that creates or changes the
//                                    row, until its event is recorded
//
// The audit module's signed states (verifiedState and record) read, write and
// point these rows through the steps here, in the module's own transaction.
// The SQL is written once, as for status changes (status.ts): the module gives
// its table's name and its authority fields, constants of its own, never
// input.
//
// Each authority field is read as canonical text in SQL, the same way when a
// state is sealed and when a row is checked against its seal, so the two can
// only differ if the value did. A time is read in UTC to the microsecond,
// whatever the session's time zone or date style, with its era, and infinity
// as itself. Each field's column must still be of the type the module
// declared, or the row is unreadable: another type's text could read the same
// for another value. A value written is read back as text by the same SQL, so
// record can check the row holds exactly what it wrote (nothing planted in the
// table changed it on the way) before sealing it.
import { type RawBuilder, sql, type Transaction } from 'kysely';

import { TABLE, UUID } from './patterns.ts';
import { assertTenant } from './tenant.ts';

/** The Postgres type of an authority field, which decides how it is read as text. */
export type SignedFieldType = 'text' | 'uuid' | 'integer' | 'timestamptz';

export interface SignedField {
  readonly column: string;
  readonly type: SignedFieldType;
}

/** A table whose rows hold authority, and what their signed state is made of: a constant in the module that owns it. */
export interface SignedStateTable {
  /** Schema and table, as `schema.table`, in lower-case words. */
  readonly table: string;
  /** The type its rows are recorded as in the audit trail: `agent`, `agent_key`. Each table has its own. */
  readonly subject: string;
  /** Every authority field, always in this order, which is the order they are sealed in. */
  readonly fields: readonly SignedField[];
}

/** The row, by its organisation and its own ID. */
export interface SignedRowKey {
  readonly orgId: string;
  readonly id: string;
}

/**
 * How the row is locked while it is read (ADR-006 §6): `share` for a read a
 * decision rests on, `change` (`FOR NO KEY UPDATE`) when the transaction will
 * change the row, since a lock is never upgraded.
 */
export type RowLock = 'share' | 'change';

/** A value to write to an authority field: text, a whole number, a time, or nothing. */
export type SignedFieldValue = string | number | bigint | Date | null;

/** Values to write, by column: each one of the table's authority fields. */
export type SignedFieldValues = Readonly<Record<string, SignedFieldValue>>;

/** An authority field's value as canonical text, or null. */
export type FieldText = readonly [column: string, value: string | null];

/**
 * What the row holds:
 * - `found`: its version, the event it points at, and its authority fields
 *   as canonical text (or null), in the table's order
 * - `missing`: no row with the key in this organisation (or, for a write or
 *   a pointer, none in the state it was written from)
 * - `unreadable`: more than one row has the key, a field's column isn't of
 *   its declared type, or the version or pointer isn't one the app writes;
 *   someone past the app changed the table
 */
export type SignedRow =
  | {
      readonly outcome: 'found';
      readonly version: number;
      readonly eventId: string | null;
      readonly fields: readonly FieldText[];
    }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'unreadable' };

/** The row as written, and each value written read as canonical text by the same SQL, in the table's order. */
export interface WrittenRow {
  readonly row: SignedRow;
  readonly written: readonly FieldText[];
}

/**
 * Names from our migrations, never from input: checked on every call anyway,
 * since they go into the SQL as names, quoted, rather than as bound values.
 */
const COLUMN = /^[a-z][a-z0-9_]{0,62}$/;
/**
 * The column types each declared type may be, by the built-in types' fixed
 * IDs (pg_type's oid), which no name on the search path can stand in for:
 * text; uuid; smallint, integer, bigint; timestamp with time zone.
 */
const COLUMN_TYPES: Readonly<Record<SignedFieldType, readonly number[]>> = {
  text: [25],
  uuid: [2950],
  integer: [21, 23, 20],
  timestamptz: [1184],
};
/** The signed-state columns themselves: sealing the pointer would need the event's ID before the event exists. */
export const OWN_COLUMNS: ReadonlySet<string> = new Set(['state_version', 'state_event_id']);
/** Postgres's integer, the state_version column's type. */
const MAX_VERSION = 2_147_483_647;

/** Refuses a table definition no module should write, before any SQL is built from it. */
function checkTable({ table, fields }: SignedStateTable): void {
  if (!TABLE.test(table)) throw new RangeError('A signed-state table is named schema.table, in lower-case words');
  if (fields.length === 0) throw new RangeError('A signed-state table seals at least one field');
  const columns = new Set<string>();
  for (const { column, type } of fields) {
    if (!COLUMN.test(column) || OWN_COLUMNS.has(column) || columns.has(column) || !Object.hasOwn(COLUMN_TYPES, type)) {
      throw new RangeError(
        "Each signed field is a lower-case column, named once, not a signed-state column, of a type it's read as",
      );
    }
    columns.add(column);
  }
}

function checkKey({ orgId, id }: SignedRowKey): void {
  if (!UUID.test(orgId) || !UUID.test(id)) throw new RangeError('A signed row is named by UUIDs');
}

const isValue = (value: unknown): value is SignedFieldValue =>
  value === null ||
  typeof value === 'string' ||
  typeof value === 'bigint' ||
  (typeof value === 'number' && Number.isSafeInteger(value)) ||
  (value instanceof Date && !Number.isNaN(value.getTime()));

/** The values to write, in the table's order: each an authority field, and for a new row every one of them. */
function valuesToWrite(
  { fields }: SignedStateTable,
  set: SignedFieldValues,
  every: boolean,
): readonly (readonly [SignedField, SignedFieldValue])[] {
  const columns = new Set(fields.map(({ column }) => column));
  if (!Object.keys(set).every((column) => columns.has(column))) {
    throw new RangeError('Only the authority fields are written with a signed state');
  }
  const values = fields
    .filter(({ column }) => Object.hasOwn(set, column))
    .map((field): readonly [SignedField, unknown] => [field, set[field.column]]);
  if (every && values.length !== fields.length) throw new RangeError("A new row's signed state names every field");
  if (!values.every(([, value]) => isValue(value))) {
    throw new RangeError('A signed field is written as text, a whole number, a valid time, or null');
  }
  return values as (readonly [SignedField, SignedFieldValue])[];
}

/**
 * A time as canonical text: UTC to the microsecond, marked BC before year 1
 * (to_char's year has no sign), and infinity as itself (to_char has no text
 * for it).
 */
function timeText(time: RawBuilder<unknown>): RawBuilder<unknown> {
  return sql`case when not pg_catalog.isfinite(${time}) then (${time})::text
    else pg_catalog.to_char((${time}) at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      || case when (${time}) < '0001-01-01 00:00:00+00'::timestamptz then ' BC' else '' end end`;
}

/** An expression of the field's type as canonical text. */
function canonical(type: SignedFieldType, value: RawBuilder<unknown>): RawBuilder<unknown> {
  return type === 'timestamptz' ? timeText(value) : sql`(${value})::text`;
}

/** A value to write, as its field's type. */
function typed(type: SignedFieldType, value: SignedFieldValue): RawBuilder<unknown> {
  if (type === 'uuid') return sql`(${value})::uuid`;
  if (type === 'integer') return sql`(${value})::bigint`;
  if (type === 'timestamptz') return sql`(${value})::timestamptz`;
  return sql`(${value})::text`;
}

/** The pointer, the version, and each field as text with its column's type, from the row aliased `target`. */
function columnsOf({ fields }: SignedStateTable): RawBuilder<unknown> {
  return sql.join([
    sql`target.state_version`,
    sql`target.state_event_id`,
    ...fields.flatMap(({ column, type }, index) => {
      const value = sql.ref(`target.${column}`);
      // Each field read twice: as canonical text (f0, f1…) and as its type (t0, t1…).
      const [field, typeOf] = [sql.id('f' + index.toString()), sql.id('t' + index.toString())];
      return [sql`${canonical(type, value)} as ${field}`, sql`pg_catalog.pg_typeof(${value})::oid as ${typeOf}`];
    }),
  ]);
}

const isVersion = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= MAX_VERSION;

const isText = (value: unknown): value is string | null => value === null || typeof value === 'string';

/** The rows read back, judged as untrusted: the table's owner could have changed any of them, or their types. */
function rowOf({ fields }: SignedStateTable, rows: readonly Readonly<Record<string, unknown>>[]): SignedRow {
  const [row, ...others] = rows;
  if (row === undefined) return { outcome: 'missing' };
  const { state_version: version, state_event_id: eventId } = row;
  const values = fields.map(({ column }, index): readonly [string, unknown] => [column, row[`f${index.toString()}`]]);
  const typesHeld = fields.every(({ type }, index) => {
    const held = row[`t${index.toString()}`];
    return typeof held === 'number' && COLUMN_TYPES[type].includes(held);
  });
  if (
    others.length > 0 ||
    !typesHeld ||
    !isVersion(version) ||
    (eventId !== null && (typeof eventId !== 'string' || !UUID.test(eventId))) ||
    !values.every(([, value]) => isText(value))
  ) {
    return { outcome: 'unreadable' };
  }
  return Object.freeze({
    outcome: 'found',
    version,
    eventId: eventId?.toLowerCase() ?? null,
    fields: Object.freeze(values as FieldText[]),
  });
}

/**
 * Reads the row's signed-state columns and authority fields, and locks it,
 * in the caller's transaction, which must be withTenant's for the row's
 * organisation: any other throws TenantContextError, since row security would
 * show the row as missing there.
 */
export async function readSignedRow<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  key: SignedRowKey,
  lock: RowLock,
): Promise<SignedRow> {
  const read = signedRowRead(table, key, lock);
  await assertTenant(tx, key.orgId);
  const { rows } = await read.execute(tx);
  return rowOf(table, rows);
}

/** The statement readSignedRow runs; with `seen`, also the row's version as locked and as the snapshot saw it. */
function signedRowRead(
  table: SignedStateTable,
  key: SignedRowKey,
  lock: RowLock,
  seen = false,
): RawBuilder<Record<string, unknown>> {
  checkTable(table);
  checkKey(key);
  return rowRead(table, key.orgId, sql`${key.id}`, lock, seen, sql``);
}

/**
 * signedRowRead's statement for the row of `orgId` whose ID `id` gives (an
 * expression), with `gate` (a condition) ANDed to its filter, both trusted
 * as built here.
 */
function rowRead(
  table: SignedStateTable,
  orgId: string,
  id: RawBuilder<unknown>,
  lock: RowLock,
  seen: boolean,
  gate: RawBuilder<unknown>,
): RawBuilder<Record<string, unknown>> {
  const versions = seen
    ? sql`, target.xmin::text as locked_xmin, (
        select pg_catalog.string_agg(s.xmin::text, ',') from ${sql.table(table.table)} as s
        where s.org_id = ${orgId} and s.id = ${id}
      ) as seen_xmin, pg_catalog.pg_typeof(target.state_version)::oid::text as version_type`
    : sql``;
  // Filtered by org_id as well as row security, as ADR-005 §7 asks of every query.
  return sql<Record<string, unknown>>`
    select ${columnsOf(table)}${versions} from ${sql.table(table.table)} as target
    where target.org_id = ${orgId} and target.id = ${id}${gate}
    ${lock === 'share' ? sql`for share` : sql`for no key update`}
  `;
}

/**
 * Where a gathered row's ID comes from (4D2d P8): given; the ID an earlier
 * row of the gather holds in a uuid field, as that row was locked; the same
 * ID as an earlier row's; the first row of the table whose `column` is
 * `value`, in one of `statusIn` (an ID alone, as openMandateOfAgent finds a
 * mandate); or the ID a uuid field of another table's row holds, read unlocked
 * on the statement's snapshot, where to look alone (4D2e C4: a key's agent,
 * locked before the key). `from` and `sameAs` name an earlier row by its place
 * in the list.
 */
export type GatheredId =
  | { readonly id: string }
  | { readonly from: number; readonly column: string }
  | { readonly sameAs: number }
  | { readonly findBy: { readonly column: string; readonly value: string; readonly statusIn: readonly string[] } }
  | { readonly lookedUp: { readonly table: SignedStateTable; readonly id: string; readonly column: string } };

/** A row to gather: its table, where its ID comes from, and its lock. */
export interface GatheredRow {
  readonly table: SignedStateTable;
  readonly id: GatheredId;
  readonly lock: RowLock;
}

/** gatheredRowReads' answer for one row: its CTE, named `name`, its ID as an expression (null for none found), and its table's subject type. */
export interface GatheredRead {
  readonly subject: string;
  readonly cte: RawBuilder<unknown>;
  readonly name: RawBuilder<unknown>;
  readonly id: RawBuilder<unknown>;
}

/** The most rows one gather reads. */
export const MOST_ROWS_GATHERED = 16;

/** A uuid field's canonical text back as a uuid, or null for anything else: a gather's ID never fails its statement. */
const asUuid = (text: RawBuilder<unknown>): RawBuilder<unknown> =>
  sql`case when ${text} ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then (${text})::uuid end`;

/**
 * signedRowReadSeen's statement for each row, in the order given, as CTEs of
 * one statement (4D2d P8), for the caller to read with each row's newest
 * signed event and judge each with signedRowSeen, as P3a's. Each row's read
 * waits for the one before it to be read and locked (its `gate`), so the
 * rows are locked in the list's order, the lock order (ADR-006 §6), whatever
 * order the statement reads the CTEs in. The caller must hold withTenant's
 * transaction for `orgId`, as readSignedRow checks.
 */
export function gatheredRowReads(orgId: string, rows: readonly GatheredRow[]): readonly GatheredRead[] {
  if (!UUID.test(orgId)) throw new RangeError('A signed row is named by UUIDs');
  if (rows.length === 0 || rows.length > MOST_ROWS_GATHERED) {
    throw new RangeError(`A gather reads 1 to ${String(MOST_ROWS_GATHERED)} rows`);
  }
  const reads: GatheredRead[] = [];
  for (const [index, row] of rows.entries()) {
    checkTable(row.table);
    const name = sql.id(`gathered_${String(index)}`);
    const id = gatheredId(orgId, row, reads, rows);
    const before = reads.at(-1);
    // The row before is read, and so locked, before this one's scan starts: an uncorrelated condition is
    // checked once, before any row is fetched.
    const gate = before === undefined ? sql`` : sql` and (select pg_catalog.count(*) from ${before.name}) >= 0`;
    const read = rowRead(row.table, orgId, id, row.lock, true, gate);
    reads.push({ subject: row.table.subject, cte: sql`${name} as materialized (${read})`, name, id });
  }
  return reads;
}

/** A gathered row's ID as an expression, from the reads before it. */
function gatheredId(
  orgId: string,
  { table, id }: GatheredRow,
  reads: readonly GatheredRead[],
  rows: readonly GatheredRow[],
): RawBuilder<unknown> {
  if ('id' in id) {
    if (!UUID.test(id.id)) throw new RangeError('A signed row is named by UUIDs');
    return sql`${id.id.toLowerCase()}::uuid`;
  }
  if ('sameAs' in id) return earlier(reads, id.sameAs).id;
  if ('from' in id) {
    const index = rows[id.from]?.table.fields.findIndex(({ column, type }) => column === id.column && type === 'uuid');
    if (index === undefined || index < 0) throw new RangeError("A gathered ID comes from an earlier row's uuid field");
    const field = sql.ref(`g.f${String(index)}`);
    return sql`(select ${asUuid(field)} from ${earlier(reads, id.from).name} as g limit 1)`;
  }
  if ('lookedUp' in id) return lookedUpId(orgId, id.lookedUp);
  const { column, value, statusIn } = id.findBy;
  if (!COLUMN.test(column) || statusIn.length === 0) throw new RangeError('A gathered row is found by one column');
  return sql`(
    select f.id from ${sql.table(table.table)} as f
    where f.org_id = ${orgId} and ${sql.ref(`f.${column}`)} = ${value}
      and f.status in (${sql.join(statusIn.map((status) => sql`${status}`))})
    limit 1
  )`;
}

/**
 * The ID a uuid field of another row holds, as an expression. Read as text, so a column swapped for another type
 * gives null, for that row's own read to call unreadable, rather than failing the statement.
 */
function lookedUpId(
  orgId: string,
  { table, id, column }: { readonly table: SignedStateTable; readonly id: string; readonly column: string },
): RawBuilder<unknown> {
  checkTable(table);
  if (!UUID.test(id)) throw new RangeError('A signed row is named by UUIDs');
  if (!table.fields.some((field) => field.column === column && field.type === 'uuid')) {
    throw new RangeError("A gathered ID is looked up in a row's uuid field");
  }
  const field = sql`(${sql.ref('l.' + column)})::text`;
  return sql`(
    select ${asUuid(field)} from ${sql.table(table.table)} as l
    where l.org_id = ${orgId} and l.id = ${id.toLowerCase()}::uuid
    limit 1
  )`;
}

/** The read of an earlier row of the gather. */
function earlier(reads: readonly GatheredRead[], index: number): GatheredRead {
  const read = reads[index];
  if (read === undefined) throw new RangeError('A gathered ID comes from an earlier row');
  return read;
}

/**
 * readSignedRow's statement, not run, for a caller that reads the row inside a
 * statement of its own (4D2d P3a) and judges what it gave with signedRowSeen.
 * The caller must hold withTenant's transaction for the row's organisation, as
 * readSignedRow checks. Beside the row: its version as locked (`xmin`, after
 * any wait for the lock) and as the statement's snapshot saw it (every copy's,
 * so a duplicated row reaches rowOf, which calls it unreadable, rather than
 * failing the statement), and its state_version column's type.
 */
export function signedRowReadSeen(table: SignedStateTable, key: SignedRowKey, lock: RowLock): RawBuilder<unknown> {
  return signedRowRead(table, key, lock, true);
}

/** An oid as a row's JSON gives it (text), as the driver gives it (a number); anything else as it came. */
const typeId = (value: unknown): unknown =>
  typeof value === 'string' && /^\d{1,10}$/.test(value) ? Number(value) : value;

/**
 * The row signedRowReadSeen's statement gave, read back as JSON, judged as
 * readSignedRow judges one: undefined when the row locked isn't the version
 * the snapshot saw (it changed while the statement waited for the lock, maybe
 * put back to an older signed state), so the caller reads it again.
 */
export function signedRowSeen(
  table: SignedStateTable,
  rows: readonly Readonly<Record<string, unknown>>[],
): SignedRow | undefined {
  const [row, ...others] = rows;
  if (row === undefined) return { outcome: 'missing' };
  if (others.length > 0) return rowOf(table, rows);
  const { locked_xmin: locked, seen_xmin: seen, version_type: versionType } = row;
  if (typeof locked !== 'string' || locked !== seen) return undefined;
  // JSON gives a version of any numeric type as a number, where the driver gives a bigint or numeric as text:
  // anything but an integer column is left to readSignedRow, which calls it unreadable (23 is int4's oid).
  if (versionType !== '23') return undefined;
  return rowOf(table, [typedJson(row)]);
}

/** A row read back as JSON with each field's type (t0, t1…) as the driver gives an oid. */
const typedJson = (row: Readonly<Record<string, unknown>>): Record<string, unknown> =>
  Object.fromEntries(
    Object.entries(row).map(([column, value]) => [column, /^t\d+$/.test(column) ? typeId(value) : value]),
  );

/** The most rows readSignedRows reads in one statement. */
export const MOST_SIGNED_ROWS_READ = 500;

/**
 * Reads many rows as readSignedRow reads one, in one statement, each locked
 * `share` in order of ID, in the caller's transaction, which must be
 * withTenant's for the organisation. Every ID asked has its read in the map,
 * by its ID in lower case: `missing` where no row holds it, and each judged
 * alone by readSignedRow's rules.
 */
export async function readSignedRows<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  orgId: string,
  ids: readonly string[],
): Promise<ReadonlyMap<string, SignedRow>> {
  checkTable(table);
  if (!UUID.test(orgId) || !ids.every((id) => UUID.test(id))) throw new RangeError('A signed row is named by UUIDs');
  const asked = [...new Set(ids.map((id) => id.toLowerCase()))];
  if (asked.length > MOST_SIGNED_ROWS_READ) {
    throw new RangeError(`At most ${MOST_SIGNED_ROWS_READ.toString()} signed rows are read at once`);
  }
  if (asked.length === 0) return new Map();
  await assertTenant(tx, orgId);
  const { rows } = await sql<Record<string, unknown>>`
    select target.id::text as row_id, ${columnsOf(table)} from ${sql.table(table.table)} as target
    where target.org_id = ${orgId} and target.id = any(${asked}::uuid[])
    order by target.id
    for share
  `.execute(tx);
  return new Map(
    asked.map((id) => [
      id,
      rowOf(
        table,
        rows.filter(({ row_id: rowId }) => rowId === id),
      ),
    ]),
  );
}

/**
 * The IDs of the table's rows in the organisation, in order (Postgres gives a
 * uuid as text in lower case), after the row `after` (null from the start),
 * at most `limit` and one more, so the caller can tell a list cut short; only
 * rows in one of `statuses` when given. `newest` lists from the highest ID
 * down, `after` then the row before which to go on (a time-ordered ID: the
 * newest first, Phase 3 B3). Locks nothing: each row is read again through
 * readSignedRow. Only in withTenant's transaction for the organisation, like
 * readSignedRow.
 */
export async function signedRowIds<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  orgId: string,
  limit: number,
  after: string | null = null,
  statuses: readonly string[] | null = null,
  order: 'oldest' | 'newest' = 'oldest',
): Promise<string[]> {
  checkTable(table);
  if (!UUID.test(orgId) || (after !== null && !UUID.test(after)))
    throw new RangeError('A signed row is named by UUIDs');
  if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError('The limit is a whole number from 1');
  // None at all would list nothing, which a caller would read as nothing to check.
  if (statuses?.length === 0) throw new RangeError('Rows are listed in at least one status');
  await assertTenant(tx, orgId);
  const newest = order === 'newest';
  const { rows } = await sql<{ id: string }>`
    select target.id::text as id from ${sql.table(table.table)} as target
    where target.org_id = ${orgId}
    ${after === null ? sql`` : newest ? sql`and target.id < ${after}` : sql`and target.id > ${after}`}
    ${statuses === null ? sql`` : sql`and target.status = any(${[...statuses]}::text[])`}
    ${newest ? sql`order by target.id desc` : sql`order by target.id`}
    limit ${limit + 1}
  `.execute(tx);
  return rows.map(({ id }) => id);
}

/**
 * Writes the authority fields `set` names and gives back the row as it now
 * is, with each value written read as text by the same SQL. From `new`: a row
 * at version 1 pointing nowhere, the one the transaction has just inserted,
 * and `set` names every field. From a version and pointer: only while the row
 * still holds them, and it moves to the next version, pointing nowhere until
 * its event is recorded; a pointer of null is a version written in this
 * transaction whose event goes in with the next's (4D2d P13). A row in any
 * other state is left as it is (`missing`). Only after readSignedRow locked
 * the row for a change, in the same transaction.
 */
export async function writeSignedRow<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  key: SignedRowKey,
  from: 'new' | { readonly version: number; readonly eventId: string | null },
  set: SignedFieldValues,
): Promise<WrittenRow> {
  checkTable(table);
  checkKey(key);
  const values = valuesToWrite(table, set, from === 'new');
  const assignments = [
    ...(from === 'new' ? [] : [sql`state_version = target.state_version + 1`, sql`state_event_id = null`]),
    ...values.map(([{ column, type }, value]) => sql`${sql.ref(column)} = ${typed(type, value)}`),
  ];
  const { version, eventId } = from === 'new' ? { version: 1, eventId: null } : from;
  const pointer = eventId === null ? sql`target.state_event_id is null` : sql`target.state_event_id = ${eventId}`;
  const state = sql`target.state_version = ${version} and ${pointer}`;
  const echoes = values.map(
    ([{ type }, value], index) => sql`${canonical(type, typed(type, value))} as ${sql.id('w' + index.toString())}`,
  );
  // The alias keeps the text after the table name from starting with SET,
  // which the lint rule against session-wide settings would take for one.
  const { rows } = await sql<Record<string, unknown>>`
    update ${sql.table(table.table)} as target set ${sql.join(assignments)}
    where target.org_id = ${key.orgId} and target.id = ${key.id} and ${state}
    returning ${sql.join([columnsOf(table), ...echoes])}
  `.execute(tx);
  const row = rowOf(table, rows);
  const written = values.map(([{ column }], index): readonly [string, unknown] => [
    column,
    rows[0]?.[`w${index.toString()}`],
  ]);
  if (row.outcome === 'found' && !written.every(([, value]) => isText(value))) {
    return { row: { outcome: 'unreadable' }, written: [] };
  }
  return Object.freeze({ row, written: Object.freeze(written as FieldText[]) });
}

/**
 * Points the row at the event that recorded its version: only a row at that
 * version and pointing nowhere yet. Gives back the row as it now is, `missing`
 * if no row was in that state.
 */
export async function pointSignedRow<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  key: SignedRowKey,
  at: { readonly version: number; readonly eventId: string },
): Promise<SignedRow> {
  const { rows } = await pointing(table, key, at, sql``, sql``).execute(tx);
  return rowOf(table, rows);
}

/** pointSignedRow's update, with `gate` ANDed to its filter and `more` returned beside the row. */
function pointing(
  table: SignedStateTable,
  key: SignedRowKey,
  at: { readonly version: number; readonly eventId: string },
  gate: RawBuilder<unknown>,
  more: RawBuilder<unknown>,
): RawBuilder<Record<string, unknown>> {
  checkTable(table);
  checkKey(key);
  if (!UUID.test(at.eventId)) throw new RangeError('A signed row points at an event by its UUID');
  return sql<Record<string, unknown>>`
    update ${sql.table(table.table)} as target set state_event_id = ${at.eventId}::uuid
    where target.org_id = ${key.orgId} and target.id = ${key.id}
      and target.state_version = ${at.version} and target.state_event_id is null${gate}
    returning ${columnsOf(table)}${more}
  `;
}

/**
 * pointSignedRow's update, not run, for the event's own write to carry in
 * its statement (4D2d P8), `gate` ANDed to its filter (that the event was
 * written); read what it gave back as JSON with signedRowPointed.
 */
export function signedRowPointing(
  table: SignedStateTable,
  key: SignedRowKey,
  at: { readonly version: number; readonly eventId: string },
  gate: RawBuilder<unknown>,
): RawBuilder<unknown> {
  return pointing(
    table,
    key,
    at,
    sql` and ${gate}`,
    sql`, pg_catalog.pg_typeof(target.state_version)::oid::text as version_type`,
  );
}

/**
 * The row signedRowPointing's update gave, read back as JSON, judged as
 * pointSignedRow judges it: anything but an integer version is unreadable,
 * as the driver's text for a wider one is.
 */
export function signedRowPointed(
  table: SignedStateTable,
  rows: readonly Readonly<Record<string, unknown>>[],
): SignedRow {
  if (rows.some(({ version_type: versionType }) => versionType !== '23')) return { outcome: 'unreadable' };
  return rowOf(table, rows.map(typedJson));
}
