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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * Names from our migrations, never from input: checked on every call anyway,
 * since they go into the SQL as names, quoted, rather than as bound values.
 */
const TABLE = /^[a-z][a-z0-9_]{0,62}\.[a-z][a-z0-9_]{0,62}$/;
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
      return [
        sql`${canonical(type, value)} as ${sql.id(`f${index.toString()}`)}`,
        sql`pg_catalog.pg_typeof(${value})::oid as ${sql.id(`t${index.toString()}`)}`,
      ];
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
  checkTable(table);
  checkKey(key);
  await assertTenant(tx, key.orgId);
  // Filtered by org_id as well as row security, as ADR-005 §7 asks of every query.
  const { rows } = await sql<Record<string, unknown>>`
    select ${columnsOf(table)} from ${sql.table(table.table)} as target
    where target.org_id = ${key.orgId} and target.id = ${key.id}
    ${lock === 'share' ? sql`for share` : sql`for no key update`}
  `.execute(tx);
  return rowOf(table, rows);
}

/**
 * The IDs of the table's rows in the organisation, in order (Postgres gives a
 * uuid as text in lower case), at most `limit` and one more, so the caller can tell a list cut short. Locks
 * nothing: each row is read again through readSignedRow. Only in withTenant's
 * transaction for the organisation, like readSignedRow.
 */
export async function signedRowIds<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  orgId: string,
  limit: number,
): Promise<string[]> {
  checkTable(table);
  if (!UUID.test(orgId)) throw new RangeError('A signed row is named by UUIDs');
  if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError('The limit is a whole number from 1');
  await assertTenant(tx, orgId);
  const { rows } = await sql<{ id: string }>`
    select target.id::text as id from ${sql.table(table.table)} as target
    where target.org_id = ${orgId}
    order by target.id
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
 * its event is recorded. A row in any other state is left as it is
 * (`missing`). Only after readSignedRow locked the row for a change, in the
 * same transaction.
 */
export async function writeSignedRow<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  key: SignedRowKey,
  from: 'new' | { readonly version: number; readonly eventId: string },
  set: SignedFieldValues,
): Promise<WrittenRow> {
  checkTable(table);
  checkKey(key);
  const values = valuesToWrite(table, set, from === 'new');
  const assignments = [
    ...(from === 'new' ? [] : [sql`state_version = target.state_version + 1`, sql`state_event_id = null`]),
    ...values.map(([{ column, type }, value]) => sql`${sql.ref(column)} = ${typed(type, value)}`),
  ];
  const state =
    from === 'new'
      ? sql`target.state_version = 1 and target.state_event_id is null`
      : sql`target.state_version = ${from.version} and target.state_event_id = ${from.eventId}`;
  const echoes = values.map(
    ([{ type }, value], index) => sql`${canonical(type, typed(type, value))} as ${sql.id(`w${index.toString()}`)}`,
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
  checkTable(table);
  checkKey(key);
  const { rows } = await sql<Record<string, unknown>>`
    update ${sql.table(table.table)} as target set state_event_id = ${at.eventId}
    where target.org_id = ${key.orgId} and target.id = ${key.id}
      and target.state_version = ${at.version} and target.state_event_id is null
    returning ${columnsOf(table)}
  `.execute(tx);
  return rowOf(table, rows);
}
