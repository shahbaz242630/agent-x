// Signed-state rows (ADR-012 §2), the row's side. A table whose fields grant,
// restore or limit authority (a status, a role, a limit, an expiry) keeps two
// columns beside them:
//
//   state_version  integer NOT NULL  the version its latest signed event made, from 1
//   state_event_id uuid              that event's ID; NULL only inside the
//                                    transaction that creates the row
//
// The audit module's signed states (verifiedState and record) read and move
// these columns through the steps here, in the module's own transaction. The
// SQL is written once, as for status changes (status.ts): the module gives its
// table's name and its authority fields, constants of its own, never input.
//
// Each authority field is read as canonical text in SQL, the same way when a
// state is sealed and when a row is checked against its seal, so the two can
// only differ if the value did. A time is read in UTC to the microsecond,
// whatever the session's time zone or date style.
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
  /** The type its rows are recorded as in the audit trail: `agent`, `agent_key`. */
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

/**
 * What the row holds:
 * - `found`: its version, the event it points at, and its authority fields
 *   as canonical text (or null), in the table's order
 * - `missing`: no row with the key in this organisation
 * - `unreadable`: more than one row has the key, or the version or pointer
 *   isn't one the app writes; someone past the app changed the table
 */
export type SignedRow =
  | {
      readonly outcome: 'found';
      readonly version: number;
      readonly eventId: string | null;
      readonly fields: readonly (readonly [column: string, value: string | null])[];
    }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'unreadable' };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * Names from our migrations, never from input: checked on every call anyway,
 * since they go into the SQL as names, quoted, rather than as bound values.
 */
const TABLE = /^[a-z][a-z0-9_]{0,62}\.[a-z][a-z0-9_]{0,62}$/;
const COLUMN = /^[a-z][a-z0-9_]{0,62}$/;
const TYPES: ReadonlySet<string> = new Set<SignedFieldType>(['text', 'uuid', 'integer', 'timestamptz']);
/** The signed-state columns themselves: sealing the pointer would need the event's ID before the event exists. */
const OWN_COLUMNS: ReadonlySet<string> = new Set(['state_version', 'state_event_id']);
/** Postgres's integer, the state_version column's type. */
const MAX_VERSION = 2_147_483_647;

/** Refuses a table definition no module should write, before any SQL is built from it. */
function checkTable({ table, fields }: SignedStateTable): void {
  if (!TABLE.test(table)) throw new RangeError('A signed-state table is named schema.table, in lower-case words');
  if (fields.length === 0) throw new RangeError('A signed-state table seals at least one field');
  const columns = new Set<string>();
  for (const { column, type } of fields) {
    if (!COLUMN.test(column) || OWN_COLUMNS.has(column) || columns.has(column) || !TYPES.has(type)) {
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

/** The field as canonical text, from the row aliased `target`. */
function canonical({ column, type }: SignedField): RawBuilder<unknown> {
  const value = sql.ref(`target.${column}`);
  return type === 'timestamptz'
    ? sql`pg_catalog.to_char((${value}) at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
    : sql`(${value})::text`;
}

/** The pointer, the version and each field, as one list for a select or a returning clause. */
function columnsOf({ fields }: SignedStateTable): RawBuilder<unknown> {
  return sql.join([
    sql`target.state_version`,
    sql`target.state_event_id`,
    ...fields.map((field, index) => sql`${canonical(field)} as ${sql.id(`f${index.toString()}`)}`),
  ]);
}

const isVersion = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= MAX_VERSION;

/** The rows read back, judged as untrusted: the table's owner could have changed any of them, or their types. */
function rowOf({ fields }: SignedStateTable, rows: readonly Readonly<Record<string, unknown>>[]): SignedRow {
  const [row, ...others] = rows;
  if (row === undefined) return { outcome: 'missing' };
  const { state_version: version, state_event_id: eventId } = row;
  const values = fields.map(({ column }, index): readonly [string, unknown] => [column, row[`f${index.toString()}`]]);
  if (
    others.length > 0 ||
    !isVersion(version) ||
    (eventId !== null && (typeof eventId !== 'string' || !UUID.test(eventId))) ||
    !values.every(([, value]) => value === null || typeof value === 'string')
  ) {
    return { outcome: 'unreadable' };
  }
  return Object.freeze({
    outcome: 'found',
    version,
    eventId: eventId?.toLowerCase() ?? null,
    fields: Object.freeze(values as (readonly [string, string | null])[]),
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
 * Moves the row on to its next version, only while it still holds the version
 * and pointer it was verified with, and clears its pointer until the new
 * version's event is recorded. Gives the row as it now is, or `missing` when
 * no row matched. Only after readSignedRow locked the row for a change, in
 * the same transaction.
 */
export async function advanceSignedRow<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  key: SignedRowKey,
  from: { readonly version: number; readonly eventId: string },
): Promise<SignedRow> {
  checkTable(table);
  checkKey(key);
  // The alias keeps the text after the table name from starting with SET,
  // which the lint rule against session-wide settings would take for one.
  const { rows } = await sql<Record<string, unknown>>`
    update ${sql.table(table.table)} as target set state_version = target.state_version + 1, state_event_id = null
    where target.org_id = ${key.orgId} and target.id = ${key.id}
      and target.state_version = ${from.version} and target.state_event_id = ${from.eventId}
    returning ${columnsOf(table)}
  `.execute(tx);
  return rowOf(table, rows);
}

/**
 * Points the row at the event that recorded its version: only a row at that
 * version and pointing nowhere yet. Whether exactly that row now points there.
 */
export async function pointSignedRow<Schema>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  key: SignedRowKey,
  at: { readonly version: number; readonly eventId: string },
): Promise<boolean> {
  checkTable(table);
  checkKey(key);
  const { rows } = await sql<{ state_event_id: unknown }>`
    update ${sql.table(table.table)} as target set state_event_id = ${at.eventId}
    where target.org_id = ${key.orgId} and target.id = ${key.id}
      and target.state_version = ${at.version} and target.state_event_id is null
    returning target.state_event_id
  `.execute(tx);
  const [row, ...others] = rows;
  return (
    others.length === 0 &&
    typeof row?.state_event_id === 'string' &&
    row.state_event_id.toLowerCase() === at.eventId.toLowerCase()
  );
}
