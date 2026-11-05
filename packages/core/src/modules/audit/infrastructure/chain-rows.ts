// 4D2e E9 (PL-29): an organisation's chain read row by row, for its recovery
// plan (apps/operator/src/chain-recovery.ts). Each row comes as the chain checks
// it and, where it can be read as the app writes one, with every column as
// stored: what a plan would write back is exactly what was read, its original
// MAC with it, never anything made again. Read only, in withTenant's
// transaction for the organisation, limited as the anchor check's reads.
//
// An operator's event is judged as every other reader judges it (PL-57,
// sealedSigned): from where signing started on its chain, one without the
// operator's own signature reads as unsealed, so a plan never keeps or blesses
// one. Its signature, where it has one, is a column of the row like any other:
// put back with its event, never made again.
import {
  type Chain,
  type ChainHead,
  ChainStoreError,
  headFields,
  sealedFields,
  sealedSigned,
  type StoredEntry,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import { assertTenant, JOB_ANSWER_WITHIN_MS, withTenant } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import { contentOf, SIGNED_EVENT_COLUMNS } from './audit-trail.ts';
import type { AuditTables } from './tables.ts';

/** An event's columns as stored, the bytes as hex and the time to the millisecond: enough to write the row again exactly. */
export interface StoredColumns {
  readonly seq: string;
  readonly id: string;
  readonly recordedAt: string;
  readonly actorType: string;
  readonly actorId: string;
  readonly action: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly subjectVersion: number;
  /** The canonical JSON text that was sealed, exactly. */
  readonly details: string;
  readonly prevHash: string;
  readonly hash: string;
  readonly mac: string;
  readonly macKeyVersion: number;
  /** The operator's signature on its event (PL-57), as stored in audit.operator_signatures, where it has one. */
  readonly signature?: { readonly signature: string; readonly keyVersion: number };
}

/**
 * Every column of a row as stored, whatever it holds: numbers as text, bytes as
 * hex, the time in UTC to the microsecond, as Postgres holds it. A row the app never
 * wrote is kept so, as evidence, before a recovery removes it.
 */
export type StoredValues = Readonly<Record<string, unknown>>;

/**
 * One stored row: its number, every column as stored, and the event as the chain
 * checks it with its columns, or neither where it can't be read. The entry's MAC
 * is taken as missing where the operator's signature it needs is not there or
 * doesn't check (sealedSigned); its columns keep the MAC as stored.
 */
export interface StoredRow {
  readonly seq: bigint;
  readonly stored: StoredValues;
  readonly read: { readonly entry: StoredEntry; readonly columns: StoredColumns } | undefined;
}

/** The event table's columns, as a stored row keeps them. */
const STORED_COLUMNS = [
  'seq',
  'id',
  'actor_type',
  'actor_id',
  'action',
  'subject_type',
  'subject_id',
  'subject_version',
  'details',
  'prev_hash',
  'hash',
  'mac',
  'mac_key_version',
  // The operator's signature on it, if any: evidence too, kept with a row removed.
  'signature',
  'signature_key_version',
] as const;

/** A value as JSON can hold it: bytes as hex, a whole number as text; anything else as read. */
const storedValue = (value: unknown): unknown => {
  if (typeof value === 'bigint') return value.toString();
  return Buffer.isBuffer(value) ? value.toString('hex') : value;
};

/** Every column of a row as stored, the time as Postgres's own text in UTC (`recorded_text`). */
function storedValues(row: Readonly<Record<string, unknown>>): StoredValues {
  const entries: [string, unknown][] = [
    ...STORED_COLUMNS.map((column): [string, unknown] => [column, storedValue(row[column])]),
    ['recorded_at', row.recorded_text],
  ];
  return Object.fromEntries(entries);
}

/** A page of a chain's rows, and its head as it stood in the same statement. */
export interface ChainRowsPage {
  readonly head: ChainHead | 'none' | 'unreadable';
  readonly rows: readonly StoredRow[];
}

/** The columns of a row the chain could read, from the row and its checked entry. */
function columnsOf(row: Readonly<Record<string, unknown>>, entry: StoredEntry): StoredColumns {
  const { signature, signature_key_version: keyVersion } = row;
  const signed =
    Buffer.isBuffer(signature) && typeof keyVersion === 'number'
      ? { signature: { signature: signature.toString('hex'), keyVersion } }
      : {};
  return {
    seq: entry.seq.toString(),
    id: entry.id,
    recordedAt: entry.recordedAt.toISOString(),
    // contentOf has read each of these as text, and the version as a number, or there would be no entry.
    actorType: String(row.actor_type),
    actorId: String(row.actor_id),
    action: String(row.action),
    subjectType: String(row.subject_type),
    subjectId: String(row.subject_id),
    subjectVersion: Number(row.subject_version),
    details: String(row.details),
    prevHash: entry.prevHash.toString('hex'),
    hash: entry.hash.toString('hex'),
    mac: entry.mac.toString('hex'),
    macKeyVersion: entry.macKeyVersion,
    ...signed,
  };
}

/** A stored row as read: any number the table holds, below 1 too, as one that isn't the app's is part of what a plan judges. */
function storedRow(keys: KeyProvider, chain: Chain, row: Readonly<Record<string, unknown>>): StoredRow {
  const { seq } = row;
  if (typeof seq !== 'bigint') throw new ChainStoreError('it read an event with no number');
  const sealed = sealedFields(row);
  const signed = sealedSigned(keys, chain, row);
  const content = contentOf(row);
  const stored = storedValues(row);
  if (sealed === undefined || signed === undefined || content === undefined) return { seq, stored, read: undefined };
  return { seq, stored, read: { entry: { ...signed, content }, columns: columnsOf(row, { ...sealed, content }) } };
}

/**
 * Whether the database holds 0079's tables of the operator's signatures (PL-57), which every row's read joins: a
 * copy restored from before 0079 holds none, and a plan refuses it in plain words rather than failing its read.
 */
export async function holdsOperatorSignatures(db: Kysely<AuditTables>): Promise<boolean> {
  const { rows } = await sql<{ held: boolean }>`
    select pg_catalog.to_regclass('audit.operator_signatures') is not null
       and pg_catalog.to_regclass('audit.operator_signing_starts') is not null as held
  `.execute(db);
  return rows[0]?.held === true;
}

/**
 * Where 0079 wrote down that signing starts on the organisation's chain, or null where it wrote nothing (a chain made
 * after it). A plan holds a copy to the live server's: a copy's own start, raised, would let it believe an operator's
 * event unsigned that the live chain never could.
 */
export function operatorSigningStart(db: Kysely<AuditTables>, orgId: string): Promise<bigint | null> {
  return withTenant(db, orgId, (tx) => operatorSigningStartIn(tx, orgId), {
    limited: true,
    answeredWithinMs: JOB_ANSWER_WITHIN_MS,
  });
}

/** operatorSigningStart in the caller's transaction, withTenant's for the organisation: a chain repair's (4D2e E10). */
export async function operatorSigningStartIn(tx: Transaction<AuditTables>, orgId: string): Promise<bigint | null> {
  const org = orgId.toLowerCase();
  await assertTenant(tx, org);
  const { rows } = await sql<{ signed_from: bigint }>`
    select f.signed_from from audit.operator_signing_starts f where f.org_id = ${org}
  `.execute(tx);
  return rows[0]?.signed_from ?? null;
}

/** The head as read: none with no head row, unreadable with more than one or one of the wrong types. */
function headOf(heads: unknown, head: ChainHead | undefined): ChainRowsPage['head'] {
  if (heads === 0n) return 'none';
  return heads === 1n && head !== undefined ? head : 'unreadable';
}

/**
 * Up to `limit` of the organisation's events numbered after `after` (from the
 * lowest stored when null), in number order, and its head, all in one
 * statement, so a page and its head come from one moment: in the caller's
 * transaction, withTenant's for the organisation (a chain repair's, 4D2e E10).
 */
export async function chainRowsIn(
  tx: Transaction<AuditTables>,
  keys: KeyProvider,
  orgId: string,
  after: bigint | null,
  limit: number,
): Promise<ChainRowsPage> {
  const org = orgId.toLowerCase();
  await assertTenant(tx, org);
  const chain: Chain = { kind: 'organisation', orgId: org };
  const { rows } = await sql<Record<string, unknown>>`
    select (select pg_catalog.count(*) from audit.heads c where c.org_id = ${org}) as heads,
           h.seq as head_seq, h.hash as head_hash, h.mac as head_mac, h.mac_key_version as head_mac_key_version,
           page.*
    from (values (1)) as one (x)
    left join (select * from audit.heads a where a.org_id = ${org} limit 1) as h on true
    left join lateral (
      select ${SIGNED_EVENT_COLUMNS}, pg_catalog.to_char(e.recorded_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as recorded_text from audit.events e
      where e.org_id = ${org} and (${after}::bigint is null or e.seq > ${after}::bigint)
      order by e.seq limit ${limit}
    ) as page on true
    order by page.seq
  `.execute(tx);
  const [first = {}] = rows;
  const head = headFields({
    seq: first.head_seq,
    hash: first.head_hash,
    mac: first.head_mac,
    mac_key_version: first.head_mac_key_version,
  });
  return {
    head: headOf(first.heads, head),
    // With no event in the page, the one row the left joins give holds no event.
    rows: rows.filter((row) => row.seq !== null).map((row) => storedRow(keys, chain, row)),
  };
}

/** chainRowsIn in a transaction of its own, withTenant's for the organisation, limited as the anchor check's reads. */
export function chainRowsAlone(
  db: Kysely<AuditTables>,
  keys: KeyProvider,
  orgId: string,
  after: bigint | null,
  limit: number,
): Promise<ChainRowsPage> {
  return withTenant(db, orgId, (tx) => chainRowsIn(tx, keys, orgId, after, limit), {
    limited: true,
    answeredWithinMs: JOB_ANSWER_WITHIN_MS,
  });
}
