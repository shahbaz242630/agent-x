// 4D2e E10 (PL-29): an organisation's chain repaired from a recovery plan
// (apps/operator/src/chain-restore.ts), in the repair's one transaction,
// withTenant's for the organisation, as the owner: the only role that may
// change or delete an event. What it writes is the copy's original rows as a
// plan read them (chain-rows.ts), each with its original MAC and, where it has
// one, the operator's original signature: nothing here makes a MAC, a
// signature or a hash, and it holds no key. A row it can't vouch for still
// reaches the table only to fail the whole check the repair runs before it
// commits, which rolls everything back.
import type { ChainHead } from '@agentx/platform/audit-chain';
import { assertTenant } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';

import type { StoredColumns } from './chain-rows.ts';
import type { AuditTables } from './tables.ts';

/** A row a repair writes: an original put back or in place of another, or a row removed. */
export type RepairRow =
  | { readonly action: 'put_back' | 'replace'; readonly seq: bigint; readonly columns: StoredColumns }
  | { readonly action: 'remove'; readonly seq: bigint };

/** How many rows one insert carries: a long repair in a few statements, none of them huge. */
const ROWS_A_STATEMENT = 5000;

/**
 * Takes the chain's head row's lock, which every writer of the chain takes
 * before it adds an event (ADR-006 §6), so nothing is added while the repair
 * reads and writes. A chain with no head row has nothing to lock: a writer
 * then refuses the chain, and a head added meanwhile meets the repair's own
 * insert of one and fails it.
 */
export async function lockChainHead(tx: Transaction<AuditTables>, orgId: string): Promise<void> {
  await assertTenant(tx, orgId);
  await sql`select h.seq from audit.heads h where h.org_id = ${orgId.toLowerCase()} for update`.execute(tx);
}

/** Splits rows into slices of ROWS_A_STATEMENT. */
const slices = <T>(rows: readonly T[]): T[][] =>
  Array.from({ length: Math.ceil(rows.length / ROWS_A_STATEMENT) }, (_, at) =>
    rows.slice(at * ROWS_A_STATEMENT, (at + 1) * ROWS_A_STATEMENT),
  );

/** Each list as a column of rows, side by side (ROWS FROM over pg_catalog.unnest), each cast to its type. */
const rowsFrom = (columns: readonly (readonly [readonly unknown[], string])[]) =>
  sql`rows from (${sql.join(columns.map(([values, type]) => sql`pg_catalog.unnest(${values}::${sql.raw(type)}[])`))})`;

/** The events' columns a repair writes, each with its type in the lists it is sent as (hex for the bytes). */
const EVENT_COLUMNS = [
  ['seq', 'bigint'],
  ['id', 'uuid'],
  ['recordedAt', 'timestamptz'],
  ['actorType', 'text'],
  ['actorId', 'text'],
  ['action', 'text'],
  ['subjectType', 'text'],
  ['subjectId', 'uuid'],
  ['subjectVersion', 'integer'],
  ['details', 'text'],
  ['prevHash', 'text'],
  ['hash', 'text'],
  ['mac', 'text'],
  ['macKeyVersion', 'integer'],
] as const satisfies readonly (readonly [keyof StoredColumns, string])[];

/** Puts the rows in as they were read: every column from its text, the bytes from hex. */
async function insertOriginals(tx: Transaction<AuditTables>, org: string, rows: readonly StoredColumns[]) {
  for (const slice of slices(rows)) {
    const events = rowsFrom(EVENT_COLUMNS.map(([key, type]) => [slice.map((row) => row[key]), type] as const));
    await sql`
      insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
                                subject_version, details, prev_hash, hash, mac, mac_key_version)
      select ${org}::uuid, r.seq, r.id, r.recorded_at, r.actor_type, r.actor_id, r.action, r.subject_type, r.subject_id,
             r.subject_version, r.details, pg_catalog.decode(r.prev_hash, 'hex'), pg_catalog.decode(r.hash, 'hex'),
             pg_catalog.decode(r.mac, 'hex'), r.mac_key_version
      from ${events} as r (seq, id, recorded_at, actor_type, actor_id, action, subject_type, subject_id,
                           subject_version, details, prev_hash, hash, mac, mac_key_version)
    `.execute(tx);
    const signed = slice.flatMap((row) => (row.signature === undefined ? [] : [{ seq: row.seq, ...row.signature }]));
    if (signed.length === 0) continue;
    const signatures = rowsFrom([
      [signed.map((row) => row.seq), 'bigint'],
      [signed.map((row) => row.signature), 'text'],
      [signed.map((row) => row.keyVersion), 'integer'],
    ]);
    await sql`
      insert into audit.operator_signatures (org_id, seq, signature, key_version)
      select ${org}::uuid, s.seq, pg_catalog.decode(s.signature, 'hex'), s.key_version
      from ${signatures} as s (seq, signature, key_version)
    `.execute(tx);
  }
}

/**
 * Writes a plan's rows and head in the caller's transaction, withTenant's for
 * the organisation: each place the plan names emptied of its event and its
 * operator's signature (one with no signature in the copy must have none
 * live, or a stray one would keep it unsealed), then the originals put in,
 * then the head. The caller checks the whole chain before it commits.
 */
export async function writeOriginalRows(
  tx: Transaction<AuditTables>,
  orgId: string,
  rows: readonly RepairRow[],
  head: ChainHead | undefined,
): Promise<void> {
  const org = orgId.toLowerCase();
  await assertTenant(tx, org);
  const places = rows.map((row) => row.seq.toString());
  const taken = rows.filter((row) => row.action !== 'put_back').map((row) => row.seq.toString());
  if (places.length > 0) {
    await sql`delete from audit.operator_signatures s where s.org_id = ${org} and s.seq = any(${places}::bigint[])`.execute(
      tx,
    );
  }
  if (taken.length > 0) {
    await sql`delete from audit.events e where e.org_id = ${org} and e.seq = any(${taken}::bigint[])`.execute(tx);
  }
  await insertOriginals(
    tx,
    org,
    rows.flatMap((row) => (row.action === 'remove' ? [] : [row.columns])),
  );
  if (head === undefined) return;
  await sql`
    insert into audit.heads (org_id, seq, hash, mac, mac_key_version)
    values (${org}, ${head.seq}, ${head.hash}, ${head.mac}, ${head.macKeyVersion})
    on conflict (org_id) do update
      set seq = excluded.seq, hash = excluded.hash, mac = excluded.mac, mac_key_version = excluded.mac_key_version
  `.execute(tx);
}
