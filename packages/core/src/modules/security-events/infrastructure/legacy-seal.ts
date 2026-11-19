// The security rows from before 0105 given their MACs, once (S206 V6), as
// 0100's people were (S205 backfillUserMacs). From then on a row with no MAC
// is never believed, whatever its ID or dates: not shown, not counted, and
// alarmed when met.
//
// The rows from before are the ones 0105 marked `before_macs`; every row
// after carries its MAC as it is written (the database refuses one without).
// In the background once the API serves, never holding up or stopping a
// start: if the platform chain says every row is sealed
// (`security_events.all_sealed`), nothing is done. If not:
// 1. Every table is searched for a marked row that already carries a MAC. Before
//    sealing begins none can; one found means the chain's record was deleted
//    past the app: the alarm, and nothing sealed again, so no row the owner
//    planted or tampered with since is blessed.
// 2. The start records `sealing_started` (under its lock, so of starts at once
//    one records it and every other joins), then gives each marked row without
//    a MAC its MAC, a page at a time. Then it records `all_sealed`.
// 3. A start that finds sealing begun but not finished never seals a row: it
//    waits for the other start's `all_sealed` (two starting at once), and
//    without it, in WAIT_FOR_OTHER_MS, raises the alarm (that start died part
//    way, or the record was deleted). The rows left then stay unbelieved, as
//    owner-planted ones: a stop, never a grant; the API serves on.
// Both records are read only through the platform chain's checked read: one
// edited (for one start, say, to have sealing run again over rows tampered
// with) fails its MAC, and nothing is sealed: the alarm. A deleted record is
// also a deleted platform-chain event, which the anchor check finds as a chain
// wound back.
//
// TODO(S206 AT10-style): delete this, and its call at start, once the release
// that brings 0105 has started everywhere and every environment holds
// `all_sealed`, as 0100's people backfill goes.
import { setTimeout as sleep } from 'node:timers/promises';

import { holdTransactionLock, limitedTransaction, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, type RawBuilder, sql, type Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import {
  createPlatformChain,
  type PlatformControlsTables,
  platformEventSealed,
  platformEventsSigned,
} from '../../platform-controls/index.ts';
import { eventMac, evidenceMessage, rowMac } from './event-seals.ts';
import type { SecurityEventsTables } from './tables.ts';

/** The platform events that record the sealing: begun, and done. */
export const SEALING_STARTED = 'security_events.sealing_started';
export const ALL_SEALED = 'security_events.all_sealed';

/**
 * After this, no sealing runs at all (as 0100's people backfill had USER_MAC_BACKFILL_UNTIL): the release has started
 * everywhere well before, so a sealing record missing by then was deleted. A later commit removes the sealing, tracked
 * with AT10.
 */
export const SECURITY_SEAL_BACKFILL_UNTIL = Date.parse('2026-12-07T00:00:00.000Z');

/** How long a start waits for another's sealing to finish before taking its missing record as deleted. */
const WAIT_FOR_OTHER_MS = 60_000;

/** How often it looks while it waits. */
const WAIT_STEP_MS = 2_000;

/** How many rows one page seals. */
const PAGE = 500;

const ACTOR = { type: 'system', id: 'api' } as const;

type Tables = SecurityEventsTables & PlatformControlsTables;
type Tx = Transaction<Tables>;

/** What the sealing found: every row sealed; its record deleted past the app; or a record that can't be believed. */
export type LegacySealing = 'sealed' | 'deleted' | 'unsealed';

/** A place on the platform chain, its event's MAC checked. */
interface ChainPlace {
  readonly seq: bigint;
  readonly hash: Buffer;
  readonly macKeyVersion: number;
}

/** The records on the platform chain, each sealed: where sealing began, if it did, and where it finished, if it did. */
interface Records {
  readonly started: ChainPlace | undefined;
  readonly sealedAt: bigint | undefined;
}

/** The records as their rows stand, each one's MAC checked; `unsealed` if any can't be believed. */
async function recordsIn(tx: Tx, keys: KeyProvider): Promise<Records | 'unsealed'> {
  const rows = await platformEventsSigned(tx).where('e.action', 'in', [SEALING_STARTED, ALL_SEALED]).execute();
  if (!rows.every((row) => platformEventSealed(keys, row))) return 'unsealed';
  const started = rows.find((row) => row.action === SEALING_STARTED);
  return {
    started:
      started === undefined
        ? undefined
        : { seq: started.seq, hash: started.hash, macKeyVersion: started.mac_key_version },
    sealedAt: rows.find((row) => row.action === ALL_SEALED)?.seq,
  };
}

/** A row as Postgres gives it back, each column as its table declares it. */
type Row = Readonly<Record<string, unknown>>;
const textOrNull = (value: unknown): string | null => (typeof value === 'string' ? value : null);

/** One table as the sealing reads it: which, what it selects, and each row's MAC. */
interface LegacyTable {
  readonly table: RawBuilder<unknown>;
  readonly columns: RawBuilder<unknown>;
  readonly macOf: (keys: KeyProvider, row: Row) => { readonly mac: Buffer; readonly mac_key_version: number };
}

/** An event row's MAC: the global table's (no organisation, no agent) or an organisation's. */
const eventRowMac = (keys: KeyProvider, row: Row) =>
  eventMac(keys, {
    id: String(row.id),
    orgId: textOrNull(row.org_id ?? null),
    kind: String(row.kind),
    reason: String(row.reason),
    ip: textOrNull(row.ip),
    userId: textOrNull(row.user_id),
    agentId: textOrNull(row.agent_id ?? null),
    windowStart: row.window_start as Date,
    count: Number(row.count),
    createdAt: row.created_at as Date,
  });

const GLOBAL_EVENTS: LegacyTable = {
  table: sql.table('security.events'),
  columns: sql`id, kind, reason, ip, user_id, window_start, count, created_at`,
  macOf: eventRowMac,
};

const ORG_EVENTS: LegacyTable = {
  table: sql.table('security.org_events'),
  columns: sql`org_id, id, kind, reason, ip, user_id, agent_id, window_start, count, created_at`,
  macOf: eventRowMac,
};

const EVIDENCE: LegacyTable = {
  table: sql.table('security.partner_event_evidence'),
  columns: sql`id, reason, ip, body_key_version, body_bytes, received_at`,
  macOf: (keys, row) =>
    rowMac(
      keys,
      evidenceMessage({
        id: String(row.id),
        reason: String(row.reason),
        ip: textOrNull(row.ip),
        body_key_version: Number(row.body_key_version),
        body_bytes: Number(row.body_bytes),
        received_at: row.received_at as Date,
      }),
    ),
};

/** Seals the table's next page of rows without a MAC, after `after`: the last ID it read, or undefined at the end. */
async function sealPage(tx: Tx, keys: KeyProvider, legacy: LegacyTable, after: string): Promise<string | undefined> {
  const { rows } = await sql<Row>`
    select ${legacy.columns} from ${legacy.table} where mac is null and before_macs and id > ${after}::uuid order by id limit ${PAGE}
  `.execute(tx);
  const last = rows.at(-1);
  if (last === undefined) return undefined;
  const macs = rows.map((row) => legacy.macOf(keys, row));
  // One statement a page, each row only while it still has no MAC: starts sealing at once do it once.
  await sql`
    update ${legacy.table} as t
    set mac = pg_catalog.decode(v.mac, 'hex'), mac_key_version = v.version
    from (
      select pg_catalog.unnest(${rows.map((row) => String(row.id))}::uuid[]) as id,
        pg_catalog.unnest(${macs.map(({ mac }) => mac.toString('hex'))}::text[]) as mac,
        pg_catalog.unnest(${macs.map(({ mac_key_version }) => mac_key_version)}::int[]) as version
    ) as v
    where t.id = v.id and t.mac is null
  `.execute(tx);
  return String(last.id);
}

/** The nil UUID: before every ID. */
const BEFORE_ALL = '00000000-0000-0000-0000-000000000000';

/** Seals every row of the table without a MAC, a page a transaction, each opened by `open`. */
async function sealTable(
  open: <T>(work: (tx: Tx) => Promise<T>) => Promise<T>,
  keys: KeyProvider,
  legacy: LegacyTable,
): Promise<void> {
  let after: string | undefined = BEFORE_ALL;
  while (after !== undefined) {
    const from: string = after;
    after = await open((tx) => sealPage(tx, keys, legacy, from));
  }
}

/** Whether any row of the table from before 0105 already carries a MAC: only a sealing gives one. */
const anyMac = async (tx: Tx, legacy: LegacyTable): Promise<boolean> => {
  const { rows } = await sql`select 1 from ${legacy.table} where mac is not null and before_macs limit 1`.execute(tx);
  return rows.length > 0;
};

export async function sealLegacyRows(
  db: Kysely<Tables>,
  {
    keys,
    ids,
    clock,
    logger,
    orgs,
    waitForOtherMs = WAIT_FOR_OTHER_MS,
  }: {
    readonly keys: KeyProvider;
    readonly ids: IdGenerator;
    /** Read against SECURITY_SEAL_BACKFILL_UNTIL. */
    readonly clock: Clock;
    readonly logger: Logger;
    /** Every organisation, whose own rows are sealed inside its transaction. */
    readonly orgs: () => Promise<readonly string[]>;
    /** WAIT_FOR_OTHER_MS, but for the tests. */
    readonly waitForOtherMs?: number;
  },
): Promise<LegacySealing> {
  const plain = <T>(work: (tx: Tx) => Promise<T>) => limitedTransaction(db, work);
  const inOrg =
    (orgId: string) =>
    <T>(work: (tx: Tx) => Promise<T>) =>
      withTenant(db, orgId, work, { limited: true });
  const alarm = (reason: 'deleted' | 'unsealed'): LegacySealing => {
    logger.error('audit.integrity_failed', {
      chain: 'platform',
      check: 'security_event',
      reason: `seal_record_${reason}`,
    });
    return reason;
  };

  /** Whether any row of any table already carries a MAC: one per organisation's transaction for its own. */
  const anySigned = async (): Promise<boolean> => {
    if (await plain(async (tx) => (await anyMac(tx, GLOBAL_EVENTS)) || anyMac(tx, EVIDENCE))) return true;
    for (const orgId of await orgs()) if (await inOrg(orgId)((tx) => anyMac(tx, ORG_EVENTS))) return true;
    return false;
  };

  const platform = createPlatformChain({ keys, ids });

  /**
   * The records, read and then held to the chain itself: from where sealing began, every event after it checked in
   * number, link and MAC (the anchor check's own walk), as far as the record of its end at least. So a record deleted
   * from the middle of the chain shows as the gap it leaves, not only as a record missing. `unsealed` if any fails.
   */
  const records = async (): Promise<Records | 'unsealed'> => {
    const found = await plain((tx) => recordsIn(tx, keys));
    if (found === 'unsealed' || found.started === undefined) return found;
    const step = await platform.checkFromAnchor(db, found.started);
    if (!step.ok) return 'unsealed';
    return found.sealedAt !== undefined && step.seq < found.sealedAt ? 'unsealed' : found;
  };

  /**
   * Records that this start seals, unless one began meanwhile (its record then read): what the chain says, `deleted`
   * when a row from before 0105 already carries a MAC, or no record when this start is to seal.
   */
  const begin = async () => {
    const signed = await anySigned();
    // Under its lock, read again: a start that began meanwhile wrote its record before any MAC, so it shows here.
    return plain(async (tx) => {
      await holdTransactionLock(tx, SEALING_STARTED);
      const now = await recordsIn(tx, keys);
      if (now === 'unsealed' || now.sealedAt !== undefined || now.started !== undefined) return now;
      if (signed) return 'deleted' as const;
      await platform.record(tx, { actor: ACTOR, action: SEALING_STARTED, details: {} });
      return now;
    });
  };

  /**
   * Another start began sealing: waits for its `all_sealed`, never sealing a row itself. One that never comes (that
   * start died, or the record was deleted past the app) is the alarm, and the rows stay unsealed: never believed.
   */
  const awaitOther = async (): Promise<LegacySealing> => {
    const until = performance.now() + waitForOtherMs;
    for (;;) {
      const now = await records();
      if (now === 'unsealed') return alarm('unsealed');
      if (now.sealedAt !== undefined) return 'sealed';
      if (performance.now() >= until) return alarm('deleted');
      await sleep(WAIT_STEP_MS);
    }
  };

  const found = await records();
  if (found === 'unsealed') return alarm('unsealed');
  if (found.sealedAt !== undefined) return 'sealed';
  // Past the cutoff no sealing runs, whatever the chain shows: one missing by then is a record deleted.
  if (clock.now().getTime() >= SECURITY_SEAL_BACKFILL_UNTIL) return alarm('deleted');
  const begun = await begin();
  if (begun === 'unsealed' || begun === 'deleted') return alarm(begun);
  if (begun.sealedAt !== undefined) return 'sealed';
  if (begun.started !== undefined) return awaitOther();
  await sealTable(plain, keys, GLOBAL_EVENTS);
  await sealTable(plain, keys, EVIDENCE);
  for (const orgId of await orgs()) await sealTable(inOrg(orgId), keys, ORG_EVENTS);
  await plain(async (tx) => {
    await holdTransactionLock(tx, SEALING_STARTED);
    const now = await recordsIn(tx, keys);
    if (now !== 'unsealed' && now.sealedAt === undefined) {
      await platform.record(tx, { actor: ACTOR, action: ALL_SEALED, details: {} });
    }
  });
  return 'sealed';
}
