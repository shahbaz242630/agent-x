// The security rows from before 0105 given their MACs, once (S206 V6), as
// 0100's people were (S205 backfillUserMacs). From then on a row with no MAC
// is never believed, whatever its ID or dates: not shown, not counted, and
// alarmed when met.
//
// The rows from before are the ones 0105 marked `before_macs`; every row
// after carries its MAC as it is written (the database refuses one without).
// In the background once the web side serves, never holding up or stopping a
// start: if the platform chain says every row is sealed
// (`security_events.all_sealed`), nothing is done. If not, one sealer at a
// time, under SEALER_LOCK, a session lock held with no transaction open for
// the whole sealing (a copy that finds it held returns at once, quietly):
// 0. The platform chain is held to its last anchor, from the write-once store
//    outside the database the anchor check keeps: a chain wiped, or wound back
//    past it, or no anchor at all, is the alarm, and nothing is sealed.
// 1. Unless sealing began (`security_events.sealing_started`), every table is
//    searched for a marked row that already carries a MAC. Before sealing
//    begins none can; one found means the chain's record was deleted past the
//    app: the alarm, and nothing sealed, so no row the owner planted or
//    tampered with since is blessed. Else it records `sealing_started`, with
//    its manifest: the count and digest of every marked row in its scope,
//    and the time it began (`until`): a row written from then on is never
//    in its scope, so a row the owner marks later is never given a MAC.
// 2. It gives each marked row in scope without a MAC its MAC, a page at a
//    time, then records `all_sealed`. A sealing begun and left (a stop, a
//    failure part way) is taken up again by the next start only if the marked
//    rows are still those of the manifest (none planted, deleted or edited
//    since), until SECURITY_SEAL_BACKFILL_UNTIL; after it, one unfinished is
//    the alarm, and the rows left stay unbelieved: a stop, never a grant.
// The records are read through the platform chain's own walk from where
// sealing began: one edited fails its MAC, one deleted from the middle leaves
// a gap; either is the alarm and nothing is sealed.
//
// TODO(S206 AT10-style): delete this, and its call at start, once the release
// that brings 0105 has started everywhere and every environment holds
// `all_sealed`, as 0100's people backfill goes.
import { createHash, type Hash } from 'node:crypto';

import { limitedTransaction, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, type RawBuilder, sql, type Transaction } from 'kysely';

import { type Clock, DAY_MS, type IdGenerator } from '../../../shared-kernel/index.ts';
import {
  createPlatformChain,
  type PlatformControlsTables,
  platformEventSealed,
  platformEventsSigned,
} from '../../platform-controls/index.ts';
import { eventMac, evidenceMessage, firstCheckableDay, type LegacyRows, rowMac } from './event-seals.ts';
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

/**
 * The detail each start of the API records on the platform chain (`platform.started`, start-record.ts) from this
 * release on: its own time. The schema guard keeps any start off a database without 0105, so no row from before 0105
 * is newer than the first start that records it, and it holds where nothing else does yet: before any sealing has
 * begun, its lock taken by the owner from the first start on. A bound read off the rows themselves (the first row
 * written with a MAC, say) won't do: the owner strips the earliest such row of its MAC, and the bound moves past it.
 * This one is sealed with the chain: one edited, or with its detail removed, fails its MAC here at once (every start
 * up to it is checked), one deleted leaves a gap (the daily walk of the whole chain; the anchor check walks only
 * past its latest anchor).
 */
export const ROW_MACS_FROM = 'rowMacsFrom';

/** The earliest of the times given (`now` always among them). */
const earliest = (now: Date, ...others: readonly (Date | undefined)[]): Date =>
  new Date(Math.min(now.getTime(), ...others.flatMap((at) => (at === undefined ? [] : [at.getTime()]))));

/** The advisory lock the one sealer at a time holds, its whole sealing long. */
export const SEALER_LOCK = 'security-events-legacy-sealer';

/** How many rows one page seals. */
const PAGE = 500;

const ACTOR = { type: 'system', id: 'api' } as const;

type Tables = SecurityEventsTables & PlatformControlsTables;
type Tx = Transaction<Tables>;

/** Why the sealing stopped short, its alarm raised. */
type SealAlarm = 'deleted' | 'unsealed' | 'unanchored' | 'manifest';

/**
 * What the sealing found: every row sealed; another sealer at work; or why it stopped short, its alarm raised: its
 * record deleted past the app, a record or the chain that can't be believed, no anchor to hold the chain to, or rows
 * from before 0105 not the ones it began with.
 */
export type LegacySealing = 'sealed' | 'busy' | SealAlarm;

/** A place on the platform chain, its event's MAC checked. */
export interface ChainPlace {
  readonly seq: bigint;
  readonly hash: Buffer;
  readonly macKeyVersion: number;
}

/** One UTC day of a manifest: how many marked rows say they were written in it, and the digest of them. */
interface ManifestDay {
  readonly rows: number;
  readonly digest: string;
}

/**
 * What `sealing_started` records of the rows from before 0105 as it began, a day at a time (by when each says it was
 * written): so a sealing taken up again days later holds the rows to it only for the days the sweep can't yet have
 * touched, never reading a row the sweep took as one deleted.
 */
export interface Manifest {
  /**
   * The rows it holds: those written from this time on. Older ones, the sweep's within days, are left to it unsealed
   * (never believed).
   */
  readonly since: string;
  readonly days: Readonly<Record<string, ManifestDay>>;
}

/** The records on the platform chain, each sealed: where sealing began and its manifest, if it did; where it ended. */
interface Records {
  readonly started: (ChainPlace & { readonly manifest: Manifest; readonly until: Date }) | undefined;
  readonly sealedAt: bigint | undefined;
}

/**
 * When the sealing began, as its record holds it: the time it took before reading the rows (`until`), or, for a record
 * written before it kept one, the chain's own time of the record. No row written from then on is one from before
 * 0105: the sealing never gives one a MAC, and the day seal never excuses one.
 */
function untilIn(details: string, recordedAt: Date): Date {
  const { until } = JSON.parse(details) as Record<string, unknown>;
  return typeof until === 'string' ? new Date(until) : recordedAt;
}

/** The manifest a record's details hold, or undefined for none. */
function manifestIn(details: string): Manifest | undefined {
  const { since, days } = JSON.parse(details) as Record<string, unknown>;
  if (typeof since !== 'string' || typeof days !== 'string') return undefined;
  // Sealed with the record, as the app wrote it: read as it was written.
  return { since, days: JSON.parse(days) as Record<string, ManifestDay> };
}

/**
 * each such day the same digest (over every row, so the same rows too), and none with rows now that had none then.
 * each such day the same count and digest, and none with rows now that had none then.
 */
function manifestHolds(then: Manifest, now: Manifest, from: string): boolean {
  const days = new Set([...Object.keys(then.days), ...Object.keys(now.days)].filter((day) => day >= from));
  return [...days].every((day) => then.days[day]?.digest === now.days[day]?.digest);
}

/** The records as their rows stand, each one's MAC checked; `unsealed` if any can't be believed, or begun with none. */
async function recordsIn(tx: Tx, keys: KeyProvider): Promise<Records | 'unsealed'> {
  const rows = await platformEventsSigned(tx).where('e.action', 'in', [SEALING_STARTED, ALL_SEALED]).execute();
  if (!rows.every((row) => platformEventSealed(keys, row))) return 'unsealed';
  const started = rows.find((row) => row.action === SEALING_STARTED);
  const manifest = started === undefined ? undefined : manifestIn(started.details);
  if (started !== undefined && manifest === undefined) return 'unsealed';
  return {
    started:
      started === undefined || manifest === undefined
        ? undefined
        : {
            seq: started.seq,
            hash: started.hash,
            macKeyVersion: started.mac_key_version,
            manifest,
            until: untilIn(started.details, started.recorded_at),
          },
    sealedAt: rows.find((row) => row.action === ALL_SEALED)?.seq,
  };
}

/**
 * What the day seal and the admins' page are told of the marked rows with no MAC at `now` (event-seals.ts LegacyRows),
 * from the records as recordsIn reads them, each MAC-checked: until `all_sealed` is recorded, rows written before the
 * sealing began (`until`), or before now if it hasn't begun (a first start's minutes; a sealing held up longer is its
 * job's own alarm, legacy-seal-job.ts); once it has ended, rows written before its scope (`since`), left to the sweep;
 * past the cutoff with no end, none. `unsealed` for a record that can't be believed: the caller's alarm. A record
 * deleted can't widen the excuse for long: the platform chain's own checks find the gap or the wound-back head (this
 * sealing's next run, the anchor check), and the cutoff ends it regardless.
 */
export async function legacyRowsAt(tx: Tx, keys: KeyProvider, now: Date): Promise<LegacyRows | 'unsealed'> {
  const found = await recordsIn(tx, keys);
  if (found === 'unsealed') return 'unsealed';
  const { started } = found;
  if (found.sealedAt !== undefined) {
    return { excusedBefore: started === undefined ? null : new Date(started.manifest.since) };
  }
  if (now.getTime() >= SECURITY_SEAL_BACKFILL_UNTIL) return { excusedBefore: null };
  if (started !== undefined) return { excusedBefore: started.until };
  const first = await firstStartWithMacs(tx, keys);
  return first === 'unsealed' ? 'unsealed' : { excusedBefore: earliest(now, first) };
}

/**
 * The time the first start of the API to record ROW_MACS_FROM gives; undefined for none yet (a database no such API
 * has started on: tests, a laptop's first run). Every start up to it is MAC-checked, so one whose detail the owner
 * removed, to pass for a start from before, is `unsealed` at once, as is one edited. One start a boot: few rows.
 */
async function firstStartWithMacs(tx: Tx, keys: KeyProvider): Promise<Date | undefined | 'unsealed'> {
  const starts = await platformEventsSigned(tx).where('e.action', '=', 'platform.started').orderBy('e.seq').execute();
  for (const start of starts) {
    if (!platformEventSealed(keys, start)) return 'unsealed';
    const at = (JSON.parse(start.details) as Record<string, unknown>)[ROW_MACS_FROM];
    if (at !== undefined) return typeof at === 'string' ? new Date(at) : 'unsealed';
  }
  return undefined;
}

/** A row as Postgres gives it back, each column as its table declares it. */
type Row = Readonly<Record<string, unknown>>;
const textOrNull = (value: unknown): string | null => (typeof value === 'string' ? value : null);

/** One table as the sealing reads it: which, what it selects, and each row's MAC. */
interface LegacyTable {
  readonly table: RawBuilder<unknown>;
  readonly columns: RawBuilder<unknown>;
  /** When a row says it was written: what the sealing's scope is held to, and the manifest's days. */
  readonly written: RawBuilder<unknown>;
  readonly writtenColumn: 'created_at' | 'received_at';
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
  written: sql.ref('created_at'),
  writtenColumn: 'created_at',
  macOf: eventRowMac,
};

const ORG_EVENTS: LegacyTable = {
  table: sql.table('security.org_events'),
  columns: sql`org_id, id, kind, reason, ip, user_id, agent_id, window_start, count, created_at`,
  written: sql.ref('created_at'),
  writtenColumn: 'created_at',
  macOf: eventRowMac,
};

const EVIDENCE: LegacyTable = {
  table: sql.table('security.partner_event_evidence'),
  columns: sql`id, reason, ip, body_key_version, body_bytes, received_at`,
  written: sql.ref('received_at'),
  writtenColumn: 'received_at',
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

/**
 * The rows a sealing gives MACs: those written from `since` (older ones left to the sweep) and before `until`, when it
 * began, so a row marked after that (by the owner: no release writes one) is never blessed.
 */
interface SealScope {
  readonly since: Date;
  readonly until: Date;
}

/** Seals the table's next page of rows without a MAC, after `after`: the last ID it read, or undefined at the end. */
async function sealPage(
  tx: Tx,
  keys: KeyProvider,
  legacy: LegacyTable,
  { since, until }: SealScope,
  after: string,
): Promise<string | undefined> {
  const { rows } = await sql<Row>`
    select ${legacy.columns} from ${legacy.table}
    where mac is null and before_macs and ${legacy.written} >= ${since} and ${legacy.written} < ${until}
      and id > ${after}::uuid
    order by id limit ${PAGE}
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

/** Seals every row of the table in scope without a MAC, a page a transaction, each opened by `open`. */
async function sealTable(
  open: <T>(work: (tx: Tx) => Promise<T>) => Promise<T>,
  keys: KeyProvider,
  legacy: LegacyTable,
  scope: SealScope,
): Promise<void> {
  let after: string | undefined = BEFORE_ALL;
  while (after !== undefined) {
    const from: string = after;
    after = await open((tx) => sealPage(tx, keys, legacy, scope, from));
  }
}

/** Whether any row of the table from before 0105 already carries a MAC: only a sealing gives one. */
/** Whether any row of the table from before 0105 is still without a MAC. */
const anyUnsealedIn = async (tx: Tx, legacy: LegacyTable): Promise<boolean> => {
  const { rows } = await sql`select 1 from ${legacy.table} where mac is null and before_macs limit 1`.execute(tx);
  return rows.length > 0;
};

const anyMac = async (tx: Tx, legacy: LegacyTable): Promise<boolean> => {
  const { rows } = await sql`select 1 from ${legacy.table} where mac is not null and before_macs limit 1`.execute(tx);
  return rows.length > 0;
};

/** A table's rows from before 0105, sealed or not, after `after`, a page of them by ID: what the manifest digests. */
async function markedPage(tx: Tx, legacy: LegacyTable, since: Date, after: string): Promise<readonly Row[]> {
  const { rows } = await sql<Row>`
    select ${legacy.columns} from ${legacy.table}
    where before_macs and ${legacy.written} >= ${since} and id > ${after}::uuid
    order by id limit ${PAGE}
  `.execute(tx);
  return rows;
}

/** A row's line in the manifest: its table and every column its MAC covers, as JSON. */
const manifestLine = (name: string, row: Row): string =>
  `${JSON.stringify([name, ...Object.values(row).map((value) => (value instanceof Date ? value.toISOString() : value))])}\n`;

/**
 * The rows from before 0105, sealed or not, counted and digested: SHA-256 over one line a row, table by table, by ID,
 * each its table and every column its MAC covers (its MAC aside, which the sealing writes). So a row planted, deleted
 * or edited between the sealing's start and a later start that takes it up again changes it.
 */
export async function legacyManifest(
  db: Kysely<Tables>,
  orgs: () => Promise<readonly string[]>,
  since: Date,
): Promise<Manifest> {
  const days = new Map<string, { rows: number; hash: Hash }>();
  const digestTable = async (
    open: <T>(work: (tx: Tx) => Promise<T>) => Promise<T>,
    name: string,
    legacy: LegacyTable,
  ): Promise<void> => {
    let after = BEFORE_ALL;
    for (;;) {
      const from = after;
      const page = await open((tx) => markedPage(tx, legacy, since, from));
      for (const row of page) {
        const day = (row[legacy.writtenColumn] as Date).toISOString().slice(0, 10);
        const seen = days.get(day) ?? { rows: 0, hash: createHash('sha256') };
        seen.hash.update(manifestLine(name, row));
        seen.rows += 1;
        days.set(day, seen);
      }
      const last = page.at(-1);
      if (last === undefined || page.length < PAGE) return;
      after = String(last.id);
    }
  };
  const plain = <T>(work: (tx: Tx) => Promise<T>) => limitedTransaction(db, work);
  await digestTable(plain, 'events', GLOBAL_EVENTS);
  await digestTable(plain, 'evidence', EVIDENCE);
  for (const orgId of await orgs()) {
    await digestTable((work) => withTenant(db, orgId, work, { limited: true }), 'org_events', ORG_EVENTS);
  }
  return {
    since: since.toISOString(),
    days: Object.fromEntries(
      [...days].map(([day, seen]) => [day, { rows: seen.rows, digest: seen.hash.digest('hex') }] as const),
    ),
  };
}

export async function sealLegacyRows(
  db: Kysely<Tables>,
  {
    keys,
    ids,
    clock,
    logger,
    orgs,
    retentionDays,
    anchor,
    anchorNow,
    notAfter,
  }: {
    readonly keys: KeyProvider;
    readonly ids: IdGenerator;
    /** Read against SECURITY_SEAL_BACKFILL_UNTIL. */
    readonly clock: Clock;
    readonly logger: Logger;
    /** Every organisation, whose own rows are sealed inside its transaction. */
    readonly orgs: () => Promise<readonly string[]>;
    /** AGENTX_SECURITY_EVENT_RETENTION_DAYS: rows within a day or two of it are left to the sweep. */
    readonly retentionDays: number;
    /** The platform chain's last anchor, from the store outside the database the anchor check keeps; undefined for none. */
    readonly anchor: () => Promise<ChainPlace | undefined>;
    /** Anchors the chain at its head now, as the anchor check does; never throws (a failure is its own to say). */
    readonly anchorNow: () => Promise<void>;
    /** When its job first found the lock taken, if it is so now: a new sealing's rows were all written before it. */
    readonly notAfter?: Date | undefined;
  },
): Promise<LegacySealing> {
  const plain = <T>(work: (tx: Tx) => Promise<T>) => limitedTransaction(db, work);
  const inOrg =
    (orgId: string) =>
    <T>(work: (tx: Tx) => Promise<T>) =>
      withTenant(db, orgId, work, { limited: true });
  const alarm = (reason: SealAlarm): LegacySealing => {
    logger.error('audit.integrity_failed', {
      chain: 'platform',
      check: 'security_event',
      reason: `seal_record_${reason}`,
    });
    return reason;
  };

  /** Whether any marked row of any table is still without a MAC: one per organisation's transaction for its own. */
  const anyUnsealed = async (): Promise<boolean> => {
    if (await plain(async (tx) => (await anyUnsealedIn(tx, GLOBAL_EVENTS)) || anyUnsealedIn(tx, EVIDENCE))) return true;
    for (const orgId of await orgs()) if (await inOrg(orgId)((tx) => anyUnsealedIn(tx, ORG_EVENTS))) return true;
    return false;
  };

  /** Whether any row of any table already carries a MAC: one per organisation's transaction for its own. */
  const anySigned = async (): Promise<boolean> => {
    if (await plain(async (tx) => (await anyMac(tx, GLOBAL_EVENTS)) || anyMac(tx, EVIDENCE))) return true;
    for (const orgId of await orgs()) {
      if (await inOrg(orgId)((tx) => anyMac(tx, ORG_EVENTS))) return true;
    }
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
   * The chain held to its last anchor, from the store outside the database: a chain wiped, or wound back past it (the
   * records deleted from its tail before an anchor passed them, then the anchor kept), never passes. Why not, or none.
   */
  const anchoredProblem = async (): Promise<SealAlarm | undefined> => {
    const from = await anchor();
    if (from === undefined) return 'unanchored';
    return (await platform.checkFromAnchor(db, from)).ok ? undefined : 'unsealed';
  };

  /** Records an event of the sealing's on the platform chain, in a transaction of its own. */
  const recordAlone = (action: string, details: Readonly<Record<string, string | number>> = {}) =>
    plain(async (tx) => {
      await platform.record(tx, { actor: ACTOR, action, details });
    });

  /**
   * The sealing itself, its lock held: begun with its manifest, or taken up again only over the very rows it began
   * with; every marked row given its MAC; its end recorded.
   */
  const sealAll = async (): Promise<LegacySealing> => {
    // Read again under the lock: a sealer before this one may have finished meanwhile.
    const now = await records();
    if (now === 'unsealed') return alarm('unsealed');
    if (now.sealedAt !== undefined) return 'sealed';
    const unanchored = await anchoredProblem();
    if (unanchored !== undefined) return alarm(unanchored);
    // A new sealing's scope: the rows two days or more inside the retention; one taken up again keeps its own.
    // ...and before it began: no later than the first start that records ROW_MACS_FROM, nor than its job first found
    // the lock taken (a sealing held up, then let go), every row from before 0105 written before either.
    const first = now.started === undefined ? await plain((tx) => firstStartWithMacs(tx, keys)) : undefined;
    if (first === 'unsealed') return alarm('unsealed');
    const scope: SealScope = {
      since: new Date(now.started?.manifest.since ?? clock.now().getTime() - (retentionDays - 2) * DAY_MS),
      until: now.started?.until ?? earliest(clock.now(), first, notAfter),
    };
    const manifest = await legacyManifest(db, orgs, scope.since);
    if (now.started === undefined) {
      if (await anySigned()) return alarm('deleted');
      await recordAlone(SEALING_STARTED, {
        since: manifest.since,
        until: scope.until.toISOString(),
        days: JSON.stringify(manifest.days),
      });
      // Anchored at once: deleting the record is then a chain wound back past an anchor, which step 0 refuses.
      await anchorNow();
    } else if (!manifestHolds(now.started.manifest, manifest, firstCheckableDay(clock.now(), retentionDays))) {
      return alarm('manifest');
    }
    await sealTable(plain, keys, GLOBAL_EVENTS, scope);
    await sealTable(plain, keys, EVIDENCE, scope);
    for (const orgId of await orgs()) await sealTable(inOrg(orgId), keys, ORG_EVENTS, scope);
    await recordAlone(ALL_SEALED);
    await anchorNow();
    return 'sealed';
  };

  // Its end recorded and sealed: done, with no walk of the chain (nothing will be sealed, so nothing rests on it).
  const found = await plain((tx) => recordsIn(tx, keys));
  if (found === 'unsealed') return alarm('unsealed');
  if (found.sealedAt !== undefined) return 'sealed';
  // Past the cutoff no sealing runs, nor is one taken up again. A marked row still without a MAC by then is a sealing
  // unfinished or its record deleted: the alarm. With none (a database made after 0105, say) there is nothing to do.
  if (clock.now().getTime() >= SECURITY_SEAL_BACKFILL_UNTIL) return (await anyUnsealed()) ? alarm('deleted') : 'sealed';
  // One sealer at a time: a session lock on a connection of its own, held with no transaction open (so no limit on
  // a transaction left waiting can end it however long the sealing runs), given back at the end; a copy that finds it
  // held leaves the work to that one, quietly. A connection lost takes the lock with it.
  return db.connection().execute(async (own) => {
    const { rows } = await sql<{ taken: boolean }>`
      select pg_catalog.pg_try_advisory_lock(pg_catalog.hashtextextended(${SEALER_LOCK}, 0)) as taken
    `.execute(own);
    if (rows[0]?.taken !== true) return 'busy';
    try {
      return await sealAll();
    } finally {
      await sql`select pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended(${SEALER_LOCK}, 0))`.execute(own);
    }
  });
}
