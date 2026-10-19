// The activity log's background downloads (Phase 3 L5c, partner decision 31;
// 0053): a range too long for one instant download, built a UTC month at a
// time in the background, one compressed file a month, kept 7 days.
//
// - Asked: the download's row and one row a month, in the transaction that
//   records `access_log.export_requested` (the download's ID is the event's).
//   Its requests are those written by then (`writtenUpTo`, the newest row's
//   UUIDv7), so a month built again after a stop holds the same ones.
// - Built: a builder claims a month (`FOR UPDATE SKIP LOCKED`, so two
//   servers never take the same one) for a lease it renews as it writes;
//   every later write names the lease it holds (`building_until`), so a
//   builder whose lease ran out, and was taken over, changes nothing. A month
//   tried too often fails, and its download's waiting months with it.
// - Ready once every month is, failed once one is; expired 7 days after its
//   last month was ready. Times are the database's own clock, as the lease
//   and `file_moves` (0053) read it.
//
// Every read and write is in the organisation's transaction, so its
// row-level security holds them too.
import { type ExpressionBuilder, sql, type Transaction } from 'kysely';

import { ACTIVITY_ACTOR_TYPES, type ActivityActor, type ActivityRange } from './activity-reads.ts';
import type { ActivityExportTables, ActivityTables } from './tables.ts';

type ExportTx = Transaction<ActivityExportTables & ActivityTables>;

/** The months table as `f`, as the claim and the under-way check read it. */
type FilesAsF = ActivityExportTables & ActivityTables & { f: ActivityExportTables['activity_exports.files'] };

/** How long a background download is kept once ready (decision 31). */
export const DOWNLOAD_KEPT_DAYS = 7;

/** A background download's formats, as an instant download's. */
export const DOWNLOAD_FORMATS = ['csv', 'ndjson'] as const;
export type DownloadFormat = (typeof DOWNLOAD_FORMATS)[number];

/** A background download as asked for. */
export interface BackgroundExportAsked extends ActivityRange {
  readonly id: string;
  readonly requestedBy: string;
  readonly format: DownloadFormat;
  /** The newest request written when it was asked; null when the organisation had none. */
  readonly writtenUpTo: string | null;
}

/** Where a download stands: building, ready (until it expires), or failed. */
export type BackgroundExportState = 'building' | 'ready' | 'expired' | 'failed';

/** One month's file as listed: its month (YYYY-MM), and once ready its count, size and SHA-256. */
export interface BackgroundExportFile {
  readonly month: string;
  readonly state: 'waiting' | 'building' | 'ready' | 'failed';
  /** How many times it was claimed: a ready file's is the try whose file it is (storedName). */
  readonly attempts: number;
  readonly requests: number | null;
  readonly bytes: number | null;
  readonly sha256: string | null;
}

/** A download as its organisation's admins see it. */
export interface BackgroundExport {
  readonly id: string;
  readonly requestedBy: string;
  readonly requestedAt: Date;
  readonly from: Date;
  readonly to: Date;
  readonly actor: ActivityActor | null;
  readonly format: DownloadFormat;
  readonly writtenUpTo: string | null;
  readonly state: BackgroundExportState;
  /** When it is, or was, deleted: 7 days after its last file was ready; null until then. */
  readonly expiresAt: Date | null;
  readonly files: readonly BackgroundExportFile[];
}

/** A month a builder holds: which, the download it is of, and the lease every write must name. */
export interface ClaimedFile {
  readonly exportId: string;
  /** The month's first day, YYYY-MM-DD. */
  readonly month: string;
  /** This claim's try, from 1: the file it writes is this try's own (storedName). */
  readonly attempt: number;
  readonly lease: Date;
  readonly download: BackgroundExport;
}

/**
 * Where a month's file is stored: its organisation, its download, its month
 * and the try that wrote it, so a builder that lost its lease and one that
 * took the month on never write into the same file, and a ready file, never
 * changed again, is read whole from one place.
 */
export const storedName = (
  orgId: string,
  { exportId, month, attempt, format }: { exportId: string; month: string; attempt: number; format: DownloadFormat },
): string => `${orgId}/${exportId}/${month.slice(0, 7)}-try${String(attempt)}.${format}.gz`;

/** What a claim found: a month to build, a month given up (tried too often), or nothing to build. */
export type Claim =
  | { readonly outcome: 'claimed'; readonly file: ClaimedFile }
  | { readonly outcome: 'given_up'; readonly exportId: string; readonly month: string; readonly requestedBy: string }
  | { readonly outcome: 'none' };

/** The UTC months [from, to) touches, each by its first day (YYYY-MM-DD), oldest first. */
export function monthsOf({ from, to }: { readonly from: Date; readonly to: Date }): string[] {
  const months: string[] = [];
  let at = Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), 1);
  while (at < to.getTime()) {
    months.push(new Date(at).toISOString().slice(0, 10));
    const month = new Date(at);
    at = Date.UTC(month.getUTCFullYear(), month.getUTCMonth() + 1, 1);
  }
  return months;
}

/** The part of the download's range in `month` (its first day, YYYY-MM-DD). */
export function rangeInMonth(range: { readonly from: Date; readonly to: Date }, month: string): ActivityRange {
  const start = new Date(`${month}T00:00:00.000Z`);
  const end = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + 1, 1));
  return {
    from: new Date(Math.max(start.getTime(), range.from.getTime())),
    to: new Date(Math.min(end.getTime(), range.to.getTime())),
  };
}

/** The ID of the newest request the organisation's log holds, null for none: on the primary key, newest first. */
export async function newestWritten(tx: ExportTx, orgId: string): Promise<string | null> {
  const newest = await tx
    .selectFrom('access.requests')
    .select('id')
    .where('org_id', '=', orgId)
    .orderBy('id', 'desc')
    .limit(1)
    .executeTakeFirst();
  return newest?.id ?? null;
}

/** Of a month `f`: none of its download's months failed (the download isn't given up). */
const noMonthFailed = (eb: ExpressionBuilder<FilesAsF, 'f'>) =>
  eb.not(
    eb.exists(
      eb
        .selectFrom('activity_exports.files as failed')
        .select('failed.month')
        .whereRef('failed.org_id', '=', 'f.org_id')
        .whereRef('failed.export_id', '=', 'f.export_id')
        .where('failed.state', '=', 'failed'),
    ),
  );

/** Whether the organisation has a download still being built: one of its months waiting or building, none failed. */
export async function downloadUnderWay(tx: ExportTx, orgId: string): Promise<boolean> {
  const found = await tx
    .selectFrom('activity_exports.files as f')
    .select('f.export_id')
    .where('f.org_id', '=', orgId)
    .where('f.state', 'in', ['waiting', 'building'])
    .where(noMonthFailed)
    .limit(1)
    .executeTakeFirst();
  return found !== undefined;
}

/** Adds the download and its months, waiting, in the caller's transaction (the one recording its event). */
export async function addBackgroundExport(tx: ExportTx, orgId: string, asked: BackgroundExportAsked): Promise<void> {
  await tx
    .insertInto('activity_exports.exports')
    .values({
      org_id: orgId,
      id: asked.id,
      requested_by: asked.requestedBy,
      range_from: asked.from,
      range_to: asked.to,
      actor_type: asked.actor?.type ?? null,
      actor_id: asked.actor?.id ?? null,
      format: asked.format,
      written_up_to: asked.writtenUpTo,
    })
    .execute();
  await tx
    .insertInto('activity_exports.files')
    .values(
      monthsOf(asked).map((month) => ({ org_id: orgId, export_id: asked.id, month, state: 'waiting', attempts: 0 })),
    )
    .execute();
}

const oneOf = <Known extends string>(known: readonly Known[], value: string): Known => {
  const found = known.find((each) => each === value);
  if (found === undefined) throw new RangeError(`a background download holds a value 0053 refuses: ${value}`);
  return found;
};

const FILE_STATES = ['waiting', 'building', 'ready', 'failed'] as const;

/** The downloads and their months, as stored, with whether each has expired by the database's clock. */
const downloadsWhere = (tx: ExportTx, orgId: string) =>
  tx
    .selectFrom('activity_exports.exports as e')
    .select([
      'e.id',
      'e.requested_by',
      'e.requested_at',
      'e.range_from',
      'e.range_to',
      'e.actor_type',
      'e.actor_id',
      'e.format',
      'e.written_up_to',
      sql<
        {
          month: string;
          state: string;
          attempts: number;
          requests: number | null;
          bytes: string | null;
          sha256: string | null;
          ready_at: string | null;
        }[]
      >`(select pg_catalog.json_agg(pg_catalog.json_build_object(
          'month', f.month::text, 'state', f.state, 'attempts', f.attempts, 'requests', f.requests, 'bytes', f.bytes::text,
          'sha256', f.sha256, 'ready_at', f.ready_at) order by f.month)
        from activity_exports.files f where f.org_id = e.org_id and f.export_id = e.id)`.as('files'),
      sql<boolean>`pg_catalog.clock_timestamp() >= (select pg_catalog.max(f.ready_at) + ${`${String(DOWNLOAD_KEPT_DAYS)} days`}::interval
        from activity_exports.files f where f.org_id = e.org_id and f.export_id = e.id)`.as('past_kept'),
    ])
    .where('e.org_id', '=', orgId);

type DownloadRow = Awaited<ReturnType<ReturnType<typeof downloadsWhere>['executeTakeFirstOrThrow']>>;

function downloadOf(row: DownloadRow): BackgroundExport {
  const files = row.files.map((file): BackgroundExportFile => ({
    month: file.month.slice(0, 7),
    state: oneOf(FILE_STATES, file.state),
    attempts: file.attempts,
    requests: file.requests,
    bytes: file.bytes === null ? null : Number(file.bytes),
    sha256: file.sha256,
  }));
  const ready = files.every((file) => file.state === 'ready');
  const lastReady = row.files.reduce<number>(
    (latest, file) => (file.ready_at === null ? latest : Math.max(latest, new Date(file.ready_at).getTime())),
    0,
  );
  let state: BackgroundExportState = 'building';
  if (files.some((file) => file.state === 'failed')) state = 'failed';
  else if (ready) state = row.past_kept ? 'expired' : 'ready';
  return {
    id: row.id,
    requestedBy: row.requested_by,
    requestedAt: row.requested_at,
    from: row.range_from,
    to: row.range_to,
    actor:
      row.actor_type === null || row.actor_id === null
        ? null
        : { type: oneOf(ACTIVITY_ACTOR_TYPES, row.actor_type), id: row.actor_id },
    format: oneOf(DOWNLOAD_FORMATS, row.format),
    writtenUpTo: row.written_up_to,
    state,
    expiresAt: ready ? new Date(lastReady + DOWNLOAD_KEPT_DAYS * 86_400_000) : null,
    files,
  };
}

/** One download of the organisation's, or undefined. */
export async function backgroundExportOf(
  tx: ExportTx,
  orgId: string,
  id: string,
): Promise<BackgroundExport | undefined> {
  const row = await downloadsWhere(tx, orgId).where('e.id', '=', id).executeTakeFirst();
  return row === undefined ? undefined : downloadOf(row);
}

/** The organisation's downloads, newest first, `limit` at most, those asked before `before` (an ID) when named. */
export async function backgroundExportsOf(
  tx: ExportTx,
  orgId: string,
  { before, limit }: { readonly before?: string | undefined; readonly limit: number },
): Promise<{ readonly downloads: readonly BackgroundExport[]; readonly next: string | null }> {
  let query = downloadsWhere(tx, orgId);
  if (before !== undefined) {
    query = query.where(
      sql<boolean>`(e.requested_at, e.id) < (select b.requested_at, b.id from activity_exports.exports b
        where b.org_id = e.org_id and b.id = ${before}::uuid)`,
    );
  }
  const rows = await query
    .orderBy('e.requested_at', 'desc')
    .orderBy('e.id', 'desc')
    .limit(limit + 1)
    .execute();
  const downloads = rows.slice(0, limit).map(downloadOf);
  return { downloads, next: rows.length > limit ? (downloads.at(-1)?.id ?? null) : null };
}

/**
 * The lease a builder holds, from the database's clock, to the millisecond:
 * the builder names it back exactly, and a Date holds no finer time.
 */
const leaseFor = (leaseMs: number) =>
  sql<Date>`pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp() + ${leaseMs} * interval '1 millisecond')`;

/**
 * Claims the organisation's next month to build: a waiting one, or one whose
 * builder's lease ran out, of a download none of whose months failed, the
 * oldest download's first. A month tried `mostTries` times already is failed
 * instead, and its download's waiting months with it.
 */
export async function claimFile(
  tx: ExportTx,
  orgId: string,
  { leaseMs, mostTries }: { readonly leaseMs: number; readonly mostTries: number },
): Promise<Claim> {
  const found = await tx
    .selectFrom('activity_exports.files as f')
    .select(['f.export_id', sql<string>`f.month::text`.as('month'), 'f.attempts'])
    .where('f.org_id', '=', orgId)
    .where((eb) =>
      eb.or([
        eb('f.state', '=', 'waiting'),
        eb.and([eb('f.state', '=', 'building'), eb('f.building_until', '<', sql<Date>`pg_catalog.clock_timestamp()`)]),
      ]),
    )
    .where(noMonthFailed)
    .orderBy('f.export_id')
    .orderBy('f.month')
    .limit(1)
    .forUpdate()
    .skipLocked()
    .executeTakeFirst();
  if (found === undefined) return { outcome: 'none' };
  const key = { orgId, exportId: found.export_id, month: found.month };
  if (found.attempts >= mostTries) {
    await failDownload(tx, key, 'ACTIVITY_EXPORT_FAILED');
    const download = await backgroundExportOf(tx, orgId, found.export_id);
    return {
      outcome: 'given_up',
      exportId: found.export_id,
      month: found.month,
      requestedBy: download?.requestedBy ?? '',
    };
  }
  const claimed = await tx
    .updateTable('activity_exports.files')
    .set({ state: 'building', attempts: found.attempts + 1, building_until: leaseFor(leaseMs) })
    .where('org_id', '=', orgId)
    .where('export_id', '=', found.export_id)
    .where('month', '=', found.month)
    .returning('building_until')
    .executeTakeFirstOrThrow();
  const download = await backgroundExportOf(tx, orgId, found.export_id);
  if (download === undefined || claimed.building_until === null) {
    throw new RangeError('a background download claimed has no row of its own');
  }
  return {
    outcome: 'claimed',
    file: {
      exportId: found.export_id,
      month: found.month,
      attempt: found.attempts + 1,
      lease: claimed.building_until,
      download,
    },
  };
}

/** A month a builder holds, by its key and the lease it set. */
interface HeldFile {
  readonly orgId: string;
  readonly exportId: string;
  readonly month: string;
  readonly lease: Date;
}

/** The held month's row, where its lease still holds. */
const held = (tx: ExportTx, { orgId, exportId, month, lease }: HeldFile) =>
  tx
    .updateTable('activity_exports.files')
    .where('org_id', '=', orgId)
    .where('export_id', '=', exportId)
    .where('month', '=', month)
    .where('state', '=', 'building')
    .where('building_until', '=', lease);

/** Renews the lease the builder holds: the new one, or undefined once it has lost the month. */
export async function renewLease(tx: ExportTx, file: HeldFile, leaseMs: number): Promise<Date | undefined> {
  const renewed = await held(tx, file)
    .where('building_until', '>', sql<Date>`pg_catalog.clock_timestamp()`)
    .set({ building_until: leaseFor(leaseMs) })
    .returning('building_until')
    .executeTakeFirst();
  return renewed?.building_until ?? undefined;
}

/** Whether a month of the download has failed, so the download is given up. */
const downloadFailed = async (tx: ExportTx, { orgId, exportId }: { orgId: string; exportId: string }) =>
  (await tx
    .selectFrom('activity_exports.files')
    .select('month')
    .where('org_id', '=', orgId)
    .where('export_id', '=', exportId)
    .where('state', '=', 'failed')
    .limit(1)
    .executeTakeFirst()) !== undefined;

/**
 * Makes the held month ready, its file's count, size and SHA-256 with it:
 * `lost` once the builder no longer holds it; `given_up` when another month
 * of its download failed meanwhile (this one failed with it); `ready` when
 * its download now is (every month ready); `more` while others are to build.
 */
export async function fileReady(
  tx: ExportTx,
  file: HeldFile,
  facts: { readonly requests: number; readonly bytes: number; readonly sha256: string },
): Promise<'lost' | 'given_up' | 'more' | 'ready'> {
  if (await downloadFailed(tx, file))
    return (await fileFailed(tx, file, 'ACTIVITY_EXPORT_GIVEN_UP')) ? 'given_up' : 'lost';
  const made = await held(tx, file)
    .where('building_until', '>', sql<Date>`pg_catalog.clock_timestamp()`)
    .set({
      state: 'ready',
      building_until: null,
      requests: facts.requests,
      bytes: BigInt(facts.bytes),
      sha256: facts.sha256,
      ready_at: sql<Date>`pg_catalog.clock_timestamp()`,
    })
    .returning('month')
    .executeTakeFirst();
  if (made === undefined) return 'lost';
  const left = await tx
    .selectFrom('activity_exports.files')
    .select('month')
    .where('org_id', '=', file.orgId)
    .where('export_id', '=', file.exportId)
    .where('state', '<>', 'ready')
    .limit(1)
    .executeTakeFirst();
  return left === undefined ? 'ready' : 'more';
}

/** Gives the held month back, waiting, for the next builder (a stop): whether the builder still held it. */
export async function giveBack(tx: ExportTx, file: HeldFile): Promise<boolean> {
  const back = await held(tx, file)
    .where('building_until', '>', sql<Date>`pg_catalog.clock_timestamp()`)
    .set({ state: 'waiting', building_until: null })
    .returning('month')
    .executeTakeFirst();
  return back !== undefined;
}

/** Fails the month (building or waiting) and every waiting month of its download, for `failure`. */
async function failDownload(
  tx: ExportTx,
  { orgId, exportId, month }: { readonly orgId: string; readonly exportId: string; readonly month: string },
  failure: string,
): Promise<void> {
  await tx
    .updateTable('activity_exports.files')
    .set({ state: 'failed', building_until: null, failure })
    .where('org_id', '=', orgId)
    .where('export_id', '=', exportId)
    .where('month', '=', month)
    .where('state', 'in', ['waiting', 'building'])
    .execute();
  await tx
    .updateTable('activity_exports.files')
    .set({ state: 'failed', failure: 'ACTIVITY_EXPORT_GIVEN_UP' })
    .where('org_id', '=', orgId)
    .where('export_id', '=', exportId)
    .where('state', '=', 'waiting')
    .execute();
}

/** Fails the held month, and its download with it: whether the builder still held it. */
export async function fileFailed(tx: ExportTx, file: HeldFile, failure: string): Promise<boolean> {
  const still = await tx
    .selectFrom('activity_exports.files')
    .select('month')
    .where('org_id', '=', file.orgId)
    .where('export_id', '=', file.exportId)
    .where('month', '=', file.month)
    .where('state', '=', 'building')
    .where('building_until', '=', file.lease)
    .forUpdate()
    .executeTakeFirst();
  if (still === undefined) return false;
  await failDownload(tx, file, failure);
  return true;
}
