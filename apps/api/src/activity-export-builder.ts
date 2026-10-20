// The activity log's background downloads, built (Phase 3 L5c; partner
// decision 31): the API's job, on a timer of its own, building each waiting
// month of an admin's download as one compressed file in the store.
//
// For each organisation the directory lists, a month is claimed under a
// lease (claimFile: FOR UPDATE SKIP LOCKED, so two servers never take the
// same one), then built outside any long transaction:
//
// - its requests read in batches, newest first, each batch in a transaction
//   of the organisation's own with every row's seal checked (heldActivity),
//   only those written by the time the download was asked, cut to the month;
//   each actor named, the login service asked at most until it first fails;
// - each line gzipped as it comes, the SHA-256 of the file kept as it is
//   written, and every 4 MiB of it put to the store as a block, the lease
//   renewed with each; memory holds one batch and one block at most;
// - committed as the try's own file (storedName), then in one transaction:
//   made ready under the lease, `access_log.export_file_made` recorded with
//   its count, size and SHA-256, and once its download's every month is
//   ready, the admin who asked told (the email in words alone, decision 30).
//
// A month that fails is given back for another try (each claim counts one);
// one tried three times fails its download, recorded as
// `access_log.export_failed`, the admin told. A builder that finds it lost
// its lease (a stop, a long pause) leaves the month to the one that took it.
// A run never throws: each failure is logged, naming the organisation and
// download, and the run goes on to the next.
import { createHash } from 'node:crypto';
import { constants, createGzip } from 'node:zlib';

import {
  type ActivityExportTables,
  type ActivityCursor,
  claimFile,
  type ClaimedFile,
  fileReady,
  giveBack,
  rangeInMonth,
  renewLease,
  storedName,
} from '@agentx/core/modules/activity';
import { createAuditTrail, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import {
  activityActorsOf,
  ACTIVITY_EXPORT_FAILED,
  ACTIVITY_EXPORT_FILE_MADE,
  createActorNamer,
  EXPORT_BATCH,
  type HeldActivityPage,
} from '@agentx/core/modules/evidence';
import type { DirectoryNames } from '@agentx/core/modules/identity';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { BlockStore } from '@agentx/platform/storage';

import { ACTIVITY_CSV_HEADER, activityLineOf } from './activity-lines.ts';
import { type ActivityLogTables, heldActivity } from './activity-log.ts';
import { csvRow } from './audit-log-exports.ts';

/** How often months are looked for, once the last run has ended. */
export const ACTIVITY_EXPORTS_EVERY_MS = 60_000;

/** How long a claim holds a month before another builder may take it on: renewed with every block. */
const LEASE_MS = 15 * 60_000;

/** How many claims a month gets before its download is given up. */
const MOST_TRIES = 3;

/** How large a block of the file is put to the store at once. */
const BLOCK_BYTES = 4 * 1024 * 1024;

/** How many months one run builds an organisation, so one with many waiting doesn't hold up the rest. */
const MOST_A_RUN = 4;

const ACTOR = { type: 'system', id: 'api' } as const;

type BuilderTables = ActivityLogTables & ActivityExportTables & NotificationsTables;
type BuilderTx = DatabaseTransaction<BuilderTables>;

export interface ActivityExportBuilder {
  /** Builds the waiting months, up to MOST_A_RUN an organisation, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** The builder lost its lease: another took the month on, so this one stops writing. */
class LeaseLost extends Error {
  constructor() {
    super('The month was taken on by another builder');
    this.name = 'LeaseLost';
  }
}

/**
 * The file written as it comes: gzipped, its SHA-256 kept, put to the store
 * a block at a time. `add` takes text and resolves once it is compressed;
 * `blocks` are put whenever BLOCK_BYTES or more are waiting.
 */
function gzipToBlocks(put: (index: number, bytes: Buffer) => Promise<void>, blockBytes: number) {
  const gzip = createGzip();
  const hash = createHash('sha256');
  const waiting: Buffer[] = [];
  let waitingBytes = 0;
  let blocks = 0;
  let bytes = 0;
  gzip.on('data', (chunk: Buffer) => {
    waiting.push(chunk);
    waitingBytes += chunk.length;
  });

  const putWaiting = async (all: boolean) => {
    while (waitingBytes >= blockBytes || (all && waitingBytes > 0)) {
      const joined = Buffer.concat(waiting.splice(0));
      const block = joined.subarray(0, Math.min(blockBytes, joined.length));
      const rest = joined.subarray(block.length);
      if (rest.length > 0) waiting.push(rest);
      waitingBytes = rest.length;
      hash.update(block);
      bytes += block.length;
      await put(blocks, block);
      blocks += 1;
    }
  };

  return {
    /** Compresses the text, then puts any full blocks waiting. */
    async add(text: string) {
      await new Promise<void>((resolve, reject) => {
        gzip.write(text, (error) => {
          if (error === null || error === undefined) resolve();
          else reject(error);
        });
      });
      // Flushed, so every byte of the text is out of the compressor before the next batch is read; a sync
      // flush keeps what it has learnt of the text, so the file compresses as well as one written whole.
      await new Promise<void>((resolve) => {
        gzip.flush(constants.Z_SYNC_FLUSH, () => {
          resolve();
        });
      });
      await putWaiting(false);
    },
    /** Ends the file, puts its last block, and gives how many blocks, bytes and its SHA-256. */
    async end() {
      await new Promise<void>((resolve, reject) => {
        gzip.once('end', resolve);
        gzip.once('error', reject);
        gzip.end();
      });
      await putWaiting(true);
      return { blocks, bytes, sha256: hash.digest('hex') };
    },
  };
}

export function createActivityExportBuilder({
  list,
  database,
  keys,
  ids,
  store,
  outbox,
  directory,
  logger,
  leaseMs = LEASE_MS,
  mostTries = MOST_TRIES,
  batch = EXPORT_BATCH,
  blockBytes = BLOCK_BYTES,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<BuilderTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly store: BlockStore;
  readonly outbox: Outbox;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
  readonly logger: Logger;
  /** LEASE_MS, MOST_TRIES, EXPORT_BATCH and BLOCK_BYTES, but for the tests. */
  readonly leaseMs?: number;
  readonly mostTries?: number;
  readonly batch?: number;
  readonly blockBytes?: number;
}): ActivityExportBuilder {
  /** A transaction of the organisation's own, its events sealed with the build's correlation ID. */
  const inOrg = <T>(
    orgId: string,
    correlationId: string,
    work: (tx: BuilderTx, states: SignedStates) => Promise<T>,
  ): Promise<T> =>
    withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }), correlationId }, work);

  /** Records an event about the organisation's activity log, as the API. */
  const record = (
    tx: BuilderTx,
    orgId: string,
    correlationId: string,
    action: string,
    details: Record<string, string | number | null>,
  ) =>
    createAuditTrail({ keys, ids, correlationId }).record(tx, orgId, {
      actor: ACTOR,
      action,
      subject: { type: 'access_log', id: orgId, version: 1 },
      details,
    });

  /** Tells the admin who asked how their download ended, in words alone. */
  const tell = (
    tx: BuilderTx,
    orgId: string,
    kind: 'access_log_export_ready' | 'access_log_export_failed',
    exportId: string,
    requestedBy: string,
  ) =>
    outbox.add(tx, [{ orgId, recipientUserId: requestedBy, kind, membershipId: null, role: null, aboutId: exportId }]);

  /** The month's file, written to the store under the lease (`holding`, renewed as it goes): its count, size and SHA-256. */
  const written = async (
    orgId: string,
    file: ClaimedFile,
    holding: { lease: Date },
    correlationId: string,
    signal: AbortSignal | undefined,
  ) => {
    const { download } = file;
    const name = storedName(orgId, { ...file, format: download.format });
    const out = gzipToBlocks(async (index, bytes) => {
      await store.putBlock(name, index, bytes);
      const held = { orgId, exportId: file.exportId, month: file.month, lease: holding.lease };
      const renewed = await inOrg(orgId, correlationId, (tx) => renewLease(tx, held, leaseMs));
      if (renewed === undefined) throw new LeaseLost();
      holding.lease = renewed;
    }, blockBytes);
    if (download.format === 'csv') await out.add(`${csvRow(ACTIVITY_CSV_HEADER)}\n`);
    // One namer for the month: once the login service fails, no later batch waits on it.
    const namer = createActorNamer({ directory, logger: logger.child({ correlationId }) });
    const range = { ...rangeInMonth(download, file.month), actor: download.actor ?? undefined };
    const { writtenUpTo } = download;
    let requests = 0;
    // undefined: the first batch, from the newest; null: none left.
    let before: ActivityCursor | null | undefined = writtenUpTo === null ? null : undefined;
    while (before !== null && writtenUpTo !== null) {
      if (signal?.aborted === true) throw signal.reason;
      const start: ActivityCursor | undefined = before;
      const read: HeldActivityPage = await inOrg(orgId, correlationId, (tx, states) =>
        heldActivity(tx, states, keys, orgId, { ...range, before: start, writtenUpTo, limit: batch }),
      );
      const names = await namer.namesOf(activityActorsOf(read.rows), read.held);
      if (read.rows.length > 0) {
        await out.add(`${read.rows.map((row) => activityLineOf(download.format, row, names)).join('\n')}\n`);
      }
      requests += read.rows.length;
      before = read.next;
    }
    const made = await out.end();
    await store.commit(name, made.blocks, { contentType: 'application/gzip', sha256: made.sha256 });
    return { requests, bytes: made.bytes, sha256: made.sha256 };
  };

  /** Builds the claimed month, made ready and recorded, or given back for another try: whether to go on to the next. */
  const build = async (orgId: string, file: ClaimedFile, signal: AbortSignal | undefined): Promise<boolean> => {
    const correlationId = ids.next();
    const log = logger.child({ correlationId, orgId });
    const about = { exportId: file.exportId, month: file.month.slice(0, 7), attempt: file.attempt };
    const holding = { lease: file.lease };
    const held = () => ({ orgId, exportId: file.exportId, month: file.month, lease: holding.lease });
    try {
      const facts = await written(orgId, file, holding, correlationId, signal);
      const ready = await inOrg(orgId, correlationId, async (tx) => {
        const done = await fileReady(tx, held(), facts);
        // Lost to another builder, or its download given up meanwhile (fileReady failed it): nothing to record.
        if (done === 'lost' || done === 'given_up') return done;
        await record(tx, orgId, correlationId, ACTIVITY_EXPORT_FILE_MADE, {
          exportId: file.exportId,
          month: file.month.slice(0, 7),
          attempt: file.attempt,
          ...facts,
        });
        if (done === 'ready')
          await tell(tx, orgId, 'access_log_export_ready', file.exportId, file.download.requestedBy);
        return done;
      });
      if (ready === 'lost') {
        log.info('access_log.export_lease_lost', about);
        return false;
      }
      if (ready === 'given_up') {
        log.info('access_log.export_given_up', about);
        return false;
      }
      log.info('access_log.export_file_made', { ...about, requests: facts.requests, bytes: facts.bytes });
      return true;
    } catch (error) {
      if (error instanceof LeaseLost) {
        log.info('access_log.export_lease_lost', about);
        return false;
      }
      // A stop is no failure: the month waits for the next builder, its try counted all the same.
      if (signal?.aborted === true) log.info('access_log.export_stopped', about);
      else log.warn('access_log.export_build_failed', { ...about, err: error });
      // Given back if it can be; if not, its lease runs out and the next claim takes it on.
      await inOrg(orgId, correlationId, (tx) => giveBack(tx, held())).catch(() => undefined);
      return false;
    }
  };

  /** The organisation's waiting months, up to MOST_A_RUN, built one after another. */
  const buildFor = async (orgId: string, signal: AbortSignal | undefined) => {
    for (let built = 0; built < MOST_A_RUN && signal?.aborted !== true; built += 1) {
      const correlationId = ids.next();
      const claim = await inOrg(orgId, correlationId, async (tx) => {
        const found = await claimFile(tx, orgId, { leaseMs, mostTries });
        if (found.outcome === 'given_up') {
          await record(tx, orgId, correlationId, ACTIVITY_EXPORT_FAILED, {
            exportId: found.exportId,
            month: found.month.slice(0, 7),
            reason: 'ACTIVITY_EXPORT_FAILED',
          });
          await tell(tx, orgId, 'access_log_export_failed', found.exportId, found.requestedBy);
        }
        return found;
      });
      if (claim.outcome === 'none') return;
      if (claim.outcome === 'given_up') {
        logger.child({ correlationId, orgId }).error('access_log.export_failed', {
          exportId: claim.exportId,
          month: claim.month.slice(0, 7),
          tries: mostTries,
        });
        continue;
      }
      // A month that failed, or was lost, waits for the next run, so its tries are spread over minutes, not spent at once.
      if (!(await build(orgId, claim.file, signal))) return;
    }
  };

  return {
    async run(signal) {
      try {
        for (const orgId of await list()) {
          if (signal?.aborted === true) return;
          try {
            await buildFor(orgId, signal);
          } catch (error) {
            logger.child({ orgId }).error('access_log.export_run_failed', { err: error });
          }
        }
      } catch (error) {
        logger.error('access_log.export_run_failed', { err: error });
      }
    },
  };
}
