// The activity log's seals, checked (Phase 3 L6c; partner decision 26;
// ADR-011 §7): the API's job, on a timer of its own, digesting each sealed
// day of every organisation's activity log again and comparing it with its
// seal, so a row changed, deleted or slipped into a sealed day past the app
// is found, and the organisation put on its integrity hold, as any tamper
// sign does (ADR-012 §2).
//
// For each organisation the directory lists, each run checks its newest two
// seals and a few more read from a point picked at random among its older ones (a
// page of its log through the signed states' logPageOf, so a seal event that
// can't be believed raises the alarm itself): each day digested again and
// compared with what its seal holds, and each seal's day the one before the
// next newer seal's on the page, so none is missing between them. A page
// that reaches the oldest seal also finds no row written before its day,
// which no seal would ever hold. Nothing is kept between runs, so a restart
// (a release, a server woken) loses nothing: over runs, every seal is
// checked, the newest every run.
//
// A mismatch raises the alarm (`audit.integrity_failed`, reason `holding`,
// on the subject `access_log`) and holds the organisation; the check goes on
// to the next organisation. A run never throws: each failure is logged.
import { randomInt } from 'node:crypto';

import {
  ACTIVITY_SEALED,
  type ActivityTables,
  digestOfDay,
  nextDay,
  sealHolds,
  writtenBefore,
} from '@agentx/core/modules/activity';
import { type AuditTables, type LogEvent, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often seals are checked, once the last run has ended. */
export const ACTIVITY_SEAL_CHECK_EVERY_MS = 30 * 60_000;

/** How many older seals one run checks an organisation, beside its newest. */
const OLDER_A_RUN = 6;

/** How many rows one read of a day's digest takes. */
const CHECK_BATCH = 5_000;

/** The widest range a page of seals is read in: every seal ever made. */
const EVER = { from: new Date('2000-01-01T00:00:00.000Z'), to: new Date('2200-01-01T00:00:00.000Z') };

type CheckTables = AuditTables & ActivityTables;
type CheckTx = DatabaseTransaction<CheckTables>;

export interface ActivitySealCheck {
  /** Checks a few seals of each organisation, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** Why a seal doesn't hold: its day's digest, a seal missing before it, or a row written before the first seal. */
type Broken = 'digest' | 'gap' | 'before';

export function createActivitySealCheck({
  list,
  database,
  keys,
  ids,
  logger,
  olderARun = OLDER_A_RUN,
  batch = CHECK_BATCH,
  pick = (below: bigint) => BigInt(randomInt(1, Number(below) + 1)),
}: {
  /** The organisations to check: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<CheckTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** OLDER_A_RUN and CHECK_BATCH, but for the tests. */
  readonly olderARun?: number;
  readonly batch?: number;
  /** Where the older seals are read from: a seq from 1 to `below`, at random; a test names its own. */
  readonly pick?: (below: bigint) => bigint;
}): ActivitySealCheck {
  const inOrg = <T>(orgId: string, correlationId: string, work: (tx: CheckTx, states: SignedStates) => Promise<T>) =>
    withSignedStates(database, orgId, { keys, ids, logger, correlationId }, work);

  /** A page of the organisation's seals, newest first, before `beforeSeq` when named: undefined for one that can't be believed. */
  const sealsOf = async (orgId: string, correlationId: string, limit: number, beforeSeq?: bigint) => {
    const page = await inOrg(orgId, correlationId, (tx, states) =>
      states.logPageOf(tx, orgId, {
        ...EVER,
        actions: [ACTIVITY_SEALED],
        ...(beforeSeq === undefined ? {} : { beforeSeq }),
        limit,
      }),
    );
    // A seal that can't be believed: the alarm raised and the hold set already.
    return page.outcome === 'read' ? page : undefined;
  };

  /** Raises the alarm for the organisation's activity log, and holds it. */
  const broken = async (orgId: string, correlationId: string, day: string, why: Broken) => {
    logger.child({ correlationId, orgId }).info('access_log_seal_check.broken', { day, why });
    await inOrg(orgId, correlationId, (_tx, states) => {
      states.mismatch('access_log', { orgId, id: orgId });
      return Promise.resolve();
    });
  };

  /** Checks a page of seals, newest first: why the first that doesn't hold doesn't, or undefined. */
  const checkPage = async (
    orgId: string,
    correlationId: string,
    events: readonly LogEvent[],
    oldestReached: boolean,
  ): Promise<{ readonly day: string; readonly why: Broken } | undefined> => {
    let newerDay: string | undefined;
    for (const { event } of events) {
      const { day } = event.details;
      if (typeof day !== 'string') return { day: 'unnamed', why: 'gap' };
      if (newerDay !== undefined && nextDay(day) !== newerDay) return { day, why: 'gap' };
      const digest = await digestOfDay((work) => inOrg(orgId, correlationId, (tx) => work(tx)), orgId, day, batch);
      if (!sealHolds(digest, event.details)) return { day, why: 'digest' };
      newerDay = day;
    }
    if (
      oldestReached &&
      newerDay !== undefined &&
      (await inOrg(orgId, correlationId, (tx) => writtenBefore(tx, orgId, newerDay)))
    ) {
      return { day: newerDay, why: 'before' };
    }
    return undefined;
  };

  /** Checks the organisation's newest seal, then a few older ones from a point picked at random. */
  const checkFor = async (orgId: string): Promise<void> => {
    const correlationId = ids.next();
    // The newest two: a seal missing just before the newest shows between them.
    const newest = await sealsOf(orgId, correlationId, 2);
    const [first] = newest?.events ?? [];
    if (newest === undefined || first === undefined) return;
    const older = await sealsOf(orgId, correlationId, olderARun, pick(first.seq));
    if (older === undefined) return;
    const found =
      (await checkPage(orgId, correlationId, newest.events, newest.next === null)) ??
      (await checkPage(orgId, correlationId, older.events, older.next === null));
    if (found !== undefined) await broken(orgId, correlationId, found.day, found.why);
  };

  return {
    async run(signal) {
      try {
        for (const orgId of await list()) {
          if (signal?.aborted === true) return;
          try {
            await checkFor(orgId);
          } catch (error) {
            logger.child({ orgId }).error('access_log_seal_check.failed', { err: error });
          }
        }
      } catch (error) {
        logger.error('access_log_seal_check.run_failed', { err: error });
      }
    },
  };
}
