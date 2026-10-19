// The activity log's seals, checked (Phase 3 L6c; partner decision 26;
// ADR-011 §7): the API's job, on a timer of its own, digesting each sealed
// day of every organisation's activity log again and comparing it with its
// seal, so a row changed, deleted or slipped into a sealed day past the app
// is found, and the organisation put on its integrity hold, as any tamper
// sign does (ADR-012 §2).
//
// For each organisation the directory lists, a few seals a run, newest
// first, a page of its log at a time (the signed states' logPageOf, so a
// seal event that can't be believed raises the alarm itself), each day
// digested again in batches and compared with what its seal holds, and each
// seal's day the one before the next newer seal's, so no day is missing
// between them. Where the run stopped is kept for the next, back to the
// oldest seal, then from the newest again: every seal is checked in turn,
// the newest within a run of being made.
//
// A mismatch raises the alarm (`audit.integrity_failed`, reason `holding`,
// on the subject `access_log`) and holds the organisation; the check goes on
// to the next organisation. A run never throws: each failure is logged.
import { ACTIVITY_SEALED, type ActivityTables, digestOfDay, nextDay, sealHolds } from '@agentx/core/modules/activity';
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often seals are checked, once the last run has ended. */
export const ACTIVITY_SEAL_CHECK_EVERY_MS = 30 * 60_000;

/** How many seals one run checks an organisation. */
const SEALS_A_RUN = 7;

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

/** Where an organisation's check stopped: before which event, and the day of the last seal checked. */
interface Place {
  readonly beforeSeq: bigint | undefined;
  readonly newerDay: string | undefined;
}

export function createActivitySealCheck({
  list,
  database,
  keys,
  ids,
  logger,
  sealsARun = SEALS_A_RUN,
  batch = CHECK_BATCH,
}: {
  /** The organisations to check: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<CheckTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** SEALS_A_RUN and CHECK_BATCH, but for the tests. */
  readonly sealsARun?: number;
  readonly batch?: number;
}): ActivitySealCheck {
  const places = new Map<string, Place>();

  const inOrg = <T>(orgId: string, correlationId: string, work: (tx: CheckTx, states: SignedStates) => Promise<T>) =>
    withSignedStates(database, orgId, { keys, ids, logger, correlationId }, work);

  /** Raises the alarm for the organisation's activity log, and holds it. */
  const broken = async (orgId: string, correlationId: string, day: string, why: 'digest' | 'gap') => {
    logger.child({ correlationId, orgId }).info('access_log_seal_check.broken', { day, why });
    await inOrg(orgId, correlationId, (_tx, states) => {
      states.mismatch('access_log', { orgId, id: orgId });
      return Promise.resolve();
    });
  };

  /** Checks the organisation's next few seals from where it stopped: whether every one held. */
  const checkFor = async (orgId: string): Promise<void> => {
    const correlationId = ids.next();
    const place = places.get(orgId) ?? { beforeSeq: undefined, newerDay: undefined };
    const page = await inOrg(orgId, correlationId, (tx, states) =>
      states.logPageOf(tx, orgId, {
        ...EVER,
        actions: [ACTIVITY_SEALED],
        ...(place.beforeSeq === undefined ? {} : { beforeSeq: place.beforeSeq }),
        limit: sealsARun,
      }),
    );
    // A seal that can't be believed: the alarm raised and the hold set already; from the newest next time.
    if (page.outcome !== 'read') {
      places.delete(orgId);
      return;
    }
    let newerDay = place.newerDay;
    for (const { seq, event } of page.events) {
      const { day } = event.details;
      if (typeof day !== 'string' || (newerDay !== undefined && nextDay(day) !== newerDay)) {
        await broken(orgId, correlationId, typeof day === 'string' ? day : 'unnamed', 'gap');
        places.delete(orgId);
        return;
      }
      const digest = await digestOfDay((work) => inOrg(orgId, correlationId, (tx) => work(tx)), orgId, day, batch);
      if (!sealHolds(digest, event.details)) {
        await broken(orgId, correlationId, day, 'digest');
        places.delete(orgId);
        return;
      }
      newerDay = day;
      places.set(orgId, { beforeSeq: seq, newerDay });
    }
    // Back at the oldest seal: from the newest again next run.
    if (page.next === null) places.delete(orgId);
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
