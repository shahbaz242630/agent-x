// The activity log's daily seal, recorded (Phase 3 L6; partner decision 26;
// ADR-011 §7): the API's job, on a timer of its own, sealing each closed UTC
// day of every organisation's activity log into one `access_log.sealed`
// event on its audit chain (activity-seal.ts in the activity module says
// what a day and its digest are).
//
// For each organisation the directory lists: the day after its newest seal,
// or the day its first row was written when it has none; then each day after
// that is closed, in order, at most MOST_DAYS_A_RUN a run (a server woken
// after days asleep catches up over a few runs), no day skipped, quiet days
// sealed too. Each day is digested in batches, then recorded in one
// transaction under the organisation's seal lock (ADR-006 §6, 11b): the
// newest seal read again (another server may have sealed the day), the day
// counted again with its last ID, and the event recorded only when both still
// stand; a day that moved is left for the next run, warned.
//
// A run never throws: each failure is logged, naming the organisation, and
// the run goes on to the next.
import {
  ACTIVITY_SEALED,
  type ActivityTables,
  dayCount,
  digestOfDay,
  firstDayOf,
  nextDay,
  SEAL_FORM,
  sealable,
} from '@agentx/core/modules/activity';
import { type AuditTables, createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, holdTransactionLock } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often closed days are looked for, once the last run has ended. */
export const ACTIVITY_SEAL_EVERY_MS = 15 * 60_000;

/** The most days one run seals an organisation, so one asleep for long doesn't hold up the rest. */
const MOST_DAYS_A_RUN = 31;

/** How many rows one read of a day's digest takes. */
const SEAL_BATCH = 5_000;

/** The advisory lock an organisation's seals are recorded under (ADR-006 §6, 11b), before the chain head's. */
export const ACTIVITY_SEAL_LOCK = 'access-log-seal';

const ACTOR = { type: 'system', id: 'api' } as const;

type SealTables = AuditTables & ActivityTables;
type SealTx = DatabaseTransaction<SealTables>;

export interface ActivitySeal {
  /** Seals the closed days, up to MOST_DAYS_A_RUN an organisation, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** The day the organisation's newest seal names, believed whole; undefined for none. */
async function newestSealed(
  tx: SealTx,
  trail: ReturnType<typeof createAuditTrail>,
  orgId: string,
): Promise<{ readonly day: string | undefined } | 'broken'> {
  const found = await trail.recordedEvents(tx, orgId, {
    subjectTypes: ['access_log'],
    subjectId: orgId,
    actions: [ACTIVITY_SEALED],
    limit: 1,
    newest: true,
  });
  if (found.kind === 'broken') return 'broken';
  const day = found.events.at(-1)?.event.details.day;
  return { day: typeof day === 'string' ? day : undefined };
}

export function createActivitySeal({
  list,
  database,
  keys,
  ids,
  clock,
  logger,
  batch = SEAL_BATCH,
}: {
  /** The organisations to seal: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<SealTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** SEAL_BATCH, but for the tests. */
  readonly batch?: number;
}): ActivitySeal {
  /** The organisation's next day to seal: the one after its newest seal, or its first row's; undefined for none. */
  const firstToSeal = async (orgId: string, correlationId: string) =>
    withSignedStates(database, orgId, { keys, ids, logger, correlationId }, async (tx) => {
      const newest = await newestSealed(tx, createAuditTrail({ keys, ids }), orgId);
      if (newest === 'broken') return 'broken' as const;
      return newest.day === undefined ? firstDayOf(tx, orgId) : nextDay(newest.day);
    });

  /** Seals `day` if nothing moved meanwhile: whether it was sealed (or found sealed already). */
  const seal = async (orgId: string, day: string, correlationId: string): Promise<boolean> => {
    const inOrg = <T>(work: (tx: SealTx) => Promise<T>) =>
      withSignedStates(database, orgId, { keys, ids, logger, correlationId }, (tx) => work(tx));
    const digest = await digestOfDay(inOrg, orgId, day, batch);
    const log = logger.child({ correlationId, orgId });
    return inOrg(async (tx) => {
      await holdTransactionLock(tx, ACTIVITY_SEAL_LOCK, orgId);
      const trail = createAuditTrail({ keys, ids, correlationId });
      const newest = await newestSealed(tx, trail, orgId);
      if (newest === 'broken') {
        log.error('access_log_seal.failed', { reason: 'chain_unreadable' });
        return false;
      }
      // Sealed by another server meanwhile.
      if (newest.day !== undefined && newest.day >= day) return true;
      const now = await dayCount(tx, orgId, day);
      if (now.requests !== digest.requests || now.idTo !== digest.idTo) {
        log.warn('access_log_seal.moved', { day, digested: digest.requests, counted: now.requests });
        return false;
      }
      await trail.record(tx, orgId, {
        actor: ACTOR,
        action: ACTIVITY_SEALED,
        subject: { type: 'access_log', id: orgId, version: 1 },
        details: {
          day,
          requests: digest.requests,
          digest: digest.digest,
          idFrom: digest.idFrom,
          idTo: digest.idTo,
          form: SEAL_FORM,
        },
      });
      log.info('access_log.sealed', { day, requests: digest.requests });
      return true;
    });
  };

  /** Seals the organisation's closed days, oldest first, up to MOST_DAYS_A_RUN. */
  const sealFor = async (orgId: string, signal: AbortSignal | undefined) => {
    const correlationId = ids.next();
    let day = await firstToSeal(orgId, correlationId);
    if (day === 'broken') {
      logger.child({ correlationId, orgId }).error('access_log_seal.failed', { reason: 'chain_unreadable' });
      return;
    }
    for (let sealed = 0; day !== undefined && sealed < MOST_DAYS_A_RUN; sealed += 1) {
      if (signal?.aborted === true || !sealable(day, clock.now())) return;
      if (!(await seal(orgId, day, correlationId))) return;
      day = nextDay(day);
    }
  };

  return {
    async run(signal) {
      try {
        for (const orgId of await list()) {
          if (signal?.aborted === true) return;
          try {
            await sealFor(orgId, signal);
          } catch (error) {
            logger.child({ orgId }).error('access_log_seal.failed', { reason: 'error', err: error });
          }
        }
      } catch (error) {
        logger.error('access_log_seal.run_failed', { err: error });
      }
    },
  };
}
