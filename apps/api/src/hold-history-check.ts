// The whole history checked while an integrity hold stands (ADR-012 §2;
// Phase 2 D1c, partner decision 7): the API's job, on a timer of its own.
// Clearing a hold checks a growing table (a spend request's) in the rows that
// can still act, so it stays bounded however long the history; before the
// admin's confirm is let through, this job checks every object of each such
// table, ended ones and ones the log holds but whose row is gone included, a
// batch at a time, each batch in a transaction of its own, and records that
// it did, against the HELD state it checked for (hold-clearing.ts waits for
// that record).
//
// Where it has got to is kept here, in the process, never in the database an
// owner could rewrite: a restart, a HELD state replaced, or a batch finding a
// record tampered with starts it again from the beginning. A run checks at
// most BATCHES_A_RUN batches an organisation, so an organisation with a long
// history can't keep the others waiting.
//
// A run never throws: each failure is logged, naming the organisation, and
// the run goes on to the next.
import { type CheckedTable, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { UseCaseTables } from './use-case-work.ts';

/** How often held organisations' histories are checked on, once the last run has ended. */
export const HOLD_HISTORY_EVERY_MS = 30_000;

/** How many objects one batch checks, in one transaction. */
const BATCH = 500;

/** How many batches one run checks an organisation: about 10,000 objects a run. */
const BATCHES_A_RUN = 20;

export interface HoldHistoryCheck {
  /** Checks on each held organisation's history, up to BATCHES_A_RUN batches each, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** Where an organisation's check has got to: the HELD state it is for, the table, the last ID checked, the count so far. */
interface Progress {
  readonly holdEventId: string;
  readonly table: number;
  readonly after: string | null;
  readonly objects: number;
}

export function createHoldHistoryCheck({
  list,
  database,
  keys,
  ids,
  logger,
  tables,
  batch = BATCH,
  batchesARun = BATCHES_A_RUN,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<UseCaseTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** Every authority table (the product's AUTHORITY_TABLES): the growing ones, with `liveStatuses`, are checked. */
  readonly tables: readonly CheckedTable[];
  /** BATCH and BATCHES_A_RUN, but for the tests. */
  readonly batch?: number;
  readonly batchesARun?: number;
}): HoldHistoryCheck {
  const growing = tables.filter(({ liveStatuses }) => liveStatuses !== undefined);
  const progress = new Map<string, Progress>();
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** The HELD state whose history is still to check, or null: the hold CLEAR, checked already, or not believed. */
  const uncheckedHold = (log: Logger, orgId: string): Promise<string | null> =>
    withSignedStates(database, orgId, services(log), async (tx, states) => {
      // A cheap look first, so a CLEAR organisation costs one read and no verifying; a hold hidden from it stays unchecked.
      if (!(await states.mayBeHeld(tx, orgId))) return null;
      const hold = await states.holdRecord(tx, orgId);
      if (hold.outcome !== 'held') return null;
      return (await states.historyChecked(tx, orgId, hold.eventId)) === 'unchecked' ? hold.eventId : null;
    });

  /** Checks on the organisation's history; false if the signal stopped it. */
  const checkIn = async (log: Logger, orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const holdEventId = await uncheckedHold(log, orgId);
    if (holdEventId === null) {
      progress.delete(orgId);
      return true;
    }
    const kept = progress.get(orgId);
    let at: Progress = kept?.holdEventId === holdEventId ? kept : { holdEventId, table: 0, after: null, objects: 0 };
    for (let done = 0; done < batchesARun && at.table < growing.length; done += 1) {
      if (signal?.aborted === true) {
        progress.set(orgId, at);
        return false;
      }
      const table = growing[at.table];
      if (table === undefined) break;
      const after = at.after;
      const checked = await withSignedStates(database, orgId, services(log), (tx, states) =>
        states.checkHistoryBatch(tx, orgId, table, after, batch),
      );
      if (checked.outcome === 'tampered') {
        // Each finding's alarm is raised; the check starts again once the record is put right.
        log.warn('hold_history.tampered', { subjectType: table.subject, findings: checked.findings.length });
        progress.delete(orgId);
        return true;
      }
      at = checked.done
        ? { holdEventId, table: at.table + 1, after: null, objects: at.objects + checked.objects }
        : { holdEventId, table: at.table, after: checked.last, objects: at.objects + checked.objects };
    }
    if (at.table < growing.length) {
      progress.set(orgId, at);
      return true;
    }
    await withSignedStates(database, orgId, services(log), (tx, states) =>
      states.recordHistoryChecked(tx, orgId, holdEventId, at.objects),
    );
    progress.delete(orgId);
    log.info('hold_history.checked', { objects: at.objects });
    return true;
  };

  return {
    async run(signal) {
      if (growing.length === 0) return;
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.warn('hold_history.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        const log = logger.child({ orgId });
        try {
          if (!(await checkIn(log, orgId, signal))) return;
        } catch (error) {
          // A hold that can't be read, a batch that failed, or the hold changed before the record: from the start next run.
          log.error('hold_history.failed', { err: error });
          progress.delete(orgId);
        }
      }
    },
  };
}
