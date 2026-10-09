// The holdings check (ADR-012 §2: reservations and order claims checked
// against the signed decisions by a frequent scheduled reconciliation;
// SEC-DB-09; Phase 2 E1): the API's job, on a timer of its own. For each
// organisation the directory lists, it goes through every spend request a
// page at a time, each page in a transaction of its own (`checkHoldings`):
// each request the table or the log holds verified (one deleted is alarmed),
// and its reservation and claim compared with what its signed status and
// decision say they must be. A request tampered with is passed over, its
// alarm raised, so the ones after it are still checked. A mismatch raises the integrity alarm
// (`holding`, SEV-1) and puts the organisation on hold, as any tamper sign
// does, so its hand-offs stop until an admin clears it.
//
// Where an organisation's pass has got to is kept here, in the process, as
// the hold history check keeps it: a run checks at most PAGES_A_RUN pages an
// organisation and the next run goes on from there, so a long history can't
// keep the others waiting; a restart starts it again from the beginning.
//
// A run never throws: each failure is logged, naming the organisation, and
// the run goes on to the next.
import { type AuditTables, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { checkHoldings, MOST_CHECKED_A_PAGE, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often every organisation's requests are checked against what they hold, once the last run has ended. */
export const HOLDINGS_CHECK_EVERY_MS = 15 * 60_000;

/** How many pages one run checks an organisation: about 10,000 requests a run. */
const PAGES_A_RUN = 50;

export interface HoldingsCheck {
  /** Checks each organisation's requests, up to PAGES_A_RUN pages each, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createHoldingsCheck({
  list,
  database,
  keys,
  ids,
  logger,
  page = MOST_CHECKED_A_PAGE,
  pagesARun = PAGES_A_RUN,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<SpendRequestsTables & LimitReservationsTables & AuditTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** MOST_CHECKED_A_PAGE and PAGES_A_RUN, but for the tests. */
  readonly page?: number;
  readonly pagesARun?: number;
}): HoldingsCheck {
  /** The last request checked in each organisation's pass so far: none for one starting from the beginning. */
  const progress = new Map<string, string>();
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** Checks the organisation's next pages, up to its share; false if the signal stopped it. */
  const checkIn = async (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    let requests = 0;
    let mismatched = 0;
    let tampered = 0;
    for (let pages = 0; pages < pagesARun; pages += 1) {
      if (signal?.aborted === true) return false;
      const after = progress.get(orgId) ?? null;
      try {
        const checked = await withSignedStates(database, orgId, services(log), (tx, states) =>
          checkHoldings(tx, states, orgId, { after, limit: page }),
        );
        requests += checked.requests;
        mismatched += checked.mismatched;
        tampered += checked.tampered;
        if (checked.next === null) {
          progress.delete(orgId);
          log.info('holdings_check.passed', { requests, mismatched, tampered });
          return true;
        }
        progress.set(orgId, checked.next);
      } catch (error) {
        log.error('holdings_check.failed', { err: error });
        return true;
      }
    }
    log.info('holdings_check.paused', { requests, mismatched, tampered });
    return true;
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.warn('holdings_check.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        if (!(await checkIn(orgId, signal))) return;
      }
    },
  };
}
