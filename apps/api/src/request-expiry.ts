// Spend requests left waiting for approval expired (PRD §4.2; ADR-006 §10;
// BR-09; partner decision 10; Phase 2 D7): the API's job, on a timer of its
// own, moving each request APPROVAL_REQUIRED past the wait its decision
// sealed (24, 48 or 72 hours from it: E6) to EXPIRED, recorded as the API's, its reservation and order claim released
// in the same transaction, so the agent's monthly budget, the split total and
// the order are free again. No one is emailed yet (Phase 3's approvals).
//
// For each organisation the directory lists, the candidates are found by
// their rows (`requestsWaitingSince`, 0042's index: waiting at least the
// shortest wait), a page at a time, each page after the last, so requests
// refused on every run (tampered with) can't fill a page and keep the rest
// waiting; each page kept to those whose sealed wait has run out, read in the
// page's one transaction (`duePage`), so one not yet due takes no lock and no
// transaction of its own every run; then each in a transaction of its own,
// judged again under its lock (`expireRequest`). A request
// approved, denied or cancelled meanwhile is left as it is.
//
// A run never throws: each failure is logged, naming the organisation and
// request, and the run goes on to the next. A run that can't read the
// organisation list is an error the integrity-runs alert counts (E2c).
import {
  type AuditTables,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import {
  type Decided,
  decisionsOf,
  expireRequest,
  requestsWaitingSince,
  SHORTEST_APPROVAL_WAIT_MS,
  type SpendRequestsTables,
  waitedOut,
} from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { eachOrganisation, expireInPages } from './expiry-pages.ts';

/** How often waiting requests are looked for, once the last run has ended: a request expires within this of its wait. */
export const REQUEST_EXPIRY_EVERY_MS = 5 * 60_000;

/** How many of an organisation's requests one run expires, and how many candidates a page holds: the rest wait for the next run. */
const MOST_EXPIRED_A_RUN = 100;

export interface RequestExpiry {
  /** Expires the requests waiting past their wait, up to MOST_EXPIRED_A_RUN an organisation, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createRequestExpiry({
  list,
  database,
  keys,
  ids,
  clock,
  logger,
  most = MOST_EXPIRED_A_RUN,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<SpendRequestsTables & LimitReservationsTables & AuditTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** MOST_EXPIRED_A_RUN, but for the tests. */
  readonly most?: number;
}): RequestExpiry {
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** Expires the request as expireRequest does, logging what came of it; whether it did. Never throws. */
  const expiredLogged = async (log: Logger, orgId: string, requestId: string): Promise<boolean> => {
    try {
      const ended = await withSignedStates(database, orgId, services(log), (tx, states) =>
        expireRequest(tx, states, keys, { orgId, id: requestId }, clock.now()),
      );
      if (ended.outcome === 'ended') log.info('request_expiry.expired', { requestId });
      // A tampered request has raised its alarm through its read; the rest were moved meanwhile, or aren't due.
      return ended.outcome === 'ended';
    } catch (error) {
      // A history that can't be read, or a write that failed.
      log.error('request_expiry.failed', { requestId, err: error });
      return false;
    }
  };

  /** Expires the organisation's requests past their wait, up to its share; false if the signal stopped it. */
  const expireIn = (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    const now = clock.now();
    return expireInPages({
      most,
      signal,
      page: (left, after) =>
        withSignedStates(database, orgId, services(log), (tx, states) =>
          duePage(tx, states, { orgId, now, left, after }),
        ),
      expire: (requestId) => expiredLogged(log, orgId, requestId),
      unreadable: (error) => {
        log.error('request_expiry.unreadable', { err: error });
      },
    });
  };

  return {
    run: (signal) =>
      eachOrganisation(
        list,
        // The whole run skipped: an error, which the integrity-runs alert counts (Phase 2 E2c).
        (error) => {
          logger.error('request_expiry.run_failed', { err: error });
        },
        (orgId) => expireIn(orgId, signal),
      ),
  };
}

/**
 * The IDs of the organisation's requests due to expire, in order of ID after
 * `after`, at most `left`: its rows waiting at least the shortest wait, read
 * `left` at a time, each kept once the wait its decision sealed has run out
 * (their decisions read in one statement a page), until `left` are kept or
 * the rows run out. Their order is the rows', so the job's next page, after
 * the last kept, reads again only rows not yet due. One whose decision can't
 * be read is kept: expireRequest judges it and fails loudly. A page whose
 * decisions can't be read at all (one past belief, say) keeps every row, so
 * each is judged alone and the rest still expire (S119 review: one bad
 * request must never hold the organisation's money for good).
 */
async function duePage(
  tx: DatabaseTransaction<SpendRequestsTables & AuditTables>,
  states: SignedStates,
  { orgId, now, left, after }: { orgId: string; now: Date; left: number; after: string | undefined },
): Promise<readonly string[]> {
  const before = new Date(now.getTime() - SHORTEST_APPROVAL_WAIT_MS);
  const due: string[] = [];
  let from = after;
  for (;;) {
    const rows = await requestsWaitingSince(tx, orgId, before, left, from);
    let decided: ReadonlyMap<string, Decided>;
    try {
      decided = await decisionsOf(tx, states, orgId, rows);
    } catch {
      decided = new Map();
    }
    for (const id of rows) {
      const decision = decided.get(id.toLowerCase());
      if (decision === undefined || waitedOut(decision, now)) due.push(id);
    }
    if (due.length >= left || rows.length < left) return due.slice(0, left);
    from = rows.at(-1);
  }
}
