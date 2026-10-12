// Spend requests left waiting for approval expired (PRD §4.2; ADR-006 §10;
// BR-09; partner decision 10; Phase 2 D7): the API's job, on a timer of its
// own, moving each request APPROVAL_REQUIRED for 72 hours from its decision
// to EXPIRED, recorded as the API's, its reservation and order claim released
// in the same transaction, so the agent's monthly budget, the split total and
// the order are free again. No one is emailed yet (Phase 3's approvals).
//
// For each organisation the directory lists, the candidates are found by
// their rows (`requestsWaitingSince`, 0042's index), a page at a time, each
// page after the last, so requests refused on every run (tampered with) can't
// fill a page and keep the rest waiting; then each in a transaction of its
// own, judged by its decision's sealed time (`expireRequest`). A request
// approved, denied or cancelled meanwhile is left as it is.
//
// A run never throws: each failure is logged, naming the organisation and
// request, and the run goes on to the next. A run that can't read the
// organisation list is an error the integrity-runs alert counts (E2c).
import { type AuditTables, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import {
  expireRequest,
  requestsWaitingSince,
  type SpendRequestsTables,
  WAITS_FOR_APPROVAL_MS,
} from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { eachOrganisation, expireInPages } from './expiry-pages.ts';

/** How often waiting requests are looked for, once the last run has ended: a request expires within this of its 72 hours. */
export const REQUEST_EXPIRY_EVERY_MS = 5 * 60_000;

/** How many of an organisation's requests one run expires, and how many candidates a page holds: the rest wait for the next run. */
const MOST_EXPIRED_A_RUN = 100;

export interface RequestExpiry {
  /** Expires the requests waiting past their 72 hours, up to MOST_EXPIRED_A_RUN an organisation, until the signal is aborted. Never throws. */
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

  /** Expires the organisation's requests past their 72 hours, up to its share; false if the signal stopped it. */
  const expireIn = (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    const before = new Date(clock.now().getTime() - WAITS_FOR_APPROVAL_MS);
    return expireInPages({
      most,
      signal,
      page: (left, after) =>
        withSignedStates(database, orgId, services(log), (tx) => requestsWaitingSince(tx, orgId, before, left, after)),
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
