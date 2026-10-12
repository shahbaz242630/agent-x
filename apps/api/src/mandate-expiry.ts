// Mandates ended by the clock (PRD §4.1; BR-05; FX-MANDATES "expired by
// clock"; Phase 2 B4): the API's job, on a timer of its own, moving each
// ACTIVE or SUSPENDED mandate whose version in force has reached its end to
// EXPIRED, recorded as the API's, and telling every admin and approver
// (0036), in the same transaction.
//
// For each organisation the directory lists, the candidates are found by
// their rows (`mandatesPastTheirEnd`), a page at a time, each page after the
// last, so mandates refused on every run (tampered with) can't fill a page
// and keep the rest from their end (S90 review), then each in a transaction
// of its own:
// the mandate read for change through its signed state (a tampered one is
// refused there, and the job goes on to the next), still open, its version in
// force verified and ended still; then moved. A mandate moved meanwhile
// (revoked, or expired by another run) is left as it is.
//
// The job is the record, not the brake: a spend checks the version's end
// itself (SEC-AG-12), so the minutes before the job reaches a mandate
// authorise nothing. Phase 3 adds the cascade in the same transaction
// (PRD §4.2).
//
// A run never throws: each failure is logged, naming the organisation and
// mandate, and the run goes on to the next.
import { type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import { isEnded, MANDATES, mandatesPastTheirEnd } from '@agentx/core/modules/mandates';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { eachOrganisation, expireInPages } from './expiry-pages.ts';
import { type MandateTables, mandateIn, toldAdminsAndApprovers, versionIn } from './mandate-reads.ts';
import { movedAsRead } from './use-case-work.ts';

/** How often ended mandates are looked for, once the last run has ended: a mandate is expired within this of its end. */
export const MANDATE_EXPIRY_EVERY_MS = 5 * 60_000;

/** How many of an organisation's mandates one run expires, and how many candidates a page holds: the rest wait for the next run. */
const MOST_EXPIRED_A_RUN = 100;

const ACTOR = { type: 'system', id: 'api' } as const;

export interface MandateExpiry {
  /** Expires the mandates past their end, up to MOST_EXPIRED_A_RUN an organisation (the rest wait for the next run), until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createMandateExpiry({
  list,
  database,
  keys,
  ids,
  clock,
  outbox,
  logger,
  most = MOST_EXPIRED_A_RUN,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<MandateTables & NotificationsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly outbox: Outbox;
  readonly logger: Logger;
  /** MOST_EXPIRED_A_RUN, but for the tests. */
  readonly most?: number;
}): MandateExpiry {
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** Expires the mandate if it is open and its version in force has ended; whether it did. */
  const expire = (log: Logger, orgId: string, id: string): Promise<boolean> =>
    withSignedStates(database, orgId, services(log), async (tx, states) => {
      const { mandate } = await mandateIn(tx, states, orgId, id, 'change');
      if (isEnded(mandate.status) || mandate.currentVersionId === null) return false;
      const current = await versionIn(tx, states, orgId, id, mandate.currentVersionId);
      if (current.endsAt === null || current.endsAt > clock.now()) return false;
      movedAsRead(
        await states.changeStatus(tx, MANDATES, { orgId, id }, 'expire', {
          actor: ACTOR,
          action: 'mandate.expired',
          details: { versionId: current.id, endsAt: current.endsAt.toISOString() },
        }),
        "a mandate read as open didn't expire",
      );
      await outbox.add(tx, toldAdminsAndApprovers(orgId, 'mandate_expired', id));
      return true;
    });

  /** Expires the mandate as `expire` does, logging what came of it; whether it did. Never throws. */
  const expiredLogged = async (log: Logger, orgId: string, mandateId: string): Promise<boolean> => {
    try {
      const expired = await expire(log, orgId, mandateId);
      if (expired) log.info('mandate_expiry.expired', { mandateId });
      return expired;
    } catch (error) {
      // A mandate that can't be believed (its alarm raised by the read), or a write that failed.
      log.error('mandate_expiry.failed', { mandateId, err: error });
      return false;
    }
  };

  /** Expires the organisation's mandates past their end, up to its share; false if the signal stopped it. */
  const expireIn = (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    return expireInPages({
      most,
      signal,
      page: (left, after) =>
        withSignedStates(database, orgId, services(log), (tx) =>
          mandatesPastTheirEnd(tx, orgId, clock.now(), left, after),
        ),
      expire: (mandateId) => expiredLogged(log, orgId, mandateId),
      unreadable: (error) => {
        log.error('mandate_expiry.unreadable', { err: error });
      },
    });
  };

  return {
    run: (signal) =>
      eachOrganisation(
        list,
        // The whole run skipped: an error, which the integrity-runs alert counts (Phase 2 E2c).
        (error) => {
          logger.error('mandate_expiry.run_failed', { err: error });
        },
        (orgId) => expireIn(orgId, signal),
      ),
  };
}
