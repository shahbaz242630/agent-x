// Mandates ended by the clock (PRD §4.1; BR-05; FX-MANDATES "expired by
// clock"; Phase 2 B4): the API's job, on a timer of its own, moving each
// ACTIVE or SUSPENDED mandate whose version in force has reached its end to
// EXPIRED, recorded as the API's, and telling every admin and approver
// (0036), in the same transaction.
//
// For each organisation the directory lists, the candidates are found by
// their rows (`mandatesPastTheirEnd`), then each in a transaction of its own:
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
import { listedOrganizations } from '@agentx/core/modules/directory';
import { isEnded, MANDATES, mandatesPastTheirEnd } from '@agentx/core/modules/mandates';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type MandateTables, mandateIn, versionIn } from './mandate-reads.ts';
import { movedAsRead } from './use-case-work.ts';

/** How often ended mandates are looked for, once the last run has ended: a mandate is expired within this of its end. */
export const MANDATE_EXPIRY_EVERY_MS = 5 * 60_000;

/** How many of an organisation's mandates one run expires: the rest wait for the next. */
const MOST_EXPIRED_A_RUN = 100;

const ACTOR = { type: 'system', id: 'api' } as const;

export interface MandateExpiry {
  /** Expires every mandate past its end, until none is left or the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createMandateExpiry({
  database,
  keys,
  ids,
  clock,
  outbox,
  logger,
}: {
  readonly database: Database<MandateTables & NotificationsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly outbox: Outbox;
  readonly logger: Logger;
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
      await outbox.add(tx, [
        { orgId, recipientUserId: null, kind: 'mandate_expired', membershipId: null, role: null, aboutId: id },
      ]);
      return true;
    });

  return {
    async run(signal) {
      let orgs: string[];
      try {
        orgs = await listedOrganizations(database);
      } catch (error) {
        logger.warn('mandate_expiry.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        const log = logger.child({ orgId });
        let due: readonly string[];
        try {
          due = await withSignedStates(database, orgId, services(log), (tx) =>
            mandatesPastTheirEnd(tx, orgId, clock.now(), MOST_EXPIRED_A_RUN),
          );
        } catch (error) {
          log.error('mandate_expiry.unreadable', { err: error });
          continue;
        }
        for (const mandateId of due) {
          if (signal?.aborted === true) return;
          try {
            if (await expire(log, orgId, mandateId)) log.info('mandate_expiry.expired', { mandateId });
          } catch (error) {
            // A mandate that can't be believed (its alarm raised by the read), or a write that failed.
            log.error('mandate_expiry.failed', { mandateId, err: error });
          }
        }
      }
    },
  };
}
