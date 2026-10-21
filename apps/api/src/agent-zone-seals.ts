// The agents' month zones kept before 0054 sealed (PL-40; agent-zones.ts):
// the API's job, run once before it serves (an unsealed zone read by a
// decision would be taken for tampering) and then on a timer of its own, in
// case one start's run failed. For each organisation the directory lists,
// each unsealed zone is sealed in a transaction of its own, so the lock order
// holds (the mandate, then the zone, then the request, ADR-006 §6), and only
// to the zone of the signed mandate its agent's first request was decided
// under, which is the zone that decision kept: one that differs, or an agent
// with no such request, is a tamper sign, alarmed, and the organisation held.
//
// One transaction a zone is a loop over rows, kept because it runs only over
// rows from before 0054 (a few, once) and the lock order allows no batch.
// A run never throws: each failure is logged, naming the organisation, and
// the run goes on to the next.
import { type AuditTables, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import {
  type LimitReservationsTables,
  sealKeptZone,
  type UnsealedZone,
  unsealedZones,
} from '@agentx/core/modules/limit-reservations';
import { mandateOf, type MandatesTables } from '@agentx/core/modules/mandates';
import { requestsOf, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often zones left unsealed are looked for, once the last run has ended. */
export const ZONE_SEALING_EVERY_MS = 15 * 60_000;

type ZoneTables = LimitReservationsTables & MandatesTables & SpendRequestsTables & AuditTables;

export interface ZoneSealing {
  /** Seals each organisation's zones kept before 0054, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createZoneSealing({
  list,
  database,
  keys,
  ids,
  logger,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<ZoneTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): ZoneSealing {
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** The zone, sealed to its agent's first request's mandate's, or mismatched; its request read again once sealed. */
  const sealOne = (orgId: string, unsealed: UnsealedZone, log: Logger) =>
    withSignedStates(database, orgId, services(log), async (tx, states) => {
      const first = await tx
        // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the agent's first request's ID and mandate, both checked against its signed state below, after the zone, as the lock order has it
        .selectFrom('spend_requests.requests')
        .select(['id', 'mandate_id'])
        .where('agent_id', '=', unsealed.agentId)
        .orderBy('id')
        .limit(1)
        .executeTakeFirst();
      const mandate =
        first?.mandate_id === undefined || first.mandate_id === null
          ? undefined
          : await mandateOf(tx, states, { orgId, id: first.mandate_id }, 'share');
      const expected = mandate?.outcome === 'found' ? mandate.mandate.timeZone : '';
      const sealed = await sealKeptZone(tx, states, orgId, unsealed, expected);
      if (sealed === 'sealed' && first !== undefined) {
        // The request's signed state names the same mandate, or nothing sealed here stands.
        const request = (await requestsOf(tx, states, orgId, [first.id])).get(first.id.toLowerCase());
        if (request?.outcome !== 'found' || request.request.mandateId !== first.mandate_id?.toLowerCase()) {
          throw new Error(`An agent's first request isn't as its row says: ${unsealed.agentId}`);
        }
      }
      return sealed;
    });

  const sealIn = async (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    const counts = { sealed: 0, mismatched: 0, gone: 0 };
    try {
      const unsealed = await withSignedStates(database, orgId, services(log), (tx) => unsealedZones(tx, orgId));
      for (const zone of unsealed) {
        if (signal?.aborted === true) return false;
        counts[await sealOne(orgId, zone, log)] += 1;
      }
    } catch (error) {
      log.error('agent_zones.seal_failed', { err: error, ...counts });
      return true;
    }
    if (counts.sealed + counts.mismatched > 0) log.info('agent_zones.sealed', counts);
    return true;
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.error('agent_zones.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        if (!(await sealIn(orgId, signal))) return;
      }
    },
  };
}
