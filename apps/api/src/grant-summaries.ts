// The grant summaries of memberships added before 0085 built (OR1;
// identity's grant-building.ts): the API's job, on a timer of its own. For
// each organisation the directory lists, one transaction builds and seals
// every summary it lacks from its history, read a page at a time, so no
// length of history stops it. Until then the two-person rule reads that
// organisation's history as before (two-person-facts.ts), so nothing waits on
// this job but the bounded read.
//
// An organisation found with every summary is not visited again by this
// process: a membership added from 0085 has its summary from the start, and
// one built is never missing again (deleted, it is found by its signed state).
// A restart visits each once more. Tampering found raises the alarm and holds
// the organisation, as any read does, and it is visited again next run.
//
// A run never throws: each failure is logged, naming the organisation, and
// the run goes on to the next. Retire it, as zone sealing was (4D2e D11), once
// every environment's summaries are built.
import { type AuditTables, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { buildGrantSummaries, type IdentityTables } from '@agentx/core/modules/identity';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often organisations left with a summary unbuilt are looked at again, once the last run has ended. */
export const GRANT_SUMMARIES_EVERY_MS = 60 * 60_000;

export interface GrantSummaryBuilding {
  /** Builds each listed organisation's missing summaries, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createGrantSummaryBuilding({
  list,
  database,
  keys,
  ids,
  logger,
  page,
}: {
  /** The organisations to look in: the directory's list, which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<IdentityTables & DirectoryTables & AuditTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** How many events a read of the history takes (tests). */
  readonly page?: number;
}): GrantSummaryBuilding {
  /** Organisations found with every summary, by ID in lower case. */
  const whole = new Set<string>();

  const buildIn = async (orgId: string): Promise<void> => {
    const log = logger.child({ orgId });
    const services: SignedStatesServices = { keys, ids, logger: log };
    try {
      const done = await withSignedStates(database, orgId, services, (tx, states) =>
        buildGrantSummaries(tx, states, orgId, page),
      );
      // Tampering found: its alarm is raised and the organisation held; it is looked at again next run.
      if (done.outcome === 'tampered') return;
      whole.add(orgId.toLowerCase());
      if (done.built > 0) log.info('grant_summaries.built', { built: done.built });
    } catch (error) {
      log.error('grant_summaries.build_failed', { err: error });
    }
  };

  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.error('grant_summaries.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        if (signal?.aborted === true) return;
        if (!whole.has(orgId.toLowerCase())) await buildIn(orgId);
      }
    },
  };
}
