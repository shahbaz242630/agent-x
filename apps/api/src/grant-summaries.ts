// The grant summaries of memberships added before 0085 built (OR1;
// identity's grant-building.ts): the API's job, on a timer of its own. For
// each organisation the directory lists, every run, it first looks, as a
// decision reads (`share`, a few trips, no lock for a change), whether any
// summary is unbuilt or left behind its membership by an image from before
// OR1; only then does one transaction build or bring each up to date from the
// history, read a page at a time, so no length of history stops it. Until
// then the two-person rule reads that organisation's history as before
// (two-person-facts.ts). Every run looks again, as a summary can be left
// behind at any time an older image serves (a swap, a rollback): nothing is
// remembered from one run to the next. Tampering found raises the alarm and
// holds the organisation, as any read does.
//
// A run never throws: each failure is logged, naming the organisation, and
// the run goes on to the next. Retire it, as zone sealing was (4D2e D11), once
// every environment's summaries are built.
import { type AuditTables, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { buildGrantSummaries, grantSummariesDue, type IdentityTables } from '@agentx/core/modules/identity';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How often every organisation is looked at for a summary unbuilt or left behind, once the last run has ended. */
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
  const buildIn = async (orgId: string): Promise<void> => {
    const log = logger.child({ orgId });
    const services: SignedStatesServices = { keys, ids, logger: log };
    try {
      const due = await withSignedStates(database, orgId, services, (tx, states) =>
        grantSummariesDue(tx, states, orgId),
      );
      // In step, or tampered with (its alarm raised and the organisation held): nothing to build this run.
      if (due !== true) return;
      const done = await withSignedStates(database, orgId, services, (tx, states) =>
        buildGrantSummaries(tx, states, orgId, page),
      );
      if (done.outcome === 'built' && done.built > 0) log.info('grant_summaries.built', { built: done.built });
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
        await buildIn(orgId);
      }
    },
  };
}
