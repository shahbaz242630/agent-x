// Reading the organisation's funding sources (PRD §7.1, §7.3, SEC-AG-05;
// Phase 1 D2-4a), each through its signed state, so nothing is shown that
// can't be believed: one tampered with refuses the answer, 503
// INTEGRITY_FAILED, and holds the organisation.
//
// - `list` and `show`: for the organisation's members, every source, ENDED
//   ones too, as Agent X holds it.
// An agent's sources are its mandate's (agent-mandate.ts, Phase 2 B5).
import { type SourceRecord, sourcesPage } from '@agentx/core/modules/funding-sources';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { createFundingSourceWork, type FundingSourceTables } from './funding-source-work.ts';
import { type Refused, refused } from './refused.ts';

/** Where a page starts, and how many it holds at most (MOST_SOURCES_A_PAGE). */
export interface SourcePage {
  readonly after: string | null;
  readonly limit: number;
}

export type SourcesListed =
  { readonly outcome: 'listed'; readonly sources: readonly SourceRecord[]; readonly next: string | null } | Refused;

export type SourceShown = { readonly outcome: 'found'; readonly source: SourceRecord } | Refused;

export interface FundingSourceReads {
  list(orgId: string, page: SourcePage, correlationId: string): Promise<SourcesListed>;
  show(orgId: string, sourceId: string, correlationId: string): Promise<SourceShown>;
}

export function createFundingSourceReads({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<FundingSourceTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): FundingSourceReads {
  const work = createFundingSourceWork({ database, keys, ids, logger });

  return {
    async list(orgId, page, correlationId) {
      const listed = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        sourcesPage(tx, states, orgId, page),
      );
      if (listed.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      return listed;
    },

    show: (orgId, sourceId, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const { source } = await work.sourceIn(tx, states, { orgId, id: sourceId }, 'share');
        return { outcome: 'found' as const, source };
      }),
  };
}
