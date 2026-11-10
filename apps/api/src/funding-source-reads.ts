// Reading the organisation's funding sources (PRD §7.1, §7.3, SEC-AG-05;
// Phase 1 D2-4a), each through its signed state, so nothing is shown that
// can't be believed: one tampered with refuses the answer, 503
// INTEGRITY_FAILED, and holds the organisation.
//
// - `list` and `show`: for the organisation's members, every source, ENDED
//   ones too, as Agent X holds it, each with its consent-expiry choice in
//   force (decision 21; a page's choices read in one trip, PM5).
// An agent's sources are its mandate's (agent-mandate.ts, Phase 2 B5).
import { type SourceRecord, sourcesPage } from '@agentx/core/modules/funding-sources';
import type { PendingChoice } from '@agentx/core/modules/spend-requests';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { consentExpiriesOf, consentExpiryOf } from './consent-expiry-choice.ts';
import { createFundingSourceWork, type FundingSourceTables } from './funding-source-work.ts';
import { type Refused, refused } from './refused.ts';

/** Where a page starts, and how many it holds at most (MOST_SOURCES_A_PAGE). */
export interface SourcePage {
  readonly after: string | null;
  readonly limit: number;
}

/** A source with its admin's choice for when its consent runs out (decision 21, E7), or null: none (so cancel). */
interface SourceWithChoice {
  readonly source: SourceRecord;
  readonly consentExpiry: PendingChoice | null;
}

/** A page of sources, as the agent's own read lists its mandate's (agent-mandate.ts) or members read theirs. */
type Listed<Source> =
  | {
      readonly outcome: 'listed';
      readonly sources: readonly Source[];
      readonly next: string | null;
      readonly unchecked: readonly string[];
    }
  | Refused;

export type SourcesListed = Listed<SourceRecord>;

/** The organisation's sources as its members read them: each with its consent-expiry choice. */
type SourcesChosenListed = Listed<SourceWithChoice>;

export type SourceShown =
  | {
      readonly outcome: 'found';
      readonly source: SourceRecord;
      /** Its admin's choice for when its consent runs out (decision 21, E7), or null: none (so cancel). */
      readonly consentExpiry: PendingChoice | null;
    }
  | Refused;

export interface FundingSourceReads {
  list(orgId: string, page: SourcePage, correlationId: string): Promise<SourcesChosenListed>;
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
      const listed = await work.inOrganisation(orgId, correlationId, async (tx, states) => {
        const read = await sourcesPage(tx, states, orgId, page);
        if (read.outcome === 'tampered') return read;
        const chosen = await consentExpiriesOf(
          tx,
          states,
          orgId,
          read.sources.map(({ id }) => id),
        );
        return { ...read, sources: read.sources.map((source, at) => ({ source, consentExpiry: chosen[at] ?? null })) };
      });
      if (listed.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      return listed;
    },

    show: (orgId, sourceId, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const { source } = await work.sourceIn(tx, states, { orgId, id: sourceId }, 'share');
        return {
          outcome: 'found' as const,
          source,
          consentExpiry: await consentExpiryOf(tx, states, orgId, source.id),
        };
      }),
  };
}
