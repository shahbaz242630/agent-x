// Changing a funding source (PRD §2.3 step 5, §7.1, ADR-012 §5, ADR-003 §8;
// Phase 1 D2-4). Composed in the API, as linking is: the partner is the
// providers module's adapter, the source the funding-sources module's.
//
// - `refresh` (`funding-sources.refresh`), an admin: Agent X asks the
//   partner, server to server, how the source stands now, and brings it up to
//   that answer: the bank's suspension and its return, a renewal's consent
//   and controls, an expiry; ENDED for good when the partner says it is gone,
//   or no longer knows it. The source is read first, so only the
//   organisation's own is asked about (SEC-PTR-08); the partner is asked
//   outside any transaction; then, in one, the key claimed, the admin read
//   again, the source read for change and the answer recorded (only what
//   changed, and never an answer older than the one it holds). An ENDED
//   source is answered as it stands, the partner not asked.
//
// Lock order (ADR-006 §6): the idempotency key, the member's membership (2a),
// the source (5), the chain head last.
import { endUnknownToPartner, type SourceRecord, updateFromPartner } from '@agentx/core/modules/funding-sources';
import type { FinancialRailAdapter, SourceLookup } from '@agentx/core/modules/providers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  asked,
  createFundingSourceWork,
  type FundingSourceMember,
  type FundingSourceTables,
  PARTNER_UNAVAILABLE,
  type Refused,
} from './funding-source-work.ts';

/** Asking the partner how a source stands now. */
export const REFRESH_OPERATION = 'funding-sources.refresh';

/** Who may ask: the admins who link the organisation's bank account (PRD §7.3). */
export const REFRESHING_ROLES = ['admin'] as const;

export type SourceChangeWrite =
  | { readonly outcome: 'changed'; readonly source: SourceRecord }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface FundingSourceChanges {
  refresh(
    member: FundingSourceMember,
    idempotent: IdempotentRequest,
    sourceId: string,
    correlationId: string,
  ): Promise<SourceChangeWrite>;
}

export function createFundingSourceChanges({
  database,
  keys,
  ids,
  rail,
  logger,
}: {
  readonly database: Database<FundingSourceTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** The partner, or undefined where none is set up (config.partner): then a refresh answers PARTNER_UNAVAILABLE. */
  readonly rail: FinancialRailAdapter | undefined;
  readonly logger: Logger;
}): FundingSourceChanges {
  const work = createFundingSourceWork({ database, keys, ids, logger });

  /** Answers the write: the source as it now stands, on a retry too. */
  const answer = async (
    orgId: string,
    correlationId: string,
    done: Awaited<ReturnType<typeof work.write>>,
  ): Promise<SourceChangeWrite> => {
    if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
    const read = await work.answered(orgId, correlationId, (tx, states) =>
      work.sourceIn(tx, states, { orgId, id: done.result.resourceId }, 'share'),
    );
    if ('outcome' in read && read.outcome === 'refused') return read;
    return { outcome: 'changed', source: read.source };
  };

  return {
    async refresh(member, idempotent, sourceId, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      // The organisation's own source, read first: only its reference is asked about.
      const known = await work.answered(member.orgId, correlationId, (tx, states) =>
        work.sourceIn(tx, states, { orgId: member.orgId, id: sourceId }, 'share'),
      );
      if ('outcome' in known && known.outcome === 'refused') return known;
      const { source } = known;
      let lookup: SourceLookup | undefined;
      if (source.status !== 'ENDED') {
        const asking = await asked(() =>
          rail.getSourceState({ organizationId: member.orgId, externalRef: source.externalRef }),
        );
        if (asking === 'unavailable') return PARTNER_UNAVAILABLE;
        lookup = asking;
      }
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REFRESHING_ROLES);
        const key = { orgId: member.orgId, id: sourceId };
        const found = await work.sourceIn(tx, states, key, 'change');
        const actor = { type: 'user' as const, id: member.userId };
        if (lookup === undefined || found.source.status === 'ENDED') return { status: 200, resourceId: sourceId };
        if (lookup.kind === 'not_found') await endUnknownToPartner(tx, states, key, found, actor);
        else await updateFromPartner(tx, states, key, found, { state: lookup.source, actor });
        return { status: 200, resourceId: sourceId };
      });
      return answer(member.orgId, correlationId, done);
    },
  };
}
