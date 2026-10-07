// An agent's own authority, as its key reads it (PRD §3, §4.1, §7.2; BR-05;
// SEC-AG-05; Phase 2 B5): the mandate it acts under, and the bank accounts
// that mandate lets it pay from.
//
// - `inForce`: the agent's mandate with a version in force that hasn't
//   reached its end, ACTIVE or SUSPENDED (so a stopped agent learns why), with
//   that version's terms. A draft waiting for acceptance grants nothing, and
//   an ended one nothing more: NOT_FOUND for either, or for none. The end is
//   checked here on the clock, not left to the expiry job (B4).
// - `sources`: the funding sources the agent may pay from now: the one its
//   ACTIVE mandate's version in force names (a version names one, B1), while
//   it may fund (`mayFund`); none without such a mandate. Paged after that
//   filter (the D2-4a review), so nothing hints at the organisation's other
//   sources.
//
// Reads alone, each through its signed state: the agent's open mandate (one
// statement, 0035's index), its version in force, the source.
import type { SignedStates } from '@agentx/core/modules/audit';
import { mayFund, type SourceRecord } from '@agentx/core/modules/funding-sources';
import { type MandateRecord, type MandateVersionRecord, openMandateOfAgent } from '@agentx/core/modules/mandates';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { SourcePage } from './funding-source-reads.ts';
import { MandateRefused, type MandateTables, type MandateTx, sourceIn, versionIn } from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork } from './use-case-work.ts';

export type AgentMandateShown =
  { readonly outcome: 'found'; readonly mandate: MandateRecord; readonly version: MandateVersionRecord } | Refused;

export type AgentSourcesListed =
  { readonly outcome: 'listed'; readonly sources: readonly SourceRecord[]; readonly next: string | null } | Refused;

export interface AgentMandates {
  inForce(orgId: string, agentId: string, correlationId: string): Promise<AgentMandateShown>;
  sources(orgId: string, agentId: string, page: SourcePage, correlationId: string): Promise<AgentSourcesListed>;
}

export function createAgentMandates({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Database<MandateTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): AgentMandates {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  /** The agent's mandate with its version in force, unended; undefined for none (INTEGRITY_FAILED if tampered with). */
  const inForceIn = async (tx: MandateTx, states: SignedStates, orgId: string, agentId: string) => {
    const read = await openMandateOfAgent(tx, states, orgId, agentId);
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') return undefined;
    const { mandate } = read;
    // Open, as the query finds it and its verified read holds: a draft has no version in force, so it grants
    // nothing; ACTIVE or SUSPENDED have one (0035; B5's mutation pass: a status check here too was dead).
    if (mandate.currentVersionId === null) return undefined;
    const version = await versionIn(tx, states, orgId, mandate.id, mandate.currentVersionId);
    if (version.endsAt !== null && version.endsAt <= clock.now()) return undefined;
    return { mandate, version };
  };

  return {
    inForce: (orgId, agentId, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const found = await inForceIn(tx, states, orgId, agentId);
        if (found === undefined) throw new MandateRefused(404, 'NOT_FOUND');
        return { outcome: 'found' as const, ...found };
      }),

    sources: (orgId, agentId, page, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const found = await inForceIn(tx, states, orgId, agentId);
        const usable: SourceRecord[] = [];
        if (found?.mandate.status === 'ACTIVE') {
          const source = await sourceIn(tx, states, orgId, found.version.fundingSourceId);
          if (mayFund(source, clock.now())) usable.push(source);
        }
        // A version names one source (B1), so a page holds it or nothing, and no page follows: after the filter.
        const after = page.after?.toLowerCase();
        return {
          outcome: 'listed' as const,
          sources: usable.filter((s) => after === undefined || s.id > after),
          next: null,
        };
      }),
  };
}
