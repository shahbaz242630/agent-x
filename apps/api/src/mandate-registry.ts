// Drafting and reading the organisation's mandates (PRD §3, §3.1, §7.1, BR-05,
// BR-06; Phase 2 B2), composed here as ADR-004 §7 has it.
//
// - `draft`, an admin: the key, the drafting lock, the admin read again, the
//   day's budget (MANDATE_DRAFTS_SPENT), the agent active (AGENT_NOT_ACTIVE)
//   with no mandate open (MANDATE_OPEN: a second could never be accepted, B1's
//   review), the terms against the organisation, then the mandate with its
//   first version. No step-up: a draft grants nothing until an admin accepts
//   it with a passkey (B3, partner S86).
// - `redraft`: a later version, waiting in place of any that waited; none for
//   an ended mandate (MANDATE_ENDED).
// - The terms against the organisation: the source its own and able to fund
//   (SOURCE_NOT_USABLE); within its bank consent (MANDATE_PAST_CONSENT when
//   strict, partner S87; flexible kept, its warnings in the version's event);
//   every supplier its own (SUPPLIER_UNKNOWN), in one statement.
// - `list` and `show`, every member: through the signed states (503
//   INTEGRITY_FAILED); `show` gives each version with how it now stands
//   against its source's consent, which the bank can change after the draft.
//
// Lock order (ADR-006 §6): the idempotency key, the drafting lock, the
// member's membership (2a), the agent (3), the mandates (4), the source (5),
// the chain head last; the suppliers are counted, never locked.
import { agentOf, type AgentsTables } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { type FundingSourcesTables, mayFund, type SourceRecord, sourceOf } from '@agentx/core/modules/funding-sources';
import {
  type ConsentAllows,
  consentCheck,
  DEFAULT_SPLIT_WINDOW_HOURS,
  draftMandate,
  draftsSince,
  draftVersion,
  isEnded,
  type MandateRecord,
  type MandatesTables,
  type MandateShown,
  type MandateTerms,
  type MandateVersionRecord,
  mandateOf,
  mandatesPage,
  mandateVersionOf,
  MOST_DRAFTS_A_DAY,
  oneDraftAtATime,
  openMandateOfAgent,
} from '@agentx/core/modules/mandates';
import { type SuppliersTables, suppliersFound } from '@agentx/core/modules/suppliers';
import { type Clock, DAY_MS, DEFAULT_TIME_ZONE, type IdGenerator, money } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { Refused } from './refused.ts';
import { createUseCaseWork, type Member, UseCaseRefused, type UseCaseTables, type Written } from './use-case-work.ts';

/** Drafting a mandate, and a later version of one. */
export const DRAFT_OPERATION = 'mandates.draft';
export const REDRAFT_OPERATION = 'mandates.redraft';

/** Who may draft: the admins, as accept (partner, S86). */
export const DRAFTING_ROLES = ['admin'] as const;

export type MandateTables = UseCaseTables & MandatesTables & AgentsTables & FundingSourcesTables & SuppliersTables;
type Tx = DatabaseTransaction<MandateTables>;

/** The mandates' UseCaseRefused: the only refusal their work answers. */
class MandateRefused extends UseCaseRefused {}

/** A new mandate as a body gives it: its agent, the zone its months are counted in and its split window, if not the defaults, and its first terms. */
export interface MandateDraft {
  readonly agentId: string;
  readonly timeZone: string | null;
  readonly splitWindowHours: number | null;
  readonly terms: MandateTerms;
}

/** A version as the routes show it: its terms, and how they now stand against the bank consent. */
export interface VersionShown {
  readonly version: MandateVersionRecord;
  readonly consentWarnings: readonly string[];
}

/** A mandate as the routes show it: its signed state, its version in force and its waiting draft. */
export interface MandateView {
  readonly mandate: MandateRecord;
  readonly current: VersionShown | null;
  readonly pending: VersionShown | null;
}

/** Where a page starts, and how many it holds at most (MOST_MANDATES_A_PAGE). */
interface MandatePage {
  readonly after: string | null;
  readonly limit: number;
}

export type MandateWrite =
  | ({ readonly outcome: 'drafted' } & MandateView)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

type MandatesListed =
  { readonly outcome: 'listed'; readonly mandates: readonly MandateShown[]; readonly next: string | null } | Refused;

export interface MandateRegistry {
  draft(
    member: Member,
    idempotent: IdempotentRequest,
    draft: MandateDraft,
    correlationId: string,
  ): Promise<MandateWrite>;
  redraft(
    member: Member,
    idempotent: IdempotentRequest,
    mandateId: string,
    terms: MandateTerms,
    correlationId: string,
  ): Promise<MandateWrite>;
  list(orgId: string, page: MandatePage, correlationId: string): Promise<MandatesListed>;
  show(
    orgId: string,
    mandateId: string,
    correlationId: string,
  ): Promise<({ readonly outcome: 'found' } & MandateView) | Refused>;
}

/** What a source's bank consent allows, as the terms are checked against it. */
const consentOf = ({ controls: { currency, period, maxPaymentMinor, maxPeriodMinor } }: SourceRecord) =>
  ({
    currency,
    maxPayment: money(maxPaymentMinor, currency),
    maxPeriod: money(maxPeriodMinor, currency),
    limitPeriod: period,
  }) satisfies ConsentAllows;

export function createMandateRegistry({
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
}): MandateRegistry {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  /** The source, read (`share`) and verified: SOURCE_NOT_USABLE for none of the organisation's. */
  const sourceIn = async (tx: Tx, states: SignedStates, orgId: string, sourceId: string) => {
    const read = await sourceOf(tx, states, { orgId, id: sourceId }, 'share');
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new MandateRefused(409, 'SOURCE_NOT_USABLE');
    return read.source;
  };

  /** The terms against the organisation: its source, able to fund; within its consent, when strict; its suppliers. Gives the version's event its consent warnings. */
  const termsChecked = async (tx: Tx, states: SignedStates, orgId: string, terms: MandateTerms, now: Date) => {
    // The edge checked the end on its own clock; again on ours, so the core's floor never refuses it later (a 500).
    if (terms.endsAt !== null && terms.endsAt <= now) throw new MandateRefused(400, 'BAD_REQUEST');
    const source = await sourceIn(tx, states, orgId, terms.fundingSourceId);
    if (!mayFund(source, now)) throw new MandateRefused(409, 'SOURCE_NOT_USABLE');
    const { refused, problems: warnings } = consentCheck(terms, consentOf(source));
    if (refused) throw new MandateRefused(409, 'MANDATE_PAST_CONSENT');
    const found = await suppliersFound(tx, orgId, terms.supplierIds);
    if (found.length !== new Set(terms.supplierIds.map((id) => id.toLowerCase())).size) {
      throw new MandateRefused(409, 'SUPPLIER_UNKNOWN');
    }
    return { consentWarnings: warnings.length === 0 ? null : warnings.join('; ') };
  };

  /** The budget and the drafting lock, in the order the lock order takes them, with the admin read again: the admin. */
  const drafting = async (tx: Tx, states: SignedStates, member: Member, now: Date) => {
    await oneDraftAtATime(tx, member.orgId);
    const admin = await work.memberIn(tx, states, member, DRAFTING_ROLES);
    if ((await draftsSince(tx, member.orgId, new Date(now.getTime() - DAY_MS))) >= MOST_DRAFTS_A_DAY) {
      throw new MandateRefused(409, 'MANDATE_DRAFTS_SPENT');
    }
    return admin;
  };

  /** The mandate read (`share` or `change`) and verified: NOT_FOUND, or INTEGRITY_FAILED for one that can't be believed. */
  const mandateIn = async (tx: Tx, states: SignedStates, orgId: string, id: string, lock: 'share' | 'change') => {
    const read = await mandateOf(tx, states, { orgId, id }, lock);
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new MandateRefused(404, 'NOT_FOUND');
    return read;
  };

  /** A version of the mandate with how it now stands against its source's consent (whichever its setting: flexible gives the list). */
  const versionShown = async (
    tx: Tx,
    states: SignedStates,
    orgId: string,
    mandateId: string,
    versionId: string | null,
  ): Promise<VersionShown | null> => {
    if (versionId === null) return null;
    const read = await mandateVersionOf(tx, states, { orgId, id: versionId }, mandateId);
    if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    // 0035's keys hold a mandate's versions to its own.
    if (read.outcome === 'missing') throw new Error(`A mandate names a version not its own: ${mandateId}`);
    const source = await sourceIn(tx, states, orgId, read.version.fundingSourceId);
    return { version: read.version, consentWarnings: consentCheck(read.version, consentOf(source)).problems };
  };

  const viewIn = async (tx: Tx, states: SignedStates, orgId: string, mandateId: string): Promise<MandateView> => {
    const { mandate } = await mandateIn(tx, states, orgId, mandateId, 'share');
    return {
      mandate,
      current: await versionShown(tx, states, orgId, mandate.id, mandate.currentVersionId),
      pending: await versionShown(tx, states, orgId, mandate.id, mandate.pendingVersionId),
    };
  };

  /** A write's answer: its refusal or its key's outcome as it is, otherwise the mandate it wrote as it now stands (on a retry too). */
  const draftedAfter = async (orgId: string, correlationId: string, done: Written): Promise<MandateWrite> => {
    if (isUnwritten(done)) return done;
    const view = await work.answered(orgId, correlationId, (tx, states) =>
      viewIn(tx, states, orgId, done.result.resourceId),
    );
    return 'outcome' in view ? view : { outcome: 'drafted', ...view };
  };

  return {
    async draft(member, idempotent, { agentId, timeZone, splitWindowHours, terms }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const now = clock.now();
        const admin = await drafting(tx, states, member, now);
        const agent = await agentOf(tx, states, { orgId: member.orgId, id: agentId }, 'share');
        if (agent.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
        if (agent.outcome === 'missing') throw new MandateRefused(404, 'NOT_FOUND');
        if (agent.agent.status !== 'ACTIVE') throw new MandateRefused(409, 'AGENT_NOT_ACTIVE');
        const open = await openMandateOfAgent(tx, states, member.orgId, agent.agent.id);
        if (open.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
        if (open.outcome === 'found') throw new MandateRefused(409, 'MANDATE_OPEN');
        const details = await termsChecked(tx, states, member.orgId, terms, now);
        const id = ids.next();
        await draftMandate(tx, states, {
          orgId: member.orgId,
          id,
          versionId: ids.next(),
          agentId: agent.agent.id,
          timeZone: timeZone ?? DEFAULT_TIME_ZONE,
          splitWindowHours: splitWindowHours ?? DEFAULT_SPLIT_WINDOW_HOURS,
          terms,
          draftedBy: admin.id,
          draftedAt: now,
          actor: { type: 'user', id: member.userId },
          details,
        });
        return { status: 201, resourceId: id };
      });
      return draftedAfter(member.orgId, correlationId, done);
    },

    async redraft(member, idempotent, mandateId, terms, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const now = clock.now();
        const admin = await drafting(tx, states, member, now);
        const read = await mandateIn(tx, states, member.orgId, mandateId, 'change');
        if (isEnded(read.mandate.status)) throw new MandateRefused(409, 'MANDATE_ENDED');
        const details = await termsChecked(tx, states, member.orgId, terms, now);
        await draftVersion(tx, states, read, {
          orgId: member.orgId,
          id: ids.next(),
          terms,
          draftedBy: admin.id,
          draftedAt: now,
          actor: { type: 'user', id: member.userId },
          details,
        });
        return { status: 200, resourceId: read.mandate.id };
      });
      return draftedAfter(member.orgId, correlationId, done);
    },

    async list(orgId, page, correlationId) {
      const listed = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        mandatesPage(tx, states, orgId, page),
      );
      if (listed.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
      return listed;
    },

    async show(orgId, mandateId, correlationId) {
      const view = await work.answered(orgId, correlationId, (tx, states) => viewIn(tx, states, orgId, mandateId));
      return 'outcome' in view ? view : { outcome: 'found', ...view };
    },
  };
}
