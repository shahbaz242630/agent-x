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
// - `suspend` (`funding-sources.suspend`, D2-4b): the business's own brake on
//   the source, one click and no step-up (ADR-014 §8: the instant brakes are
//   never behind step-up), for an admin or a finance approver. The key
//   claimed first; the member read again; the source read for change; then
//   ACTIVE > SUSPENDED, recorded as the member's. A source suspended or
//   ENDED already is left as it is, and answered: a brake pressed twice is
//   not an error. A suspended source funds nothing (`mayFund`). Phase 3 adds
//   the cascade in the same transaction: its pending requests denied, their
//   approvals cancelled (PRD §4.2).
// - `reactivate` (`funding-sources.reactivate`, D2-4b): gives the source its
//   authority back, so an admin's, with step-up (a passkey, ADR-003 §8,
//   SEC-HA-12). The ask: the key claimed first; the admin read again; the
//   source, SUSPENDED (SOURCE_NOT_SUSPENDED otherwise); a challenge bound to
//   the event that suspended the source, so it
//   reactivates exactly that suspension and not a later one. The confirm,
//   with the challenge: the same reads, the source for change; the challenge
//   consumed; then SUSPENDED > ACTIVE, with the step-up's evidence on its
//   event. The partner's own word still decides whether it may fund.
//
// Lock order (ADR-006 §6): the idempotency key, the member's membership (2a),
// the source (5), the step-up challenge, the chain head last.
import type { SignedStates } from '@agentx/core/modules/audit';
import {
  endUnknownToPartner,
  SOURCES,
  type SourceRecord,
  updateFromPartner,
} from '@agentx/core/modules/funding-sources';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { FinancialRailAdapter, SourceLookup } from '@agentx/core/modules/providers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  asked,
  createFundingSourceWork,
  type FundingSourceMember,
  FundingSourceRefused,
  type FundingSourceTables,
  type FundingSourceTx,
  PARTNER_UNAVAILABLE,
  type Refused,
} from './funding-source-work.ts';

/** Asking the partner how a source stands now. */
export const REFRESH_OPERATION = 'funding-sources.refresh';

/** Who may ask: the admins who link the organisation's bank account (PRD §7.3). */
export const REFRESHING_ROLES = ['admin'] as const;

/** The brake on a source. */
export const SUSPEND_OPERATION = 'funding-sources.suspend';
/** Asking to reactivate one: its operation, which the step-up challenge names as its action too. */
export const REACTIVATE_OPERATION = 'funding-sources.reactivate';
/** Reactivating it, once stepped up. */
export const REACTIVATE_CONFIRM_OPERATION = 'funding-sources.reactivate.confirm';

/** Who may press the brake: the admins, and the finance approvers who answer for the money (ADR-012 §5). */
export const SUSPENDING_ROLES = ['admin', 'approver'] as const;
/** Who may give a source its authority back: an admin (ADR-003 §8). */
export const REACTIVATING_ROLES = ['admin'] as const;

/** A member acting in a session of theirs, which a step-up challenge is bound to. */
export interface SessionMember extends FundingSourceMember {
  readonly sessionId: string;
}

export type SourceChangeWrite =
  | { readonly outcome: 'changed'; readonly source: SourceRecord }
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
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
  suspend(
    member: FundingSourceMember,
    idempotent: IdempotentRequest,
    sourceId: string,
    correlationId: string,
  ): Promise<SourceChangeWrite>;
  reactivate(
    member: SessionMember,
    idempotent: IdempotentRequest,
    sourceId: string,
    correlationId: string,
  ): Promise<SourceChangeWrite>;
  reactivateConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    sourceId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<SourceChangeWrite>;
}

/**
 * The pending change's SHA-256: the event that suspended the source, its ID in
 * lower case. That event is the source's own, read from its signed state
 * inside the organisation's walls, so it names the organisation, the source
 * and exactly this suspension.
 */
const reactivationHash = (suspendedBy: string): Buffer =>
  changeHashOf([REACTIVATE_OPERATION, suspendedBy.toLowerCase()]);

export function createFundingSourceChanges({
  database,
  keys,
  ids,
  rail,
  challenges,
  logger,
}: {
  readonly database: Database<FundingSourceTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** The partner, or undefined where none is set up (config.partner): then a refresh answers PARTNER_UNAVAILABLE. */
  readonly rail: FinancialRailAdapter | undefined;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): FundingSourceChanges {
  const work = createFundingSourceWork({ database, keys, ids, logger });

  /** A suspended source, and the event that suspended it: SOURCE_NOT_SUSPENDED for one active or ended. */
  const suspendedSource = async (tx: FundingSourceTx, states: SignedStates, orgId: string, sourceId: string) => {
    const read = await work.sourceIn(tx, states, { orgId, id: sourceId }, 'change');
    if (read.source.status !== 'SUSPENDED') throw new FundingSourceRefused(409, 'SOURCE_NOT_SUSPENDED');
    return { id: read.source.id, suspendedBy: read.state.eventId };
  };

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
        // An answer about another source or organisation is the partner's fault: believed in nothing, and told.
        if (
          asking.kind === 'found' &&
          (asking.source.externalRef !== source.externalRef ||
            asking.source.organizationId.toLowerCase() !== member.orgId.toLowerCase())
        ) {
          logger
            .child({ correlationId, orgId: member.orgId })
            .error('funding_sources.partner_answer_mismatch', { sourceId });
          return PARTNER_UNAVAILABLE;
        }
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

    async suspend(member, idempotent, sourceId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, SUSPENDING_ROLES);
        const key = { orgId: member.orgId, id: sourceId };
        const { source } = await work.sourceIn(tx, states, key, 'change');
        // Pressed twice, or on a source already ended: stopped already, and answered as it is.
        if (source.status === 'ACTIVE') {
          const moved = await states.changeStatus(tx, SOURCES, key, 'suspend', {
            actor: { type: 'user', id: member.userId },
            action: 'funding_source.suspended',
            details: {},
          });
          if (moved.outcome !== 'changed') throw new Error(`a source read as ACTIVE didn't suspend: ${moved.outcome}`);
        }
        return { status: 200, resourceId: source.id };
      });
      return answer(member.orgId, correlationId, done);
    },

    async reactivate(member, idempotent, sourceId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const source = await suspendedSource(tx, states, member.orgId, sourceId);
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: REACTIVATE_OPERATION,
          changeHash: reactivationHash(source.suspendedBy),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new FundingSourceRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async reactivateConfirm(member, idempotent, sourceId, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const source = await suspendedSource(tx, states, member.orgId, sourceId);
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: REACTIVATE_OPERATION,
            changeHash: reactivationHash(source.suspendedBy),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new FundingSourceRefused(403, 'STEP_UP_FAILED');
        const moved = await states.changeStatus(tx, SOURCES, { orgId: member.orgId, id: source.id }, 'reactivate', {
          actor: { type: 'user', id: member.userId },
          action: 'funding_source.reactivated',
          details: stepUpDetails(consumed),
        });
        if (moved.outcome !== 'changed') {
          throw new Error(`a source read as SUSPENDED didn't reactivate: ${moved.outcome}`);
        }
        return { status: 200, resourceId: source.id };
      });
      return answer(member.orgId, correlationId, done);
    },
  };
}
