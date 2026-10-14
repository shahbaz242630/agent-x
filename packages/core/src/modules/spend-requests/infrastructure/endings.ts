// A spend request ended before hand-off, its capacity and order given back
// (PRD §4.2; ADR-006 §6, §10–§11; BR-09; partner decisions 10, Phase 3's 6;
// Phase 2 D7, D8; Phase 3 B4a, C1): a request waiting for approval 72 hours
// from its decision is EXPIRED; one cancelled by a person, or by the agent
// that made it, before hand-off (waiting, approved or ready) is CANCELLED; one
// a person rejects while it waits is DENIED, with their reason; and one whose
// authority no longer stands (voidCauses) is DENIED, with its causes.
//
// In the caller's transaction (withSignedStates' for the organisation), in
// ADR-006's lock order: the request read for change and verified (level 8);
// an agent's own cancels counted under its cancel lock (8a); its reservation
// and order claim locked (11); then the move, signed, which
// takes the audit head (12); then the reservation and claim released, which
// 0040's `held_for_its_request` and 0039's `claim_guard` allow only once the
// request has ended. So no lock is taken after the head's.
//
// The 72 hours run from the decision's own event (`spend_request.decided`),
// whose time the audit chain seals: a request still waiting has signed no
// other since, so it is the verified read's own event. The row's `created_at`
// is unsealed, so it only picks the candidates (`requestsWaitingSince`): a
// request that claims to be older than it is is never expired early, and one
// moved later past the app is only left holding (money kept, never paid). The
// sealed time is the database's clock, `now` the app's: seconds apart at most,
// against 72 hours.
import { holdTransactionLock } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Transaction } from 'kysely';

import {
  actorEventsSince,
  type AuditDetails,
  type AuditTables,
  type SignedChange,
  type SignedStates,
  type TamperSign,
} from '../../audit/index.ts';
import {
  type LimitReservationsTables,
  lockReservationsOf,
  releaseReservationsOf,
} from '../../limit-reservations/index.ts';
import { DAY_MS, movedAsRead, type ReasonCode } from '../../../shared-kernel/index.ts';
import { SPEND_REQUEST } from '../domain/spend-request.ts';
import { type AuthorityNow, PENDING_STATUSES, voidCauses } from '../domain/voids.ts';
import { decidedAgainst, requestOf, type SpendRequestRecord } from './decisions.ts';
import { requestHoldingsWhole } from './holdings-check.ts';
import { lockClaimsOf, releaseClaim } from './order-claims.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type EndingsTransaction = Transaction<SpendRequestsTables & AuditTables & LimitReservationsTables>;

/** How long a request waits for approval before it expires (partner decision 10; a constant for the Pilot). */
export const WAITS_FOR_APPROVAL_MS = 72 * 3_600_000;

/** Whether a request decided at `decidedAt` (its decision's sealed time) has waited for approval as long as it may. */
export const waitedOut = (decidedAt: Date, now: Date): boolean =>
  decidedAt.getTime() + WAITS_FOR_APPROVAL_MS <= now.getTime();

/**
 * How many of its own requests an agent may cancel in 24 hours (partner
 * decision 11b): enough for real changes of plan, too few to map its approval
 * line by asking and cancelling. A person's cancels never count.
 */
const MOST_AGENT_CANCELS_A_DAY = 10;

const ACTOR = { type: 'system', id: 'api' } as const;

/**
 * What came of ending a request: ended, its holdings released; already moved
 * on, as it stands; not yet due; its agent's cancels for the day spent; or not
 * to be believed.
 */
export type Ended =
  | { readonly outcome: 'ended'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'not_open'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'spent' }
  | { readonly outcome: 'not_due' }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The IDs of the organisation's requests waiting for approval since `before`
 * or earlier by their rows, in order of ID, after `after` when given, at most
 * `most` (0042's index): each to be read through its signed state and judged
 * by its decision's sealed time. The job pages on past the last, so requests
 * refused on every run can't fill a page and keep the others from expiring.
 */
export async function requestsWaitingSince(
  tx: Transaction<SpendRequestsTables>,
  orgId: string,
  before: Date,
  most: number,
  after?: string,
): Promise<readonly string[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state by expireRequest before it moves anything
    .selectFrom(SPEND_REQUESTS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('status', '=', 'APPROVAL_REQUIRED')
    .where('created_at', '<=', before)
    .where((where) => (after === undefined ? where.lit(true) : where('id', '>', after)))
    .orderBy('id')
    .limit(most)
    .execute();
  return rows.map(({ id }) => id);
}

/**
 * Expires the request if it is still waiting for approval and its decision
 * was made WAITS_FOR_APPROVAL_MS or more before `now`, releasing its
 * reservation and order claim, recorded as the API's.
 */
export async function expireRequest(
  tx: EndingsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  key: { readonly orgId: string; readonly id: string },
  now: Date,
): Promise<Ended> {
  const read = await requestOf(tx, states, key, 'change');
  if (read.outcome !== 'found') return read;
  if (read.request.status !== 'APPROVAL_REQUIRED') return { outcome: 'not_open', request: read.request };
  // Still waiting, its latest signed event is its decision: the chain seals when that was recorded.
  const decided = read.state.recordedAt;
  if (!waitedOut(decided, now)) return { outcome: 'not_due' };
  await endHolding(tx, states, keys, key, 'expire', now, {
    actor: ACTOR,
    action: 'spend_request.expired',
    details: { decidedAt: decided.toISOString() },
  });
  return { outcome: 'ended', request: { ...read.request, status: 'EXPIRED' } };
}

/**
 * Who cancels (PRD §7.2): a person (the API checks their role), or the agent
 * that made the request, with the key it came with (kept as evidence, as the
 * request's own is).
 */
export type Canceller =
  | { readonly kind: 'user'; readonly userId: string }
  | { readonly kind: 'agent'; readonly agentId: string; readonly agentKeyId: string };

/**
 * Cancels the request if it hasn't ended or been handed off (SPEND_REQUEST's
 * `cancel`: waiting, approved or ready), releasing its reservation and order
 * claim, recorded as the canceller's. An agent's own requests alone: another
 * agent's is answered as none; and MOST_AGENT_CANCELS_A_DAY of them (`spent`).
 * Already cancelled, or ended otherwise, it is answered as it stands
 * (`not_open`), counting nothing.
 */
export async function cancelRequest(
  tx: EndingsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  key: { readonly orgId: string; readonly id: string },
  by: Canceller,
  now: Date,
): Promise<Ended> {
  const read = await requestOf(tx, states, key, 'change');
  if (read.outcome !== 'found') return read;
  if (by.kind === 'agent' && read.request.agentId !== by.agentId) return { outcome: 'missing' };
  if (!SPEND_REQUEST.transition(read.request.status, 'cancel').ok)
    return { outcome: 'not_open', request: read.request };
  const actor =
    by.kind === 'user' ? ({ type: 'user', id: by.userId } as const) : ({ type: 'agent', id: by.agentId } as const);
  if (by.kind === 'agent') {
    // Counted from the agent's own signed cancels (0044), under the agent's cancel lock (ADR-006 §6, 8a: after
    // its request, before its holdings), so its other cancel in flight commits or rolls back before this counts.
    await holdTransactionLock(tx, 'agent-cancels', key.orgId, by.agentId);
    const since = new Date(now.getTime() - DAY_MS);
    if ((await actorEventsSince(tx, key.orgId, actor, 'spend_request.cancelled', since)) >= MOST_AGENT_CANCELS_A_DAY)
      return { outcome: 'spent' };
  }
  await endHolding(tx, states, keys, key, 'cancel', now, {
    actor,
    action: 'spend_request.cancelled',
    details: by.kind === 'agent' ? { agentKeyId: by.agentKeyId } : {},
  });
  return { outcome: 'ended', request: { ...read.request, status: 'CANCELLED' } };
}

/** The agent, mandate, source and supplier a request names, as its row named them to the caller who read them. */
export interface SubjectsNamed {
  readonly agentId: string;
  readonly mandateId: string | null;
  readonly fundingSourceId: string;
  readonly supplierId: string;
}

/** What came of voiding a request: void, its holdings released; still standing; or as an ending's. */
export type Voided =
  | { readonly outcome: 'voided'; readonly request: SpendRequestRecord; readonly causes: readonly ReasonCode[] }
  | { readonly outcome: 'standing' }
  | Extract<Ended, { readonly outcome: 'not_open' | 'missing' | 'tampered' }>;

/**
 * Denies the request if it is still pending (waiting, approved or ready) and
 * the authority it was decided under no longer stands (voidCauses), releasing
 * its reservation and order claim, recorded as the API's with the causes
 * (`spend_request.voided`). `authority`: its agent, mandate, source and
 * supplier as they now stand, read by the caller through their signed states
 * before this, in ADR-006's order (levels 3–6); `named`, the IDs it read them
 * by, which must be the request's own.
 */
export async function voidRequest(
  tx: EndingsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  key: { readonly orgId: string; readonly id: string },
  { named, authority }: { readonly named: SubjectsNamed; readonly authority: AuthorityNow },
  now: Date,
): Promise<Voided> {
  const read = await requestOf(tx, states, key, 'change');
  if (read.outcome !== 'found') return read;
  const { request } = read;
  if (!(PENDING_STATUSES as readonly string[]).includes(request.status)) return { outcome: 'not_open', request };
  // The caller read them by the request's row, which its verified state has just vouched for, and a request's
  // agent, mandate, source and supplier never change: another's is a bug.
  if (
    request.agentId !== named.agentId ||
    request.mandateId !== named.mandateId ||
    request.fundingSourceId !== named.fundingSourceId ||
    request.supplierId !== named.supplierId
  ) {
    throw new Error(`A spend request was judged by another's authority: ${key.id}`);
  }
  const against = decidedAgainst(read.state);
  const causes = voidCauses({ mandateId: request.mandateId, ...against }, authority);
  if (causes.length === 0) return { outcome: 'standing' };
  await endHolding(tx, states, keys, key, 'deny', now, {
    actor: ACTOR,
    action: 'spend_request.voided',
    details: { causes: causes.join(',') },
  });
  return { outcome: 'voided', request: { ...request, status: 'DENIED' }, causes };
}

const REJECTED = 'spend_request.rejected';

/** A person's reject (partner decisions 1 and 6): who, why, and the step-up they proved it with. */
export interface Rejection {
  readonly userId: string;
  /** As rejectReason keeps it. */
  readonly reason: string;
  readonly stepUp: AuditDetails;
}

/**
 * Rejects the request, read for change in this transaction while it waits
 * for approval: DENIED, its reservation and order claim released, recorded
 * as the person's with their step-up and reason (`spend_request.rejected`).
 * The reason goes in the event alone, never in `reason_codes`: those are the
 * decision's (0039).
 */
export async function rejectRequest(
  tx: EndingsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  key: { readonly orgId: string; readonly id: string },
  rejection: Rejection,
  now: Date,
): Promise<void> {
  await endHolding(tx, states, keys, key, 'deny', now, {
    actor: { type: 'user', id: rejection.userId },
    action: REJECTED,
    details: { ...rejection.stepUp, reason: rejection.reason },
  });
}

/** How a request was rejected, as its signed event says: by whom, when, and why. */
export interface RejectionShown {
  readonly byUserId: string;
  readonly at: Date;
  readonly reason: string;
}

/**
 * The request's reject, from its event in the log, each believed only whole
 * (historyOf): none for one never rejected (a DENIED request is final, so
 * at most one); tampered with, the alarm raised.
 */
export async function rejectionOf(
  tx: Transaction<AuditTables>,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
): Promise<
  | { readonly outcome: 'rejected'; readonly rejection: RejectionShown }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'tampered' }
> {
  const history = await states.historyOf(tx, key.orgId, {
    subjectTypes: [SPEND_REQUESTS.subject],
    subjectId: key.id,
    actions: [REJECTED],
    limit: 1,
  });
  if (history.outcome !== 'read') return { outcome: 'tampered' };
  const [found] = history.events;
  if (found === undefined) return { outcome: 'none' };
  const { actor, details } = found.event;
  // Only rejectRequest records it, whole under the chain's MAC: a person's, with their reason as text.
  return {
    outcome: 'rejected',
    rejection: { byUserId: actor.id, at: found.recordedAt, reason: String(details.reason) },
  };
}

/**
 * The move and its release, in lock order: the reservation and claim locked
 * (11), the request moved and signed (the head, 12), then both released. The
 * request was read for change in this transaction and may make the move.
 * Its reservation and claim are first judged as the holdings check judges
 * them, once locked: one changed past the app (released, deleted, or its
 * amount, month or payee moved) raises the alarm, and the request still ends
 * (a brake), rather than its ending hiding the change from the holdings check.
 */
async function endHolding(
  tx: EndingsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  key: { readonly orgId: string; readonly id: string },
  event: 'expire' | 'cancel' | 'deny',
  at: Date,
  change: SignedChange,
): Promise<void> {
  await lockReservationsOf(tx, key.id);
  await lockClaimsOf(tx, key.id);
  // A mismatch is alarmed by the judging itself.
  await requestHoldingsWhole(tx, states, keys, key.orgId, key.id);
  const moved = await states.changeStatus(tx, SPEND_REQUESTS, key, event, change);
  movedAsRead(moved, `A spend request read as open didn't ${event}`);
  await releaseReservationsOf(tx, { requestId: key.id, at });
  await releaseClaim(tx, { requestId: key.id, releasedAt: at });
}
