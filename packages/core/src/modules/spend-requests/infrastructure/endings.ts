// A spend request ended before hand-off, its capacity and order given back
// (PRD §4.2; ADR-006 §6, §10–§11; BR-09; partner decisions 10, Phase 3's 6;
// Phase 2 D7, D8; Phase 3 B4a, C1): a request waiting for approval 72 hours
// from its decision is EXPIRED; one cancelled by a person, or by the agent
// that made it, before hand-off (waiting, approved or ready) is CANCELLED; one
// a person rejects while it waits is DENIED, with their reason; and one whose
// authority no longer stands (voidCauses) is DENIED, with its causes, by the
// job one at a time (voidRequest), or by the brake that stops it, a batch in
// the brake's own transaction (voidPendingOf, C2).
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
import { DAY_MS, isReasonCode, movedAsRead, type ReasonCode } from '../../../shared-kernel/index.ts';
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

const REJECTED = 'spend_request.rejected';
/** A request's void, by the job or a brake: the API's, with its causes. */
const VOIDED = 'spend_request.voided';

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
 * (`spend_request.voided`). `authority`: its organisation, agent, mandate,
 * source and supplier as they now stand, read by the caller through their
 * signed states before this, in ADR-006's order (levels 2–6); `named`, the
 * IDs it read them
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
    action: VOIDED,
    details: { causes: causes.join(',') },
  });
  return { outcome: 'voided', request: { ...request, status: 'DENIED' }, causes };
}

/**
 * How many pending requests a brake voids in its own transaction: the rest
 * are left to the request-voids job (5 minutes), meanwhile unable to be
 * approved or handed off under the stop. Kept small so the brake is quick:
 * each void is a dozen statements, made while the brake holds what it stops.
 */
const MOST_VOIDED_BY_A_BRAKE = 20;

/**
 * What a brake stops: the organisation (its freeze; D1), an agent (its
 * suspend), a mandate (its suspend, revoke, expiry or supersede), a funding
 * source (its suspend) or a supplier (its suspend, or its new details or
 * payee made current; C3).
 */
type Braked =
  | { readonly organizationId: string }
  | { readonly agentId: string }
  | { readonly mandateId: string }
  | { readonly fundingSourceId: string }
  | { readonly supplierId: string };

/** The request's column naming what a brake stops, and its ID. */
function brakedColumn(braked: Braked) {
  if ('organizationId' in braked) return { column: 'org_id', id: braked.organizationId } as const;
  if ('agentId' in braked) return { column: 'agent_id', id: braked.agentId } as const;
  if ('mandateId' in braked) return { column: 'mandate_id', id: braked.mandateId } as const;
  if ('fundingSourceId' in braked) return { column: 'funding_source_id', id: braked.fundingSourceId } as const;
  return { column: 'supplier_id', id: braked.supplierId } as const;
}

/**
 * A brake's own cascade (PRD §4.2; ADR-006 §6 "Cascades"; Phase 3 C2): the
 * pending requests (waiting, approved or ready) of what it stops DENIED, with
 * `cause`, their reservations and order claims released, recorded as the
 * API's (`spend_request.voided`, as voidRequest records it). The caller holds
 * what it stops for change and calls this before its own signed move: the
 * requests, at most `most` of them, are found and locked in one statement in
 * order of ID after that lock (8), each verified, then all their holdings
 * locked in one statement each (11), and only then is each moved (the head,
 * 12). A request whose signed state can't be believed (its alarm raised) is
 * left as it is: the brake still holds. How many were voided.
 */
export async function voidPendingOf(
  tx: EndingsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  braked: Braked,
  cause: ReasonCode,
  now: Date,
  most = MOST_VOIDED_BY_A_BRAKE,
): Promise<number> {
  const { column, id: brakedId } = brakedColumn(braked);
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the batch's IDs, locked; each verified below before it moves
    .selectFrom(SPEND_REQUESTS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('status', 'in', PENDING_STATUSES)
    .where(column, '=', brakedId)
    .orderBy('id')
    .limit(most)
    .forNoKeyUpdate()
    .execute();
  const pending: string[] = [];
  for (const { id } of rows) {
    // Locked as pending, so one found is pending: its verified state is its row's.
    if ((await requestOf(tx, states, { orgId, id }, 'change')).outcome === 'found') pending.push(id);
  }
  if (pending.length === 0) return 0;
  await lockReservationsOf(tx, pending);
  await lockClaimsOf(tx, pending);
  for (const id of pending) {
    await endHolding(tx, states, keys, { orgId, id }, 'deny', now, {
      actor: ACTOR,
      action: VOIDED,
      details: { causes: cause },
    });
  }
  return pending.length;
}

/**
 * Whether more of what a brake stops are pending than voidPendingOf voids
 * at once (a supplier's fresh start back VERIFIED, Phase 3 decision 9,
 * which leaves none for the request-voids job), by their rows alone: a
 * request tampered with counts too.
 */
export async function pendingPastABrake(tx: EndingsTransaction, orgId: string, braked: Braked): Promise<boolean> {
  const { column, id } = brakedColumn(braked);
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone; nothing moves on it
    .selectFrom(SPEND_REQUESTS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('status', 'in', PENDING_STATUSES)
    .where(column, '=', id)
    .limit(MOST_VOIDED_BY_A_BRAKE + 1)
    .execute();
  return rows.length > MOST_VOIDED_BY_A_BRAKE;
}

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

/** How a request was voided, as its signed event says: when, and why (C1, C2). */
export interface VoidingShown {
  readonly at: Date;
  readonly causes: readonly ReasonCode[];
}

/**
 * Why a DENIED request ended after its decision, from its event in the log,
 * each believed only whole (historyOf): a person's reject, or a void; none
 * for one denied by its decision (a DENIED request is final, so at most one
 * of them); tampered with, the alarm raised.
 */
export async function denialOf(
  tx: Transaction<AuditTables>,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
): Promise<
  | { readonly outcome: 'rejected'; readonly rejection: RejectionShown }
  | { readonly outcome: 'voided'; readonly voiding: VoidingShown }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'tampered' }
> {
  const history = await states.historyOf(tx, key.orgId, {
    subjectTypes: [SPEND_REQUESTS.subject],
    subjectId: key.id,
    actions: [REJECTED, VOIDED],
    limit: 1,
  });
  if (history.outcome !== 'read') return { outcome: 'tampered' };
  const [found] = history.events;
  if (found === undefined) return { outcome: 'none' };
  const { actor, action, details } = found.event;
  if (action === VOIDED) {
    // Only voidRequest and voidPendingOf record it, whole under the chain's MAC: registered codes, comma-joined.
    const causes = String(details.causes).split(',').filter(isReasonCode);
    return { outcome: 'voided', voiding: { at: found.recordedAt, causes } };
  }
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
  await lockReservationsOf(tx, [key.id]);
  await lockClaimsOf(tx, [key.id]);
  // A mismatch is alarmed by the judging itself.
  await requestHoldingsWhole(tx, states, keys, key.orgId, key.id);
  const moved = await states.changeStatus(tx, SPEND_REQUESTS, key, event, change);
  movedAsRead(moved, `A spend request read as open didn't ${event}`);
  await releaseReservationsOf(tx, { requestId: key.id, at });
  await releaseClaim(tx, { requestId: key.id, releasedAt: at });
}
