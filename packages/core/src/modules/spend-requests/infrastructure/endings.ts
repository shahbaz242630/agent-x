// A spend request ended before hand-off, its capacity and order given back
// (PRD §4.2; ADR-006 §6, §10–§11; BR-09; partner decision 10; Phase 2 D7):
// a request waiting for approval 72 hours from its decision is EXPIRED.
//
// In the caller's transaction (withSignedStates' for the organisation), in
// ADR-006's lock order: the request read for change and verified (level 8);
// its reservation and order claim locked (11); then the move, signed, which
// takes the audit head (12); then the reservation and claim released, which
// 0040's `held_for_its_request` and 0039's `claim_guard` allow only once the
// request has ended. So no lock is taken after the head's.
//
// The 72 hours run from the decision's own event (`spend_request.decided`),
// whose time the audit chain seals: a request still waiting has signed no
// other since, so it is the verified read's own event. The row's `created_at`
// is unsealed, so it only picks the candidates (`requestsWaitingSince`), and a
// request that claims to be older than it is is never expired early.
import type { Transaction } from 'kysely';

import type { AuditTables, SignedChange, SignedStates, TamperSign } from '../../audit/index.ts';
import {
  type LimitReservationsTables,
  lockReservationsOf,
  releaseReservationsOf,
} from '../../limit-reservations/index.ts';
import { movedAsRead } from '../../../shared-kernel/index.ts';
import { requestOf, type SpendRequestRecord } from './decisions.ts';
import { lockClaimsOf, releaseClaim } from './order-claims.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type EndingsTransaction = Transaction<SpendRequestsTables & AuditTables & LimitReservationsTables>;

/** How long a request waits for approval before it expires (partner decision 10; a constant for the Pilot). */
export const WAITS_FOR_APPROVAL_MS = 72 * 3_600_000;

const ACTOR = { type: 'system', id: 'api' } as const;

/** What came of ending a request: ended, its holdings released; already moved on; not yet due; or not to be believed. */
export type Ended =
  | { readonly outcome: 'ended'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'not_open'; readonly status: SpendRequestRecord['status'] }
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
  key: { readonly orgId: string; readonly id: string },
  now: Date,
): Promise<Ended> {
  const read = await requestOf(tx, states, key, 'change');
  if (read.outcome !== 'found') return read;
  if (read.request.status !== 'APPROVAL_REQUIRED') return { outcome: 'not_open', status: read.request.status };
  // Still waiting, its latest signed event is its decision: the chain seals when that was recorded.
  const decided = read.state.recordedAt;
  if (decided.getTime() + WAITS_FOR_APPROVAL_MS > now.getTime()) return { outcome: 'not_due' };
  await endHolding(tx, states, key, 'expire', now, {
    actor: ACTOR,
    action: 'spend_request.expired',
    details: { decidedAt: decided.toISOString() },
  });
  return { outcome: 'ended', request: { ...read.request, status: 'EXPIRED' } };
}

/**
 * The move and its release, in lock order: the reservation and claim locked
 * (11), the request moved and signed (the head, 12), then both released. The
 * request was read for change in this transaction and may make the move.
 */
async function endHolding(
  tx: EndingsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  event: 'expire',
  at: Date,
  change: SignedChange,
): Promise<void> {
  await lockReservationsOf(tx, key.id);
  await lockClaimsOf(tx, key.id);
  const moved = await states.changeStatus(tx, SPEND_REQUESTS, key, event, change);
  movedAsRead(moved, `A spend request read as open didn't ${event}`);
  await releaseReservationsOf(tx, { requestId: key.id, at });
  await releaseClaim(tx, { requestId: key.id, releasedAt: at });
}
