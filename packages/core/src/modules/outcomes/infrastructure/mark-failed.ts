// Phase 4 E1c: Agent X's own team marks a payment failed, once the bank has
// confirmed in writing that it never accepted it (ADR-007 §10; partner
// decision, S141: our team only, never the customer's admin, as the bank's
// statement comes to us), through the operator's command
// (apps/operator `mark-payment-failed`). The bank check (E1a) leaves a payment
// UNKNOWN when the bank's answer proves nothing either way; this is how one
// leaves it without the bank's own status query.
//
// One transaction, withSignedStates' for the organisation, in ADR-006 §6's
// lock order: the organisation verified; the payment read for change (10), an
// earlier run of the same request found (its move's ID); the payment refused
// unless it is UNKNOWN and was handed off more than MARK_FAILED_AFTER_MS
// ago (the bank's longest time to settle, until the partner's answer to STA-4);
// its request's holdings locked (11); `transaction.fail` on its chain (12,
// the operator its actor, its ID the request's, naming the case reference and
// the bank's evidence reference); its held money and its order given back
// (`settlePayment`); a notice to every admin (0064); and
// `operator.payment_marked_failed` on the platform chain, locked last (13).
// All of it, or none. The bank check keeps checking it for 7 days, as it does
// a paid one, so the bank paying it after all is said (E1a's contradiction).
// The payment is read twice, here and by `lockPayment`, under the same lock:
// once for the refusals named here, once for the settling every move shares.
//
// The request's ID is made where it was written, so a request run again finds
// its own event and changes nothing. The case reference and the evidence
// reference are sealed on both chains, never logged.
import type { Database } from '@agentx/platform/db';

import { type AuditTables, type SignedStatesServices, withSignedStates } from '../../audit/index.ts';
import type { InstructionsTables } from '../../instructions/index.ts';
import type { LimitReservationsTables } from '../../limit-reservations/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { ORGANIZATIONS, type OrganizationsTables } from '../../organizations/index.ts';
import {
  createPlatformChain,
  type PlatformActor,
  type PlatformControlsTables,
  platformEventWith,
} from '../../platform-controls/index.ts';
import type { SpendRequestsTables } from '../../spend-requests/index.ts';
import { moveTransaction, transactionOf, type TransactionsTables } from '../../transactions/index.ts';
import { type Clock, type IdGenerator, uuidV7Ids } from '../../../shared-kernel/index.ts';
import { lockPayment, NO_FACTS, settlePayment } from './payment-outcome.ts';

/** Every table the change reaches: the payment, its holdings, both chains and the admins' notice. */
export type MarkFailedTables = AuditTables &
  OrganizationsTables &
  PlatformControlsTables &
  NotificationsTables &
  TransactionsTables &
  InstructionsTables &
  LimitReservationsTables &
  SpendRequestsTables;

/** How long after its hand-off a payment may be marked failed: past the bank's longest time to settle one. */
export const MARK_FAILED_AFTER_MS = 24 * 60 * 60_000;

/** The platform's own record of it, naming the organisation, the payment and the request. */
export const PLATFORM_MARKED_FAILED = 'operator.payment_marked_failed';

/** The organisation's record of it: the payment's own move. */
const MARKED_FAILED = 'transaction.fail';

/** A payment to mark failed, as its request asks it. */
export interface MarkFailedRequest {
  /** Agent X's own team, as the operator's command names itself on both chains. */
  readonly actor: PlatformActor;
  readonly orgId: string;
  readonly transactionId: string;
  /** A case reference: sealed on both chains, never logged. */
  readonly reason: string;
  /** The bank's reference for its written statement that it never accepted the payment: sealed, never logged. */
  readonly evidence: string;
  /** The request's ID, made where it was written: its event's on the organisation's chain. */
  readonly id: string;
  readonly release: string;
  readonly run: string | null;
}

/** Why a payment can't be marked failed, never naming either reference. */
export class MarkFailedRefused extends Error {
  readonly problems: readonly string[];

  constructor(problem: string) {
    super(`Marking the payment failed refused: ${problem}`);
    this.name = 'MarkFailedRefused';
    this.problems = [problem];
  }
}

/** What the request came to: the payment marked failed now, or by an earlier run of the same request. */
export type MarkedFailed =
  { readonly outcome: 'marked'; readonly platformSeq: bigint } | { readonly outcome: 'marked_before' };

/** Refused for a request ID that names any other record. */
const ANOTHER_RECORD = 'the ID names another record: write a new request';

/**
 * IDs as the caller's, but the request's for the one taken while `armed`: the
 * payment's move, so a run again finds it. Every other event (an integrity
 * hold above all, recorded after the work rolls back) takes one of its own.
 */
function requestIdOnce(ids: IdGenerator, id: string) {
  let armed = false;
  return {
    ids: {
      next: () => {
        if (!armed) return ids.next();
        armed = false;
        return id;
      },
    } satisfies IdGenerator,
    arm: () => {
      armed = true;
    },
  };
}

/** Marks the payment failed, or finds an earlier run's mark; throws MarkFailedRefused for one it may not. */
export function markPaymentFailed(
  database: Database<MarkFailedTables>,
  services: SignedStatesServices & { readonly clock: Clock },
  request: MarkFailedRequest,
): Promise<MarkedFailed> {
  const { actor, orgId, transactionId, reason, evidence, id, release, run } = request;
  const { clock } = services;
  const platform = createPlatformChain({ keys: services.keys, ids: services.ids });
  const outbox = createOutbox({ ids: uuidV7Ids, clock });
  const key = { orgId, id: transactionId };
  const moveIds = requestIdOnce(services.ids, id);
  return withSignedStates(
    database,
    orgId,
    { ...services, ids: moveIds.ids },
    async (tx, states): Promise<MarkedFailed> => {
      const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
      if (organization.outcome === 'missing') throw new MarkFailedRefused('no organisation has this ID');
      if (organization.outcome === 'tampered')
        throw new MarkFailedRefused("the organisation's records can't be verified");
      // Read for change first (10): a run of the same request at once waits here, then finds the first's move below.
      const read = await transactionOf(tx, states, key, 'change');
      if (read.outcome === 'missing') throw new MarkFailedRefused('no payment of this organisation has this ID');
      if (read.outcome === 'tampered') throw new MarkFailedRefused("the payment's records can't be verified");
      // Through the signed states: a record that can't be believed raises the alarm and the hold.
      const before = await states.eventOf(tx, orgId, { eventId: id });
      if (before.outcome === 'tampered') throw new MarkFailedRefused("the organisation's audit log can't be verified");
      if (before.event !== undefined) {
        const { event } = before.event;
        const same =
          event.action === MARKED_FAILED &&
          event.subject.id === transactionId &&
          event.actor.type === actor.type &&
          event.actor.id === actor.id;
        if (!same) throw new MarkFailedRefused(ANOTHER_RECORD);
        return { outcome: 'marked_before' };
      }
      // Another organisation's mark of this ID: one request ID names one mark.
      if (await platformEventWith(tx, PLATFORM_MARKED_FAILED, { requestId: id })) {
        throw new MarkFailedRefused(ANOTHER_RECORD);
      }
      const { status, createdAt } = read.transaction;
      if (status !== 'UNKNOWN') {
        throw new MarkFailedRefused(
          `the payment is ${status}: only one whose outcome can't be known (UNKNOWN) is marked failed`,
        );
      }
      if (clock.now().getTime() - createdAt.getTime() <= MARK_FAILED_AFTER_MS) {
        throw new MarkFailedRefused(
          'the payment was handed off less than 24 hours ago: the bank may still settle it, so wait past that',
        );
      }
      const locked = await lockPayment(tx, states, key);
      // Its one event, its status's change (no facts are new), takes the request's ID.
      moveIds.arm();
      const moved = await moveTransaction(tx, states, key, 'fail', NO_FACTS, {
        actor,
        details: { via: 'operator', reason, evidenceRef: evidence },
      });
      // Read for change under this lock, and UNKNOWN: anything but a move is something past the app.
      if (moved.outcome !== 'moved') throw new Error(`An UNKNOWN payment didn't move to FAILED: ${moved.outcome}`);
      await settlePayment(tx, outbox, {
        orgId,
        requestId: locked.instruction.spendRequestId,
        transactionId,
        status: 'FAILED',
        at: clock.now(),
      });
      await outbox.add(tx, [
        {
          orgId,
          recipientUserId: null,
          kind: 'payment_marked_failed',
          membershipId: null,
          role: null,
          aboutId: transactionId,
        },
      ]);
      const recorded = await platform.record(tx, {
        actor,
        action: PLATFORM_MARKED_FAILED,
        details: { orgId, transactionId, requestId: id, reason, evidenceRef: evidence, release, run },
      });
      return { outcome: 'marked', platformSeq: recorded.seq };
    },
  );
}
