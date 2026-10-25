// An admin marks an UNKNOWN payment failed, once their bank has confirmed in
// writing that it never accepted it (ADR-007 §10; partner decision 38, S144,
// replacing decision 35: a payment's follow-up is between the customer and
// their bank, never our team's; Rule Book §1.9, §1.10). Its held money and
// its order are given back, so the invoice could be paid again: a double
// payment is the customer's own risk to judge, so the admin confirms that in
// plain words, proved with a passkey, and every admin is told. Core's
// `markFailed` does the move.
//
// - The ask (`payments.mark-failed`), an admin, with the bank's evidence
//   reference and the statement confirmed: the admin read again; the payment,
//   UNKNOWN and handed off over a day ago (PAYMENT_NOT_UNKNOWN,
//   PAYMENT_TOO_RECENT, both 409); a challenge bound to the organisation, the
//   payment's latest signed event and the reference, so the passkey marks this
//   payment, as it stood when asked, on this evidence alone; answered 202.
// - The confirm (`….confirm`): the same reads, the payment for change, so the
//   bank check settling it at once is waited for and then refuses the mark;
//   the challenge consumed; then the mark, its event naming the reference, the
//   statement's version and the step-up's evidence, in the same transaction.
// - Allowed while the organisation is frozen (as a reject, decision 3): a mark
//   only gives capacity back, so the organisation isn't read. None of the
//   organisation's is NOT_FOUND; one tampered with is INTEGRITY_FAILED.
//
// Lock order (ADR-006 §6): the idempotency key, the session's challenges (0b,
// confirm only), the admin's membership (2a), the payment (10), the challenge
// consumed, its holdings (11), the chain head (12), then the notice.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { InstructionsTables } from '@agentx/core/modules/instructions';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { MARK_FAILED_AFTER_MS, markFailed } from '@agentx/core/modules/outcomes';
import type { SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { transactionOf, type TransactionsTables } from '@agentx/core/modules/transactions';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import type { Refused } from './refused.ts';
import {
  createStepUps,
  createUseCaseWork,
  type SessionMember,
  UseCaseRefused,
  type UseCaseTables,
} from './use-case-work.ts';

export const MARK_FAILED_OPERATION = 'payments.mark-failed';
export const MARK_FAILED_CONFIRM_OPERATION = 'payments.mark-failed.confirm';

/** Who may mark a payment failed (decision 38): the customer's admins. */
export const MARKING_ROLES = ['admin'] as const;

/** The bank's reference for its written statement, as the operator's case references were: 3 to 64 of these. */
export const EVIDENCE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$/;

/** The consequence the admin confirms, in the words the console shows (Rule Book §1.9). */
export const MARK_FAILED_STATEMENT =
  'Marking this payment failed frees its amount against your limits and frees its invoice, so the invoice can be ' +
  'paid again. Do this only once your bank has confirmed in writing that the money never left your account: if the ' +
  'bank paid it after all, the invoice could be paid twice.';

/** The version of MARK_FAILED_STATEMENT each mark names: raised with any change to its words. */
export const MARK_FAILED_STATEMENT_VERSION = 1;

/** The choice the request makes explicit, confirming the statement. */
export const MARK_FAILED_CONFIRMED = 'invoice_can_be_paid_again';

type MarkTables = UseCaseTables &
  TransactionsTables &
  InstructionsTables &
  LimitReservationsTables &
  SpendRequestsTables &
  NotificationsTables;

export type MarkAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type Marked =
  | { readonly outcome: 'marked'; readonly paymentId: string }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface PaymentMarks {
  /** `evidenceRef` as EVIDENCE_REFERENCE takes it: the route has checked it. */
  ask(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    evidenceRef: string,
    correlationId: string,
  ): Promise<MarkAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    confirm: { readonly evidenceRef: string; readonly stepUpChallengeId: string },
    correlationId: string,
  ): Promise<Marked>;
}

/** Refused inside a mark's write, so its transaction ends there. */
class MarkRefused extends UseCaseRefused {}

/**
 * The mark's SHA-256: the organisation, the payment's latest event, IDs in
 * lower case, and the evidence reference. That event is the payment's own,
 * read from its signed state, so a move since (the bank check's) makes the
 * step-up another's.
 */
const markHash = (orgId: string, paymentEvent: string, evidenceRef: string): Buffer =>
  changeHashOf([MARK_FAILED_OPERATION, orgId.toLowerCase(), paymentEvent.toLowerCase(), evidenceRef]);

/** The payment read (`share` or `change`) and verified: refused unless the organisation's, UNKNOWN, over a day old. */
async function markable(
  tx: DatabaseTransaction<MarkTables>,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
  now: Date,
) {
  const read = await transactionOf(tx, states, key, lock);
  if (read.outcome === 'missing') throw new MarkRefused(404, 'NOT_FOUND');
  if (read.outcome === 'tampered') throw new MarkRefused(503, 'INTEGRITY_FAILED');
  if (read.transaction.status !== 'UNKNOWN') throw new MarkRefused(409, 'PAYMENT_NOT_UNKNOWN');
  if (now.getTime() - read.transaction.createdAt.getTime() <= MARK_FAILED_AFTER_MS) {
    throw new MarkRefused(409, 'PAYMENT_TOO_RECENT');
  }
  return read;
}

export function createPaymentMarks({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Database<MarkTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): PaymentMarks {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MarkRefused });
  const stepUps = createStepUps({ challenges, Refusal: MarkRefused });

  return {
    async ask(member, idempotent, paymentId, evidenceRef, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, MARKING_ROLES);
        const read = await markable(tx, states, { orgId: member.orgId, id: paymentId }, 'share', clock.now());
        return stepUps.ask(tx, member, {
          action: MARK_FAILED_OPERATION,
          changeHash: markHash(member.orgId, read.state.eventId, evidenceRef),
        });
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, paymentId, { evidenceRef, stepUpChallengeId }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        await work.memberIn(tx, states, member, MARKING_ROLES);
        const key = { orgId: member.orgId, id: paymentId };
        const read = await markable(tx, states, key, 'change', clock.now());
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: MARK_FAILED_OPERATION, changeHash: markHash(member.orgId, read.state.eventId, evidenceRef) },
          { passkeyRequired: true },
        );
        await markFailed(tx, states, outbox, {
          orgId: member.orgId,
          transactionId: read.transaction.id,
          userId: member.userId,
          details: {
            evidenceRef,
            confirmed: MARK_FAILED_CONFIRMED,
            statementVersion: String(MARK_FAILED_STATEMENT_VERSION),
            ...stepUpDetails(consumed),
          },
          at: clock.now(),
        });
        return { status: 200, resourceId: read.transaction.id };
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'marked', paymentId: done.result.resourceId };
    },
  };
}
