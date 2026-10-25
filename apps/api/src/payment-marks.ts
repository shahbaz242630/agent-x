// Two admins mark an UNKNOWN payment failed, once their bank has confirmed in
// writing that it never accepted it (ADR-007 §10; partner decision 38, S144,
// replacing decision 35: a payment's follow-up is between the customer and
// their bank, never our team's; Rule Book §1.9, §1.10). Agent X can't check
// the bank's reference an admin types, so one admin proposes and a second
// confirms (the partner's S145 heads-up). Its held money and its order are
// given back, so the invoice could be paid again: a double payment is the
// customer's own risk to judge, so each admin confirms that in plain words,
// proved with a passkey, and every admin is told at each step.
//
// - Propose (`payments.failure-proposal`, then `….confirm`): an admin, with
//   the bank's evidence reference; the payment UNKNOWN and handed off over a
//   day ago (PAYMENT_NOT_UNKNOWN, PAYMENT_TOO_RECENT); none open for it
//   (FAILURE_PROPOSAL_OPEN). The payment stays as it is: the proposal is
//   made OPEN and signed, and `payment_mark_proposed` tells every admin.
// - Approve (`….approve`, then `….approve.confirm`): an admin who didn't
//   propose it (FAILURE_PROPOSAL_YOURS), unless the organisation has one
//   active admin only: then that admin, a day after proposing
//   (FAILURE_PROPOSAL_TOO_RECENT; never blocked, partner S113). The ask
//   answers the proposal, so the second admin sees the reference they
//   confirm. The confirm moves the proposal CONFIRMED and the payment FAILED
//   (core's `markFailed`), its event naming both admins, the reference, the
//   statement's version and the step-up's evidence.
// - Withdraw (`….withdraw`, then `….withdraw.confirm`): any admin, the
//   proposer among them; the payment as it stands; `payment_mark_withdrawn`.
// - None open is NO_FAILURE_PROPOSAL; a payment not the organisation's,
//   NOT_FOUND; one tampered with, INTEGRITY_FAILED. Allowed while the
//   organisation is frozen (as a reject, decision 3): nothing here spends.
// - Each step-up binds the organisation and where things stand when asked:
//   the payment's latest signed event (so the bank check's word since makes
//   it another's), the reference, and the proposal's latest event.
//
// Lock order (ADR-006 §6): the idempotency key, the session's challenges (0b,
// a confirm's), the admin's membership and, to approve, every admin's (2a),
// the payment (10), its proposal (10, after it), the challenge consumed, its
// holdings (11), the chain head (12), then the notice.
import type { SignedStates } from '@agentx/core/modules/audit';
import {
  changeHashOf,
  type StepUpChallenges,
  stepUpDetails,
  twoPersonFactsOf,
  type VerifierRefusal,
  verifierVerdict,
} from '@agentx/core/modules/identity';
import type { InstructionsTables } from '@agentx/core/modules/instructions';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { MARK_FAILED_AFTER_MS, markFailed } from '@agentx/core/modules/outcomes';
import type { SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import {
  type FailureProposalRecord,
  moveProposal,
  openProposalOf,
  proposalOf,
  proposeFailure,
  transactionOf,
  type TransactionsTables,
} from '@agentx/core/modules/transactions';
import type { Clock, IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
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

export const PROPOSE_OPERATION = 'payments.failure-proposal';
export const PROPOSE_CONFIRM_OPERATION = 'payments.failure-proposal.confirm';
export const APPROVE_OPERATION = 'payments.failure-proposal.approve';
export const APPROVE_CONFIRM_OPERATION = 'payments.failure-proposal.approve.confirm';
export const WITHDRAW_OPERATION = 'payments.failure-proposal.withdraw';
export const WITHDRAW_CONFIRM_OPERATION = 'payments.failure-proposal.withdraw.confirm';

/** Who may propose, approve or withdraw (decision 38): the customer's admins. */
export const MARKING_ROLES = ['admin'] as const;

/** The bank's reference for its written statement, as 0066 holds it: 3 to 64 of these. */
export const EVIDENCE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$/;

/** The consequence each admin confirms, in the words the console shows (Rule Book §1.9). */
export const MARK_FAILED_STATEMENT =
  'Marking this payment failed frees its amount against your limits and frees its invoice, so the invoice can be ' +
  'paid again. Do this only once your bank has confirmed in writing that the money never left your account: if the ' +
  'bank paid it after all, the invoice could be paid twice. A second admin must confirm it.';

/** The version of MARK_FAILED_STATEMENT each step names: raised with any change to its words. */
export const MARK_FAILED_STATEMENT_VERSION = 1;

/** The choice the request makes explicit, confirming the statement. */
export const MARK_FAILED_CONFIRMED = 'invoice_can_be_paid_again';

/** How long a lone admin waits after proposing before confirming their own proposal. */
export const LONE_ADMIN_WAIT_MS = 24 * 60 * 60_000;

type MarkTables = UseCaseTables &
  TransactionsTables &
  InstructionsTables &
  LimitReservationsTables &
  SpendRequestsTables &
  NotificationsTables;

type MarkTx = DatabaseTransaction<MarkTables>;

type Unwritten = { readonly outcome: 'conflict' } | { readonly outcome: 'busy' } | Refused;

type MarkAsked = { readonly outcome: 'asked'; readonly stepUpChallengeId: string } | Unwritten;
type ApproveAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string; readonly proposal: FailureProposalRecord }
  | Unwritten;
type Proposed = { readonly outcome: 'proposed'; readonly proposal: FailureProposalRecord } | Unwritten;
type Marked = { readonly outcome: 'marked'; readonly paymentId: string } | Unwritten;
type Withdrawn = { readonly outcome: 'withdrawn'; readonly proposal: FailureProposalRecord } | Unwritten;

export interface PaymentMarks {
  /** `evidenceRef` as EVIDENCE_REFERENCE takes it: the route has checked it. */
  propose(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    evidenceRef: string,
    correlationId: string,
  ): Promise<MarkAsked>;
  confirmProposal(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    confirm: { readonly evidenceRef: string; readonly stepUpChallengeId: string },
    correlationId: string,
  ): Promise<Proposed>;
  approve(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    correlationId: string,
  ): Promise<ApproveAsked>;
  confirmApproval(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<Marked>;
  withdraw(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    correlationId: string,
  ): Promise<MarkAsked>;
  confirmWithdrawal(
    member: SessionMember,
    idempotent: IdempotentRequest,
    paymentId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<Withdrawn>;
}

/** Each refusal of the confirming admin by the two-person rule, as answered. */
const CONFIRMER_REFUSALS: Readonly<Record<VerifierRefusal, readonly [number, ReasonCode]>> = {
  NOT_A_VERIFIER: [403, 'FORBIDDEN'],
  SAME_PERSON: [403, 'FAILURE_PROPOSAL_YOURS'],
  VERIFIER_GRANTED_BY_ENTERER: [403, 'FAILURE_PROPOSAL_GRANTED_BY_PROPOSER'],
  VERIFIER_TOO_NEW: [403, 'FAILURE_PROPOSAL_CONFIRMER_TOO_NEW'],
  SOLO_PATH_LOCKED: [409, 'FAILURE_PROPOSAL_ALONE_LOCKED'],
};

/** Refused inside a mark's write, so its transaction ends there. */
class MarkRefused extends UseCaseRefused {}

/** A step's SHA-256: its operation, the organisation, and where things stand, IDs in lower case. */
const hashOf = (operation: string, orgId: string, ...standing: readonly string[]): Buffer =>
  changeHashOf([operation, orgId.toLowerCase(), ...standing]);

/** The statement each confirming step keeps on its event, with the step-up's evidence. */
const confirmedDetails = () => ({
  confirmed: MARK_FAILED_CONFIRMED,
  statementVersion: String(MARK_FAILED_STATEMENT_VERSION),
});

/** The organisation's payment, read (`share` or `change`) and verified, as it stands: NOT_FOUND or INTEGRITY_FAILED otherwise. */
async function paymentIn(
  tx: MarkTx,
  states: SignedStates,
  key: { orgId: string; id: string },
  lock: 'share' | 'change',
) {
  const read = await transactionOf(tx, states, key, lock);
  if (read.outcome === 'missing') throw new MarkRefused(404, 'NOT_FOUND');
  if (read.outcome === 'tampered') throw new MarkRefused(503, 'INTEGRITY_FAILED');
  return read;
}

/** The payment, as `paymentIn` reads it, and markable: UNKNOWN, handed off over a day before `now`. */
async function markable(
  tx: MarkTx,
  states: SignedStates,
  key: { orgId: string; id: string },
  lock: 'share' | 'change',
  now: Date,
) {
  const read = await paymentIn(tx, states, key, lock);
  if (read.transaction.status !== 'UNKNOWN') throw new MarkRefused(409, 'PAYMENT_NOT_UNKNOWN');
  if (now.getTime() - read.transaction.createdAt.getTime() <= MARK_FAILED_AFTER_MS) {
    throw new MarkRefused(409, 'PAYMENT_TOO_RECENT');
  }
  return read;
}

/** The payment's OPEN proposal, after the payment (10): NO_FAILURE_PROPOSAL or INTEGRITY_FAILED otherwise. */
async function openIn(
  tx: MarkTx,
  states: SignedStates,
  orgId: string,
  transactionId: string,
  lock: 'share' | 'change',
) {
  const open = await openProposalOf(tx, states, { orgId, transactionId }, lock);
  if (open.outcome === 'tampered') throw new MarkRefused(503, 'INTEGRITY_FAILED');
  if (open.outcome === 'none') throw new MarkRefused(409, 'NO_FAILURE_PROPOSAL');
  return open;
}

/** Every admin of the organisation, `aboutId` the payment's transaction. */
const toAdmins = (orgId: string, kind: 'payment_mark_proposed' | 'payment_mark_withdrawn', transactionId: string) => [
  { orgId, recipientUserId: null, kind, membershipId: null, role: null, aboutId: transactionId },
];

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

  /** A proposal one may propose for: the payment markable and none open. */
  const proposable = async (
    tx: MarkTx,
    states: SignedStates,
    member: SessionMember,
    paymentId: string,
    lock: 'share' | 'change',
  ) => {
    await work.memberIn(tx, states, member, MARKING_ROLES);
    const read = await markable(tx, states, { orgId: member.orgId, id: paymentId }, lock, clock.now());
    const open = await openProposalOf(tx, states, { orgId: member.orgId, transactionId: read.transaction.id }, lock);
    if (open.outcome === 'tampered') throw new MarkRefused(503, 'INTEGRITY_FAILED');
    if (open.outcome === 'found') throw new MarkRefused(409, 'FAILURE_PROPOSAL_OPEN');
    return read;
  };

  /**
   * The proposal this admin may approve: the payment markable, its proposal
   * open, and the admin a second person by the two-person rule (ADR-012 §1,
   * partner S145: as a supplier's verifier, among the admins): not the
   * proposer, a member 14 days, not made admin by them. Where no admin is,
   * the one-person path, a day after proposing, unless an admin or approver
   * was removed or had their role changed in the last 14 days. The members and
   * their history are read at 2a, before the payment.
   */
  const approvable = async (
    tx: MarkTx,
    states: SignedStates,
    member: SessionMember,
    paymentId: string,
    lock: 'share' | 'change',
  ) => {
    const confirmer = await work.memberIn(tx, states, member, MARKING_ROLES);
    const facts = await twoPersonFactsOf(tx, states, member.orgId);
    if (facts.outcome === 'tampered') throw new MarkRefused(503, 'INTEGRITY_FAILED');
    const now = clock.now();
    const read = await markable(tx, states, { orgId: member.orgId, id: paymentId }, lock, now);
    const open = await openIn(tx, states, member.orgId, read.transaction.id, lock);
    // A membership is never deleted (deactivated, it stays): a proposer with none is past the app.
    const proposer = facts.members.find(({ userId }) => userId.toLowerCase() === open.proposal.proposedBy);
    if (proposer === undefined) throw new MarkRefused(503, 'INTEGRITY_FAILED');
    // Among the admins alone (only they confirm a mark), and the proposer whatever their role now.
    const amongAdmins = {
      ...facts,
      members: facts.members.filter(({ id, role }) => role === 'admin' || id === proposer.id),
    };
    const verdict = verifierVerdict(amongAdmins, { enteredById: proposer.id, verifierId: confirmer.id }, now);
    if (verdict.outcome === 'refused') throw new MarkRefused(...CONFIRMER_REFUSALS[verdict.reason]);
    if (verdict.outcome === 'single_user' && now.getTime() - open.proposal.createdAt.getTime() <= LONE_ADMIN_WAIT_MS) {
      throw new MarkRefused(409, 'FAILURE_PROPOSAL_TOO_RECENT');
    }
    return { read, open, hash: hashOf(APPROVE_OPERATION, member.orgId, read.state.eventId, open.state.eventId) };
  };

  /** The proposal any admin may withdraw: its payment the organisation's, as it stands, and its proposal open. */
  const withdrawable = async (
    tx: MarkTx,
    states: SignedStates,
    member: SessionMember,
    paymentId: string,
    lock: 'share' | 'change',
  ) => {
    await work.memberIn(tx, states, member, MARKING_ROLES);
    const read = await paymentIn(tx, states, { orgId: member.orgId, id: paymentId }, 'share');
    const open = await openIn(tx, states, member.orgId, read.transaction.id, lock);
    return { read, open, hash: hashOf(WITHDRAW_OPERATION, member.orgId, open.state.eventId) };
  };

  /** A proposal as it now stands, once written or answered for its key. */
  const proposalAnswer = (orgId: string, correlationId: string, id: string) =>
    work.answered(orgId, correlationId, async (tx, states) => {
      const found = await proposalOf(tx, states, { orgId, id }, 'share');
      if (found.outcome === 'tampered') throw new MarkRefused(503, 'INTEGRITY_FAILED');
      // Proposals are never deleted (0066's grants): one written is there.
      if (found.outcome !== 'found') throw new Error(`A failure proposal is missing: ${id}`);
      return found.proposal;
    });

  return {
    async propose(member, idempotent, paymentId, evidenceRef, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const read = await proposable(tx, states, member, paymentId, 'share');
        return stepUps.ask(tx, member, {
          action: PROPOSE_OPERATION,
          changeHash: hashOf(PROPOSE_OPERATION, member.orgId, read.state.eventId, evidenceRef),
        });
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirmProposal(member, idempotent, paymentId, { evidenceRef, stepUpChallengeId }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const read = await proposable(tx, states, member, paymentId, 'change');
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          {
            action: PROPOSE_OPERATION,
            changeHash: hashOf(PROPOSE_OPERATION, member.orgId, read.state.eventId, evidenceRef),
          },
          { passkeyRequired: true },
        );
        const id = ids.next();
        await proposeFailure(
          tx,
          states,
          {
            orgId: member.orgId,
            id,
            transactionId: read.transaction.id,
            evidenceRef,
            proposedBy: member.userId,
            createdAt: clock.now(),
          },
          {
            actor: { type: 'user', id: member.userId },
            details: { ...confirmedDetails(), ...stepUpDetails(consumed) },
          },
        );
        await outbox.add(tx, toAdmins(member.orgId, 'payment_mark_proposed', read.transaction.id));
        return { status: 201, resourceId: id };
      });
      if (isUnwritten(done)) return done;
      const proposal = await proposalAnswer(member.orgId, correlationId, done.result.resourceId);
      return 'outcome' in proposal ? proposal : { outcome: 'proposed', proposal };
    },

    async approve(member, idempotent, paymentId, correlationId) {
      let shown: FailureProposalRecord | undefined;
      const done = await work.historyBounded(member, idempotent, correlationId, async (tx, states) => {
        const { open, hash } = await approvable(tx, states, member, paymentId, 'share');
        shown = open.proposal;
        return stepUps.ask(tx, member, { action: APPROVE_OPERATION, changeHash: hash });
      });
      if (isUnwritten(done)) return done;
      // A replayed ask answers from its key's record, which keeps no proposal: it is read again, as it now stands.
      if (shown === undefined) {
        const again = await work.answered(member.orgId, correlationId, async (tx, states) => {
          const read = await paymentIn(tx, states, { orgId: member.orgId, id: paymentId }, 'share');
          return { proposal: (await openIn(tx, states, member.orgId, read.transaction.id, 'share')).proposal };
        });
        if ('outcome' in again) return again;
        shown = again.proposal;
      }
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId, proposal: shown };
    },

    async confirmApproval(member, idempotent, paymentId, stepUpChallengeId, correlationId) {
      const done = await work.historyBounded(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const { read, open, hash } = await approvable(tx, states, member, paymentId, 'change');
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: APPROVE_OPERATION, changeHash: hash },
          { passkeyRequired: true },
        );
        const evidence = { ...confirmedDetails(), ...stepUpDetails(consumed) };
        const actor = { type: 'user', id: member.userId } as const;
        // The payment first: its holdings (11) are locked before any event takes the chain's head (12).
        await markFailed(tx, states, outbox, {
          orgId: member.orgId,
          transactionId: read.transaction.id,
          userId: member.userId,
          details: {
            evidenceRef: open.proposal.evidenceRef,
            proposalId: open.proposal.id,
            proposedBy: open.proposal.proposedBy,
            ...evidence,
          },
          at: clock.now(),
        });
        await moveProposal(tx, states, { orgId: member.orgId, id: open.proposal.id }, 'confirm', {
          actor,
          details: evidence,
        });
        return { status: 200, resourceId: read.transaction.id };
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'marked', paymentId: done.result.resourceId };
    },

    async withdraw(member, idempotent, paymentId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const { hash } = await withdrawable(tx, states, member, paymentId, 'share');
        return stepUps.ask(tx, member, { action: WITHDRAW_OPERATION, changeHash: hash });
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirmWithdrawal(member, idempotent, paymentId, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const { read, open, hash } = await withdrawable(tx, states, member, paymentId, 'change');
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: WITHDRAW_OPERATION, changeHash: hash },
          { passkeyRequired: true },
        );
        await moveProposal(tx, states, { orgId: member.orgId, id: open.proposal.id }, 'withdraw', {
          actor: { type: 'user', id: member.userId },
          details: stepUpDetails(consumed),
        });
        await outbox.add(tx, toAdmins(member.orgId, 'payment_mark_withdrawn', read.transaction.id));
        return { status: 200, resourceId: open.proposal.id };
      });
      if (isUnwritten(done)) return done;
      const proposal = await proposalAnswer(member.orgId, correlationId, done.result.resourceId);
      return 'outcome' in proposal ? proposal : { outcome: 'withdrawn', proposal };
    },
  };
}
