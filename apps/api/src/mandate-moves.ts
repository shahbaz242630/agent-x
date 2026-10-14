// Suspending, resuming and revoking a mandate (PRD §4.1, §7.1, §7.3; BR-05,
// BR-11; ADR-003 §8, ADR-014 §8; Phase 2 B4): each an admin's, proved with a
// passkey (step-up also before suspending or revoking a mandate, ADR-014 §8;
// resuming gives its authority back), as accepting is.
//
// - The ask (`mandates.suspend`, `.resume`, `.revoke`): the admin read again;
//   the mandate, able to make the move (`movable`); a challenge bound to the
//   organisation and the mandate's latest signed event, so the step-up makes
//   this move on the mandate as it stood when asked and on no later state of
//   it; answered 202.
// - The confirm (`….confirm`): the same reads, the mandate for change; the
//   challenge consumed; then the move, with the step-up's evidence on its
//   event, and every admin and approver told (0036), in the same transaction.
// - What each move takes: suspend an ACTIVE mandate (MANDATE_NOT_ACTIVE
//   otherwise); resume a SUSPENDED one (MANDATE_NOT_SUSPENDED) whose version
//   in force hasn't reached its end (MANDATE_ENDED: the expiry job ends it,
//   mandate-expiry.ts); revoke any open one (MANDATE_ENDED once revoked or
//   expired), a draft never accepted included. A suspended mandate keeps its
//   waiting draft, accepted only once it is resumed (B3); a revoked one keeps
//   it too, never to be accepted (0035).
// - A suspend names what happens to the mandate's pending requests, cancel
//   or pause (Phase 3 decision 7, suspensions.ts): the ask binds the choice
//   into its challenge, so the step-up confirms that choice alone, and the
//   move's event keeps it. A suspended mandate whose suspension paused its
//   requests may be suspended again to cancel them, recorded as a further
//   suspend event with its signed state unchanged; a pause over a cancel is
//   PENDING_REQUESTS_CANCELLED (suspensions.ts' chosenAgain, for the
//   one-click brakes).
// - A revoke, and a suspend on cancel, DENY the mandate's pending requests
//   in the confirm's transaction, before the move (voidPendingOf, Phase 3
//   C2b): a pause made a cancel too. The request-voids job takes any past
//   the batch.
//
// Lock order (ADR-006 §6): the idempotency key, the session's challenges (0b,
// confirm only), the admin's membership (2a), the mandate (4), the version in
// force (a resume's, read), the challenge consumed, the mandate's pending
// requests (8) and their holdings (11), the chain head last. The agent (3) is
// not read: none of these moves needs it active, and a suspended agent can't
// spend whatever its mandate says.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import { isEnded, MANDATES } from '@agentx/core/modules/mandates';
import type { NoticeKind, NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { type PendingChoice, voidPendingOf } from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  MandateRefused,
  type MandateTables,
  type MandateTx,
  mandateIn,
  type MandateView,
  toldAdminsAndApprovers,
  versionIn,
  viewIn,
} from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { choiceDetails, pausedOf, SUSPENDS } from './suspensions.ts';
import { createStepUps, createUseCaseWork, movedAsRead, type SessionMember } from './use-case-work.ts';

/** The moves, by the state machine's events (MANDATE). */
export const MANDATE_MOVES = ['suspend', 'resume', 'revoke'] as const;
export type MandateMove = (typeof MANDATE_MOVES)[number];

/** A move as asked: a suspend with the suspender's choice for the mandate's pending requests (decision 7). */
export type MoveChosen =
  | { readonly move: 'suspend'; readonly pendingRequests: PendingChoice }
  | { readonly move: Exclude<MandateMove, 'suspend'> };

/** Each move's operations: the ask, which the step-up challenge names as its action too, and its confirm. */
export const MOVE_OPERATIONS = {
  suspend: { ask: 'mandates.suspend', confirm: 'mandates.suspend.confirm' },
  resume: { ask: 'mandates.resume', confirm: 'mandates.resume.confirm' },
  revoke: { ask: 'mandates.revoke', confirm: 'mandates.revoke.confirm' },
} as const satisfies Record<MandateMove, { ask: string; confirm: string }>;

/** What each move records, and whom it tells (0036). */
const MOVED = {
  suspend: { action: SUSPENDS.mandate.action, notice: 'mandate_suspended' },
  resume: { action: 'mandate.resumed', notice: 'mandate_resumed' },
  revoke: { action: 'mandate.revoked', notice: 'mandate_revoked' },
} as const satisfies Record<MandateMove, { action: string; notice: NoticeKind }>;

/** Who may move a mandate: an admin, as for accepting it (ADR-003 §8). */
export const MOVING_ROLES = ['admin'] as const;

export type MoveAsked =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type MandateMoved =
  | ({ readonly outcome: 'moved' } & MandateView)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface MandateMoves {
  ask(
    member: SessionMember,
    idempotent: IdempotentRequest,
    mandateId: string,
    chosen: MoveChosen,
    correlationId: string,
  ): Promise<MoveAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    mandateId: string,
    chosen: MoveChosen,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<MandateMoved>;
}

/**
 * The move's SHA-256: the organisation and the mandate's latest event, IDs in
 * lower case, and a suspend's choice. That event is the mandate's own, read
 * from its signed state, so it names the mandate as it stood when asked: any
 * change to it since makes the step-up another change's; so does another
 * choice. The move itself is the challenge's action, which its consume
 * checks (B4's mutation pass: naming it here too was dead).
 */
const moveHash = (orgId: string, mandateEvent: string, chosen: MoveChosen): Buffer =>
  changeHashOf([
    orgId.toLowerCase(),
    mandateEvent.toLowerCase(),
    ...(chosen.move === 'suspend' ? [chosen.pendingRequests] : []),
  ]);

/** Whether the move ends the mandate's pending requests: a revoke, or a suspend that cancels them (decision 7). */
const cancels = (chosen: MoveChosen): boolean =>
  chosen.move === 'revoke' || (chosen.move === 'suspend' && chosen.pendingRequests === 'cancel');

/** What the move's event keeps beside its step-up: a suspend's choice. */
const chosenDetails = (chosen: MoveChosen) => (chosen.move === 'suspend' ? choiceDetails(chosen.pendingRequests) : {});

/**
 * Refused unless the mandate may be suspended with `choice`: ACTIVE; or
 * SUSPENDED with its requests paused, to cancel them (decision 7). A pause
 * over a cancel is PENDING_REQUESTS_CANCELLED.
 */
async function suspendable(
  tx: MandateTx,
  states: SignedStates,
  orgId: string,
  mandate: { readonly id: string; readonly status: string },
  choice: PendingChoice,
): Promise<void> {
  if (mandate.status === 'ACTIVE') return;
  if (mandate.status !== 'SUSPENDED') throw new MandateRefused(409, 'MANDATE_NOT_ACTIVE');
  const paused = (await pausedOf(tx, states, orgId, [['mandate', mandate.id]])).has('mandate');
  if (!paused && choice === 'pause') throw new MandateRefused(409, 'PENDING_REQUESTS_CANCELLED');
  // Suspended again only to make its pause a cancel.
  if (!paused || choice === 'pause') throw new MandateRefused(409, 'MANDATE_NOT_ACTIVE');
}

export function createMandateMoves({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Database<MandateTables & NotificationsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): MandateMoves {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });
  const stepUps = createStepUps({ challenges, Refusal: MandateRefused });

  /** The mandate read (`share` or `change`) and verified: refused unless it may make the move now. */
  const movable = async (
    tx: MandateTx,
    states: SignedStates,
    orgId: string,
    mandateId: string,
    chosen: MoveChosen,
    lock: 'share' | 'change',
  ) => {
    const read = await mandateIn(tx, states, orgId, mandateId, lock);
    const { mandate } = read;
    if (chosen.move === 'revoke') {
      if (isEnded(mandate.status)) throw new MandateRefused(409, 'MANDATE_ENDED');
    } else if (chosen.move === 'suspend') {
      await suspendable(tx, states, orgId, mandate, chosen.pendingRequests);
    } else {
      if (mandate.status !== 'SUSPENDED') throw new MandateRefused(409, 'MANDATE_NOT_SUSPENDED');
      // 0035's a_status_on_its_versions keeps a version in force on a SUSPENDED mandate.
      if (mandate.currentVersionId === null) throw new Error(`A suspended mandate has no version: ${mandate.id}`);
      const current = await versionIn(tx, states, orgId, mandate.id, mandate.currentVersionId);
      if (current.endsAt !== null && current.endsAt <= clock.now()) throw new MandateRefused(409, 'MANDATE_ENDED');
    }
    return read;
  };

  return {
    async ask(member, idempotent, mandateId, chosen, correlationId) {
      const { move } = chosen;
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, MOVING_ROLES);
        const read = await movable(tx, states, member.orgId, mandateId, chosen, 'share');
        return stepUps.ask(tx, member, {
          action: MOVE_OPERATIONS[move].ask,
          changeHash: moveHash(member.orgId, read.state.eventId, chosen),
        });
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, mandateId, chosen, stepUpChallengeId, correlationId) {
      const { move } = chosen;
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        await work.memberIn(tx, states, member, MOVING_ROLES);
        const read = await movable(tx, states, member.orgId, mandateId, chosen, 'change');
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: MOVE_OPERATIONS[move].ask, changeHash: moveHash(member.orgId, read.state.eventId, chosen) },
          { passkeyRequired: true },
        );
        const { id } = read.mandate;
        if (cancels(chosen)) {
          await voidPendingOf(tx, states, keys, member.orgId, { mandateId: id }, 'MANDATE_NOT_IN_FORCE', clock.now());
        }
        const change = {
          actor: { type: 'user' as const, id: member.userId },
          action: MOVED[move].action,
          details: { ...stepUpDetails(consumed), ...chosenDetails(chosen) },
        };
        if (read.mandate.status === 'SUSPENDED' && move === 'suspend') {
          // Its pause made a cancel (movable): the suspension recorded again, the mandate as it stands.
          await states.record(tx, MANDATES, { orgId: member.orgId, id }, read.state, {}, change);
        } else {
          movedAsRead(
            await states.changeStatus(tx, MANDATES, { orgId: member.orgId, id }, move, change),
            `a mandate read as able to ${move} didn't`,
          );
        }
        await outbox.add(tx, toldAdminsAndApprovers(member.orgId, MOVED[move].notice, id));
        return { status: 200, resourceId: id };
      });
      if (isUnwritten(done)) return done;
      const view = await work.answered(member.orgId, correlationId, (tx, states) =>
        viewIn(tx, states, member.orgId, done.result.resourceId),
      );
      return 'outcome' in view ? view : { outcome: 'moved', ...view };
    },
  };
}
