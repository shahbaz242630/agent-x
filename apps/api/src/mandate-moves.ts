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
// - Phase 3 adds the cascade in the same transaction (PRD §4.2): every request
//   of the mandate awaiting approval or hand-off DENIED, its approval
//   cancelled and its reservation released.
//
// Lock order (ADR-006 §6): the idempotency key, the session's challenges (0b,
// confirm only), the admin's membership (2a), the mandate (4), the version in
// force (a resume's, read), the challenge consumed, the chain head last. The
// agent (3) is not read: none of these moves needs it active, and a
// suspended agent can't spend whatever its mandate says.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import { isEnded, MANDATES } from '@agentx/core/modules/mandates';
import type { NoticeKind, NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
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
  toldOfMandate,
  versionIn,
  viewIn,
} from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork, movedAsRead, type SessionMember } from './use-case-work.ts';

/** The moves, by the state machine's events (MANDATE). */
export const MANDATE_MOVES = ['suspend', 'resume', 'revoke'] as const;
export type MandateMove = (typeof MANDATE_MOVES)[number];

/** Each move's operations: the ask, which the step-up challenge names as its action too, and its confirm. */
export const MOVE_OPERATIONS = {
  suspend: { ask: 'mandates.suspend', confirm: 'mandates.suspend.confirm' },
  resume: { ask: 'mandates.resume', confirm: 'mandates.resume.confirm' },
  revoke: { ask: 'mandates.revoke', confirm: 'mandates.revoke.confirm' },
} as const satisfies Record<MandateMove, { ask: string; confirm: string }>;

/** What each move records, and whom it tells (0036). */
const MOVED = {
  suspend: { action: 'mandate.suspended', notice: 'mandate_suspended' },
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
    move: MandateMove,
    correlationId: string,
  ): Promise<MoveAsked>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    mandateId: string,
    move: MandateMove,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<MandateMoved>;
}

/**
 * The move's SHA-256: the organisation and the mandate's latest event, IDs in
 * lower case. That event is the mandate's own, read from its signed state, so
 * it names the mandate as it stood when asked: any change to it since makes
 * the step-up another change's. The move itself is the challenge's action,
 * which its consume checks (B4's mutation pass: naming it here too was dead).
 */
const moveHash = (orgId: string, mandateEvent: string): Buffer =>
  changeHashOf([orgId.toLowerCase(), mandateEvent.toLowerCase()]);

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

  /** The mandate read (`share` or `change`) and verified: refused unless it may make the move now. */
  const movable = async (
    tx: MandateTx,
    states: SignedStates,
    orgId: string,
    mandateId: string,
    move: MandateMove,
    lock: 'share' | 'change',
  ) => {
    const read = await mandateIn(tx, states, orgId, mandateId, lock);
    const { mandate } = read;
    if (move === 'revoke') {
      if (isEnded(mandate.status)) throw new MandateRefused(409, 'MANDATE_ENDED');
    } else if (move === 'suspend') {
      if (mandate.status !== 'ACTIVE') throw new MandateRefused(409, 'MANDATE_NOT_ACTIVE');
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
    async ask(member, idempotent, mandateId, move, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, MOVING_ROLES);
        const read = await movable(tx, states, member.orgId, mandateId, move, 'share');
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: MOVE_OPERATIONS[move].ask,
          changeHash: moveHash(member.orgId, read.state.eventId),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new MandateRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, mandateId, move, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        await work.memberIn(tx, states, member, MOVING_ROLES);
        const read = await movable(tx, states, member.orgId, mandateId, move, 'change');
        const consumed = await challenges.consume(
          tx,
          held,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: MOVE_OPERATIONS[move].ask,
            changeHash: moveHash(member.orgId, read.state.eventId),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new MandateRefused(403, 'STEP_UP_FAILED');
        const { id } = read.mandate;
        movedAsRead(
          await states.changeStatus(tx, MANDATES, { orgId: member.orgId, id }, move, {
            actor: { type: 'user', id: member.userId },
            action: MOVED[move].action,
            details: stepUpDetails(consumed),
          }),
          `a mandate read as able to ${move} didn't`,
        );
        await outbox.add(tx, toldOfMandate(member.orgId, MOVED[move].notice, id));
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
