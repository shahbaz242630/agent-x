// Freezing and unfreezing the organisation (PRD §5.3, ADR-003 §8, ADR-014
// §8; Phase 3 D1, partner decisions 3, 10 and 11). Composed in the API, as
// the other brakes are (agent-changes.ts, supplier-changes.ts).
//
// - `freeze` (`organization.freeze`): an instant brake, one click and no
//   step-up, for any admin, confirmed (decision 11: the console's
//   are-you-sure, so a mis-click blocks nothing) and with the admin's choice
//   for the organisation's pending spend requests, cancel or pause (decision
//   10, suspensions.ts). The key claimed first; the organisation read for
//   change; the admin read again; on cancel, the pending requests DENIED
//   before its move (voidPendingOf, the request-voids job taking any past
//   the batch), pressed again too; then ACTIVE > FROZEN with the choice on
//   its event. One frozen already is answered as it is, unless the choice
//   changes (chosenAgain: a pause made a cancel recorded; a cancel made a
//   pause refused, PENDING_REQUESTS_CANCELLED). While frozen nothing is
//   decided or approved (ORG_FROZEN); rejecting and cancelling go on
//   (decision 3).
// - `unfreeze` (`organization.unfreeze`): gives the organisation its
//   authority back, so an admin's, with a passkey step-up and a reason kept
//   on its event. The ask: the key claimed first; the organisation, FROZEN
//   (ORG_NOT_FROZEN otherwise); the admin read again; a freeze that cancels
//   with more pending than one brake voids is refused
//   (PENDING_REQUESTS_TOO_MANY), as once ACTIVE the request-voids job never
//   looks at those left; a challenge bound to the organisation, the event
//   that froze it and the reason. The confirm, with the challenge and the
//   same reason: the same reads, the challenge consumed; a freeze that
//   cancels voids those left first; then FROZEN > ACTIVE.
// Each is told to every admin and approver (`organization_frozen`,
// `organization_unfrozen`; 0045), in the same transaction; a brake pressed
// twice tells no one twice.
//
// Lock order (ADR-006 §6): the idempotency key, the session's challenges
// (0b, an unfreeze's confirm), the organisation (2) before the admin's
// membership (2a), as an approval reads them, the challenge consumed, the
// pending requests (8) and their holdings (11), the chain head, then the
// notices, new rows that wait on nothing.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  pendingPastABrake,
  type PendingChoice,
  type SpendRequestsTables,
  voidPendingOf,
} from '@agentx/core/modules/spend-requests';
import { type Clock, type IdGenerator, keptNote } from '@agentx/core/shared-kernel';
import { type Database, type DatabaseTransaction, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { toldAdminsAndApprovers } from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { chosenAgain, freezeChoiceDetails, pausedOf } from './suspensions.ts';
import {
  createStepUps,
  createUseCaseWork,
  movedAsRead,
  type SessionMember,
  UseCaseRefused,
  type UseCaseTables,
} from './use-case-work.ts';

/** The brake on the whole organisation. */
export const FREEZE_OPERATION = 'organization.freeze';
/** Asking to unfreeze it: its operation, which the step-up challenge names as its action too. */
export const UNFREEZE_OPERATION = 'organization.unfreeze';
/** Unfreezing it, once stepped up. */
export const UNFREEZE_CONFIRM_OPERATION = 'organization.unfreeze.confirm';

/** Who may freeze it, and unfreeze it: any admin (PRD §5.3, Phase 3 D1). */
export const FREEZING_ROLES = ['admin'] as const;

/** The most characters an unfreeze's reason may have. */
export const UNFREEZE_REASON_MOST = 200;

/** The reason as it is kept (composed, NFC), with the problems that keep it from being one. */
export const unfreezeReason = (reason: string) => keptNote(reason, UNFREEZE_REASON_MOST, 'the reason');

type OrganizationTables = UseCaseTables &
  OrganizationsTables &
  NotificationsTables &
  SpendRequestsTables &
  LimitReservationsTables;
type OrganizationTx = DatabaseTransaction<OrganizationTables>;

/** The organisation's UseCaseRefused: the only refusal its work answers. */
class OrganizationRefused extends UseCaseRefused {}

/** The organisation as a change leaves it. */
interface OrganizationShown {
  readonly id: string;
  readonly status: string;
}

export type OrganizationChangeWrite =
  | { readonly outcome: 'changed'; readonly organization: OrganizationShown }
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | Refused
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' };

export interface OrganizationChanges {
  freeze(
    member: SessionMember,
    idempotent: IdempotentRequest,
    pendingRequests: PendingChoice,
    correlationId: string,
  ): Promise<OrganizationChangeWrite>;
  unfreeze(
    member: SessionMember,
    idempotent: IdempotentRequest,
    reason: string,
    correlationId: string,
  ): Promise<OrganizationChangeWrite>;
  unfreezeConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    confirmed: { readonly stepUpChallengeId: string; readonly reason: string },
    correlationId: string,
  ): Promise<OrganizationChangeWrite>;
}

/**
 * The unfreeze's SHA-256: the organisation and the event that froze it, IDs
 * in lower case, and the reason as it is kept: another freeze since, or
 * another reason, makes the step-up another change's.
 */
const unfreezeHash = (orgId: string, frozenBy: string, reason: string): Buffer =>
  changeHashOf([UNFREEZE_OPERATION, orgId.toLowerCase(), frozenBy.toLowerCase(), reason]);

export function createOrganizationChanges({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Database<OrganizationTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): OrganizationChanges {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: OrganizationRefused });
  const stepUps = createStepUps({ challenges, Refusal: OrganizationRefused });
  const actor = (member: SessionMember) => ({ type: 'user', id: member.userId }) as const;

  /** Level 2: the organisation, read through its signed state (INTEGRITY_FAILED for one tampered with). */
  const organizationIn = async (tx: OrganizationTx, states: SignedStates, orgId: string, lock: 'share' | 'change') => {
    const read = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, lock);
    // The organisation always exists while its members can act in it.
    if (read.outcome !== 'verified') throw new OrganizationRefused(503, 'INTEGRITY_FAILED');
    return { key: { orgId, id: orgId }, state: read, status: read.fields.get('status') };
  };

  /**
   * The organisation, FROZEN (ORG_NOT_FROZEN otherwise), and the admin, for
   * an unfreeze: refused PENDING_REQUESTS_TOO_MANY when its freeze cancels
   * and more are pending than one brake voids. Whether its freeze cancels.
   */
  const unfreezable = async (tx: OrganizationTx, states: SignedStates, member: SessionMember) => {
    const organization = await organizationIn(tx, states, member.orgId, 'change');
    await work.memberIn(tx, states, member, FREEZING_ROLES);
    if (organization.status !== 'FROZEN') throw new OrganizationRefused(409, 'ORG_NOT_FROZEN');
    const paused = await pausedOf(tx, states, member.orgId, [['organization', member.orgId, 'FROZEN']]);
    const cancels = !paused.has('organization');
    if (cancels && (await pendingPastABrake(tx, member.orgId, { organizationId: member.orgId }))) {
      throw new OrganizationRefused(409, 'PENDING_REQUESTS_TOO_MANY');
    }
    return { organization, cancels };
  };

  /** The organisation as it now stands, once a write is done; its refusal or key's outcome as it is. */
  const changedAfter = async (
    orgId: string,
    correlationId: string,
    done: Awaited<ReturnType<typeof work.write>>,
  ): Promise<OrganizationChangeWrite> => {
    if (isUnwritten(done)) return done;
    const standing = await work.answered(orgId, correlationId, async (tx, states) => {
      const { status } = await organizationIn(tx, states, orgId, 'share');
      return { id: orgId, status: String(status) };
    });
    if ('outcome' in standing) return standing;
    return { outcome: 'changed', organization: standing };
  };

  return {
    async freeze(member, idempotent, pendingRequests, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const { key, state, status } = await organizationIn(tx, states, member.orgId, 'change');
        await work.memberIn(tx, states, member, FREEZING_ROLES);
        if (pendingRequests === 'cancel') {
          const braked = { organizationId: member.orgId };
          await voidPendingOf(tx, states, keys, member.orgId, braked, 'ORG_FROZEN', clock.now());
        }
        const details = freezeChoiceDetails(pendingRequests);
        // Pressed twice: frozen already, and answered as it is, unless the choice changes (chosenAgain).
        if (status === 'FROZEN') {
          const again = await chosenAgain(
            tx,
            states,
            { which: 'organization', table: ORGANIZATIONS, key, state },
            pendingRequests,
            actor(member),
            details,
          );
          if (again === 'refused') throw new OrganizationRefused(409, 'PENDING_REQUESTS_CANCELLED');
        } else {
          movedAsRead(
            await states.changeStatus(tx, ORGANIZATIONS, key, 'freeze', {
              actor: actor(member),
              action: FREEZE_OPERATION,
              details,
            }),
            "an organisation read as ACTIVE didn't freeze",
          );
          await outbox.add(tx, toldAdminsAndApprovers(member.orgId, 'organization_frozen', member.orgId));
        }
        return { status: 200, resourceId: member.orgId };
      });
      return changedAfter(member.orgId, correlationId, done);
    },

    async unfreeze(member, idempotent, reason, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const { organization } = await unfreezable(tx, states, member);
        return stepUps.ask(tx, member, {
          action: UNFREEZE_OPERATION,
          changeHash: unfreezeHash(member.orgId, organization.state.eventId, reason),
        });
      });
      if (isUnwritten(done)) return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async unfreezeConfirm(member, idempotent, { stepUpChallengeId, reason }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const { organization, cancels } = await unfreezable(tx, states, member);
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: UNFREEZE_OPERATION, changeHash: unfreezeHash(member.orgId, organization.state.eventId, reason) },
          { passkeyRequired: true },
        );
        if (cancels) {
          // Those the freeze's batch left, before the job reached them: once ACTIVE, it never would.
          const braked = { organizationId: member.orgId };
          await voidPendingOf(tx, states, keys, member.orgId, braked, 'ORG_FROZEN', clock.now());
        }
        movedAsRead(
          await states.changeStatus(tx, ORGANIZATIONS, organization.key, 'unfreeze', {
            actor: actor(member),
            action: UNFREEZE_OPERATION,
            details: { ...stepUpDetails(consumed), reason },
          }),
          "an organisation read as FROZEN didn't unfreeze",
        );
        await outbox.add(tx, toldAdminsAndApprovers(member.orgId, 'organization_unfrozen', member.orgId));
        return { status: 200, resourceId: member.orgId };
      });
      return changedAfter(member.orgId, correlationId, done);
    },
  };
}
