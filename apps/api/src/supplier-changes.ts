// The business's brake on a supplier, and lifting it (PRD §7.1, ADR-012 §5,
// ADR-003 §8, ADR-014 §8; Phase 1 E1-2), as a funding source's are
// (funding-source-changes.ts).
//
// - `suspend` (`suppliers.suspend`): one click and no step-up (ADR-014 §8:
//   the instant brakes are never behind step-up), for an admin or a finance
//   approver. The key claimed first; the member read again; the supplier read
//   for change; then UNVERIFIED or VERIFIED > SUSPENDED, recorded as the
//   member's, with what the member chose for its pending requests, cancel or
//   pause (Phase 3 decision 7, suspensions.ts). On cancel they are DENIED in
//   the same transaction, before its move (voidPendingOf, Phase 3 C3),
//   pressed again too, so a pause made a cancel voids them; the
//   request-voids job takes any past the batch. A pause over an UNVERIFIED
//   supplier whose stop cancels voids those the job hasn't reached first,
//   the job any past the batch, as that stop's event still cancels them
//   (C3c's suspend over a cancel; decision 32a, F1 G1). One suspended already is
//   answered as it is: a brake pressed twice is not an error. A suspended
//   supplier is shown to no agent.
// - `reactivate` (`suppliers.reactivate`): gives the supplier its place back,
//   so an admin's, with a passkey step-up (partner, S69; SEC-HA-12), and the
//   admin's choice for its held requests (Phase 3 decision 9, partner S112,
//   suspensions.ts): a fresh start (cancel) or an un-pause (pause), the
//   latter refused (PENDING_REQUESTS_CANCELLED) when the suspension in force
//   cancelled them. The ask: the key claimed first; the admin read again; the
//   supplier, SUSPENDED (SUPPLIER_NOT_SUSPENDED otherwise); a challenge bound
//   to the event that suspended it and to the choice, so it lifts exactly
//   that suspension that way. The confirm, with the challenge and the same
//   choice: the same reads, the challenge consumed; on a fresh start every
//   pending request DENIED up to a brake's batch, the request-voids job the
//   rest by the reactivation's event (decision 32a, F1 G1); then back VERIFIED only if
//   nothing changed while it was suspended (the suppliers module's
//   reactivateSupplier), otherwise UNVERIFIED with its verification cleared,
//   its requests held while it is if un-paused, the step-up's evidence and
//   the choice on its events.
// Each is told to every active member and the counting contacts
// (`supplier_suspended`, `supplier_reactivated`; partner S69, E3-2b), in the
// same transaction; a brake pressed twice tells no one twice.
//
// Lock order (ADR-006 §6): the idempotency key, the member's membership (2a),
// the supplier (6), its version, a suspend's pending requests (8) and their
// holdings (11), a reactivation's after its step-up challenge is consumed,
// the chain head, then the notices, new
// rows that wait on nothing.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import { reactivateSupplier, SUPPLIERS, suspendSupplier } from '@agentx/core/modules/suppliers';
import type { Outbox } from '@agentx/core/modules/notifications';
import { type PendingChoice, voidPendingOf } from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  createSupplierWork,
  cancelledByItsStop,
  type SessionMember,
  type SupplierChangeWrite,
  type SupplierMember,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
  toldEveryone,
} from './supplier-work.ts';
import { choiceDetails, chosenAgain, pausedOf, reactivationChoiceDetails } from './suspensions.ts';
import { createStepUps } from './use-case-work.ts';

/** The brake on a supplier. */
export const SUSPEND_OPERATION = 'suppliers.suspend';
/** Asking to reactivate one: its operation, which the step-up challenge names as its action too. */
export const REACTIVATE_OPERATION = 'suppliers.reactivate';
/** Reactivating it, once stepped up. */
export const REACTIVATE_CONFIRM_OPERATION = 'suppliers.reactivate.confirm';

/** Who may press the brake: the admins, and the finance approvers who answer for the money (ADR-012 §5). */
export const SUSPENDING_ROLES = ['admin', 'approver'] as const;
/** Who may lift it: an admin (partner, S69). */
export const REACTIVATING_ROLES = ['admin'] as const;

export interface SupplierChanges {
  suspend(
    member: SupplierMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    pendingRequests: PendingChoice,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  reactivate(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    pendingRequests: PendingChoice,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  reactivateConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    confirmed: { readonly stepUpChallengeId: string; readonly pendingRequests: PendingChoice },
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
}

/**
 * The pending change's SHA-256: the event that suspended the supplier, its ID
 * in lower case, and the admin's choice. That event is the supplier's own,
 * read from its signed state inside the organisation's walls, so it names the
 * organisation, the supplier and exactly this suspension; another choice
 * makes the step-up another change's (decision 9).
 */
const reactivationHash = (suspendedBy: string, choice: PendingChoice): Buffer =>
  changeHashOf([REACTIVATE_OPERATION, suspendedBy.toLowerCase(), choice]);

export function createSupplierChanges({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Database<SupplierTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): SupplierChanges {
  const work = createSupplierWork({ database, keys, ids, logger });
  const stepUps = createStepUps({ challenges, Refusal: SupplierRefused });

  /**
   * A suspended supplier, read for change, and the event that suspended it:
   * SUPPLIER_NOT_SUSPENDED otherwise; PENDING_REQUESTS_CANCELLED for an
   * un-pause when its suspension in force cancelled them (decision 9).
   */
  const suspended = async (
    tx: SupplierTx,
    states: SignedStates,
    orgId: string,
    supplierId: string,
    choice: PendingChoice,
  ) => {
    const found = await work.supplierIn(tx, states, { orgId, id: supplierId }, 'change');
    if (found.supplier.status !== 'SUSPENDED') throw new SupplierRefused(409, 'SUPPLIER_NOT_SUSPENDED');
    if (choice === 'pause') {
      const paused = await pausedOf(tx, states, orgId, [['supplier', supplierId, 'SUSPENDED']]);
      if (!paused.has('supplier')) throw new SupplierRefused(409, 'PENDING_REQUESTS_CANCELLED');
    }
    return { found, suspendedBy: found.state.eventId };
  };

  return {
    async suspend(member, idempotent, supplierId, pendingRequests, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, SUSPENDING_ROLES);
        const key = { orgId: member.orgId, id: supplierId };
        const found = await work.supplierIn(tx, states, key, 'change');
        const braked = { supplierId: found.supplier.id };
        const cancelledBefore =
          pendingRequests === 'pause' && (await cancelledByItsStop(tx, states, member.orgId, found.supplier));
        if (pendingRequests === 'cancel' || cancelledBefore) {
          await voidPendingOf(tx, states, keys, member.orgId, braked, 'SUPPLIER_NOT_VERIFIED', clock.now());
        }
        // Pressed twice: stopped already, and answered as it is, unless the choice changes (chosenAgain).
        if (found.supplier.status === 'SUSPENDED') {
          const again = await chosenAgain(
            tx,
            states,
            { which: 'supplier', table: SUPPLIERS, key, state: found.state },
            pendingRequests,
            { type: 'user', id: member.userId },
          );
          if (again === 'refused') throw new SupplierRefused(409, 'PENDING_REQUESTS_CANCELLED');
        } else {
          await suspendSupplier(tx, states, key, found, {
            actor: { type: 'user', id: member.userId },
            details: choiceDetails(pendingRequests),
          });
          await outbox.add(tx, toldEveryone(member.orgId, found.supplier.id, 'supplier_suspended'));
        }
        return { status: 200, resourceId: found.supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },

    async reactivate(member, idempotent, supplierId, pendingRequests, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const { suspendedBy } = await suspended(tx, states, member.orgId, supplierId, pendingRequests);
        return stepUps.ask(tx, member, {
          action: REACTIVATE_OPERATION,
          changeHash: reactivationHash(suspendedBy, pendingRequests),
        });
      });
      return work.askedAfter(done);
    },

    async reactivateConfirm(member, idempotent, supplierId, { stepUpChallengeId, pendingRequests }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const { found, suspendedBy } = await suspended(tx, states, member.orgId, supplierId, pendingRequests);
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: REACTIVATE_OPERATION, changeHash: reactivationHash(suspendedBy, pendingRequests) },
          { passkeyRequired: true },
        );
        if (pendingRequests === 'cancel') {
          // A brake's batch; the request-voids job the rest, by this reactivation's event (F1 G1).
          const braked = { supplierId: found.supplier.id };
          await voidPendingOf(tx, states, keys, member.orgId, braked, 'SUPPLIER_NOT_VERIFIED', clock.now());
        }
        await reactivateSupplier(tx, states, { orgId: member.orgId, id: found.supplier.id }, found, {
          actor: { type: 'user', id: member.userId },
          details: { ...stepUpDetails(consumed), ...reactivationChoiceDetails(pendingRequests) },
        });
        await outbox.add(tx, toldEveryone(member.orgId, found.supplier.id, 'supplier_reactivated'));
        return { status: 200, resourceId: found.supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },
  };
}
