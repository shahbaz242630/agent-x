// The business's brake on a supplier, and lifting it (PRD §7.1, ADR-012 §5,
// ADR-003 §8, ADR-014 §8; Phase 1 E1-2), as a funding source's are
// (funding-source-changes.ts).
//
// - `suspend` (`suppliers.suspend`): one click and no step-up (ADR-014 §8:
//   the instant brakes are never behind step-up), for an admin or a finance
//   approver. The key claimed first; the member read again; the supplier read
//   for change; then UNVERIFIED or VERIFIED > SUSPENDED, recorded as the
//   member's. One suspended already is answered as it is: a brake pressed
//   twice is not an error. A suspended supplier is shown to no agent.
// - `reactivate` (`suppliers.reactivate`): gives the supplier its place back,
//   so an admin's, with a passkey step-up (partner, S69; SEC-HA-12). The ask:
//   the key claimed first; the admin read again; the supplier, SUSPENDED
//   (SUPPLIER_NOT_SUSPENDED otherwise); a challenge bound to the event that
//   suspended it, so it lifts exactly that suspension. The confirm, with the
//   challenge: the same reads, the challenge consumed, then back VERIFIED
//   only if nothing changed while it was suspended (the suppliers module's
//   reactivateSupplier), otherwise UNVERIFIED with its verification cleared,
//   the step-up's evidence on its events. Telling every member of it waits
//   for the supplier notices' kinds (E2-1's migration; `Carry-Forward.md`).
//
// Lock order (ADR-006 §6): the idempotency key, the member's membership (2a),
// the supplier (6), its version, the step-up challenge, the chain head last.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import { reactivateSupplier, suspendSupplier } from '@agentx/core/modules/suppliers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  createSupplierWork,
  type SessionMember,
  type SupplierChangeWrite,
  type SupplierMember,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
} from './supplier-work.ts';

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
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  reactivate(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  reactivateConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
}

/**
 * The pending change's SHA-256: the event that suspended the supplier, its ID
 * in lower case. That event is the supplier's own, read from its signed state
 * inside the organisation's walls, so it names the organisation, the supplier
 * and exactly this suspension.
 */
const reactivationHash = (suspendedBy: string): Buffer =>
  changeHashOf([REACTIVATE_OPERATION, suspendedBy.toLowerCase()]);

export function createSupplierChanges({
  database,
  keys,
  ids,
  challenges,
  logger,
}: {
  readonly database: Database<SupplierTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): SupplierChanges {
  const work = createSupplierWork({ database, keys, ids, logger });

  /** A suspended supplier, read for change, and the event that suspended it: SUPPLIER_NOT_SUSPENDED otherwise. */
  const suspended = async (tx: SupplierTx, states: SignedStates, orgId: string, supplierId: string) => {
    const found = await work.supplierIn(tx, states, { orgId, id: supplierId }, 'change');
    if (found.supplier.status !== 'SUSPENDED') throw new SupplierRefused(409, 'SUPPLIER_NOT_SUSPENDED');
    return { found, suspendedBy: found.state.eventId };
  };

  return {
    async suspend(member, idempotent, supplierId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, SUSPENDING_ROLES);
        const key = { orgId: member.orgId, id: supplierId };
        const found = await work.supplierIn(tx, states, key, 'change');
        // Pressed twice: stopped already, and answered as it is.
        if (found.supplier.status !== 'SUSPENDED') {
          await suspendSupplier(tx, states, key, found, { actor: { type: 'user', id: member.userId } });
        }
        return { status: 200, resourceId: found.supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },

    async reactivate(member, idempotent, supplierId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const { suspendedBy } = await suspended(tx, states, member.orgId, supplierId);
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: REACTIVATE_OPERATION,
          changeHash: reactivationHash(suspendedBy),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new SupplierRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      return work.askedAfter(done);
    },

    async reactivateConfirm(member, idempotent, supplierId, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const { found, suspendedBy } = await suspended(tx, states, member.orgId, supplierId);
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          { sessionId: member.sessionId, action: REACTIVATE_OPERATION, changeHash: reactivationHash(suspendedBy) },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new SupplierRefused(403, 'STEP_UP_FAILED');
        await reactivateSupplier(tx, states, { orgId: member.orgId, id: found.supplier.id }, found, {
          actor: { type: 'user', id: member.userId },
          details: stepUpDetails(consumed),
        });
        return { status: 200, resourceId: found.supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },
  };
}
