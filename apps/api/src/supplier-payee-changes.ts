// A supplier's payee change waiting, confirmed or withdrawn (ADR-014 §3 step
// 4, ADR-012 §1, ADR-003 §9, SEC-PAY-03; Phase 1 E2-2b). E2-2a's check left
// the new version waiting and inert: nothing is paid to it until the admin
// who registered it confirms it with a passkey, and only then do its
// cooling-off start and everyone hear of it.
//
// - `approve` (`suppliers.payee.approve`), the admin who started the
//   registration that made the change waiting (PAYEE_CHANGE_NOT_YOURS for
//   another: "the entering admin's step-up", ADR-014 §3): the key claimed;
//   the admin read again; the supplier, with a change waiting
//   (SUPPLIER_NO_CHANGE_WAITING otherwise), that version and its
//   registration; a challenge bound to that very version, so it confirms
//   exactly that change.
// - `approveConfirm` (`suppliers.payee.approve.confirm`), with the challenge:
//   the same reads, the supplier for change, the challenge consumed with a
//   passkey (SEC-HA-12), then the change made current with its payee key
//   (the suppliers module's confirmPayeeChange), its cooling-off ending 24
//   hours on (PAYEE_COOLING_OFF_MS), the step-up's evidence on its event,
//   and `supplier_payee_changed` written for every active member and the
//   registered contacts that count, in the same transaction. Another
//   supplier paid to that payee first is 0033's index refusing the key:
//   everything rolled back, SUPPLIER_PAYEE_TAKEN, and the change left waiting
//   for a withdrawal.
// - `withdraw` (`suppliers.payee.withdraw`): a brake, so at once and with no
//   step-up (ADR-014 §8), for an admin or a finance approver: the change
//   waiting dropped, the payee paid now untouched, so another may be
//   registered. Its event is the audit trail's; no one is told, as nothing
//   anyone relies on changed.
//
// Lock order (ADR-006 §6): the idempotency key, the member's membership (2a),
// the supplier (6), its registration, then its versions (made once and never
// locked for change, so read before the registration that names them
// without a wait between them), the step-up challenge, the chain head with
// the first event recorded, then the notices, new rows that wait on nothing.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { Outbox } from '@agentx/core/modules/notifications';
import {
  confirmPayeeChange,
  isPayeeTaken,
  PAYEE_COOLING_OFF_MS,
  withdrawPayeeChange,
} from '@agentx/core/modules/suppliers';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { REGISTERING_ROLES } from './supplier-payees.ts';
import {
  createSupplierWork,
  type SessionMember,
  type SupplierChangeWrite,
  type SupplierMember,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
  toldEveryone,
} from './supplier-work.ts';

/** Asking to confirm the change waiting: its operation, which the step-up challenge names as its action too. */
export const PAYEE_APPROVE_OPERATION = 'suppliers.payee.approve';
/** Confirming it, once stepped up. */
export const PAYEE_APPROVE_CONFIRM_OPERATION = 'suppliers.payee.approve.confirm';
/** Withdrawing it. */
export const PAYEE_WITHDRAW_OPERATION = 'suppliers.payee.withdraw';

/** Who may drop a change waiting: the admins, and the finance approvers who answer for the money (ADR-012 §5). */
export const WITHDRAWING_ROLES = ['admin', 'approver'] as const;

export interface SupplierPayeeChanges {
  approve(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  approveConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  withdraw(
    member: SupplierMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
}

/**
 * The pending change's SHA-256: the version waiting, its ID in lower case.
 * That version is the supplier's own, read from its signed state inside the
 * organisation's walls, and made for one registration of it alone, so it
 * names the organisation, the supplier and exactly this change.
 */
const approvalHash = (pendingVersionId: string): Buffer =>
  changeHashOf([PAYEE_APPROVE_OPERATION, pendingVersionId.toLowerCase()]);

export function createSupplierPayeeChanges({
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
}): SupplierPayeeChanges {
  const work = createSupplierWork({ database, keys, ids, logger });

  /**
   * The change waiting for this admin's confirmation, read in the write's
   * transaction: the supplier (`lock`), the version waiting and the
   * registration it was made from, which this admin must have started.
   */
  const waitingFor = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SupplierMember,
    supplierId: string,
    lock: 'share' | 'change',
  ) => {
    const admin = await work.memberIn(tx, states, member, REGISTERING_ROLES);
    const { orgId } = member;
    const found = await work.supplierIn(tx, states, { orgId, id: supplierId }, lock);
    const { pendingVersionId } = found.supplier;
    if (pendingVersionId === null) throw new SupplierRefused(409, 'SUPPLIER_NO_CHANGE_WAITING');
    const version = await work.versionIn(tx, states, orgId, found.supplier.id, pendingVersionId);
    const registration = await work.registrationFor(tx, states, orgId, version);
    // stagePayeeChange stages only a version made from a registration of its supplier.
    if (registration === null) throw new Error(`A payee change waits with no registration: ${version.id}`);
    if (registration.startedBy !== admin.id) throw new SupplierRefused(403, 'PAYEE_CHANGE_NOT_YOURS');
    return { found, version, registration };
  };

  return {
    async approve(member, idempotent, supplierId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const { version } = await waitingFor(tx, states, member, supplierId, 'share');
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: PAYEE_APPROVE_OPERATION,
          changeHash: approvalHash(version.id),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new SupplierRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      return work.askedAfter(done);
    },

    async approveConfirm(member, idempotent, supplierId, stepUpChallengeId, correlationId) {
      let done: Awaited<ReturnType<typeof work.write>>;
      try {
        done = await work.write(member, idempotent, correlationId, async (tx, states) => {
          const held = await challenges.hold(tx, member.sessionId);
          const { orgId } = member;
          const { found, version, registration } = await waitingFor(tx, states, member, supplierId, 'change');
          const current = await work.versionIn(tx, states, orgId, found.supplier.id, found.supplier.currentVersionId);
          const consumed = await challenges.consume(
            tx,
            held,
            stepUpChallengeId,
            { sessionId: member.sessionId, action: PAYEE_APPROVE_OPERATION, changeHash: approvalHash(version.id) },
            // An admin's change: proved with a passkey (SEC-HA-12).
            { passkeyRequired: true },
          );
          if (consumed === undefined) throw new SupplierRefused(403, 'STEP_UP_FAILED');
          await confirmPayeeChange(
            tx,
            states,
            { orgId, id: found.supplier.id },
            found,
            { version, registration, current },
            {
              actor: { type: 'user', id: member.userId },
              details: stepUpDetails(consumed),
              coolingOffUntil: new Date(clock.now().getTime() + PAYEE_COOLING_OFF_MS),
            },
          );
          await outbox.add(tx, toldEveryone(orgId, found.supplier.id, 'supplier_payee_changed'));
          return { status: 200, resourceId: found.supplier.id };
        });
      } catch (error) {
        // 0033's index: another supplier was paid to this payee first. Nothing was kept, the challenge included.
        if (!isPayeeTaken(error)) throw error;
        return { outcome: 'refused', status: 409, code: 'SUPPLIER_PAYEE_TAKEN' };
      }
      return work.changedAfter(member.orgId, correlationId, done);
    },

    async withdraw(member, idempotent, supplierId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, WITHDRAWING_ROLES);
        const found = await work.supplierIn(tx, states, { orgId: member.orgId, id: supplierId }, 'change');
        const { pendingVersionId } = found.supplier;
        if (pendingVersionId === null) throw new SupplierRefused(409, 'SUPPLIER_NO_CHANGE_WAITING');
        await withdrawPayeeChange(tx, states, { orgId: member.orgId, id: found.supplier.id }, found, pendingVersionId, {
          actor: { type: 'user', id: member.userId },
        });
        return { status: 200, resourceId: found.supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },
  };
}
