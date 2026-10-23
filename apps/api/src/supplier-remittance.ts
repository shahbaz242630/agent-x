// Whether a supplier is emailed when it is paid (Phase 4 C2a; partner
// decision 34b and 34d, S139; Rule Book §1.9): the admin chooses `on` or
// `off` as the supplier is added (supplier-registry.ts), and may change it
// after as the supplier's other details change (decision 34d): with a passkey
// step-up, and every member and counting contact told. Switching it off
// quietly would hide a payment from the supplier, and switching it on sends
// payment facts outside the organisation. Unlike the details, the supplier
// stays as it is, VERIFIED included: the setting never changes who is paid.
//
// - `ask` (`suppliers.remittance-email`), an admin, with the new setting: the
//   key claimed; the admin read again; the supplier; its setting, which must
//   differ (SUPPLIER_REMITTANCE_UNCHANGED: a step-up for nothing); a
//   challenge bound to the setting as it stands and the new one, so the
//   passkey confirms exactly that change.
// - `confirm` (`suppliers.remittance-email.confirm`), with the challenge and
//   the same setting: the same reads with the supplier and its setting for
//   change, so two admins confirming at once take turns; the challenge
//   consumed with a passkey (SEC-HA-12); then the setting, recorded as the
//   admin's with the step-up's evidence (`supplier_remittance.chosen` the
//   first time for a supplier added before 0061, `.changed` after); and
//   `supplier_remittance_changed` written for every active member and the
//   counting contacts, in the same transaction.
//
// Lock order (ADR-006 §6): the idempotency key, the step-up challenge's
// session, the admin's membership (2a), the supplier (6), its setting (6,
// after its versions), the step-up challenge, the chain head, then the
// notices.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { Outbox } from '@agentx/core/modules/notifications';
import { type RemittanceEmail, remittanceOf, setRemittance } from '@agentx/core/modules/suppliers';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  createSupplierWork,
  type SessionMember,
  type SupplierChangeWrite,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
  toldEveryone,
} from './supplier-work.ts';
import { createStepUps } from './use-case-work.ts';

/** Asking to change whether a supplier is emailed when it is paid: its operation, which the step-up names as its action too. */
export const REMITTANCE_OPERATION = 'suppliers.remittance-email';
/** Changing it, once stepped up. */
export const REMITTANCE_CONFIRM_OPERATION = 'suppliers.remittance-email.confirm';

/** Who may change it: the admins, who add suppliers (partner, S69). */
export const REMITTANCE_ROLES = ['admin'] as const;

export interface SupplierRemittance {
  ask(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    remittanceEmail: RemittanceEmail,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  confirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    confirmed: { readonly stepUpChallengeId: string; readonly remittanceEmail: RemittanceEmail },
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
}

/**
 * The change's SHA-256: the supplier, its ID in lower case; the setting's
 * latest event (none for a supplier added before 0061 and never set), so a
 * change confirmed is exactly the one asked from where it stood; and the new
 * setting. Both read inside the organisation's walls, so it names the
 * organisation too.
 */
const changeHash = (supplierId: string, standsAt: string | null, remittanceEmail: RemittanceEmail): Buffer =>
  changeHashOf([REMITTANCE_OPERATION, supplierId.toLowerCase(), standsAt?.toLowerCase() ?? 'unset', remittanceEmail]);

export function createSupplierRemittance({
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
}): SupplierRemittance {
  const work = createSupplierWork({ database, keys, ids, logger });
  const stepUps = createStepUps({ challenges, Refusal: SupplierRefused });

  /**
   * The supplier and its setting, read in the write's transaction (both
   * `lock`ed as asked) after the admin, with the change's hash; or a refusal
   * thrown: INTEGRITY_FAILED for a setting that can't be believed,
   * SUPPLIER_REMITTANCE_UNCHANGED for one already as asked.
   */
  const changeable = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SessionMember,
    supplierId: string,
    remittanceEmail: RemittanceEmail,
    lock: 'share' | 'change',
  ) => {
    await work.memberIn(tx, states, member, REMITTANCE_ROLES);
    const { supplier } = await work.supplierIn(tx, states, { orgId: member.orgId, id: supplierId }, lock);
    const read = await remittanceOf(tx, states, { orgId: member.orgId, supplierId: supplier.id }, lock);
    if (read.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    if (read.remittanceEmail === remittanceEmail) throw new SupplierRefused(409, 'SUPPLIER_REMITTANCE_UNCHANGED');
    const standsAt = read.outcome === 'set' ? read.state.eventId : null;
    return { supplier, read, hash: changeHash(supplier.id, standsAt, remittanceEmail) };
  };

  return {
    async ask(member, idempotent, supplierId, remittanceEmail, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const { hash } = await changeable(tx, states, member, supplierId, remittanceEmail, 'share');
        return stepUps.ask(tx, member, { action: REMITTANCE_OPERATION, changeHash: hash });
      });
      return work.askedAfter(done);
    },

    async confirm(member, idempotent, supplierId, { stepUpChallengeId, remittanceEmail }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const held = await challenges.hold(tx, member.sessionId);
        const { supplier, read, hash } = await changeable(tx, states, member, supplierId, remittanceEmail, 'change');
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: REMITTANCE_OPERATION, changeHash: hash },
          { passkeyRequired: true },
        );
        await setRemittance(tx, states, read, {
          orgId: member.orgId,
          supplierId: supplier.id,
          remittanceEmail,
          at: clock.now(),
          actor: { type: 'user', id: member.userId },
          details: stepUpDetails(consumed),
        });
        await outbox.add(tx, toldEveryone(member.orgId, supplier.id, 'supplier_remittance_changed'));
        return { status: 200, resourceId: supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },
  };
}
