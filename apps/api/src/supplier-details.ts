// A supplier's details changed (ADR-012 §1: "supplier contact changes are
// sensitive too: step-up, notification to everyone, and the supplier becomes
// unverified"; SEC-PAY-07; Phase 1 E3-2b): its name, contacts or independent
// source, never its payee, which changes only through the partner (E2).
//
// - `change` (`suppliers.details`), an admin (they add suppliers, partner
//   S69), with the new details: the key claimed; the organisation's supplier
//   lock and the day's budget; the admin read again; the supplier, with no
//   change waiting (SUPPLIER_CHANGE_WAITING: its payee's change follows the
//   current version) and details that differ from its current ones
//   (SUPPLIER_DETAILS_UNCHANGED: a change that changes nothing would only
//   unverify it); a challenge bound to the current version and the new
//   details, so the passkey confirms exactly them.
// - `changeConfirm` (`suppliers.details.confirm`), with the challenge and the
//   same details: the same reads with the supplier for change, the challenge
//   consumed with a passkey (SEC-HA-12), then the new version made current,
//   entered by this admin, the supplier UNVERIFIED (the suppliers module's
//   changeDetails), and `supplier_details_changed` written for every active
//   member and the counting contacts, in the same transaction.
//
// Its pending requests, as the admin chose (decision 15, E3; no default,
// bound into the step-up and kept on the change's events): `cancel` DENIES
// them first whatever the supplier's status (voidPendingOf, Phase 3 C3), the
// request-voids job taking any past the batch; `pause` holds them, carried to
// the new version (pausedFromOf), so they stand again once a second person
// verifies the supplier, a waiting one still re-checked by its approver
// (decision 16, E5). A pause over an UNVERIFIED supplier whose stop cancels
// voids those the job hasn't reached first, refused at the ask and the
// confirm (PENDING_REQUESTS_TOO_MANY) past what one brake voids, so it never
// carries what that stop cancelled (as C3e's suspend).
//
// Every version is kept for good, so the organisation may enter at most 200
// changes of its suppliers a day: payee registrations (100 a day of their
// own) and details changes; never counting a supplier added (the B8-1
// lesson; E3-2b's review).
//
// Lock order (ADR-006 §6): the idempotency key, the supplier lock, the
// member's membership (2a), the supplier (6), its version, the step-up
// challenge, the pending requests (8) and their holdings (11), the chain head
// with the first event recorded, then the notices.
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { Outbox } from '@agentx/core/modules/notifications';
import { pendingPastABrake, type PendingChoice, voidPendingOf } from '@agentx/core/modules/spend-requests';
import {
  changeDetails,
  nextVersionNumber,
  oneSupplierAddAtATime,
  changesEnteredSince,
  type SupplierDetails,
} from '@agentx/core/modules/suppliers';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { ADDING_ROLES } from './supplier-registry.ts';
import {
  createSupplierWork,
  type SessionMember,
  type SupplierChangeWrite,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
  toldEveryone,
} from './supplier-work.ts';
import { DETAILS_STATEMENT_VERSION, detailsChoiceDetails, pausedOf } from './suspensions.ts';
import { createStepUps } from './use-case-work.ts';

/** Asking to change a supplier's details: its operation, which the step-up challenge names as its action too. */
export const DETAILS_OPERATION = 'suppliers.details';
/** Changing them, once stepped up. */
export const DETAILS_CONFIRM_OPERATION = 'suppliers.details.confirm';

/** The most changes of its suppliers an organisation may enter in any 24 hours: payee registrations' 100 and as many details changes. */
export const MOST_CHANGES_A_DAY = 200;

/** The new details, and the admin's choice for the supplier's pending requests (decision 15). */
interface DetailsChange {
  readonly details: SupplierDetails;
  readonly pendingRequests: PendingChoice;
}

export interface SupplierDetailsChanges {
  change(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    change: DetailsChange,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  changeConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    confirm: DetailsChange & { readonly stepUpChallengeId: string },
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
}

/** The details as a list of their fields, in one order, none left out: what a change is compared and bound by. */
const fieldsOf = ({ displayName, contacts, source }: SupplierDetails): string[] => [
  displayName,
  contacts.phone,
  contacts.email ?? '',
  contacts.tradeLicence ?? '',
  source.kind,
  source.ref,
];

/**
 * The change's SHA-256: the version it follows, its ID in lower case, every
 * field of the new details, and the choice with the version of its words.
 * That version is the supplier's own, read from its signed state inside the
 * organisation's walls, so it names the organisation, the supplier and
 * exactly the details and choice confirmed.
 */
const changeHash = (versionId: string, { details, pendingRequests }: DetailsChange): Buffer =>
  changeHashOf([
    DETAILS_OPERATION,
    versionId.toLowerCase(),
    ...fieldsOf(details),
    pendingRequests,
    String(DETAILS_STATEMENT_VERSION),
  ]);

export function createSupplierDetailsChanges({
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
}): SupplierDetailsChanges {
  const work = createSupplierWork({ database, keys, ids, logger });
  const stepUps = createStepUps({ challenges, Refusal: SupplierRefused });

  /**
   * Whether this admin may change the supplier's details as `change` asks
   * now, read in the write's transaction (the supplier `lock`ed as asked),
   * after the caller took the add lock (oneSupplierAddAtATime) first: the
   * admin, the supplier and its current version, and whether a pause must
   * void first what an UNVERIFIED supplier's stop cancelled (refused past
   * what one brake voids); or a refusal thrown.
   */
  const changeable = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SessionMember,
    supplierId: string,
    { details, pendingRequests }: DetailsChange,
    lock: 'share' | 'change',
    correlationId: string,
  ) => {
    const { orgId } = member;
    const since = new Date(clock.now().getTime() - DAY_MS);
    if ((await changesEnteredSince(tx, orgId, since)) >= MOST_CHANGES_A_DAY) {
      throw new SupplierRefused(409, 'SUPPLIER_CHANGES_SPENT');
    }
    const admin = await work.memberIn(tx, states, member, ADDING_ROLES);
    const found = await work.supplierIn(tx, states, { orgId, id: supplierId }, lock);
    if (found.supplier.pendingVersionId !== null) throw new SupplierRefused(409, 'SUPPLIER_CHANGE_WAITING');
    const current = await work.versionIn(tx, states, orgId, found.supplier.id, found.supplier.currentVersionId);
    const currentFields = fieldsOf({ ...current, contacts: await work.contactsIn(tx, orgId, current, correlationId) });
    if (fieldsOf(details).every((field, at) => field === currentFields[at])) {
      throw new SupplierRefused(409, 'SUPPLIER_DETAILS_UNCHANGED');
    }
    const cancelledBefore =
      pendingRequests === 'pause' &&
      found.supplier.status === 'UNVERIFIED' &&
      !(await pausedOf(tx, states, orgId, [['supplier', found.supplier.id, 'UNVERIFIED']])).has('supplier');
    if (cancelledBefore && (await pendingPastABrake(tx, orgId, { supplierId: found.supplier.id }))) {
      throw new SupplierRefused(409, 'PENDING_REQUESTS_TOO_MANY');
    }
    return { admin, found, current, cancelledBefore };
  };

  return {
    async change(member, idempotent, supplierId, change, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await oneSupplierAddAtATime(tx, member.orgId);
        const { current } = await changeable(tx, states, member, supplierId, change, 'share', correlationId);
        return stepUps.ask(tx, member, { action: DETAILS_OPERATION, changeHash: changeHash(current.id, change) });
      });
      return work.askedAfter(done);
    },

    async changeConfirm(member, idempotent, supplierId, { stepUpChallengeId, ...change }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await oneSupplierAddAtATime(tx, member.orgId);
        const held = await challenges.hold(tx, member.sessionId);
        const { orgId } = member;
        const { admin, found, current, cancelledBefore } = await changeable(
          tx,
          states,
          member,
          supplierId,
          change,
          'change',
          correlationId,
        );
        const consumed = await stepUps.consumed(
          tx,
          member,
          held,
          stepUpChallengeId,
          { action: DETAILS_OPERATION, changeHash: changeHash(current.id, change) },
          { passkeyRequired: true },
        );
        const braked = { supplierId: found.supplier.id };
        if (change.pendingRequests === 'cancel') {
          await voidPendingOf(tx, states, keys, orgId, braked, 'SUPPLIER_CHANGED', clock.now());
        } else if (cancelledBefore) {
          await voidPendingOf(tx, states, keys, orgId, braked, 'SUPPLIER_NOT_VERIFIED', clock.now());
        }
        await changeDetails(tx, states, keys, { orgId, id: found.supplier.id }, found, {
          orgId,
          id: ids.next(),
          supplierId: found.supplier.id,
          version: await nextVersionNumber(tx, orgId, found.supplier.id),
          supplier: change.details,
          enteredBy: admin.id,
          enteredAt: clock.now(),
          actor: { type: 'user', id: member.userId },
          details: { ...stepUpDetails(consumed), ...detailsChoiceDetails(change.pendingRequests) },
          follows: current,
        });
        await outbox.add(tx, toldEveryone(orgId, found.supplier.id, 'supplier_details_changed'));
        return { status: 200, resourceId: found.supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },
  };
}
