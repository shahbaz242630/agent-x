// A spend request approved by a person while it waits (PRD §4.2, §7.2;
// BR-09, BR-10; ADR-006 §6, §10; partner decision 1; Phase 3 B4b): APPROVED,
// keeping the reservation and order claim its decision made, recorded as the
// person's with their step-up (`spend_request.approved`). The API has weighed
// it again first, in lock order, against the others' holdings
// (spend-request-approvals.ts).
//
// In the caller's transaction (withSignedStates' for the organisation), the
// request read for change and verified (level 8): its reservation and claim
// judged as the holdings check judges them, so nothing is approved on
// capacity changed past the app (the alarm raised by the judging, and nothing
// moved); then the move, signed, which takes the audit head (12). They aren't
// locked: the app changes them only under their request's lock, held here.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Transaction } from 'kysely';

import type { AuditDetails, AuditTables, SignedStates } from '../../audit/index.ts';
import type { LimitReservationsTables } from '../../limit-reservations/index.ts';
import { movedAsRead } from '../../../shared-kernel/index.ts';
import { NO_PAYMENTS, requestHoldingsWhole } from './holdings-check.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

/** A person's approval (partner decision 1): who, and the step-up they proved it with. */
export interface Approval {
  readonly userId: string;
  /** The step-up's evidence, with the policy versions the API weighed it under. */
  readonly stepUp: AuditDetails;
}

/**
 * Approves the request, read for change in this transaction while it waits:
 * `approved`, or `mismatch` when its holdings don't match its decision (the
 * alarm raised, nothing moved: the caller refuses).
 */
export async function approveRequest(
  tx: Transaction<SpendRequestsTables & AuditTables & LimitReservationsTables>,
  states: SignedStates,
  keys: KeyProvider,
  key: { readonly orgId: string; readonly id: string },
  approval: Approval,
): Promise<'approved' | 'mismatch'> {
  // Waiting for approval: never handed off.
  if (!(await requestHoldingsWhole(tx, states, keys, key.orgId, key.id, NO_PAYMENTS))) return 'mismatch';
  const moved = await states.changeStatus(tx, SPEND_REQUESTS, key, 'approve', {
    actor: { type: 'user', id: approval.userId },
    action: 'spend_request.approved',
    details: approval.stepUp,
  });
  movedAsRead(moved, "A spend request read as waiting didn't approve");
  return 'approved';
}
