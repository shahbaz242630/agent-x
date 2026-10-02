// A refusal inside a write: thrown, so the claim and all the write roll back,
// and caught at the write's edge into its status and code. Each write keeps
// its own subclass, so its catch takes only its own refusals.
import type { ReasonCode } from '../../../shared-kernel/index.ts';
import type { SignedStates } from '../../audit/index.ts';
import { membershipOf, type MembershipsTransaction } from './memberships.ts';

export class Refusal extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(message: string, status: number, code: ReasonCode) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/**
 * The admin's membership, read again for this write's decision: its ID, or
 * the write's own refusal (503 if tampered with, 403 if not an active admin).
 */
export async function activeAdminId(
  tx: MembershipsTransaction,
  states: SignedStates,
  admin: { readonly orgId: string; readonly userId: string },
  Refused: new (status: number, code: ReasonCode) => Refusal,
): Promise<string> {
  const membership = await membershipOf(tx, states, admin.orgId, admin.userId);
  if (membership.outcome === 'tampered') throw new Refused(503, 'INTEGRITY_FAILED');
  if (membership.outcome !== 'active' || membership.role !== 'admin') throw new Refused(403, 'FORBIDDEN');
  return membership.id;
}
