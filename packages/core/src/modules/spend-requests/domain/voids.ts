// Why a pending spend request is void (PRD §4.2, §11; BR-09, BR-11; Phase 3
// C1; partner decision 4): the authority it was decided under no longer
// stands. Its agent suspended, its mandate no longer in force or superseded
// (a new version accepted), its source unable to fund, or its supplier no
// longer verified or its details changed (a new version). Not the limits or
// the policies: an approval weighs those again (B4b), and a request already
// approved keeps its place under them.
//
// Each cause found is kept with the void, in the order the engine checks
// them; none and the request stands.
import type { ReasonCode } from '../../../shared-kernel/index.ts';
import type { SpendRequestStatus } from './spend-request.ts';

/** The statuses a request holds capacity in before hand-off: each one a cascade ends (0046's index). */
export const PENDING_STATUSES = [
  'APPROVAL_REQUIRED',
  'APPROVED',
  'INSTRUCTION_READY',
] as const satisfies readonly SpendRequestStatus[];

/** What a request was decided under, as its signed state names it. */
export interface DecidedUnder {
  readonly mandateId: string | null;
  readonly mandateVersionId: string | null;
  readonly supplierVersionId: string | null;
}

/** The authority behind it as it now stands, each read through its signed state: none for one not found. */
export interface AuthorityNow {
  readonly agentStatus: string;
  readonly mandate: { readonly status: string; readonly currentVersionId: string | null } | null;
  readonly sourceMayFund: boolean;
  readonly supplier: { readonly status: string; readonly currentVersionId: string } | null;
}

/** Why the request is void, the engine's order; empty while its authority stands. */
export function voidCauses(decided: DecidedUnder, now: AuthorityNow): readonly ReasonCode[] {
  const causes: ReasonCode[] = [];
  if (now.agentStatus !== 'ACTIVE') causes.push('AGENT_SUSPENDED');
  const { mandate, supplier } = now;
  if (
    decided.mandateId === null ||
    mandate?.status !== 'ACTIVE' ||
    mandate.currentVersionId !== decided.mandateVersionId
  ) {
    causes.push('MANDATE_NOT_IN_FORCE');
  }
  if (!now.sourceMayFund) causes.push('SOURCE_NOT_USABLE');
  if (supplier?.status !== 'VERIFIED') causes.push('SUPPLIER_NOT_VERIFIED');
  if (supplier !== null && supplier.currentVersionId !== decided.supplierVersionId) causes.push('SUPPLIER_CHANGED');
  return causes;
}
