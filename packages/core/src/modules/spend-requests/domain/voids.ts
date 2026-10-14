// Why a pending spend request is void (PRD §4.2, §11; BR-09, BR-11; Phase 3
// C1; partner decisions 4, 7 and 10): the authority it was decided under no
// longer stands. Its organisation frozen, its agent suspended, its mandate no longer in force or
// superseded (a new version accepted), its source unable to fund, or its
// supplier no longer verified or its details changed (a new version). Not the
// limits or the policies: an approval weighs those again (B4b), and a request
// already approved keeps its place under them.
//
// A suspension is the suspender's choice (decision 7), and so is a freeze
// (decision 10, D1): one that cancels voids as any stop does; one that pauses
// voids nothing, its requests standing again on resume or unfreeze. The bank's own suspension of a source (its availability
// SUSPENDED) pauses, by the same decision: nobody on the team chose it.
// Consent the bank ended (revoked, expired, consumed or rejected: its
// availability UNAVAILABLE) or past its end, a revoke, an expiry, a
// supersede, an ended source and a supplier no longer verified always void,
// but for one a payee registration unverified with its requests paused, as the
// registering admin chose (decision 8): its requests stand again once it is
// verified again, and a new payee made current voids them (a new version).
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

/** What a suspension does to the pending requests of what it suspends, as the suspender chose (decision 7). */
export const PENDING_CHOICES = ['cancel', 'pause'] as const;
export type PendingChoice = (typeof PENDING_CHOICES)[number];

export const isPendingChoice = (value: unknown): value is PendingChoice =>
  (PENDING_CHOICES as readonly unknown[]).includes(value);

/** What a request's authority is made of, each of which may be stopped with its requests paused. */
export type Pausable = 'organization' | 'agent' | 'mandate' | 'source' | 'supplier';

/** The statuses each may be stopped in with its requests paused: a supplier unverified by a payee registration too. */
export const PAUSED_IN = {
  organization: ['FROZEN'],
  agent: ['SUSPENDED'],
  mandate: ['SUSPENDED'],
  source: ['SUSPENDED'],
  supplier: ['SUSPENDED', 'UNVERIFIED'],
} as const satisfies Record<Pausable, readonly string[]>;

/** What a request was decided under, as its signed state names it. */
export interface DecidedUnder {
  readonly mandateId: string | null;
  readonly mandateVersionId: string | null;
  readonly supplierVersionId: string | null;
}

/** The authority behind it as it now stands, each read through its signed state: none for one not found. */
export interface AuthorityNow {
  readonly organizationStatus: string;
  readonly agentStatus: string;
  readonly mandate: { readonly status: string; readonly currentVersionId: string | null } | null;
  /** Its own status, the bank's word on it (its availability), and whether its consent has run out. */
  readonly source: { readonly status: string; readonly availability: string; readonly consentPast: boolean };
  readonly supplier: { readonly status: string; readonly currentVersionId: string } | null;
  /** Those stopped with their requests paused, as the freeze, suspension (or a supplier's unverify) in force chose. */
  readonly paused: ReadonlySet<Pausable>;
}

/** Why the request is void, the engine's order; empty while its authority stands. */
export function voidCauses(decided: DecidedUnder, now: AuthorityNow): readonly ReasonCode[] {
  // Stopped: not as it must be, unless stopped with its requests paused.
  const stopped = (status: string, standing: string, which: Pausable) =>
    status !== standing && !((PAUSED_IN[which] as readonly string[]).includes(status) && now.paused.has(which));
  const causes: ReasonCode[] = [];
  if (stopped(now.organizationStatus, 'ACTIVE', 'organization')) causes.push('ORG_FROZEN');
  if (stopped(now.agentStatus, 'ACTIVE', 'agent')) causes.push('AGENT_SUSPENDED');
  const { mandate, source, supplier } = now;
  if (
    decided.mandateId === null ||
    mandate === null ||
    stopped(mandate.status, 'ACTIVE', 'mandate') ||
    mandate.currentVersionId !== decided.mandateVersionId
  ) {
    causes.push('MANDATE_NOT_IN_FORCE');
  }
  // The bank's suspension pauses; any other word of its but ACTIVE ends the consent.
  const bankEnded = source.availability !== 'ACTIVE' && source.availability !== 'SUSPENDED';
  if (stopped(source.status, 'ACTIVE', 'source') || bankEnded || source.consentPast) causes.push('SOURCE_NOT_USABLE');
  if (supplier === null || stopped(supplier.status, 'VERIFIED', 'supplier')) causes.push('SUPPLIER_NOT_VERIFIED');
  if (supplier !== null && supplier.currentVersionId !== decided.supplierVersionId) causes.push('SUPPLIER_CHANGED');
  return causes;
}
