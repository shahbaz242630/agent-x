// Why a pending spend request is void (PRD §4.2, §11; BR-09, BR-11; Phase 3
// C1; partner decisions 4, 7 and 10): the authority it was decided under no
// longer stands. Its organisation frozen, its agent suspended, its mandate no longer in force,
// past its version's end (whether or not the expiry job has recorded it yet: SEC-AG-12) or
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
// availability UNAVAILABLE) or past its end voids too, but for consent that
// ran out on a source whose admin chose to hold its requests until it is
// renewed (decision 21, E7): they stand again once it is. A revoke, an expiry, a
// supersede, an ended source and a supplier no longer verified always void,
// but for one a payee registration unverified with its requests paused, as the
// registering admin chose (decision 8): its requests stand again once it is
// verified again, and a new payee made current voids them (a new version).
// New details void them too, unless the admin changing them chose to pause
// (decision 15, E3): a request decided under a version the current one
// carries from stands once the supplier is verified again; its status is
// judged as ever meanwhile.
//
// A stop chosen to cancel voids for good (decision 32a, F1 G1): a request
// decided before it stays void once what was stopped stands again, its brake
// having voided only a batch, the request-voids job the rest. A pause, or a
// reactivation that names no cancel, never does.
//
// An approval stands APPROVAL_HORIZON_MS unpaid (AT13d, partner decision of 21
// Nov; R-15): past it the request is void (APPROVAL_LAPSED), and the agent asks
// again with a new request. Its age runs from its approval as the audit chain
// sealed it (the newest of its decided and approved events: a person's approval,
// or the policy's own at its decision), never a row's column, to the time it is
// judged; one still waiting for approval has none, and expires by its own wait.
// So no version of a request older than the horizon can be handed off, which is
// what lets the signed states' digest forget its request past it.
//
// Each cause found is kept with the void, in the order the engine checks
// them; none and the request stands.
import { DAY_MS, type ReasonCode } from '../../../shared-kernel/index.ts';
import type { SpendRequestStatus } from './spend-request.ts';

/** The statuses a request holds capacity in before hand-off: each one a cascade ends (0046's index). */
export const PENDING_STATUSES = [
  'APPROVAL_REQUIRED',
  'APPROVED',
  'INSTRUCTION_READY',
] as const satisfies readonly SpendRequestStatus[];

/** Whether a request is pending: holding capacity before hand-off. */
export const isPending = (status: SpendRequestStatus): boolean =>
  (PENDING_STATUSES as readonly string[]).includes(status);

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

/**
 * How long an approval stands unpaid (AT13d): long enough for a hand-off held by a pause of a few days, short enough
 * that the digest needn't keep a request's facts for good (R-15).
 */
export const APPROVAL_HORIZON_MS = 7 * DAY_MS;

/** Whether an approval sealed at `approvedAt` has lapsed by `at`: at the horizon exactly it has, erring on refusing. */
export const approvalLapsed = (approvedAt: Date, at: Date): boolean =>
  at.getTime() - approvedAt.getTime() >= APPROVAL_HORIZON_MS;

/** What a request was decided under, as its signed state names it. */
export interface DecidedUnder {
  readonly mandateId: string | null;
  readonly mandateVersionId: string | null;
  readonly supplierVersionId: string | null;
  /**
   * When it was approved, as the chain sealed it (its newest decided or approved event, Postgres's clock): null while
   * it waits for approval, which has no approval to age.
   */
  readonly approvedAt: Date | null;
}

/** The authority behind it as it now stands, each read through its signed state: none for one not found. */
export interface AuthorityNow {
  readonly organizationStatus: string;
  readonly agentStatus: string;
  /**
   * Its status and version in force, whether that one still carries
   * requests from older versions (Phase 4 A3, PL-47: an acceptance that
   * carried past 20, its rest waiting for the carry job), and whether that
   * one has reached its end (SEC-AG-12, 6F1 G3): ended by the clock whatever
   * its status says until the expiry job records it.
   */
  readonly mandate: {
    readonly status: string;
    readonly currentVersionId: string | null;
    readonly carriesRest?: boolean;
    readonly ended: boolean;
  } | null;
  /**
   * Its own status, the bank's word on it (its availability), whether its
   * consent has run out, and whether its admin chose to hold its requests
   * when it does (decision 21, E7).
   */
  readonly source: {
    readonly status: string;
    readonly availability: string;
    readonly consentPast: boolean;
    readonly consentHeld: boolean;
  };
  /**
   * Its status and current version, and the versions that one carries
   * requests from: each moved on from by a details change chosen to pause
   * (decision 15, E3).
   */
  readonly supplier: {
    readonly status: string;
    readonly currentVersionId: string;
    readonly pausedFrom: readonly string[];
  } | null;
  /** Those stopped with their requests paused, as the freeze, suspension (or a supplier's unverify) in force chose. */
  readonly paused: ReadonlySet<Pausable>;
  /** Those stopped since the request's decision by a stop chosen to cancel, whatever they are now (F1 G1). */
  readonly cancelledBy: ReadonlySet<Pausable>;
  /** When it is judged (the app's clock): what an approval's age runs to (AT13d). */
  readonly at: Date;
}

/** Every cause a void may give, in the engine's order: what the voids' marks must each answer (4D2e D9). */
export const VOID_CAUSES = [
  'ORG_FROZEN',
  'AGENT_SUSPENDED',
  'MANDATE_NOT_IN_FORCE',
  'SOURCE_NOT_USABLE',
  'SUPPLIER_NOT_VERIFIED',
  'SUPPLIER_SUSPENDED',
  'SUPPLIER_CHANGED',
  'APPROVAL_LAPSED',
] as const satisfies readonly ReasonCode[];
export type VoidCause = (typeof VOID_CAUSES)[number];

/** Why the request is void, the engine's order; empty while its authority stands. */
export function voidCauses(decided: DecidedUnder, now: AuthorityNow): readonly VoidCause[] {
  // Stopped: cancelled since its decision, or not as it must be unless stopped with its requests paused.
  const stopped = (status: string, standing: string, which: Pausable) =>
    now.cancelledBy.has(which) ||
    (status !== standing && !((PAUSED_IN[which] as readonly string[]).includes(status) && now.paused.has(which)));
  const causes: VoidCause[] = [];
  if (stopped(now.organizationStatus, 'ACTIVE', 'organization')) causes.push('ORG_FROZEN');
  if (stopped(now.agentStatus, 'ACTIVE', 'agent')) causes.push('AGENT_SUSPENDED');
  const { mandate, source, supplier } = now;
  if (
    decided.mandateId === null ||
    mandate === null ||
    stopped(mandate.status, 'ACTIVE', 'mandate') ||
    mandate.ended ||
    (mandate.currentVersionId !== decided.mandateVersionId &&
      (decided.mandateVersionId === null || mandate.carriesRest !== true))
  ) {
    causes.push('MANDATE_NOT_IN_FORCE');
  }
  // The bank's suspension pauses; any other word of its but ACTIVE ends the consent, but consent run out on a source
  // holding its requests until it is renewed (decision 21): the bank's word then is that expiry (updateFromPartner).
  const bankEnded = source.availability !== 'ACTIVE' && source.availability !== 'SUSPENDED';
  const heldPast = source.consentPast && source.consentHeld;
  if (stopped(source.status, 'ACTIVE', 'source') || (!heldPast && (bankEnded || source.consentPast))) {
    causes.push('SOURCE_NOT_USABLE');
  }
  if (supplier === null || stopped(supplier.status, 'VERIFIED', 'supplier')) {
    // Suspended now is named apart (E6-P5); unknown, unverified or reactivated after a cancelling stop is not verified.
    causes.push(supplier?.status === 'SUSPENDED' ? 'SUPPLIER_SUSPENDED' : 'SUPPLIER_NOT_VERIFIED');
  }
  if (supplier !== null && supplier.currentVersionId !== decided.supplierVersionId) {
    const carried = decided.supplierVersionId !== null && supplier.pausedFrom.includes(decided.supplierVersionId);
    if (!carried) causes.push('SUPPLIER_CHANGED');
  }
  causes.push(...lapsedOf(decided, now));
  return causes;
}

/** APPROVAL_LAPSED for an approval past the horizon by the time it is judged; none for one waiting. */
function lapsedOf({ approvedAt }: DecidedUnder, { at }: AuthorityNow): readonly VoidCause[] {
  return approvedAt !== null && approvalLapsed(approvedAt, at) ? ['APPROVAL_LAPSED'] : [];
}
