// How long a request waits for approval before it expires (PRD §4.2; BR-09;
// partner decision 10, then 15 and 20, Phase 3 E6): the organisation chooses
// 24, 48 or 72 hours, 72 the ceiling and what one that hasn't chosen waits.
// Each request waits what was in force when it was decided, sealed on its
// decided event (decision 20: a lowered wait expires none already waiting,
// and the time its approvers were shown never moves). One decided before E6
// sealed none: it waits 72 hours, the rule then. Its hours run from its
// decision's sealed time (E4b): a carry moves no clock.
import { HOUR_MS } from '../../../shared-kernel/index.ts';

/** The waits an organisation may choose, in hours. */
export const APPROVAL_WAITS = [24, 48, 72] as const;
export type ApprovalWaitHours = (typeof APPROVAL_WAITS)[number];

/** The longest wait: the ceiling, and what a request decided before E6 (or under no choice) waits. */
export const LONGEST_APPROVAL_WAIT: ApprovalWaitHours = 72;

/** The shortest wait: no request decided more recently than this has waited out (the expiry job's first look). */
export const SHORTEST_APPROVAL_WAIT_MS = APPROVAL_WAITS[0] * HOUR_MS;

/** A waiting request's clock: when its decision was sealed, and the wait it sealed. */
export interface ApprovalClock {
  readonly decidedAt: Date;
  readonly waitHours: ApprovalWaitHours;
}

const isApprovalWait = (value: unknown): value is ApprovalWaitHours => APPROVAL_WAITS.some((hours) => hours === value);

/**
 * The wait a decided event's details sealed (`approvalWaitHours`): 72 for one
 * that sealed none (before E6). Any other value is no choice ever offered, on
 * an event the chain vouches for: a bug, so it throws rather than guess.
 */
export function approvalWaitOf(details: Readonly<Record<string, unknown>> | undefined): ApprovalWaitHours {
  const sealed = details?.approvalWaitHours;
  if (sealed === undefined) return LONGEST_APPROVAL_WAIT;
  if (!isApprovalWait(sealed))
    throw new Error(`A decided event sealed an approval wait never offered: ${JSON.stringify(sealed)}`);
  return sealed;
}

/** When a waiting request expires: its decision's sealed time and its wait. */
export const expiresAtOf = ({ decidedAt, waitHours }: ApprovalClock): Date =>
  new Date(decidedAt.getTime() + waitHours * HOUR_MS);

/** Whether a waiting request has waited for approval as long as it may. */
export const waitedOut = (clock: ApprovalClock, now: Date): boolean => expiresAtOf(clock).getTime() <= now.getTime();
