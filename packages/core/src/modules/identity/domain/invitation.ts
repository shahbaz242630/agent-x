// An invitation (ADR-005 §6, PRD §7.1 `POST /v1/members/invitations`): an
// admin asks for a person, by their email address, to join the organisation
// with one of its four roles.
//
// It starts as a DRAFT, the pending change the admin's step-up binds to
// (ADR-003 §9), and opens (DRAFT>OPEN) once the step-up is consumed, when its
// token is made and shown to the admin once. It ends a fixed time after it was
// asked for, whatever its status. Accepted (B4-4b, 0018) by the person whose
// verified email it names: a developer or viewer joins at once (OPEN>ACCEPTED);
// an admin or finance approver waits for an existing admin to confirm who
// accepted (OPEN>AWAITING_CONFIRMATION, then ACCEPTED or DECLINED; ADR-005 §6).
// The database's status guard holds the same moves (0018).
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const INVITATION = defineStateMachine({
  name: 'invitation',
  states: ['DRAFT', 'OPEN', 'AWAITING_CONFIRMATION', 'ACCEPTED', 'DECLINED'],
  initial: 'DRAFT',
  events: {
    open: { from: ['DRAFT'], to: 'OPEN' },
    accept: { from: ['OPEN'], to: 'ACCEPTED' },
    await: { from: ['OPEN'], to: 'AWAITING_CONFIRMATION' },
    confirm: { from: ['AWAITING_CONFIRMATION'], to: 'ACCEPTED' },
    decline: { from: ['AWAITING_CONFIRMATION'], to: 'DECLINED' },
  },
});

/** The roles an existing admin must confirm, with step-up, before anyone holds them (ADR-005 §6). */
export const CONFIRMED_ROLES = ['admin', 'approver'] as const;

/** Whether a role waits for an admin's confirmation when its invitation is accepted. */
export const needsConfirmation = (role: string): boolean => CONFIRMED_ROLES.some((each) => each === role);

/** How long an invitation lasts from when it was asked for: short (ADR-005 §6), and long enough to reach someone over a weekend. */
export const INVITATION_HOURS = 72;

/** When an invitation asked for at `createdAt` ends. */
export const invitationEnds = (createdAt: Date): Date => new Date(createdAt.getTime() + INVITATION_HOURS * 3_600_000);

/** The longest email address there is (RFC 5321's path limit, less its brackets). */
export const EMAIL_MAX = 254;

/**
 * The address as an invitation keeps and compares it: in lower case, as the
 * login service compares a verified address. Undefined for anything that
 * isn't one address of at most 254 characters with one `@` between a local
 * part and a domain, and no spaces or control characters. The API's own
 * check is stricter; this is the module's floor.
 */
export function invitationEmail(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > EMAIL_MAX || !value.isWellFormed()) return undefined;
  // eslint-disable-next-line no-control-regex -- Refusing control characters is the point.
  if (/[\s\u0000-\u001f\u007f]/.test(value)) return undefined;
  const at = value.indexOf('@');
  if (at < 1 || at !== value.lastIndexOf('@') || at === value.length - 1) return undefined;
  return value.toLowerCase();
}
