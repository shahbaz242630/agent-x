// After a second factor is removed (ADR-003 §4: "a cooling-off period before
// the recovered admin can make privileged changes"; ADR-012 §8; SEC-OPS-04;
// B6-3d): for 7 days the person has no admin's or finance approver's powers,
// in any organisation, keeping only what a developer or a viewer may do. A
// reset asked for by social engineering, or a factor removed at the login
// service behind Agent X's back, so can't hand anyone an admin's powers
// before the people told have had time to stop it.
//
// A factor the person removed themselves, signed in with their second factor,
// doesn't count: they were already who they said, and an admin changing a
// lost security key for a new one isn't locked out of their organisation.

/** How long after a second factor is removed the person has no admin's or approver's powers. */
export const REMOVAL_RESTRICTION_DAYS = 7;

const DAY_MS = 86_400_000;

/** When the restriction from a removal at `removedAt` ends. */
export const restrictedUntil = (removedAt: Date): Date =>
  new Date(removedAt.getTime() + REMOVAL_RESTRICTION_DAYS * DAY_MS);

/** Whether a person whose latest counted removal was at `removedAt` (none: undefined) is restricted at `now`: strictly before its end. */
export const isRestricted = (removedAt: Date | undefined, now: Date): boolean =>
  removedAt !== undefined && now.getTime() < restrictedUntil(removedAt).getTime();
