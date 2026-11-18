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

import { DAY_MS } from '../../../shared-kernel/index.ts';
import type { Role } from './membership.ts';

/** How long after a second factor is removed the person has no admin's or approver's powers. */
export const REMOVAL_RESTRICTION_DAYS = 7;

/** When the restriction from a removal at `removedAt` ends. */
export const restrictedUntil = (removedAt: Date): Date =>
  new Date(removedAt.getTime() + REMOVAL_RESTRICTION_DAYS * DAY_MS);

/** Whether a person whose latest counted removal was at `removedAt` (none: undefined) is restricted at `now`: strictly before its end. */
export const isRestricted = (removedAt: Date | undefined, now: Date): boolean =>
  removedAt !== undefined && now.getTime() < restrictedUntil(removedAt).getTime();

/**
 * The role a person acts in while kept to what a developer or a viewer may do
 * (6F1 G1): the most of those their own role already holds. An admin holds a
 * developer's powers; an approver a viewer's alone, as an approver registers
 * no agents. A developer or a viewer keeps their own.
 */
export const roleWithoutPowers = (role: Role): Role => {
  if (role === 'admin') return 'developer';
  if (role === 'approver') return 'viewer';
  return role;
};
