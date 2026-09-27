// Whether a person is in the 7 days without an admin's or approver's powers
// that follow a second factor removed (domain/removal-restriction.ts; ADR-003
// §4, ADR-012 §8; SEC-OPS-04; B6-3d), read from the platform chain by person,
// so it holds in every organisation they belong to, and from before they
// joined one:
// - every second factor removal the login service's events say someone else
//   made, or the login service itself (`idp.event_copied`, B6-2b), copied
//   whether the person was in an organisation or not: a removal made in
//   Zitadel directly, by its admin, counts as one Agent X made;
// - every reset Agent X carried out (`person.second_factors_removed`,
//   recorded by reset-removals.ts as it completes), since the copier reads the
//   login service's own events a few minutes behind.
//
// Reads only, as the app role. An event deleted to lift a restriction breaks
// the chain, which the anchor check finds (A2b).
import type { Kysely } from 'kysely';

import type { Clock } from '../../../shared-kernel/index.ts';
import { latestPlatformTimeOf, type PlatformControlsTables } from '../../platform-controls/index.ts';
import { SECOND_FACTOR_REMOVED_EVENTS } from '../domain/idp-event.ts';
import { isRestricted, restrictedUntil } from '../domain/removal-restriction.ts';
import { IDP_EVENT_COPIED } from './idp-copier.ts';

/** The platform chain's record of a reset carried out: the person's second factors removed by Agent X. */
export const SECOND_FACTORS_REMOVED = 'person.second_factors_removed';

/** When the person's second factor was last removed, as the restriction counts removals; undefined for never. */
export const lastCountedRemoval = (db: Kysely<PlatformControlsTables>, userId: string): Promise<Date | undefined> => {
  const person = userId.toLowerCase();
  return latestPlatformTimeOf(db, 'at', [
    {
      action: IDP_EVENT_COPIED,
      facts: { person },
      oneOf: { type: SECOND_FACTOR_REMOVED_EVENTS },
      noneOf: { by: ['self'] },
    },
    { action: SECOND_FACTORS_REMOVED, facts: { person } },
  ]);
};

/** Until when a person has no admin's or approver's powers: undefined when they have them. */
export type RemovalRestriction = (userId: string) => Promise<Date | undefined>;

export function createRemovalRestriction({
  database,
  clock,
}: {
  readonly database: Kysely<PlatformControlsTables>;
  readonly clock: Clock;
}): RemovalRestriction {
  return async (userId) => {
    const removedAt = await lastCountedRemoval(database, userId);
    return removedAt !== undefined && isRestricted(removedAt, clock.now()) ? restrictedUntil(removedAt) : undefined;
  };
}
