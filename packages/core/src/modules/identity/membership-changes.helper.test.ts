// A member deactivated, or their role changed, as the product does it: the membership read for
// the change, then its grant summary, both moved on together (OR1). Since 0089 (OR1b) the
// database refuses a membership moved past its summary, so a test that needs a member gone or
// changed, without going through the route, comes here rather than to the signed states alone.
import { type SignedStatesServices, withSignedStates } from '../audit/index.ts';
import type { Role } from './domain/membership.ts';
import { grantsBelieved, grantsToChange } from './infrastructure/membership-grants.ts';
import {
  changeMembershipRole,
  deactivateMembership,
  memberOf,
  type MembershipChangeRead,
  type MembershipsTransaction,
} from './infrastructure/memberships.ts';
import type { AuditActor, AuditTables, SignedStates, VerifiedState } from '../audit/index.ts';
import type { Kysely } from 'kysely';
import type { DirectoryTables } from '../directory/index.ts';
import type { IdentityTables } from './infrastructure/tables.ts';

type Tables = IdentityTables & DirectoryTables & AuditTables;

/** The membership and its summary read for a change, in their lock order, then `change` made from them. */
function changed(
  db: Kysely<Tables>,
  services: SignedStatesServices,
  key: { readonly orgId: string; readonly id: string },
  actor: AuditActor,
  change: (
    tx: MembershipsTransaction,
    states: SignedStates,
    read: MembershipChangeRead & { readonly state: VerifiedState },
  ) => Promise<void>,
): Promise<void> {
  return withSignedStates(db, key.orgId, services, async (tx, states) => {
    const found = await memberOf(tx, states, key, 'change');
    if (found.outcome !== 'found') throw new Error(`the membership reads as ${found.outcome}`);
    const grants = grantsBelieved(await grantsToChange(tx, states, key));
    await change(tx, states, { key, member: found.member, grants, actor, evidence: {}, state: found.state });
  });
}

/** The member deactivated by `actor`, as the product deactivates one. */
export const deactivatedAsTheProduct = (
  db: Kysely<Tables>,
  services: SignedStatesServices,
  key: { readonly orgId: string; readonly id: string },
  actor: AuditActor,
): Promise<void> => changed(db, services, key, actor, (tx, states, read) => deactivateMembership(tx, states, read));

/** The member's role changed to `roleTo` by `actor`, as the product changes one. */
export const roleChangedAsTheProduct = (
  db: Kysely<Tables>,
  services: SignedStatesServices,
  key: { readonly orgId: string; readonly id: string },
  roleTo: Role,
  actor: AuditActor,
): Promise<void> =>
  changed(db, services, key, actor, (tx, states, read) => changeMembershipRole(tx, states, { ...read, roleTo }));
