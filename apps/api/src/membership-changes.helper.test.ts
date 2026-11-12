// A member deactivated, or their role changed, as the product does it: the membership read for
// the change, then its grant summary, both moved on together (OR1). Since 0089 (OR1b) the
// database refuses a membership moved past its summary, so a test that needs a member gone or
// changed, without going through the route, comes here rather than to the signed states alone.
import {
  type AuditActor,
  type AuditTables,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  changeMembershipRole,
  deactivateMembership,
  grantsBelieved,
  grantsToChange,
  type IdentityTables,
  memberOf,
  type Role,
} from '@agentx/core/modules/identity';
import type { Database } from '@agentx/platform/db';

/** The tables a membership's change reaches. */
type Db = Database<IdentityTables & DirectoryTables & AuditTables>;

/** The membership's key: its organisation and its ID. */
interface MembershipKey {
  readonly orgId: string;
  readonly id: string;
}

/** The membership and its summary read for a change, in their lock order (ADR-006 §6, 2a). */
async function readForChange(
  db: Db,
  services: SignedStatesServices,
  key: MembershipKey,
  actor: AuditActor,
  change: 'deactivate' | Role,
): Promise<void> {
  await withSignedStates(db, key.orgId, services, async (tx, states) => {
    const found = await memberOf(tx, states, key, 'change');
    if (found.outcome !== 'found') throw new Error(`the membership reads as ${found.outcome}`);
    const grants = grantsBelieved(await grantsToChange(tx, states, key));
    const read = { key, member: found.member, grants, actor, evidence: {} };
    if (change === 'deactivate') await deactivateMembership(tx, states, read);
    else await changeMembershipRole(tx, states, { ...read, state: found.state, roleTo: change });
  });
}

/** The member deactivated by `actor`, as the product deactivates one. */
export const deactivatedAsTheProduct = (
  db: Db,
  services: SignedStatesServices,
  key: MembershipKey,
  actor: AuditActor,
): Promise<void> => readForChange(db, services, key, actor, 'deactivate');

/** The member's role changed to `roleTo` by `actor`, as the product changes one. */
export const roleChangedAsTheProduct = (
  db: Db,
  services: SignedStatesServices,
  key: MembershipKey,
  roleTo: Role,
  actor: AuditActor,
): Promise<void> => readForChange(db, services, key, actor, roleTo);
