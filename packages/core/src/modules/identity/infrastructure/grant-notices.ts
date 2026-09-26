// Telling an organisation's admins of a role granted (ADR-003 §10; B5-1b): a
// member made an admin or a finance approver, whether by a role change or by
// joining, and anyone rejoining, whatever their role. One notice to the
// organisation's admins, written to the outbox in the change's own
// transaction, so it commits or rolls back with the change.
//
// The change reads no one: the sender finds the active admins, but the member
// it is about, through their signed states in a transaction of its own
// (0021). Verifying every admin here would take locks two changes at once
// could each wait on for the other.
import type { Transaction } from 'kysely';

import type { NoticeKind, NotificationsTables, Outbox } from '../../notifications/index.ts';
import type { Role } from '../domain/membership.ts';

/** The roles whose grant the admins are told of: a developer or a viewer is not. */
const TOLD_OF: readonly Role[] = ['admin', 'approver'];

/** What changed: a membership now holding `role`, and whether its person rejoined. */
export interface Grant {
  readonly orgId: string;
  readonly membershipId: string;
  readonly role: Role;
  readonly rejoined: boolean;
}

/** Writes a notice of the grant to the organisation's admins, if it is one they are told of. */
export async function tellAdminsOfGrant(
  tx: Transaction<NotificationsTables>,
  outbox: Outbox,
  grant: Grant,
): Promise<void> {
  const kind: NoticeKind | undefined = grant.rejoined
    ? 'member_rejoined'
    : TOLD_OF.includes(grant.role)
      ? 'role_granted'
      : undefined;
  if (kind === undefined) return;
  await outbox.add(tx, [
    { orgId: grant.orgId, recipientUserId: null, kind, membershipId: grant.membershipId, role: grant.role },
  ]);
}
