// Telling an organisation's admins of a role granted (ADR-003 §10; B5-1b): a
// member made an admin or a finance approver, whether by a role change or by
// joining, and anyone rejoining, whatever their role; and since the S68 audit
// of one taken away: any member removed, an admin or approver demoted. One notice to the
// organisation's admins, written to the outbox in the change's own
// transaction, so it commits or rolls back with the change.
//
// The change reads no one: the sender finds the active admins, but the member
// it is about, through their signed states in a transaction of its own
// (0021). Verifying every admin here would take locks two changes at once
// could each wait on for the other.
import type { Transaction } from 'kysely';

import type { Notice, NoticeKind, NotificationsTables, Outbox } from '../../notifications/index.ts';
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

/** What was taken away: a membership deactivated, with the role it held; or a role changed, with the one it lost. */
export interface Removal {
  readonly orgId: string;
  readonly membershipId: string;
  readonly kind: 'deactivated' | 'demoted';
  readonly role: Role;
}

/**
 * Writes a notice of the removal to the organisation's admins (the S68
 * audit): any member removed, whatever their role, since their agents keep
 * running; an admin's or finance approver's role taken away. A developer's or
 * viewer's role changed is not told, as its grant isn't.
 */
export async function tellAdminsOfRemoval(
  tx: Transaction<NotificationsTables>,
  outbox: Outbox,
  removal: Removal,
): Promise<void> {
  const kind: NoticeKind | undefined =
    removal.kind === 'deactivated' ? 'member_removed' : TOLD_OF.includes(removal.role) ? 'role_removed' : undefined;
  if (kind === undefined) return;
  await outbox.add(tx, [
    { orgId: removal.orgId, recipientUserId: null, kind, membershipId: removal.membershipId, role: removal.role },
  ]);
}

/**
 * The notices about a reset of the person's second factor (or a change to
 * how they sign in, never sent to the contacts): to them, as
 * themselves, and to the organisation's admins but them, found as they are
 * sent; and to its ACTIVE contacts once it was sent to them.
 */
export const toldOfReset = (orgId: string, kind: NoticeKind, personUserId: string, toContacts: boolean): Notice[] => {
  const about = { orgId, kind, membershipId: null, role: null, aboutId: personUserId } as const;
  return [
    { ...about, recipientUserId: personUserId },
    { ...about, recipientUserId: null },
    ...(toContacts ? [{ ...about, recipientUserId: null, toContacts: true }] : []),
  ];
};
