// A membership (PRD §3 `Membership`): a person in an organisation, with one of
// its four roles (PRD §7.1), the same names the API's access lists use.
//
// Its status is ACTIVE or DEACTIVATED. A membership starts ACTIVE: a person
// invited as an admin or finance approver waits for an existing admin's
// confirmation on the invitation, before any membership exists (ADR-005 §6,
// B4-4). Deactivating ends the person's sessions in the same transaction
// (ADR-003 §7, B4-5a). Reactivating brings a deactivated person back through a
// new invitation, to the same membership (B4-5c, 0019). The database's status
// guard holds the same moves.
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const MEMBERSHIP = defineStateMachine({
  name: 'membership',
  states: ['ACTIVE', 'DEACTIVATED'],
  initial: 'ACTIVE',
  events: {
    deactivate: { from: ['ACTIVE'], to: 'DEACTIVATED' },
    reactivate: { from: ['DEACTIVATED'], to: 'ACTIVE' },
  },
});

/** An organisation's roles, as its members hold them and its routes name them. */
export const ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

export const isRole = (value: unknown): value is Role => ROLES.some((role) => role === value);
