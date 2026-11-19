// The roles a person a notice is sent to must hold as it is sent (AG10, 6F1). The sender's giving up of the rest is
// sender.db.test.ts.
import { describe, expect, it } from 'vitest';

import { type NoticeKind, rolesToReceive } from './notice.ts';

const PERSON = '0199a0f0-0000-7000-8000-00000000a710';
const SOMEONE_ELSE = '0199a0f0-0000-7000-8000-00000000a711';
const EVERY_ROLE = ['admin', 'approver', 'developer', 'viewer'];

const rolesFor = (kind: NoticeKind, recipientUserId: string | null = PERSON, aboutId: string | null = null) =>
  rolesToReceive({ kind, recipientUserId, aboutId });

describe('the roles a notice’s recipient must hold as it is sent (AG10)', () => {
  it('any role for what every member is told, and for an agent handed to its new owner', () => {
    expect(rolesFor('supplier_verified')).toEqual(EVERY_ROLE);
    expect(rolesFor('factor_reset_by_support', PERSON, SOMEONE_ELSE)).toEqual(EVERY_ROLE);
    expect(rolesFor('agent_handed_to_you')).toEqual(EVERY_ROLE);
  });

  it('any role for a notice about a person sent to that person, in any case; an admin for the others it reaches', () => {
    expect(rolesFor('second_factor_removed', PERSON, PERSON)).toEqual(EVERY_ROLE);
    expect(rolesFor('factor_reset_asked', PERSON.toUpperCase(), PERSON)).toEqual(EVERY_ROLE);
    expect(rolesFor('second_factor_removed', PERSON, SOMEONE_ELSE)).toEqual(['admin']);
    expect(rolesFor('second_factor_removed', PERSON, null)).toEqual(['admin']);
    // Not about a person: naming the recipient in `aboutId` gives no wider audience.
    expect(rolesFor('agent_handed_over', PERSON, PERSON)).toEqual(['admin']);
    expect(rolesFor('second_factor_removed', null, null)).toEqual(['admin']);
  });

  it('an admin or approver for what waits on them, an admin for the rest', () => {
    expect(rolesFor('mandate_suspended')).toEqual(['admin', 'approver']);
    expect(rolesFor('organization_frozen')).toEqual(['admin', 'approver']);
    expect(rolesFor('spend_request_waiting')).toEqual(['admin', 'approver']);
    expect(rolesFor('spend_request_stopped')).toEqual(['admin']);
    expect(rolesFor('role_granted')).toEqual(['admin']);
    expect(rolesFor('access_log_export_ready')).toEqual(['admin']);
  });
});
