// B5-1b: what a notice's email says. It tells, from IDs and constants alone,
// and does nothing: no link, no token, no approval power (PRD §4.4, SEC-HA-11).
import { describe, expect, it } from 'vitest';

import { messageFor } from './messages.ts';
import type { ClaimedNotice } from './notice.ts';

const NOTICE: ClaimedNotice = {
  id: '0199a0f0-0000-7000-8000-00000000b5c1',
  orgId: '0199a0f0-0000-7000-8000-00000000b5c2',
  recipientUserId: '0199a0f0-0000-7000-8000-00000000b5c3',
  kind: 'role_granted',
  membershipId: '0199a0f0-0000-7000-8000-00000000b5c4',
  role: 'approver',
  createdAt: new Date('2026-09-26T09:00:00Z'),
  attempts: 0,
};

describe('a notice’s email (B5-1b)', () => {
  it('tells an admin a member was made a finance approver, naming the organisation and membership by ID', () => {
    const message = messageFor(NOTICE, 'admin@example.test');

    expect(message).toMatchObject({ id: NOTICE.id, to: 'admin@example.test' });
    expect(message.subject).toBe('Agent X: a member of your organisation is now a finance approver');
    expect(message.text).toContain('was given the finance approver role.');
    expect(message.text).toContain(`Organisation: ${NOTICE.orgId}`);
    expect(message.text).toContain(`Membership: ${NOTICE.membershipId}`);
  });

  it('says an admin with “an”, and tells of a rejoin as such', () => {
    expect(messageFor({ ...NOTICE, role: 'admin' }, 'a@example.test').subject).toBe(
      'Agent X: a member of your organisation is now an admin',
    );
    const rejoined = messageFor({ ...NOTICE, kind: 'member_rejoined', role: 'viewer' }, 'a@example.test');
    expect(rejoined.subject).toBe('Agent X: a member rejoined your organisation as a viewer');
    expect(rejoined.text).toContain('rejoined it, as a viewer.');
  });

  it('SEC-HA-11 carries no link and no token, and says it can change nothing', () => {
    const { subject, text } = messageFor(NOTICE, 'admin@example.test');

    expect(`${subject} ${text}`).not.toMatch(/https?:|www\.|token|#/i);
    expect(text).toContain("This email can't approve or change anything.");
    // Nothing of the recipient but where it goes, and nothing of the member but their membership's ID.
    expect(text).not.toContain('admin@example.test');
    expect(text).not.toContain(NOTICE.recipientUserId);
  });
});
