// B4-3a: an invitation as a pending change, and its hash, which the admin's
// step-up challenge binds to (ADR-003 §9).
import { describe, expect, it } from 'vitest';

import type { Role } from '../domain/membership.ts';
import { invitationChange, INVITATIONS } from './invitations.ts';

describe('the pending change (B4-3a)', () => {
  const request = {
    orgId: '0199a0f0-0000-7000-8000-0000000000aa',
    id: '0199a0f0-0000-7000-8000-0000000000bb',
    email: 'sara@example.test',
    role: 'viewer' as Role,
    invitedBy: '0199a0f0-0000-7000-8000-0000000000cc',
    createdAt: new Date('2026-09-25T09:00:00Z'),
  };
  const hash = (changes: Partial<typeof request> = {}) => invitationChange({ ...request, ...changes }).changeHash;

  it('hashes to 32 bytes, the same for the same change, whatever the case of the address or the IDs', () => {
    expect(hash()).toHaveLength(32);
    expect(hash().equals(hash({ email: 'SARA@Example.TEST' }))).toBe(true);
    expect(hash().equals(hash({ orgId: request.orgId.toUpperCase(), id: request.id.toUpperCase() }))).toBe(true);
    expect(hash().equals(hash({ invitedBy: request.invitedBy.toUpperCase() }))).toBe(true);
  });

  it.each([
    ['organisation', { orgId: '0199a0f0-0000-7000-8000-0000000000ab' }],
    ['invitation', { id: '0199a0f0-0000-7000-8000-0000000000bc' }],
    ['address', { email: 'sarah@example.test' }],
    ['role', { role: 'admin' as Role }],
    ['admin', { invitedBy: '0199a0f0-0000-7000-8000-0000000000cd' }],
    ['end', { createdAt: new Date('2026-09-25T09:00:00.001Z') }],
  ])('hashes differently for another %s', (_what, changes) => {
    expect(hash().equals(hash(changes))).toBe(false);
  });

  it('refuses an address that isn’t one, or a role that isn’t one', () => {
    expect(() => invitationChange({ ...request, email: 'no-at-sign' })).toThrow(RangeError);
    expect(() => invitationChange({ ...request, role: 'owner' as Role })).toThrow(RangeError);
  });

  it('describes its authority table by name and subject', () => {
    expect(INVITATIONS).toMatchObject({ table: 'identity.invitations', subject: 'invitation' });
  });
});
