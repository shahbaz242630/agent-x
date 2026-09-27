// B6-1a: a contact as a pending change, and its hash, which the admin's
// step-up challenge binds to (ADR-003 §9).
import { describe, expect, it } from 'vitest';

import { contactChange, REGISTERED_CONTACTS } from './registered-contacts.ts';

describe('the pending change (B6-1a)', () => {
  const request = {
    orgId: '0199a0f0-0000-7000-8000-0000000000aa',
    id: '0199a0f0-0000-7000-8000-0000000000bb',
    email: 'finance.office@example.test',
    addedBy: '0199a0f0-0000-7000-8000-0000000000cc',
  };
  const hash = (changes: Partial<typeof request> = {}) => contactChange({ ...request, ...changes }).changeHash;

  it('hashes to 32 bytes, the same for the same change, whatever the case of the address or the IDs', () => {
    expect(hash()).toHaveLength(32);
    expect(hash().equals(hash({ email: 'Finance.Office@Example.TEST' }))).toBe(true);
    expect(
      hash().equals(
        hash({
          orgId: request.orgId.toUpperCase(),
          id: request.id.toUpperCase(),
          addedBy: request.addedBy.toUpperCase(),
        }),
      ),
    ).toBe(true);
  });

  it.each([
    ['organisation', { orgId: '0199a0f0-0000-7000-8000-0000000000ab' }],
    ['contact', { id: '0199a0f0-0000-7000-8000-0000000000bc' }],
    ['address', { email: 'finance.offices@example.test' }],
    ['admin', { addedBy: '0199a0f0-0000-7000-8000-0000000000cd' }],
  ])('hashes differently for another %s', (_what, changes) => {
    expect(hash().equals(hash(changes))).toBe(false);
  });

  it('keeps the address in lower case', () => {
    expect(contactChange({ ...request, email: 'Finance.Office@Example.TEST' }).change.email).toBe(
      'finance.office@example.test',
    );
  });

  it('refuses an address that isn’t one', () => {
    expect(() => contactChange({ ...request, email: 'no-at-sign' })).toThrow(RangeError);
  });

  it('describes its authority table by name and subject', () => {
    expect(REGISTERED_CONTACTS).toMatchObject({
      table: 'identity.registered_contacts',
      subject: 'registered_contact',
    });
  });
});
