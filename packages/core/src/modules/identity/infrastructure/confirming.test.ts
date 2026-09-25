// B4-4d: the confirmation's pending change, as its step-up binds to it: every
// fact it is made of changes its SHA-256.
import { describe, expect, it } from 'vitest';

import { confirmationHash } from './confirming.ts';
import type { InvitationRecord } from './invitations.ts';

const ORG = '0199a0f0-0000-7000-8000-0000000000aa';
const WAITING: InvitationRecord = {
  id: '0199a0f0-0000-7000-8000-0000000000bb',
  role: 'approver',
  status: 'AWAITING_CONFIRMATION',
  expiresAt: new Date('2026-09-28T09:00:00Z'),
  stepUpChallengeId: '0199a0f0-0000-7000-8000-0000000000cc',
  byOperator: false,
  acceptedBy: '0199a0f0-0000-7000-8000-0000000000dd',
};
const hash = (changes: Partial<InvitationRecord> = {}, org = ORG, version = 4) =>
  confirmationHash(org, { ...WAITING, ...changes }, version);

describe("a confirmation's pending change (B4-4d)", () => {
  it('hashes to 32 bytes, the same for the same facts, the organisation in any case', () => {
    expect(hash()).toHaveLength(32);
    expect(hash().equals(hash({}, ORG.toUpperCase()))).toBe(true);
  });

  it.each<[string, () => Buffer]>([
    ['organisation', () => hash({}, '0199a0f0-0000-7000-8000-0000000000ab')],
    ['invitation', () => hash({ id: '0199a0f0-0000-7000-8000-0000000000bc' })],
    ['person who accepted', () => hash({ acceptedBy: '0199a0f0-0000-7000-8000-0000000000de' })],
    ['no one who accepted', () => hash({ acceptedBy: null })],
    ['role', () => hash({ role: 'admin' })],
    ['version', () => hash({}, ORG, 5)],
  ])('hashes differently for another %s', (_what, other) => {
    expect(hash().equals(other())).toBe(false);
  });

  it('keeps the facts apart: an ID that runs into the next never hashes as another pair', () => {
    expect(hash({ role: 'admin' }, ORG, 14).equals(hash({ role: 'admin1' as never }, ORG, 4))).toBe(false);
  });
});
