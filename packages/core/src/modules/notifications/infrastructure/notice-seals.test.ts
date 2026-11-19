// S206 V4 (R-15; 0104): a notice's seals as queued and as it ended, made and
// judged with `audit-mac` under labels of their own.
import { createKeyProvider, type KeyProvider, PURPOSES } from '@agentx/platform/keys';
import { describe, expect, it } from 'vitest';

import { endJudged, endSeal, type QueuedColumns, queuedJudged, queuedSeal } from './notice-seals.ts';

/** The app's keys, `audit-mac` at version `current` with every version up to it held; `fill` makes another app's. */
const keysAt = (current: number, fill = 1): KeyProvider =>
  createKeyProvider(
    Object.fromEntries(
      PURPOSES.map((purpose, index) => {
        const versions = purpose === 'audit-mac' ? current : 1;
        return [
          purpose,
          {
            current: versions,
            versions: new Map(
              Array.from({ length: versions }, (_, v) => [v + 1, Buffer.alloc(32, index * 8 + v + fill)]),
            ),
          },
        ];
      }),
    ),
  );
const keys = keysAt(1);

const QUEUED: QueuedColumns = {
  id: '0199A0F0-0000-7000-8000-0000005206B1',
  org_id: '0199a0f0-0000-7000-8000-0000005206b2',
  recipient_user_id: '0199a0f0-0000-7000-8000-0000005206b3',
  recipient_contact_id: null,
  to_contacts: false,
  kind: 'second_factor_added',
  membership_id: null,
  role: null,
  about_id: '0199a0f0-0000-7000-8000-0000005206b3',
  created_at: new Date('2026-12-02T09:00:00.000Z'),
};

const sealed = (row: QueuedColumns, with_: KeyProvider = keys) => {
  const { mac, keyVersion } = queuedSeal(with_, row);
  return { ...row, mac, mac_key_version: keyVersion };
};

describe('a notice sealed as it is queued (S206 V4)', () => {
  it('holds for the notice as queued, whatever the case of its IDs', () => {
    expect(queuedJudged(keys, sealed(QUEUED))).toBe('sound');
    expect(queuedJudged(keys, { ...sealed(QUEUED), id: QUEUED.id.toLowerCase() })).toBe('sound');
  });

  it.each([
    ['moved to another person', { recipient_user_id: '0199a0f0-0000-7000-8000-0000005206b4' }],
    ['moved to a contact', { recipient_user_id: null, recipient_contact_id: '0199a0f0-0000-7000-8000-0000005206b3' }],
    ['moved to the contacts', { recipient_user_id: null, to_contacts: true }],
    ['moved to another organisation', { org_id: '0199a0f0-0000-7000-8000-0000005206b5' }],
    ['another kind', { kind: 'password_changed' }],
    ['about someone else', { about_id: '0199a0f0-0000-7000-8000-0000005206b4' }],
    ['about a membership', { membership_id: '0199a0f0-0000-7000-8000-0000005206b6' }],
    ['with a role', { role: 'admin' }],
    ['queued at another time', { created_at: new Date('2026-12-02T09:00:00.001Z') }],
    ['another notice', { id: '0199a0f0-0000-7000-8000-0000005206b7' }],
  ])('does not hold for a notice %s', (_change, change) => {
    expect(queuedJudged(keys, { ...sealed(QUEUED), ...change })).toBe('tampered');
  });

  it('holds for nothing made without the app’s key, cut short, or naming a version not held', () => {
    expect(queuedJudged(keys, sealed(QUEUED, keysAt(1, 100)))).toBe('tampered');
    expect(queuedJudged(keys, { ...sealed(QUEUED), mac: sealed(QUEUED).mac.subarray(1) })).toBe('tampered');
    expect(queuedJudged(keys, { ...sealed(QUEUED), mac_key_version: 2 })).toBe('tampered');
    expect(queuedJudged(keys, { ...sealed(QUEUED), mac_key_version: 1.5 })).toBe('tampered');
    expect(queuedJudged(keys, { ...sealed(QUEUED), mac: 'not bytes' })).toBe('tampered');
  });

  it('checks a seal with the version it names, the newer one used once it is current', () => {
    const newer = keysAt(2);
    expect(queuedJudged(newer, sealed(QUEUED, keys))).toBe('sound');
    expect(sealed(QUEUED, newer).mac_key_version).toBe(2);
  });

  it('holds for no notice with no seal, or half of one, however old', () => {
    const bare = { ...QUEUED, created_at: new Date('2020-01-01T00:00:00.000Z'), mac: null, mac_key_version: null };
    expect(queuedJudged(keys, bare)).toBe('tampered');
    expect(queuedJudged(keys, { ...bare, mac_key_version: 1 })).toBe('tampered');
    expect(queuedJudged(keys, { ...bare, mac: Buffer.alloc(32) })).toBe('tampered');
  });
});

describe('a notice’s end sealed (S206 V4)', () => {
  const ID = QUEUED.id;
  const AT = new Date('2026-12-02T09:05:00.000Z');
  const ended = (end: Parameters<typeof endSeal>[2]) => {
    const { mac, keyVersion } = endSeal(keys, ID, end);
    return { end_mac: mac, end_key_version: keyVersion };
  };
  const open = { id: ID, sent_at: null, given_up_at: null, last_failure: null, end_mac: null, end_key_version: null };

  it('is open while the notice is neither sent nor given up', () => {
    expect(endJudged(keys, open)).toBe('open');
  });

  it('holds for a notice sent, whatever failed before, and one given up with its own reason', () => {
    const sent = ended({ outcome: 'sent' });
    expect(endJudged(keys, { ...open, sent_at: AT, last_failure: 'send_error', ...sent })).toBe('sound');
    const givenUp = ended({ outcome: 'given_up', failure: 'no_address' });
    expect(endJudged(keys, { ...open, given_up_at: AT, last_failure: 'no_address', ...givenUp })).toBe('sound');
  });

  it('does not hold for an end the owner wrote, swapped or moved to another notice', () => {
    expect(endJudged(keys, { ...open, sent_at: AT })).toBe('tampered');
    const givenUp = ended({ outcome: 'given_up', failure: 'no_address' });
    expect(endJudged(keys, { ...open, sent_at: AT, ...givenUp })).toBe('tampered');
    expect(endJudged(keys, { ...open, given_up_at: AT, last_failure: 'reset_closed', ...givenUp })).toBe('tampered');
    expect(endJudged(keys, { ...open, given_up_at: AT, ...givenUp })).toBe('tampered');
    const sent = ended({ outcome: 'sent' });
    expect(endJudged(keys, { ...open, id: '0199a0f0-0000-7000-8000-0000005206b7', sent_at: AT, ...sent })).toBe(
      'tampered',
    );
  });
});
