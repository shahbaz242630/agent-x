// S205: the MAC messages of sessions and step-up challenges, and their check.
// The database half (a row the owner plants or edits) is sessions-tamper.db.test.ts.
import { createKeyProvider, type KeyProvider } from '@agentx/platform/keys';
import { LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import {
  type ChallengeFacts,
  challengeMessage,
  macHolds,
  macOf,
  rowForged,
  type SessionFacts,
  sessionMessage,
} from './row-macs.ts';

const keys = createKeyProvider({ 'session-mac': { current: 1, versions: new Map([[1, Buffer.alloc(32, 5)]]) } }, [
  'session-mac',
]);

const AT = new Date('2026-11-19T09:00:00Z');
const SESSION: SessionFacts = {
  id: '0199a0f0-0000-7000-8000-000000000001',
  userId: '0199a0f0-0000-7000-8000-000000000002',
  cookieHash: Buffer.alloc(32, 1),
  idpSessionId: null,
  authTime: AT,
  amr: ['pwd', 'user', 'mfa'],
  createdAt: AT,
  endsAt: new Date(AT.getTime() + 60_000),
};
const CHALLENGE: ChallengeFacts = {
  id: SESSION.id,
  sessionId: SESSION.id,
  userId: SESSION.userId,
  action: 'members.change-role',
  changeHash: Buffer.alloc(32, 2),
  nonce: 'n',
  createdAt: AT,
  endsAt: SESSION.endsAt,
  verified: undefined,
};
const VERIFIED: ChallengeFacts = {
  ...CHALLENGE,
  verified: {
    verifiedAt: AT,
    authTime: AT,
    amr: ['pwd', 'user'],
    idpSessionId: null,
    idTokenHash: Buffer.alloc(32, 3),
  },
};

const holds = (message: Parameters<typeof macHolds>[1], sealedFor = message) =>
  macHolds(keys, message, macOf(keys, sealedFor));

describe('session and step-up MACs (S205)', () => {
  it('holds for the facts it was made over, and for nothing else', () => {
    expect(holds(sessionMessage(SESSION))).toBe(true);
    expect(holds(challengeMessage(CHALLENGE))).toBe(true);
    expect(holds(challengeMessage(VERIFIED))).toBe(true);
    for (const changed of [
      { ...SESSION, idpSessionId: 'none' },
      { ...SESSION, idpSessionId: '' },
      { ...SESSION, amr: ['pwd', 'user'] },
      { ...SESSION, amr: ['pwd', 'user', 'mfa', ''] },
      { ...SESSION, endsAt: new Date(SESSION.endsAt.getTime() + 1) },
    ]) {
      expect(holds(sessionMessage(changed), sessionMessage(SESSION))).toBe(false);
    }
    // An opened challenge's MAC never stands for a verified one, nor a session's for either.
    expect(holds(challengeMessage(VERIFIED), challengeMessage(CHALLENGE))).toBe(false);
    expect(holds(challengeMessage(CHALLENGE), sessionMessage(SESSION))).toBe(false);
  });

  it('holds for no MAC or version a row could be given in place of its own', () => {
    const message = sessionMessage(SESSION);
    const { mac } = macOf(keys, message);
    expect(macHolds(keys, message, { mac, mac_key_version: 2 })).toBe(false);
    expect(macHolds(keys, message, { mac, mac_key_version: 1.5 })).toBe(false);
    expect(macHolds(keys, message, { mac, mac_key_version: '1' })).toBe(false);
    expect(macHolds(keys, message, { mac: null, mac_key_version: 1 })).toBe(false);
    expect(macHolds(keys, message, { mac: mac.subarray(1), mac_key_version: 1 })).toBe(false);
  });

  it('lets any other failure of the keys through, rather than reading it as a forged row', () => {
    const broken = {
      ...keys,
      verifyMac: () => {
        throw new TypeError('the key store is down');
      },
    } as KeyProvider;
    expect(() => macHolds(broken, sessionMessage(SESSION), macOf(keys, sessionMessage(SESSION)))).toThrow(TypeError);
  });

  it('raises the integrity alarm naming the row and its person', () => {
    const capture = new LogCapture();
    rowForged(testLogger(capture), 'session', { id: SESSION.id, user_id: SESSION.userId });
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        level: 'error',
        event: 'audit.integrity_failed',
        check: 'session',
        reason: 'mac',
        rowId: SESSION.id,
        userId: SESSION.userId,
      }),
    ]);
  });
});
