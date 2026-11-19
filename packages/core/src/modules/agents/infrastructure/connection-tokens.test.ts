// V7 (PL-67, SEC-OAUTH-14): an MCP token's check at the door does the same
// work whatever its row says, so how long the answer takes tells an outsider
// nothing of whether a key or token ID is in use. Asserted as the work done
// (one verifyMac, same purpose, a 32-byte MAC), never as wall-clock time.
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { describe, expect, it, vi } from 'vitest';

import { connectionTokenMessage, type PresentedToken } from '../domain/connection.ts';
import { tokenProven, type TokenRow } from './connection-tokens.ts';

/** Stand-in keys, one per purpose; the agent-key pepper rotated once, so version 2 is current and 1 still held. */
const material = Object.fromEntries(
  PURPOSES.map((purpose, index) => [
    purpose,
    purpose === 'agent-key-pepper'
      ? {
          current: 2,
          versions: new Map([
            [1, Buffer.alloc(32, 0x71)],
            [2, Buffer.alloc(32, 0x72)],
          ]),
        }
      : { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) },
  ]),
);

const keys = createKeyProvider(material);
const KEY_ID = '0199a0f0-0000-7000-8000-0000000007a1';
const TOKEN_ID = '0199a0f0-0000-7000-8000-0000000007b2';
const EXPIRES = new Date('2026-11-21T09:00:00Z');
const SCOPES = 'requests:read';

const presented: PresentedToken = { kind: 'access', keyId: KEY_ID, tokenId: TOKEN_ID, secret: Buffer.alloc(32, 0x5a) };

/** A row as issueTokens keeps one, its MAC over `madeFor` (the presented one's own words unless given). */
const rowFor = (madeFor: Buffer, changes: Partial<TokenRow> = {}): TokenRow => {
  const { mac, keyVersion } = keys.mac(
    'agent-key-pepper',
    connectionTokenMessage(
      { kind: 'access', keyId: KEY_ID, tokenId: TOKEN_ID, expiresAt: EXPIRES, scopes: SCOPES },
      madeFor,
    ),
  );
  return {
    keyId: KEY_ID,
    kind: 'access',
    scopes: SCOPES,
    secretMac: mac,
    secretKeyVersion: keyVersion,
    expiresAt: EXPIRES,
    usedAt: null,
    ...changes,
  };
};

/** tokenProven with its verifyMac watched: what it answered, and every verifyMac it made. */
const watched = (row: TokenRow | undefined) => {
  const verifyMac = vi.fn((...args: Parameters<typeof keys.verifyMac>) => keys.verifyMac(...args));
  const proof = tokenProven({ ...keys, verifyMac }, row, presented);
  return { outcome: proof.outcome, calls: verifyMac.mock.calls };
};

describe('V7 (PL-67) a token checked at the door: the same work whatever is found', () => {
  it('makes exactly one verifyMac, with the pepper’s current version and a 32-byte MAC, for every outcome', () => {
    const cases = {
      unread: watched(undefined),
      anotherKey: watched(rowFor(presented.secret, { keyId: '0199a0f0-0000-7000-8000-0000000007c3' })),
      anotherKind: watched(rowFor(presented.secret, { kind: 'refresh' })),
      wrongSecret: watched(rowFor(Buffer.alloc(32, 0x11))),
      notHeld: watched(rowFor(presented.secret, { secretKeyVersion: 9 })),
      proven: watched(rowFor(presented.secret)),
    };

    expect(Object.fromEntries(Object.entries(cases).map(([name, { outcome }]) => [name, outcome]))).toEqual({
      unread: 'unread',
      anotherKey: 'unread',
      anotherKind: 'unread',
      wrongSecret: 'wrong_secret',
      notHeld: 'key_not_held',
      proven: 'proven',
    });
    for (const { calls } of Object.values(cases)) {
      expect(calls).toHaveLength(1);
      const [purpose, version, message, mac] = calls[0] ?? [];
      expect([purpose, version, mac?.length]).toEqual(['agent-key-pepper', 2, 32]);
      // The presented secret is always what is checked: a token never issued is MAC'd as fully as one in use.
      expect(Array.isArray(message) ? message.at(-1) : undefined).toEqual(presented.secret);
    }
    // Nothing to compare with is compared with zeros, never skipped.
    expect(cases.unread.calls[0]?.[3]).toEqual(Buffer.alloc(32));
    expect(cases.notHeld.calls[0]?.[3]).toEqual(Buffer.alloc(32));
  });

  it('verifies nothing, and proves nothing, when this process holds no pepper', () => {
    const others = PURPOSES.filter((purpose) => purpose !== 'agent-key-pepper');
    const noPepper = createKeyProvider(
      Object.fromEntries(Object.entries(material).filter(([purpose]) => purpose !== 'agent-key-pepper')),
      others,
    );
    const verifyMac = vi.fn((...args: Parameters<typeof noPepper.verifyMac>) => noPepper.verifyMac(...args));

    expect(tokenProven({ ...noPepper, verifyMac }, rowFor(presented.secret), presented)).toEqual({
      outcome: 'key_not_held',
    });
    expect(tokenProven({ ...noPepper, verifyMac }, undefined, presented)).toEqual({ outcome: 'unread' });
    expect(verifyMac).not.toHaveBeenCalled();
  });
});
