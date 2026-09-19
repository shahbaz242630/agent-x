import { createPublicKey, verify } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { encodeMessage } from '../keys/message.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { createMemoryAnchorStore, signAnchor } from './anchor.ts';
import type { Chain } from './chain.ts';

const keys = createKeyProvider(
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1)]]),
  })) satisfies KeyMaterial,
);

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const PLATFORM: Chain = { kind: 'platform' };
const AT = new Date('2026-09-19T09:00:00.000Z');
const POINT = { seq: 7n, hash: Buffer.alloc(32, 9) };

describe('an anchor (ADR-012 §2)', () => {
  it('signs the chain, the place and hash, and the time, so anyone can check it with the public key', () => {
    const anchor = signAnchor(keys, PLATFORM, POINT, AT);
    const publicKey = keys.describe().find((key) => key.purpose === 'audit-anchor')?.versions[0]?.publicKey;
    if (publicKey === undefined) throw new Error('The anchor key has no public half');
    const outsiders = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' });
    const message = encodeMessage(['audit-anchor', 'platform', '7', POINT.hash, '2026-09-19T09:00:00.000Z']);

    expect(anchor).toMatchObject({ chain: 'platform', seq: 7n, hash: POINT.hash, at: AT, keyVersion: 1 });
    expect(verify(null, message, outsiders, anchor.signature)).toBe(true);
    expect(
      verify(
        null,
        encodeMessage(['audit-anchor', 'platform', '6', POINT.hash, AT.toISOString()]),
        outsiders,
        anchor.signature,
      ),
    ).toBe(false);
  });

  it("names its chain, so one chain's anchor can't stand for another's", () => {
    const org = signAnchor(keys, { kind: 'organisation', orgId: ORG }, POINT, AT);

    expect(org.chain).toBe(`organisation:${ORG}`);
    expect(org.signature).not.toEqual(signAnchor(keys, PLATFORM, POINT, AT).signature);
  });
});

describe('the anchors kept in memory', () => {
  it('holds the last anchor of each chain, apart', () => {
    const store = createMemoryAnchorStore();
    const orgChain: Chain = { kind: 'organisation', orgId: ORG };
    const first = signAnchor(keys, PLATFORM, POINT, AT);
    const later = signAnchor(keys, PLATFORM, { seq: 8n, hash: Buffer.alloc(32, 8) }, AT);
    store.keep(first);
    store.keep(later);

    expect(store.latest(PLATFORM)).toBe(later);
    expect(store.latest(orgChain)).toBeUndefined();
  });
});
