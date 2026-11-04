import { createPublicKey, verify } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { encodeMessage } from '../keys/message.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { createMemoryAnchorStore, createMemoryPassRecord, signAnchor, signPass, signProgress } from './anchor.ts';
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
const POINT = { seq: 7n, hash: Buffer.alloc(32, 9), macKeyVersion: 3 };

describe('an anchor (ADR-012 §2)', () => {
  it("signs the chain, the place and hash, the MAC key's version and the time, so anyone can check it with the public key", () => {
    const anchor = signAnchor(keys, PLATFORM, POINT, AT);
    const publicKey = keys.describe().find((key) => key.purpose === 'audit-anchor')?.versions[0]?.publicKey;
    if (publicKey === undefined) throw new Error('The anchor key has no public half');
    const outsiders = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' });
    const message = encodeMessage(['audit-anchor', '0', 'platform', '7', POINT.hash, '3', '2026-09-19T09:00:00.000Z']);

    expect(anchor).toMatchObject({
      chain: 'platform',
      seq: 7n,
      hash: POINT.hash,
      macKeyVersion: 3,
      at: AT,
      keyVersion: 1,
    });
    expect(verify(null, message, outsiders, anchor.signature)).toBe(true);
    expect(
      verify(
        null,
        encodeMessage(['audit-anchor', '0', 'platform', '6', POINT.hash, '3', AT.toISOString()]),
        outsiders,
        anchor.signature,
      ),
    ).toBe(false);
    // The MAC key's version is signed: an anchor can't be read as allowing an older key than the one it saw.
    expect(
      verify(
        null,
        encodeMessage(['audit-anchor', '0', 'platform', '7', POINT.hash, '2', AT.toISOString()]),
        outsiders,
        anchor.signature,
      ),
    ).toBe(false);
  });

  it("names its chain, so one chain's anchor can't stand for another's", () => {
    expect(signAnchor(keys, PLATFORM, POINT, AT, 2).signature).not.toEqual(
      signAnchor(keys, PLATFORM, POINT, AT, 3).signature,
    );
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
    const later = signAnchor(keys, PLATFORM, { seq: 8n, hash: Buffer.alloc(32, 8), macKeyVersion: 3 }, AT);
    store.keep(first);
    store.keep(later);

    expect(store.latest(PLATFORM)).toBe(later);
    expect(store.latest(orgChain)).toBeUndefined();
  });
});

describe('a finished full pass (4D2e E7)', () => {
  it('signs the same fields under its own label: a pass is never an anchor, nor an anchor a pass', () => {
    const pass = signPass(keys, PLATFORM, POINT, AT, 1);
    const publicKey = keys.describe().find((key) => key.purpose === 'audit-anchor')?.versions[0]?.publicKey;
    if (publicKey === undefined) throw new Error('The anchor key has no public half');
    const outsiders = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' });
    const fields = ['1', 'platform', '7', POINT.hash, '3', AT.toISOString()] as const;

    expect(pass).toMatchObject({
      chain: 'platform',
      seq: 7n,
      hash: POINT.hash,
      macKeyVersion: 3,
      at: AT,
      keyVersion: 1,
    });
    expect(verify(null, encodeMessage(['audit-anchor-pass', ...fields]), outsiders, pass.signature)).toBe(true);
    expect(verify(null, encodeMessage(['audit-anchor', ...fields]), outsiders, pass.signature)).toBe(false);
    expect(pass.signature).not.toEqual(signAnchor(keys, PLATFORM, POINT, AT, 1).signature);
  });

  it('is kept in memory for each chain apart, the last one kept', () => {
    const record = createMemoryPassRecord();
    const orgChain: Chain = { kind: 'organisation', orgId: ORG };
    const first = signPass(keys, PLATFORM, POINT, AT);
    const later = signPass(keys, PLATFORM, POINT, new Date(AT.getTime() + 1000));
    record.keepPass(first);
    record.keepPass(later);

    expect(record.lastPass(PLATFORM)).toBe(later);
    expect(record.lastPass(orgChain)).toBeUndefined();
  });

  it("keeps each chain's place under way until its pass finishes, signed under a label of its own", () => {
    const record = createMemoryPassRecord();
    const place = signProgress(keys, PLATFORM, POINT, AT, 1);
    record.keepProgress(place);
    expect(record.lastProgress(PLATFORM)).toBe(place);
    expect(place.signature).not.toEqual(signPass(keys, PLATFORM, POINT, AT, 1).signature);
    expect(place.signature).not.toEqual(signAnchor(keys, PLATFORM, POINT, AT, 1).signature);
    record.keepPass(signPass(keys, PLATFORM, POINT, AT));
    expect(record.lastProgress(PLATFORM)).toBeUndefined();
  });
});
