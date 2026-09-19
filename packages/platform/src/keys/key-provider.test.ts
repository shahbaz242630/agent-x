import { createHmac, createPublicKey, verify } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  createKeyProvider,
  KeyError,
  type KeyMaterial,
  keyMaterialProblems,
  type KeyProvider,
  type PurposeKeys,
} from './key-provider.ts';
import { encodeMessage, type Message } from './message.ts';
import {
  type AeadPurpose,
  byPurpose,
  type KeyPurpose,
  type MacPurpose,
  PURPOSES,
  type SigningPurpose,
} from './purposes.ts';

/** A stand-in key: 32 bytes of one value, so every key in a test is told apart by its fill. */
const key = (fill: number): Buffer => Buffer.alloc(32, fill);

const oneVersion = (fill: number): PurposeKeys => ({ current: 1, versions: new Map([[1, key(fill)]]) });

/** Version 1, and version 2 made current: a rotation half-way through, with the old key kept. */
const rotated = (oldFill: number, newFill: number, current = 2): PurposeKeys => ({
  current,
  versions: new Map([
    [1, key(oldFill)],
    [2, key(newFill)],
  ]),
});

/** A key for every purpose, each its own; `changes` replaces some. */
function material(changes: Partial<Record<KeyPurpose, PurposeKeys>> = {}): KeyMaterial {
  return byPurpose((purpose) => changes[purpose] ?? oneVersion(PURPOSES.indexOf(purpose) + 1));
}

const provider = (changes: Partial<Record<KeyPurpose, PurposeKeys>> = {}): KeyProvider =>
  createKeyProvider(material(changes));

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const SUPPLIER = '0199a0f0-0000-7000-8000-000000000003';
const REQUEST: Message = ['request', ORG, 'POST /v1/suppliers', '{"name":"Acme"}'];
const ROW: Message = [ORG, SUPPLIER, '1'];

describe('SEC-DATA-07 keyed hashes (HMAC-SHA-256)', () => {
  it('is the standard HMAC of the encoded message, with the current key, and names that key', () => {
    const result = provider().mac('request-hash', REQUEST);
    const expected = createHmac('sha256', key(2)).update(encodeMessage(REQUEST)).digest();

    expect(result).toEqual({ keyVersion: 1, mac: expected });
  });

  it('stays on a newer version it is asked for, never an older one', () => {
    // Current is 1 here, with version 2 held: a process rolled back after a rotation.
    const keys = provider({ 'request-hash': rotated(2, 9, 1) });
    const withKey = (fill: number): Buffer => createHmac('sha256', key(fill)).update(encodeMessage(REQUEST)).digest();

    expect(keys.mac('request-hash', REQUEST, 2)).toEqual({ keyVersion: 2, mac: withKey(9) });
    expect(keys.mac('request-hash', REQUEST, 1)).toEqual({ keyVersion: 1, mac: withKey(2) });
    expect(provider({ 'request-hash': rotated(2, 9) }).mac('request-hash', REQUEST, 1)).toEqual({
      keyVersion: 2,
      mac: withKey(9),
    });
  });

  it('refuses a newer version it does not hold', () => {
    expect(() => provider().mac('request-hash', REQUEST, 3)).toThrow(new KeyError('request-hash has no version 3'));
  });

  it('gives the same message the same hash, and another message another hash', () => {
    const keys = provider();

    expect(keys.mac('request-hash', REQUEST).mac).toEqual(keys.mac('request-hash', REQUEST).mac);
    expect(keys.mac('request-hash', REQUEST).mac).not.toEqual(keys.mac('request-hash', ['request', OTHER_ORG]).mac);
  });

  it("gives each purpose its own key, so one purpose's hash never stands for another's", () => {
    const keys = provider();
    const hashes = (['agent-key-pepper', 'request-hash', 'audit-mac', 'payee-index'] as const).map(
      (purpose) => keys.mac(purpose, REQUEST).mac,
    );

    expect(new Set(hashes.map((hash) => hash.toString('hex'))).size).toBe(4);
  });

  it('checks a hash against its message', () => {
    const keys = provider();
    const { keyVersion, mac } = keys.mac('audit-mac', REQUEST);

    expect(keys.verifyMac('audit-mac', keyVersion, REQUEST, mac)).toBe(true);
    expect(
      keys.verifyMac('audit-mac', keyVersion, ['request', ORG, 'POST /v1/suppliers', '{"name":"Acme!"}'], mac),
    ).toBe(false);
  });

  it.each([
    ['one bit changed', (mac: Buffer) => Buffer.from(mac.map((byte, at) => (at === 31 ? byte ^ 1 : byte)))],
    ['cut short', (mac: Buffer) => mac.subarray(0, 31)],
    ['one byte longer', (mac: Buffer) => Buffer.concat([mac, Buffer.of(0)])],
    ['empty', () => Buffer.alloc(0)],
  ])('refuses a hash %s', (_what, change) => {
    const keys = provider();
    const { keyVersion, mac } = keys.mac('audit-mac', REQUEST);

    expect(keys.verifyMac('audit-mac', keyVersion, REQUEST, change(mac))).toBe(false);
  });

  it("can't be made or checked without the key", () => {
    const { keyVersion, mac } = provider().mac('request-hash', REQUEST);
    const anotherKey = provider({ 'request-hash': oneVersion(200) });

    expect(anotherKey.mac('request-hash', REQUEST).mac).not.toEqual(mac);
    expect(anotherKey.verifyMac('request-hash', keyVersion, REQUEST, mac)).toBe(false);
  });

  it('still matches a retry during a rotation: a hash made with the old version checks with it', () => {
    const stored = provider({ 'request-hash': oneVersion(50) }).mac('request-hash', REQUEST);
    const afterRotation = provider({ 'request-hash': rotated(50, 51) });

    expect(afterRotation.verifyMac('request-hash', stored.keyVersion, REQUEST, stored.mac)).toBe(true);
    expect(afterRotation.verifyMac('request-hash', 2, REQUEST, stored.mac)).toBe(false);
  });

  it('uses the new version for new hashes once it is current, and the old one until then', () => {
    const before = provider({ 'request-hash': rotated(50, 51, 1) }).mac('request-hash', REQUEST);
    const after = provider({ 'request-hash': rotated(50, 51) }).mac('request-hash', REQUEST);

    expect(before.keyVersion).toBe(1);
    expect(after.keyVersion).toBe(2);
    expect(after.mac).not.toEqual(before.mac);
  });

  it("refuses a version it doesn't hold", () => {
    const { mac } = provider().mac('request-hash', REQUEST);

    expect(() => provider().verifyMac('request-hash', 2, REQUEST, mac)).toThrow(
      new KeyError('request-hash has no version 2'),
    );
  });
});

describe('SEC-DATA-07 encryption (AES-256-GCM with associated data)', () => {
  const contact = Buffer.from('+971 50 123 4567', 'utf8');

  it('opens what it sealed, with the same associated data, and names the key it used', () => {
    const keys = provider();
    const sealed = keys.encrypt('field-encryption', contact, ROW);

    expect(sealed.keyVersion).toBe(1);
    expect(keys.decrypt('field-encryption', sealed, ROW)).toEqual(contact);
  });

  it('opens an empty value', () => {
    const keys = provider();

    expect(keys.decrypt('field-encryption', keys.encrypt('field-encryption', Buffer.alloc(0), ROW), ROW)).toEqual(
      Buffer.alloc(0),
    );
  });

  it('stores the nonce, the tag and the ciphertext, and never the value itself', () => {
    const { ciphertext } = provider().encrypt('field-encryption', contact, ROW);

    expect(ciphertext).toHaveLength(12 + 16 + contact.length);
    expect(ciphertext.includes(contact)).toBe(false);
  });

  it("seals the same value differently every time, so equal values don't show as equal", () => {
    const keys = provider();

    expect(keys.encrypt('field-encryption', contact, ROW).ciphertext).not.toEqual(
      keys.encrypt('field-encryption', contact, ROW).ciphertext,
    );
  });

  it("can't be read without the key", () => {
    const sealed = provider().encrypt('field-encryption', contact, ROW);

    expect(() => provider({ 'field-encryption': oneVersion(200) }).decrypt('field-encryption', sealed, ROW)).toThrow(
      KeyError,
    );
  });

  it.each([
    ['another organisation', [OTHER_ORG, SUPPLIER, '1']],
    ['another row', [ORG, OTHER_ORG, '1']],
    ['another version of the row', [ORG, SUPPLIER, '2']],
    ['the same IDs split differently', [`${ORG}${SUPPLIER}`, '1']],
  ] as const)('refuses a value copied to %s (ADR-012 §2)', (_where, associatedData: Message) => {
    const keys = provider();
    const sealed = keys.encrypt('field-encryption', contact, ROW);

    expect(() => keys.decrypt('field-encryption', sealed, associatedData)).toThrow(
      new KeyError(
        "field-encryption: the ciphertext doesn't open: the wrong key or associated data, or its bytes were changed",
      ),
    );
  });

  it('refuses a ciphertext with any one byte changed: nonce, tag or body', () => {
    const keys = provider();
    const { keyVersion, ciphertext } = keys.encrypt('field-encryption', contact, ROW);

    for (let at = 0; at < ciphertext.length; at += 1) {
      const changed = Buffer.from(ciphertext);
      changed[at] = (changed[at] ?? 0) ^ 0x01;
      expect(() => keys.decrypt('field-encryption', { keyVersion, ciphertext: changed }, ROW)).toThrow(KeyError);
    }
  });

  it.each([
    ['one byte short', 1],
    ['without its body', 16],
  ])('refuses a ciphertext cut %s', (_what, cut) => {
    const keys = provider();
    const { keyVersion, ciphertext } = keys.encrypt('field-encryption', contact, ROW);

    expect(() =>
      keys.decrypt('field-encryption', { keyVersion, ciphertext: ciphertext.subarray(0, -cut) }, ROW),
    ).toThrow(KeyError);
  });

  it('refuses a ciphertext too short to hold its nonce and tag', () => {
    expect(() => provider().decrypt('field-encryption', { keyVersion: 1, ciphertext: Buffer.alloc(27) }, ROW)).toThrow(
      new KeyError('field-encryption: the ciphertext is too short'),
    );
  });

  it('still opens what the old version sealed once a new one is current, and seals new values with the new one', () => {
    const old = provider({ 'field-encryption': oneVersion(60) }).encrypt('field-encryption', contact, ROW);
    const afterRotation = provider({ 'field-encryption': rotated(60, 61) });
    const sealedNow = afterRotation.encrypt('field-encryption', contact, ROW);

    expect(afterRotation.decrypt('field-encryption', old, ROW)).toEqual(contact);
    expect(sealedNow.keyVersion).toBe(2);
    expect(afterRotation.decrypt('field-encryption', sealedNow, ROW)).toEqual(contact);
  });

  it('refuses a ciphertext whose stored version was changed to another key', () => {
    const keys = provider({ 'field-encryption': rotated(60, 61) });
    const { ciphertext } = keys.encrypt('field-encryption', contact, ROW);

    expect(() => keys.decrypt('field-encryption', { keyVersion: 1, ciphertext }, ROW)).toThrow(KeyError);
    expect(() => keys.decrypt('field-encryption', { keyVersion: 3, ciphertext }, ROW)).toThrow(
      new KeyError('field-encryption has no version 3'),
    );
  });
});

describe('signatures (Ed25519), for anchoring the audit chains', () => {
  const HEAD: Message = ['audit-head', ORG, '42', 'sha256:00ff'];

  it('signs with the current key and checks the signature', () => {
    const keys = provider();
    const { keyVersion, signature } = keys.sign('audit-anchor', HEAD);

    expect(keyVersion).toBe(1);
    expect(signature).toHaveLength(64);
    expect(keys.verifySignature('audit-anchor', keyVersion, HEAD, signature)).toBe(true);
  });

  it('can be checked by an outsider with the published public key and nothing of ours but the encoding', () => {
    const keys = provider();
    const { signature } = keys.sign('audit-anchor', HEAD);
    const published = keys.describe().find((entry) => entry.purpose === 'audit-anchor')?.versions[0]?.publicKey;
    if (published === undefined) throw new Error('the signing key has no public half');
    const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: published }, format: 'jwk' });

    expect(verify(null, encodeMessage(HEAD), publicKey, signature)).toBe(true);
  });

  it.each([
    ['another message', ['audit-head', ORG, '43', 'sha256:00ff'] as Message, (signature: Buffer) => signature],
    [
      'a changed signature',
      HEAD,
      (signature: Buffer) => Buffer.from(signature.map((byte, at) => (at === 0 ? byte ^ 1 : byte))),
    ],
    ['a signature cut short', HEAD, (signature: Buffer) => signature.subarray(0, 63)],
    ['an empty signature', HEAD, () => Buffer.alloc(0)],
  ])('refuses %s', (_what, message, change) => {
    const keys = provider();
    const { keyVersion, signature } = keys.sign('audit-anchor', HEAD);

    expect(keys.verifySignature('audit-anchor', keyVersion, message, change(signature))).toBe(false);
  });

  it("refuses another key's signature", () => {
    const { keyVersion, signature } = provider({ 'audit-anchor': oneVersion(200) }).sign('audit-anchor', HEAD);

    expect(provider().verifySignature('audit-anchor', keyVersion, HEAD, signature)).toBe(false);
  });

  it('still checks what the old version signed once a new one is current', () => {
    const old = provider({ 'audit-anchor': oneVersion(70) }).sign('audit-anchor', HEAD);
    const afterRotation = provider({ 'audit-anchor': rotated(70, 71) });
    const signedNow = afterRotation.sign('audit-anchor', HEAD);

    expect(afterRotation.verifySignature('audit-anchor', old.keyVersion, HEAD, old.signature)).toBe(true);
    expect(signedNow.keyVersion).toBe(2);
    expect(afterRotation.verifySignature('audit-anchor', 2, HEAD, old.signature)).toBe(false);
  });
});

describe('each key does only its own job', () => {
  // The compiler already refuses these; a caller it can't see (a cast, plain JavaScript) is refused at run time.
  it.each([
    [
      'a keyed hash with the encryption key',
      (keys: KeyProvider) => keys.mac('field-encryption' as MacPurpose, REQUEST),
      'field-encryption is not a mac key',
    ],
    [
      'a keyed hash with the signing key',
      (keys: KeyProvider) => keys.mac('audit-anchor' as MacPurpose, REQUEST),
      'audit-anchor is not a mac key',
    ],
    [
      'encryption with a hash key',
      (keys: KeyProvider) => keys.encrypt('audit-mac' as AeadPurpose, Buffer.of(1), ROW),
      'audit-mac is not a aead key',
    ],
    [
      'a signature with a hash key',
      (keys: KeyProvider) => keys.sign('audit-mac' as SigningPurpose, REQUEST),
      'audit-mac is not a signing key',
    ],
    [
      "a purpose that doesn't exist",
      (keys: KeyProvider) => keys.mac('api-token' as MacPurpose, REQUEST),
      'api-token is not a mac key',
    ],
  ])('refuses %s', (_what, use, message) => {
    expect(() => use(provider())).toThrow(new KeyError(message));
  });
});

describe('the keys stay inside the provider (ADR-011 §2)', () => {
  const encodings = (fill: number): string[] => {
    const bytes = key(fill);
    return [bytes.toString('hex'), bytes.toString('base64'), bytes.toString('base64url')];
  };

  it('offers operations only: nothing on it is a key', () => {
    const keys = provider();

    expect(Object.values(keys).every((value) => typeof value === 'function')).toBe(true);
    expect(JSON.stringify(keys)).toBe('{}');
    expect(Object.isFrozen(keys)).toBe(true);
  });

  it("describes every purpose, its current version and each version's check value, and never a key", () => {
    const description = provider({ 'audit-mac': rotated(80, 81) }).describe();
    const shown = JSON.stringify(description);

    expect(description.map((entry) => entry.purpose)).toEqual(PURPOSES);
    const auditMac = description.find((entry) => entry.purpose === 'audit-mac');
    expect(auditMac?.current).toBe(2);
    expect(auditMac?.versions.map((entry) => entry.version)).toEqual([1, 2]);
    for (const entry of description.flatMap(({ versions }) => versions)) expect(entry.check).toMatch(/^[0-9a-f]{32}$/);
    for (const fill of [1, 2, 3, 4, 5, 6, 80, 81]) {
      for (const encoding of encodings(fill)) expect(shown).not.toContain(encoding);
    }
  });

  it('gives a key the same check value wherever it is held, and another key another', () => {
    const checkOf = (keys: KeyProvider) =>
      keys.describe().find((entry) => entry.purpose === 'audit-mac')?.versions[0]?.check;

    expect(checkOf(provider())).toBe(checkOf(provider()));
    expect(checkOf(provider({ 'audit-mac': oneVersion(200) }))).not.toBe(checkOf(provider()));
  });

  it("shows a signing key's public half, and no other key has one", () => {
    const withPublicKey = provider()
      .describe()
      .filter((entry) => entry.versions.some((version) => version.publicKey !== undefined))
      .map((entry) => entry.purpose);

    expect(withPublicKey).toEqual(['audit-anchor']);
  });

  it("holds its own copy, so clearing the caller's bytes afterwards changes nothing", () => {
    const given = material();
    const keys = createKeyProvider(given);
    const before = keys.mac('audit-mac', REQUEST);
    for (const purpose of PURPOSES) for (const bytes of given[purpose].versions.values()) bytes.fill(0);

    expect(keys.mac('audit-mac', REQUEST)).toEqual(before);
  });
});

describe('which sets of keys can be used', () => {
  it('accepts a key for every purpose, each its own', () => {
    expect(keyMaterialProblems(material())).toEqual([]);
  });

  it('refuses a purpose without its current version, and says which file is missing', () => {
    const problems = keyMaterialProblems(material({ 'audit-mac': { current: 2, versions: new Map([[1, key(90)]]) } }));

    expect(problems).toEqual(['audit-mac has no key for its current version 2 (key-audit-mac-v2)']);
  });

  it.each([
    ['a second version', rotated(91, 92, 1)],
    ['a version other than 1 made current', rotated(91, 92)],
    ['only a version 2', { current: 2, versions: new Map([[2, key(92)]]) }],
  ])('refuses %s of the payee index key, which is never rotated in place (ADR-014 §3)', (_what, keys) => {
    expect(keyMaterialProblems(material({ 'payee-index': keys }))).toContain(
      'payee-index is never rotated in place (ADR-014 §3): only its version 1 may exist, and it stays current',
    );
  });

  it.each([31, 33, 0])('refuses a key of %i bytes', (length) => {
    const problems = keyMaterialProblems(
      material({ 'audit-mac': { current: 1, versions: new Map([[1, Buffer.alloc(length, 9)]]) } }),
    );

    expect(problems).toEqual(['key-audit-mac-v1 must be 32 bytes']);
  });

  it('refuses one key held for two purposes, or for two versions of one', () => {
    expect(keyMaterialProblems(material({ 'request-hash': oneVersion(3) }))).toEqual([
      'key-audit-mac-v1 holds the same key as key-request-hash-v1: every key must be its own',
    ]);
    expect(keyMaterialProblems(material({ 'audit-mac': rotated(95, 95) }))).toEqual([
      'key-audit-mac-v2 holds the same key as key-audit-mac-v1: every key must be its own',
    ]);
  });

  it('is refused by the provider too, with every problem listed', () => {
    expect(() =>
      createKeyProvider(material({ 'request-hash': oneVersion(3), 'payee-index': rotated(96, 97) })),
    ).toThrow(
      new KeyError(
        "The keys can't be used:\n" +
          '- key-audit-mac-v1 holds the same key as key-request-hash-v1: every key must be its own\n' +
          '- payee-index is never rotated in place (ADR-014 §3): only its version 1 may exist, and it stays current',
      ),
    );
  });
});
