import { describe, expect, it } from 'vitest';

import { createKeyProvider, KeyError, type KeyMaterial } from './key-provider.ts';
import type { Message } from './message.ts';
import { PURPOSES } from './purposes.ts';
import { publicKeyChecker } from './public-checker.ts';

/** The API's keys, one version each, and the anchor key rotated to a second version. */
const material = Object.fromEntries(
  PURPOSES.map((purpose, index) => [
    purpose,
    purpose === 'audit-anchor'
      ? {
          current: 2,
          versions: new Map([
            [1, Buffer.alloc(32, 40)],
            [2, Buffer.alloc(32, 41)],
          ]),
        }
      : { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) },
  ]),
) as unknown as KeyMaterial;
const signer = createKeyProvider(material);

/** The public keys as the API logs them at start. */
const published = new Map(
  (signer.describe().find((one) => one.purpose === 'audit-anchor')?.versions ?? []).map(({ version, publicKey }) => [
    version,
    String(publicKey),
  ]),
);

const message: Message = ['audit-anchor', '1', 'organisation:x', '4'];

describe("4D2e E9: checking the anchors' signatures with their public keys alone", () => {
  it('passes a signature the API made, under the version it names, and nothing else', () => {
    const checker = publicKeyChecker('audit-anchor', published);
    const { signature, keyVersion } = signer.sign('audit-anchor', message);
    expect(keyVersion).toBe(2);
    expect(checker.verifySignature('audit-anchor', 2, message, signature)).toBe(true);
    expect(checker.verifySignature('audit-anchor', 1, message, signature)).toBe(false);
    expect(checker.verifySignature('audit-anchor', 3, message, signature)).toBe(false);
    expect(checker.verifySignature('audit-anchor', 2, [...message, 'more'], signature)).toBe(false);
    // A purpose of its own to come (E11's rebase key): the anchor's public key never stands for it.
    expect(checker.verifySignature('audit-rebase' as 'audit-anchor', 2, message, signature)).toBe(false);
  });

  it('holds no key: every other use is refused', () => {
    const checker = publicKeyChecker('audit-anchor', published);
    expect(() => checker.sign('audit-anchor', message)).toThrow(KeyError);
    expect(() => checker.mac('audit-mac', message)).toThrow(KeyError);
    expect(() => checker.verifyMac('audit-mac', 1, message, Buffer.alloc(32))).toThrow(KeyError);
    expect(() => checker.encrypt('field-encryption', Buffer.alloc(1), message)).toThrow(KeyError);
    expect(() => checker.decrypt('field-encryption', { keyVersion: 1, ciphertext: Buffer.alloc(40) }, message)).toThrow(
      KeyError,
    );
    expect(checker.describe()).toEqual([]);
  });

  it("refuses a public key that isn't one", () => {
    expect(() => publicKeyChecker('audit-anchor', new Map([[1, 'not-a-key']]))).toThrow(
      "audit-anchor's public key version 1 isn't an Ed25519 public key",
    );
  });
});
