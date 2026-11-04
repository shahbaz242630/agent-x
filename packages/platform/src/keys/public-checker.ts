// A key provider that holds no key (4D2e E9, PL-29): only the public halves of
// one signing purpose's versions, as the API logs them at start (`api.starting`,
// keys). The operator checks the anchors' signatures with it, so it can read the
// anchors' store and never sign a line there itself. Every other use is refused.
import { createPublicKey, type KeyObject, verify } from 'node:crypto';

import { KeyError, type KeyProvider } from './key-provider.ts';
import { encodeMessage } from './message.ts';
import type { SigningPurpose } from './purposes.ts';

/** Checks `purpose`'s signatures with the public keys given, by version (each the JWK `x`, base64url); nothing else. */
export function publicKeyChecker(purpose: SigningPurpose, publicKeys: ReadonlyMap<number, string>): KeyProvider {
  const keys = new Map<number, KeyObject>();
  for (const [version, x] of publicKeys) {
    try {
      keys.set(version, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' }));
    } catch {
      throw new KeyError(`${purpose}'s public key version ${String(version)} isn't an Ed25519 public key`);
    }
  }
  const refuse = (): never => {
    throw new KeyError(`This process holds only ${purpose}'s public keys: it checks a signature, and nothing more`);
  };
  const checker: KeyProvider = {
    mac: refuse,
    verifyMac: refuse,
    encrypt: refuse,
    decrypt: refuse,
    sign: refuse,
    verifySignature(asked, version, message, signature) {
      const key = asked === purpose ? keys.get(version) : undefined;
      return key !== undefined && verify(null, encodeMessage(message), key, signature);
    },
    describe: () => [],
  };
  return Object.freeze(checker);
}
