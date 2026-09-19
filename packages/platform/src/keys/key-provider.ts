// The KeyProvider (ADR-011 §2): every key the app holds, used only through the
// operations below, never handed out. A bank's HSM would offer the same
// operations with keys that can't be exported, so the interface never needs
// to change for one; this is the in-process provider our SaaS uses, its keys
// read from files the platform mounts (ADR-010: no cloud SDK).
//
// Every result carries the version of the key that made it, and a caller
// stores that version with it (ADR-014 §3). A new version becomes current for
// new work, and the older ones stay usable to check and read what they made,
// so a retry during a rotation still matches (SEC-DATA-07).
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  type KeyObject,
  randomBytes,
  sign as signBytes,
  timingSafeEqual,
  verify as verifyBytes,
} from 'node:crypto';

import { encodeMessage, type Message } from './message.ts';
import {
  type AeadPurpose,
  KEY_PURPOSES,
  type KeyKind,
  type KeyPurpose,
  type MacPurpose,
  PURPOSES,
  type SigningPurpose,
} from './purposes.ts';

/** Every key is 32 random bytes: an HMAC-SHA-256 key, an AES-256 key, or an Ed25519 seed. */
export const KEY_BYTES = 32;

/** AES-GCM's usual 96-bit nonce, fresh for every encryption, and its full 128-bit tag. */
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/** Ed25519's PKCS #8 wrapping of a 32-byte seed (RFC 8410): Node reads a private key only in a format like this. */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Refused use of a key: an unknown version, the wrong kind of key, or a ciphertext that doesn't open. Never names data. */
export class KeyError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'KeyError';
  }
}

/** A result and the version of the key that made it, which the caller stores with it. */
interface Keyed {
  readonly keyVersion: number;
}

export interface Mac extends Keyed {
  /** HMAC-SHA-256: 32 bytes. */
  readonly mac: Buffer;
}

export interface Sealed extends Keyed {
  /** The nonce (12 bytes), the tag (16 bytes), then the ciphertext. */
  readonly ciphertext: Buffer;
}

export interface Signature extends Keyed {
  /** Ed25519: 64 bytes. */
  readonly signature: Buffer;
}

/** A key version as the start-up log and the config fingerprint show it: never the key. */
export interface KeyVersionDescription {
  readonly version: number;
  /**
   * SHA-256 of a fixed label and the key, cut to 128 bits: it changes when the
   * key does, so a key swapped under the same version shows in the
   * fingerprint. Safe to show, since every key is 32 random bytes and can't be
   * guessed from it.
   */
  readonly check: string;
  /** A signing key's public half, base64url (the JWK `x`), for anyone checking a signature. */
  readonly publicKey?: string;
}

export interface KeyDescription {
  readonly purpose: KeyPurpose;
  readonly current: number;
  readonly versions: readonly KeyVersionDescription[];
}

export interface KeyProvider {
  /**
   * A keyed hash of the message with the current key, or with version
   * `atLeast` where that is newer. Something sealed in a line, like an audit
   * chain, stays on the newest version it has reached, whatever this process
   * has as current: a release rolled back, or two running side by side during
   * a rotation. Throws a KeyError if that version isn't held.
   */
  mac(purpose: MacPurpose, message: Message, atLeast?: number): Mac;
  /** Whether `mac` is the keyed hash of the message with that version, compared in constant time. */
  verifyMac(purpose: MacPurpose, keyVersion: number, message: Message, mac: Uint8Array): boolean;
  /**
   * Encrypts with the current key. The associated data is bound to the
   * ciphertext without being stored in it: the IDs of the row it belongs to
   * (ADR-012 §2), so a value copied to another row or organisation won't open.
   */
  encrypt(purpose: AeadPurpose, plaintext: Uint8Array, associatedData: Message): Sealed;
  /** Opens a ciphertext, or throws a KeyError: wrong key, wrong associated data, or changed bytes. */
  decrypt(purpose: AeadPurpose, sealed: Sealed, associatedData: Message): Buffer;
  sign(purpose: SigningPurpose, message: Message): Signature;
  verifySignature(purpose: SigningPurpose, keyVersion: number, message: Message, signature: Uint8Array): boolean;
  /** Every purpose's versions, current version and check values. */
  describe(): readonly KeyDescription[];
}

/** One purpose's keys: every version held, by number, and the one new work uses. */
export interface PurposeKeys {
  readonly current: number;
  readonly versions: ReadonlyMap<number, Uint8Array>;
}

export type KeyMaterial = Readonly<Record<KeyPurpose, PurposeKeys>>;

/**
 * Why a set of keys can't be used, or nothing: every purpose has its current
 * version, every key is 32 bytes and none is another's copy, and a key that is
 * never rotated in place has only version 1 (ADR-014 §3).
 */
export function keyMaterialProblems(material: KeyMaterial): string[] {
  const problems: string[] = [];
  const seen = new Map<string, string>();
  for (const purpose of PURPOSES) {
    const { current, versions } = material[purpose];
    if (!versions.has(current)) {
      problems.push(`${purpose} has no key for its current version ${current} (key-${purpose}-v${current})`);
    }
    // A current version other than 1 is either missing (above) or among the versions.
    if (!KEY_PURPOSES[purpose].rotates && [...versions.keys()].some((version) => version !== 1)) {
      problems.push(
        `${purpose} is never rotated in place (ADR-014 §3): only its version 1 may exist, and it stays current`,
      );
    }
    for (const [version, key] of versions) {
      const name = `key-${purpose}-v${version}`;
      if (key.length !== KEY_BYTES) {
        problems.push(`${name} must be ${KEY_BYTES} bytes`);
        continue;
      }
      const check = checkValue(key);
      const twin = seen.get(check);
      if (twin === undefined) seen.set(check, name);
      else problems.push(`${name} holds the same key as ${twin}: every key must be its own`);
    }
  }
  return problems;
}

function checkValue(key: Uint8Array): string {
  return createHash('sha256').update('agentx key check value\0').update(key).digest('hex').slice(0, 32);
}

interface Held {
  readonly kind: KeyKind;
  readonly current: number;
  readonly keys: ReadonlyMap<number, KeyObject>;
  readonly description: KeyDescription;
}

function holdKey(kind: KeyKind, key: Uint8Array): KeyObject {
  return kind === 'signing'
    ? createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, key]), format: 'der', type: 'pkcs8' })
    : createSecretKey(key);
}

function hold(purpose: KeyPurpose, { current, versions }: PurposeKeys): Held {
  const { kind } = KEY_PURPOSES[purpose];
  const keys = new Map<number, KeyObject>();
  const described: KeyVersionDescription[] = [];
  for (const [version, bytes] of [...versions].sort(([a], [b]) => a - b)) {
    const key = holdKey(kind, bytes);
    keys.set(version, key);
    const publicKey = kind === 'signing' ? createPublicKey(key).export({ format: 'jwk' }).x : undefined;
    described.push(
      Object.freeze(
        publicKey === undefined
          ? { version, check: checkValue(bytes) }
          : { version, check: checkValue(bytes), publicKey },
      ),
    );
  }
  return {
    kind,
    current,
    keys,
    description: Object.freeze({ purpose, current, versions: Object.freeze(described) }),
  };
}

/**
 * The in-process provider, holding its own copy of each key. Throws a
 * KeyError if the keys break a rule of `keyMaterialProblems`.
 *
 * Nothing clears the bytes it was given: JavaScript can't clear the strings a
 * key was read through, so the protection is the process's own memory, not
 * wiping one copy of several (ADR-011 §2: an HSM adapter is the answer for a
 * bank that needs more).
 */
export function createKeyProvider(material: KeyMaterial): KeyProvider {
  const problems = keyMaterialProblems(material);
  if (problems.length > 0) throw new KeyError(`The keys can't be used:\n- ${problems.join('\n- ')}`);
  const held = new Map(PURPOSES.map((purpose) => [purpose, hold(purpose, material[purpose])]));

  // A caller the compiler can't see (plain JavaScript, or a cast) could still
  // name another kind's purpose: refuse it rather than use a key for the wrong job.
  const heldAs = (purpose: KeyPurpose, kind: KeyKind): Held => {
    const entry = held.get(purpose);
    if (entry?.kind !== kind) throw new KeyError(`${purpose} is not a ${kind} key`);
    return entry;
  };
  const keyFor = (purpose: KeyPurpose, kind: KeyKind, version: number): KeyObject => {
    const key = heldAs(purpose, kind).keys.get(version);
    if (key === undefined) throw new KeyError(`${purpose} has no version ${version}`);
    return key;
  };
  const currentOf = (purpose: KeyPurpose, kind: KeyKind): { version: number; key: KeyObject } => {
    const { current } = heldAs(purpose, kind);
    return { version: current, key: keyFor(purpose, kind, current) };
  };
  const hmac = (key: KeyObject, message: Message): Buffer =>
    createHmac('sha256', key).update(encodeMessage(message)).digest();

  return Object.freeze({
    mac(purpose: MacPurpose, message: Message, atLeast?: number): Mac {
      const { current } = heldAs(purpose, 'mac');
      const version = atLeast !== undefined && atLeast > current ? atLeast : current;
      return Object.freeze({ keyVersion: version, mac: hmac(keyFor(purpose, 'mac', version), message) });
    },

    verifyMac(purpose: MacPurpose, keyVersion: number, message: Message, mac: Uint8Array): boolean {
      const expected = hmac(keyFor(purpose, 'mac', keyVersion), message);
      // The length is public (always 32); only the bytes are compared in constant time.
      return mac.length === expected.length && timingSafeEqual(mac, expected);
    },

    encrypt(purpose: AeadPurpose, plaintext: Uint8Array, associatedData: Message): Sealed {
      const { version, key } = currentOf(purpose, 'aead');
      const nonce = randomBytes(NONCE_BYTES);
      const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
      cipher.setAAD(encodeMessage(associatedData));
      const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return Object.freeze({ keyVersion: version, ciphertext: Buffer.concat([nonce, cipher.getAuthTag(), body]) });
    },

    decrypt(purpose: AeadPurpose, sealed: Sealed, associatedData: Message): Buffer {
      const key = keyFor(purpose, 'aead', sealed.keyVersion);
      const { ciphertext } = sealed;
      if (ciphertext.length < NONCE_BYTES + TAG_BYTES) throw new KeyError(`${purpose}: the ciphertext is too short`);
      const decipher = createDecipheriv('aes-256-gcm', key, ciphertext.subarray(0, NONCE_BYTES), {
        authTagLength: TAG_BYTES,
      });
      decipher.setAuthTag(ciphertext.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES));
      decipher.setAAD(encodeMessage(associatedData));
      try {
        return Buffer.concat([decipher.update(ciphertext.subarray(NONCE_BYTES + TAG_BYTES)), decipher.final()]);
      } catch (error) {
        throw new KeyError(
          `${purpose}: the ciphertext doesn't open: the wrong key or associated data, or its bytes were changed`,
          // Node's reason, "unable to authenticate data", names nothing secret.
          { cause: error },
        );
      }
    },

    sign(purpose: SigningPurpose, message: Message): Signature {
      const { version, key } = currentOf(purpose, 'signing');
      return Object.freeze({ keyVersion: version, signature: signBytes(null, encodeMessage(message), key) });
    },

    verifySignature(purpose: SigningPurpose, keyVersion: number, message: Message, signature: Uint8Array): boolean {
      const key = keyFor(purpose, 'signing', keyVersion);
      return verifyBytes(null, encodeMessage(message), key, signature);
    },

    describe(): readonly KeyDescription[] {
      return Object.freeze([...held.values()].map((entry) => entry.description));
    },
  });
}
