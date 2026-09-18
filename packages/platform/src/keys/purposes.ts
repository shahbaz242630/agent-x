// The keys the app holds (ADR-011 §1–§3, ADR-012 §2, ADR-014 §3): one per job,
// so a key only ever does the one thing it was made for, and each can be
// rotated on its own. A purpose's name is fixed once a key exists: it is part
// of its key files' names and its vault secrets' names.

/** What a key does: keyed hashes (HMAC-SHA-256), encryption (AES-256-GCM) or signatures (Ed25519). */
export type KeyKind = 'mac' | 'aead' | 'signing';

export const KEY_PURPOSES = {
  /** ADR-011 §1: an agent key is stored as an HMAC of its secret with this pepper. */
  'agent-key-pepper': { kind: 'mac', rotates: true },
  /** ADR-014 §3: the idempotency table's request hashes. */
  'request-hash': { kind: 'mac', rotates: true },
  /** ADR-012 §2: the MAC on every audit event. */
  'audit-mac': { kind: 'mac', rotates: true },
  /**
   * ADR-014 §3: the payee key's fingerprint of an account. Never rotated in
   * place: only the fingerprints are stored, so they can't be recomputed with a
   * new key. If it is ever exposed, payees are registered again.
   */
  'payee-index': { kind: 'mac', rotates: false },
  /** ADR-011 §2: sensitive fields, such as a supplier's contact details. */
  'field-encryption': { kind: 'aead', rotates: true },
  /** ADR-011 §3: signs the audit chains' heads, so an outsider can check them with its public key. */
  'audit-anchor': { kind: 'signing', rotates: true },
} as const satisfies Readonly<Record<string, { readonly kind: KeyKind; readonly rotates: boolean }>>;

export type KeyPurpose = keyof typeof KEY_PURPOSES;

type PurposeOf<Kind extends KeyKind> = {
  [Purpose in KeyPurpose]: (typeof KEY_PURPOSES)[Purpose]['kind'] extends Kind ? Purpose : never;
}[KeyPurpose];

export type MacPurpose = PurposeOf<'mac'>;
export type AeadPurpose = PurposeOf<'aead'>;
export type SigningPurpose = PurposeOf<'signing'>;

/** Every purpose, in a fixed order. */
export const PURPOSES = Object.keys(KEY_PURPOSES) as readonly KeyPurpose[];

export const isKeyPurpose = (name: string): name is KeyPurpose => Object.hasOwn(KEY_PURPOSES, name);

/** A value for every purpose, each made by `make`. */
export function byPurpose<T>(make: (purpose: KeyPurpose) => T): Record<KeyPurpose, T> {
  // Built from PURPOSES, so every purpose is there; the compiler can't follow fromEntries.
  return Object.fromEntries(PURPOSES.map((purpose) => [purpose, make(purpose)])) as Record<KeyPurpose, T>;
}
