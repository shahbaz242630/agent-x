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
  /**
   * PRD §5.2: the evaluated-input hash every spend request's decision keeps as
   * evidence (Phase 2 D4). Its own key, as a request hash's version may be
   * retired once the idempotency retention has passed, while a decision's is
   * checked for good: rotated by a new version, the old ones never retired.
   */
  'decision-hash': { kind: 'mac', rotates: true },
  /**
   * PL-57: signs the operator's command's events on the platform chain, held by
   * the operator's job alone. The API holds only its public half, to check
   * them: a foothold in the API can't sign an operator's act.
   */
  'operator-signing': { kind: 'signing', rotates: true },
  /**
   * 4D2e E11: signs a rebase, which moves a chain's anchor on after a sanctioned
   * change to the chain (rebase.ts), held by the operator's job alone. The API
   * checks it with the public half: a foothold in the API can't move an anchor.
   */
  'audit-rebase': { kind: 'signing', rotates: true },
  /**
   * S205 tamper pass: the MAC on each console session and step-up challenge
   * (identity/infrastructure/row-macs.ts), so a row the database's owner plants
   * or edits signs no one in and verifies no change (ADR-012 §2). Rotated by a
   * new version: a row is checked with the version it names, and a session
   * lives at most a day, so an old version can go once its rows have ended.
   */
  'session-mac': { kind: 'mac', rotates: true },
  /**
   * TR-20 (R-12): signs the witness log's snapshots, held by the copy that
   * holds the jobs alone. A `web` copy checks them with the public half: one
   * broken into can't sign a snapshot that leaves a witnessed head out, as it
   * could while snapshots were signed with `audit-anchor`, which every copy holds.
   */
  'witness-snapshot': { kind: 'signing', rotates: true },
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

/** The keys the operator's command holds and the API never does (PL-57, E11): the API checks with their public halves. */
export const OPERATOR_ONLY: readonly SigningPurpose[] = ['operator-signing', 'audit-rebase'];

/** Every purpose the API holds: all but the operator's own. */
export const API_PURPOSES: readonly KeyPurpose[] = PURPOSES.filter(
  (purpose) => !(OPERATOR_ONLY as readonly KeyPurpose[]).includes(purpose),
);

/** The keys only the copy that holds the jobs holds (TR-20): a `web` copy checks with their public halves. */
export const JOBS_ONLY: readonly SigningPurpose[] = ['witness-snapshot'];

/** Every purpose a `web` copy of the API holds: the API's, but the jobs' own. */
export const WEB_PURPOSES: readonly KeyPurpose[] = API_PURPOSES.filter(
  (purpose) => !(JOBS_ONLY as readonly KeyPurpose[]).includes(purpose),
);

/** What a `web` copy checks with public halves alone: the operator's keys and the jobs' own. */
export const WEB_CHECKS: readonly SigningPurpose[] = [...OPERATOR_ONLY, ...JOBS_ONLY];

export const isKeyPurpose = (name: string): name is KeyPurpose => Object.hasOwn(KEY_PURPOSES, name);

/**
 * A value for every purpose, each made by `make`. Only tests use it (key
 * material for every purpose); it stays beside the list it walks rather than
 * making the testing package depend on this one for three lines (S64 sweep).
 */
export function byPurpose<T>(make: (purpose: KeyPurpose) => T): Record<KeyPurpose, T> {
  // Built from PURPOSES, so every purpose is there; the compiler can't follow fromEntries.
  return Object.fromEntries(PURPOSES.map((purpose) => [purpose, make(purpose)])) as Record<KeyPurpose, T>;
}
