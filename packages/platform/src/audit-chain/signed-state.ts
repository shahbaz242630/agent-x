// Signed state (ADR-012 §2): every field that grants, restores or limits
// authority (a status, a role, a limit, an expiry) must equal its latest signed
// event. That event carries a seal of the object's authority fields: a keyed
// hash, with the `audit-mac` key the database never holds, over the
// organisation, the object's type, ID and version, and each field by name.
// Someone with only the database can change a field, or point a row back at an
// older version, but can't make a seal to match.
//
// The seal travels in the event's details (`stateFingerprint`,
// `stateKeyVersion`), so the event's own hash and MAC cover it as well; an
// audit event that carries one is a signed-state event. Its message starts
// with its own label, so it can never pass for an event's or a head's MAC,
// though the key is the same.
//
// The fields come as canonical text, or null: whoever records and whoever
// checks must read each field the same way (the row side, A3b-2, reads them
// in SQL). A field's name goes in with its value, so values moved from one
// field to another don't match either.
import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';

/** What a signed state is about, and what it holds. */
export interface StateFacts {
  readonly orgId: string;
  /** The object, as its audit events name it: type, ID, and the version this state is. */
  readonly subject: { readonly type: string; readonly id: string; readonly version: number };
  /** The authority fields, by name, always in the same order: canonical text, or null. */
  readonly fields: readonly (readonly [name: string, value: string | null])[];
}

/** A state's seal, and the key version it was made with. */
export interface StateSeal {
  readonly fingerprint: Buffer;
  readonly keyVersion: number;
}

/** The two details a signed-state event carries its seal in. */
export interface StateSealDetails {
  /** The seal as 64 lower-case hex digits. */
  readonly stateFingerprint: string;
  readonly stateKeyVersion: number;
}

const FINGERPRINT = /^[0-9a-f]{64}$/;

/**
 * The seal's message, or nothing for facts no row could hold: a seal over no
 * fields would match any row, and a version is a whole number from 1.
 */
function stateMessage({ orgId, subject, fields }: StateFacts): Message | undefined {
  if (fields.length === 0 || !Number.isSafeInteger(subject.version) || subject.version < 1) return undefined;
  return [
    'signed-state',
    orgId.toLowerCase(),
    subject.type,
    subject.id.toLowerCase(),
    subject.version.toString(),
    // `null` and `value` tell a missing value from the text "null".
    ...fields.flatMap(([name, value]) => (value === null ? ['field', name, 'null'] : ['field', name, 'value', value])),
  ];
}

/** Seals the state with the current key. Throws a RangeError for facts no row could hold. */
export function sealState(keys: KeyProvider, facts: StateFacts): StateSeal {
  const message = stateMessage(facts);
  if (message === undefined) throw new RangeError('A state seal needs at least one field and a version from 1');
  const { mac, keyVersion } = keys.mac('audit-mac', message);
  return Object.freeze({ fingerprint: mac, keyVersion });
}

/**
 * Whether the seal is the one for this state. A key version the app doesn't
 * hold, a fingerprint of the wrong length, or facts no row could hold, is
 * simply a mismatch: what the database hands back can't be trusted to be well
 * formed.
 */
export function stateSealMatches(keys: KeyProvider, facts: StateFacts, seal: StateSeal): boolean {
  const message = stateMessage(facts);
  if (message === undefined) return false;
  try {
    return keys.verifyMac('audit-mac', seal.keyVersion, message, seal.fingerprint);
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/** The seal as an event's details. */
export function stateSealDetails(seal: StateSeal): StateSealDetails {
  return { stateFingerprint: seal.fingerprint.toString('hex'), stateKeyVersion: seal.keyVersion };
}

/**
 * The seal in an event's details: undefined if they carry none, `malformed` if
 * they carry only half of one, or either half isn't what stateSealDetails
 * writes. The details may come from anywhere, the database included.
 */
export function stateSealIn(details: Readonly<Record<string, unknown>>): StateSeal | 'malformed' | undefined {
  const hasFingerprint = Object.hasOwn(details, 'stateFingerprint');
  const hasKeyVersion = Object.hasOwn(details, 'stateKeyVersion');
  if (!hasFingerprint && !hasKeyVersion) return undefined;
  const { stateFingerprint: fingerprint, stateKeyVersion: keyVersion } = details;
  if (typeof fingerprint !== 'string' || !FINGERPRINT.test(fingerprint)) return 'malformed';
  if (typeof keyVersion !== 'number' || !Number.isSafeInteger(keyVersion) || keyVersion < 1) return 'malformed';
  return Object.freeze({ fingerprint: Buffer.from(fingerprint, 'hex'), keyVersion });
}
