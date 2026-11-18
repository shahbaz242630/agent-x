// The random texts the authorization server hands out (6E3a): a client's ID,
// an authorization code, and the browser's flow cookie; and a device flow's
// two codes (6E3c, RFC 8628 §3.2): the device code the device polls with,
// and the short user code the person types. Each is kept as its SHA-256
// alone where it is a secret, so a copy of the table holds nothing that
// works.
import { createHash, randomBytes, randomInt } from 'node:crypto';

/** What every authorization code starts with, so the log scrubber knows one (scrub.ts). */
const CODE_PREFIX = 'axc_';

/** What every self-registered client's ID starts with. */
const CLIENT_ID_PREFIX = 'axcl_';

/** 256 bits of randomness, as every secret here has. */
const SECRET_BYTES = 32;

/** What every device code starts with, so the log scrubber knows one too. */
const DEVICE_CODE_PREFIX = 'axd_';

/**
 * The letters a user code is made of (RFC 8628 §6.1's own set): 20 consonants, no vowels, so no word is ever spelt.
 * 20^8 codes, about 2^34.6, against a lookup of 5 tries a minute a person (oauth-device.ts).
 */
const USER_CODE_LETTERS = 'BCDFGHJKLMNPQRSTVWXZ';

/** How many letters a user code has; shown as two groups of four. */
const USER_CODE_LENGTH = 8;

const CODE_TEXT = /^axc_[A-Za-z0-9_-]{43}$/;
const DEVICE_CODE_TEXT = /^axd_[A-Za-z0-9_-]{43}$/;
const USER_CODE_TEXT = new RegExp(`^[${USER_CODE_LETTERS}]{${String(USER_CODE_LENGTH)}}$`);
const COOKIE_TEXT = /^[A-Za-z0-9_-]{43}$/;
const CLIENT_ID_TEXT = /^axcl_[0-9a-f]{32}$/;

/** A new authorization code: shown once, in the redirect, and kept as its hash. */
export const newCode = (): string => `${CODE_PREFIX}${randomBytes(SECRET_BYTES).toString('base64url')}`;

/** A new flow cookie's value: the browser holds it, the flow keeps its hash. */
export const newFlowCookie = (): string => randomBytes(SECRET_BYTES).toString('base64url');

/** A new client's ID: public, never a secret (`none`, decision 3), but never guessable either. */
export const newClientId = (): string => `${CLIENT_ID_PREFIX}${randomBytes(16).toString('hex')}`;

/** A new device code: handed to the device once, kept as its hash. */
export const newDeviceCode = (): string => `${DEVICE_CODE_PREFIX}${randomBytes(SECRET_BYTES).toString('base64url')}`;

/** A new user code, as the person reads it: two groups of four letters, `BCDF-GHJK`, each letter drawn evenly. */
export function newUserCode(): string {
  const letters = Array.from({ length: USER_CODE_LENGTH }, () => USER_CODE_LETTERS.charAt(randomInt(20))).join('');
  return `${letters.slice(0, 4)}-${letters.slice(4)}`;
}

/**
 * The user code as typed, read as the code it is: capitals or not, with or without its dash or spaces; undefined for
 * text that can be no user code (never looked up).
 */
export function userCodeOf(typed: string): string | undefined {
  const letters = typed.toUpperCase().replaceAll(/[\s-]/g, '');
  return USER_CODE_TEXT.test(letters) ? letters : undefined;
}

export const isCodeText = (text: string): boolean => CODE_TEXT.test(text);

export const isDeviceCodeText = (text: string): boolean => DEVICE_CODE_TEXT.test(text);

export const isFlowCookie = (text: string): boolean => COOKIE_TEXT.test(text);

export const isRegisteredClientId = (text: string): boolean => CLIENT_ID_TEXT.test(text);

/** A secret as it is kept: its SHA-256, in lower-case hex. */
export const hashOf = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
