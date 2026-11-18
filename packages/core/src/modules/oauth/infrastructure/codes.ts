// The random texts the authorization server hands out (6E3a): a client's ID,
// an authorization code, and the browser's flow cookie. Each is kept as its
// SHA-256 alone where it is a secret, so a copy of the table holds nothing
// that works.
import { createHash, randomBytes } from 'node:crypto';

/** What every authorization code starts with, so the log scrubber knows one (scrub.ts). */
const CODE_PREFIX = 'axc_';

/** What every self-registered client's ID starts with. */
const CLIENT_ID_PREFIX = 'axcl_';

/** 256 bits of randomness, as every secret here has. */
const SECRET_BYTES = 32;

const CODE_TEXT = /^axc_[A-Za-z0-9_-]{43}$/;
const COOKIE_TEXT = /^[A-Za-z0-9_-]{43}$/;
const CLIENT_ID_TEXT = /^axcl_[0-9a-f]{32}$/;

/** A new authorization code: shown once, in the redirect, and kept as its hash. */
export const newCode = (): string => `${CODE_PREFIX}${randomBytes(SECRET_BYTES).toString('base64url')}`;

/** A new flow cookie's value: the browser holds it, the flow keeps its hash. */
export const newFlowCookie = (): string => randomBytes(SECRET_BYTES).toString('base64url');

/** A new client's ID: public, never a secret (`none`, decision 3), but never guessable either. */
export const newClientId = (): string => `${CLIENT_ID_PREFIX}${randomBytes(16).toString('hex')}`;

export const isCodeText = (text: string): boolean => CODE_TEXT.test(text);

export const isFlowCookie = (text: string): boolean => COOKIE_TEXT.test(text);

export const isRegisteredClientId = (text: string): boolean => CLIENT_ID_TEXT.test(text);

/** A secret as it is kept: its SHA-256, in lower-case hex. */
export const hashOf = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
