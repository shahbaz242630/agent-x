// PKCE (RFC 7636; OAuth 2.1 §4.1.1; SEC-OAUTH-02): S256 alone, never
// `plain`, and on every authorization code. The client sends a challenge,
// BASE64URL(SHA-256(verifier)), with its request, and the verifier with its
// code: a code taken on its way back is useless without it.
import { createHash, timingSafeEqual } from 'node:crypto';

/** The one method taken (OAuth 2.1: `plain` is never offered). */
export const PKCE_METHOD = 'S256';

/** RFC 7636 §4.1: 43 to 128 unreserved characters. */
const VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

/** A SHA-256 in base64url without padding: always 43 characters. */
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

export const isCodeVerifier = (value: string): boolean => VERIFIER.test(value);

export const isCodeChallenge = (value: string): boolean => CHALLENGE.test(value);

/** The S256 challenge of a verifier. */
export const challengeOf = (verifier: string): string =>
  createHash('sha256').update(verifier, 'ascii').digest('base64url');

/**
 * Whether the verifier is the one the challenge was made from: a well-formed verifier, and its challenge equal to
 * the one kept, compared in constant time.
 */
export function pkceMatches(verifier: string, challenge: string): boolean {
  if (!isCodeVerifier(verifier) || !isCodeChallenge(challenge)) return false;
  return timingSafeEqual(Buffer.from(challengeOf(verifier), 'ascii'), Buffer.from(challenge, 'ascii'));
}
