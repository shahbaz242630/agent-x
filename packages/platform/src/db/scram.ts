// A role's login as Postgres stores it: a SCRAM-SHA-256 verifier (RFC 5802,
// RFC 7677), worked out here so the login itself never reaches the server. The
// set-up job sends `ALTER ROLE … PASSWORD '<verifier>'`, which Postgres stores
// as it is, the way psql's \password does. A statement the server logs (a
// failed one, or every one where statement logging is on) then carries a
// salted hash that can't be used to log in, never the login.
import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';

/** Postgres's defaults: `scram_iterations` and the salt length its own client library uses. */
const ITERATIONS = 4096;
const SALT_BYTES = 16;

/**
 * Printable ASCII without spaces. Postgres prepares a login with SASLprep
 * before hashing it, which leaves these characters as they are; anything else
 * could be changed by SASLprep, and the verifier would stop matching.
 */
const PLAIN_LOGIN = /^[\x21-\x7e]+$/;

export class ScramInputError extends Error {
  constructor(problem: string) {
    super(`Can't make a SCRAM verifier: ${problem}`);
    this.name = 'ScramInputError';
  }
}

export interface ScramOptions {
  /** A fresh 16 random bytes when not given; tests pass one to compare with Postgres's own result. */
  readonly salt?: Buffer;
  readonly iterations?: number;
}

/**
 * The SCRAM-SHA-256 verifier Postgres would store for this login, in its
 * format: `SCRAM-SHA-256$<iterations>:<salt>$<stored key>:<server key>`, the
 * last three in base64, so it holds no quote.
 */
export function scramVerifier(login: string, options: ScramOptions = {}): string {
  if (!PLAIN_LOGIN.test(login)) {
    throw new ScramInputError('the login must be printable ASCII with no spaces, which SASLprep leaves unchanged');
  }
  const salt = options.salt ?? randomBytes(SALT_BYTES);
  const iterations = options.iterations ?? ITERATIONS;
  if (salt.length === 0) throw new ScramInputError('the salt is empty');
  if (!Number.isSafeInteger(iterations) || iterations < 1) {
    throw new ScramInputError('the iteration count must be a whole number of at least 1');
  }
  const salted = pbkdf2Sync(login, salt, iterations, 32, 'sha256');
  const client = createHmac('sha256', salted).update('Client Key').digest();
  const stored = createHash('sha256').update(client).digest();
  const server = createHmac('sha256', salted).update('Server Key').digest();
  return `SCRAM-SHA-256$${String(iterations)}:${salt.toString('base64')}$${stored.toString('base64')}:${server.toString('base64')}`;
}
