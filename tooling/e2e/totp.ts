// Time-based one-time passwords (RFC 6238 over RFC 4226), for the test user
// whose second factor is an authenticator app. HMAC-SHA1, 30-second steps,
// 6 digits: what Zitadel issues and every authenticator app uses.
import { createHmac } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32, as authenticator secrets are written: case and padding don't matter. */
export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replaceAll(/[\s=]/g, '');
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error(`not a base32 character: ${JSON.stringify(char)}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

/** The code for one time step (RFC 4226 §5.3). */
export function hotp(secret: Buffer, counter: bigint, digits = 6): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = createHmac('sha1', secret).update(message).digest();
  const offset = (digest.at(-1) ?? 0) & 0x0f;
  const binary = ((digest.readUInt32BE(offset) & 0x7f_ff_ff_ff) % 10 ** digits).toString();
  return binary.padStart(digits, '0');
}

/** The code valid at `atMs` (milliseconds since 1970), for a base32 secret. */
export function totp(secret: string, atMs: number, stepSeconds = 30, digits = 6): string {
  return hotp(base32Decode(secret), BigInt(Math.floor(atMs / 1000 / stepSeconds)), digits);
}
