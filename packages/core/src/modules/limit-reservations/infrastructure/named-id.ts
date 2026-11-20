// An ID named by what it is the row of (GM-1a): the same parts always give the
// same ID, so a row the app finds gone can be told from one never made: its
// signed events are still in the log under that ID. Every other row ID is made
// at random by time (the shared kernel's ids.ts, ADR-007); kept here, not in the shared kernel, which may import nothing but uuid (ADR-004).
import { createHash } from 'node:crypto';

/**
 * A UUID named by `parts` (each lower-cased, so an ID in either case names the
 * same row): the first 16 bytes of the SHA-256 of their JSON, marked as
 * RFC 9562's version 8 (a UUID made by its own rule) and its variant.
 */
export function namedId(parts: readonly string[]): string {
  const hash = createHash('sha256')
    .update(JSON.stringify(parts.map((part) => part.toLowerCase())))
    .digest();
  // The version's four bits, then the variant's two (10), as RFC 9562 §5.8 places them.
  hash.writeUInt8((hash.readUInt8(6) & 0x0f) | 0x80, 6);
  hash.writeUInt8((hash.readUInt8(8) & 0x3f) | 0x80, 8);
  const hex = hash.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
