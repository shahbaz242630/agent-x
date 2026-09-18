// What a key works on is a list of parts, never one string glued together by
// the caller (ADR-012 §2: org ‖ object ‖ version ‖ content). Each part is
// written as its length, then its bytes, so no two different lists give the
// same input: ['ab', 'c'] and ['a', 'bc'] can't share a MAC.

/** One part: text (written as UTF-8) or bytes. */
export type MessagePart = string | Uint8Array;

/** At least one part: a key never works on nothing. */
export type Message = readonly [MessagePart, ...MessagePart[]];

/** The length prefix: 4 bytes, big-endian. */
const LENGTH_BYTES = 4;

/** The bytes a key works on: each part's length, then the part. */
export function encodeMessage(parts: Message): Buffer {
  const chunks = parts.flatMap((part) => {
    const bytes = typeof part === 'string' ? Buffer.from(part, 'utf8') : part;
    const length = Buffer.alloc(LENGTH_BYTES);
    length.writeUInt32BE(bytes.length);
    return [length, bytes];
  });
  return Buffer.concat(chunks);
}
