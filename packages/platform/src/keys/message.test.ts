import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { encodeMessage, type Message } from './message.ts';

/** Reads the parts back out of an encoding, as bytes: proof that no two lists of parts share one. */
function decode(encoded: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  for (let at = 0; at < encoded.length;) {
    const length = encoded.readUInt32BE(at);
    parts.push(encoded.subarray(at + 4, at + 4 + length));
    at += 4 + length;
  }
  return parts;
}

const bytesOf = (part: string | Uint8Array): Buffer =>
  typeof part === 'string' ? Buffer.from(part, 'utf8') : Buffer.from(part);

describe('the parts a key works on', () => {
  it('writes each part as its length, then its bytes', () => {
    expect(encodeMessage(['ab', Uint8Array.of(7)]).toString('hex')).toBe('00000002616200000001' + '07');
  });

  it('keeps an empty part, so a missing value and an empty one still differ from no part', () => {
    expect(encodeMessage(['a', '']).toString('hex')).toBe('0000000161' + '00000000');
  });

  it('gives lists that join to the same text different inputs', () => {
    expect(encodeMessage(['ab', 'c'])).not.toEqual(encodeMessage(['a', 'bc']));
    expect(encodeMessage(['abc'])).not.toEqual(encodeMessage(['ab', 'c']));
  });

  it('can always be read back into the same parts, so different lists never collide', () => {
    const part = fc.oneof(fc.string({ unit: 'binary' }), fc.uint8Array());
    const message = fc.tuple(part, fc.array(part)).map(([first, rest]): Message => [first, ...rest]);
    fc.assert(
      fc.property(message, (parts) => {
        expect(decode(encodeMessage(parts))).toEqual(parts.map(bytesOf));
      }),
    );
  });
});
