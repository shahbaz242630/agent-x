import { describe, expect, it } from 'vitest';

import { base32Decode, hotp, totp } from './totp.ts';

/** RFC 6238 Appendix B: the SHA-1 vectors, whose input is the ASCII text "12345678901234567890". */
const RFC_VECTOR = Buffer.from('12345678901234567890', 'ascii');
const RFC_VECTOR_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('TOTP for the authenticator-app test user', () => {
  it.each([
    [59, '94287082'],
    [1_111_111_109, '07081804'],
    [1_111_111_111, '14050471'],
    [1_234_567_890, '89005924'],
    [2_000_000_000, '69279037'],
    [20_000_000_000, '65353130'],
  ])('matches RFC 6238 at %s seconds', (seconds, expected) => {
    expect(totp(RFC_VECTOR_BASE32, seconds * 1000, 30, 8)).toBe(expected);
  });

  it('gives six digits by default, zero-padded', () => {
    expect(totp(RFC_VECTOR_BASE32, 1_111_111_109 * 1000)).toBe('081804');
  });

  it('changes with the step and stays the same within it', () => {
    const at = 1_700_000_000_000;
    expect(totp(RFC_VECTOR_BASE32, at)).toBe(totp(RFC_VECTOR_BASE32, at + 29_999 - (at % 30_000)));
    expect(totp(RFC_VECTOR_BASE32, at)).not.toBe(totp(RFC_VECTOR_BASE32, at + 60_000));
  });

  it('counts like HOTP (RFC 4226 Appendix D)', () => {
    expect([0n, 1n, 2n, 9n].map((counter) => hotp(RFC_VECTOR, counter))).toEqual([
      '755224',
      '287082',
      '359152',
      '520489',
    ]);
  });

  it('decodes base32 whatever the case, spacing or padding', () => {
    expect(base32Decode('JBSWY3DPEHPK3PXP').toString('hex')).toBe('48656c6c6f21deadbeef');
    expect(base32Decode('jbsw y3dp ehpk 3pxp')).toEqual(base32Decode('JBSWY3DPEHPK3PXP'));
    expect(base32Decode('MZXW6===')).toEqual(Buffer.from('foo'));
    expect(base32Decode(RFC_VECTOR_BASE32)).toEqual(RFC_VECTOR);
  });

  it('maps every one of the 32 characters to its value (the whole alphabet, then the last one repeated)', () => {
    expect(base32Decode('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567').toString('hex')).toBe(
      '00443214c74254b635cf84653a56d7c675be77df',
    );
    expect(base32Decode('77777777').toString('hex')).toBe('ffffffffff');
  });

  it('refuses text that is not base32', () => {
    expect(() => base32Decode('not-base32!')).toThrow('not a base32 character');
  });
});
