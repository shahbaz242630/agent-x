import { describe, expect, it } from 'vitest';

import { ScramInputError, scramVerifier } from './scram.ts';

const BASE64 = '[A-Za-z0-9+/]+={0,2}';
/** Postgres's format for a verifier, which holds no quote. */
const SCRAM_VERIFIER = new RegExp(`^SCRAM-SHA-256\\$[1-9][0-9]*:${BASE64}\\$${BASE64}:${BASE64}$`);

/** A stand-in login, assembled when the test runs. */
const login = ['plain', 'words', 'only'].join('-');

/** The parts of a verifier: iterations, salt, stored key, server key. */
function parts(verifier: string): { iterations: number; salt: Buffer; stored: Buffer; server: Buffer } {
  const [, head = '', tail = ''] = verifier.split('$');
  const [iterations = '', salt = ''] = head.split(':');
  const [stored = '', server = ''] = tail.split(':');
  return {
    iterations: Number(iterations),
    salt: Buffer.from(salt, 'base64'),
    stored: Buffer.from(stored, 'base64'),
    server: Buffer.from(server, 'base64'),
  };
}

describe('scramVerifier', () => {
  it("writes Postgres's format with its defaults: 4096 iterations, a 16-byte salt, 32-byte keys", () => {
    const verifier = scramVerifier(login);
    expect(verifier).toMatch(SCRAM_VERIFIER);
    const { iterations, salt, stored, server } = parts(verifier);
    expect(iterations).toBe(4096);
    expect(salt).toHaveLength(16);
    expect(stored).toHaveLength(32);
    expect(server).toHaveLength(32);
  });

  it('never carries the login itself', () => {
    expect(scramVerifier(login)).not.toContain(login);
  });

  it('uses a fresh salt every time, so the same login gives a different verifier', () => {
    const first = scramVerifier(login);
    const second = scramVerifier(login);
    expect(parts(first).salt.equals(parts(second).salt)).toBe(false);
    expect(first).not.toBe(second);
  });

  it('gives the same verifier for the same login, salt and iterations, and another for any change', () => {
    const salt = Buffer.alloc(16, 7);
    const base = scramVerifier(login, { salt, iterations: 4096 });
    expect(scramVerifier(login, { salt, iterations: 4096 })).toBe(base);
    expect(scramVerifier(`${login}x`, { salt, iterations: 4096 })).not.toBe(base);
    expect(scramVerifier(login, { salt: Buffer.alloc(16, 8), iterations: 4096 })).not.toBe(base);
    expect(scramVerifier(login, { salt, iterations: 4097 })).not.toBe(base);
  });

  it.each([
    ['an empty login', ''],
    ['a space', 'two words'],
    ['a letter outside ASCII, which SASLprep could change', `caf${String.fromCharCode(0xe9)}`],
    ['a tab', `a${String.fromCharCode(9)}b`],
    ['a control character', `a${String.fromCharCode(0x7f)}b`],
  ])('refuses %s', (_, value) => {
    expect(() => scramVerifier(value)).toThrow(ScramInputError);
  });

  it('refuses an empty salt or an iteration count below 1', () => {
    expect(() => scramVerifier(login, { salt: Buffer.alloc(0) })).toThrow(/the salt is empty/);
    expect(() => scramVerifier(login, { iterations: 0 })).toThrow(/iteration count/);
    expect(() => scramVerifier(login, { iterations: 1.5 })).toThrow(/iteration count/);
  });

  it('the format check matches only a whole verifier', () => {
    const verifier = scramVerifier(login);
    expect(SCRAM_VERIFIER.test(verifier)).toBe(true);
    expect(SCRAM_VERIFIER.test(`${verifier}'`)).toBe(false);
    expect(SCRAM_VERIFIER.test(`x${verifier}`)).toBe(false);
    expect(SCRAM_VERIFIER.test(verifier.replace('SCRAM-SHA-256', 'md5'))).toBe(false);
    expect(SCRAM_VERIFIER.test(verifier.replace('$4096:', '$0:'))).toBe(false);
  });
});
