import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { ConfigError } from '../config/common.ts';
import { loadKeys } from './load.ts';
import { type KeyPurpose, PURPOSES } from './purposes.ts';

/** A key file's contents: 32 bytes of one value, as base64url, so each key in a test is told apart by its fill. */
const encoded = (fill: number): string => Buffer.alloc(32, fill).toString('base64url');

/** The same key with one of the last character's 2 spare bits set: it decodes to the same bytes, but isn't how they're written. */
function withSpareBitSet(text: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return text.slice(0, -1) + (alphabet[alphabet.indexOf(text.slice(-1)) ^ 1] ?? '');
}

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

/** A keys directory holding the given files; by default one version 1 key for every purpose. */
function keysDirectory(files: Readonly<Record<string, string>> = everyPurpose()): string {
  const directory = mkdtempSync(join(tmpdir(), 'agentx-keys-'));
  directories.push(directory);
  for (const [name, contents] of Object.entries(files)) writeFileSync(join(directory, name), contents);
  return directory;
}

function everyPurpose(): Record<string, string> {
  return Object.fromEntries(PURPOSES.map((purpose, index) => [`key-${purpose}-v1`, `${encoded(index + 1)}\n`]));
}

/** The problems a start is refused with. */
function problemsOf(directory: string, current: Partial<Record<KeyPurpose, number>> = {}): readonly string[] {
  try {
    loadKeys({ directory, current });
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
  throw new Error('the keys were accepted');
}

describe('reading the keys from the files the platform mounts', () => {
  it('reads one key file per purpose and version, and makes version 1 current', () => {
    const keys = loadKeys({ directory: keysDirectory(), current: {} });

    expect(keys.describe().map(({ purpose, current, versions }) => [purpose, current, versions.length])).toEqual(
      PURPOSES.map((purpose) => [purpose, 1, 1]),
    );
    expect(keys.mac('audit-mac', ['x']).keyVersion).toBe(1);
  });

  it('keeps every version it finds, and makes current the one it is told', () => {
    const directory = keysDirectory({
      ...everyPurpose(),
      'key-audit-mac-v2': encoded(40),
      'key-audit-mac-v3': encoded(41),
    });
    const keys = loadKeys({ directory, current: { 'audit-mac': 2 } });

    expect(keys.describe().find((entry) => entry.purpose === 'audit-mac')).toMatchObject({
      current: 2,
      versions: [{ version: 1 }, { version: 2 }, { version: 3 }],
    });
    expect(keys.mac('audit-mac', ['x']).keyVersion).toBe(2);
  });

  it('holds the same key as the file, whatever line ending the file has', () => {
    const withLineFeed = loadKeys({ directory: keysDirectory(), current: {} });
    const files = Object.fromEntries(
      Object.entries(everyPurpose()).map(([name, text]) => [name, text.replace(/\n$/, '\r\n')]),
    );
    const withCarriageReturn = loadKeys({ directory: keysDirectory(files), current: {} });
    const bare = loadKeys({
      directory: keysDirectory(Object.fromEntries(Object.entries(files).map(([name, text]) => [name, text.trim()]))),
      current: {},
    });

    expect(withCarriageReturn.describe()).toEqual(withLineFeed.describe());
    expect(bare.describe()).toEqual(withLineFeed.describe());
  });

  it('leaves alone the other files mounted with the keys', () => {
    const directory = keysDirectory({ ...everyPurpose(), 'db-app-password': 'not a key', '..data': '' });
    mkdirSync(join(directory, '..2026_09_18'));

    expect(() => loadKeys({ directory, current: {} })).not.toThrow();
  });

  it("refuses a directory that can't be read, without naming its path", () => {
    const missing = join(keysDirectory(), 'nowhere');

    expect(problemsOf(missing)).toEqual(["the keys directory can't be read"]);
  });

  it('refuses an empty directory, naming every missing key', () => {
    expect(problemsOf(keysDirectory({}))).toEqual(
      PURPOSES.map((purpose) => `${purpose} has no key for its current version 1 (key-${purpose}-v1)`),
    );
  });

  it.each([
    ['a purpose the app has no key for', 'key-api-token-v1'],
    ['a misspelt purpose', 'key-audit-macs-v1'],
    // Version 2, which isn't there, so a file system that ignores case can't take it for version 1.
    ['capitals', 'KEY-audit-mac-v2'],
    ['no version', 'key-audit-mac'],
    ['version 0', 'key-audit-mac-v0'],
    ['a version with a leading zero', 'key-audit-mac-v01'],
    ['an ending', 'key-audit-mac-v1.txt'],
  ])('refuses a key file named with %s, rather than ignore it', (_what, name) => {
    expect(problemsOf(keysDirectory({ ...everyPurpose(), [name]: encoded(50) }))).toEqual([
      `${name} is not a key the app knows: key files are named key-<purpose>-v<version>, the purpose one of ${PURPOSES.join(', ')}`,
    ]);
  });

  it.each([
    ['empty', ''],
    ['too short', encoded(50).slice(0, 42)],
    ['too long', `${encoded(50)}A`],
    ['base64 with padding', Buffer.alloc(32, 50).toString('base64')],
    ['base64 with + and /', Buffer.alloc(32, 0xfb).toString('base64').replace(/=+$/, '')],
    ['written with a spare bit set', withSpareBitSet(encoded(50))],
    ['two lines', `${encoded(50)}\n${encoded(51)}`],
    ['a line break too many', `${encoded(50)}\n\n`],
    ['spaces around it', ` ${encoded(50)} `],
    ['hex', Buffer.alloc(32, 50).toString('hex')],
  ])('refuses a key file %s, without showing what it holds', (_what, contents) => {
    const problems = problemsOf(keysDirectory({ ...everyPurpose(), 'key-audit-mac-v1': contents }));

    expect(problems).toEqual([
      'key-audit-mac-v1 must hold one key: 32 random bytes written as base64url, 43 characters',
      'audit-mac has no key for its current version 1 (key-audit-mac-v1)',
    ]);
    if (contents.trim() !== '') for (const problem of problems) expect(problem).not.toContain(contents.trim());
  });

  it("refuses a key file that can't be read", () => {
    const directory = keysDirectory(everyPurpose());
    mkdirSync(join(directory, 'key-audit-mac-v2'));

    expect(problemsOf(directory)).toEqual(["key-audit-mac-v2 can't be read"]);
  });

  it('refuses a current version with no file', () => {
    expect(problemsOf(keysDirectory(), { 'request-hash': 2 })).toEqual([
      'request-hash has no key for its current version 2 (key-request-hash-v2)',
    ]);
  });

  it('refuses a second version of the payee index key, which is never rotated in place (ADR-014 §3)', () => {
    const problem =
      'payee-index is never rotated in place (ADR-014 §3): only its version 1 may exist, and it stays current';

    expect(problemsOf(keysDirectory({ ...everyPurpose(), 'key-payee-index-v2': encoded(60) }))).toEqual([problem]);
    expect(
      problemsOf(keysDirectory({ ...everyPurpose(), 'key-payee-index-v2': encoded(60) }), { 'payee-index': 2 }),
    ).toEqual([problem]);
  });

  it('refuses one key copied into two files', () => {
    const files = everyPurpose();

    expect(problemsOf(keysDirectory({ ...files, 'key-request-hash-v1': files['key-audit-mac-v1'] ?? '' }))).toEqual([
      'key-audit-mac-v1 holds the same key as key-request-hash-v1: every key must be its own',
    ]);
  });

  it('lists every problem at once', () => {
    const directory = keysDirectory({ ...everyPurpose(), 'key-audit-mac-v1': 'short', 'key-unknown-v1': encoded(70) });

    expect(problemsOf(directory, { 'field-encryption': 2 })).toEqual([
      'key-audit-mac-v1 must hold one key: 32 random bytes written as base64url, 43 characters',
      `key-unknown-v1 is not a key the app knows: key files are named key-<purpose>-v<version>, the purpose one of ${PURPOSES.join(', ')}`,
      'audit-mac has no key for its current version 1 (key-audit-mac-v1)',
      'field-encryption has no key for its current version 2 (key-field-encryption-v2)',
    ]);
  });
});
