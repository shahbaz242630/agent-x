import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { writeTestKeys } from './keys.ts';

describe('stand-in keys for a test run', () => {
  it('writes one version 1 key file per purpose, each 32 bytes of its own value', () => {
    const keys = writeTestKeys(['audit-mac', 'request-hash']);
    try {
      expect(readdirSync(keys.directory).sort()).toEqual(['key-audit-mac-v1', 'key-request-hash-v1']);
      const read = (name: string) =>
        Buffer.from(readFileSync(path.join(keys.directory, name), 'utf8').trim(), 'base64url');
      expect(read('key-audit-mac-v1')).toEqual(Buffer.alloc(32, 1));
      expect(read('key-request-hash-v1')).toEqual(Buffer.alloc(32, 2));
    } finally {
      keys.remove();
    }
  });

  it('removes its folder', () => {
    const keys = writeTestKeys(['audit-mac']);
    keys.remove();

    expect(existsSync(keys.directory)).toBe(false);
  });
});
