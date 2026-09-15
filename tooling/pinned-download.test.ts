import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { sha256Of, sha256OfFile } from './pinned-download.ts';

const dir = mkdtempSync(path.join(tmpdir(), 'agentx-pinned-'));
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("hashing an installed tool's file", () => {
  it('reads it in pieces and gets the same SHA-256 as hashing it whole, across piece boundaries', () => {
    for (const size of [0, 1, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1, 3 * 1024 * 1024 + 7]) {
      const bytes = Uint8Array.from({ length: size }, (_, index) => (index * 31 + 7) % 256);
      const file = path.join(dir, `file-${String(size)}`);
      writeFileSync(file, bytes);
      expect(sha256OfFile(file)).toBe(sha256Of(bytes));
    }
  });

  it('reports a missing file as missing, and any other failure as an error', () => {
    expect(sha256OfFile(path.join(dir, 'absent'))).toBeUndefined();
    expect(() => sha256OfFile(dir)).toThrow();
  });
});
