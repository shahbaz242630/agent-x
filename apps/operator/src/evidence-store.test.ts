// Phase 3 E10c: the local folder standing in for the write-once container:
// each file made once, a second write of its name answered, never written
// over, and any other failure of the disk passed on.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

import { folderStore } from './evidence-store.ts';

/** A failure no real write causes here (a full disk), switched on by a test and off after it. */
const faults = vi.hoisted(() => ({ write: undefined as Error | undefined }));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    writeFile: (...args: Parameters<typeof actual.writeFile>) =>
      faults.write === undefined ? actual.writeFile(...args) : Promise.reject(faults.write),
  };
});

afterEach(() => {
  faults.write = undefined;
});

const folder = mkdtempSync(path.join(tmpdir(), 'agentx-evidence-store-'));
afterAll(() => {
  rmSync(folder, { recursive: true, force: true });
});

describe('E10c the local evidence store', () => {
  it('writes a file once, in its organisation’s folder, and never over it', async () => {
    const store = folderStore(folder);

    const first = await store.put('org-1/export-1.ndjson', Buffer.from('first\n'));
    const second = await store.put('org-1/export-1.ndjson', Buffer.from('second\n'));

    expect([first, second]).toEqual(['written', 'there_already']);
    expect(readFileSync(path.join(folder, 'org-1', 'export-1.ndjson'), 'utf8')).toBe('first\n');
  });

  it('passes on any other failure of the disk', async () => {
    faults.write = Object.assign(new Error('no space left on device'), { code: 'ENOSPC' });

    await expect(folderStore(folder).put('org-1/export-2.ndjson', Buffer.from('x'))).rejects.toThrow(
      'no space left on device',
    );
  });
});
