import { gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { fileName, type FileKind, isSoundFile, namesIn, parsed, signedFile, timeOfName } from './signed-files.ts';

const keys = createKeyProvider(
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1)]]),
  })) satisfies KeyMaterial,
);
const KIND: FileKind = { label: 'test-file', purpose: 'audit-anchor' };
const OTHER_KIND: FileKind = { label: 'other-file', purpose: 'audit-anchor' };
const anyLine = (fields: unknown): boolean => typeof fields === 'object' && fields !== null;

describe('signed files', () => {
  it('a file is sound for its own name, kind and epoch alone (a control, then each changed)', async () => {
    const name = fileName('e1/test/', 1_700_000_000_000);
    expect(timeOfName(name.slice('e1/test/'.length, 'e1/test/'.length + 13))).toBe(1_700_000_000_000);
    const bytes = await signedFile(keys, KIND, name, 1, ['{"a":1}', '{"b":2}']);
    expect(await isSoundFile(keys, KIND, bytes, name, 1, anyLine)).toBe(true);
    expect(await isSoundFile(keys, OTHER_KIND, bytes, name, 1, anyLine)).toBe(false);
    expect(await isSoundFile(keys, KIND, bytes, `${name}0`, 1, anyLine)).toBe(false);
    expect(await isSoundFile(keys, KIND, bytes, name, 2, anyLine)).toBe(false);
    expect(await isSoundFile(keys, KIND, bytes, name, 1, () => false)).toBe(false);
  });

  it('a closing line not ours, a key version not held, or bytes that are no gzip, is never sound', async () => {
    const name = 'e1/test/x';
    const closing = (fields: unknown) => gzipSync(`{"a":1}\n${JSON.stringify(fields)}`);
    expect(await isSoundFile(keys, KIND, closing('nope'), name, 1, anyLine)).toBe(false);
    expect(await isSoundFile(keys, KIND, closing({ k: 'z', kv: 99, sig: 'AA==' }), name, 1, anyLine)).toBe(false);
    expect(await isSoundFile(keys, KIND, closing({ k: 'y', kv: 1, sig: 'AA==' }), name, 1, anyLine)).toBe(false);
    expect(await isSoundFile(keys, KIND, Buffer.from('plain'), name, 1, anyLine)).toBe(false);
    expect(await isSoundFile(keys, KIND, gzipSync(''), name, 1, anyLine)).toBe(false);
    expect(parsed('{not json')).toBeUndefined();
  });

  it('TR-7 D1: a window lists every name from `since` to the clock, newest first, once each; none dated far ahead', async () => {
    const { store, files, calls } = createFakeWriteOnceStore();
    const now = Date.UTC(2026, 10, 20, 9, 0, 0, 0);
    const day = 24 * 60 * 60_000;
    // Names a few seconds to twelve days back, a handful just ahead, and a flood dated in 2200 never listed.
    const times = Array.from({ length: 400 }, (_, index) => now - Math.floor((index * index * 6_481) % (12 * day)));
    const ahead = [now + 2 * 60_000, now + 20 * 60_000, now + 50 * 60_000];
    for (const at of [...times, ...ahead]) files.set(fileName('e1/x/', at), Buffer.alloc(0));
    for (let index = 0; index < 2000; index += 1)
      files.set(fileName('e1/x/', Date.UTC(2200, 0, 1) + index), Buffer.alloc(0));
    const listed = async (since: number | undefined, slackMs: number) => {
      const future: number[] = [];
      const names: number[] = [];
      const before = calls.lists;
      for await (const { at } of namesIn(
        store,
        'e1/x/',
        () => now + 5 * 60_000,
        (at) => future.push(at),
        5000,
        {
          since,
          slackMs,
        },
      )) {
        if (since !== undefined && at < since) break;
        names.push(at);
      }
      return { names, future, lists: calls.lists - before };
    };
    for (const [since, slackMs] of [
      [now - 10 * 60_000, 60 * 60_000],
      [now - day, day],
      [now - 3 * day, 3 * day],
      [undefined, 60 * 60_000],
    ] as const) {
      const { names, future, lists } = await listed(since, slackMs);
      const expected = [...times, ahead[0] ?? 0]
        .filter((at) => since === undefined || at >= since)
        .toSorted((one, other) => other - one);
      expect(names).toEqual(expected);
      // Each ahead past the spread said at most once, and never the flood in 2200.
      expect(future.every((at) => at === ahead[1] || at === ahead[2])).toBe(true);
      expect(new Set(future).size).toBe(future.length);
      expect(lists).toBeLessThanOrEqual(since === undefined ? 60 : 4);
    }
  });
});
