import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { fileName, type FileKind, isSoundFile, parsed, signedFile, timeOfName } from './signed-files.ts';

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
});
