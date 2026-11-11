import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  bodyHash,
  closingV2Message,
  SHARD_FILE,
  shardFolder,
  shardHex,
  shardOf,
  SHARDS,
  shardsFolder,
} from './shards.ts';

describe('SEC-ANC-04 the anchors’ shards (PL-65 PR2)', () => {
  // Golden: the database's generated column (PR4) must give these same shards, `get_byte(sha256(name), 0)`.
  it.each([
    ['platform', 210],
    ['organisation:0199a0f0-0000-7000-8000-000000000001', 150],
    ['organisation:0199a0f0-0000-7000-8000-000000000002', 213],
    ['organisation:00000000-0000-7000-8000-000000000000', 16],
    ['organisation:ffffffff-ffff-7fff-bfff-ffffffffffff', 226],
  ])('%s is in shard %i: the first byte of the SHA-256 of its name', (chain, shard) => {
    expect(shardOf(chain)).toBe(shard);
  });

  it('spreads organisations made one after another across the shards, as UUIDv7 prefixes would not', () => {
    const shards = new Set(
      Array.from({ length: 64 }, (_, index) =>
        shardOf(`organisation:0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`),
      ),
    );
    expect(shards.size).toBeGreaterThan(40);
    expect(SHARDS).toBe(256);
  });

  it('names each shard’s folder by two hex digits, in its epoch', () => {
    expect(shardHex(0)).toBe('00');
    expect(shardHex(10)).toBe('0a');
    expect(shardHex(255)).toBe('ff');
    expect(shardsFolder(3)).toBe('e3/shards/');
    expect(shardFolder(1, 171)).toBe('e1/shards/ab/');
  });

  it.each([
    ['9998233417199999-00000000-0000-4000-8000-000000000001-s', false],
    ['8233417199999-00000000-0000-4000-8000-000000000001-s', true],
    ['8233417199999-00000000-0000-4000-8000-000000000001-d', true],
    ['8233417199999-00000000-0000-4000-8000-000000000001-x', false],
    ['8233417199999-00000000-0000-4000-8000-000000000001', false],
    ['8233417199999-00000000-0000-4000-8000-00000000000G-d', false],
  ])('%s is a shard file’s name: %s', (name, is) => {
    expect(SHARD_FILE.test(name)).toBe(is);
  });

  it('signs a version 2 closing line under its own label, apart from version 1’s', () => {
    expect(closingV2Message('e1/shards/00/x', 1, 2, 'ab')).toEqual([
      'audit-anchor-file-v2',
      'e1/shards/00/x',
      '1',
      '2',
      'ab',
    ]);
  });

  it('hashes the bytes before a closing line: each line and its end, counted', () => {
    const body = bodyHash();
    body.add('{"k":"a"}');
    body.add('é');
    expect(body.lines).toBe(2);
    expect(body.digest()).toBe(createHash('sha256').update('{"k":"a"}\né\n', 'utf8').digest('hex'));
  });
});
