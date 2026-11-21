import { describe, expect, it } from 'vitest';

import {
  ChainDigest,
  ENTRY_BYTES,
  fingerprintOf,
  halvesOf,
  packEntries,
  placeOf,
  subjectKey,
  unpackEntries,
  valueAt,
} from './state-digest.ts';

describe('SEC-DB-10, SEC-DB-11 the digest’s table of one chain (AT13)', () => {
  it('keeps each object’s highest place, says whether it moved, and grows past three slots in four', () => {
    const table = new ChainDigest(1000, 4);
    expect(table.put(1, 2, 5)).toBe(true);
    expect(table.put(1, 2, 5)).toBe(false);
    expect(table.put(1, 2, 3)).toBe(false);
    expect(table.put(1, 2, 9)).toBe(true);
    expect(table.get(1, 2)).toBe(9);
    expect(table.get(1, 3)).toBeUndefined();
    const small = new ChainDigest(0, 4);
    for (let high = 1; high <= 4; high += 1) small.put(high, high, 1);
    // A fourth object in four slots: grown first, at most three in four used.
    expect(small.bytes).toBe(8 * 4 * 2 + 8 * 8);
    const before = table.bytes;
    // Objects whose low halves all land on the same slot, each found past the others.
    for (let high = 2; high < 40; high += 1) table.put(high, 2, high);
    expect(table.bytes).toBeGreaterThan(before);
    expect(table.size).toBe(39);
    for (let high = 2; high < 40; high += 1) expect(table.get(high, 2)).toBe(high);
    expect([...table.entries()]).toHaveLength(39);
    expect(table.bornAt).toBe(1000);
  });

  it('names an object by its type and its ID in lower case, and never by the empty slot’s 0 and 0', () => {
    expect(subjectKey('agent', 'ABC')).toBe('agent\nabc');
    expect(fingerprintOf(subjectKey('agent', 'ABC'))).toEqual(fingerprintOf(subjectKey('agent', 'abc')));
    expect(fingerprintOf('agent\na')).not.toEqual(fingerprintOf('agent_key\na'));
    expect(halvesOf(Buffer.alloc(32))).toEqual([0, 1]);
    expect(halvesOf(Buffer.from([0, 0, 0, 1, 0, 0, 0, 2]))).toEqual([1, 2]);
    expect(valueAt(new Float64Array(2), 5)).toBe(0);
  });

  it('takes a place from 1 to the largest safe count, and refuses any other', () => {
    expect(placeOf(1n)).toBe(1);
    expect(placeOf(BigInt(Number.MAX_SAFE_INTEGER))).toBe(Number.MAX_SAFE_INTEGER);
    expect(() => placeOf(0n)).toThrow(RangeError);
    expect(() => placeOf(BigInt(Number.MAX_SAFE_INTEGER) + 1n)).toThrow(RangeError);
  });

  it('packs entries 16 bytes each and reads them back; anything else is no line of ours', () => {
    const entries = [
      [1, 2, 3],
      [0xffff_ffff, 0, Number.MAX_SAFE_INTEGER],
    ] as const;
    const packed = packEntries(entries, 2);
    expect(packed).toHaveLength(2 * ENTRY_BYTES);
    expect(unpackEntries(packed)).toEqual(entries);
    expect(() => packEntries(entries, 3)).toThrow(RangeError);
    expect(unpackEntries(Buffer.alloc(0))).toBeUndefined();
    expect(unpackEntries(Buffer.alloc(ENTRY_BYTES + 1))).toBeUndefined();
    // The empty slot's fingerprint, a place of 0, and one past a safe count.
    expect(unpackEntries(packEntries([[0, 0, 3]], 1))).toBeUndefined();
    const zero = packEntries([[1, 2, 3]], 1);
    zero.writeBigUInt64BE(0n, 8);
    expect(unpackEntries(zero)).toBeUndefined();
    const huge = packEntries([[1, 2, 3]], 1);
    huge.writeBigUInt64BE(BigInt(Number.MAX_SAFE_INTEGER) + 1n, 8);
    expect(unpackEntries(huge)).toBeUndefined();
  });
});
