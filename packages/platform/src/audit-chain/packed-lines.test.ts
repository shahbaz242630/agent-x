// The packed table (PL-65) against a Map of the same lines, step by random step: what it holds, in what order, each
// line's stamp and mark, and what a file taken from it holds however the table moves on after.
import { describe, expect, it } from 'vitest';

import type { Anchor, Progress } from './anchor.ts';
import { packedLines, type Taken } from './packed-lines.ts';
import { shardOf } from './shards.ts';

const AT = new Date('2026-11-02T09:00:00.000Z');

/** A value the test knows is there, or the test fails saying so. */
function defined<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('the test expected a value here');
  return value;
}

/** A small, seeded random source, so a failing seed can be run again. */
function randomFrom(seed: number) {
  let state = seed >>> 0;
  return (count: number): number => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return Math.floor((state / 4_294_967_296) * count);
  };
}

const chainOf = (index: number): string => `organisation:0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`;

/** A line, now and then one no record fits, so it is kept whole. */
function lineOf(random: (count: number) => number, chain: string, places: boolean): Anchor | Progress {
  const odd = random(8);
  const line = {
    chain,
    seq: odd === 0 ? 2n ** 64n + BigInt(random(9)) : BigInt(random(1000)),
    hash: Buffer.alloc(odd === 1 ? 31 : 32, random(256)),
    macKeyVersion: random(4),
    at: new Date(AT.getTime() + random(1e9)),
    keyVersion: odd === 2 ? 2 ** 40 + random(9) : random(4),
    signature: Buffer.alloc(odd === 3 ? 65 : 64, random(256)),
  };
  return Object.freeze(places ? { ...line, began: new Date(AT.getTime() - random(1e9)) } : line);
}

interface Model {
  readonly lines: Map<string, { line: Anchor; stamp: number; marked: boolean }>;
}

/** How many of the model's lines a record holds: those with none of `lineOf`'s odd fields. */
const fitting = (model: Model): number =>
  [...model.lines.values()].filter(
    ({ line }) => line.seq < 2n ** 64n && line.hash.length === 32 && line.signature.length === 64,
  ).length;

const takenOf = (taken: Taken<Anchor>) => ({
  lines: [...taken.lines()],
  stamps: [...taken.stamps()],
  size: taken.size,
});

describe.each([false, true])('a packed table, places %s', (places) => {
  it.each(Array.from({ length: 40 }, (_, index) => index + 1))(
    'seed %i: holds what a Map would, step by step',
    (seed) => {
      const random = randomFrom(seed);
      const table = packedLines<Anchor>(places);
      const model: Model = { lines: new Map() };
      const open: { taken: Taken<Anchor>; was: ReturnType<typeof takenOf> }[] = [];
      let stamp = 0;
      for (let step = 0; step < 400; step += 1) {
        const chain = chainOf(random(30));
        const pick = random(10);
        if (pick < 5) {
          const line = lineOf(random, chain, places);
          const marked = random(4) === 0;
          stamp += 1;
          table.set(line, stamp, marked);
          model.lines.set(chain, { line, stamp, marked });
        } else if (pick < 7) {
          table.delete(chain);
          model.lines.delete(chain);
        } else if (pick === 7) {
          const keep = (name: string) => name.endsWith(String(random(3)));
          const taken = table.take(keep);
          open.push({ taken, was: takenOf(taken) });
        } else if (pick === 8 && open.length > 0) {
          const first = defined(open.splice(random(open.length), 1)[0]);
          // What was taken reads the same however the table moved since, until let go; let go twice is once.
          expect(takenOf(first.taken)).toEqual(first.was);
          first.taken.release();
          first.taken.release();
        }
        expect(table.size).toBe(model.lines.size);
        expect([...table.keys()]).toEqual([...model.lines.keys()]);
        expect(table.get(chain)).toEqual(model.lines.get(chain)?.line);
        expect(table.has(chain)).toBe(model.lines.has(chain));
        expect(table.stampOf(chain)).toBe(model.lines.get(chain)?.stamp);
        expect(table.marked(chain)).toBe(model.lines.get(chain)?.marked ?? false);
        // With nothing taken, a record a line that fits and none more; with something taken, the ones it reads besides.
        if (open.length === 0) expect(table.records).toBe(fitting(model));
        else expect(table.records).toBeGreaterThanOrEqual(fitting(model));
      }
      expect([...table.held()]).toEqual(
        [...model.lines.values()].map(({ line, stamp: kept }) => ({ line, stamp: kept })),
      );
      for (const { taken, was } of open) expect(takenOf(taken)).toEqual(was);
      for (const { taken } of open) taken.release();
      expect(table.records).toBe(fitting(model));
    },
  );
});

describe('a line read back', () => {
  it('is a frozen copy: changing what was given, or what came back, changes nothing held', () => {
    const table = packedLines<Anchor>(false);
    const hash = Buffer.alloc(32, 7);
    const signature = Buffer.alloc(64, 9);
    table.set({ chain: chainOf(1), seq: 5n, hash, macKeyVersion: 1, at: AT, keyVersion: 1, signature }, 1);
    hash.fill(0);
    const first = defined(table.get(chainOf(1)));
    expect(Object.isFrozen(first)).toBe(true);
    expect(first.hash).toEqual(Buffer.alloc(32, 7));
    first.signature.fill(0);
    expect(table.get(chainOf(1))?.signature).toEqual(Buffer.alloc(64, 9));
    expect(table.get(chainOf(1))).not.toBe(first);
  });

  it('keeps the largest place a record holds, and a field more is kept whole', () => {
    const table = packedLines<Anchor>(false);
    const most = 2n ** 64n - 1n;
    const line = {
      chain: chainOf(2),
      seq: most,
      hash: Buffer.alloc(32),
      macKeyVersion: 0,
      at: AT,
      keyVersion: 0,
      signature: Buffer.alloc(64),
    };
    table.set(line, 1);
    expect(table.get(chainOf(2))?.seq).toBe(most);
    const more = { ...line, began: AT };
    table.set(more, 2);
    expect(table.get(chainOf(2))).toBe(more);
  });

  it('a place reached without when its pass began is kept whole, and given back as it came', () => {
    const table = packedLines<Progress>(true);
    const place = {
      chain: chainOf(3),
      seq: 1n,
      hash: Buffer.alloc(32),
      macKeyVersion: 0,
      at: AT,
      keyVersion: 0,
      signature: Buffer.alloc(64),
      began: 'then',
    };
    table.set(place as unknown as Progress, 1);
    expect(table.get(chainOf(3))).toBe(place);
  });

  it('reuses what a line deleted was in once nothing taken may read it, and not before', () => {
    const table = packedLines<Anchor>(false);
    const at = (seq: bigint, index: number): Anchor => ({
      chain: chainOf(index),
      seq,
      hash: Buffer.alloc(32),
      macKeyVersion: 0,
      at: AT,
      keyVersion: 0,
      signature: Buffer.alloc(64),
    });
    table.set(at(1n, 1), 1);
    const taken = table.take(() => true);
    table.delete(chainOf(1));
    table.set(at(2n, 2), 2);
    expect([...taken.lines()].map(({ line }) => line.seq)).toEqual([1n]);
    taken.release();
    table.delete(chainOf(2));
    table.set(at(3n, 3), 3);
    expect([...table.held()].map(({ line }) => line.seq)).toEqual([3n]);
  });
});

describe('the records a table holds (PL-65 review)', () => {
  const line = (index: number, seq = 1n): Anchor => ({
    chain: chainOf(index),
    seq,
    hash: Buffer.alloc(32, index % 256),
    macKeyVersion: 1,
    at: new Date(AT.getTime() + index),
    keyVersion: 1,
    signature: Buffer.alloc(64, 1),
  });

  it('one chain set ten times while a file holds it, then let go and set again: one record', () => {
    const table = packedLines<Anchor>(false);
    const taken = table.take(() => true);
    for (let time = 1; time <= 10; time += 1) table.set(line(1, BigInt(time)), time);
    expect(table.records).toBe(10);
    taken.release();
    expect(table.records).toBe(1);
    table.set(line(1, 11n), 11);
    expect(table.records).toBe(1);
    expect(table.get(chainOf(1))?.seq).toBe(11n);
  });

  it('a chain deleted, another set, nothing taken: its record reused', () => {
    const table = packedLines<Anchor>(false);
    table.set(line(1), 1);
    table.delete(chainOf(1));
    table.set(line(2), 2);
    expect(table.records).toBe(1);
  });

  it('a line that fits, the same chain`s next that doesn`t, then another chain`s that fits: one record', () => {
    const table = packedLines<Anchor>(false);
    table.set(line(1), 1);
    table.set({ ...line(1), hash: Buffer.alloc(31) }, 2);
    expect(table.records).toBe(0);
    table.set(line(2), 3);
    expect(table.records).toBe(1);
    expect(table.get(chainOf(1))?.hash).toHaveLength(31);
  });

  it.each([false, true])('past one buffer of records (places %s): every line reads back as it went in', (places) => {
    const table = packedLines<Anchor | Progress>(places);
    const count = 2100;
    for (let index = 0; index < count; index += 1) {
      const each = line(index, BigInt(index * 3 + 1));
      table.set(places ? { ...each, began: new Date(AT.getTime() - index) } : each, index + 1);
    }
    expect(table.records).toBe(count);
    for (let index = 0; index < count; index += 1) {
      const back = defined(table.get(chainOf(index)));
      expect(back.seq).toBe(BigInt(index * 3 + 1));
      expect(back.hash).toEqual(Buffer.alloc(32, index % 256));
      expect(back.at).toEqual(new Date(AT.getTime() + index));
      expect(table.stampOf(chainOf(index))).toBe(index + 1);
      if (places) expect((back as Progress).began).toEqual(new Date(AT.getTime() - index));
    }
  });
});

describe('each line keeps its chain’s shard (PL-65 PR2)', () => {
  const anchorOf = (chain: string, seq: bigint, hashBytes = 32): Anchor => ({
    chain,
    seq,
    hash: Buffer.alloc(hashBytes, 1),
    macKeyVersion: 1,
    at: AT,
    keyVersion: 1,
    signature: Buffer.alloc(64, 2),
  });

  it('in a record and in a line kept whole alike, through a line set again, for a file taken a shard at a time', () => {
    const table = packedLines<Anchor>(false);
    const [fits, whole] = [chainOf(1), chainOf(2)];
    table.set(anchorOf(fits, 1n), 1);
    table.set(anchorOf(whole, 1n, 31), 2);
    table.set(anchorOf(fits, 2n), 3);
    table.set(anchorOf(whole, 2n), 4);
    expect(table.shardOf(fits)).toBe(shardOf(fits));
    expect(table.shardOf(whole)).toBe(shardOf(whole));
    expect(table.shardOf(chainOf(3))).toBeUndefined();

    const shards: number[] = [];
    const taken = table.take((_chain, _line, shard) => {
      shards.push(shard);
      return shard === shardOf(whole);
    });
    expect(shards).toEqual([shardOf(fits), shardOf(whole)]);
    expect([...taken.stamps()]).toEqual([[whole, 4]]);
    taken.release();
  });
});
