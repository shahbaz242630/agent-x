// The packed table (PL-65) against a Map of the same lines, step by random step: what it holds, in what order, each
// line's stamp and mark, and what a file taken from it holds however the table moves on after.
import { describe, expect, it } from 'vitest';

import type { Anchor, Progress } from './anchor.ts';
import { packedLines, type Taken } from './packed-lines.ts';

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
      }
      expect([...table.held()]).toEqual(
        [...model.lines.values()].map(({ line, stamp: kept }) => ({ line, stamp: kept })),
      );
      for (const { taken, was } of open) expect(takenOf(taken)).toEqual(was);
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
