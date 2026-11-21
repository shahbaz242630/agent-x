import { describe, expect, it } from 'vitest';

import type { StoredEntry } from './chain.ts';
import type { ChainReader } from './store.ts';
import { heldToWitnessed, watchingPlaces } from './witness-path.ts';

const hash = (fill: number): Buffer => Buffer.alloc(32, fill);
const head = (seq: bigint, fill: number) => ({ seq, hash: hash(fill) });
const reached = (seq: bigint, fill: number, to = seq) =>
  ({ ok: true, seq, hash: hash(fill), macKeyVersion: 1, to }) as const;

describe('SEC-DB-20 TR-1 a walk held to the witnessed heads', () => {
  it('keeps the hash its own reads found at each witnessed place, no read of its own', async () => {
    const found = new Map<bigint, Buffer>();
    const entries = [4n, 5n, 6n].map((seq) => ({ seq, hash: hash(Number(seq)) }) as unknown as StoredEntry);
    const source: Pick<ChainReader, 'events'> = { events: () => Promise.resolve([...entries, undefined]) };
    const reader = watchingPlaces(source, [head(5n, 0)], found);
    await reader.events(3n, 6n, 10);
    expect([...found]).toEqual([[5n, hash(5)]]);
    // No heads, the reader as it was.
    const plain = { events: () => Promise.resolve([]) };
    expect(watchingPlaces(plain, [], found)).toBe(plain);
  });

  it('a walk through every head passes (control); a fork at one, or a head above where it reached, is cut_back', () => {
    const found = new Map([[5n, hash(5)]]);
    const walk = reached(8n, 8);
    expect(heldToWitnessed(walk, [head(5n, 5), head(8n, 8)], found, 2n)).toBe(walk);
    // Row mixing: the original row put back at 5 beside a cut branch reads true alone, but the walk's own hash differs.
    expect(heldToWitnessed(walk, [head(5n, 9)], found, 2n)).toEqual({
      ok: false,
      problem: { reason: 'cut_back', seq: 5n },
    });
    // A head witnessed above the head the walk read: cut back below it; the highest named.
    expect(heldToWitnessed(walk, [head(9n, 9), head(12n, 1)], found, 2n)).toEqual({
      ok: false,
      problem: { reason: 'cut_back', seq: 12n },
    });
    // At the head's own place, the head's own hash.
    expect(heldToWitnessed(walk, [head(8n, 1)], found, 2n)).toMatchObject({ ok: false });
    // A place it read with no hash kept: missed.
    expect(heldToWitnessed(walk, [head(6n, 6)], found, 2n)).toMatchObject({ ok: false });
  });

  it('leaves to the next walk a head at or below where it began, or past where a capped step stopped short of its goal', () => {
    const found = new Map<bigint, Buffer>();
    const capped = reached(8n, 8, 20n);
    expect(heldToWitnessed(capped, [head(2n, 1), head(15n, 1)], found, 2n)).toBe(capped);
    expect(heldToWitnessed(capped, [head(21n, 1)], found, 2n)).toMatchObject({ ok: false });
    // A walk that failed already, or no heads, as it was.
    const failed = { ok: false, problem: { reason: 'link', seq: 4n } } as const;
    expect(heldToWitnessed(failed, [head(21n, 1)], found, 2n)).toBe(failed);
    const plain = reached(8n, 8);
    expect(heldToWitnessed(plain, [], found, 2n)).toBe(plain);
    // A whole report (no `to`): its head is its goal.
    const whole = { ok: true, seq: 8n, hash: hash(8), macKeyVersion: 1 } as const;
    expect(heldToWitnessed(whole, [head(9n, 1)], found, 0n)).toMatchObject({ ok: false });
  });
});
