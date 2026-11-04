import { FixedClock } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { eachDay, owedPasses, rotation, slotOf, slotsBetween } from './org-passes.ts';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const SLOT_MS = 30 * MINUTE;
const SLOTS = 12;
/** Midnight UTC, a cycle's first slot. */
const MIDNIGHT = new Date('2026-11-04T00:00:00.000Z');

/** Enough IDs that every slot of twelve holds some. */
const ORGS = Array.from(
  { length: 120 },
  (_, at) => `0193${at.toString(16).padStart(4, '0')}-0000-7000-8000-000000000000`,
);

const listing = (orgs: readonly string[] = ORGS) => {
  let reads = 0;
  return {
    all: () => {
      reads += 1;
      return Promise.resolve(orgs);
    },
    reads: () => reads,
  };
};

describe('an organisation’s slot', () => {
  it('is the same for its ID in either case, and within the slots', () => {
    for (const orgId of ORGS) {
      expect(slotOf(orgId, SLOTS)).toBe(slotOf(orgId.toUpperCase(), SLOTS));
      expect(slotOf(orgId, SLOTS)).toBeGreaterThanOrEqual(0);
      expect(slotOf(orgId, SLOTS)).toBeLessThan(SLOTS);
    }
  });

  it('spreads organisations over every slot', () => {
    expect(new Set(ORGS.map((orgId) => slotOf(orgId, SLOTS))).size).toBe(SLOTS);
  });

  it('is its ID’s hash: the first four bytes of its SHA-256, by the slots', () => {
    // sha256('a') begins ca978112, 3398926610; sha256('b') 3e23e816, 1042540566; sha256('c') 2e7d2c03, 779955203.
    expect(['a', 'b', 'c'].map((id) => slotOf(id, SLOTS))).toEqual([2, 6, 11]);
    expect(slotOf('c', 7)).toBe(779_955_203 % 7);
  });
});

describe('the slots begun between two looks', () => {
  const at = (slot: number) => MIDNIGHT.getTime() + slot * SLOT_MS;

  it('are those whose start is after the first and at or before the second', () => {
    expect(slotsBetween(at(0), at(0), SLOTS, SLOT_MS)).toEqual(new Set());
    expect(slotsBetween(at(0), at(1) - 1, SLOTS, SLOT_MS)).toEqual(new Set());
    expect(slotsBetween(at(0), at(1), SLOTS, SLOT_MS)).toEqual(new Set([1]));
    expect(slotsBetween(at(1) - 1, at(3), SLOTS, SLOT_MS)).toEqual(new Set([1, 2, 3]));
  });

  it('run on round the cycle, and are every slot at most', () => {
    expect(slotsBetween(at(11), at(13), SLOTS, SLOT_MS)).toEqual(new Set([0, 1]));
    expect(slotsBetween(at(0), at(100), SLOTS, SLOT_MS).size).toBe(SLOTS);
    expect(slotsBetween(at(0), at(SLOTS), SLOTS, SLOT_MS).size).toBe(SLOTS);
    expect(slotsBetween(at(0), at(SLOTS - 1), SLOTS, SLOT_MS).size).toBe(SLOTS - 1);
  });

  it('are fixed to the epoch, not to when anyone looked', () => {
    // A look at the very end of slot 2 and the next at the start of slot 3: slot 3 alone.
    expect(slotsBetween(at(3) - 1, at(3), SLOTS, SLOT_MS)).toEqual(new Set([3]));
  });
});

describe('a rotation', () => {
  it('lists every organisation at its first run, then a twelfth a slot, each once a cycle', async () => {
    const clock = new FixedClock(new Date(MIDNIGHT.getTime() + 10 * MINUTE));
    const { all } = listing();
    const list = rotation({ all, slots: SLOTS, slotMs: SLOT_MS, clock });

    expect(await list()).toEqual(ORGS);
    const seen = new Map<string, number>();
    for (let run = 1; run <= SLOTS; run += 1) {
      clock.advanceBy(SLOT_MS);
      const listed = await list();
      // Slot `run`'s, whose start came since the run before.
      expect(listed).toEqual(ORGS.filter((orgId) => slotOf(orgId, SLOTS) === run % SLOTS));
      for (const orgId of listed) seen.set(orgId, (seen.get(orgId) ?? 0) + 1);
    }
    expect([...seen.keys()].toSorted()).toEqual(ORGS.toSorted());
    expect(new Set(seen.values())).toEqual(new Set([1]));
  });

  it('lists nothing for a run before the next slot begins, and every slot begun since for a late run', async () => {
    const clock = new FixedClock(MIDNIGHT);
    const list = rotation({ all: listing().all, slots: SLOTS, slotMs: SLOT_MS, clock });
    await list();
    clock.advanceBy(SLOT_MS - 1);
    expect(await list()).toEqual([]);
    // Three slots late: 1, 2 and 3, none missed.
    clock.advanceBy(3 * SLOT_MS);
    expect(await list()).toEqual(ORGS.filter((orgId) => [1, 2, 3].includes(slotOf(orgId, SLOTS))));
    // A whole cycle late: every one.
    clock.advanceBy(SLOTS * SLOT_MS);
    expect(await list()).toEqual(ORGS);
  });

  it('a run whose list fails looks again from the same place', async () => {
    const clock = new FixedClock(MIDNIGHT);
    let fails = false;
    const list = rotation({
      all: () => (fails ? Promise.reject(new Error('no directory')) : Promise.resolve(ORGS)),
      slots: SLOTS,
      slotMs: SLOT_MS,
      clock,
    });
    await list();
    clock.advanceBy(SLOT_MS);
    fails = true;
    await expect(list()).rejects.toThrow('no directory');
    fails = false;
    clock.advanceBy(SLOT_MS);
    expect(await list()).toEqual(ORGS.filter((orgId) => [1, 2].includes(slotOf(orgId, SLOTS))));
  });

  it('a first run whose list fails is a first run again', async () => {
    const clock = new FixedClock(MIDNIGHT);
    let fails = true;
    const list = rotation({
      all: () => (fails ? Promise.reject(new Error('no directory')) : Promise.resolve(ORGS)),
      slots: SLOTS,
      slotMs: SLOT_MS,
      clock,
    });
    await expect(list()).rejects.toThrow('no directory');
    fails = false;
    expect(await list()).toEqual(ORGS);
  });
});

describe('a pass a day', () => {
  it('lists every organisation at the first run and the first of each UTC day, nothing read between', async () => {
    const clock = new FixedClock(new Date('2026-11-04T23:00:00.000Z'));
    const { all, reads } = listing(['a', 'b']);
    const list = eachDay({ all, clock });

    expect(await list()).toEqual(['a', 'b']);
    clock.advanceBy(HOUR - 1);
    expect(await list()).toEqual([]);
    expect(reads()).toBe(1);
    clock.advanceBy(1);
    expect(await list()).toEqual(['a', 'b']);
    clock.advanceBy(23 * HOUR);
    expect(await list()).toEqual([]);
    expect(reads()).toBe(2);
  });

  it('a day starting past midnight starts there', async () => {
    const clock = new FixedClock(new Date('2026-11-04T00:10:00.000Z'));
    const list = eachDay({ all: listing(['a']).all, startsAfterMs: 15 * MINUTE, clock });
    expect(await list()).toEqual(['a']);
    clock.advanceBy(5 * MINUTE - 1);
    expect(await list()).toEqual([]);
    clock.advanceBy(1);
    expect(await list()).toEqual(['a']);
  });

  it('a run whose list fails tries the day’s pass again', async () => {
    const clock = new FixedClock(MIDNIGHT);
    let fails = false;
    const list = eachDay({
      all: () => (fails ? Promise.reject(new Error('no directory')) : Promise.resolve(['a'])),
      clock,
    });
    await list();
    clock.advanceBy(DAY);
    fails = true;
    await expect(list()).rejects.toThrow('no directory');
    fails = false;
    expect(await list()).toEqual(['a']);
  });
});

describe('what is owed', () => {
  it('stays listed, first, until the job says it is done', async () => {
    let named: readonly string[] = ['a', 'b', 'c'];
    const owed = owedPasses(() => Promise.resolve(named));

    expect(await owed.list()).toEqual(['a', 'b', 'c']);
    owed.done('b');
    named = ['d', 'a'];
    expect(await owed.list()).toEqual(['a', 'c', 'd']);
    owed.done('a');
    owed.done('c');
    owed.done('d');
    named = [];
    expect(await owed.list()).toEqual([]);
  });

  it('a source that fails fails the list, and keeps what is owed', async () => {
    let fails = false;
    const owed = owedPasses(() => (fails ? Promise.reject(new Error('no directory')) : Promise.resolve(['a'])));
    await owed.list();
    fails = true;
    await expect(owed.list()).rejects.toThrow('no directory');
    fails = false;
    expect(await owed.list()).toEqual(['a']);
  });
});
