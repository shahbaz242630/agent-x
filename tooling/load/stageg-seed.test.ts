// Stage G's seed's pure parts (stageg-seed.ts): each index's kind, the run's
// organisation IDs, the worker pool, and the kinds stage-g.k6.js knows the
// cohort's agents by. The database parts: stageg-seed.db.test.ts.
import { describe, expect, it } from 'vitest';

import { STAGE_G_HEAVY_EVERY, STAGE_G_LIGHT_EVERY } from './plan.ts';
import { cohortKindOf, pooled, stageGKindAt, stageGOrgId, stageGSeedWorkers } from './stageg-seed.ts';

describe('stageGKindAt', () => {
  it('makes the first the long chain, about 0.5% heavy, about 2% light and the rest idle', () => {
    const kinds = Array.from({ length: 10_000 }, (_, index) => stageGKindAt(index));
    const count = (kind: string) => kinds.filter((each) => each === kind).length;
    expect(kinds.slice(0, 4)).toEqual(['huge-chain', 'heavy', 'light', 'idle']);
    expect(count('huge-chain')).toBe(1);
    expect(count('heavy')).toBe(10_000 / STAGE_G_HEAVY_EVERY);
    expect(count('light')).toBe(10_000 / STAGE_G_LIGHT_EVERY);
    expect(stageGKindAt(STAGE_G_HEAVY_EVERY + 1)).toBe('heavy');
  });
});

describe('stageGOrgId', () => {
  it('is a version 8 UUID, the same for a run and index on every call, another for another', () => {
    const id = stageGOrgId('run', 7);
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(stageGOrgId('run', 7)).toBe(id);
    expect(new Set([id, stageGOrgId('run', 8), stageGOrgId('other', 7)]).size).toBe(3);
  });
});

describe('pooled', () => {
  it('runs every item, never more than the workers at once', async () => {
    let running = 0;
    let most = 0;
    const done: number[] = [];
    await pooled([1, 2, 3, 4, 5, 6, 7], 3, async (n) => {
      running += 1;
      most = Math.max(most, running);
      await new Promise((resolve) => setTimeout(resolve, 5));
      done.push(n);
      running -= 1;
    });
    expect(done.toSorted()).toEqual([1, 2, 3, 4, 5, 6, 7]);
    expect(most).toBe(3);
  });

  it('takes no new item after a failure, lets the others finish theirs, then throws it', async () => {
    const started: number[] = [];
    const finished: number[] = [];
    const run = pooled([1, 2, 3, 4, 5], 2, async (n) => {
      started.push(n);
      if (n === 1) throw new Error('one failed');
      await new Promise((resolve) => setTimeout(resolve, 10));
      finished.push(n);
    });
    await expect(run).rejects.toThrow('one failed');
    expect({ started, finished }).toEqual({ started: [1, 2], finished: [2] });
  });

  it('runs nothing for no items', async () => {
    let calls = 0;
    await pooled([], 4, () => {
      calls += 1;
      return Promise.resolve();
    });
    expect(calls).toBe(0);
  });
});

describe('cohortKindOf', () => {
  it('sends the steady traffic as the light organisations alone', () => {
    expect(cohortKindOf('light', 'steady', 0)).toBe('ample');
    expect(cohortKindOf('heavy', 'steady', 0)).toBeUndefined();
    expect(cohortKindOf('huge-chain', 'steady', 0)).toBeUndefined();
    expect(cohortKindOf('idle', 'steady', 0)).toBeUndefined();
  });

  it('beside the calm ones, the first heavy organisation is the busy one and the second the stuck one', () => {
    expect(cohortKindOf('light', 'neighbours', 0)).toBe('neighbour-calm');
    expect(cohortKindOf('heavy', 'neighbours', 0)).toBe('neighbour-busy');
    expect(cohortKindOf('heavy', 'neighbours', 1)).toBe('neighbour-stuck');
    expect(cohortKindOf('heavy', 'neighbours', 2)).toBeUndefined();
    expect(cohortKindOf('huge-chain', 'neighbours', 0)).toBeUndefined();
  });
});

describe('stageGSeedWorkers', () => {
  it("leaves one connection of the budget spare: the load job's six give five workers", () => {
    expect(stageGSeedWorkers()).toBe(5);
    expect(stageGSeedWorkers(9)).toBe(8);
    expect(stageGSeedWorkers(1)).toBe(1);
  });
});
