// 4D2e Stage F: which lines may go, and what can't choose it.
import { globSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { createLogSample, EVERY_LINE, SLOW_DECISION_MS, timersKept } from './log-sample.ts';

const IDS = Array.from({ length: 20_000 }, (_, n) => `0199a0f0-0000-7000-8000-${n.toString(16).padStart(12, '0')}`);
const SALT_A = Buffer.alloc(32, 1);
const SALT_B = Buffer.alloc(32, 2);

const NOTHING = { oneIn: 20, keeps: () => false };
const ALL_OF_TWENTY = { oneIn: 20, keeps: () => true };
const TIMERS = () => ({ turnWaitMs: 1 });

describe('the sample', () => {
  it('keeps every line at 1, the default, without hashing anything', () => {
    expect(createLogSample(1)).toBe(EVERY_LINE);
    expect(IDS.every((id) => EVERY_LINE.keeps(id))).toBe(true);
  });

  it('keeps about 1 in N, the same answer for one ID within a process', () => {
    const sample = createLogSample(20, SALT_A);
    const kept = IDS.filter((id) => sample.keeps(id));
    expect(kept.length).toBeGreaterThan(850);
    expect(kept.length).toBeLessThan(1_150);
    expect(kept.every((id) => sample.keeps(id))).toBe(true);
  });

  it("a client's chosen ID can't choose the sample: what one process keeps tells nothing of another's", () => {
    const one = createLogSample(20, SALT_A);
    const other = createLogSample(20, SALT_B);
    const keptByOne = IDS.filter((id) => one.keeps(id));
    const keptByBoth = keptByOne.filter((id) => other.keeps(id));
    // If the salt didn't matter this would be all of them; unrelated, about 1 in 20 of them.
    expect(keptByBoth.length).toBeLessThan(keptByOne.length / 10);
    // A plain hash of the ID would give every process one answer, known ahead to anyone.
    const unsalted = IDS.filter((id) => createLogSample(20, Buffer.alloc(0)).keeps(id));
    expect(keptByOne).not.toEqual(unsalted);
  });

  it('makes its own random salt, a process at a time', () => {
    const kept = () => {
      const sample = createLogSample(2);
      return IDS.slice(0, 256).map((id) => sample.keeps(id));
    };
    expect(kept()).not.toEqual(kept());
  });

  it('a security or money line is never sampled: only the request line and a decision’s timers ever ask', () => {
    const asking = globSync('{apps,packages,tooling}/**/*.ts', {
      exclude: (name) => name === 'node_modules' || name.endsWith('.test.ts'),
    })
      .filter((file) => /\.keeps\(|logSample|createLogSample|timersKept/.test(readFileSync(file, 'utf8')))
      .map((file) => file.replaceAll('\\', '/'))
      .sort();
    expect(asking).toEqual([
      'apps/api/src/log-sample.ts',
      'apps/api/src/request-log.ts',
      'apps/api/src/server.ts',
      'apps/api/src/spend-request-decisions.ts',
      'apps/api/src/start-web.ts',
    ]);
    // A read of every source file: past the default 5 s on a busy laptop's whole unit run (S183, Vitest 5).
  }, 30_000);
});

describe('a decision’s timers', () => {
  it('go with a fast decision outside the sample', () => {
    expect(timersKept(NOTHING, 'id', SLOW_DECISION_MS - 1, TIMERS)).toEqual({});
  });

  it('stay at 150 ms or over, whatever the sample says, each standing for itself', () => {
    expect(timersKept(NOTHING, 'id', SLOW_DECISION_MS, TIMERS)).toEqual({ turnWaitMs: 1 });
    expect(timersKept(ALL_OF_TWENTY, 'id', SLOW_DECISION_MS, TIMERS)).toEqual({ turnWaitMs: 1 });
  });

  it('stay on a fast decision in the sample, saying how many it stands for', () => {
    expect(timersKept(ALL_OF_TWENTY, 'id', 3, TIMERS)).toEqual({ turnWaitMs: 1, sampleOf: 20 });
  });

  it('are as they always were with sampling off', () => {
    expect(timersKept(EVERY_LINE, 'id', 3, TIMERS)).toEqual({ turnWaitMs: 1 });
  });
});
