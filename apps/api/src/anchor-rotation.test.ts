// The anchor check's rotation (4D2e E7): which organisations' days come when, the counts and walks they make, the full
// pass's share and order, and what is late. Every read is a fake that answers as the test says, or is held until let go.
import {
  type Anchor,
  type ChainProblem,
  type ChainStep,
  type CheckedPoint,
  createMemoryAnchorStore,
  createMemoryPassRecord,
  signAnchor,
  signPass,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  COUNTED_A_STATEMENT,
  createRotation,
  PASS_LATE_MS,
  PASS_WITHIN_MS,
  passBudget,
  type RotatedChecks,
  type RotationCheck,
  rotatedChecksOf,
  slotOf,
  SLOTS,
  slotsBetween,
} from './anchor-rotation.ts';
import { PastDeadline, Stopped, withinDeadline } from './background.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const SLOT_MS = 300_000;
const DAY = 86_400_000;
/** 09:00 UTC: slot 108 begins. */
const AT = new Date('2026-11-02T09:00:00.000Z');
const LATE_MS = 3_600_000;
const ORG_PREFIX = '0199a0f0-0000-7000-8000-';

/** An organisation whose five minutes are `slot`, the `nth` found. */
function orgInSlot(slot: number, nth = 0): string {
  let found = 0;
  for (let index = 0; ; index += 1) {
    const orgId = `${ORG_PREFIX}${String(index).padStart(12, '0')}`;
    if (slotOf(orgId) === slot && found++ === nth) return orgId;
  }
}
const chainOf = (orgId: string) => ({ kind: 'organisation', orgId }) as const;
const point = (seq: bigint, fill = Number(seq % 200n)): CheckedPoint => ({
  seq,
  hash: Buffer.alloc(32, fill),
  macKeyVersion: 1,
});
const stepTo = (seq: bigint, to: bigint): ChainStep => ({ ok: true, ...point(seq), to });
const settled = async (): Promise<void> => {
  for (let round = 0; round < 200; round += 1) await Promise.resolve();
};

type Call =
  | { readonly check: 'count'; readonly orgId: string; readonly after: bigint; readonly upTo: bigint }
  | { readonly check: 'walk'; readonly orgId: string; readonly to: bigint; readonly most: number }
  | {
      readonly check: 'pass';
      readonly orgId: string;
      readonly from: bigint;
      readonly to: bigint;
      readonly most: number;
    };

/** Reads that pass, unless a test says otherwise; each call kept. */
function fakeChecks() {
  const calls: Call[] = [];
  const answer: {
    count?: (orgId: string, after: bigint, upTo: bigint) => Promise<ChainProblem | undefined>;
    walk?: (orgId: string) => Promise<ChainStep>;
    pass?: (orgId: string, cursor: CheckedPoint, target: CheckedPoint, most: number) => Promise<ChainStep>;
  } = {};
  const checks: RotatedChecks = {
    count: (orgId, after, upTo) => {
      calls.push({ check: 'count', orgId, after, upTo });
      return answer.count?.(orgId, after, upTo) ?? Promise.resolve(undefined);
    },
    walkLast: (orgId, target, most) => {
      calls.push({ check: 'walk', orgId, to: target.seq, most });
      return answer.walk?.(orgId) ?? Promise.resolve(stepTo(target.seq, target.seq));
    },
    passStep: (orgId, cursor, target, most) => {
      calls.push({ check: 'pass', orgId, from: cursor.seq, to: target.seq, most });
      if (answer.pass !== undefined) return answer.pass(orgId, cursor, target, most);
      const reached = cursor.seq + BigInt(most) < target.seq ? cursor.seq + BigInt(most) : target.seq;
      return Promise.resolve(
        reached === target.seq ? { ok: true, ...target, to: target.seq } : stepTo(reached, target.seq),
      );
    },
  };
  return { checks, calls, answer };
}

function rotating(more: { epoch?: number; started?: Date } = {}) {
  const capture = new LogCapture();
  const clock = new FixedClock(more.started ?? AT);
  const anchors = createMemoryAnchorStore();
  const passes = createMemoryPassRecord();
  const { checks, calls, answer } = fakeChecks();
  const failed: [string, RotationCheck, ChainProblem][] = [];
  const missed: [string, RotationCheck, unknown][] = [];
  const rotation = createRotation({
    checks,
    anchors,
    passes,
    keys,
    clock,
    logger: testLogger(capture),
    epoch: more.epoch,
    lateAfterMs: LATE_MS,
    // Longer than any test's own wait: a read past it is made by rejecting with PastDeadline.
    bounded: (work, signal) => withinDeadline(work(), 3_600_000, signal),
    failed: (orgId, check, problem) => {
      failed.push([orgId, check, problem]);
      return Promise.resolve();
    },
    missed: (orgId, check, error) => {
      missed.push([orgId, check, error]);
      return Promise.resolve();
    },
  });
  const anchor = (orgId: string, seq: bigint, at = clock.now()): Anchor => {
    const signed = signAnchor(keys, chainOf(orgId), point(seq), at);
    anchors.keep(signed);
    return signed;
  };
  const run = (listed: readonly string[], signal = new AbortController().signal) => rotation.run(listed, signal);
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  return { rotation, run, clock, anchors, passes, calls, answer, failed, missed, anchor, lines, capture };
}

const onlyDays = (calls: readonly Call[]) => calls.filter((call) => call.check !== 'pass');

afterEach(() => {
  vi.useRealTimers();
});

describe("an organisation's five minutes of the day", () => {
  it('comes from its ID alone, whatever its case, and spreads 10,000 organisations over the day', () => {
    const orgId = `${ORG_PREFIX}00000000abcd`;
    expect(slotOf(orgId)).toBe(slotOf(orgId.toUpperCase()));
    const counts = new Array<number>(SLOTS).fill(0);
    for (let index = 0; index < 10_000; index += 1) {
      const slot = slotOf(`${ORG_PREFIX}${String(index).padStart(12, '0')}`);
      expect(slot).toBeGreaterThanOrEqual(0);
      expect(slot).toBeLessThan(SLOTS);
      counts[slot] = (counts[slot] ?? 0) + 1;
    }
    // About 35 each: none empty, none crowded.
    expect(Math.min(...counts)).toBeGreaterThan(10);
    expect(Math.max(...counts)).toBeLessThan(70);
  });

  it('a stretch of time holds the slots beginning after its start, up to and at its end, a day at most', () => {
    const nine = AT.getTime();
    expect([...slotsBetween(nine - 1, nine)]).toEqual([108]);
    expect([...slotsBetween(nine, nine + SLOT_MS - 1)]).toEqual([]);
    expect([...slotsBetween(nine, nine + 2 * SLOT_MS)]).toEqual([109, 110]);
    // Midnight is slot 0 of the next day.
    const midnight = Date.parse('2026-11-03T00:00:00.000Z');
    expect([...slotsBetween(midnight - SLOT_MS, midnight)]).toEqual([0]);
    expect(slotsBetween(nine, nine + DAY).size).toBe(SLOTS);
    expect(slotsBetween(nine, nine + 3 * DAY).size).toBe(SLOTS);
  });
});

describe('the full pass share', () => {
  it("is the chains' lengths over 1,728 runs, rounded up", () => {
    expect(passBudget(0n)).toBe(0n);
    expect(passBudget(1n)).toBe(1n);
    expect(passBudget(1728n)).toBe(1n);
    expect(passBudget(1729n)).toBe(2n);
    expect(passBudget(4_000_000_000n)).toBe(2_314_815n);
  });
});

describe("each organisation's day: the count and the walk (decisions 1 and 2b)", () => {
  it('counts every event to its anchor and walks the last 1,000, when its five minutes come, once a day', async () => {
    const made = rotating();
    const orgId = orgInSlot(109);
    made.anchor(orgId, 5000n);
    await made.run([orgId]);
    // Its five minutes are yet to come: a first run looks back an hour, not forward.
    expect(onlyDays(made.calls)).toEqual([]);

    made.clock.advanceBy(SLOT_MS);
    await made.run([orgId]);
    expect(onlyDays(made.calls)).toEqual([
      { check: 'count', orgId, after: 0n, upTo: 5000n },
      { check: 'walk', orgId, to: 5000n, most: 1000 },
    ]);

    made.calls.length = 0;
    made.clock.advanceBy(SLOT_MS);
    await made.run([orgId]);
    made.clock.advanceBy(DAY - 2 * SLOT_MS);
    await made.run([orgId]);
    expect(onlyDays(made.calls)).toEqual([]);
    made.clock.advanceBy(SLOT_MS);
    await made.run([orgId]);
    expect(onlyDays(made.calls).map(({ check }) => check)).toEqual(['count', 'walk']);
    expect(made.failed).toEqual([]);
  });

  it("a process's first run takes those whose five minutes came within the hour before it, and none before that", async () => {
    const made = rotating();
    const recent = orgInSlot(97);
    const older = orgInSlot(96);
    made.anchor(recent, 3n);
    made.anchor(older, 3n);
    await made.run([recent, older]);

    expect(onlyDays(made.calls).map(({ orgId }) => orgId)).toEqual([recent, recent]);
  });

  it('counts a long chain a million events a statement, and walks no more than the chain holds', async () => {
    const made = rotating();
    const orgId = orgInSlot(108);
    const long = 2n * COUNTED_A_STATEMENT + 500n;
    made.anchor(orgId, long);
    const short = orgInSlot(108, 1);
    made.anchor(short, 40n);
    await made.run([orgId, short]);

    expect(onlyDays(made.calls)).toEqual([
      { check: 'count', orgId, after: 0n, upTo: COUNTED_A_STATEMENT },
      { check: 'count', orgId, after: COUNTED_A_STATEMENT, upTo: 2n * COUNTED_A_STATEMENT },
      { check: 'count', orgId, after: 2n * COUNTED_A_STATEMENT, upTo: long },
      { check: 'walk', orgId, to: long, most: 1000 },
      { check: 'count', orgId: short, after: 0n, upTo: 40n },
      { check: 'walk', orgId: short, to: 40n, most: 40 },
    ]);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([
      expect.objectContaining({ due: 2, left: 0, counted: String(long + 40n), walked: 1040 }),
    ]);
  });

  it('reads nothing for an empty chain, and drops one never anchored, its first check reading it whole', async () => {
    const made = rotating();
    const empty = orgInSlot(108);
    const unanchored = orgInSlot(108, 1);
    made.anchor(empty, 0n);
    await made.run([empty, unanchored]);

    expect(made.calls).toEqual([]);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([expect.objectContaining({ due: 2, left: 0 })]);
  });

  it('takes no organisation off the list, and drops a day waiting whose organisation has left it', async () => {
    const made = rotating();
    const [leaving, unlisted] = [orgInSlot(108), orgInSlot(108, 1)];
    made.anchor(leaving, 9n);
    made.anchor(unlisted, 9n);
    made.answer.count = () => Promise.reject(new Error('the database is away'));
    await made.run([leaving]);
    expect(onlyDays(made.calls).map(({ orgId }) => orgId)).toEqual([leaving]);

    delete made.answer.count;
    made.calls.length = 0;
    made.clock.advanceBy(SLOT_MS);
    await made.run([]);
    expect(made.calls).toEqual([]);
    expect(made.lines('audit.anchor_rotation_done').at(-1)).toMatchObject({ due: 1, left: 0 });
  });

  it('a count short is the alarm, with no walk; a walk that fails is the alarm', async () => {
    const made = rotating();
    const deleted = orgInSlot(108);
    const edited = orgInSlot(108, 1);
    made.anchor(deleted, 50n);
    made.anchor(edited, 50n);
    made.answer.count = (orgId) => Promise.resolve(orgId === deleted ? { reason: 'gap', seq: 1n } : undefined);
    made.answer.walk = () => Promise.resolve({ ok: false, problem: { reason: 'hash', seq: 44n } });
    await made.run([deleted, edited]);

    expect(made.failed).toEqual([
      [deleted, 'count', { reason: 'gap', seq: 1n }],
      [edited, 'walk', { reason: 'hash', seq: 44n }],
    ]);
    expect(onlyDays(made.calls).map(({ check, orgId }) => `${check} ${orgId}`)).toEqual([
      `count ${deleted}`,
      `count ${edited}`,
      `walk ${edited}`,
    ]);
    // Both days are over: not read again this day.
    made.calls.length = 0;
    made.clock.advanceBy(SLOT_MS);
    await made.run([deleted, edited]);
    expect(onlyDays(made.calls)).toEqual([]);
  });

  it("a read that doesn't come back is said, ends the days for the run, and is tried again first next run", async () => {
    const made = rotating();
    const first = orgInSlot(108);
    const second = orgInSlot(108, 1);
    made.anchor(first, 50n);
    made.anchor(second, 50n);
    const away = new Error('the database is away');
    made.answer.walk = () => Promise.reject(away);
    await made.run([first, second]);

    expect(made.missed).toEqual([[first, 'walk', away]]);
    expect(onlyDays(made.calls).map(({ check, orgId }) => `${check} ${orgId}`)).toEqual([
      `count ${first}`,
      `walk ${first}`,
    ]);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([expect.objectContaining({ due: 2, left: 2 })]);

    delete made.answer.walk;
    made.calls.length = 0;
    made.clock.advanceBy(SLOT_MS);
    await made.run([first, second]);
    // Counted already: the walk alone is left for the first.
    expect(onlyDays(made.calls).map(({ check, orgId }) => `${check} ${orgId}`)).toEqual([
      `walk ${first}`,
      `count ${second}`,
      `walk ${second}`,
    ]);
  });

  it('a count cut off by the run goes on next run from the statement it reached, to the anchor it began with', async () => {
    const made = rotating();
    const orgId = orgInSlot(108);
    made.anchor(orgId, 3n * COUNTED_A_STATEMENT);
    const ending = new AbortController();
    made.answer.count = (_orgId, after) => {
      if (after === COUNTED_A_STATEMENT) ending.abort();
      return Promise.resolve(undefined);
    };
    await made.run([orgId], ending.signal);
    made.anchor(orgId, 4n * COUNTED_A_STATEMENT);
    delete made.answer.count;
    made.calls.length = 0;
    made.clock.advanceBy(SLOT_MS);
    await made.run([orgId]);

    expect(onlyDays(made.calls)).toEqual([
      { check: 'count', orgId, after: 2n * COUNTED_A_STATEMENT, upTo: 3n * COUNTED_A_STATEMENT },
      { check: 'walk', orgId, to: 3n * COUNTED_A_STATEMENT, most: 1000 },
    ]);
    expect(made.missed).toEqual([]);
  });

  it('days waiting an hour past their five minutes are late, on one line; less is not', async () => {
    const made = rotating();
    const orgId = orgInSlot(108);
    made.anchor(orgId, 50n);
    made.answer.count = () => Promise.reject(new Error('the database is away'));
    await made.run([orgId]);
    made.clock.advanceBy(LATE_MS - 1);
    await made.run([orgId]);
    expect(made.lines('audit.daily_check_overdue')).toEqual([]);

    made.clock.advanceBy(1);
    await made.run([orgId]);
    expect(made.lines('audit.daily_check_overdue')).toEqual([
      expect.objectContaining({ level: 'error', organisations: 1, firstFew: [orgId], waiting: 1 }),
    ]);
  });
});

describe('the full pass (decision 3)', () => {
  it("reads each chain from its first event to its anchor, a share a run, and signs its end in the store's epoch", async () => {
    const made = rotating({ epoch: 4 });
    const orgId = orgInSlot(5);
    const target = made.anchor(orgId, 3456n);
    // 3,456 events over 1,728 runs: 2 a run.
    await made.run([orgId]);
    await made.run([orgId]);
    expect(made.calls).toEqual([
      { check: 'pass', orgId, from: 0n, to: 3456n, most: 2 },
      { check: 'pass', orgId, from: 2n, to: 3456n, most: 2 },
    ]);
    expect(made.lines('audit.anchor_rotation_done').at(-1)).toMatchObject({ budget: '2', passed: '2', finished: 0 });

    made.answer.pass = (_orgId, cursor, to) =>
      Promise.resolve(cursor.seq === 4n ? { ok: true, ...to, to: to.seq } : stepTo(cursor.seq + 2n, to.seq));
    made.calls.length = 0;
    made.clock.advanceBy(1000);
    // Moved on since: the pass still goes to where it set out for.
    made.anchor(orgId, 4000n);
    await made.run([orgId]);
    const pass = made.passes.lastPass(chainOf(orgId));
    expect(pass).toEqual(signPass(keys, chainOf(orgId), target, made.clock.now(), 4));
    expect(made.lines('audit.anchor_rotation_done').at(-1)).toMatchObject({ finished: 1 });
  });

  it('takes at most 2,000 events a step, the passed longest ago first, and a new round at most once a run', async () => {
    const made = rotating();
    const [never, old, recent] = [orgInSlot(1), orgInSlot(2), orgInSlot(3)];
    for (const orgId of [never, old, recent]) made.anchor(orgId, 2_000_000n);
    made.passes.keepPass(signPass(keys, chainOf(recent), point(5n), new Date(AT.getTime() - 1000)));
    made.passes.keepPass(signPass(keys, chainOf(old), point(5n), new Date(AT.getTime() - DAY)));
    await made.run([recent, old, never]);

    // 6,000,000 over 1,728 runs: 3,473 a run, so a step of 2,000 and one of 1,473.
    expect(made.calls).toEqual([
      { check: 'pass', orgId: never, from: 0n, to: 2_000_000n, most: 2000 },
      { check: 'pass', orgId: never, from: 2000n, to: 2_000_000n, most: 1473 },
    ]);
  });

  it('begins a new round at most once a run: chains that all fail are each tried once, whatever share is left', async () => {
    const made = rotating();
    const orgs = [orgInSlot(1), orgInSlot(2)];
    for (const orgId of orgs) made.anchor(orgId, 1728n * 100n);
    made.answer.pass = () => Promise.resolve({ ok: false, problem: { reason: 'mac', seq: 1n } });
    await made.run(orgs);
    expect(made.calls.map(({ orgId }) => orgId)).toEqual(orgs);
    await made.run(orgs);
    expect(made.calls.map(({ orgId }) => orgId)).toEqual([...orgs, ...orgs]);
    expect(made.failed).toHaveLength(4);
  });

  it('finishes empty chains with no read, and passes over those never anchored or gone from the list', async () => {
    const made = rotating();
    const [empty, unanchored, gone] = [orgInSlot(1), orgInSlot(2), orgInSlot(3)];
    made.anchor(empty, 0n);
    made.anchor(gone, 9000n);
    made.anchor(orgInSlot(4), 9000n);
    await made.run([empty, unanchored, orgInSlot(4)]);

    expect(made.passes.lastPass(chainOf(empty))).toBeDefined();
    expect(made.calls.map(({ orgId }) => orgId)).toEqual([orgInSlot(4)]);
    expect(made.passes.lastPass(chainOf(unanchored))).toBeUndefined();
  });

  it('a chain under way that leaves the list is dropped, and the next one taken', async () => {
    const made = rotating();
    const [leaving, staying] = [orgInSlot(1), orgInSlot(2)];
    made.anchor(leaving, 3456n);
    made.anchor(staying, 3456n);
    await made.run([leaving, staying]);
    made.calls.length = 0;
    await made.run([staying]);
    expect(made.calls).toEqual([{ check: 'pass', orgId: staying, from: 0n, to: 3456n, most: 2 }]);
  });

  it('a step that fails is the alarm, and the pass goes on to the next chain', async () => {
    const made = rotating();
    const [edited, next] = [orgInSlot(1), orgInSlot(2)];
    made.anchor(edited, 1728n * 3n);
    made.anchor(next, 1728n * 3n);
    made.answer.pass = (orgId, _cursor, to, most) =>
      Promise.resolve(
        orgId === edited ? { ok: false, problem: { reason: 'hash', seq: 2n } } : stepTo(BigInt(most), to.seq),
      );
    await made.run([edited, next]);

    expect(made.failed).toEqual([[edited, 'pass', { reason: 'hash', seq: 2n }]]);
    expect(made.calls).toEqual([
      { check: 'pass', orgId: edited, from: 0n, to: 5184n, most: 6 },
      { check: 'pass', orgId: next, from: 0n, to: 5184n, most: 6 },
    ]);
  });

  it("a step that doesn't come back is said and ends the pass for the run; it goes on from the same place", async () => {
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 3456n);
    const away = new Error('the database is away');
    made.answer.pass = () => Promise.reject(away);
    await made.run([orgId]);
    expect(made.missed).toEqual([[orgId, 'pass', away]]);

    delete made.answer.pass;
    await made.run([orgId]);
    expect(made.calls).toEqual([
      { check: 'pass', orgId, from: 0n, to: 3456n, most: 2 },
      { check: 'pass', orgId, from: 0n, to: 3456n, most: 2 },
    ]);
  });

  it('stops at 150 seconds, the step under way left to end, nothing said for it', async () => {
    vi.useFakeTimers();
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 1728n * 10_000n);
    const { promise: held, resolve: letGo } = Promise.withResolvers<ChainStep>();
    made.answer.pass = () => held;
    const running = made.run([orgId]);
    await settled();
    await vi.advanceTimersByTimeAsync(PASS_WITHIN_MS - 1);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await running;
    expect(made.missed).toEqual([]);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([expect.objectContaining({ passed: '0' })]);
    letGo(stepTo(2000n, 1728n * 10_000n));
  });

  it('takes no step in a run already ended', async () => {
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 1728n * 10_000n);
    const ended = new AbortController();
    ended.abort();
    await made.run([orgId], ended.signal);
    expect(made.calls).toEqual([]);
  });

  it('stops when the run does', async () => {
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 1728n * 10_000n);
    const ending = new AbortController();
    made.answer.pass = (_orgId, cursor, to, most) => {
      ending.abort();
      return Promise.resolve(stepTo(cursor.seq + BigInt(most), to.seq));
    };
    await made.run([orgId], ending.signal);
    expect(made.calls).toHaveLength(1);
    expect(made.missed).toEqual([]);
  });

  describe('late: 7 days with no pass finished, judged after the run, from this process start at the earliest', () => {
    it('a chain whose last pass is older is late; one finished this run, or never anchored, is not', async () => {
      const made = rotating({ started: new Date(AT.getTime() - PASS_LATE_MS) });
      const [late, finishing, unanchored] = [orgInSlot(1), orgInSlot(2), orgInSlot(3)];
      made.anchor(late, 1728n * 4000n);
      made.anchor(finishing, 0n);
      made.passes.keepPass(signPass(keys, chainOf(late), point(1n), new Date(AT.getTime() - PASS_LATE_MS)));
      made.clock.advanceBy(PASS_LATE_MS);
      // The empty chain, never passed, goes first and finishes; the late one gets its share and is still short.
      await made.run([late, finishing, unanchored]);

      expect(made.lines('audit.full_pass_overdue')).toEqual([
        expect.objectContaining({ level: 'error', organisations: 1, firstFew: [late], withinDays: 7 }),
      ]);
    });

    it('a process woken after a long sleep says nothing for the time it slept', async () => {
      const made = rotating();
      const orgId = orgInSlot(1);
      made.anchor(orgId, 1728n * 4000n);
      made.passes.keepPass(signPass(keys, chainOf(orgId), point(1n), new Date(AT.getTime() - 30 * DAY)));
      await made.run([orgId]);
      expect(made.lines('audit.full_pass_overdue')).toEqual([]);

      made.clock.advanceBy(PASS_LATE_MS - 1);
      await made.run([orgId]);
      expect(made.lines('audit.full_pass_overdue')).toEqual([]);
      made.clock.advanceBy(1);
      await made.run([orgId]);
      expect(made.lines('audit.full_pass_overdue')).toHaveLength(1);
    });
  });
});

describe('a run of the rotation', () => {
  it('days first, then the pass, and one line with what it did', async () => {
    const made = rotating();
    const orgId = orgInSlot(108);
    made.anchor(orgId, 1728n);
    await made.run([orgId]);

    expect(made.calls.map(({ check }) => check)).toEqual(['count', 'walk', 'pass']);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([
      expect.objectContaining({
        level: 'info',
        due: 1,
        left: 0,
        counted: '1728',
        walked: 1000,
        budget: '1',
        passed: '1',
        finished: 0,
        daysMs: expect.any(Number) as number,
        slicesMs: expect.any(Number) as number,
      }),
    ]);
  });

  it('never throws: anything unforeseen is the crash line', async () => {
    const made = rotating();
    const orgId = orgInSlot(108);
    made.anchor(orgId, 5n);
    const counting = fakeChecks();
    counting.answer.count = () => Promise.resolve({ reason: 'gap', seq: 1n });
    const failing = createRotation({
      checks: counting.checks,
      anchors: made.anchors,
      passes: made.passes,
      keys,
      clock: made.clock,
      logger: testLogger(made.capture),
      epoch: undefined,
      lateAfterMs: LATE_MS,
      bounded: (work) => work(),
      failed: () => Promise.reject(new Error('unforeseen')),
      missed: () => Promise.resolve(),
    });
    await expect(failing.run([orgId], new AbortController().signal)).resolves.toBeUndefined();
    expect(made.lines('audit.anchor_check_crashed')).toEqual([
      expect.objectContaining({ level: 'error', check: 'rotation' }),
    ]);
  });

  it('a read past its deadline is a miss; one ended by the run is not', async () => {
    const made = rotating();
    const orgId = orgInSlot(108);
    made.anchor(orgId, 5n);
    const late = new PastDeadline('the check did not finish');
    made.answer.count = () => Promise.reject(late);
    await made.run([orgId]);
    expect(made.missed).toEqual([[orgId, 'count', late]]);

    const stopped = rotating();
    stopped.anchor(orgId, 5n);
    stopped.answer.count = () => Promise.reject(new Stopped('the check was stopped'));
    await stopped.run([orgId]);
    expect(stopped.missed).toEqual([]);
  });
});

describe("the rotation's reads, from the audit trail", () => {
  it("passes each to the trail's own, on the job's database", async () => {
    const database = { name: 'the job database' } as unknown as Parameters<typeof rotatedChecksOf>[1];
    const asked: unknown[][] = [];
    const answer = { ok: true, ...point(3n), to: 3n } as const;
    const reads = rotatedChecksOf(
      {
        countStep: (...args) => {
          asked.push(['count', ...args]);
          return Promise.resolve(undefined);
        },
        walkLast: (...args) => {
          asked.push(['walk', ...args]);
          return Promise.resolve(answer);
        },
        passStep: (...args) => {
          asked.push(['pass', ...args]);
          return Promise.resolve(answer);
        },
      },
      database,
    );
    const orgId = orgInSlot(1);
    expect(await reads.count(orgId, 0n, 3n)).toBeUndefined();
    expect(await reads.walkLast(orgId, point(3n), 3)).toBe(answer);
    expect(await reads.passStep(orgId, point(1n), point(3n), 2)).toBe(answer);
    expect(asked).toEqual([
      ['count', database, orgId, 0n, 3n],
      ['walk', database, orgId, point(3n), 3],
      ['pass', database, orgId, point(1n), point(3n), 2],
    ]);
  });
});
