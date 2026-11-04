// The anchor check's rotation (4D2e E7): which organisations' days come when, the counts and walks they make, the full
// pass's share and order, and what is late. Every read is a fake that answers as the test says, or is held until let go.
import {
  type Anchor,
  type ChainProblem,
  type ChainStep,
  type CheckedPoint,
  createMemoryAnchorStore,
  type AnchorStore,
  createMemoryPassRecord,
  type PassRecord,
  signAnchor,
  signPass,
  signProgress,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  COUNTED_AT_ONCE,
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

interface Rotating {
  readonly epoch?: number;
  readonly started?: Date;
  readonly sleeps?: boolean;
  readonly lastRanAt?: Date;
  /** Another process's memory of the store, to start after it as a restart would. */
  readonly after?: { readonly anchors: AnchorStore; readonly passes: PassRecord };
}

function rotating(more: Rotating = {}) {
  const capture = new LogCapture();
  const clock = new FixedClock(more.started ?? AT);
  const anchors = more.after?.anchors ?? createMemoryAnchorStore();
  const passes = more.after?.passes ?? createMemoryPassRecord();
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
    lastRanAt: () => more.lastRanAt,
    sleeps: more.sleeps ?? false,
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
  const MINUTE = 60_000;
  it("is the chains' lengths times the time since the last run over three days, rounded up", () => {
    expect(passBudget(0n, 5 * MINUTE)).toBe(0n);
    expect(passBudget(1n, 5 * MINUTE)).toBe(1n);
    // Five minutes are 1/864 of three days.
    expect(passBudget(864n, 5 * MINUTE)).toBe(1n);
    expect(passBudget(865n, 5 * MINUTE)).toBe(2n);
    expect(passBudget(864n, 9 * MINUTE)).toBe(2n);
    expect(passBudget(8640n, 9 * MINUTE)).toBe(18n);
    expect(passBudget(4_000_000_000n, 5 * MINUTE)).toBe(4_629_630n);
  });

  it("five minutes' worth at least, a whole round's at most", () => {
    expect(passBudget(8640n, 0)).toBe(10n);
    expect(passBudget(8640n, MINUTE)).toBe(10n);
    expect(passBudget(8640n, 3 * DAY)).toBe(8640n);
    expect(passBudget(8640n, 30 * DAY)).toBe(8640n);
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
    const long = 2n * COUNTED_AT_ONCE + 500n;
    made.anchor(orgId, long);
    const short = orgInSlot(108, 1);
    made.anchor(short, 40n);
    await made.run([orgId, short]);

    expect(onlyDays(made.calls)).toEqual([
      { check: 'count', orgId, after: 0n, upTo: COUNTED_AT_ONCE },
      { check: 'count', orgId, after: COUNTED_AT_ONCE, upTo: 2n * COUNTED_AT_ONCE },
      { check: 'count', orgId, after: 2n * COUNTED_AT_ONCE, upTo: long },
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

  it("one organisation whose reads keep failing holds up no other's day, nor the pass, and is late in time", async () => {
    const made = rotating();
    const failing = orgInSlot(108);
    const other = orgInSlot(108, 1);
    made.anchor(failing, 50n);
    made.anchor(other, 1728n);
    const away = new Error('the database is away for one organisation');
    made.answer.count = (orgId) => (orgId === failing ? Promise.reject(away) : Promise.resolve(undefined));
    await made.run([failing, other]);

    // Its read first, failing; then the other's day the same run, and the pass's steps.
    expect(made.calls.map(({ check, orgId }) => `${check} ${orgId === failing ? 'failing' : 'other'}`)).toEqual([
      'count failing',
      'count other',
      'walk other',
      // The run's share, 3 events, all taken by the first chain in the round.
      'pass failing',
    ]);
    expect(made.missed).toEqual([[failing, 'count', away]]);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([expect.objectContaining({ due: 2, left: 1 })]);

    // Still failing each run: tried again each run, and an hour past its five minutes it is late.
    made.clock.advanceBy(LATE_MS - 1);
    await made.run([failing, other]);
    expect(made.lines('audit.daily_check_overdue')).toEqual([]);
    made.clock.advanceBy(1);
    await made.run([failing, other]);
    expect(made.lines('audit.daily_check_overdue')).toEqual([
      expect.objectContaining({ organisations: 1, firstFew: [failing], waiting: 1 }),
    ]);
    expect(made.missed).toHaveLength(3);
  });

  it('a day whose walk failed keeps its count, and goes to the back behind those after it', async () => {
    const made = rotating();
    const first = orgInSlot(108);
    const second = orgInSlot(108, 1);
    made.anchor(first, 50n);
    made.anchor(second, 50n);
    const away = new Error('the database is away');
    let failures = 1;
    made.answer.walk = () => (failures-- > 0 ? Promise.reject(away) : Promise.resolve(stepTo(50n, 50n)));
    await made.run([first, second]);
    expect(onlyDays(made.calls).map(({ check, orgId }) => `${check} ${orgId === first ? 1 : 2}`)).toEqual([
      'count 1',
      'walk 1',
      'count 2',
      'walk 2',
    ]);

    made.calls.length = 0;
    made.clock.advanceBy(SLOT_MS);
    await made.run([first, second]);
    // Counted already: the walk alone is left.
    expect(onlyDays(made.calls).map(({ check, orgId }) => `${check} ${orgId === first ? 1 : 2}`)).toEqual(['walk 1']);
  });

  it('a first run after an outage takes every five minutes since the last process left off, a day at most', async () => {
    const made = rotating({ lastRanAt: new Date(AT.getTime() - 3 * 3_600_000) });
    // 06:00 is slot 72: its five minutes began when the last process left off, so it is not due again.
    const [atLeaving, inOutage, recent, older] = [orgInSlot(72), orgInSlot(73), orgInSlot(107), orgInSlot(60)];
    for (const orgId of [atLeaving, inOutage, recent, older]) made.anchor(orgId, 5n);
    made.answer.walk = (orgId) =>
      orgId === inOutage ? Promise.reject(new Error('away')) : Promise.resolve(stepTo(5n, 5n));
    await made.run([atLeaving, inOutage, recent, older]);

    expect(new Set(onlyDays(made.calls).map(({ orgId }) => orgId))).toEqual(new Set([inOutage, recent]));
    // Due from its own five minutes, nearly three hours ago: late at once, though seen only now.
    expect(made.lines('audit.daily_check_overdue')).toEqual([expect.objectContaining({ firstFew: [inOutage] })]);

    const longAway = rotating({ lastRanAt: new Date(AT.getTime() - 3 * DAY) });
    longAway.anchor(older, 5n);
    await longAway.run([older]);
    expect(onlyDays(longAway.calls).map(({ orgId }) => orgId)).toEqual([older, older]);
  });

  it('a count cut off by the run goes on next run from the statement it reached, to the anchor it began with', async () => {
    const made = rotating();
    const orgId = orgInSlot(108);
    made.anchor(orgId, 3n * COUNTED_AT_ONCE);
    const ending = new AbortController();
    made.answer.count = (_orgId, after) => {
      if (after === COUNTED_AT_ONCE) ending.abort();
      return Promise.resolve(undefined);
    };
    await made.run([orgId], ending.signal);
    made.anchor(orgId, 4n * COUNTED_AT_ONCE);
    delete made.answer.count;
    made.calls.length = 0;
    made.clock.advanceBy(SLOT_MS);
    await made.run([orgId]);

    expect(onlyDays(made.calls)).toEqual([
      { check: 'count', orgId, after: 2n * COUNTED_AT_ONCE, upTo: 3n * COUNTED_AT_ONCE },
      { check: 'walk', orgId, to: 3n * COUNTED_AT_ONCE, most: 1000 },
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
    const target = made.anchor(orgId, 1728n);
    // 1,728 events over 864 runs: 2 a run.
    await made.run([orgId]);
    await made.run([orgId]);
    expect(made.calls).toEqual([
      { check: 'pass', orgId, from: 0n, to: 1728n, most: 2 },
      { check: 'pass', orgId, from: 2n, to: 1728n, most: 2 },
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
    // Dated when the pass began, three runs and a second ago: every event to its target was read since then.
    expect(pass).toEqual(signPass(keys, chainOf(orgId), target, AT, 4));
    expect(made.lines('audit.anchor_rotation_done').at(-1)).toMatchObject({ finished: 1 });
  });

  it('takes at most 2,000 events a step, the passed longest ago first, and a new round at most once a run', async () => {
    const made = rotating();
    const [never, old, recent] = [orgInSlot(1), orgInSlot(2), orgInSlot(3)];
    for (const orgId of [never, old, recent]) made.anchor(orgId, 1_000_000n);
    made.passes.keepPass(signPass(keys, chainOf(recent), point(5n), new Date(AT.getTime() - 1000)));
    made.passes.keepPass(signPass(keys, chainOf(old), point(5n), new Date(AT.getTime() - DAY)));
    await made.run([recent, old, never]);

    // 3,000,000 over 864 runs: 3,473 a run, so a step of 2,000 and one of 1,473.
    expect(made.calls).toEqual([
      { check: 'pass', orgId: never, from: 0n, to: 1_000_000n, most: 2000 },
      { check: 'pass', orgId: never, from: 2000n, to: 1_000_000n, most: 1473 },
    ]);
  });

  it('begins a new round at most once a run: chains that all fail are each tried once, whatever share is left', async () => {
    const made = rotating();
    const orgs = [orgInSlot(1), orgInSlot(2)];
    for (const orgId of orgs) made.anchor(orgId, 864n * 100n);
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
    made.anchor(leaving, 1728n);
    made.anchor(staying, 1728n);
    await made.run([leaving, staying]);
    made.calls.length = 0;
    await made.run([staying]);
    expect(made.calls).toEqual([{ check: 'pass', orgId: staying, from: 0n, to: 1728n, most: 2 }]);
  });

  it('a step that fails is the alarm, and the pass goes on to the next chain', async () => {
    const made = rotating();
    const [edited, next] = [orgInSlot(1), orgInSlot(2)];
    made.anchor(edited, 864n * 3n);
    made.anchor(next, 864n * 3n);
    made.answer.pass = (orgId, _cursor, to, most) =>
      Promise.resolve(
        orgId === edited ? { ok: false, problem: { reason: 'hash', seq: 2n } } : stepTo(BigInt(most), to.seq),
      );
    await made.run([edited, next]);

    expect(made.failed).toEqual([[edited, 'pass', { reason: 'hash', seq: 2n }]]);
    expect(made.calls).toEqual([
      { check: 'pass', orgId: edited, from: 0n, to: 2592n, most: 6 },
      { check: 'pass', orgId: next, from: 0n, to: 2592n, most: 6 },
    ]);
  });

  it("a step that doesn't come back is said, that chain waits for next run at its place, and the others go on", async () => {
    const made = rotating();
    const [failing, other] = [orgInSlot(1), orgInSlot(2)];
    made.anchor(failing, 1728n);
    made.anchor(other, 1728n);
    // One run: the first is under way at 4; then its reads fail.
    await made.run([failing, other]);
    const away = new Error('the database is away');
    made.answer.pass = (orgId, cursor, to, most) =>
      // Failing on a later turn of the event loop, as a database does: a pass that kept retrying it would spin until the test's limit.
      orgId === failing
        ? new Promise((_resolve, reject) => setImmediate(() => reject(away)))
        : Promise.resolve(stepTo(cursor.seq + BigInt(most), to.seq));
    made.calls.length = 0;
    await made.run([failing, other]);
    expect(made.missed).toEqual([[failing, 'pass', away]]);
    expect(made.calls).toEqual([
      { check: 'pass', orgId: failing, from: 4n, to: 1728n, most: 4 },
      { check: 'pass', orgId: other, from: 0n, to: 1728n, most: 4 },
    ]);

    delete made.answer.pass;
    made.calls.length = 0;
    await made.run([failing, other]);
    expect(made.calls[0]).toEqual({ check: 'pass', orgId: failing, from: 4n, to: 1728n, most: 4 });
  });

  it('stops at 150 seconds, the step under way left to end, nothing said for it', async () => {
    vi.useFakeTimers();
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 864n * 10_000n);
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
    letGo(stepTo(2000n, 864n * 10_000n));
  });

  it('takes no step in a run already ended', async () => {
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 864n * 10_000n);
    const ended = new AbortController();
    ended.abort();
    await made.run([orgId], ended.signal);
    expect(made.calls).toEqual([]);
  });

  it('stops when the run does', async () => {
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 864n * 10_000n);
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
      made.anchor(late, 864n * 4000n);
      made.anchor(finishing, 0n);
      made.passes.keepPass(signPass(keys, chainOf(late), point(1n), new Date(AT.getTime() - PASS_LATE_MS)));
      made.clock.advanceBy(PASS_LATE_MS);
      // The empty chain, never passed, goes first and finishes; the late one gets its share and is still short.
      await made.run([late, finishing, unanchored]);

      expect(made.lines('audit.full_pass_overdue')).toEqual([
        expect.objectContaining({ level: 'error', organisations: 1, firstFew: [late], withinDays: 7 }),
      ]);
    });

    it('in production a restart never moves the 7 days on: last passed 6.9 days ago, late within 0.1 days', async () => {
      const before = rotating();
      const orgId = orgInSlot(1);
      before.anchor(orgId, 864n * 4000n);
      before.passes.keepPass(signPass(keys, chainOf(orgId), point(1n), new Date(AT.getTime() - 6.9 * DAY)));
      await before.run([orgId]);
      expect(before.lines('audit.full_pass_overdue')).toEqual([]);

      const after = rotating({ started: new Date(AT.getTime() + 60_000), after: before });
      await after.run([orgId]);
      expect(after.lines('audit.full_pass_overdue')).toEqual([]);
      after.clock.advanceBy(0.1 * DAY);
      await after.run([orgId]);
      expect(after.lines('audit.full_pass_overdue')).toHaveLength(1);
    });

    it('a big chain passed round after round is never late, though runs come every 9 minutes, not 5', async () => {
      const made = rotating();
      const orgId = orgInSlot(1);
      // 4,320 events at a run every 9 minutes (5 between, 4 of run): 9 a run, 480 runs, three days a round. A share by
      // run count, 5 a run, would take 864 runs, 5.4 days a round, and be late before the second ended.
      made.anchor(orgId, 4320n);
      const passedAt = new Set<number>();
      for (let run = 0; run < 1445; run += 1) {
        made.clock.advanceBy(9 * 60_000);
        await made.run([orgId]);
        const last = made.passes.lastPass(chainOf(orgId))?.at.getTime();
        if (last !== undefined) passedAt.add(last);
      }
      // Nine days: three rounds finished, none late.
      expect(passedAt.size).toBe(3);
      expect(made.lines('audit.full_pass_overdue')).toEqual([]);
    });

    it('a share not read within its 150 seconds is said as capacity', async () => {
      vi.useFakeTimers();
      const made = rotating();
      const orgId = orgInSlot(1);
      made.anchor(orgId, 864n * 10_000n);
      const { promise: held, resolve: letGo } = Promise.withResolvers<ChainStep>();
      made.answer.pass = () => held;
      const running = made.run([orgId]);
      await settled();
      await vi.advanceTimersByTimeAsync(PASS_WITHIN_MS);
      await running;
      expect(made.lines('audit.full_pass_behind')).toEqual([
        expect.objectContaining({ level: 'warn', share: '10000', left: '10000', withinMs: PASS_WITHIN_MS }),
      ]);
      letGo(stepTo(2000n, 864n * 10_000n));
    });

    it('says nothing when its share was read, or nothing was left to read', async () => {
      const made = rotating();
      const orgId = orgInSlot(1);
      made.anchor(orgId, 864n);
      await made.run([orgId]);
      await made.run([]);
      expect(made.lines('audit.full_pass_behind')).toEqual([]);
    });

    it('a chain whose pass stalls is late, 7 days after its pass began', async () => {
      const made = rotating();
      const orgId = orgInSlot(1);
      made.anchor(orgId, 864n * 10n);
      await made.run([orgId]);
      made.answer.pass = () => Promise.reject(new Error('the database is away'));
      made.clock.advanceBy(PASS_LATE_MS - 1);
      await made.run([orgId]);
      expect(made.lines('audit.full_pass_overdue')).toEqual([]);
      made.clock.advanceBy(1);
      await made.run([orgId]);
      expect(made.lines('audit.full_pass_overdue')).toEqual([expect.objectContaining({ firstFew: [orgId] })]);
    });

    it('never passed: late 7 days from when it was first owed one, a place line in the store', async () => {
      const made = rotating();
      const orgId = orgInSlot(1);
      made.anchor(orgId, 864n * 4000n);
      await made.run([orgId]);
      made.clock.advanceBy(PASS_LATE_MS - 1);
      await made.run([orgId]);
      expect(made.lines('audit.full_pass_overdue')).toEqual([]);
      made.clock.advanceBy(1);
      await made.run([orgId]);
      expect(made.lines('audit.full_pass_overdue')).toHaveLength(1);
    });

    it('where the environment sleeps, a process woken after a long sleep says nothing for the time it slept', async () => {
      const made = rotating({ sleeps: true });
      const orgId = orgInSlot(1);
      made.anchor(orgId, 864n * 4000n);
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
    made.anchor(orgId, 864n);
    await made.run([orgId]);

    expect(made.calls.map(({ check }) => check)).toEqual(['count', 'walk', 'pass']);
    expect(made.lines('audit.anchor_rotation_done')).toEqual([
      expect.objectContaining({
        level: 'info',
        due: 1,
        left: 0,
        counted: '864',
        walked: 864,
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
      sleeps: false,
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

describe('a pass across restarts: its place kept in the store (4D2e E7 review)', () => {
  it('writes the place a pass reached each run it moved, and none once it finishes', async () => {
    const made = rotating({ epoch: 2 });
    const orgId = orgInSlot(1);
    made.anchor(orgId, 1728n);
    await made.run([orgId]);
    expect(made.passes.lastProgress(chainOf(orgId))).toEqual(
      signProgress(keys, chainOf(orgId), point(2n), { at: AT, began: AT }, 2),
    );
    made.answer.pass = (_orgId, _cursor, to) => Promise.resolve({ ok: true, ...to, to: to.seq });
    await made.run([orgId]);
    expect(made.passes.lastProgress(chainOf(orgId))).toBeUndefined();
    expect(made.passes.lastPass(chainOf(orgId))?.seq).toBe(1728n);
  });

  it('a restart goes on from the place the store holds, once the event there still holds it: no slower than unbroken', async () => {
    const steady = rotating();
    const orgId = orgInSlot(1);
    // 100 events, a share of 1 a run: 100 runs unbroken.
    steady.anchor(orgId, 100n);
    let runs = 0;
    // Bounded, so a pass that never finishes fails here rather than spinning.
    while (steady.passes.lastPass(chainOf(orgId)) === undefined && runs < 200) {
      await steady.run([orgId]);
      runs += 1;
    }

    let process = rotating();
    process.anchor(orgId, 100n);
    let restarted = 0;
    const verified: Call[] = [];
    while (process.passes.lastPass(chainOf(orgId)) === undefined && restarted < 400) {
      await process.run([orgId]);
      restarted += 1;
      // A restart after every run: memory gone but the store's lines.
      process = rotating({ after: process });
      process.answer.walk = (asked) => {
        verified.push({ check: 'walk', orgId: asked, to: 0n, most: 1 });
        return Promise.resolve(stepTo(1n, 1n));
      };
    }
    expect(runs).toBe(100);
    expect(restarted).toBe(runs);
    expect(verified.length).toBe(runs - 1);
  });

  it("SEC-DB-11 a place whose event no longer holds what was signed is tampering: the alarm and the hold, and the chain's pass starts again", async () => {
    const before = rotating();
    const orgId = orgInSlot(1);
    before.anchor(orgId, 1728n);
    await before.run([orgId]);
    await before.run([orgId]);

    const after = rotating({ after: before });
    after.answer.walk = () => Promise.resolve({ ok: false, problem: { reason: 'hash', seq: 4n } });
    await after.run([orgId]);
    expect(after.failed).toEqual([[orgId, 'pass', { reason: 'hash', seq: 4n }]]);
    // Nothing more of it this run; the next starts from its first event.
    expect(after.calls).toEqual([{ check: 'walk', orgId, to: 4n, most: 1 }]);
    after.calls.length = 0;
    await after.run([orgId]);
    expect(after.calls).toEqual([{ check: 'pass', orgId, from: 0n, to: 1728n, most: 2 }]);
  });

  it('one alarm and one hold a chain a run: a chain that failed is not taken again by a round begun the same run', async () => {
    const made = rotating();
    const [small, failing] = [orgInSlot(1), orgInSlot(2)];
    made.anchor(small, 1n);
    made.anchor(failing, 864n * 10n);
    // The first run: the small chain passed, the other under way.
    await made.run([small, failing]);
    expect(made.passes.lastPass(chainOf(small))).toBeDefined();
    made.answer.pass = (orgId, cursor, to, most) =>
      orgId === failing
        ? Promise.resolve({ ok: false, problem: { reason: 'mac', seq: 1n } })
        : Promise.resolve(stepTo(cursor.seq + BigInt(most), to.seq));
    made.calls.length = 0;
    await made.run([small, failing]);
    // It fails under way; the round begun again then puts it first, never passed: it is not taken again.
    expect(made.failed).toEqual([[failing, 'pass', { reason: 'mac', seq: 1n }]]);
    expect(made.calls.filter((call) => call.orgId === failing)).toHaveLength(1);
  });

  it("a place whose pass began more than 7 days ago isn't gone on from: that pass starts again, its lateness kept", async () => {
    const before = rotating();
    const orgId = orgInSlot(1);
    before.anchor(orgId, 864n * 4000n);
    await before.run([orgId]);
    const owed = before.passes.lastProgress(chainOf(orgId))?.at;

    const after = rotating({ started: new Date(AT.getTime() + PASS_LATE_MS + 1), after: before });
    await after.run([orgId]);
    // No check of the old place: read from the start again.
    expect(after.calls.map((call) => (call.check === 'pass' ? call.from : -1n))).toEqual([0n, 2000n]);
    const place = after.passes.lastProgress(chainOf(orgId));
    expect(place?.began).toEqual(after.clock.now());
    // Owed since the first pass began: never passed, it is late all the same.
    expect(place?.at).toEqual(owed);
    expect(after.lines('audit.full_pass_overdue')).toHaveLength(1);
  });

  it('a step that fails leaves a place at the start: the next round reads the chain whole', async () => {
    const made = rotating();
    const orgId = orgInSlot(1);
    made.anchor(orgId, 1728n);
    await made.run([orgId]);
    await made.run([orgId]);
    made.answer.pass = () => Promise.resolve({ ok: false, problem: { reason: 'mac', seq: 5n } });
    await made.run([orgId]);
    expect(made.passes.lastProgress(chainOf(orgId))?.seq).toBe(0n);

    // A restart: nothing goes on from below what failed.
    const after = rotating({ after: made });
    await after.run([orgId]);
    expect(after.calls).toEqual([{ check: 'pass', orgId, from: 0n, to: 1728n, most: 2 }]);
  });

  describe("a chain whose read didn't come back is tried first next run, not a round later", () => {
    const three = (made: ReturnType<typeof rotating>) => {
      const orgs = [orgInSlot(1), orgInSlot(2), orgInSlot(3)];
      for (const orgId of orgs) made.anchor(orgId, 864n * 2n);
      return orgs;
    };

    it('its first step', async () => {
      const made = rotating();
      const orgs = three(made);
      const [first = ''] = orgs;
      let failures = 1;
      made.answer.pass = (orgId, cursor, to, most) =>
        orgId === first && failures-- > 0
          ? Promise.reject(new Error('away'))
          : Promise.resolve(stepTo(cursor.seq + BigInt(most), to.seq));
      await made.run(orgs);
      made.calls.length = 0;
      await made.run(orgs);
      expect(made.calls[0]).toMatchObject({ orgId: first, from: 0n });
    });

    it('and once its step has come back failing, it is not first again: the round goes on', async () => {
      const made = rotating();
      const orgs = three(made);
      const [first = ''] = orgs;
      let calls = 0;
      made.answer.pass = (orgId, cursor, to, most) => {
        if (orgId !== first) return Promise.resolve(stepTo(cursor.seq + BigInt(most), to.seq));
        calls += 1;
        return calls === 1
          ? Promise.reject(new Error('away'))
          : // On a later turn of the event loop, as a database answers: a chain retried without end fails the test, not hangs it.
            new Promise<ChainStep>((resolve) =>
              setImmediate(() => {
                resolve({ ok: false, problem: { reason: 'mac', seq: 1n } });
              }),
            );
      };
      await made.run(orgs);
      await made.run(orgs);
      expect(made.failed).toEqual([[first, 'pass', { reason: 'mac', seq: 1n }]]);
      made.calls.length = 0;
      await made.run(orgs);
      expect(made.calls[0]).toMatchObject({ orgId: orgs[1] });
    });

    it('its resume check after a restart', async () => {
      const before = rotating();
      const orgs = three(before);
      const [first = ''] = orgs;
      // The first gets under way, with its place in the store.
      await before.run(orgs);
      const after = rotating({ after: before });
      let failures = 1;
      after.answer.walk = (orgId) =>
        orgId === first && failures-- > 0 ? Promise.reject(new Error('away')) : Promise.resolve(stepTo(1n, 1n));
      await after.run(orgs);
      expect(after.missed).toEqual([[first, 'pass', expect.any(Error) as Error]]);
      after.calls.length = 0;
      await after.run(orgs);
      expect(after.calls[0]).toMatchObject({ check: 'walk', orgId: first });
      expect(after.calls[1]).toMatchObject({ check: 'pass', orgId: first, from: 6n });
    });
  });

  it('a chain never reached is owed a pass from when it was first seen anchored, across restarts', async () => {
    const before = rotating();
    const [reached, waiting] = [orgInSlot(1), orgInSlot(2)];
    before.anchor(reached, 864n * 4000n);
    before.anchor(waiting, 864n * 4000n);
    await before.run([reached, waiting]);
    expect(new Set(before.calls.map(({ orgId }) => orgId))).toEqual(new Set([reached]));
    expect(before.passes.lastProgress(chainOf(waiting))).toMatchObject({ seq: 0n, at: AT });

    const after = rotating({ started: new Date(AT.getTime() + 6.9 * DAY), after: before });
    await after.run([reached, waiting]);
    expect(after.lines('audit.full_pass_overdue')).toEqual([]);
    after.clock.advanceBy(0.1 * DAY);
    await after.run([reached, waiting]);
    expect(after.lines('audit.full_pass_overdue')).toEqual([
      expect.objectContaining({ organisations: 2, firstFew: [reached, waiting] }),
    ]);
  });

  it("a place past the chain's anchor, or a check of it that doesn't come back, goes on safely", async () => {
    const before = rotating();
    const orgId = orgInSlot(1);
    before.anchor(orgId, 1728n);
    before.passes.keepProgress(signProgress(keys, chainOf(orgId), point(5000n), { at: AT, began: AT }));
    await before.run([orgId]);
    expect(before.calls).toEqual([{ check: 'pass', orgId, from: 0n, to: 1728n, most: 2 }]);

    const after = rotating({ after: before });
    const away = new Error('the database is away');
    after.answer.walk = () => Promise.reject(away);
    await after.run([orgId]);
    expect(after.missed).toEqual([[orgId, 'pass', away]]);
    expect(after.calls).toEqual([{ check: 'walk', orgId, to: 2n, most: 1 }]);
  });
});
