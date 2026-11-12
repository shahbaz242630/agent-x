// The anchor check's rotation (4D2e E7): what a check from the anchor can't see, an
// event below the anchor deleted or edited, found on a schedule rather than by
// reading every chain whole each run. Since E8 the runs read no organisation's chain
// whole (the probe, and the chains that moved from their anchors), so this is what
// finds an old event deleted past the last 1,000, or edited; the platform's chain,
// which it doesn't read, is read whole once a day instead (platformChainCheck).
//
// - Each organisation's day (decisions 1 and 2b): once a day, at its own five
//   minutes of 288 (its ID's hash), every event up to its anchor counted, a million
//   a statement, so one deleted shows as a count short; then its last 1,000 events
//   walked to the anchor, so one edited to hide from a signed-state read shows too.
//   A run takes those whose five minutes came since the last run; a process's first
//   looks back to the newest file in the anchors' store, where the last process left
//   off, an hour at least and a day at most, so a restart loses none of an outage's.
//   Each is due from its five minutes, not from when it was seen. Those a run's time
//   cut off wait, first next run; one whose read fails goes to the back and the others
//   go on. Any still waiting an hour past its five minutes is `audit.daily_check_overdue`.
// - The full pass (decision 3): every chain read from its first event to its anchor
//   as it stood when the pass reached it, the chains passed longest ago first. A
//   run's share is the sum of every chain's length times the time since the last run
//   over three days (five minutes' worth at least, three days' at most), so a round is
//   three days of wall time whatever the runs' cadence; at most 150 seconds of it, 2,000
//   events a step. Three, not six: a pass is dated when it began, so a chain's lateness
//   is the time between two passes' starts and the second's own length, two rounds at
//   worst, and that must stay within 7 days. A share cut short by its 150 seconds or by
//   the run's own time is capacity, said as `audit.full_pass_behind` (`by: pass | run`),
//   and what was left unread is carried into the next run's share, a round's worth at
//   most, so the round stays three days; `audit.full_pass_overdue` stays the alarm.
//   Each chain's pass finished is a signed line in the store, dated when that pass began
//   (so it says when its first event was read), and so is the place a pass under way has
//   reached, written each run it moves, with when its pass began and since when one was
//   owed. A restart goes on with the oldest, from where it had got to, once the event there
//   still holds the hash and MAC version signed; one that doesn't is tampering, the alarm
//   and the hold, and that chain's pass starts again. A place whose pass began more than
//   7 days ago isn't gone on from: the pass starts again. A step that fails leaves a place
//   at the start, so the next round reads the chain whole. A chain whose read doesn't come
//   back is tried first next run, ahead of the round's order.
//   A chain not passed for 7 days is `audit.full_pass_overdue`, judged after the run's
//   steps: from its last pass's start, or for one never passed, from when it was first
//   owed one (its first place line, written when it is first seen anchored). Where the
//   environment sleeps (staging), the 7 days count from this process's start at the
//   earliest, so a woken process raises nothing for the time it slept; in production a
//   restart never moves them.
//
// A chain found failing is the integrity alarm and its hold, as any check's. A read
// that doesn't come back is said, and that organisation waits for next run while the
// others go on: one failing organisation never holds up another. Only the run's end
// stops the rotation. Every read holds one connection, within the lanes'.
import { createHash } from 'node:crypto';

import type { AuditTrail } from '@agentx/core/modules/audit';
import { type Clock, DAY_MS } from '@agentx/core/shared-kernel';
import {
  type Anchor,
  type AnchorStore,
  type Chain,
  CHAIN_START,
  type LastKnown,
  type ChainProblem,
  type ChainReport,
  type ChainStep,
  type CheckedPoint,
  OLD_EDIT_DAYS,
  type PassRecord,
  type Progress,
  shardOf,
  signPass,
  signProgress,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { Stopped } from './background.ts';

/** The rotation's reads of one organisation's chain, each in a transaction of its own under its wall. */
export interface RotatedChecks {
  /** Whether every event numbered after `after` and at most `upTo` is stored (countStep). */
  count(orgId: string, after: bigint, upTo: bigint): Promise<ChainProblem | undefined>;
  /** The last `most` events up to `target` walked (walkLast). */
  walkLast(orgId: string, target: CheckedPoint, most: number): Promise<ChainStep>;
  /** One step of a full pass (passStep). */
  passStep(orgId: string, cursor: CheckedPoint, target: CheckedPoint, most: number): Promise<ChainStep>;
}

/** The rotation's reads from the audit trail's own, each in its own transaction under the organisation's wall. */
export const rotatedChecksOf = (
  trail: Pick<AuditTrail, 'countStep' | 'walkLast' | 'passStep'>,
  database: Parameters<AuditTrail['countStep']>[0],
): RotatedChecks => ({
  count: (orgId, after, upTo) => trail.countStep(database, orgId, after, upTo),
  walkLast: (orgId, target, most) => trail.walkLast(database, orgId, target, most),
  passStep: (orgId, cursor, target, most) => trail.passStep(database, orgId, cursor, target, most),
});

/** How often the platform's chain is read whole: decision 1's day for an old event deleted, and well inside 3's 7 days for one edited. */
const PLATFORM_WHOLE_EVERY_MS = DAY_MS;

/**
 * The platform chain's check each run (4D2e E8, "Each run" step 2): whole at a process's first run and once a day after,
 * as no rotation reads it, and from its anchor in between. A whole check counts only once it has passed, dated when it
 * began; one that fails, or a chain not yet anchored, is read whole again next run.
 */
export function platformChainCheck({
  fromAnchor,
  whole,
  clock,
}: {
  readonly fromAnchor: (from: CheckedPoint) => Promise<ChainReport>;
  readonly whole: (anchor: CheckedPoint | undefined) => Promise<ChainReport>;
  readonly clock: Clock;
}): (anchor: CheckedPoint | undefined) => Promise<ChainReport> {
  let wholeAt: number | undefined;
  return async (anchor) => {
    const now = clock.now().getTime();
    if (anchor !== undefined && wholeAt !== undefined && now - wholeAt < PLATFORM_WHOLE_EVERY_MS) {
      return fromAnchor(anchor);
    }
    const report = await whole(anchor);
    if (report.ok) wholeAt = now;
    return report;
  };
}

/**
 * The organisations the platform chain records as created (4D2e E8, "Each run" step 2), for the check to hold the
 * directory's list to: read only past the last event read, and only as far as the chain's own check has reached (its
 * anchor), so a row past it is neither believed nor moves the place on. All of them so far each run; a process's first
 * read takes every one, then only those new. None before the platform chain is anchored. Kept in memory, an ID each.
 */
export function recordedSince({
  since,
  checkedTo,
}: {
  readonly since: (
    afterSeq: bigint,
    upTo: bigint,
  ) => Promise<{ readonly orgIds: readonly string[]; readonly seq: bigint }>;
  readonly checkedTo: () => bigint | undefined;
}): () => Promise<readonly string[]> {
  let readTo = 0n;
  const recorded = new Set<string>();
  return async () => {
    const upTo = checkedTo();
    // Only a rebase moves the platform chain's anchor back (E11): the chain begun again, read again from its start.
    if (upTo !== undefined && upTo < readTo) readTo = 0n;
    if (upTo !== undefined && upTo > readTo) {
      const { orgIds } = await since(readTo, upTo);
      for (const orgId of orgIds) recorded.add(orgId);
      // Every row up to it has been read, whether or not one recorded an organisation.
      readTo = upTo;
    }
    return [...recorded];
  };
}

/** Which of the rotation's reads found a chain failing, or didn't come back. */
export type RotationCheck = 'count' | 'walk' | 'pass';

/** The slots of a day: five minutes each. */
export const SLOTS = 288;
const SLOT_MS = DAY_MS / SLOTS;

/** How many of a chain's last events its day walks (decision 2b). */
const WALKED = 1000;

/** How many events one statement of a day's count counts. */
export const COUNTED_AT_ONCE = 1_000_000n;

/** How long a round of the full pass takes, whatever the runs' cadence: two rounds stay within 7 days. */
const PASS_ROUND_MS = 3 * DAY_MS;

/** The least time a run's share is sized for: the default interval, so a run soon after another still reads some. */
const LEAST_GAP_MS = 5 * 60_000;

/** How long a run's pass steps may take. */
export const PASS_WITHIN_MS = 150_000;

/** The most events one pass step reads, in one statement. */
const PASS_STEP = 2000n;

/** How long a chain may go without a finished pass. */
export const PASS_LATE_MS = OLD_EDIT_DAYS * DAY_MS;

/** How many IDs a late line names: the count is the whole of it. */
const NAMED = 5;

/** An organisation's five minutes of the day, from its ID: spread evenly, and the same in every process. */
export const slotOf = (orgId: string): number =>
  createHash('sha256').update(orgId.toLowerCase()).digest().readUInt32BE(0) % SLOTS;

/** The slots whose five minutes begin after `afterMs` and at or before `upToMs`: a whole day's at most. */
export function slotsBetween(afterMs: number, upToMs: number): ReadonlySet<number> {
  const slots = new Set<number>();
  for (let slot = Math.floor(afterMs / SLOT_MS) + 1; slot <= Math.floor(upToMs / SLOT_MS); slot += 1) {
    slots.add(slot % SLOTS);
    if (slots.size === SLOTS) break;
  }
  return slots;
}

/**
 * A run's share of a full pass, in events: the chains' lengths, times the time since the last run over a round, rounded up.
 * Five minutes' worth at least, a whole round's at most.
 */
export const passBudget = (total: bigint, sinceLastMs: number): bigint => {
  const gap = BigInt(Math.round(Math.min(Math.max(sinceLastMs, LEAST_GAP_MS), PASS_ROUND_MS)));
  const round = BigInt(PASS_ROUND_MS);
  return (total * gap + round - 1n) / round;
};

const smallest = (...values: readonly bigint[]): bigint =>
  values.reduce((least, value) => (value < least ? value : least));

export interface RotationOptions {
  readonly checks: RotatedChecks;
  readonly anchors: AnchorStore;
  readonly passes: PassRecord;
  readonly keys: KeyProvider;
  readonly clock: Clock;
  readonly logger: Logger;
  /** The store's epoch, which a pass line is signed for; none where no store keeps them. */
  readonly epoch: number | undefined;
  /** How long an organisation's day may wait once due before it is late, and how far back a first run looks at least. */
  readonly lateAfterMs: number;
  /** Where the last process left off: the newest file in the anchors' store, if one was read. */
  readonly lastRanAt?: () => Date | undefined;
  /** Whether this environment sleeps when unused (staging): then a pass's lateness counts from this process's start. */
  readonly sleeps: boolean;
  /** Runs one read within the check's deadline, its connection counted with the lanes': Stopped once `signal` aborts. */
  readonly bounded: <T>(work: () => Promise<T>, signal: AbortSignal) => Promise<T>;
  /** A chain found failing: the alarm and its hold. */
  readonly failed: (orgId: string, check: RotationCheck, problem: ChainProblem) => Promise<void>;
  /** A read that didn't come back, the run not stopped: the alarm where the database refused it, a warning otherwise. */
  readonly missed: (orgId: string, check: RotationCheck, error: unknown) => Promise<void>;
  /**
   * The anchors' log where it lets shards go (PL-65 PR3): a chain's shard is pinned for each step that reads its anchor
   * or keeps its lines, so it is never read as never anchored, nor its lines refused. None, where all are held.
   */
  readonly shards?: {
    holds(chain: Chain): boolean;
    pin(chain: Chain): Promise<(() => void) | undefined>;
    /** What is last known of a chain, held or let go, with no read: what the share, the order and lateness go by. */
    lastKnown(chain: Chain): LastKnown | undefined;
  };
}

export interface Rotation {
  /**
   * A run's days and pass steps for these organisations, until `signal` aborts (the run's time, or `stopping`, the process
   * stopping); its lines after. Never throws.
   */
  run(listed: readonly string[], signal: AbortSignal, stopping?: AbortSignal): Promise<void>;
}

/** An organisation's day: due since `dueAt`, counted so far up to `countedTo` of `target`, its anchor when it began. */
interface Day {
  readonly orgId: string;
  readonly dueAt: number;
  target?: Anchor;
  countedTo: bigint;
}

/** A chain's full pass under way: read to `cursor`, going to `target`, begun at `began`, owed since `owed` (ms). */
interface Passing {
  readonly cursor: CheckedPoint;
  readonly target: Anchor;
  readonly began: number;
  readonly owed: number;
}

/** A run's pass: whether it has begun a new round, and the chains it tried whose reads didn't come back. */
interface PassRun {
  roundBegun: boolean;
  readonly tried: Set<string>;
}

/** A read that didn't come back. */
const MISSED = Symbol('missed');

/** Why a run's pass stopped when its own 150 seconds ran out. */
const PASS_TIME_UP = Symbol('pass time up');

/** A chain found failing: its alarm raised, and nothing more of it this run. */
const FAILED = Symbol('failed');

const chainOf = (orgId: string) => ({ kind: 'organisation', orgId }) as const;

/** An organisation's chain's shard in the anchors' store (PL-65). */
const shardOfOrg = (orgId: string): number => shardOf(`organisation:${orgId}`);

export function createRotation({
  checks,
  anchors,
  passes,
  keys,
  clock,
  logger,
  epoch,
  lateAfterMs,
  lastRanAt = () => undefined,
  sleeps,
  bounded,
  failed,
  missed,
  shards,
}: RotationOptions): Rotation {
  const started = clock.now().getTime();
  const slots = new Map<string, number>();
  const days = new Map<string, Day>();
  let lookedUpTo: number | undefined;
  // The full pass: this round's order, how far along it, and the passes under way, each where it has got to.
  let order: readonly string[] = [];
  let next = 0;
  const underWay = new Map<string, Passing>();
  // Chains whose first read of a pass didn't come back: first next run, ahead of the round's order.
  const retryFirst = new Set<string>();
  // What the run did, for its line.
  let counted = 0n;
  let walked = 0;
  let passed = 0n;
  let finished = 0;
  // When the last run's pass began, so the next run's share covers the time since.
  let lastPassAt: number | undefined;
  // A share cut short by time, still owed: read on top of the next run's.
  let carried = 0n;

  /**
   * What is known of a chain, never reading a shard back for it (PR3): held, as held now; let go (`held` false), as the
   * log last knew it. Its anchored place, when its last pass began, and since when it has gone unpassed.
   */
  const knownOf = (orgId: string) => {
    const chain = chainOf(orgId);
    if (shards?.holds(chain) === false) {
      const known = shards.lastKnown(chain);
      return { held: false, seq: known?.seq, passedAt: known?.passedAt, passAt: known?.passedAt ?? known?.placeAt };
    }
    const passedAt = passes.lastPass(chain)?.at.getTime();
    const passAt = passedAt ?? passes.lastProgress(chain)?.at.getTime();
    return { held: true, seq: anchors.latest(chain)?.seq, passedAt, passAt };
  };

  /** `work` with the chain's shard pinned, read again first if it was let go; MISSED if it can't be (said by the log). */
  const pinned = async <T>(orgId: string, work: () => Promise<T>): Promise<T | typeof MISSED> => {
    if (shards === undefined) return work();
    const release = await shards.pin(chainOf(orgId));
    if (release === undefined) return MISSED;
    try {
      return await work();
    } finally {
      release();
    }
  };

  const slotFor = (orgId: string): number => {
    let slot = slots.get(orgId);
    if (slot === undefined) {
      slot = slotOf(orgId);
      slots.set(orgId, slot);
    }
    return slot;
  };

  /** The read, or MISSED where it didn't come back: said, unless the run ended it. */
  const read = async <T>(
    orgId: string,
    check: RotationCheck,
    work: () => Promise<T>,
    signal: AbortSignal,
  ): Promise<T | typeof MISSED> => {
    try {
      return await bounded(work, signal);
    } catch (error) {
      // Ended as the run or its pass time did, not for itself: nothing to say.
      if (!(error instanceof Stopped)) await missed(orgId, check, error);
      return MISSED;
    }
  };

  /** Where a process's first run looks back to: where the last left off, an hour at least and a day at most. */
  const firstLook = (now: number): number => {
    const left = lastRanAt()?.getTime() ?? now;
    // A day at most: slotsBetween holds no more than a day's slots.
    return Math.min(left, now - lateAfterMs);
  };

  /** Those whose five minutes came since the last run, added to the days waiting, each due from its five minutes. */
  const dueNow = (listed: readonly string[], now: number): void => {
    const due = slotsBetween(lookedUpTo ?? firstLook(now), now);
    lookedUpTo = now;
    if (due.size === 0) return;
    const current = Math.floor(now / SLOT_MS);
    for (const orgId of listed) {
      const slot = slotFor(orgId);
      if (days.has(orgId) || !due.has(slot)) continue;
      const dueAt = (current - ((current - slot) % SLOTS)) * SLOT_MS;
      days.set(orgId, { orgId, dueAt, countedTo: 0n });
    }
  };

  /** One organisation's day: the count in statements of a million, then the walk. Whether it ended, one way or the other. */
  const oneDay = async (day: Day, target: Anchor, signal: AbortSignal): Promise<boolean> => {
    const { orgId } = day;
    while (day.countedTo < target.seq) {
      if (signal.aborted) return false;
      const after = day.countedTo;
      const upTo = smallest(after + COUNTED_AT_ONCE, target.seq);
      const problem = await read(orgId, 'count', () => checks.count(orgId, after, upTo), signal);
      if (problem === MISSED) return false;
      if (problem !== undefined) {
        await failed(orgId, 'count', problem);
        return true;
      }
      day.countedTo = upTo;
      counted += upTo - after;
    }
    if (target.seq === 0n) return true;
    if (signal.aborted) return false;
    const most = Number(smallest(BigInt(WALKED), target.seq));
    const walk = await read(orgId, 'walk', () => checks.walkLast(orgId, target, most), signal);
    if (walk === MISSED) return false;
    if (walk.ok) walked += most;
    else await failed(orgId, 'walk', walk.problem);
    return true;
  };

  /**
   * Where shards are let go (PR3), the days grouped by shard, so each shard is read back once a run however many of its
   * days are due; the groups oldest first, by the longest-waiting day in each, so a shard late in number never waits
   * behind others run after run. A day missed keeps when it was due, and ages to the front.
   */
  const inShards = (queue: readonly Day[]): readonly Day[] => {
    const groups = new Map<number, Day[]>();
    for (const day of queue) {
      const shard = shardOfOrg(day.orgId);
      const group = groups.get(shard);
      if (group === undefined) groups.set(shard, [day]);
      else group.push(day);
    }
    // A fold, not Math.min(...): a spread of a very long group would overflow the stack.
    const oldest = (group: readonly Day[]): number =>
      group.reduce((least, day) => Math.min(least, day.dueAt), Number.POSITIVE_INFINITY);
    return [...groups.values()].toSorted((one, other) => oldest(one) - oldest(other)).flat();
  };

  /**
   * The days waiting, oldest first (by shard, oldest group first, where shards are let go), until the run ends. One whose
   * read fails goes to the back, where it was, and the rest go on.
   */
  const takeDays = async (listed: ReadonlySet<string>, signal: AbortSignal): Promise<void> => {
    const queue = [...days.values()];
    const ordered = shards === undefined ? queue : inShards(queue);
    for (const day of ordered) {
      if (signal.aborted) return;
      // Gone from the list (its own alarm).
      if (!listed.has(day.orgId)) {
        days.delete(day.orgId);
        continue;
      }
      const ended = await pinned(day.orgId, async () => {
        // Never anchored, so its first check reads it whole: nothing for the day.
        const target = day.target ?? anchors.latest(chainOf(day.orgId));
        if (target === undefined) return true;
        day.target = target;
        return oneDay(day, target, signal);
      });
      days.delete(day.orgId);
      // Not ended, or its shard not read again: kept, at the back.
      if (ended !== true) days.set(day.orgId, day);
    }
  };

  /** The listed, the chains passed longest ago first, those never passed before all. */
  const oldestFirst = (listed: readonly string[]): readonly string[] =>
    listed
      // A chain whose shard is let go by its last pass known: one passed lately doesn't jump the queue to be read back.
      .map((orgId) => ({ orgId, at: knownOf(orgId).passedAt ?? 0 }))
      .sort((one, other) => one.at - other.at)
      .map(({ orgId }) => orgId);

  /**
   * The next chain to pass: one whose read didn't come back first, then one under way, then by the round's order; a new
   * round at most once a run.
   */
  const nextChain = (listed: readonly string[], listedNow: ReadonlySet<string>, run: PassRun): string | undefined => {
    for (const orgId of [...retryFirst, ...underWay.keys()]) {
      if (listedNow.has(orgId) && !run.tried.has(orgId)) return orgId;
    }
    for (;;) {
      const orgId = order[next];
      if (orgId === undefined) {
        if (run.roundBegun) return undefined;
        run.roundBegun = true;
        order = oldestFirst(listed);
        next = 0;
        continue;
      }
      next += 1;
      // A chain whose shard is let go may well be anchored: its step pins it and reads it again.
      const anchored = shards?.holds(chainOf(orgId)) === false || anchors.latest(chainOf(orgId)) !== undefined;
      if (listedNow.has(orgId) && !run.tried.has(orgId) && anchored) return orgId;
    }
  };

  /** Since when a chain has owed a pass, for one starting at `now`: for one never passed, its first place line's. */
  const owedFor = (orgId: string, now: number): number =>
    passes.lastPass(chainOf(orgId)) === undefined ? (passes.lastProgress(chainOf(orgId))?.at.getTime() ?? now) : now;

  /** A place line: where a pass has got to, when it began and since when one was owed. */
  const placeLine = (orgId: string, cursor: CheckedPoint, began: number, owed: number): Progress =>
    signProgress(keys, chainOf(orgId), cursor, { at: new Date(owed), began: new Date(began) }, epoch);

  /** Starts the chain's next pass from its first event, the store told so: nothing goes on from a place before. */
  const startAgain = (orgId: string, target: Anchor): Passing => {
    const now = clock.now().getTime();
    const owed = owedFor(orgId, now);
    passes.keepProgress(placeLine(orgId, CHAIN_START, now, owed));
    return { cursor: CHAIN_START, target, began: now, owed };
  };

  /**
   * Where a chain's pass goes from: this process's place, or the store's from a process before, once the event there
   * still holds what was signed and its pass began within the last 7 days; otherwise its first event. An event that no
   * longer holds what was signed is tampering. MISSED where that read didn't come back.
   */
  const passFrom = async (
    orgId: string,
    signal: AbortSignal,
  ): Promise<Passing | typeof MISSED | typeof FAILED | undefined> => {
    const held = underWay.get(orgId);
    if (held !== undefined && !passes.rebasedAfter(chainOf(orgId), new Date(held.began))) return held;
    // A pass under way when a rebase moved the chain on (E11) read the chain as it was: it starts again.
    underWay.delete(orgId);
    const target = anchors.latest(chainOf(orgId));
    if (target === undefined) return undefined;
    const now = clock.now().getTime();
    const line = passes.lastProgress(chainOf(orgId));
    if (line === undefined || line.seq === 0n || line.seq > target.seq || now - line.began.getTime() > PASS_LATE_MS) {
      return { cursor: CHAIN_START, target, began: now, owed: owedFor(orgId, now) };
    }
    const still = await read(orgId, 'pass', () => checks.walkLast(orgId, line, 1), signal);
    if (still === MISSED) return MISSED;
    const { seq, hash, macKeyVersion } = line;
    if (still.ok)
      return { cursor: { seq, hash, macKeyVersion }, target, began: line.began.getTime(), owed: line.at.getTime() };
    // Nothing honest seals an event again: only a rebase moves a chain's anchors, and it clears the place too (E11).
    await failed(orgId, 'pass', still.problem);
    startAgain(orgId, target);
    return FAILED;
  };

  /** One step of a chain's pass, or its pass finished: what of the budget it took, MISSED or FAILED. */
  const passStep = async (orgId: string, passing: Passing, budget: bigint, signal: AbortSignal) => {
    const { cursor, target } = passing;
    if (cursor.seq < target.seq) {
      const most = smallest(PASS_STEP, budget, target.seq - cursor.seq);
      const step = await read(orgId, 'pass', () => checks.passStep(orgId, cursor, target, Number(most)), signal);
      if (step === MISSED) return MISSED;
      retryFirst.delete(orgId);
      if (!step.ok) {
        underWay.delete(orgId);
        await failed(orgId, 'pass', step.problem);
        // The next round reads it whole: nothing goes on from a place below what failed.
        startAgain(orgId, target);
        return FAILED;
      }
      const { seq, hash, macKeyVersion } = step;
      underWay.set(orgId, { ...passing, cursor: { seq, hash, macKeyVersion } });
      passed += seq - cursor.seq;
      if (seq < target.seq) return seq - cursor.seq;
    }
    underWay.delete(orgId);
    retryFirst.delete(orgId);
    // Dated when the pass began: every event to its target has been read since then.
    passes.keepPass(signPass(keys, chainOf(orgId), target, new Date(passing.began), epoch));
    finished += 1;
    return target.seq - cursor.seq;
  };

  /** The places the passes under way reached this run, signed into the store so a restart goes on from them. */
  const keepPlaces = async (moved: ReadonlySet<string>): Promise<void> => {
    for (const orgId of moved) {
      const place = underWay.get(orgId);
      if (place === undefined) continue;
      // Its shard held as the place is kept: one that can't be read again keeps its place in memory, for the next run.
      await pinned(orgId, () => {
        passes.keepProgress(placeLine(orgId, place.cursor, place.began, place.owed));
        return Promise.resolve();
      });
    }
  };

  /** Every listed chain anchored and never owed a pass yet: owed one from now, in the store, so no restart moves it. */
  const markOwed = async (listed: readonly string[], signal: AbortSignal): Promise<void> => {
    const now = clock.now().getTime();
    const owed = (orgId: string): void => {
      const chain = chainOf(orgId);
      if (anchors.latest(chain) === undefined || passes.lastPass(chain) !== undefined) return;
      if (passes.lastProgress(chain) === undefined) passes.keepProgress(placeLine(orgId, CHAIN_START, now, now));
    };
    // Those whose shard is let go, anchored and with no pass or place known: read back for it, each shard once.
    const away: string[] = [];
    for (const orgId of listed) {
      const known = knownOf(orgId);
      if (known.held) owed(orgId);
      else if (known.seq !== undefined && known.passAt === undefined) away.push(orgId);
    }
    const byShard = away.toSorted((one, other) => shardOfOrg(one) - shardOfOrg(other));
    for (const orgId of byShard) {
      if (signal.aborted) return;
      await pinned(orgId, () => {
        owed(orgId);
        return Promise.resolve();
      });
    }
  };

  /**
   * Steps through the chains until the share is read, the time is up or no chain is left: what of the share is left. A chain
   * found failing or whose read didn't come back is done for the run; the others go on.
   */
  const stepChains = async (
    listed: readonly string[],
    listedNow: ReadonlySet<string>,
    share: bigint,
    signal: AbortSignal,
  ) => {
    const run: PassRun = { roundBegun: false, tried: new Set() };
    const moved = new Set<string>();
    let left = share;
    try {
      while (left > 0n && !signal.aborted) {
        const orgId = nextChain(listed, listedNow, run);
        if (orgId === undefined) break;
        // Its shard pinned from reading where the pass goes from to keeping the pass: a shard that can't be read is MISSED.
        const stepped = await pinned(orgId, async () => {
          const from = await passFrom(orgId, signal);
          return {
            from,
            took: typeof from === 'object' ? await passStep(orgId, from, left, signal) : (from ?? MISSED),
          };
        });
        const { from, took } = stepped === MISSED ? { from: undefined, took: MISSED } : stepped;
        if (typeof took === 'bigint') {
          moved.add(orgId);
          left -= took;
          continue;
        }
        // Found failing (its one alarm and hold this run), or a read that didn't come back: done for this run.
        run.tried.add(orgId);
        // One not under way yet whose read didn't come back must not wait for the round to come round.
        if (took === MISSED && from !== undefined && !underWay.has(orgId)) retryFirst.add(orgId);
      }
    } finally {
      await keepPlaces(moved);
    }
    return left;
  };

  /** The run's share of the full pass, within its own 150 seconds and the run's time. */
  const takePass = async (
    listed: readonly string[],
    listedNow: ReadonlySet<string>,
    signal: AbortSignal,
    stopping: AbortSignal | undefined,
  ) => {
    // A chain whose shard is let go counts at its last known place, nothing read back: the share doesn't shrink as shards go.
    const total = listed.reduce((sum, orgId) => sum + (knownOf(orgId).seq ?? 0n), 0n);
    const at = clock.now().getTime();
    // A round's worth at most, carried part and all: past that a whole round is being asked for in one run anyway.
    const budget = smallest(passBudget(total, at - (lastPassAt ?? at)) + carried, total);
    lastPassAt = at;
    const slices = new AbortController();
    const end = (): void => {
      slices.abort();
    };
    const timer = setTimeout(() => {
      slices.abort(PASS_TIME_UP);
    }, PASS_WITHIN_MS);
    timer.unref();
    signal.addEventListener('abort', end, { once: true });
    if (signal.aborted) end();
    const began = performance.now();
    let left: bigint;
    try {
      left = await stepChains(listed, listedNow, budget, slices.signal);
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', end);
    }
    // Cut short by time, its own or the run's, with some unread: capacity, carried, said before it is late. Not as the
    // process stops: the next process starts afresh.
    carried = slices.signal.aborted && stopping?.aborted !== true ? left : 0n;
    if (carried > 0n) {
      logger.warn('audit.full_pass_behind', {
        by: slices.signal.reason === PASS_TIME_UP ? 'pass' : 'run',
        share: budget,
        left,
        withinMs: PASS_WITHIN_MS,
      });
    }
    return { budget, slicesMs: Math.round(performance.now() - began) };
  };

  /** What is late after the run's steps: days waiting too long, and chains not passed for too long. */
  const sayLate = (listed: readonly string[]): void => {
    const now = clock.now().getTime();
    const lateDays = [...days.values()].filter((day) => now - day.dueAt >= lateAfterMs).map((day) => day.orgId);
    if (lateDays.length > 0) {
      logger.error('audit.daily_check_overdue', {
        organisations: lateDays.length,
        firstFew: lateDays.slice(0, NAMED),
        waiting: days.size,
      });
    }
    const latePasses = listed.filter((orgId) => {
      // Never anchored: its first check reads it whole. One whose shard is let go is never taken for that: as last known.
      const { held, seq, passAt: last } = knownOf(orgId);
      if (held && seq === undefined) return false;
      // From the last pass's start, or since one was first owed; a restart never moves it, but where the environment sleeps.
      const since = sleeps ? Math.max(last ?? 0, started) : (last ?? started);
      return now - since >= PASS_LATE_MS;
    });
    if (latePasses.length > 0) {
      logger.error('audit.full_pass_overdue', {
        organisations: latePasses.length,
        firstFew: latePasses.slice(0, NAMED),
        withinDays: OLD_EDIT_DAYS,
      });
    }
  };

  return Object.freeze({
    async run(listed: readonly string[], signal: AbortSignal, stopping?: AbortSignal): Promise<void> {
      counted = 0n;
      walked = 0;
      passed = 0n;
      finished = 0;
      const listedNow = new Set(listed);
      const began = performance.now();
      try {
        dueNow(listed, clock.now().getTime());
        const due = days.size;
        await takeDays(listedNow, signal);
        const daysMs = Math.round(performance.now() - began);
        const { budget, slicesMs } = await takePass(listed, listedNow, signal, stopping);
        await markOwed(listed, signal);
        sayLate(listed);
        logger.info('audit.anchor_rotation_done', {
          due,
          left: days.size,
          counted,
          walked,
          daysMs,
          budget,
          passed,
          finished,
          slicesMs,
        });
      } catch (error) {
        // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
        logger.error('audit.anchor_check_crashed', { chain: 'organisation', check: 'rotation', err: error });
      }
    },
  });
}
