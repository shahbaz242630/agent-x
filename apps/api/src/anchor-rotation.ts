// The anchor check's rotation (4D2e E7): what a check from the anchor can't see, an
// event below the anchor deleted or edited, found on a schedule rather than by
// reading every chain whole each run. Until E8 switches the whole reads off, this
// runs beside them and changes no guarantee: it is here to be right, and measured.
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
//   run's share is the sum of every chain's length over 864 runs (three days at five
//   minutes), at most 150 seconds of it, 2,000 events a step. Three, not six: a pass is
//   dated when it began, so a chain's lateness is the time between two passes' starts
//   and the second's own length, two rounds at worst, and that must stay within 7 days.
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
  CHAIN_START,
  type ChainProblem,
  type ChainStep,
  type CheckedPoint,
  OLD_EDIT_DAYS,
  type PassRecord,
  type Progress,
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

/** Which of the rotation's reads found a chain failing, or didn't come back. */
export type RotationCheck = 'count' | 'walk' | 'pass';

/** The slots of a day: five minutes each. */
export const SLOTS = 288;
const SLOT_MS = DAY_MS / SLOTS;

/** How many of a chain's last events its day walks (decision 2b). */
const WALKED = 1000;

/** How many events one statement of a day's count counts. */
export const COUNTED_AT_ONCE = 1_000_000n;

/** The runs a full pass is spread over: three days at the default five minutes, so two rounds stay within 7 days. */
const PASS_RUNS = 864n;

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

/** A run's share of a full pass, in events: the sum of the chains' lengths over its runs, rounded up. */
export const passBudget = (total: bigint): bigint => (total + PASS_RUNS - 1n) / PASS_RUNS;

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
}

export interface Rotation {
  /** A run's days and pass steps for these organisations, until `signal` aborts; its lines after. Never throws. */
  run(listed: readonly string[], signal: AbortSignal): Promise<void>;
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

/** A chain found failing: its alarm raised, and nothing more of it this run. */
const FAILED = Symbol('failed');

const chainOf = (orgId: string) => ({ kind: 'organisation', orgId }) as const;

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

  /** The days waiting, oldest first, until the run ends. One whose read fails goes to the back, where it was, and the rest go on. */
  const takeDays = async (listed: ReadonlySet<string>, signal: AbortSignal): Promise<void> => {
    for (const day of [...days.values()]) {
      if (signal.aborted) return;
      // Gone from the list (its own alarm), or never anchored, so its first check reads it whole.
      const target = day.target ?? anchors.latest(chainOf(day.orgId));
      if (!listed.has(day.orgId) || target === undefined) {
        days.delete(day.orgId);
        continue;
      }
      day.target = target;
      const ended = await oneDay(day, target, signal);
      days.delete(day.orgId);
      if (!ended) days.set(day.orgId, day);
    }
  };

  /** The listed, the chains passed longest ago first, those never passed before all. */
  const oldestFirst = (listed: readonly string[]): readonly string[] =>
    listed
      .map((orgId) => ({ orgId, at: passes.lastPass(chainOf(orgId))?.at.getTime() ?? 0 }))
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
      if (listedNow.has(orgId) && !run.tried.has(orgId) && anchors.latest(chainOf(orgId)) !== undefined) return orgId;
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
    if (held !== undefined) return held;
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
    retryFirst.delete(orgId);
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
  const keepPlaces = (moved: ReadonlySet<string>): void => {
    for (const orgId of moved) {
      const place = underWay.get(orgId);
      if (place !== undefined) passes.keepProgress(placeLine(orgId, place.cursor, place.began, place.owed));
    }
  };

  /** Every listed chain anchored and never owed a pass yet: owed one from now, in the store, so no restart moves it. */
  const markOwed = (listed: readonly string[]): void => {
    const now = clock.now().getTime();
    for (const orgId of listed) {
      const chain = chainOf(orgId);
      if (anchors.latest(chain) === undefined || passes.lastPass(chain) !== undefined) continue;
      if (passes.lastProgress(chain) === undefined) passes.keepProgress(placeLine(orgId, CHAIN_START, now, now));
    }
  };

  /** The run's share of the full pass, within its own time and the run's. */
  const takePass = async (listed: readonly string[], listedNow: ReadonlySet<string>, signal: AbortSignal) => {
    const total = listed.reduce((sum, orgId) => sum + (anchors.latest(chainOf(orgId))?.seq ?? 0n), 0n);
    const budget = passBudget(total);
    const slices = new AbortController();
    const end = (): void => {
      slices.abort();
    };
    const timer = setTimeout(end, PASS_WITHIN_MS);
    timer.unref();
    signal.addEventListener('abort', end, { once: true });
    if (signal.aborted) end();
    const began = performance.now();
    const run: PassRun = { roundBegun: false, tried: new Set() };
    const moved = new Set<string>();
    try {
      let left = budget;
      while (left > 0n && !slices.signal.aborted) {
        const orgId = nextChain(listed, listedNow, run);
        if (orgId === undefined) break;
        const from = await passFrom(orgId, slices.signal);
        const took = typeof from === 'object' ? await passStep(orgId, from, left, slices.signal) : (from ?? MISSED);
        // Found failing: its one alarm and hold this run, and its pass starts again next round.
        if (took === FAILED) {
          run.tried.add(orgId);
          continue;
        }
        // A read that didn't come back: this chain waits for next run, its place kept, and the rest go on.
        if (took === MISSED) {
          run.tried.add(orgId);
          // Not under way yet, so not first next run by that: it must not wait for the round to come round.
          if (from !== undefined && !underWay.has(orgId)) retryFirst.add(orgId);
          continue;
        }
        moved.add(orgId);
        left -= took;
      }
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', end);
      keepPlaces(moved);
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
      const chain = chainOf(orgId);
      if (anchors.latest(chain) === undefined) return false;
      // From the last pass's start, or since one was first owed; a restart never moves it, but where the environment sleeps.
      const last = (passes.lastPass(chain)?.at ?? passes.lastProgress(chain)?.at)?.getTime();
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
    async run(listed: readonly string[], signal: AbortSignal): Promise<void> {
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
        const { budget, slicesMs } = await takePass(listed, listedNow, signal);
        markOwed(listed);
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
