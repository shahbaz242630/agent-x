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
//   looks back as far as an organisation may wait (`lateAfterMs`), so a restart loses
//   none of a short outage's. Those a run's time cut off wait, first next run, and
//   any still waiting past that same limit are `audit.daily_check_overdue`.
// - The full pass (decision 3): every chain read from its first event to its anchor
//   as it stood when the pass reached it, the chains passed longest ago first. A
//   run's share is the sum of every chain's length over 1,728 runs (six days at five
//   minutes), at most 150 seconds of it, 2,000 events a step.
//   Each chain's pass finished is a signed line in the store, so a restart goes on
//   with the oldest; the place reached within a chain is memory alone. A chain not
//   passed for 7 days is `audit.full_pass_overdue`, judged after the run's steps and
//   counted from this process's start at the earliest, so a woken process raises
//   nothing for the time it slept.
//
// A chain found failing is the integrity alarm and its hold, as any check's. A read
// that doesn't come back ends the rotation for the run, to go on next run: one slow call
// a run, never one an organisation. Every read holds one connection, within the lanes'.
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
  signPass,
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

/** The runs a full pass is spread over: six days at the default five minutes. */
const PASS_RUNS = 1728n;

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
  /** How long an organisation's day may wait once due before it is late, and how far back a first run looks. */
  readonly lateAfterMs: number;
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

/** A chain's full pass under way: read to `cursor`, going to `target`. */
interface Passing {
  readonly orgId: string;
  readonly cursor: CheckedPoint;
  readonly target: Anchor;
}

/** A read that didn't come back: its part of the run ends. */
const MISSED = Symbol('missed');

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
  bounded,
  failed,
  missed,
}: RotationOptions): Rotation {
  const started = clock.now().getTime();
  const slots = new Map<string, number>();
  const days = new Map<string, Day>();
  let lookedUpTo: number | undefined;
  // The full pass: this round's order, how far along it, and the chain under way.
  let order: readonly string[] = [];
  let next = 0;
  let passing: Passing | undefined;
  // What the run did, for its line.
  let counted = 0n;
  let walked = 0;
  let passed = 0n;
  let finished = 0;
  let missedOne = false;

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
      if (!(error instanceof Stopped)) {
        missedOne = true;
        await missed(orgId, check, error);
      }
      return MISSED;
    }
  };

  /** Those whose five minutes came since the last run, added to the days waiting. */
  const dueNow = (listed: readonly string[], now: number): void => {
    const due = slotsBetween(lookedUpTo ?? now - lateAfterMs, now);
    lookedUpTo = now;
    if (due.size === 0) return;
    for (const orgId of listed) {
      if (!days.has(orgId) && due.has(slotFor(orgId))) days.set(orgId, { orgId, dueAt: now, countedTo: 0n });
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

  /** The days waiting, oldest first, until the run ends or a read doesn't come back. */
  const takeDays = async (listed: ReadonlySet<string>, signal: AbortSignal): Promise<void> => {
    for (const day of days.values()) {
      if (signal.aborted) return;
      // Gone from the list (its own alarm), or never anchored, so its first check reads it whole.
      const target = day.target ?? anchors.latest(chainOf(day.orgId));
      if (!listed.has(day.orgId) || target === undefined) {
        days.delete(day.orgId);
        continue;
      }
      day.target = target;
      if (!(await oneDay(day, target, signal))) return;
      days.delete(day.orgId);
    }
  };

  /** The listed, the chains passed longest ago first, those never passed before all. */
  const oldestFirst = (listed: readonly string[]): readonly string[] =>
    listed
      .map((orgId) => ({ orgId, at: passes.lastPass(chainOf(orgId))?.at.getTime() ?? 0 }))
      .sort((one, other) => one.at - other.at)
      .map(({ orgId }) => orgId);

  /** The next chain to pass, from its first event to its anchor now; a new round at most once a run. */
  const nextPassing = (listed: readonly string[], listedNow: ReadonlySet<string>, round: { begun: boolean }) => {
    for (;;) {
      const orgId = order[next];
      if (orgId === undefined) {
        if (round.begun) return undefined;
        round.begun = true;
        order = oldestFirst(listed);
        next = 0;
        continue;
      }
      next += 1;
      const target = listedNow.has(orgId) ? anchors.latest(chainOf(orgId)) : undefined;
      if (target !== undefined) return { orgId, cursor: CHAIN_START, target };
    }
  };

  /** One step of the chain under way, or its pass finished: what of the budget it took, or MISSED. */
  const passStep = async ({ orgId, cursor, target }: Passing, budget: bigint, signal: AbortSignal) => {
    if (cursor.seq < target.seq) {
      const most = smallest(PASS_STEP, budget, target.seq - cursor.seq);
      const step = await read(orgId, 'pass', () => checks.passStep(orgId, cursor, target, Number(most)), signal);
      if (step === MISSED) return MISSED;
      if (!step.ok) {
        passing = undefined;
        await failed(orgId, 'pass', step.problem);
        return 0n;
      }
      const { seq, hash, macKeyVersion } = step;
      passing = { orgId, cursor: { seq, hash, macKeyVersion }, target };
      passed += seq - cursor.seq;
      if (seq < target.seq) return seq - cursor.seq;
    }
    passing = undefined;
    passes.keepPass(signPass(keys, chainOf(orgId), target, clock.now(), epoch));
    finished += 1;
    return target.seq - cursor.seq;
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
    const round = { begun: false };
    try {
      let left = budget;
      while (left > 0n && !slices.signal.aborted) {
        if (passing !== undefined && !listedNow.has(passing.orgId)) passing = undefined;
        passing ??= nextPassing(listed, listedNow, round);
        if (passing === undefined) break;
        const took = await passStep(passing, left, slices.signal);
        if (took === MISSED) break;
        left -= took;
      }
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', end);
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
      return now - Math.max(passes.lastPass(chain)?.at.getTime() ?? 0, started) >= PASS_LATE_MS;
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
      missedOne = false;
      const listedNow = new Set(listed);
      const began = performance.now();
      try {
        dueNow(listed, clock.now().getTime());
        const due = days.size;
        await takeDays(listedNow, signal);
        const daysMs = Math.round(performance.now() - began);
        const { budget, slicesMs } = missedOne
          ? { budget: 0n, slicesMs: 0 }
          : await takePass(listed, listedNow, signal);
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
