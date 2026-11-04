// How the integrity jobs that look in every organisation choose where to look each run (4D2e D11; Stage D's
// decision 2): an idle organisation is looked at less often, never left out. Three ways, each a `list` as a job
// takes it:
//
// - a rotation: each organisation has a slot of a cycle, from its ID's hash, so it is the same in every process and
//   needs nothing kept; a run takes those whose slot began since the last run's look. A cycle's slots are fixed to
//   UTC, not to when a process started, so runs that drift or a run cut short never move a slot.
// - a pass a UTC day: every organisation, once a day, at the first run after the day begins (a job may say the day
//   starts later, past midnight).
// - and `withWholePasses` (org-work.ts): a job's marks each run, every organisation every few runs.
//
// Each of them lists every organisation at a process's first run: what the last process had done is not known, so
// nothing it may have left owed waits past its bound. A restart, a wake from sleep or a new leader of the jobs only
// ever makes a pass come sooner.
//
// And what a run listed and didn't finish (it failed, was stopped, or had more to do than its share) stays owed, from
// memory, first next run (`owedPasses`): a failure waits a run, not a cycle. A restart loses that, and its first run
// lists every organisation anyway.
import { createHash } from 'node:crypto';

import { type Clock, systemClock } from '@agentx/core/shared-kernel';

/** A job's organisations for a run, as its `list` takes them. */
type OrgList = () => Promise<readonly string[]>;

/** The organisations a run should visit, and what the job says it finished. */
export interface OwedPasses {
  /** Those still owed from runs before, first, then those `source` names now. */
  readonly list: OrgList;
  /** One the job finished: owed no more until `source` names it again. */
  done(orgId: string): void;
}

/**
 * Every organisation `source` names stays owed until the job says it is done: one not finished is listed again next
 * run, ahead of the new. Never more than the organisations `source` has named, each once.
 */
export function owedPasses(source: OrgList): OwedPasses {
  const owed = new Set<string>();
  return {
    list: async () => {
      for (const orgId of await source()) owed.add(orgId);
      return [...owed];
    },
    done: (orgId) => {
      owed.delete(orgId);
    },
  };
}

/** An organisation's slot of `slots`, from its ID's hash: spread evenly, and the same in every process. */
export const slotOf = (orgId: string, slots: number): number =>
  createHash('sha256').update(orgId.toLowerCase()).digest().readUInt32BE(0) % slots;

/** The slots of `slots`, each `slotMs` long from the epoch, that began after `afterMs` and at or before `upToMs`. */
export function slotsBetween(afterMs: number, upToMs: number, slots: number, slotMs: number): ReadonlySet<number> {
  const began = new Set<number>();
  // A whole cycle at most: past it, every slot has begun.
  for (let at = Math.floor(afterMs / slotMs) + 1; at <= Math.floor(upToMs / slotMs) && began.size < slots; at += 1) {
    began.add(at % slots);
  }
  return began;
}

/**
 * Every organisation `all` lists at the first run; after, those whose slot of `slots`, each `slotMs` long, began
 * since the last run. So each is listed once a cycle (`slots` × `slotMs`), at the first run after its slot begins:
 * at most a cycle and the time between two runs apart.
 */
export function rotation({
  all,
  slots,
  slotMs,
  clock = systemClock,
}: {
  readonly all: OrgList;
  readonly slots: number;
  readonly slotMs: number;
  /** The job's own. */
  readonly clock?: Clock;
}): OrgList {
  let lookedUpTo: number | undefined;
  return async () => {
    const now = clock.now().getTime();
    const listed = await all();
    const from = lookedUpTo;
    // Only once listed: a run whose list failed looks again from the same place.
    lookedUpTo = now;
    if (from === undefined) return listed;
    const began = slotsBetween(from, now, slots, slotMs);
    return listed.filter((orgId) => began.has(slotOf(orgId, slots)));
  };
}

/** The UTC day of `ms`. */
const dayOf = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/**
 * Every organisation `all` lists, at the first run and at the first run of each UTC day after; none otherwise, and
 * then nothing is read. A day may start `startsAfterMs` past midnight (the activity seal's, once yesterday can be
 * sealed).
 */
export function eachDay({
  all,
  startsAfterMs = 0,
  clock = systemClock,
}: {
  readonly all: OrgList;
  readonly startsAfterMs?: number;
  /** The job's own. */
  readonly clock?: Clock;
}): OrgList {
  let passed: string | undefined;
  return async () => {
    const day = dayOf(clock.now().getTime() - startsAfterMs);
    if (day === passed) return [];
    const listed = await all();
    // Only once listed: a run whose list failed tries the day's pass again.
    passed = day;
    return listed;
  };
}
