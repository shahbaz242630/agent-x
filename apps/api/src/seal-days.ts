// What the activity logs' daily seals share (Phase 3 L6; 6E1a): an
// organisation's log sealed on its own chain (activity-seal.ts) and the person
// log on the platform chain (person-seal.ts) take the same steps, each on its
// own chain, lock and log lines:
//
// - A day is digested in batches, then recorded in one transaction under its
//   seal's lock (ADR-006 §6, before the chain head's): the newest seal read
//   again (another server may have sealed the day), the day counted again with
//   its last ID, and the event recorded only when both still stand; a day that
//   moved is left for the next run, an error. A day holding a row written past
//   the app (`misdated`) is never sealed: its alarm raised instead.
// - A run seals the days from its first, in order, each only once closed past
//   its grace, at most MOST_DAYS_A_RUN, stopping at the first not sealed.
import { type DayDigest, nextDay, sealable, sealHolds } from '@agentx/core/modules/activity';
import type { Clock } from '@agentx/core/shared-kernel';
import type { Logger, ProblemEvent } from '@agentx/platform/observability';

/** The most days one run seals a log, so one asleep for long doesn't hold up the rest. */
const MOST_DAYS_A_RUN = 31;

/** One log's seal: how it is digested, locked, read, counted and recorded, and what it logs. */
export interface DaySealing<Held> {
  readonly digest: (day: string) => Promise<DayDigest>;
  /** A day holding a row written past the app: its alarm raised (and, for an organisation, its hold). */
  readonly misdated: (day: string) => Promise<void>;
  /** The recording transaction, its seal's lock taken first. */
  readonly locked: <T>(work: (held: Held) => Promise<T>) => Promise<T>;
  /** The newest sealed day (`day` null for none), or `tampered`, its alarm raised already. */
  readonly newest: (held: Held) => Promise<{ readonly day: string | null } | 'tampered'>;
  readonly count: (held: Held, day: string) => Promise<{ readonly requests: number; readonly idTo: string | null }>;
  readonly record: (held: Held, details: Readonly<Record<string, string | number | null>>) => Promise<void>;
  /** The seal's form, recorded with it. */
  readonly form: number;
  readonly log: Logger;
  /** Its lines: a day that moved (an error), and a day sealed. */
  readonly lines: { readonly moved: ProblemEvent; readonly sealed: `${string}.${string}` };
}

/** Seals `day` if nothing moved meanwhile: whether it was sealed (or found sealed already). */
export async function sealDay<Held>(sealing: DaySealing<Held>, day: string): Promise<boolean> {
  const digest = await sealing.digest(day);
  if (digest.misdated !== null) {
    await sealing.misdated(day);
    return false;
  }
  return sealing.locked(async (held) => {
    const newest = await sealing.newest(held);
    if (newest === 'tampered') return false;
    // Sealed by another server meanwhile.
    if (newest.day !== null && newest.day >= day) return true;
    const now = await sealing.count(held, day);
    if (now.requests !== digest.requests || now.idTo !== digest.idTo) {
      sealing.log.error(sealing.lines.moved, { day, digested: digest.requests, counted: now.requests });
      return false;
    }
    await sealing.record(held, {
      day,
      requests: digest.requests,
      digest: digest.digest,
      idFrom: digest.idFrom,
      idTo: digest.idTo,
      form: sealing.form,
    });
    sealing.log.info(sealing.lines.sealed, { day, requests: digest.requests });
    return true;
  });
}

/**
 * Seals the closed days from `first` (undefined: a log with no rows yet), oldest first, up to MOST_DAYS_A_RUN, each
 * by `seal`: whether the log is finished, every closed day sealed.
 */
export async function sealDaysFrom(
  first: string | undefined,
  seal: (day: string) => Promise<boolean>,
  clock: Clock,
  signal: AbortSignal | undefined,
): Promise<boolean> {
  let day = first;
  for (let sealed = 0; day !== undefined && sealed < MOST_DAYS_A_RUN; sealed += 1) {
    if (signal?.aborted === true) return false;
    if (!sealable(day, clock.now())) return true;
    if (!(await seal(day))) return false;
    day = nextDay(day);
  }
  return day === undefined;
}

/** Why a seal doesn't hold: its day's digest, a row in it written past the app (F1, G3), a seal missing before it, or a row written before the first seal. */
export type SealBroken = 'digest' | 'misdated' | 'gap' | 'before';

/**
 * Checks a page of a log's seals, newest first (each its details): each seal's day the one before the next newer
 * seal's, its day digested again and held to it; and, on a page that reaches the oldest seal, no row written before
 * its day. Why the first that doesn't hold doesn't, or undefined. An organisation's check and the person log's alike.
 */
export async function brokenSealIn(
  seals: readonly Readonly<Record<string, unknown>>[],
  oldestReached: boolean,
  {
    digest,
    form,
    writtenBefore,
  }: {
    readonly digest: (day: string) => Promise<DayDigest>;
    readonly form: number;
    readonly writtenBefore: (day: string) => Promise<boolean>;
  },
): Promise<{ readonly day: string; readonly why: SealBroken } | undefined> {
  let newerDay: string | undefined;
  for (const details of seals) {
    const { day } = details;
    if (typeof day !== 'string') return { day: 'unnamed', why: 'gap' };
    if (newerDay !== undefined && nextDay(day) !== newerDay) return { day, why: 'gap' };
    const digested = await digest(day);
    if (!sealHolds(digested, details, form)) return { day, why: 'digest' };
    if (digested.misdated !== null) return { day, why: 'misdated' };
    newerDay = day;
  }
  if (oldestReached && newerDay !== undefined && (await writtenBefore(newerDay)))
    return { day: newerDay, why: 'before' };
  return undefined;
}
