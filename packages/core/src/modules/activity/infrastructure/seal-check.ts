// Checking a page of an activity log's daily seals (Phase 3 L6; 6E1a, CO8b):
// one rule for every reader that holds a log to its seals, so none can drift
// from the others. An organisation's seal check and the person log's
// (apps/api activity-seal-check.ts, person-seal-check.ts) and the operator's
// export of one person's log for a case (person-activity-export.ts) each read
// a page of seals, newest first, and hold it here.
import { type DayDigest, nextDay, sealHolds } from './activity-seal.ts';

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
