// The security events' tally, every 5 minutes (S206, faster detection;
// Threat-Model R-15): the rows of yesterday and today counted, for the global
// table and for every organisation, so rows the database's owner deletes are
// found within a run, not at the day's seal (security-seal.ts).
//
// Each run reads the global table's count of each day, then every listed
// organisation's, a page of organisations a trip (readEachTenant: each read
// under its own wall, one index range of its rows), and holds each count to
// the one this process read of that day before:
//
// - Fewer rows than before (a day gone whole counts as none): some were
//   deleted past the app, which never deletes a row this young (only the
//   retention sweep, days old). The integrity alarm (`audit.integrity_failed`,
//   check `security_event`, reason `count_fell`), and the line below at once.
//   The count before is this process's memory, never the database's, so the
//   owner can't move it.
// - The tally line (`security_seal.tally`: its day, rows and last ID), off the
//   database: when a day is first counted, when it fell, and when it grew, at
//   most once an hour a day, so the log stays small (each row is a minute's
//   count of one kind, so a busy organisation grows every run). The
//   environment's alert holds each new line, and each seal, to every tally of
//   its day that read no further (its last ID not past this one's): so a fall
//   is found even across a restart, which forgets the memory, within the
//   alert's own few minutes, and an older read logged within a minute of a
//   newer one is no fall.
//
// And once an hour, every retained day of each log counted again (S206,
// faster detection): its rows by their ID's day, dated or not, one statement a
// log, each day a count over its range of the ID's index (dayCountsRead), from the first day
// the seal still checks (firstCheckableDay, well inside the retention, so the
// sweep never makes a day fall). A day before yesterday with fewer rows than
// this process counted of it an hour before is the same alarm, `count_fell`:
// a sealed day's rows deleted are found within the hour, beside the seal
// check's own visit (each organisation every 6 hours). No line is logged for
// those days: the alarm is enough, and a restart's first count would log them
// all at once.
//
// One organisation slow or failing holds up only its own page's trip, each
// statement within its answer's limit; a page that fails is read again one
// organisation at a time (readEachTenant), and one that still fails says so
// and keeps its counts from before. A run never throws.
import {
  type DayTally,
  type SecurityEventsTables,
  type SecurityLog,
  dayCountsRead,
  firstCheckableDay,
  securityLogAlarm,
  talliesOf,
  tallyRead,
} from '@agentx/core/modules/security-events';
import { nextDay } from '@agentx/core/modules/activity';
import { type Clock, DAY_MS, UUID } from '@agentx/core/shared-kernel';
import { type Database, JOB_ANSWER_WITHIN_MS, limitedTransaction, readEachTenant } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

/** How often a run counts, once the last run has ended. */
export const SECURITY_TALLY_EVERY_MS = 5 * 60_000;

/** How many organisations one trip counts. */
const PAGE = 500;

/** A day that only grew is logged again at most this often. */
const LOG_AGAIN_MS = 60 * 60_000;

/** How often every retained day is counted. */
const WHOLE_EVERY_MS = 60 * 60_000;

/** A day's count as this process last read it, and as it last logged it. */
interface Seen {
  readonly rows: number;
  readonly loggedRows: number;
  readonly loggedAt: number;
}

export interface SecurityTally {
  /** Counts the global table's days, then the listed organisations', until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** The UTC day of `ms`. */
const dayOf = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/** Every day from `first` to `last`, in order. */
function daysBetween(first: string, last: string): readonly string[] {
  const days: string[] = [];
  for (let day = first; day <= last; day = nextDay(day)) days.push(day);
  return days;
}

/** A day's count held to the one read before: whether it fell, whether its line is due, and what is kept of it now. */
function judged(was: Seen | undefined, rows: number, now: number) {
  const logged = { rows, loggedRows: rows, loggedAt: now };
  if (was === undefined) return { fell: false, due: true, kept: logged };
  const fell = rows < was.rows;
  const due = fell || (rows !== was.loggedRows && now - was.loggedAt >= LOG_AGAIN_MS);
  return { fell, due, kept: due ? logged : { ...was, rows } };
}

export function createSecurityTally({
  list,
  database,
  clock,
  logger,
  retentionDays,
  page = PAGE,
}: {
  /** Every organisation. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<SecurityEventsTables>;
  readonly clock: Clock;
  readonly logger: Logger;
  /** AGENTX_SECURITY_EVENT_RETENTION_DAYS: the hourly count reads from the first day still well inside it. */
  readonly retentionDays: number;
  /** PAGE, but for the tests. */
  readonly page?: number;
}): SecurityTally {
  /** Each log's days as last read, by the organisation's ID in lower case ('' for the global table). */
  const seen = new Map<string, ReadonlyMap<string, Seen>>();

  /** Holds the log's counts to those read before, from `from` on: the alarm for a fall, the line when due. */
  const judge = (log: SecurityLog, tallies: readonly DayTally[], from: string, now: number): void => {
    const chain = log === 'global' ? '' : log.orgId;
    const before = seen.get(chain) ?? new Map<string, Seen>();
    const counted = new Map(tallies.map((tally) => [tally.day, tally]));
    // A day read before with rows and none now: every one of them deleted.
    for (const day of before.keys())
      if (day >= from && !counted.has(day)) counted.set(day, { day, rows: 0, idTo: null });
    const lines = log === 'global' ? logger : logger.child({ orgId: chain });
    const after = new Map<string, Seen>();
    for (const { day, rows, idTo } of counted.values()) {
      const { fell, due, kept } = judged(before.get(day), rows, now);
      if (fell) securityLogAlarm(logger, log, 'count_fell', day);
      if (due) lines.info('security_seal.tally', { day, rows, idTo });
      if (rows > 0) after.set(day, kept);
    }
    seen.set(chain, after);
  };

  /** Each log's every retained day as the last hourly count read it, keyed as `seen`. */
  const whole = new Map<string, ReadonlyMap<string, number>>();
  let wholeAt: number | undefined;

  /** Holds the log's every retained day to the last hourly count: the alarm for a day before `older` that fell. */
  const judgeWhole = (log: SecurityLog, tallies: readonly DayTally[], from: string, older: string): void => {
    const chain = log === 'global' ? '' : log.orgId;
    const counted = new Map(tallies.map(({ day, rows }) => [day, rows]));
    // Yesterday and today are the five-minute tally's: their fall is its alarm already.
    for (const [day, was] of whole.get(chain) ?? []) {
      if (day >= from && day < older && (counted.get(day) ?? 0) < was) securityLogAlarm(logger, log, 'count_fell', day);
    }
    whole.set(chain, counted);
  };

  /**
   * The global table's days as `read` reads them, then every listed organisation's, a page a trip, each held by `hold`; one
   * whose read failed says so and keeps what was read of it before.
   */
  const countEvery = async (
    asked: readonly string[],
    read: (log: SecurityLog) => ReturnType<typeof tallyRead>,
    hold: (log: SecurityLog, tallies: readonly DayTally[]) => void,
    signal: AbortSignal | undefined,
  ): Promise<void> => {
    try {
      const { rows } = await limitedTransaction(database, (tx) => read('global').execute(tx));
      hold('global', talliesOf(rows));
    } catch (error) {
      logger.warn('security_tally.missed', { err: error });
    }
    for (let at = 0; at < asked.length && signal?.aborted !== true; at += page) {
      const items = asked.slice(at, at + page).map((orgId) => ({ orgId }));
      const reads = await readEachTenant(database, items, ({ orgId }) => read({ orgId }), {
        answeredWithinMs: JOB_ANSWER_WITHIN_MS,
      });
      for (const { item, read } of reads) {
        if ('failed' in read) logger.child({ orgId: item.orgId }).warn('security_tally.missed', { err: read.failed });
        else hold({ orgId: item.orgId }, talliesOf(read.rows));
      }
    }
  };

  return {
    async run(signal) {
      const now = clock.now().getTime();
      const from = dayOf(now - DAY_MS);
      try {
        const asked = [...new Set((await list()).filter((orgId) => UUID.test(orgId)).map((id) => id.toLowerCase()))];
        await countEvery(
          asked,
          (log) => tallyRead(log, from),
          (log, tallies) => {
            judge(log, tallies, from, now);
          },
          signal,
        );
        if (wholeAt !== undefined && now - wholeAt < WHOLE_EVERY_MS) return;
        wholeAt = now;
        const checkable = firstCheckableDay(new Date(now), retentionDays);
        await countEvery(
          asked,
          (log) => dayCountsRead(log, daysBetween(checkable, dayOf(now))),
          (log, tallies) => {
            judgeWhole(log, tallies, checkable, from);
          },
          signal,
        );
      } catch (error) {
        logger.error('security_tally.run_failed', { err: error });
      }
    },
  };
}
