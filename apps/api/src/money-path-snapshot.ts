// The money path's snapshot (GA4, PRD §9.3: approvals, unknown payments and
// money held, as counts): every 15 minutes, every organisation's counts read
// and added up into one `money_path.snapshot` line, which the workbook's tiles
// read (metrics.bicep). No table, right or role is added for it: each
// organisation is read under its own wall, a page of them a trip
// (readEachTenant, as the security tally reads them), one statement each
// (moneyPathRead). So a pass at 10,000 organisations is 20 trips.
//
// The line names no organisation: its totals across all of them, how many
// were counted, and how many could not be read. Where an organisation has a
// payment UNKNOWN or one under way past STUCK_AFTER_MS, its own counts are
// logged too (`money_path.organisation`, its ID alone, as every job's lines
// carry it), so the one to look at can be found; those are few, and a payment's
// own lines say the rest (`payment_check.still_unknown`).
//
// One organisation's read failing says so and leaves it out of that pass's
// totals (`missed` counts it); a pass stopped early (the API stopping, or the
// lease lost) still logs what it counted, marked incomplete. A run never throws.
import { v7Floor } from '@agentx/core/modules/activity';
import type { InstructionsTables } from '@agentx/core/modules/instructions';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import { type MoneyPath, moneyPathOf, moneyPathRead, type MoneyPathWindow } from '@agentx/core/modules/outcomes';
import { LONGEST_APPROVAL_WAIT, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import type { TransactionsTables } from '@agentx/core/modules/transactions';
import { type Clock, DAY_MS, HOUR_MS, UUID } from '@agentx/core/shared-kernel';
import { type Database, JOB_ANSWER_WITHIN_MS, readEachTenant } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

/** The tables a pass counts in. */
export type MoneyPathTables = SpendRequestsTables & TransactionsTables & InstructionsTables & LimitReservationsTables;

/** How often a pass runs, once the last has ended. */
export const MONEY_PATH_EVERY_MS = 15 * 60_000;

/** How many organisations one trip reads. */
const PAGE = 500;

/** A payment under way longer than this counts as stuck: far past the hand-off's 10 minutes to an answer. */
export const STUCK_AFTER_MS = HOUR_MS;

/** Approvals that ran out within this, up to the pass, are counted as expired. */
export const EXPIRED_WITHIN_MS = DAY_MS;

/** The times a pass at `now` reads every organisation at. */
export function windowAt(now: Date): MoneyPathWindow {
  const expiredSince = now.getTime() - EXPIRED_WITHIN_MS;
  return {
    now,
    expiredSince: new Date(expiredSince),
    // A request's wait ends at most the longest wait after it was made, and its ID is made before that: an hour spare.
    idFloor: v7Floor(expiredSince - LONGEST_APPROVAL_WAIT * HOUR_MS - HOUR_MS),
    stuckBefore: new Date(now.getTime() - STUCK_AFTER_MS),
  };
}

/** Money paths added up: the counts summed, the oldest UNKNOWN the older, the money held summed by currency. */
export function added(paths: readonly MoneyPath[]): MoneyPath {
  const held = new Map<string, { reservations: number; amountMinor: bigint }>();
  let oldestUnknownAt: Date | null = null;
  for (const path of paths) {
    if (path.oldestUnknownAt !== null && (oldestUnknownAt === null || path.oldestUnknownAt < oldestUnknownAt))
      oldestUnknownAt = path.oldestUnknownAt;
    for (const { currency, reservations, amountMinor } of path.held) {
      const sum = held.get(currency) ?? { reservations: 0, amountMinor: 0n };
      held.set(currency, {
        reservations: sum.reservations + reservations,
        amountMinor: sum.amountMinor + BigInt(amountMinor),
      });
    }
  }
  const total = (count: (path: MoneyPath) => number): number => paths.reduce((sum, path) => sum + count(path), 0);
  return {
    approvalsWaiting: total((path) => path.approvalsWaiting),
    approvalsExpired: total((path) => path.approvalsExpired),
    unknownPayments: total((path) => path.unknownPayments),
    oldestUnknownAt,
    stuckPayments: total((path) => path.stuckPayments),
    held: [...held]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([currency, sum]) => ({
        currency,
        reservations: sum.reservations,
        amountMinor: sum.amountMinor.toString(),
      })),
  };
}

/** A money path as its line logs it at `now`: the oldest UNKNOWN as its age in whole seconds. */
export const lineOf = (path: MoneyPath, now: Date) => ({
  approvalsWaiting: path.approvalsWaiting,
  approvalsExpiredLastDay: path.approvalsExpired,
  unknownPayments: path.unknownPayments,
  oldestUnknownSeconds:
    path.oldestUnknownAt === null
      ? null
      : Math.max(0, Math.floor((now.getTime() - path.oldestUnknownAt.getTime()) / 1000)),
  stuckPayments: path.stuckPayments,
  stuckAfterMinutes: STUCK_AFTER_MS / 60_000,
  held: path.held,
});

/** Whether an organisation's own counts are logged: a payment whose outcome isn't known, or one stuck under way. */
const worthNaming = (path: MoneyPath): boolean => path.unknownPayments > 0 || path.stuckPayments > 0;

export interface MoneyPathSnapshot {
  /** Reads every organisation's counts, until the signal is aborted, and logs their totals. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createMoneyPathSnapshot({
  list,
  database,
  clock,
  logger,
  page = PAGE,
}: {
  /** Every organisation. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<MoneyPathTables>;
  readonly clock: Clock;
  readonly logger: Logger;
  /** PAGE, but for the tests. */
  readonly page?: number;
}): MoneyPathSnapshot {
  return {
    async run(signal) {
      try {
        const now = clock.now();
        const at = windowAt(now);
        const asked = [...new Set((await list()).filter((orgId) => UUID.test(orgId)).map((id) => id.toLowerCase()))];
        const counted: MoneyPath[] = [];
        let missed = 0;
        let read = 0;
        for (; read < asked.length && signal?.aborted !== true; read += page) {
          const items = asked.slice(read, read + page).map((orgId) => ({ orgId }));
          const reads = await readEachTenant(database, items, ({ orgId }) => moneyPathRead(orgId, at), {
            answeredWithinMs: JOB_ANSWER_WITHIN_MS,
          });
          for (const { item, read: answer } of reads) {
            const log = logger.child({ orgId: item.orgId });
            if ('failed' in answer) {
              missed += 1;
              log.warn('money_path.missed', { err: answer.failed });
              continue;
            }
            // The statement's one row.
            for (const path of answer.rows.map(moneyPathOf)) {
              counted.push(path);
              if (worthNaming(path)) log.info('money_path.organisation', lineOf(path, now));
            }
          }
        }
        logger.info('money_path.snapshot', {
          organisations: counted.length,
          missed,
          complete: read >= asked.length,
          ...lineOf(added(counted), now),
        });
      } catch (error) {
        logger.error('money_path.run_failed', { err: error });
      }
    },
  };
}
