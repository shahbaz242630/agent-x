// What a decision weighs from the tables once its locks are held, in one
// statement (4D2d P12): the claims on the order; and, beside them on the same
// trip, the agent's month's signed total (GM-1a, month-totals.ts) and its
// payee's signed split windows (GM-1b, payee-windows.ts). The reservations'
// own month sum (`month` here) is no longer weighed by any decision: it is what
// the holdings check holds the signed total to, and the tests' view of what is
// reserved; their split sum is gone, the windows holding what it read. A
// statement's snapshot is taken as it starts, so it goes in a statement of its
// own, after the supplier's and the month's locks: never in the statement that
// takes either, whose snapshot would miss what the lock's holder committed
// during the wait (the S157 trap). It may share a trip with the month's lock
// (4D2e C7): the server starts it, and takes its snapshot, only once the lock
// ahead of it is answered, so one trip saves the round trip and loses nothing
// it would have seen.
import { sql, type Transaction } from 'kysely';

import type { AuditTables, SignedStates } from '../../audit/index.ts';
import {
  agentMonthLocking,
  type LimitReservationsTables,
  type MonthTotalCheck,
  monthTotalGathered,
  type MonthTotalKey,
  monthTotalOf,
  monthTotalsCutOver,
  monthSpentRead,
  type MonthToSum,
  type Payee,
  type PayeeWindowCheck,
  payeeWindowGathered,
  payeeWindowId,
  type PayeeWindowKey,
  payeeWindowKeys,
  payeeWindowOf,
  payeeWindowOrder,
  payeeWindowsCutOver,
  type WindowToWrite,
} from '../../limit-reservations/index.ts';
import { claimLooks, type OrderWeighed } from './order-claims.ts';
import type { SpendRequestsTables } from './tables.ts';

/** Each part read only where it is weighed: 0, or no claim, for one not asked. */
interface TotalsToWeigh {
  readonly month: MonthToSum | null;
  readonly order: OrderWeighed | null;
}

interface TotalsWeighed {
  readonly spent: bigint;
  readonly claims: { readonly duplicate: boolean; readonly possible: boolean };
}

const NOTHING_WEIGHED: TotalsWeighed = Object.freeze({
  spent: 0n,
  claims: Object.freeze({ duplicate: false, possible: false }),
});

type TotalsTransaction = Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>;

/** The statement reading the totals and claims asked, all from one moment, not run: at least one asked. */
function totalsRead(tx: TotalsTransaction, { month, order }: TotalsToWeigh) {
  const looks = order === null ? null : claimLooks(tx, order);
  return tx.selectNoFrom([
    (month === null ? sql<string>`'0'::text` : sql<string>`(${monthSpentRead(tx, month)})`).as('spent'),
    (looks?.duplicate ?? sql<boolean>`false`).as('duplicate'),
    (looks?.possible ?? sql<boolean>`false`).as('possible'),
  ]);
}

/** totalsRead's row as what it weighs. */
const totalsOf = (found: {
  readonly spent: string;
  readonly duplicate: boolean;
  readonly possible: boolean;
}): TotalsWeighed => ({
  spent: BigInt(found.spent),
  claims: { duplicate: found.duplicate, possible: found.possible },
});

/** The totals and claims asked: no trip when none is asked. */
export async function totalsWeighed(tx: TotalsTransaction, toWeigh: TotalsToWeigh): Promise<TotalsWeighed> {
  if (toWeigh.month === null && toWeigh.order === null) return NOTHING_WEIGHED;
  return totalsOf(await totalsRead(tx, toWeigh).executeTakeFirstOrThrow());
}

/**
 * A decision's month's total, read for change with its month's lock (GM-1a): what it holds, with what it is to be
 * written from (`held`, or `none`: a month nothing is held in yet); `busy` for an organisation not yet counted in
 * signed totals (its cutover to come); or `tampered`, the alarm raised.
 */
export type DecisionMonthTotal =
  | {
      readonly outcome: 'held' | 'none';
      readonly key: MonthTotalKey;
      readonly total: Exclude<MonthTotalCheck, { readonly outcome: 'tampered' }>;
      readonly spent: bigint;
    }
  | { readonly outcome: 'busy' }
  | { readonly outcome: 'tampered' };

/**
 * A decision's payee's windows, read for change with its month's lock (GM-1b), in payeeWindowKeys' order (none for a
 * request to no supplier of the organisation's): each with what it is to be written from; `busy` for an organisation
 * not yet counted in signed windows; or `tampered`, the alarm raised.
 */
export type DecisionWindows =
  | {
      readonly outcome: 'read';
      readonly rows: readonly { readonly key: PayeeWindowKey; readonly read: WindowToWrite }[];
    }
  | { readonly outcome: 'busy' }
  | { readonly outcome: 'tampered' };

/**
 * The agent's month locked (agentMonthLocking), then the claims asked read in a statement of their own, then the
 * month's signed total and the payee's signed windows gathered for change (GM-1a, GM-1b; 11a, then 11b in order of
 * ID), all on one trip (4D2e C7), a decision's: its supplier's lock is alone before it. Each read in a statement after
 * the lock, so each sees what the lock's holder committed. The month's total and the split window are the signed
 * ones, never the reservations' sums, which the database's owner could cut (R-15). A wait run out or a deadlock on
 * the lock comes back as itself: the statements behind it fail only after it, unseen. A month with no total, or a
 * payee with no window, makes one more trip, to the organisation's log: nothing held after its cutover.
 */
export async function monthLockedAndTotalsWeighed(
  tx: TotalsTransaction,
  states: SignedStates,
  { orgId, at, payee }: { readonly orgId: string; readonly at: Date; readonly payee: Payee | null },
  toWeigh: TotalsToWeigh & { readonly month: MonthToSum },
): Promise<TotalsWeighed & { readonly monthTotal: DecisionMonthTotal; readonly windows: DecisionWindows }> {
  const { agentId, month, currency } = toWeigh.month;
  const key = { agentId, month, currency };
  const windows = (payee === null ? [] : payeeWindowKeys(payee)).map((windowKey) => ({
    key: windowKey,
    id: payeeWindowId(orgId, windowKey),
  }));
  const others = totalsRead(tx, { ...toWeigh, month: null });
  const {
    ahead: [, locked, found],
  } = await states.gatherBehind(
    tx,
    orgId,
    [...agentMonthLocking(tx, { orgId, agentId, month, at }), others],
    [
      monthTotalGathered(orgId, key, 'change'),
      // In the lock order: each window after the total, in order of ID.
      ...windows
        .toSorted((a, b) => payeeWindowOrder(a.id, b.id))
        .map((window) => payeeWindowGathered(orgId, window.key, 'change')),
    ],
  );
  if (locked.rows.length !== 1) throw new Error(`the agent's period was not there to lock: ${month}`);
  const weighed = totalsOf(found.rows[0] as Parameters<typeof totalsOf>[0]);
  // Answered from the gather: no trip.
  const total = await monthTotalOf(tx, states, orgId, key, 'change');
  const reads = [];
  for (const window of windows)
    reads.push({ key: window.key, read: await payeeWindowOf(tx, states, orgId, window.id, 'change') });
  const counted = await countedAsRead(
    tx,
    states,
    orgId,
    total,
    reads.map(({ read }) => read),
  );
  return {
    ...weighed,
    monthTotal: decisionTotal(key, total, counted.monthTotals),
    windows: decisionWindows(reads, counted.payeeWindows),
  };
}

type Counted = 'cut_over' | 'not_yet' | 'tampered';

/**
 * Whether the organisation is counted in signed totals and windows, read only for what was found missing: none for a
 * month and payee each read whole. A window missing reads the windows' cutover alone: the job cuts an organisation's
 * windows over only once its totals are, so one cut over says both are (one trip, never two).
 */
async function countedAsRead(
  tx: TotalsTransaction,
  states: SignedStates,
  orgId: string,
  total: MonthTotalCheck,
  windows: readonly { readonly outcome: string }[],
): Promise<{ readonly monthTotals: Counted; readonly payeeWindows: Counted }> {
  if (windows.some(({ outcome }) => outcome === 'none')) {
    const windowsCounted = await payeeWindowsCutOver(tx, states, orgId);
    return { monthTotals: windowsCounted, payeeWindows: windowsCounted };
  }
  if (total.outcome === 'none')
    return { monthTotals: await monthTotalsCutOver(tx, states, orgId), payeeWindows: 'cut_over' };
  return { monthTotals: 'cut_over', payeeWindows: 'cut_over' };
}

/** A decision's month total as read: a month with none holds nothing once the organisation is cut over, else busy. */
function decisionTotal(key: MonthTotalKey, total: MonthTotalCheck, counted: Counted): DecisionMonthTotal {
  if (total.outcome === 'tampered') return TAMPERED;
  if (total.outcome === 'held') return { outcome: 'held', key, total, spent: total.held };
  if (counted === 'cut_over') return { outcome: 'none', key, total, spent: 0n };
  return NOT_COUNTED[counted];
}

/** What a read missing answers before the organisation is counted: busy, or its log can't be believed. */
const NOT_COUNTED = {
  not_yet: Object.freeze({ outcome: 'busy' as const }),
  tampered: Object.freeze({ outcome: 'tampered' as const }),
} as const;

/** A decision's windows as read: any tampered with refuses them all; one missing holds nothing once cut over, else busy. */
function decisionWindows(
  reads: readonly { readonly key: PayeeWindowKey; readonly read: PayeeWindowCheck }[],
  counted: Counted,
): DecisionWindows {
  const rows: { readonly key: PayeeWindowKey; readonly read: WindowToWrite }[] = [];
  for (const { key, read } of reads) {
    if (read.outcome === 'tampered') return TAMPERED;
    rows.push({ key, read });
  }
  if (counted !== 'cut_over' && rows.some(({ read }) => read.outcome === 'none')) return NOT_COUNTED[counted];
  return { outcome: 'read', rows };
}

const TAMPERED = NOT_COUNTED.tampered;
