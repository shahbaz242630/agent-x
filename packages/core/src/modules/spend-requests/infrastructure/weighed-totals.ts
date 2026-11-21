// What a decision weighs from the tables once its locks are held, in one
// statement (4D2d P12): the payee's split total and the claims on the order;
// and, beside them on the same trip, the agent's month's signed total (GM-1a,
// month-totals.ts). The reservations' own month sum (`month` here) is no
// longer weighed by any decision: it is what the holdings check holds the
// signed total to, and the tests' view of what is reserved. A statement's snapshot is taken as it starts, so it
// goes in a statement of its own, after the supplier's and the month's locks:
// never in the statement that takes either, whose snapshot would miss what the
// lock's holder committed during the wait (the S157 trap). It may share a trip
// with the month's lock (4D2e C7): the server starts it, and takes its snapshot,
// only once the lock ahead of it is answered, so one trip saves the round trip
// and loses nothing it would have seen.
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
  splitHeldRead,
  type SplitToSum,
} from '../../limit-reservations/index.ts';
import { claimLooks, type OrderWeighed } from './order-claims.ts';
import type { SpendRequestsTables } from './tables.ts';

/** Each part read only where it is weighed: 0, or no claim, for one not asked. */
interface TotalsToWeigh {
  readonly month: MonthToSum | null;
  readonly split: SplitToSum | null;
  readonly order: OrderWeighed | null;
}

interface TotalsWeighed {
  readonly spent: bigint;
  readonly split: bigint;
  readonly claims: { readonly duplicate: boolean; readonly possible: boolean };
}

const NOTHING_WEIGHED: TotalsWeighed = Object.freeze({
  spent: 0n,
  split: 0n,
  claims: Object.freeze({ duplicate: false, possible: false }),
});

type TotalsTransaction = Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>;

/** The statement reading the totals and claims asked, all from one moment, not run: at least one asked. */
function totalsRead(tx: TotalsTransaction, { month, split, order }: TotalsToWeigh) {
  const looks = order === null ? null : claimLooks(tx, order);
  return tx.selectNoFrom([
    (month === null ? sql<string>`'0'::text` : sql<string>`(${monthSpentRead(tx, month)})`).as('spent'),
    (split === null ? sql<string>`'0'::text` : sql<string>`(${splitHeldRead(tx, split)})`).as('split'),
    (looks?.duplicate ?? sql<boolean>`false`).as('duplicate'),
    (looks?.possible ?? sql<boolean>`false`).as('possible'),
  ]);
}

/** totalsRead's row as what it weighs. */
const totalsOf = (found: {
  readonly spent: string;
  readonly split: string;
  readonly duplicate: boolean;
  readonly possible: boolean;
}): TotalsWeighed => ({
  spent: BigInt(found.spent),
  split: BigInt(found.split),
  claims: { duplicate: found.duplicate, possible: found.possible },
});

/** The totals and claims asked: no trip when none is asked. */
export async function totalsWeighed(tx: TotalsTransaction, toWeigh: TotalsToWeigh): Promise<TotalsWeighed> {
  if (toWeigh.month === null && toWeigh.split === null && toWeigh.order === null) return NOTHING_WEIGHED;
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
 * The agent's month locked (agentMonthLocking), then the split total and claims asked read in a statement of their
 * own, then the month's signed total gathered for change (GM-1a), all on one trip (4D2e C7), a decision's: its
 * supplier's lock is alone before it. Each read in a statement after the lock, so each sees what the lock's holder
 * committed. The month's total is the signed one, never the reservations' sum, which the database's owner could cut
 * (R-15). A wait run out or a deadlock on the lock comes back as itself: the statements behind it fail only after it,
 * unseen. A month with no total makes one more trip, to the organisation's log: nothing held after its cutover.
 */
export async function monthLockedAndTotalsWeighed(
  tx: TotalsTransaction,
  states: SignedStates,
  { orgId, at }: { readonly orgId: string; readonly at: Date },
  toWeigh: TotalsToWeigh & { readonly month: MonthToSum },
): Promise<TotalsWeighed & { readonly monthTotal: DecisionMonthTotal }> {
  const { agentId, month, currency } = toWeigh.month;
  const key = { agentId, month, currency };
  const others = totalsRead(tx, { ...toWeigh, month: null });
  const {
    ahead: [, locked, found],
  } = await states.gatherBehind(
    tx,
    orgId,
    [...agentMonthLocking(tx, { orgId, agentId, month, at }), others],
    [monthTotalGathered(orgId, key, 'change')],
  );
  if (locked.rows.length !== 1) throw new Error(`the agent's period was not there to lock: ${month}`);
  const weighed = totalsOf(found.rows[0] as Parameters<typeof totalsOf>[0]);
  // Answered from the gather: no trip.
  const total = await monthTotalOf(tx, states, orgId, key, 'change');
  return { ...weighed, monthTotal: await decisionTotal(tx, states, orgId, key, total) };
}

/** A decision's month total as read: a month with none holds nothing once the organisation is cut over, else busy. */
async function decisionTotal(
  tx: TotalsTransaction,
  states: SignedStates,
  orgId: string,
  key: MonthTotalKey,
  total: MonthTotalCheck,
): Promise<DecisionMonthTotal> {
  if (total.outcome === 'tampered') return TAMPERED;
  if (total.outcome === 'held') return { outcome: 'held', key, total, spent: total.held };
  const cutOver = await monthTotalsCutOver(tx, states, orgId);
  if (cutOver === 'cut_over') return { outcome: 'none', key, total, spent: 0n };
  return cutOver === 'tampered' ? TAMPERED : BUSY;
}

const TAMPERED = Object.freeze({ outcome: 'tampered' as const });
const BUSY = Object.freeze({ outcome: 'busy' as const });
