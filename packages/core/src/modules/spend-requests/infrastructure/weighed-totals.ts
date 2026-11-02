// What a decision weighs from the tables once its locks are held, in one
// statement (4D2d P12): the agent's month's total, the payee's split total and
// the claims on the order. A statement's snapshot is taken as it starts, so it
// goes in a statement of its own, after the supplier's and the month's locks:
// never in the statement that takes either, whose snapshot would miss what the
// lock's holder committed during the wait (the S157 trap). It may share a trip
// with the month's lock (4D2e C7): the server starts it, and takes its snapshot,
// only once the lock ahead of it is answered, so one trip saves the round trip
// and loses nothing it would have seen.
import { sendTogether } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';

import type { AuditTables } from '../../audit/index.ts';
import {
  agentMonthLocking,
  type LimitReservationsTables,
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
 * The agent's month locked (agentMonthLocking), then the totals and claims asked read in a statement of their own, on
 * one trip (4D2e C7), a decision's: its supplier's lock is alone before it. A wait run out or a deadlock on the lock
 * comes back as itself: the statement behind it fails only after it, unseen.
 */
export async function monthLockedAndTotalsWeighed(
  tx: TotalsTransaction,
  { orgId, at }: { readonly orgId: string; readonly at: Date },
  toWeigh: TotalsToWeigh & { readonly month: MonthToSum },
): Promise<TotalsWeighed> {
  const { agentId, month } = toWeigh.month;
  const totals = totalsRead(tx, toWeigh);
  const [, locked, found] = await sendTogether(tx, [...agentMonthLocking(tx, { orgId, agentId, month, at }), totals]);
  if (locked.rows.length !== 1) throw new Error(`the agent's period was not there to lock: ${month}`);
  return totalsOf(found.rows[0] as Parameters<typeof totalsOf>[0]);
}
