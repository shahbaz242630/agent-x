// What a decision weighs from the tables once its locks are held, in one
// statement (4D2d P12): the agent's month's total, the payee's split total and
// the claims on the order. A statement's snapshot is taken as it starts, so it
// goes in a statement of its own, after the supplier's and the month's locks:
// never in the statement that takes either, whose snapshot would miss what the
// lock's holder committed during the wait (the S157 trap).
import { sql, type Transaction } from 'kysely';

import type { AuditTables } from '../../audit/index.ts';
import {
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

/** The totals and claims asked, all from one moment: no trip when none is asked. */
export async function totalsWeighed(
  tx: Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>,
  { month, split, order }: TotalsToWeigh,
): Promise<TotalsWeighed> {
  if (month === null && split === null && order === null) return NOTHING_WEIGHED;
  const looks = order === null ? null : claimLooks(tx, order);
  const found = await tx
    .selectNoFrom([
      (month === null ? sql<string>`'0'::text` : sql<string>`(${monthSpentRead(tx, month)})`).as('spent'),
      (split === null ? sql<string>`'0'::text` : sql<string>`(${splitHeldRead(tx, split)})`).as('split'),
      (looks?.duplicate ?? sql<boolean>`false`).as('duplicate'),
      (looks?.possible ?? sql<boolean>`false`).as('possible'),
    ])
    .executeTakeFirstOrThrow();
  return {
    spent: BigInt(found.spent),
    split: BigInt(found.split),
    claims: { duplicate: found.duplicate, possible: found.possible },
  };
}
