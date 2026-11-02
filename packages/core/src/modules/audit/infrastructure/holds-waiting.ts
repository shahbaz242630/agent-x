// directory.holds_waiting (0069): an integrity hold that couldn't be recorded,
// kept outside the process. Its rows only add caution: with-signed-states.ts says
// what it does with them, and signed-states.ts how Tx A reads them.
import { limitedTransaction, readAloneOnOneTrip } from '@agentx/platform/db';
import type { Kysely, Transaction } from 'kysely';

import type { AuditTables } from './tables.ts';

/** One hold waiting: an ID and how the tampering showed, as far as a row may say. */
export interface HoldWaiting {
  readonly org_id: string;
  readonly reason: string;
}

/** Keeps a hold that couldn't be recorded. One there already stands. Its own transaction, so a hung statement ends. */
export async function keepHoldWaiting(db: Kysely<AuditTables>, orgId: string, reason: string): Promise<void> {
  await limitedTransaction(db, (tx) =>
    tx
      .insertInto('directory.holds_waiting')
      .values({ org_id: orgId, reason })
      .onConflict((conflict) => conflict.column('org_id').doNothing())
      .execute(),
  );
}

/** Takes the row away, in the transaction that recorded the hold (or found it held), so the two can't part. */
export async function holdNoLongerWaiting(tx: Transaction<AuditTables>, orgId: string): Promise<void> {
  await tx.deleteFrom('directory.holds_waiting').where('org_id', '=', orgId).execute();
}

/**
 * Every hold waiting, on one trip: an empty table is the usual answer. No limit,
 * as the key and the directory's list bound it to one row an organisation, and
 * a partial answer would read as rows deleted.
 */
export function holdsWaiting(db: Kysely<AuditTables>): Promise<readonly HoldWaiting[]> {
  return readAloneOnOneTrip(db, db.selectFrom('directory.holds_waiting').select(['org_id', 'reason']));
}
