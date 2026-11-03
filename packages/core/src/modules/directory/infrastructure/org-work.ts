// directory.org_work (0072): which organisation has work of which kind, written by
// deferred triggers as the work's own row commits. A row chooses when to look, and
// nothing is believed from it: whoever looks reads and acts inside withTenant.
//
// A mark that waits for its row waits inside COMMIT, where statement_timeout doesn't
// reach (measured, org-work.db.test.ts): lock_timeout does, if the transaction set one,
// and fails the whole commit. So nothing may hold a mark long: writers commit, and
// what's here is one row in a transaction of its own, under the idle limit if it hangs.
import { limitedTransaction } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { DirectoryTables } from './tables.ts';

/** The work the marks follow so far. */
export type OrgWorkJob = 'hand_off' | 'hand_off_sweep' | 'payment_check';

/** One mark. `marks` moves with every mark made, and is only ever compared. */
export interface OrgWorkMark {
  readonly job: OrgWorkJob;
  readonly due_at: Date;
  readonly marks: string;
}

/** The organisation's marks, not run: a statement for a caller's trip. */
export const orgWorkOf = (tx: Transaction<DirectoryTables>, orgId: string) =>
  tx.selectFrom('directory.org_work').select(['job', 'due_at', 'marks']).where('org_id', '=', orgId);

/**
 * Makes the mark a write left out, or brings one that stands forward, as the trigger would. A transaction of its
 * own and one row: nothing marking in COMMIT can end up waiting on it while it waits on them.
 */
export async function markOrgWork(
  db: Kysely<DirectoryTables>,
  orgId: string,
  job: OrgWorkJob,
  dueAt: Date,
): Promise<void> {
  await limitedTransaction(db, (tx) =>
    tx
      .insertInto('directory.org_work')
      .values({ org_id: orgId, job, due_at: dueAt })
      .onConflict((conflict) =>
        conflict.columns(['org_id', 'job']).doUpdateSet({
          marks: sql`org_work.marks + 1`,
          due_at: sql`LEAST(org_work.due_at, excluded.due_at)`,
        }),
      )
      .execute(),
  );
}

/**
 * After looking: with nothing more due the mark goes, otherwise it moves to the next due time, either only while it
 * still reads as `marks`, the value read **before** looking. A mark made since has moved it, so this does nothing and
 * that mark stands. Whether it did anything comes back. One row in its own transaction, as markOrgWork.
 */
export async function settleOrgWork(
  db: Kysely<DirectoryTables>,
  { orgId, job, marks }: { readonly orgId: string; readonly job: OrgWorkJob; readonly marks: string },
  nextDue: Date | null,
): Promise<boolean> {
  const isThisMark = { org_id: orgId, job, marks };
  const settled = await limitedTransaction(db, async (tx) => {
    if (nextDue === null) {
      const { numDeletedRows } = await tx
        .deleteFrom('directory.org_work')
        .where((where) => where.and(isThisMark))
        .executeTakeFirst();
      return numDeletedRows;
    }
    const { numUpdatedRows } = await tx
      .updateTable('directory.org_work')
      .set({ due_at: nextDue })
      .where((where) => where.and(isThisMark))
      .executeTakeFirst();
    return numUpdatedRows;
  });
  return settled === 1n;
}
