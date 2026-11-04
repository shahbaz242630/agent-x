// directory.org_work (0072, 0073, 0075, 0077): which organisation has work of which kind, written by
// deferred triggers as the work's own row commits, or (a hold, an audit event, which no trigger
// watches) by the work's own transaction last of all. A row chooses when to look, and
// nothing is believed from it: whoever looks reads and acts inside withTenant.
//
// A mark that waits for its row waits inside COMMIT, where statement_timeout doesn't
// reach (measured, org-work.db.test.ts): lock_timeout does, if the transaction set one,
// and fails the whole commit. So nothing may hold a mark long: writers commit, and
// what's here is one row in a transaction of its own, under the idle limit if it hangs,
// or a page of rows that skips any a commit holds and holds the rest for one trip.
import { limitedTransaction } from '@agentx/platform/db';
import { type Kysely, type QueryExecutorProvider, sql, type Transaction } from 'kysely';

import { readAlone } from './read-alone.ts';
import { type DirectoryTables, ORG_WORK_JOBS, type OrgWorkJob } from './tables.ts';

export type { OrgWorkJob } from './tables.ts';

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
 * Makes the organisation's mark of the job, due now, or brings one that stands forward, in the caller's transaction, as
 * a trigger would at its commit: its last statement, after every lock ADR-006 orders (the head's too), so it waits on
 * no one but a mark's own row. Only an organisation the directory lists, the only ones a job visits: an ID it doesn't
 * list makes nothing, never an error that would undo the work it marks.
 */
export async function markOrgWorkNow(tx: QueryExecutorProvider, orgId: string, job: OrgWorkJob): Promise<void> {
  await sql`
    insert into directory.org_work (org_id, job, due_at)
    select o.org_id, ${job}, pg_catalog.now() from directory.orgs o where o.org_id = ${orgId}::uuid
    on conflict (org_id, job) do update set marks = org_work.marks + 1,
      due_at = least(org_work.due_at, excluded.due_at)
  `.execute(tx);
}

/** A mark as a job reads it to choose where to go: whose, and its count then, which its settling compares. */
export interface DueOrgWork {
  readonly orgId: string;
  readonly marks: string;
}

/**
 * A job's marks due by `by` (its clock) or by Postgres's, whichever is later, those due longest first, at most `most`,
 * so a run's list never grows with the organisations: each one settled moves behind those due before it, so none waits
 * for ever. One statement, in a read of its own.
 */
export function dueOrgWork(
  db: Kysely<DirectoryTables>,
  job: OrgWorkJob,
  { most, by }: { readonly most: number; readonly by: Date },
): Promise<DueOrgWork[]> {
  return readAlone(db, (tx) =>
    tx
      .selectFrom('directory.org_work')
      // As text, as its type says: the pool reads a bigint as a BigInt.
      .select((eb) => ['org_id as orgId', eb.cast<string>('marks', 'text').as('marks')])
      .where('job', '=', job)
      // By the later clock: the triggers' marks are Postgres's, a job's due times its own.
      .where('due_at', '<=', sql<Date>`greatest(pg_catalog.now(), ${by}::timestamptz)`)
      .orderBy('due_at')
      .limit(most)
      .execute(),
  );
}

/**
 * The organisations with a mark of any job, whenever due: those with work, or work coming. Due soonest first, at most
 * `most`, so a run's list never grows with the organisations. One statement, in a read of its own: each job's soonest
 * `most` from the due index (org_work_due), then each organisation once by its soonest. Exact: an organisation among
 * the soonest `most` by its soonest mark has fewer than `most` marks of that mark's job before it, each another
 * organisation's that comes before it too, so that mark is among its job's soonest `most`.
 */
export async function organisationsWithMarks(db: Kysely<DirectoryTables>, most: number): Promise<string[]> {
  const rows = await readAlone(db, async (tx) => (await organisationsWithMarksRead(most).execute(tx)).rows);
  return rows.map(({ org_id }) => org_id);
}

/** organisationsWithMarks' statement, not run: its plan is the test's. */
export function organisationsWithMarksRead(most: number) {
  const eachJob = sql.join(
    ORG_WORK_JOBS.map(
      (job) =>
        sql`(select org_id, due_at from directory.org_work where job = ${job} order by due_at, org_id limit ${most})`,
    ),
    sql` union all `,
  );
  return sql<{ org_id: string }>`
    select org_id from (${eachJob}) soonest
    group by org_id order by min(due_at), org_id limit ${most}
  `;
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

/** One organisation's mark as a job settles it: its count when listed, and what its rows said next after the visit. */
export interface SettledOrgWork {
  readonly orgId: string;
  readonly marks: string;
  readonly due: Date | null;
}

/**
 * settleOrgWork for a page of a job's marks, in one statement in a transaction of its own: each goes (nothing due) or
 * moves to its next due time, only while it still reads as listed. A row a commit is marking right now is skipped, not
 * waited for: that commit moves its count, so settling it would do nothing, and never waiting means no settle is ever
 * in a writer's wait, or a deadlock with one marking several jobs. The rows taken are held from this statement to its
 * commit, the next trip. How many it settled comes back.
 */
export async function settleOrgWorkPage(
  db: Kysely<DirectoryTables>,
  job: OrgWorkJob,
  page: readonly SettledOrgWork[],
): Promise<number> {
  if (page.length === 0) return 0;
  const { rows } = await limitedTransaction(db, (tx) =>
    sql<{ settled: number }>`
      with page as (
        select * from rows from (
          pg_catalog.unnest(${page.map(({ orgId }) => orgId)}::uuid[]),
          pg_catalog.unnest(${page.map(({ marks }) => marks)}::bigint[]),
          pg_catalog.unnest(${page.map(({ due }) => due)}::timestamptz[])
        ) as p (org_id, marks, due)
      ),
      held as (
        select w.org_id, p.due from directory.org_work w
        join page p on p.org_id = w.org_id and p.marks = w.marks
        where w.job = ${job}
        for update of w skip locked
      ),
      gone as (
        delete from directory.org_work w using held h
        where w.job = ${job} and w.org_id = h.org_id and h.due is null
        returning 1
      ),
      moved as (
        update directory.org_work w set due_at = h.due from held h
        where w.job = ${job} and w.org_id = h.org_id and h.due is not null
        returning 1
      )
      select ((select pg_catalog.count(*) from gone) + (select pg_catalog.count(*) from moved))::integer as settled
    `.execute(tx),
  );
  // One row always: its count.
  return rows.reduce((sum, { settled }) => sum + settled, 0);
}
