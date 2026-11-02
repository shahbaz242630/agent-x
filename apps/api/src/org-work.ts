// The marks kept honest (4D2e D6): each hour, every organisation's marks in
// directory.org_work (0070) held to what its own rows say is due. A mark the triggers
// should have made and didn't is written and said (`org_work.unmarked`): that is the
// count the jobs' switch to the marks waits on being zero, and what bounds a lost
// mark at about an hour once it has happened. One that says too late is brought
// forward and said too; one with nothing left to do goes.
//
// Watching only: no job reads the marks yet, so nothing here changes what any job
// does, and the marks of work since done are cleared here alone.
//
// One organisation's reads go on one trip, between its start and its commit: the
// marks, what is due, the marks again. Each is a statement of its own, so each sees
// its own moment, and each mark is read for what it can safely mean. A row and its
// mark commit together, so a row seen due has its mark in the later read: none there
// is a real miss. And a mark is only cleared by its value in the earlier read, so one
// made while looking has moved it, and the clearing does nothing.
import {
  markOrgWork,
  type OrgWorkJob,
  type OrgWorkMark,
  orgWorkOf,
  settleOrgWork,
} from '@agentx/core/modules/directory';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import type { SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { HOUR_MS } from '@agentx/core/shared-kernel';
import type { TransactionsTables } from '@agentx/core/modules/transactions';
import { type Database, sendTogether, withTenant } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { handOffDue, handOffSweepDue } from './handoff.ts';
import { paymentCheckDue } from './payment-checks.ts';

/** How often every organisation's marks are looked over: about 8 trips a second at 10,000 organisations. */
export const ORG_WORK_REDISCOVERY_EVERY_MS = HOUR_MS;

/** How far past what is due a mark may read before it counts as late: a mark's time and its row's differ by a transaction. */
const LATE_BY_MS = 60_000;

type OrgWorkTables = DirectoryTables & SpendRequestsTables & TransactionsTables;

/** Each job with the read saying when its work is next due: no answer or a null, none is. In the order of the trip. */
const DUE_READS = [
  ['hand_off', handOffDue],
  ['hand_off_sweep', handOffSweepDue],
  ['payment_check', paymentCheckDue],
] as const satisfies readonly (readonly [OrgWorkJob, unknown])[];

/** What the organisation's rows and marks said on one trip. */
interface Looked {
  readonly before: readonly OrgWorkMark[];
  readonly due: readonly { readonly job: OrgWorkJob; readonly dueAt: Date | null }[];
  readonly after: readonly OrgWorkMark[];
}

/** What one look at an organisation calls for, one row each. */
type Move =
  | { readonly kind: 'unmarked'; readonly job: OrgWorkJob; readonly dueAt: Date }
  | { readonly kind: 'late'; readonly job: OrgWorkJob; readonly dueAt: Date; readonly marks: string }
  | { readonly kind: 'cleared'; readonly job: OrgWorkJob; readonly marks: string };

export function movesOf({ before, due, after }: Looked): Move[] {
  return due.flatMap(({ job, dueAt }): Move[] => {
    const standing = before.find((mark) => mark.job === job);
    if (dueAt === null) return standing === undefined ? [] : [{ kind: 'cleared', job, marks: standing.marks }];
    if (!after.some((mark) => mark.job === job)) return [{ kind: 'unmarked', job, dueAt }];
    if (standing === undefined || standing.due_at.getTime() - dueAt.getTime() <= LATE_BY_MS) return [];
    return [{ kind: 'late', job, dueAt, marks: standing.marks }];
  });
}

/** The organisation's marks and rows, on one trip between its start and its commit. */
function lookedAt(database: Database<OrgWorkTables>, orgId: string): Promise<Looked> {
  return withTenant(
    database,
    orgId,
    async (tx) => {
      const answers = await sendTogether(tx, [
        orgWorkOf(tx, orgId),
        ...DUE_READS.map(([, read]) => read(tx, orgId)),
        orgWorkOf(tx, orgId),
      ]);
      const marks = (at: number) => (answers[at]?.rows ?? []) as readonly OrgWorkMark[];
      return {
        before: marks(0),
        due: DUE_READS.map(([job], at) => ({
          job,
          dueAt: (answers[at + 1]?.rows[0] as { due: Date | null } | undefined)?.due ?? null,
        })),
        after: marks(DUE_READS.length + 1),
      };
    },
    { limited: true },
  );
}

/** Carries a move out, each row in a transaction of its own, after the look's has ended; whether it took. */
async function carriedOut(database: Database<OrgWorkTables>, orgId: string, move: Move, log: Logger): Promise<boolean> {
  if (move.kind === 'cleared') return settleOrgWork(database, { orgId, job: move.job, marks: move.marks }, null);
  if (move.kind === 'late') {
    const moved = await settleOrgWork(database, { orgId, job: move.job, marks: move.marks }, move.dueAt);
    if (moved) log.warn('org_work.unmarked', { job: move.job, late: true });
    return moved;
  }
  await markOrgWork(database, orgId, move.job, move.dueAt);
  log.warn('org_work.unmarked', { job: move.job, late: false });
  return true;
}

export function createOrgWorkRediscovery({
  list,
  database,
  logger,
}: {
  /** The organisations to look in: the directory's list, which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<OrgWorkTables>;
  readonly logger: Logger;
}): { run(signal?: AbortSignal): Promise<void> } {
  return {
    async run(signal) {
      let orgs: readonly string[];
      try {
        orgs = await list();
      } catch (error) {
        logger.error('org_work.rediscovery_failed', { err: error });
        return;
      }
      const counts = { organisations: 0, unmarked: 0, late: 0, cleared: 0, failed: 0 };
      for (const orgId of orgs) {
        // Stopped between organisations, so the process stops promptly however many there are.
        if (signal?.aborted === true) return;
        const log = logger.child({ orgId });
        counts.organisations += 1;
        try {
          for (const move of movesOf(await lookedAt(database, orgId))) {
            if (await carriedOut(database, orgId, move, log)) counts[move.kind] += 1;
          }
        } catch (error) {
          counts.failed += 1;
          log.error('org_work.rediscovery_failed', { err: error });
        }
      }
      logger.info('org_work.rediscovered', counts);
    },
  };
}
