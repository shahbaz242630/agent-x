// The marks (directory.org_work, 0072, 0073, 0075, 0077), kept honest and followed (4D2e D6-D10).
//
// Followed: the hand-off, its sweep, the payment checks, the two expiries, the request
// voids, the waiting rejections, the carry rest, the factor removals, the background
// downloads and the hold history visit only the
// organisations whose marks are due by their clock, at most ORG_WORK_MOST a run,
// those due longest first, instead of every organisation in the directory. Each
// one's due time is when its work is next really needed, so with more due than a
// run takes, one waits behind those due before it: a delay, never a skip.
//
// After a run each one listed is settled, a page at a time: what its rows say is
// next due read in its own withTenant (the tenant is a transaction's, set at its
// start and read back at its commit, so reads of several organisations can't share
// one), holding no mark; then the page's marks moved to those times or taken away
// in one statement, each only where it still reads as it did when listed
// (settleOrgWorkPage). That statement skips a mark a commit is making right now
// and holds the rest only until its commit, so a writer (Tx A, Tx B, an agent's
// decision) waits a trip at most, and no settle ever waits on one. A mark made
// since moves `marks` and stands; a stopped or crashed run settles nothing, and
// its marks are read again; a visit that failed leaves its rows due, so their mark
// too; one a job says it didn't finish (`keep`) stays as it was, first next run.
// A job whose visit also checks what no mark can point at (the factor removals'
// every reset verified, decision 3) visits every organisation besides, every few
// hours (`withWholePasses`).
//
// Kept honest: each hour, every organisation's marks held to what its own rows say
// is due. A mark the triggers should have made and didn't is written and said
// (`org_work.unmarked`): the count the switch above waited on being zero, and what
// bounds a lost mark at about an hour once it has happened. One that says too late
// is brought forward and said too; one with nothing left to do goes.
//
// One organisation's reads go on one trip, between its start and its commit: the
// marks, what is due, the marks again. Each is a statement of its own, so each sees
// its own moment, and each mark is read for what it can safely mean. A row and its
// mark commit together, so a row seen due has its mark in the later read: none there
// is a real miss, unless a job settled it between (a false `unmarked`, rare, and only
// a visit more). And a mark is only cleared by its value in the earlier read, so one
// made while looking has moved it, and the clearing does nothing.
import { backgroundDownloadsDue, type ActivityExportTables } from '@agentx/core/modules/activity';
import { type AuditTables, holdHistoryDue } from '@agentx/core/modules/audit';
import {
  dueOrgWork,
  markOrgWork,
  type OrgWorkJob,
  type OrgWorkMark,
  orgWorkOf,
  type SettledOrgWork,
  settleOrgWork,
  settleOrgWorkPage,
} from '@agentx/core/modules/directory';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { factorRemovalsDue, type IdentityTables } from '@agentx/core/modules/identity';
import { mandateExpiryDue } from '@agentx/core/modules/mandates';
import { requestExpiryDue } from '@agentx/core/modules/spend-requests';
import { type Clock, HOUR_MS, systemClock } from '@agentx/core/shared-kernel';
import type { TransactionsTables } from '@agentx/core/modules/transactions';
import { type Database, type DatabaseTransaction, sendTogether, withTenant } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { createGate, type Gate } from './fair-lanes.ts';
import { handOffDue, handOffSweepDue } from './handoff.ts';
import { carryRestDue } from './mandate-carry-rest.ts';
import { paymentCheckDue } from './payment-checks.ts';
import { requestVoidsDue, type VoidTables } from './request-voids.ts';
import type { DecisionTables } from './spend-request-decisions.ts';
import { waitingRejectionsDue } from './waiting-rejections.ts';

/** How often every organisation's marks are looked over: a serial burst, one organisation after another. */
export const ORG_WORK_REDISCOVERY_EVERY_MS = HOUR_MS;

/** How far past what is due a mark may read before it counts as late: a mark's time and its row's differ by a transaction. */
const LATE_BY_MS = 60_000;

type OrgWorkTables = DirectoryTables &
  VoidTables &
  DecisionTables &
  TransactionsTables &
  AuditTables &
  IdentityTables &
  ActivityExportTables;

/** How many organisations a job takes from its marks a run: its list stays this size however many have work. */
export const ORG_WORK_MOST = 1_000;

/** How many organisations' marks one statement settles: their reads first, then the page's one write. */
const SETTLE_PAGE = 100;

/** A job's read of when its work is next due in an organisation, by `now`, not run: no answer or a null, none is. */
type NextDue = (
  tx: DatabaseTransaction<OrgWorkTables>,
  orgId: string,
  now: Date,
) => { execute(): Promise<readonly { readonly due: Date | null }[]> };

/** A job's organisations from its marks, as its `list` takes them, and their settling once a run has visited them. */
export interface MarkedOrganisations {
  /** Those due by the job's clock, at most ORG_WORK_MOST, due longest first. */
  readonly list: () => Promise<readonly string[]>;
  /** One the run didn't finish: its mark left as it stands, due since before, so the next run takes it first. */
  keep(orgId: string): void;
  /** A time the job knows its next turn there is due: the mark is settled no later, whatever its rows say. */
  dueBy(orgId: string, at: Date): void;
  /** Each one listed since the last settling, its mark settled by what its rows say now; at a stop, none. */
  settle(signal?: AbortSignal): Promise<void>;
}

/** How many organisations' next due times are read at once where no gate is given (job-list.ts gives all its jobs one). */
const READS_AT_ONCE = 4;

/** What the organisation's rows say is next due, read in its own withTenant, holding no mark. */
const nextDueOf = (database: Database<OrgWorkTables>, orgId: string, nextDue: NextDue, now: Date) =>
  withTenant(
    database,
    orgId,
    async (tx) => {
      const [row] = await nextDue(tx, orgId, now).execute();
      return row?.due ?? null;
    },
    { limited: true },
  );

export function markedOrganisations({
  job,
  nextDue,
  database,
  logger,
  clock = systemClock,
  most = ORG_WORK_MOST,
  reads = createGate(READS_AT_ONCE),
}: {
  readonly job: OrgWorkJob;
  readonly nextDue: NextDue;
  readonly database: Database<OrgWorkTables>;
  readonly logger: Logger;
  /** The job's own: what is due is read by it, and the next due times are counted from it. */
  readonly clock?: Clock;
  /** ORG_WORK_MOST unless a test names fewer. */
  readonly most?: number;
  /** The gate its settling's reads go through, each a connection of the pool's: job-list.ts gives every job one gate. */
  readonly reads?: Gate;
}): MarkedOrganisations {
  // Each one's marks as first read since the last settling. A later read can only be newer: settling by the older does
  // nothing where they differ, and the mark stands for another visit.
  let listed = new Map<string, string>();
  let dueBy = new Map<string, number>();

  /**
   * When the organisation is next due: what its rows say, no later than a time the job gave; nothing, none. Work due
   * already (left by the visit: refused, past its share, a moment early) is due now, behind those due before it: kept
   * at its old time, it would be listed ahead of every other for ever, and with more such than a run takes, the rest
   * never.
   */
  const dueOf = async (orgId: string, given: ReadonlyMap<string, number>): Promise<Date | null> => {
    const now = clock.now();
    const rows = await nextDueOf(database, orgId, nextDue, now);
    const by = given.get(orgId);
    const due = rows === null || by === undefined || rows.getTime() <= by ? rows : new Date(by);
    return due !== null && due < now ? now : due;
  };

  /**
   * A page's next due times, as many at a time as `reads` lets, each in its own withTenant: one that can't be read is said, and its
   * mark left for another visit.
   */
  const pageOf = async (
    marks: readonly (readonly [string, string])[],
    given: ReadonlyMap<string, number>,
  ): Promise<SettledOrgWork[]> => {
    const read = await Promise.all(
      marks.map(([orgId, counted]) =>
        reads.run(orgId, async (): Promise<SettledOrgWork | undefined> => {
          try {
            return { orgId, marks: counted, due: await dueOf(orgId, given) };
          } catch (error) {
            logger.child({ orgId }).error('org_work.settle_failed', { job, err: error });
            return undefined;
          }
        }),
      ),
    );
    return read.filter((settled) => settled !== undefined);
  };

  return {
    list: async () => {
      const marks = await dueOrgWork(database, job, { most, by: clock.now() });
      for (const { orgId, marks: read } of marks) if (!listed.has(orgId)) listed.set(orgId, read);
      return marks.map(({ orgId }) => orgId);
    },
    keep: (orgId) => {
      listed.delete(orgId);
    },
    dueBy: (orgId, at) => {
      dueBy.set(orgId, at.getTime());
    },
    async settle(signal) {
      const settling = [...listed];
      listed = new Map();
      const given = dueBy;
      dueBy = new Map();
      for (let at = 0; at < settling.length; at += SETTLE_PAGE) {
        // Stopped, the rest stay as they are, and are read again.
        if (signal?.aborted === true) return;
        try {
          await settleOrgWorkPage(database, job, await pageOf(settling.slice(at, at + SETTLE_PAGE), given));
        } catch (error) {
          // Left as they stand: those organisations are only visited again.
          logger.error('org_work.settle_failed', { job, err: error });
        }
      }
    },
  };
}

/**
 * The job with its organisations from the marks: those each run listed are settled after it, unless it was stopped.
 * What its run says (a skip) comes back as it said it.
 */
export function withOrgWork<Job extends { run(signal?: AbortSignal): Promise<unknown> }>(
  marked: readonly MarkedOrganisations[],
  job: Job,
): Job {
  return {
    ...job,
    async run(signal?: AbortSignal) {
      const ran = await job.run(signal);
      for (const each of marked) await each.settle(signal);
      return ran;
    },
  };
}

/**
 * A job's list from its marks, and at its first run and once every `everyMs` after, every organisation `all` lists
 * besides: for a visit that also checks what no mark can point at (a record changed past the app, which no trigger
 * sees). Those the marks gave first, so a pass never holds up work that is due; each once. Marks that can't be read
 * are said (`org_work.marks_unread`) and never hold up a whole pass that is due: the run goes on with it alone; with
 * none due, the run fails as its list did, and its own line says so.
 */
export function withWholePasses(
  marked: Pick<MarkedOrganisations, 'list'>,
  {
    job,
    everyMs,
    all,
    logger,
    clock = systemClock,
  }: {
    /** The job's name, for its line. */
    readonly job: string;
    readonly everyMs: number;
    readonly all: () => Promise<readonly string[]>;
    readonly logger: Logger;
    /** The job's own. */
    readonly clock?: Clock;
  },
): () => Promise<readonly string[]> {
  let lastWhole: number | undefined;
  return async () => {
    const at = clock.now().getTime();
    const wholeDue = lastWhole === undefined || at - lastWhole >= everyMs;
    let listed: readonly string[] = [];
    try {
      listed = await marked.list();
    } catch (error) {
      logger.error('org_work.marks_unread', { job, err: error });
      if (!wholeDue) throw error;
    }
    if (!wholeDue) return listed;
    const whole = await all();
    lastWhole = at;
    return [...new Set([...listed, ...whole])];
  };
}

/** Each job with the read saying when its work is next due: no answer or a null, none is. In the order of the trip. */
const DUE_READS = [
  ['hand_off', handOffDue],
  ['hand_off_sweep', handOffSweepDue],
  ['payment_check', paymentCheckDue],
  ['request_expiry', requestExpiryDue],
  ['mandate_expiry', mandateExpiryDue],
  ['request_voids', requestVoidsDue],
  ['waiting_rejections', waitingRejectionsDue],
  ['carry_rest', carryRestDue],
  ['factor_removals', factorRemovalsDue],
  ['background_downloads', backgroundDownloadsDue],
  ['hold_history', holdHistoryDue],
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

/**
 * What one look calls for, at `now` (the jobs' clock). Work due already is due now, as a settle stores it (dueOf): a
 * mark is late only past the later of its rows' time and now, so one settled at a visit for work still due (refused,
 * stuck, a request made before 0073) is no miss, and is left where the settle put it, behind those due before it.
 */
export function movesOf({ before, due, after }: Looked, now: Date): Move[] {
  return due.flatMap(({ job, dueAt }): Move[] => {
    const standing = before.find((mark) => mark.job === job);
    if (dueAt === null) return standing === undefined ? [] : [{ kind: 'cleared', job, marks: standing.marks }];
    if (!after.some((mark) => mark.job === job)) return [{ kind: 'unmarked', job, dueAt }];
    const neededBy = Math.max(dueAt.getTime(), now.getTime());
    if (standing === undefined || standing.due_at.getTime() - neededBy <= LATE_BY_MS) return [];
    return [{ kind: 'late', job, dueAt, marks: standing.marks }];
  });
}

/** The organisation's marks and rows, on one trip between its start and its commit. */
function lookedAt(database: Database<OrgWorkTables>, orgId: string, now: Date): Promise<Looked> {
  return withTenant(
    database,
    orgId,
    async (tx) => {
      const answers = await sendTogether(tx, [
        orgWorkOf(tx, orgId),
        ...DUE_READS.map(([, read]) => read(tx, orgId, now)),
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
  clock = systemClock,
}: {
  /** The organisations to look in: the directory's list, which job-list.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<OrgWorkTables>;
  readonly logger: Logger;
  /** The jobs' own, which their due times are counted by. */
  readonly clock?: Clock;
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
        // Stopped between organisations, so a stopped run says no count: the switch counts finished runs only.
        if (signal?.aborted === true) return;
        const log = logger.child({ orgId });
        counts.organisations += 1;
        try {
          const now = clock.now();
          for (const move of movesOf(await lookedAt(database, orgId, now), now)) {
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
