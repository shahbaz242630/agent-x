// Phase 3 L7: the operator exports an organisation's activity log for a
// case, a dispute or a regulator's request (ADR-005 §6's second exception,
// extended to the activity log; partner decision 26). Read only, as the audit
// log's export (audit-export.ts), and its steps the same (case-export.ts):
//
// 1. Recorded first, in one transaction, withSignedStates' for the
//    organisation: the organisation must exist and be verified; the range
//    counted with the last request written then, refused past
//    MOST_EXPORTED_REQUESTS (a larger case is exported in parts, each
//    recorded and told); `access_log.exported` on its own chain (actor
//    system:operator, its ID the export's, naming the case reference, the
//    range, the count and the last request), a notice to every admin
//    (`access_log_exported`, 0053), and `operator.access_log_exported` on the
//    platform chain, locked last (ADR-006 §6: 12, then 13).
// 2. Then the seals: every sealed day the range's requests could be written
//    in (its first day to the day after its last, L6) digested again and
//    held to its seal. One that doesn't hold raises the alarm and holds the
//    organisation, and no file is written.
// 3. Then the file: the requests of the range written by then, newest first,
//    in batches, each row believed only as an admin's download believes it,
//    the same NDJSON lines, each actor named from what Agent X keeps; then
//    the store, once, as `<org>/activity-<export>.ndjson`.
import {
  ACTIVITY_SEALED,
  type ActivityCursor,
  activityInRange,
  type ActivityTables,
  digestOfDay,
  nextDay,
  sealHolds,
} from '@agentx/core/modules/activity';
import {
  createAuditTrail,
  type LogPage,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import {
  ACTIVITY_LOG_EXPORTED,
  activityActorsOf,
  activityNdjsonLine,
  type ActivityReadTables,
  createActorNamer,
  EXPORT_BATCH,
  type HeldActivityPage,
  heldActivityPage,
  MOST_EXPORTED_REQUESTS,
} from '@agentx/core/modules/evidence';
import { createOutbox, type NotificationsTables } from '@agentx/core/modules/notifications';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { type CaseExportRequest, CaseExportRefused, earlierRecord, runCaseExport, theExportId } from './case-export.ts';
import { OPERATOR, type OperatorTables } from './create-organization.ts';
import type { EvidenceStore } from './evidence-store.ts';

/** Every table the export reaches: both chains, the activity log and the names of its actors, and the admins' notice. */
export type ActivityExportTables = OperatorTables & ActivityReadTables & ActivityTables & NotificationsTables;

type ExportTx = DatabaseTransaction<ActivityExportTables>;

/** The platform's own record of an export, naming the organisation and the export. */
const PLATFORM_EXPORTED = 'operator.access_log_exported';

/** How many seals one read of the log takes, checking a range's. */
const SEALS_A_PAGE = 100;

/** How many rows one read of a day's digest takes. */
const DIGEST_BATCH = 5_000;

/** The widest range seals are read in: every seal ever made. */
const EVER = { from: new Date('2000-01-01T00:00:00.000Z'), to: new Date('2200-01-01T00:00:00.000Z') };

/** The export as recorded: how many requests, the last written then, and whether an earlier run recorded it. */
interface Recorded {
  readonly requests: number;
  readonly writtenUpTo: string | null;
  readonly recordedBefore: boolean;
}

/** Records the export on both chains and tells the admins, or finds an earlier run's record of it. */
function record(
  database: Database<ActivityExportTables>,
  services: SignedStatesServices,
  request: CaseExportRequest,
  mostRequests: number,
): Promise<Recorded> {
  const { orgId, exportId, from, to, caseRef, release, run } = request;
  const trail = createAuditTrail({ keys: services.keys, ids: theExportId(exportId) });
  const platform = createPlatformChain({ keys: services.keys, ids: services.ids });
  const outbox = createOutbox({ ids: uuidV7Ids, clock: systemClock });
  return withSignedStates(database, orgId, services, async (tx, states) => {
    const before = await earlierRecord(tx, states, trail, request, {
      action: ACTIVITY_LOG_EXPORTED,
      platformAction: PLATFORM_EXPORTED,
    });
    if (before !== undefined) {
      const { requests, writtenUpTo } = before;
      return {
        requests: Number(requests),
        writtenUpTo: typeof writtenUpTo === 'string' ? writtenUpTo : null,
        recordedBefore: true,
      };
    }
    const range = await activityInRange(tx, orgId, { from, to });
    if (range.rows > mostRequests) {
      throw new CaseExportRefused(
        `the range holds more than ${String(mostRequests)} requests: export it in parts, each its own request`,
      );
    }
    const shown = { from: from.toISOString(), to: to.toISOString() };
    await trail.record(tx, orgId, {
      actor: OPERATOR,
      action: ACTIVITY_LOG_EXPORTED,
      subject: { type: 'access_log', id: orgId, version: 1 },
      details: {
        caseRef,
        ...shown,
        actor: null,
        format: 'ndjson',
        requests: range.rows,
        writtenUpTo: range.writtenUpTo,
      },
    });
    await outbox.add(tx, [
      { orgId, recipientUserId: null, kind: 'access_log_exported', membershipId: null, role: null, aboutId: exportId },
    ]);
    await platform.record(tx, {
      actor: OPERATOR,
      action: PLATFORM_EXPORTED,
      details: { orgId, exportId, caseRef, ...shown, requests: range.rows, release, run },
    });
    return { requests: range.rows, writtenUpTo: range.writtenUpTo, recordedBefore: false };
  });
}

/**
 * Holds every sealed day the range's requests could be written in to its
 * seal: from the range's first day to the day after its last (a request
 * answered after midnight is written then). One that doesn't raises the
 * alarm and holds the organisation (withSignedStates), and is refused.
 */
async function sealsHold(
  database: Database<ActivityExportTables>,
  services: SignedStatesServices,
  { orgId, from, to }: CaseExportRequest,
): Promise<void> {
  const first = from.toISOString().slice(0, 10);
  const last = nextDay(new Date(to.getTime() - 1).toISOString().slice(0, 10));
  const inOrg = <T>(work: (tx: ExportTx, states: SignedStates) => Promise<T>) =>
    withSignedStates(database, orgId, services, work);
  let beforeSeq: bigint | null | undefined = undefined;
  while (beforeSeq !== null) {
    const before: bigint | undefined = beforeSeq;
    const page: LogPage = await inOrg((tx, states) =>
      states.logPageOf(tx, orgId, {
        ...EVER,
        actions: [ACTIVITY_SEALED],
        ...(before === undefined ? {} : { beforeSeq: before }),
        limit: SEALS_A_PAGE,
      }),
    );
    if (page.outcome !== 'read') throw new CaseExportRefused("the activity log's seals can't be verified");
    for (const { event } of page.events) {
      const { day } = event.details;
      if (typeof day !== 'string' || day < first || day > last) continue;
      const digest = await digestOfDay((work) => inOrg((tx) => work(tx)), orgId, day, DIGEST_BATCH);
      if (!sealHolds(digest, event.details)) {
        await inOrg((_tx, states) => {
          states.mismatch('access_log', { orgId, id: orgId });
          return Promise.resolve();
        });
        throw new CaseExportRefused(`the activity log of ${day} doesn't hold to its seal`);
      }
    }
    // Seals are made in day order: once past the range's first day, no older one is in it.
    const oldest: unknown = page.events.at(-1)?.event.details.day;
    beforeSeq = typeof oldest === 'string' && oldest < first ? null : page.next;
  }
}

/** The export's file: the range's requests written by `writtenUpTo`, newest first, as an admin's NDJSON download holds them. */
async function fileOf(
  database: Database<ActivityExportTables>,
  services: SignedStatesServices,
  { orgId, from, to }: CaseExportRequest,
  writtenUpTo: string | null,
  logger: Logger,
): Promise<Buffer> {
  const lines: string[] = [];
  // No login service here: people are named from the copy Agent X keeps (decision 27).
  const namer = createActorNamer({ directory: undefined, logger });
  // undefined: the first batch, from the newest; null: none left.
  let before: ActivityCursor | null | undefined = writtenUpTo === null ? null : undefined;
  while (before !== null && writtenUpTo !== null) {
    const start: ActivityCursor | undefined = before;
    const read: HeldActivityPage | 'tampered' = await withSignedStates(database, orgId, services, (tx, states) =>
      heldActivityPage(tx, states, services.keys, orgId, { from, to, before: start, writtenUpTo, limit: EXPORT_BATCH }),
    );
    if (read === 'tampered')
      throw new CaseExportRefused("an agent the range names, or its newest seal, can't be verified");
    const names = await namer.namesOf(activityActorsOf(read.rows), read.held);
    lines.push(...read.rows.map((row) => activityNdjsonLine(row, names, read.sealedDay)));
    before = read.next;
  }
  return Buffer.from(`${lines.join('\n')}\n`);
}

/** Exports the organisation's activity log for a case: the exit code, 0 once its file is in the store. */
export function exportActivityLog(
  database: Database<ActivityExportTables>,
  services: SignedStatesServices,
  store: EvidenceStore,
  request: CaseExportRequest,
  mostRequests = MOST_EXPORTED_REQUESTS,
): Promise<number> {
  const log = services.logger.child({ orgId: request.orgId });
  return runCaseExport(store, request, log, {
    command: 'activity-export',
    done: 'operator.activity_exported',
    file: `${request.orgId}/activity-${request.exportId}.ndjson`,
    record: () => record(database, services, request, mostRequests),
    shown: (made) => ({ requests: made.requests, writtenUpTo: made.writtenUpTo, recordedBefore: made.recordedBefore }),
    content: async (made) => {
      await sealsHold(database, services, request);
      return fileOf(database, services, request, made.writtenUpTo, log);
    },
  });
}
