// Phase 3 E10c: the operator exports an organisation's audit log for a case,
// a dispute or a regulator's request (ADR-005 §6's second exception; partner
// decisions 24 and 27). Read only: it changes no authority row.
//
// 1. Recorded first, in one transaction, withSignedStates' for the
//    organisation, before a byte of the log is read out: the organisation
//    must exist and be verified; the range is counted, refused past
//    MOST_EXPORTED_EVENTS (a larger case is exported in parts, each recorded
//    and told); then `audit_log.exported` on its own chain (actor
//    system:operator, its ID the export's, naming the case reference, the
//    range, the count and the newest event's seq), a notice to every admin
//    (0050), and `operator.audit_log_exported` on the platform chain, locked
//    last (ADR-006 §6: 12, then 13). Both chains and the notice, or none.
// 2. Then the file: the whole log in the range up to that seq, newest first,
//    read in batches of EXPORT_BATCH, each event believed only whole as an
//    admin's download believes it (the evidence module), the same NDJSON
//    lines, each actor named from what Agent X keeps (decision 27). One that
//    can't be believed holds the organisation, and no file is written.
// 3. Then the store, once (evidence-store.ts): never the run's log, which
//    names the export, the counts and the written file's SHA-256 alone, never the case
//    reference or an event.
//
// The export's ID is made where the request was written, so a request run
// again finds its record (case-export.ts, which the activity log's export
// shares): the same request writes the file that wasn't, to the same seq,
// recording and telling nothing again; any other is refused. A file found
// there already is left as it is: the run says so, and names no hash of
// what it rebuilt. The record marks the read authorised, not that the file
// was written: a run that failed after it says so, and is run again.
import {
  createAuditTrail,
  eventsInRange,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import {
  actorsOf,
  AUDIT_LOG_EXPORTED,
  createActorNamer,
  EXPORT_BATCH,
  heldLogPage,
  type LogReadTables,
  MOST_EXPORTED_EVENTS,
  ndjsonLine,
} from '@agentx/core/modules/evidence';
import { createOutbox, type NotificationsTables } from '@agentx/core/modules/notifications';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { type CaseExportRequest, CaseExportRefused, earlierRecord, runCaseExport, theExportId } from './case-export.ts';
import { OPERATOR, type OperatorTables } from './create-organization.ts';
import type { EvidenceStore } from './evidence-store.ts';

/** Every table the export reaches: both chains, the names of the log's actors, and the admins' notice. */
export type AuditExportTables = OperatorTables & LogReadTables & NotificationsTables;

/** The platform's own record of an export, naming the organisation and the export. */
const PLATFORM_EXPORTED = 'operator.audit_log_exported';

/** An export of the audit log for a case, as its request asks it. */
export type AuditExportRequest = CaseExportRequest;

/** The export as recorded: how many events, the newest one's seq, and whether an earlier run recorded it. */
interface Recorded {
  readonly events: number;
  readonly upToSeq: bigint | null;
  readonly recordedBefore: boolean;
}

/** What the export's record names, as an admin's download records its own, the case reference beside. */
const detailsOf = ({ caseRef, from, to }: AuditExportRequest, events: number, upToSeq: bigint | null) => ({
  caseRef,
  from: from.toISOString(),
  to: to.toISOString(),
  actions: null,
  actor: null,
  format: 'ndjson',
  events,
  upToSeq: upToSeq?.toString() ?? null,
});

/** Records the export on both chains and tells the admins, or finds an earlier run's record of it. */
function record(
  database: Database<AuditExportTables>,
  services: SignedStatesServices,
  request: AuditExportRequest,
  mostEvents: number,
): Promise<Recorded> {
  const { orgId, exportId, from, to, caseRef, release, run } = request;
  const trail = createAuditTrail({ keys: services.keys, ids: theExportId(exportId) });
  const platform = createPlatformChain({ keys: services.keys, ids: services.ids });
  const outbox = createOutbox({ ids: uuidV7Ids, clock: systemClock });
  return withSignedStates(database, orgId, services, async (tx, states) => {
    const before = await earlierRecord(tx, states, trail, request, {
      action: AUDIT_LOG_EXPORTED,
      platformAction: PLATFORM_EXPORTED,
    });
    if (before !== undefined) {
      const { events, upToSeq } = before;
      return {
        events: Number(events),
        upToSeq: typeof upToSeq === 'string' ? BigInt(upToSeq) : null,
        recordedBefore: true,
      };
    }
    const range = await eventsInRange(tx, orgId, { from, to, actions: undefined });
    if (range.events > mostEvents) {
      throw new CaseExportRefused(
        `the range holds more than ${String(mostEvents)} events: export it in parts, each its own request`,
      );
    }
    const details = detailsOf(request, range.events, range.upToSeq);
    await trail.record(tx, orgId, {
      actor: OPERATOR,
      action: AUDIT_LOG_EXPORTED,
      subject: { type: 'audit_log', id: orgId, version: 1 },
      details,
    });
    await outbox.add(tx, [
      { orgId, recipientUserId: null, kind: 'audit_log_exported', membershipId: null, role: null, aboutId: exportId },
    ]);
    await platform.record(tx, {
      actor: OPERATOR,
      action: PLATFORM_EXPORTED,
      details: { orgId, exportId, caseRef, from: details.from, to: details.to, events: range.events, release, run },
    });
    return { events: range.events, upToSeq: range.upToSeq, recordedBefore: false };
  });
}

/** The export's file: every event of the range up to `upToSeq`, newest first, as an admin's NDJSON download holds them. */
async function fileOf(
  database: Database<AuditExportTables>,
  services: SignedStatesServices,
  { orgId, from, to }: AuditExportRequest,
  upToSeq: bigint | null,
  logger: Logger,
): Promise<Buffer> {
  const lines: string[] = [];
  // No login service here: people are named from the copy Agent X keeps (decision 27).
  const namer = createActorNamer({ directory: undefined, logger });
  let beforeSeq = upToSeq === null ? null : upToSeq + 1n;
  while (beforeSeq !== null) {
    const before = beforeSeq;
    const read = await withSignedStates(database, orgId, services, (tx, states) =>
      heldLogPage(tx, states, services.keys, orgId, { from, to, beforeSeq: before, limit: EXPORT_BATCH }),
    );
    if (read === 'tampered') {
      throw new CaseExportRefused("an event in the range, or an agent it names, can't be verified");
    }
    const names = await namer.namesOf(actorsOf(read.events), read.held);
    lines.push(...read.events.map((event) => ndjsonLine(event, names)));
    beforeSeq = read.next;
  }
  return Buffer.from(`${lines.join('\n')}\n`);
}

/** Exports the organisation's audit log for a case: the exit code, 0 once its file is in the store. */
export function exportAuditLog(
  database: Database<AuditExportTables>,
  services: SignedStatesServices,
  store: EvidenceStore,
  request: AuditExportRequest,
  mostEvents = MOST_EXPORTED_EVENTS,
): Promise<number> {
  const log = services.logger.child({ orgId: request.orgId });
  return runCaseExport(store, request, log, {
    command: 'audit-export',
    done: 'operator.audit_exported',
    file: `${request.orgId}/${request.exportId}.ndjson`,
    record: () => record(database, services, request, mostEvents),
    shown: (made) => ({
      events: made.events,
      upToSeq: made.upToSeq?.toString() ?? null,
      recordedBefore: made.recordedBefore,
    }),
    content: (made) => fileOf(database, services, request, made.upToSeq, log),
  });
}
