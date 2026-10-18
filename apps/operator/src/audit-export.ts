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
// again finds its record: the same request (case, range) writes the file
// that wasn't, to the same seq, recording and telling nothing again; any
// other is refused, in this organisation or another (the platform chain names
// every export). A file found there already is left as it is: the run says
// so, and names no hash of what it rebuilt. The record marks the read authorised, not that the file
// was written: a run that failed after it says so, and is run again.
import { createHash } from 'node:crypto';

import {
  createAuditTrail,
  eventsInRange,
  type ReadEvent,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import {
  AUDIT_LOG_EXPORTED,
  createActorNamer,
  EXPORT_BATCH,
  heldLogPage,
  type LogReadTables,
  MOST_EXPORTED_EVENTS,
  ndjsonLine,
} from '@agentx/core/modules/evidence';
import { createOutbox, type NotificationsTables } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createPlatformChain, platformEventWith } from '@agentx/core/modules/platform-controls';
import { type IdGenerator, systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { OPERATOR, type OperatorTables } from './create-organization.ts';
import type { EvidenceStore } from './evidence-store.ts';

/** Every table the export reaches: both chains, the names of the log's actors, and the admins' notice. */
export type AuditExportTables = OperatorTables & LogReadTables & NotificationsTables;

/** The platform's own record of an export, naming the organisation and the export. */
const PLATFORM_EXPORTED = 'operator.audit_log_exported';

export interface AuditExportRequest {
  readonly orgId: string;
  /** The export's ID, made where the request was written: its record's ID on the organisation's chain. */
  readonly exportId: string;
  readonly from: Date;
  readonly to: Date;
  /** The case it is for (CASE_REFERENCE): sealed on both chains, never logged. */
  readonly caseRef: string;
  readonly release: string;
  readonly run: string | null;
}

/** Why the export can't be made, never naming the case reference. */
class AuditExportRefused extends Error {
  readonly problems: readonly string[];

  constructor(problem: string) {
    super(`The audit export refused: ${problem}`);
    this.name = 'AuditExportRefused';
    this.problems = [problem];
  }
}

/** Refused for an export ID that names any other record or export. */
const ANOTHER_RECORD = 'the export ID names another record: write a new request';

/** The export as recorded: how many events, the newest one's seq, and whether an earlier run recorded it. */
interface Recorded {
  readonly events: number;
  readonly upToSeq: bigint | null;
  readonly recordedBefore: boolean;
}

/** The one ID the export's record takes: the request's. */
const theExportId = (exportId: string): IdGenerator => ({ next: () => exportId });

/** What the export's record names, as an admin's download records its own, the case reference beside. */
const detailsOf = ({ caseRef, from, to }: AuditExportRequest, events: number, upToSeq: bigint | null) => ({
  caseRef,
  from: from.toISOString(),
  to: to.toISOString(),
  actions: null,
  format: 'ndjson',
  events,
  upToSeq: upToSeq?.toString() ?? null,
});

/** An earlier run's record of this export: the same request's, or refused. */
function recordedBefore(found: ReadEvent, request: AuditExportRequest): Recorded {
  const { action, actor, details } = found.event;
  const same =
    action === AUDIT_LOG_EXPORTED &&
    actor.type === OPERATOR.type &&
    actor.id === OPERATOR.id &&
    details.caseRef === request.caseRef &&
    details.from === request.from.toISOString() &&
    details.to === request.to.toISOString();
  if (!same) throw new AuditExportRefused(ANOTHER_RECORD);
  const { events, upToSeq } = details;
  return {
    events: Number(events),
    upToSeq: typeof upToSeq === 'string' ? BigInt(upToSeq) : null,
    recordedBefore: true,
  };
}

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
    const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
    if (organization.outcome === 'missing') throw new AuditExportRefused('no organisation has this ID');
    if (organization.outcome === 'tampered') {
      throw new AuditExportRefused("the organisation's records can't be verified");
    }
    const found = await trail.recordedEvent(tx, orgId, { eventId: exportId });
    if (found.kind === 'broken') throw new AuditExportRefused("the organisation's audit log can't be verified");
    if (found.kind === 'recorded') return recordedBefore(found, request);
    // Another organisation's export of this ID: one export ID names one export.
    if (await platformEventWith(tx, PLATFORM_EXPORTED, { exportId })) throw new AuditExportRefused(ANOTHER_RECORD);
    const range = await eventsInRange(tx, orgId, { from, to, actions: undefined });
    if (range.events > mostEvents) {
      throw new AuditExportRefused(
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
      throw new AuditExportRefused("an event in the range, or an agent it names, can't be verified");
    }
    const names = await namer.namesOf(read.events, read.held);
    lines.push(...read.events.map((event) => ndjsonLine(event, names)));
    beforeSeq = read.next;
  }
  return Buffer.from(`${lines.join('\n')}\n`);
}

/** Exports the organisation's audit log for a case: the exit code, 0 once its file is in the store. */
export async function exportAuditLog(
  database: Database<AuditExportTables>,
  services: SignedStatesServices,
  store: EvidenceStore,
  request: AuditExportRequest,
  mostEvents = MOST_EXPORTED_EVENTS,
): Promise<number> {
  const log = services.logger.child({ orgId: request.orgId });
  const { exportId } = request;
  let made: Recorded;
  try {
    made = await record(database, services, request, mostEvents);
  } catch (error) {
    if (error instanceof AuditExportRefused) {
      log.error('operator.refused', { exportId, problems: error.problems });
    } else {
      log.error('operator.failed', { command: 'audit-export', exportId, err: error });
    }
    return 1;
  }
  // Recorded: from here a failure leaves the record without its file, and says so, to be run again.
  const recorded = {
    exportId,
    events: made.events,
    upToSeq: made.upToSeq?.toString() ?? null,
    recordedBefore: made.recordedBefore,
  };
  try {
    const content = await fileOf(database, services, request, made.upToSeq, log);
    const file = `${request.orgId}/${request.exportId}.ndjson`;
    const write = await store.put(file, content);
    // The hash of what this run wrote; a file there already is an earlier run's, which this one didn't write.
    const written =
      write === 'written' ? { bytes: content.length, sha256: createHash('sha256').update(content).digest('hex') } : {};
    log.info('operator.audit_exported', { ...recorded, file, write, ...written });
    return 0;
  } catch (error) {
    log.error(
      'operator.export_unwritten',
      error instanceof AuditExportRefused ? { ...recorded, problems: error.problems } : { ...recorded, err: error },
    );
    return 1;
  }
}
