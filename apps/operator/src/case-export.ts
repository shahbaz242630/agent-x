// What the operator's exports for a case share (Phase 3 E10c's audit log,
// L7's activity log, CO8b's one person's own activity log, whose run alone it
// shares; ADR-005 §6's second exception): the request, the steps
// of the record and of the run, and how each ends in the run's log. Each
// export says what it records, reads and writes; this says the order, and
// the rules on a request run again.
//
// - Its record: the organisation must exist and be verified; an export ID
//   already on its chain must be this same request's (the case, the range),
//   which then writes the file that wasn't, recording and telling nothing
//   again; an export ID on the platform chain for another organisation's is
//   refused (one export ID names one export).
// - Its run: recorded first, then the file, then the store, once. The run's
//   log names the export, the counts and the written file's SHA-256 alone,
//   never the case reference or a line of the file; a failure after the
//   record says so, to be run again.
import { createHash } from 'node:crypto';

import type { ReadEvent, SignedStates } from '@agentx/core/modules/audit';
import { OPERATOR_PERSON_LOG_EXPORTED } from '@agentx/core/modules/evidence';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { platformEventWith } from '@agentx/core/modules/platform-controls';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { OPERATOR, type OperatorTables } from './create-organization.ts';
import type { EvidenceStore } from './evidence-store.ts';

/** An export for a case, as its request asks it. */
export interface CaseExportRequest {
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

/** Why an export can't be made, never naming the case reference. */
export class CaseExportRefused extends Error {
  readonly problems: readonly string[];

  constructor(problem: string) {
    super(`The export refused: ${problem}`);
    this.name = 'CaseExportRefused';
    this.problems = [problem];
  }
}

/** Refused for an export ID that names any other record or export. */
export const ANOTHER_RECORD = 'the export ID names another record: write a new request';

/** The platform's record of an organisation's audit log export (E10c), naming the organisation and the export. */
export const AUDIT_PLATFORM_EXPORTED = 'operator.audit_log_exported';

/** The platform's record of an organisation's activity log export (L7), naming the organisation and the export. */
export const ACTIVITY_PLATFORM_EXPORTED = 'operator.access_log_exported';

/**
 * Every platform record of an export for a case, of whatever kind, each naming its export's ID (`exportId`): an
 * organisation's audit log or activity log, or one person's own activity log (CO8b).
 */
const PLATFORM_EXPORTS = [AUDIT_PLATFORM_EXPORTED, ACTIVITY_PLATFORM_EXPORTED, OPERATOR_PERSON_LOG_EXPORTED] as const;

/**
 * Whether the platform chain records an export of any kind with this ID: one export ID names one export, so an ID an
 * organisation's export took is never a person's, nor the other way round (CO8b review).
 */
export async function exportIdTaken(db: Parameters<typeof platformEventWith>[0], exportId: string): Promise<boolean> {
  for (const action of PLATFORM_EXPORTS) {
    if (await platformEventWith(db, action, { exportId })) return true;
  }
  return false;
}

/** The one ID the export's record takes: the request's. */
export const theExportId = (exportId: string): IdGenerator => ({ next: () => exportId });

/**
 * The details of an earlier run's record of this export, read under the
 * organisation's verified state; undefined for none, so the caller records
 * it. Refused for an organisation missing or tampered with, a log that can't
 * be believed, or an export ID that names any other record or export.
 */
export async function earlierRecord(
  tx: DatabaseTransaction<OperatorTables>,
  states: SignedStates,
  request: CaseExportRequest,
  action: string,
): Promise<ReadEvent['event']['details'] | undefined> {
  const { orgId, exportId } = request;
  const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
  if (organization.outcome === 'missing') throw new CaseExportRefused('no organisation has this ID');
  if (organization.outcome === 'tampered') throw new CaseExportRefused("the organisation's records can't be verified");
  // Through the signed states: a record that can't be believed raises the alarm and the hold (F1, G2).
  const found = await states.eventOf(tx, orgId, { eventId: exportId });
  if (found.outcome === 'tampered') throw new CaseExportRefused("the organisation's audit log can't be verified");
  if (found.event !== undefined) {
    const { event } = found.event;
    const same =
      event.action === action &&
      event.actor.type === OPERATOR.type &&
      event.actor.id === OPERATOR.id &&
      event.details.caseRef === request.caseRef &&
      event.details.from === request.from.toISOString() &&
      event.details.to === request.to.toISOString();
    if (!same) throw new CaseExportRefused(ANOTHER_RECORD);
    return event.details;
  }
  // Another organisation's export of this ID, or a person's: one export ID names one export.
  if (await exportIdTaken(tx, exportId)) throw new CaseExportRefused(ANOTHER_RECORD);
  return undefined;
}

/** The export's run, in its steps: what it recorded (and logs), and its file's content. */
export interface CaseExportSteps<Recorded> {
  /** Its command, as the run's failure names it. */
  readonly command: string;
  /** The line a written export ends with. */
  readonly done: 'operator.audit_exported' | 'operator.activity_exported' | 'operator.person_activity_exported';
  /** Where its file goes in the store. */
  readonly file: string;
  readonly record: () => Promise<Recorded & { readonly recordedBefore: boolean }>;
  /** What the run's log says of the record: never the case reference. */
  readonly shown: (recorded: Recorded & { readonly recordedBefore: boolean }) => Record<string, unknown>;
  readonly content: (recorded: Recorded) => Promise<Buffer>;
}

/** Runs the export: the exit code, 0 once its file is in the store. */
export async function runCaseExport<Recorded>(
  store: EvidenceStore,
  // An organisation's export or a person's (person-activity-export.ts): the run's lines name the export alone.
  request: Pick<CaseExportRequest, 'exportId'>,
  log: Logger,
  steps: CaseExportSteps<Recorded>,
): Promise<number> {
  const { exportId } = request;
  let made: Recorded & { readonly recordedBefore: boolean };
  try {
    made = await steps.record();
  } catch (error) {
    if (error instanceof CaseExportRefused) {
      log.error('operator.refused', { exportId, problems: error.problems });
    } else {
      log.error('operator.failed', { command: steps.command, exportId, err: error });
    }
    return 1;
  }
  // Recorded: from here a failure leaves the record without its file, and says so, to be run again.
  const recorded = { exportId, ...steps.shown(made) };
  try {
    const content = await steps.content(made);
    const write = await store.put(steps.file, content);
    // The hash of what this run wrote; a file there already is an earlier run's, which this one didn't write.
    const written =
      write === 'written' ? { bytes: content.length, sha256: createHash('sha256').update(content).digest('hex') } : {};
    log.info(steps.done, { ...recorded, file: steps.file, write, ...written });
    return 0;
  } catch (error) {
    log.error(
      'operator.export_unwritten',
      error instanceof CaseExportRefused ? { ...recorded, problems: error.problems } : { ...recorded, err: error },
    );
    return 1;
  }
}
