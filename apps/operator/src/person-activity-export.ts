// CO8b (Phase 6; decision 26's L8, D2): the operator exports one person's own
// activity log for a case, a dispute or a regulator's request: their requests
// naming no organisation they are verified in (`access.person_requests`,
// 0052; read by the operator's role from 0092). Their requests in an
// organisation are that organisation's log, exported by activity-export.ts.
// Read only, and in an organisation's export's steps (activity-export.ts,
// case-export.ts's run), on the platform chain alone, as the log belongs to
// no organisation (D3):
//
// 1. Recorded first, in one transaction: the person must be one Agent X
//    knows; the range counted with the last row written then, refused past
//    MOST_EXPORTED_REQUESTS (a larger case is exported in parts, each its own
//    request); then `operator.person_log_exported` on the platform chain
//    (actor system:operator, signed, its ID the export's), naming the person,
//    the case reference, the range, the count and the last row. That record
//    is what the person's own My activity page lists (D2: a person is always
//    told when we read theirs out), so nothing is read before it.
// 2. Then the seals: every sealed day the range's rows could be written in
//    (its first day to the day after its last), with the seal next to them on
//    each side, held to its seal (core's brokenSealIn, as the API's check
//    holds them): one that doesn't, a seal missing between them, or a seal
//    that can't be believed raises the alarm (`audit.integrity_failed`,
//    check `person_log`; no hold, D3) and is refused, and no file is written.
//    Days past the newest seal are unsealed: said, and each row marked so.
// 3. Then the file: the person's rows of the range written by then, newest
//    first, in batches, as their own NDJSON download holds them, each marked
//    sealed or not; then the store, once, as
//    `persons/<user>/activity-<export>.ndjson`.
//
// The export's ID is made where the request was written, so a request run
// again finds its record: the same person, case and range writes the file
// that wasn't, recording nothing again; an ID naming any other record is refused.
import {
  type ActivityTables,
  brokenSealIn,
  dayOfId,
  idsOfDay,
  nextDay,
  type PersonActivityRow,
  PERSON_SEAL_FORM,
  personDigestOfDay,
  personInRange,
  personLogAlarm,
  personRowsWritten,
  writtenBeforeIn,
} from '@agentx/core/modules/activity';
import {
  EXPORT_BATCH,
  MOST_EXPORTED_REQUESTS,
  OPERATOR_PERSON_LOG_EXPORTED,
  personLogEventOf,
  personNdjsonLine,
  personSealsPage,
} from '@agentx/core/modules/evidence';
import { type IdentityTables, isUser } from '@agentx/core/modules/identity';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { type Database, type DatabaseTransaction, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { ANOTHER_RECORD, CaseExportRefused, exportIdTaken, runCaseExport, theExportId } from './case-export.ts';
import { OPERATOR } from './create-organization.ts';
import type { EvidenceStore } from './evidence-store.ts';

/** Every table the export reaches: the person log, the platform chain, and the people Agent X knows. */
export type PersonActivityExportTables = ActivityTables & PlatformControlsTables & IdentityTables;

type ExportTx = DatabaseTransaction<PersonActivityExportTables>;

/** One person's activity log export for a case, as its request asks it. */
export interface PersonActivityExportRequest {
  readonly userId: string;
  /** The export's ID, made where the request was written: its record's ID on the platform chain. */
  readonly exportId: string;
  readonly from: Date;
  readonly to: Date;
  /** The case it is for: sealed on the platform chain and shown to the person, never logged. */
  readonly caseRef: string;
  readonly release: string;
  readonly run: string | null;
}

/** What the export needs beside its database: the chain's keys, and where its lines go. */
export interface PersonActivityExportServices {
  readonly keys: KeyProvider;
  readonly logger: Logger;
}

/** How many seals one read of the platform chain takes, checking a range's. */
const SEALS_A_PAGE = 100;

/** How many rows one read of a day's digest takes. */
const DIGEST_BATCH = 5_000;

/** The export as recorded: how many rows, the last written then, and whether an earlier run recorded it. */
interface Recorded {
  readonly requests: number;
  readonly writtenUpTo: string | null;
  readonly recordedBefore: boolean;
}

/** A UTC day as the seals name one. */
const dayOf = (at: Date): string => at.toISOString().slice(0, 10);

/** An earlier run's record of this export, read from the platform chain and believed; undefined for none. */
async function earlierRecord(
  tx: ExportTx,
  { keys, logger }: PersonActivityExportServices,
  request: PersonActivityExportRequest,
): Promise<Recorded | undefined> {
  const found = await personLogEventOf(tx, keys, request.exportId);
  if (found === 'unsealed') {
    personLogAlarm(logger, 'unsealed', null);
    throw new CaseExportRefused("the platform audit chain's record of this export ID can't be verified");
  }
  if (found === undefined) {
    // An organisation's export of this ID: one export ID names one export.
    if (await exportIdTaken(tx, request.exportId)) throw new CaseExportRefused(ANOTHER_RECORD);
    return undefined;
  }
  const { action, actor, details } = found;
  const same =
    action === OPERATOR_PERSON_LOG_EXPORTED &&
    actor.type === OPERATOR.type &&
    actor.id === OPERATOR.id &&
    details.person === request.userId &&
    details.caseRef === request.caseRef &&
    details.from === request.from.toISOString() &&
    details.to === request.to.toISOString();
  if (!same) throw new CaseExportRefused(ANOTHER_RECORD);
  const { requests, writtenUpTo } = details;
  return {
    requests: Number(requests),
    writtenUpTo: typeof writtenUpTo === 'string' ? writtenUpTo : null,
    recordedBefore: true,
  };
}

/** Records the export on the platform chain, or finds an earlier run's record of it. */
function record(
  database: Database<PersonActivityExportTables>,
  services: PersonActivityExportServices,
  request: PersonActivityExportRequest,
  mostRequests: number,
): Promise<Recorded> {
  const { userId, exportId, from, to, caseRef, release, run } = request;
  const platform = createPlatformChain({ keys: services.keys, ids: theExportId(exportId) });
  return limitedTransaction(database, async (tx) => {
    const before = await earlierRecord(tx, services, request);
    if (before !== undefined) return before;
    if (!(await isUser(tx, userId))) throw new CaseExportRefused('no person has this user ID');
    const range = await personInRange(tx, userId, { from, to });
    if (range.rows > mostRequests) {
      throw new CaseExportRefused(
        `the range holds more than ${String(mostRequests)} of the person's requests: export it in parts, each its own request`,
      );
    }
    await platform.record(tx, {
      actor: OPERATOR,
      action: OPERATOR_PERSON_LOG_EXPORTED,
      details: {
        person: userId,
        exportId,
        caseRef,
        from: from.toISOString(),
        to: to.toISOString(),
        requests: range.rows,
        writtenUpTo: range.writtenUpTo,
        release,
        run,
      },
    });
    return { requests: range.rows, writtenUpTo: range.writtenUpTo, recordedBefore: false };
  });
}

type SealDetails = Readonly<Record<string, unknown>>;

/** The seals a range is held to, newest first, and the newest day sealed at all (null for none). */
interface RangeSeals {
  readonly checked: readonly SealDetails[];
  /** Whether the oldest seal there is is among them: then no row may be written before its day. */
  readonly oldestReached: boolean;
  readonly sealedThrough: string | null;
}

/**
 * The seals of every day from `first` to `last`, newest first, each believed, with the seal next to them on each
 * side (the nearest newer than `last` and the nearest older than `first`), so a seal missing at either edge is a gap
 * as one between them is. A seal that can't be believed raises the alarm and is refused.
 */
async function rangeSeals(
  inTx: <T>(work: (tx: ExportTx) => Promise<T>) => Promise<T>,
  { keys, logger }: PersonActivityExportServices,
  range: { readonly first: string; readonly last: string },
  sealsAPage: number,
): Promise<RangeSeals> {
  const walk: SealWalk = { checked: [], newer: undefined };
  let sealedThrough: string | null | undefined;
  let beforeSeq: bigint | null | undefined;
  while (beforeSeq !== null) {
    const start: bigint | undefined = beforeSeq;
    const page = await inTx((tx) => personSealsPage(tx, keys, { beforeSeq: start, limit: sealsAPage }));
    if (page === 'unsealed') {
      personLogAlarm(logger, 'unsealed', null);
      throw new CaseExportRefused("the person log's seals can't be verified");
    }
    const newest: unknown = page.events[0]?.details.day;
    sealedThrough ??= typeof newest === 'string' ? newest : null;
    if (takeSeals(walk, page.events, range)) return { checked: walk.checked, oldestReached: false, sealedThrough };
    beforeSeq = page.next;
  }
  // Every seal read: the range reaches back past the first seal, or is older than every seal but `newer`.
  if (walk.newer !== undefined) walk.checked.push(walk.newer);
  return { checked: walk.checked, oldestReached: true, sealedThrough: sealedThrough ?? null };
}

/** The seals taken so far, and the nearest newer than the range's last day seen, not yet taken. */
interface SealWalk {
  readonly checked: SealDetails[];
  newer: SealDetails | undefined;
}

/**
 * Takes a page of seals, newest first, into `walk`: a seal past the range's last day held back as the nearest newer
 * one until the range's first is met. Whether the seal older than the range's first day was taken: the walk's end.
 */
function takeSeals(
  walk: SealWalk,
  events: readonly { readonly details: SealDetails }[],
  { first, last }: { readonly first: string; readonly last: string },
): boolean {
  for (const { details } of events) {
    const { day } = details;
    if (typeof day === 'string' && day > last) {
      walk.newer = details;
      continue;
    }
    if (walk.newer !== undefined) walk.checked.push(walk.newer);
    walk.newer = undefined;
    walk.checked.push(details);
    // Seals are made in day order: past the range's first day, no older one is in it.
    if (typeof day === 'string' && day < first) return true;
  }
  return false;
}

/**
 * What the seals checked vouch for: the newest day sealed at all, and the IDs a row of the range may have, the days
 * checked (from the oldest seal checked; from any, when no seal is older) to the range's last.
 */
interface CheckedSeals {
  readonly sealedThrough: string | null;
  readonly idsFrom: string | null;
  readonly idsTo: string;
}

/**
 * Holds every sealed day the range's rows could be written in to its seal (step 2): what the seals checked vouch
 * for, or refused, the alarm raised, when one doesn't hold.
 */
async function sealsHold(
  database: Database<PersonActivityExportTables>,
  services: PersonActivityExportServices,
  { from, to }: PersonActivityExportRequest,
  { batch, sealsAPage }: { readonly batch: number; readonly sealsAPage: number },
): Promise<CheckedSeals> {
  const inTx = <T>(work: (tx: ExportTx) => Promise<T>): Promise<T> => limitedTransaction(database, work);
  // A row answered after midnight is written the day after its time.
  const range = { first: dayOf(from), last: nextDay(dayOf(new Date(to.getTime() - 1))) };
  const seals = await rangeSeals(inTx, services, range, sealsAPage);
  const broken = await brokenSealIn(seals.checked, seals.oldestReached, {
    digest: (day) => personDigestOfDay(inTx, day, batch),
    form: PERSON_SEAL_FORM,
    writtenBefore: (day) => inTx((tx) => writtenBeforeIn(tx, 'person', day)),
  });
  if (broken !== undefined) {
    personLogAlarm(services.logger, broken.why, broken.day);
    throw new CaseExportRefused(`the person log of ${broken.day} doesn't hold to its seal`);
  }
  // Not reached the oldest: the last seal checked is the one before the range's first day, a string (takeSeals).
  const oldest: unknown = seals.checked.at(-1)?.day;
  return {
    sealedThrough: seals.sealedThrough,
    idsFrom: !seals.oldestReached && typeof oldest === 'string' ? idsOfDay(oldest).from : null,
    idsTo: idsOfDay(range.last).to,
  };
}

/**
 * The file's rows, each held to the days the seals checked (CO8b review): a row of the range whose ID's day lies
 * outside them (its time moved into the range past the app, or its ID forged early or late) would be shown sealed by
 * a seal never read, or by none. It raises the alarm and is refused, and no file is written.
 */
function heldToSeals(rows: readonly PersonActivityRow[], { idsFrom, idsTo }: CheckedSeals, logger: Logger): void {
  const outside = rows.find(({ id }) => (idsFrom !== null && id < idsFrom) || id >= idsTo);
  if (outside === undefined) return;
  const day = dayOfId(outside.id);
  personLogAlarm(logger, 'misdated', day);
  throw new CaseExportRefused(`a request in the range was written on ${day}, outside the days its seals cover`);
}

/** The range's first day not sealed (null when every day of it is): its rows are marked unsealed. */
function unsealedFrom({ from, to }: PersonActivityExportRequest, sealedThrough: string | null): string | null {
  const first = dayOf(from);
  if (sealedThrough === null) return first;
  const next = nextDay(sealedThrough);
  if (next > dayOf(new Date(to.getTime() - 1))) return null;
  return next > first ? next : first;
}

/** The export's limits: MOST_EXPORTED_REQUESTS, and the batches it reads in, but for the tests. */
export interface PersonActivityExportLimits {
  readonly mostRequests?: number;
  /** The rows of a file's batch and of a day's digest. */
  readonly batch?: number;
  readonly sealsAPage?: number;
}

/** Exports one person's own activity log for a case: the exit code, 0 once its file is in the store. */
export function exportPersonActivityLog(
  database: Database<PersonActivityExportTables>,
  services: PersonActivityExportServices,
  store: EvidenceStore,
  request: PersonActivityExportRequest,
  { mostRequests = MOST_EXPORTED_REQUESTS, batch, sealsAPage = SEALS_A_PAGE }: PersonActivityExportLimits = {},
): Promise<number> {
  const { logger } = services;
  const { userId, exportId } = request;
  return runCaseExport(store, request, logger, {
    command: 'person-activity-export',
    done: 'operator.person_activity_exported',
    file: `persons/${userId}/activity-${exportId}.ndjson`,
    record: () => record(database, services, request, mostRequests),
    shown: (made) => ({ requests: made.requests, writtenUpTo: made.writtenUpTo, recordedBefore: made.recordedBefore }),
    content: async (made) => {
      // Every row marked against the seal read here: one landing mid-file would show a day half sealed.
      const checked = await sealsHold(database, services, request, { batch: batch ?? DIGEST_BATCH, sealsAPage });
      const { sealedThrough } = checked;
      logger.info('operator.person_log_seals', {
        exportId,
        sealedThrough,
        unsealedFrom: unsealedFrom(request, sealedThrough),
      });
      const read = <T>(work: (tx: ExportTx) => Promise<T>): Promise<T> => limitedTransaction(database, work);
      const rows = await personRowsWritten(read, userId, request, made.writtenUpTo, batch ?? EXPORT_BATCH);
      heldToSeals(rows, checked, logger);
      // Every row's ID is within the range's last day now, so a seal past it marks none it didn't check.
      return Buffer.from(`${rows.map((row) => personNdjsonLine(row, sealedThrough)).join('\n')}\n`);
    },
  });
}
