// Signed state (ADR-012 §2): every field that grants, restores or limits
// authority must equal the object's latest signed event, and every
// security-path read goes through verifiedState:
// 1. it finds the object's latest signed event in the audit log itself, never
//    from the row's own pointer (latestSignedState)
// 2. the row must point at exactly that event, at that event's version
// 3. the row's fields must match the event's seal: a keyed hash over the
//    organisation, the object's type, ID and version and each field, which
//    someone with only the database can't make
// So a field changed past the app, a row pointed back at an older valid event
// (a key "un-revoked"), a seal stripped or forged, or a row deleted, is denied
// and raises the integrity alarm (`audit.integrity_failed`, SEV-1). Every
// tamper sign is also handed to `onTamper`, and withSignedStates, the one way
// product code gets signed states, puts the organisation on its integrity
// hold for each once the transaction has ended (with-signed-states.ts).
//
// The hold itself is a signed state kept in the log alone, with no row
// (domain/integrity-hold.ts): read by integrityHold, started CLEAR with the
// organisation, and set HELD by `hold`, which adds its event whatever state
// the rest of the organisation is in.
//
// The read locks the row (ADR-006 §6): `share` for a decision, `change` when
// the transaction will change it, never one and then the other. A change must
// commit before a reader can lock the row, and it records its event in the
// same transaction, so a check never meets a row and a log from either side
// of one change.
//
// Every change records the new state: record writes the authority fields the
// change names, moving the row to its next version, and reads the row back. It
// must hold exactly the verified state with those values written: a trigger or
// rule planted in the table that changed any field on the way is caught there,
// before anything is sealed, rather than sealed as if the app had written it.
// Then the fields are sealed, the event goes to the audit chain (ADR-007
// §1.3's history row, ADR-014 §8) and the row points at it. A change starts
// from a state verified for change in the same transaction, so a field
// tampered with before it can't be changed and sealed as if it were real.
// Events about an authority object are its state changes only: activity goes
// against other subjects.
import { type AnchorPoint, sealState, stateSealDetails, stateSealMatches } from '@agentx/platform/audit-chain';
import {
  createStatusChanger,
  type FieldText,
  type GatheredRow,
  gatheredRowReads,
  MOST_SIGNED_ROWS_READ,
  readSignedRow,
  readSignedRows,
  type RowLock,
  type SignedFieldValues,
  type SignedRow,
  type SignedRowKey,
  signedRowIds,
  signedRowReadSeen,
  signedRowSeen,
  signedRowPointed,
  signedRowPointing,
  type SignedStateTable,
  StatusChangeFailed,
  type StatusTable,
  writeSignedRow,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { UUID } from '../../../shared-kernel/index.ts';
import { type AuditActor, type AuditDetails, type AuditEvent, AuditEventRefused } from '../domain/event.ts';
import {
  HISTORY_CHECK_SUBJECT,
  HOLD_SUBJECT,
  INTEGRITY_HOLD,
  INVESTIGATION_SUBJECT,
  type InvestigationConclusion,
  isIncidentReference,
  isInvestigationConclusion,
} from '../domain/integrity-hold.ts';
import {
  type AuditTrail,
  type AuditTransaction,
  type EventToFind,
  type GatheredLatest,
  type HistoryToRead,
  type LogEvent,
  type LogPageToRead,
  type LatestSignedState,
  type LatestWithRow,
  lockChainHead,
  type ReadEvent,
  type RecordedAuditEvent,
  type RecordedEventCheck,
  type RecordedEventsCheck,
  recordHoldEvent,
  TooManyEventsAboutObject,
  TooManyEventsToRead,
} from './audit-trail.ts';

/**
 * Where a row and its signed state part:
 * - `row`: the row can't be read as the app writes it, or, locked for a
 *   change, didn't hold exactly what the change wrote
 * - `deleted`: the row is gone but its signed state is in the log (the app
 *   role can't delete)
 * - `unsigned`: the row exists but no event about it carries a seal
 * - `log`: its signed events can't be believed: the latest, or one after it,
 *   fails its own check, or one exists for a row being created
 * - `pointer`: the row points at another event than the latest signed one
 * - `version`: the row's version isn't the latest signed event's
 * - `seal`: the row's fields aren't the ones sealed
 * - `status`: a status change on a verified row failed as only something
 *   past the app could make it fail
 * - `chain`: the organisation's audit chain failed the anchor check (B1d-3;
 *   its alarm line names how), found by no read of a row
 * - `holding`: what a verified object holds elsewhere (a request's
 *   reservation or order claim, Phase 2 E1) isn't what its signed state
 *   says it must be (`mismatch`), or the log lacks an event its signed
 *   state stands on (a pending request's decision: a chain wound back, H7)
 */
export type TamperSign =
  'row' | 'deleted' | 'unsigned' | 'log' | 'pointer' | 'version' | 'seal' | 'status' | 'chain' | 'holding';

/** A tamper sign, as the alarm names it: the organisation and the object's type and ID (IDs in lower case), and the sign. */
export interface TamperFinding {
  readonly orgId: string;
  readonly subjectType: string;
  readonly objectId: string;
  readonly sign: TamperSign;
  /** For the sign `chain`: how the chain failed the anchor check, as its alarm names it. */
  readonly chainFailure?: string;
}

/**
 * The organisation's integrity hold, from its newest signed event: verified
 * `clear` or `held`, or tampered with (the alarm is raised, and the hold is
 * set once the transaction ends). Only a verified `clear` lets anything the
 * hold stops through.
 */
type HoldCheck =
  | { readonly outcome: 'clear' | 'held'; readonly version: number; readonly eventId: string }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The subject a chain's own failure is held under: the organisation's chain, by its ID (anchorKept, holdOrganisation). */
export const CHAIN_SUBJECT = 'audit_chain';

/** The chain against its last anchor: still holding it, or wound back (the alarm raised). */
type AnchorKept = { readonly outcome: 'kept' } | { readonly outcome: 'tampered'; readonly sign: 'chain' };

/** The row's state, matched with its latest signed event. */
export interface VerifiedState {
  readonly outcome: 'verified';
  readonly version: number;
  readonly eventId: string;
  /** When that event was recorded, as the chain seals it (a waiting request's decision: D7). */
  readonly recordedAt: Date;
  /** The authority fields, by column, exactly as sealed: canonical text, or null. */
  readonly fields: ReadonlyMap<string, string | null>;
}

/**
 * The row verified; no such row in this organisation; or tampered with (the
 * alarm is already raised). The caller denies both of the last two: a missing
 * row never means "no limit", so a freeze is a status on a row that always
 * exists, never a row whose absence lifts it (and the integrity hold a state
 * the log holds from the organisation's creation on).
 */
export type StateCheck =
  VerifiedState | { readonly outcome: 'missing' } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * A page's row that can't be judged now (Phase 3 A1b, partner decision 5): its
 * object has more events since its newest signed one than one read takes
 * (BackloggedRead). Not a tamper sign; the page leaves it out and says so.
 */
export type PageCheck = StateCheck | { readonly outcome: 'backlog' };

/**
 * A table verifyAll checks: all of it, or, for one whose rows only grow (a
 * spend request's, Phase 2 D1), its rows in `liveStatuses` alone: those that
 * can still act. One moved back to a live status is listed, so checked; an
 * ended one, or a live one moved to an end or deleted, is not judged here:
 * clearing reads the record its hold names, the whole history is checked in
 * batches before a clearing is confirmed (Phase 2 D1c), and claims and
 * reservations are reconciled with the log (E1).
 */
export interface CheckedTable extends SignedStateTable {
  readonly liveStatuses?: readonly string[];
}

/**
 * Every object of the tables checked (verifyAll; a growing table's live rows):
 * all verified, with how many there were; some tampered with, each finding
 * named (every alarm is already raised); or more objects in one table than the
 * limit, with none judged.
 */
export type OrganisationCheck =
  | { readonly outcome: 'verified'; readonly objects: number }
  | { readonly outcome: 'tampered'; readonly findings: readonly TamperFinding[] }
  | { readonly outcome: 'too_many'; readonly subjectType: string };

/**
 * One batch of a growing table's whole history (checkHistoryBatch): its
 * objects after `after`, every status and every one the log holds an event
 * about, verified; with the last ID judged, to start the next batch after,
 * and whether none was left past it. Or some tampered with, each named (every
 * alarm is already raised).
 */
export type HistoryBatch =
  | { readonly outcome: 'checked'; readonly objects: number; readonly last: string | null; readonly done: boolean }
  | { readonly outcome: 'tampered'; readonly findings: readonly TamperFinding[] };

/**
 * Whether a HELD state's whole history was checked (historyChecked): checked,
 * not yet, or the record of it can't be believed (the alarm is raised).
 */
export type HistoryCheckRecord = 'checked' | 'unchecked' | 'tampered';

/**
 * The hold as its newest signed event holds it, for showing (holdRecord):
 * CLEAR or HELD since that event, with what a HELD one names as found, or
 * tampered with (the alarm is raised).
 */
export type HoldRecord =
  | { readonly outcome: 'clear'; readonly version: number; readonly since: Date }
  | {
      readonly outcome: 'held';
      readonly version: number;
      readonly eventId: string;
      readonly since: Date;
      /** The tamper sign that set it, and the object type it was found on; null where the event names none. */
      readonly reason: string | null;
      readonly foundOn: string | null;
    }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** An investigation of a hold, as its event records it (domain/integrity-hold.ts). */
export interface HoldInvestigation {
  readonly id: string;
  /** The HELD state it investigated: the hold's version and that state's event. */
  readonly holdVersion: number;
  readonly holdEventId: string;
  readonly conclusion: InvestigationConclusion;
  readonly reference: string;
  /** The person who recorded it, by their user ID. */
  readonly recordedBy: string;
  readonly recordedAt: Date;
}

/** What recording an investigation did: recorded; refused, the hold not HELD; or the hold tampered with. */
export type InvestigationRecording =
  | { readonly outcome: 'recorded'; readonly investigation: HoldInvestigation }
  | { readonly outcome: 'not_held' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * What clearing the hold did: cleared, as its newest signed state; refused,
 * the hold not HELD, HELD in another state than the one asked about (set
 * again, or cleared and set again, since), or with no investigation of that
 * HELD state by that ID; or the hold, or the investigation, tampered with.
 */
export type HoldClearing =
  | { readonly outcome: 'cleared'; readonly version: number; readonly eventId: string }
  | { readonly outcome: 'not_held' | 'moved_on' | 'no_investigation' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The step-up a clearing was confirmed with, as its event records it (identity's stepUpDetails). */
export type ClearingStepUp = Readonly<Record<string, string>> & { readonly stepUpChallengeId: string };

/** An investigation read by its ID: found; no investigation of this organisation's has it; or its event tampered with. */
export type InvestigationCheck =
  | { readonly outcome: 'found'; readonly investigation: HoldInvestigation }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** Who made a change, and the facts about it; the subject and the seal are added. */
export interface SignedChange {
  readonly actor: AuditActor;
  readonly action: string;
  readonly details: AuditDetails;
}

export interface RecordedState {
  readonly version: number;
  readonly eventId: string;
  readonly seq: bigint;
}

/** A status change with its signed event: as a status change, or refused on the row's verified state. */
/** A status change that moved the row. */
type SignedStatusChanged<State extends string> = Extract<SignedStatusChange<State>, { outcome: 'changed' }>;

export type SignedStatusChange<State extends string> =
  | {
      readonly outcome: 'changed';
      readonly from: State;
      readonly to: State;
      readonly version: number;
      readonly eventId: string;
      /** The state recorded, as sealed and read back with its pointer: what a fresh answer shows (4D2d P8). */
      readonly state: VerifiedState;
    }
  | { readonly outcome: 'refused'; readonly from: State }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * A signed state couldn't be read or recorded as asked:
 * - `basis`: record was given a state that isn't the latest verified for
 *   change on this row, with this table, in this transaction (or was used
 *   once already), or `new` for a row that isn't new
 * - `lock_order`: a row read for a decision (`share`) was then read for a
 *   change in the same transaction, a lock upgrade ADR-006 §6 forbids
 * - `not_applied`: the row didn't hold what the change wrote, or didn't take
 *   its pointer (the alarm is raised: the row was locked)
 * - `tampered`: a row being created can't be read, or the log already holds
 *   a signed state for it (the alarm is raised)
 * The caller's transaction must roll back: throwing out of withTenant does.
 */
export class SignedStateFailed extends Error {
  readonly reason: 'basis' | 'lock_order' | 'not_applied' | 'tampered';

  constructor(reason: SignedStateFailed['reason'], message: string) {
    super(message);
    this.name = 'SignedStateFailed';
    this.reason = reason;
  }
}

/** A history read from the log (historyOf): every event, whole; or tampered with, with the alarm raised. */
export type HistoryCheck =
  | { readonly outcome: 'read'; readonly events: readonly ReadEvent[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** One event read from the log (eventOf): whole, or none found; or tampered with, with the alarm raised. */
export type EventRead =
  | { readonly outcome: 'read'; readonly event: ReadEvent | undefined }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** A page of the whole log (logPageOf): its events newest first and the next page's start; or tampered with, the alarm raised. */
export type LogPage =
  | { readonly outcome: 'read'; readonly events: readonly LogEvent[]; readonly next: bigint | null }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The check verifiedStates gave the row `id`, in lower case as the database
 * lists IDs: it answers every ID asked, so one missing is a bug, never a row
 * to believe.
 */
/**
 * The checks, every row judged: a backlogged one refuses them all as
 * latestSignedState does one (TooManyEventsAboutObject; partner decision 5),
 * for any read but a list's page.
 */
function whole(checks: ReadonlyMap<string, PageCheck>): ReadonlyMap<string, StateCheck> {
  const judged = new Map<string, StateCheck>();
  for (const [id, check] of checks) {
    if (check.outcome === 'backlog') throw new TooManyEventsAboutObject();
    judged.set(id, check);
  }
  return judged;
}

export function checkOf<Check extends PageCheck>(checks: ReadonlyMap<string, Check>, id: string): Check {
  const check = checks.get(id);
  if (check === undefined) throw new Error(`A row was asked for and not read: ${id}`);
  return check;
}

export interface SignedStates {
  /**
   * The row's state, verified against the log (ADR-012 §2), in the caller's
   * transaction, which must be withTenant's for the row's organisation. The
   * row stays locked as asked to the end of the transaction.
   */
  verifiedState(tx: AuditTransaction, table: SignedStateTable, key: SignedRowKey, lock: RowLock): Promise<StateCheck>;
  /**
   * Reads and locks the organisation's rows in the order given (the lock
   * order, ADR-006 §6), each with its newest signed event, in one statement
   * (4D2d P8), so that the next verifiedState of each, with the lock it was
   * gathered with, answers from this read with no trip of its own. Judged as
   * verifiedState judges its own one-statement read: a row that changed while
   * the statement waited for a lock, or that disagrees with its log, is left
   * for that verifiedState to read again, and only that read raises an
   * alarm. A row's ID can come from an earlier row (GatheredId). Each row's
   * ID as its read named it, in the order given, null for none found.
   */
  gather(tx: AuditTransaction, orgId: string, rows: readonly GatheredRow[]): Promise<readonly (string | null)[]>;
  /**
   * verifiedState for many rows of one table in the organisation, each locked
   * `share`: the rows in one statement and their signed states in another,
   * each judged alone as verifiedState judges one, its alarm raised the same.
   * Each ID asked, in lower case, has its check in the map. A row not found
   * whole is read again on its own, through verifiedState. At most 500 rows
   * (readSignedRows).
   */
  verifiedStates(
    tx: AuditTransaction,
    table: SignedStateTable,
    orgId: string,
    ids: readonly string[],
  ): Promise<ReadonlyMap<string, StateCheck>>;
  /**
   * verifiedStates for a page of a list (verifiedPage): a row whose object
   * has a backlog of events is answered `backlog` rather than refusing the
   * whole page, which verifiedStates and verifyAll do (Phase 3 A1b).
   */
  pageStates(
    tx: AuditTransaction,
    table: SignedStateTable,
    orgId: string,
    ids: readonly string[],
  ): Promise<ReadonlyMap<string, PageCheck>>;
  /**
   * Every object of these tables in the organisation, verified as
   * verifiedState does and locked `share`, for a decision that rests on
   * nothing of the organisation's being tampered with (clearing its integrity
   * hold, B3+). The objects are the table's rows and every object the log
   * holds an event about, so a row deleted is found as well as one changed or
   * planted: one listed but with neither a row nor a signed state when read is
   * `deleted` too (its seals stripped as well), with its alarm. Table by
   * table in the order given, which must be the lock order's (ADR-006 §6),
   * and by ID within each. Past `limit` rows, or objects in the log, in one
   * table: `too_many`, with nothing more judged. A table with `liveStatuses`
   * is checked in its live rows alone (CheckedTable).
   */
  verifyAll(
    tx: AuditTransaction,
    orgId: string,
    tables: readonly CheckedTable[],
    limit: number,
  ): Promise<OrganisationCheck>;
  /**
   * Writes the authority fields `set` names and records the row's new state,
   * in this transaction. From `from`: the state verifiedState last gave for
   * change on this row, with this same table, here (each one used once); or
   * `new`, for a row the transaction has just inserted, where `set` names
   * every field. A status changes only through changeStatus. Takes the audit
   * head's lock, which comes last (ADR-006 §6).
   */
  record(
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    from: VerifiedState | 'new',
    set: SignedFieldValues,
    change: SignedChange,
  ): Promise<RecordedState>;
  /**
   * The one step for a status change on an authority row: verified for
   * change, moved by the table's machine (createStatusChanger), and recorded,
   * with the move's `statusFrom` and `statusTo` added to the details.
   */
  changeStatus<State extends string, Event extends string>(
    tx: AuditTransaction,
    table: SignedStateTable & StatusTable<State, Event>,
    key: SignedRowKey,
    event: NoInfer<Event>,
    change: SignedChange,
  ): Promise<SignedStatusChange<State>>;
  /**
   * `record` of a row just inserted and `changeStatus` straight after, in one
   * step of the chain (4D2d P13): the row written and moved first, then the
   * head locked once and both events written with the row's pointer in one
   * statement, so this row's step holds the head for that alone (unless the
   * transaction took it earlier). The events are as those two would record,
   * sharing one time. A move its machine refuses throws: nothing
   * is signed, so the caller's transaction must not commit the row.
   */
  recordNewAndMove<State extends string, Event extends string>(
    tx: AuditTransaction,
    table: SignedStateTable & StatusTable<State, Event>,
    key: SignedRowKey,
    set: SignedFieldValues,
    change: SignedChange,
    event: NoInfer<Event>,
    moveChange: SignedChange,
  ): Promise<SignedStatusChanged<State>>;
  /**
   * One batch of a growing table's whole history (Phase 2 D1c): the objects
   * after `after` (null from the start), its rows in every status and every
   * object the log holds an event about, at most `size`, each verified as
   * verifyAll does and locked `share`. In the caller's transaction, which
   * must be withSignedStates' for the organisation.
   */
  checkHistoryBatch(
    tx: AuditTransaction,
    orgId: string,
    table: SignedStateTable,
    after: string | null,
    size: number,
  ): Promise<HistoryBatch>;
  /**
   * The table's next objects in the organisation after `after` (null from the
   * start), at most `size`, by ID: its rows and every object the log holds an
   * event about, so one whose row was deleted is listed too (a read of it is
   * then `deleted`); and the ID to list the next after, or null for the last.
   */
  objectIds(
    tx: AuditTransaction,
    orgId: string,
    table: SignedStateTable,
    after: string | null,
    size: number,
  ): Promise<{ readonly ids: readonly string[]; readonly next: string | null }>;
  /**
   * The newest investigation of the HELD state `holdEventId` names, by its ID,
   * or null for none yet: the one the API's job checks the whole history
   * after (D1c review), so the check runs once the cause is declared removed.
   */
  latestInvestigation(tx: AuditTransaction, orgId: string, holdEventId: string): Promise<string | null>;
  /**
   * Records that the whole history was checked (`objects` of them) after the
   * investigation `investigationId`, by the API's job: refused (`basis`)
   * unless the hold is still HELD in the state that investigation is of, read
   * with the chain head's lock.
   */
  recordHistoryChecked(tx: AuditTransaction, orgId: string, investigationId: string, objects: number): Promise<void>;
  /**
   * Whether the hold's newest event, as the table holds it and believed in
   * nothing, set it: a cheap look for a job before it makes the verified read
   * (holdRecord), which alone decides anything. Raises no alarm.
   */
  mayBeHeld(tx: AuditTransaction, orgId: string): Promise<boolean>;
  /** Whether the whole history was checked after the investigation `investigationId`. */
  historyChecked(tx: AuditTransaction, orgId: string, investigationId: string): Promise<HistoryCheckRecord>;
  /**
   * The organisation's integrity hold, from the log, in the caller's
   * transaction (withTenant's for it). Anything the hold stops goes ahead
   * only on `clear`. A decision that must not pass a hold being set, as a
   * freeze can't be passed (Tx A), reads it with `lock: 'head'`: the chain
   * head's lock is taken first, so a hold being set is waited for, and one
   * set later comes after the decision's own events in the chain. That lock
   * comes last of all (ADR-006 §6): every row is locked before this read,
   * and a row this transaction hasn't read through verifiedState yet is
   * refused after it (`lock_order`). A hold this
   * process found but couldn't record yet reads as `tampered` with the sign
   * that found it, until it is recorded.
   */
  integrityHold(tx: AuditTransaction, orgId: string, lock: 'none' | 'head'): Promise<HoldCheck>;
  /**
   * Whether the organisation's chain still holds its last anchor (ADR-012 §2:
   * Tx A refuses a head behind it), read after integrityHold's `head` lock in
   * this transaction, so the chain can't move between the two. One wound back
   * raises the alarm and holds the organisation as the anchor check would
   * (the sign `chain`), and reads `tampered`. The anchor is the caller's, held
   * apart from the database; with none yet (a process just started), there is
   * nothing to compare and the anchor check's next run decides.
   */
  anchorKept(tx: AuditTransaction, orgId: string, anchor: AnchorPoint): Promise<AnchorKept>;
  /**
   * Records a new organisation's integrity hold, CLEAR, as its first state, in
   * the transaction that creates the organisation: after `record(…, 'new')`
   * of the organisation's own row (its ID the organisation's) with these
   * signed states, as the chain's first event, and once; otherwise `basis`. So
   * the log held nothing for the hold before, and a hold whose events were
   * deleted can't be started again as CLEAR.
   */
  startIntegrityHold(tx: AuditTransaction, orgId: string, actor: AuditActor): Promise<RecordedState>;
  /**
   * The hold for showing, from its newest signed event and that event itself,
   * read as integrityHold reads it with no lock: nothing is decided on it.
   */
  holdRecord(tx: AuditTransaction, orgId: string): Promise<HoldRecord>;
  /**
   * Records an investigation of the organisation's hold (B3+-2b), by a person
   * (a user, never the app or an agent), only while the hold is a verified
   * HELD: read with the chain head's lock, which comes last (ADR-006 §6), so
   * no hold set or cleared meanwhile is missed. `id` is the investigation's
   * own, new. The conclusion and reference are checked first (RangeError).
   */
  recordInvestigation(
    tx: AuditTransaction,
    orgId: string,
    investigation: {
      readonly id: string;
      readonly actor: AuditActor;
      readonly conclusion: InvestigationConclusion;
      readonly reference: string;
    },
  ): Promise<InvestigationRecording>;
  /** An investigation of the organisation's hold by its ID, from its event in the log, believed only whole. */
  holdInvestigation(tx: AuditTransaction, orgId: string, id: string): Promise<InvestigationCheck>;
  /**
   * Every event about an object of `find`'s types (one object alone, when it
   * names one) in the organisation's log, in chain order, each believed only
   * whole (the trail's recordedEvents): a history a decision rests on, such
   * as who granted a member's role (ADR-012 §1). One that isn't whole raises
   * the alarm and holds the organisation. Past `find.limit` events it throws
   * TooManyEventsToRead.
   */
  historyOf(tx: AuditTransaction, orgId: string, find: HistoryToRead): Promise<HistoryCheck>;
  /**
   * Reads these histories in one statement (4D2d P8, the trail's
   * recordedHistories), so that the next historyOf of each, asked alike in
   * this transaction, answers from this read with no trip of its own, once.
   * Judged as historyOf judges each, its alarm raised by that historyOf, so a
   * history read here and never asked raises none, as one never read. A
   * history past its limit leaves them all to their own reads.
   */
  gatherHistories(tx: AuditTransaction, orgId: string, finds: readonly HistoryToRead[]): Promise<void>;
  /**
   * One event of the organisation's log, by its ID or its object (the trail's
   * recordedEvent), believed only whole: a record an answer rests on, such as
   * an export's or a download's (Phase 3 F1, G2). One that isn't whole raises
   * the alarm and holds the organisation, as historyOf's.
   */
  eventOf(tx: AuditTransaction, orgId: string, find: EventToFind): Promise<EventRead>;
  /**
   * A page of the organisation's whole log for its admins (E10; the trail's
   * logPage), any event that can't be believed raising the alarm and the
   * hold, as historyOf's: never a page with it left out.
   */
  logPageOf(tx: AuditTransaction, orgId: string, find: LogPageToRead): Promise<LogPage>;
  /**
   * Clears the organisation's hold (ADR-012 §2, B3+-2c): a person, never the
   * app or an operator alone (invariant 13), with the step-up they confirmed
   * it with, from the HELD state recorded by `holdEventId`, after that
   * state's investigation, and only once verifyAll has verified the
   * organisation's authority objects (a growing table's live rows) in this
   * same transaction (otherwise `basis`): a hold is never cleared over a
   * record still tampered with. The
   * hold is read with the chain head's lock, which comes last (ADR-006 §6).
   */
  clearIntegrityHold(
    tx: AuditTransaction,
    orgId: string,
    clearing: {
      readonly actor: AuditActor;
      /** The HELD state asked about, by its event: the event names its version too. */
      readonly holdEventId: string;
      readonly investigationId: string;
      readonly stepUp: ClearingStepUp;
    },
  ): Promise<HoldClearing>;
  /**
   * Raises the integrity alarm for the object `key` names, verified here, for
   * rows it holds in a table with no signed state of its own that don't match
   * it (`holding`, E1: a request's reservation or order claim, ADR-012 §2).
   * The organisation is put on hold as for any tamper sign, once the
   * transaction ends (withSignedStates).
   */
  mismatch(subjectType: string, key: SignedRowKey): void;
}

/**
 * The signed states withSignedStates works with: these can also set the hold,
 * which only it does, in a transaction of its own once the one that found the
 * tampering has ended.
 */
export interface HoldingSignedStates extends SignedStates {
  /**
   * Puts the finding's organisation on hold, in this transaction (withTenant's
   * for it): HELD, recorded as its newest signed state, unless a verified
   * HELD is already there (`already`). Over a hold that can't be verified the
   * event is added all the same, so the hold can be set whatever has been
   * tampered with, as long as the chain takes new events. Locks the chain head
   * first, so two can't both start from the same state; the transaction takes
   * no other lock.
   */
  hold(tx: AuditTransaction, finding: TamperFinding, findings: number): Promise<'set' | 'already'>;
}

type FoundRow = Extract<SignedRow, { outcome: 'found' }>;

/** A row this transaction has read: the lock it holds, and the state it may record a change from. */
interface Held {
  lock: RowLock;
  from?: { readonly table: SignedStateTable; readonly state: VerifiedState };
  /** The state this transaction just recorded on the row, still locked, for changeStatus to go on from (4D2d P3b). */
  wrote?: { readonly table: SignedStateTable; readonly state: VerifiedState };
}

/** A history as gatherHistories keeps it: the organisation and every field of the find, a seq as its text. */
const historyName = (orgId: string, find: HistoryToRead): string =>
  JSON.stringify([orgId.toLowerCase(), Object.entries(find).toSorted(([a], [b]) => a.localeCompare(b))], (_, value) =>
    typeof value === 'bigint' ? `${value.toString()}n` : (value as unknown),
  );

const MISSING = Object.freeze({ outcome: 'missing' as const });
const MISSING_HOLD = Object.freeze({ outcome: 'not_held' as const });
const MOVED_ON = Object.freeze({ outcome: 'moved_on' as const });
const NO_INVESTIGATION = Object.freeze({ outcome: 'no_investigation' as const });

/**
 * The investigation an event about one records, or nothing if its facts don't
 * read as one. Only the hold's own steps write its subject type, always as
 * recordInvestigation does (audit-trail.ts), and the event is believed only
 * whole: the checks here narrow the facts' types.
 */
function investigationIn(found: Extract<RecordedEventCheck, { kind: 'recorded' }>): HoldInvestigation | undefined {
  const { event } = found;
  const { holdVersion, holdEventId, conclusion, reference } = event.details;
  if (
    typeof holdVersion !== 'number' ||
    typeof holdEventId !== 'string' ||
    !isInvestigationConclusion(conclusion) ||
    !isIncidentReference(reference)
  ) {
    return undefined;
  }
  return Object.freeze({
    id: event.subject.id.toLowerCase(),
    holdVersion,
    holdEventId,
    conclusion,
    reference,
    recordedBy: event.actor.id.toLowerCase(),
    recordedAt: found.recordedAt,
  });
}
/** The status column, which only changeStatus writes on a row that exists. */
const STATUS = 'status';
/** Who sets a hold: the app itself, on a tamper sign. */
const HOLDER: AuditActor = Object.freeze({ type: 'system', id: 'integrity-hold' });
/** The most investigations of an organisation's holds read to find a HELD state's newest. */
const INVESTIGATIONS_READ = 1000;
/** Who records a HELD state's history checked: the API's job (Phase 2 D1c). */
const HISTORY_CHECKER: AuditActor = Object.freeze({ type: 'system', id: 'api' });

type HoldStatus = (typeof INTEGRITY_HOLD.states)[number];

const lockOrder = (): SignedStateFailed =>
  new SignedStateFailed(
    'lock_order',
    "A row read for a decision isn't read again for a change in the same transaction: lock it for the change first (ADR-006 §6)",
  );

const sameFields = (row: readonly FieldText[], expected: (column: string) => string | null | undefined): boolean =>
  row.every(([column, value]) => value === expected(column));

/**
 * The hold's subject types are its own: a row recorded under one would be read
 * as the organisation's hold, or as an investigation of it.
 */
const notTheHold = (table: SignedStateTable): void => {
  if (table.subject === HOLD_SUBJECT || table.subject === INVESTIGATION_SUBJECT)
    throw new RangeError(`The subject type ${table.subject} is the integrity hold's own`);
};

/**
 * Build one from the request's or job's logger, a child carrying its
 * correlation ID (Rule Book §8); each alarm adds the organisation, and is
 * handed to `onTamper` as it is raised. What it knows of each transaction's
 * rows (locks and verified states) is its own: use one for the whole
 * transaction. Outside tests, only withSignedStates builds one.
 */
export function createSignedStates({
  keys,
  trail,
  logger,
  onTamper,
  unrecorded,
}: {
  readonly keys: KeyProvider;
  readonly trail: AuditTrail;
  readonly logger: Logger;
  readonly onTamper: (finding: TamperFinding) => void;
  /** The finding of a hold this process couldn't record yet for the organisation, if one is waiting. */
  readonly unrecorded: (orgId: string) => TamperFinding | undefined;
}): HoldingSignedStates {
  const statuses = createStatusChanger({ logger });
  const rowsHeld = new WeakMap<AuditTransaction, Map<string, Held>>();
  /** Organisations whose own row each transaction has created, whose hold it may start. */
  const created = new WeakMap<AuditTransaction, Set<string>>();
  /** Transactions holding their chain head's lock, after which no row is locked (ADR-006 §6). */
  const headLocked = new WeakSet<AuditTransaction>();
  const KEPT: AnchorKept = Object.freeze({ outcome: 'kept' });
  /** Organisations verifyAll found whole in each transaction, whose hold it may clear. */
  const verifiedWhole = new WeakMap<AuditTransaction, Set<string>>();
  /** What each transaction's gatherHistories read, by history, for its next historyOf to answer from (P8). */
  const historiesGathered = new WeakMap<AuditTransaction, Map<string, RecordedEventsCheck>>();
  /** What each transaction's gathers read and believed, by row, for its next verifiedState to answer from (P8). */
  const gathered = new WeakMap<AuditTransaction, Map<string, { readonly lock: RowLock; readonly check: StateCheck }>>();

  const heldIn = (tx: AuditTransaction): Map<string, Held> => {
    const known = rowsHeld.get(tx) ?? new Map<string, Held>();
    rowsHeld.set(tx, known);
    return known;
  };
  const rowName = (table: SignedStateTable, { orgId, id }: SignedRowKey): string =>
    `${table.table}|${orgId.toLowerCase()}|${id.toLowerCase()}`;

  /** Raises the alarm, hands the finding on, and gives the outcome a read denies. */
  const alarm = (subjectType: string, key: SignedRowKey, sign: TamperSign, seq?: bigint) => {
    logger.child({ orgId: key.orgId.toLowerCase() }).error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'state',
      reason: sign,
      subjectType,
      objectId: key.id.toLowerCase(),
      ...(seq === undefined ? {} : { seq }),
    });
    onTamper(Object.freeze({ orgId: key.orgId.toLowerCase(), subjectType, objectId: key.id.toLowerCase(), sign }));
    return Object.freeze({ outcome: 'tampered' as const, sign });
  };

  /** Raises the alarm and fails: the locked row didn't hold what was just written to it. */
  const notApplied = (table: SignedStateTable, key: SignedRowKey, what: string): never => {
    alarm(table.subject, key, 'row');
    throw new SignedStateFailed('not_applied', what);
  };

  const latestOf = (tx: AuditTransaction, table: SignedStateTable, key: SignedRowKey): Promise<LatestSignedState> =>
    trail.latestSignedState(tx, key.orgId, { type: table.subject, id: key.id });

  /** The row matched with the log's latest signed event for it: the state, or the tamper sign it shows. */
  const judge = (
    table: SignedStateTable,
    key: SignedRowKey,
    row: FoundRow,
    latest: LatestSignedState,
  ): Extract<StateCheck, { outcome: 'verified' }> | { readonly sign: TamperSign; readonly seq?: bigint } => {
    if (latest.kind === 'none') return { sign: 'unsigned' };
    if (latest.kind === 'broken') return latest.seq === undefined ? { sign: 'log' } : { sign: 'log', seq: latest.seq };
    const eventId = latest.id.toLowerCase();
    if (row.eventId !== eventId) return { sign: 'pointer' };
    if (row.version !== latest.version) return { sign: 'version' };
    const facts = {
      orgId: key.orgId,
      subject: { type: table.subject, id: key.id, version: row.version },
      fields: row.fields,
    };
    if (!stateSealMatches(keys, facts, latest.seal)) return { sign: 'seal' };
    return Object.freeze({
      outcome: 'verified',
      version: row.version,
      eventId,
      recordedAt: latest.recordedAt,
      fields: new Map(row.fields),
    });
  };

  /** judge, with the alarm raised for a tamper sign. */
  const compare = (
    table: SignedStateTable,
    key: SignedRowKey,
    row: FoundRow,
    latest: LatestSignedState,
  ): StateCheck => {
    const judged = judge(table, key, row, latest);
    return 'sign' in judged ? alarm(table.subject, key, judged.sign, judged.seq) : judged;
  };

  /**
   * The row, locked, and its newest signed event in one statement (4D2d P3a):
   * believed only when they agree (verified), or when there is neither a row
   * nor a signed event. Anything else is undefined, raising no alarm: the row
   * may have changed while the statement waited for its lock, after the log's
   * snapshot was taken, so the caller checks again in two statements, as
   * before, and only that check raises the alarm.
   */
  const inOneStatement = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    lock: RowLock,
  ): Promise<StateCheck | undefined> => {
    let read: LatestWithRow;
    try {
      read = await trail.latestSignedStateWithRow(
        tx,
        key.orgId,
        { type: table.subject, id: key.id },
        signedRowReadSeen(table, key, lock),
      );
    } catch (error) {
      // A backlog: the check in two statements reads the row first, so an unreadable row raises its own alarm.
      if (error instanceof TooManyEventsAboutObject) return undefined;
      throw error;
    }
    return believedPair(table, key, read.latest, read.rows);
  };

  /**
   * A row and its newest signed event read in one statement, believed only
   * when they agree (verified), or when there is neither: undefined for
   * anything else, raising no alarm (inOneStatement's rule).
   */
  const believedPair = (
    table: SignedStateTable,
    key: SignedRowKey,
    latest: GatheredLatest['latest'],
    rows: GatheredLatest['rows'],
  ): StateCheck | undefined => {
    if (rows === undefined || latest.kind === 'backlog') return undefined;
    const row = signedRowSeen(table, rows);
    if (row === undefined) return undefined;
    if (row.outcome === 'missing') return latest.kind === 'none' ? MISSING : undefined;
    if (row.outcome !== 'found') return undefined;
    const judged = judge(table, key, row, latest);
    return 'sign' in judged ? undefined : judged;
  };

  const gather = async (
    tx: AuditTransaction,
    orgId: string,
    list: readonly GatheredRow[],
  ): Promise<readonly (string | null)[]> => {
    for (const { table } of list) notTheHold(table);
    if (headLocked.has(tx)) checkLockOrder(tx, undefined, 'share');
    const rows = heldIn(tx);
    // A row named here held already: the lock order is checked before the statement can raise it.
    for (const { table, id, lock } of list) {
      if ('id' in id) checkLockOrder(tx, rows.get(rowName(table, { orgId, id: id.id })), lock);
    }
    const answers = await trail.latestSignedStatesGathered(tx, orgId, gatheredRowReads(orgId, list));
    const kept = gathered.get(tx) ?? new Map<string, { readonly lock: RowLock; readonly check: StateCheck }>();
    gathered.set(tx, kept);
    // Once a row isn't believed (it may have changed while the statement waited for its lock), the rows after it
    // aren't either: the statement's snapshot is older than that wait, so a row made by the change that ended it,
    // found through the row as it now is, would read as missing (S161 review). Each is then read on its own.
    let believing = true;
    return list.map(({ table, lock }, index) => {
      const answer = answers[index];
      if (answer === undefined || answer.id === null) return null;
      const key = { orgId, id: answer.id };
      const name = rowName(table, key);
      const held = rows.get(name);
      checkLockOrder(tx, held, lock);
      // Held from here, as verifiedState holds a row it reads.
      rows.set(name, { lock: held?.lock ?? lock, ...(lock === 'share' && held?.from ? { from: held.from } : {}) });
      const check = believing ? believedPair(table, key, answer.latest, answer.rows) : undefined;
      believing = check !== undefined;
      // A row not believed here keeps what an earlier gather believed of it: the row has been locked since.
      if (check !== undefined) kept.set(name, { lock, check });
      return answer.id;
    });
  };

  /** What a gather believed of the row, once, if it was gathered with this lock: no trip (P8). */
  const takeGathered = (tx: AuditTransaction, name: string, lock: RowLock): StateCheck | undefined => {
    const kept = gathered.get(tx)?.get(name);
    gathered.get(tx)?.delete(name);
    return kept?.lock === lock ? kept.check : undefined;
  };

  /** Throws if locking the row now would break the lock order: a shared lock raised to change, or a row after the head. */
  const checkLockOrder = (tx: AuditTransaction, held: Held | undefined, lock: RowLock): void => {
    if (held?.lock === 'share' && lock === 'change') throw lockOrder();
    if (held === undefined && headLocked.has(tx)) {
      throw new SignedStateFailed(
        'lock_order',
        "A row is locked before the chain head, never after it (ADR-006 §6): read the integrity hold with lock 'head' last",
      );
    }
  };

  const verifiedState = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    lock: RowLock,
  ): Promise<StateCheck> => {
    notTheHold(table);
    const rows = heldIn(tx);
    const name = rowName(table, key);
    const held = rows.get(name);
    checkLockOrder(tx, held, lock);
    // Held from here: the statement below takes the lock before it gives anything back.
    rows.set(name, { lock: held?.lock ?? lock, ...(lock === 'share' && held?.from ? { from: held.from } : {}) });
    const quick = takeGathered(tx, name, lock) ?? (await inOneStatement(tx, table, key, lock));
    const checked = quick ?? (await inTwoStatements(tx, table, key, lock));
    if (checked.outcome === 'verified' && lock === 'change') rows.set(name, { lock, from: { table, state: checked } });
    return checked;
  };

  /**
   * The state this transaction last recorded on the row, with this same table,
   * made the one to change from, as verifiedState would: no trip (4D2d P3b).
   * Any read or change of the row since recorded it ends this; then undefined.
   */
  const justWritten = (tx: AuditTransaction, table: SignedStateTable, key: SignedRowKey): VerifiedState | undefined => {
    const rows = heldIn(tx);
    const name = rowName(table, key);
    const wrote = rows.get(name)?.wrote;
    if (wrote?.table !== table) return undefined;
    rows.set(name, { lock: 'change', from: wrote });
    return wrote.state;
  };

  /** The check as it was before 4D2d P3a, each step a statement of its own, raising the alarm it finds. */
  const inTwoStatements = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    lock: RowLock,
  ): Promise<StateCheck> => {
    let row = await readSignedRow(tx, table, key, lock);
    if (row.outcome === 'unreadable') return alarm(table.subject, key, 'row');
    let latest = await latestOf(tx, table, key);
    if (row.outcome === 'missing') {
      if (latest.kind === 'none') return MISSING;
      if (latest.kind === 'broken') return alarm(table.subject, key, 'log', latest.seq);
      // The row commits with its first event, so with the event in the log,
      // the row is gone, unless it was created since it was read: read again.
      row = await readSignedRow(tx, table, key, lock);
      if (row.outcome === 'missing') return alarm(table.subject, key, 'deleted');
      if (row.outcome === 'unreadable') return alarm(table.subject, key, 'row');
      latest = await latestOf(tx, table, key);
    }
    return compare(table, key, row, latest);
  };

  /**
   * verifiedStates, each check made in ID order with its alarm. `listed`: the
   * IDs were listed as the table's objects (judged), so one with neither a
   * row nor a signed state is `deleted`, its alarm raised in that same order,
   * as the hold records the first alarm it hears (withSignedStates).
   */
  const checksOf = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    orgId: string,
    ids: readonly string[],
    listed: boolean,
  ): Promise<ReadonlyMap<string, PageCheck>> => {
    notTheHold(table);
    const rows = heldIn(tx);
    const asked = [...new Set(ids.map((id) => id.toLowerCase()))];
    for (const id of asked) checkLockOrder(tx, rows.get(rowName(table, { orgId, id })), 'share');
    const read = await readSignedRows(tx, table, orgId, asked);
    for (const id of asked) {
      const name = rowName(table, { orgId, id });
      const held = rows.get(name);
      rows.set(name, { lock: held?.lock ?? 'share', ...(held?.from ? { from: held.from } : {}) });
    }
    const latest = await trail.latestSignedStates(tx, orgId, table.subject, asked);
    const checks = new Map<string, PageCheck>();
    for (const id of asked) {
      const key = { orgId, id };
      const row = read.get(id);
      const last = latest.get(id);
      // Both reads answer every ID asked; one that didn't would be a bug, never a row to believe.
      if (row === undefined || last === undefined) throw new Error('A signed state was asked for and not read');
      // A row not found whole (missing, or unreadable: rare, and a tamper sign) is read again on its own, which
      // judges it as verifiedState always does, a row created since it was read among them: an unreadable row's
      // alarm comes before its log is read, so a backlog never hides it (A1b review).
      let check: PageCheck;
      if (row.outcome !== 'found') check = await verifiedState(tx, table, key, 'share');
      else if (last.kind === 'backlog') check = { outcome: 'backlog' };
      else check = compare(table, key, row, last);
      checks.set(id, listed && check.outcome === 'missing' ? alarm(table.subject, key, 'deleted') : check);
    }
    return checks;
  };

  const verifiedStates = async (tx: AuditTransaction, table: SignedStateTable, orgId: string, ids: readonly string[]) =>
    whole(await checksOf(tx, table, orgId, ids, false));

  /** checksOf for a list's page: each backlogged row logged as an error, which the app-errors alert counts. */
  const pageStates = async (tx: AuditTransaction, table: SignedStateTable, orgId: string, ids: readonly string[]) => {
    const checks = await checksOf(tx, table, orgId, ids, false);
    for (const [id, check] of checks) {
      if (check.outcome === 'backlog') {
        logger
          .child({ orgId: orgId.toLowerCase() })
          .error('audit.backlog', { subjectType: table.subject, objectId: id });
      }
    }
    return checks;
  };

  /**
   * Locks a row being created for change, once it is as the app inserts one:
   * at version 1, pointing at no event, in its first status, with nothing
   * signed for it in the log yet.
   */
  const lockNewRow = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    set: SignedFieldValues,
    rows: Map<string, Held>,
    name: string,
  ): Promise<void> => {
    if (rows.get(name)?.lock === 'share') throw lockOrder();
    const read = await readSignedRow(tx, table, key, 'change');
    if (read.outcome === 'unreadable') {
      alarm(table.subject, key, 'row');
      throw new SignedStateFailed('tampered', 'A row being created is not as the app writes one');
    }
    if (read.outcome !== 'found' || read.version !== 1 || read.eventId !== null) {
      throw new SignedStateFailed('basis', 'A new signed row is at version 1 and points at no event yet');
    }
    // The status guard let the row in only in its machine's first status;
    // any other would be a move no machine decided. (A status is text, so
    // its canonical text is the value itself.)
    const inserted = new Map(read.fields).get(STATUS);
    if (Object.hasOwn(set, STATUS) && set[STATUS] !== inserted) {
      throw new RangeError('A new row keeps the status it was inserted in; it moves only through changeStatus');
    }
    if ((await latestOf(tx, table, key)).kind !== 'none') {
      alarm(table.subject, key, 'log');
      throw new SignedStateFailed('tampered', 'The log already holds a signed state for a row being created');
    }
    rows.set(name, { lock: 'change' });
  };

  /**
   * Writes the change and gives back the row at its new version, once it
   * holds exactly the state it was verified in (or, for a new row, nothing
   * yet) with the values written.
   */
  const written = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    from: VerifiedState | 'new',
    set: SignedFieldValues,
  ): Promise<FoundRow> => {
    notTheHold(table);
    const rows = heldIn(tx);
    const name = rowName(table, key);
    // A row written is never answered from what a gather read before, nor any history from one: the change's
    // event may belong in it.
    gathered.get(tx)?.delete(name);
    historiesGathered.delete(tx);
    if (from === 'new') {
      await lockNewRow(tx, table, key, set, rows, name);
    } else {
      const held = rows.get(name);
      if (held?.from?.state !== from || held.from.table !== table) {
        throw new SignedStateFailed(
          'basis',
          'A change is recorded from the state last verified for change on its row, with its table, here',
        );
      }
      rows.set(name, { lock: 'change' });
    }
    return writtenOver(tx, table, key, from, set);
  };

  /** The write itself, and the row read back: from new, or from a version and pointer, with the fields it held. */
  const writtenOver = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    from: 'new' | (Pick<VerifiedState, 'version' | 'fields'> & { readonly eventId: string | null }),
    set: SignedFieldValues,
  ): Promise<FoundRow> => {
    const { row, written: values } = await writeSignedRow(tx, table, key, from, set);
    const expectedVersion = from === 'new' ? 1 : from.version + 1;
    if (row.outcome !== 'found' || row.version !== expectedVersion || row.eventId !== null) {
      return notApplied(table, key, "The row didn't move on from the state it was verified in");
    }
    const wrote = new Map(values);
    const expected = (column: string) =>
      wrote.has(column) ? wrote.get(column) : from === 'new' ? undefined : from.fields.get(column);
    if (!sameFields(row.fields, expected)) {
      return notApplied(table, key, "The row didn't hold what the change wrote, over the state it was verified in");
    }
    return row;
  };

  /** An unsealed status could be flipped unseen. */
  const sealsStatus = (table: SignedStateTable): void => {
    if (!table.fields.some(({ column }) => column === STATUS)) {
      throw new RangeError('A signed status table seals its status');
    }
  };

  /** A status change's event says what it moved from and to. */
  const withMove = (
    change: SignedChange,
    { from, to }: { readonly from: string; readonly to: string },
  ): SignedChange => ({ ...change, details: { ...change.details, statusFrom: from, statusTo: to } });

  /** A change's details may not bring the seal, which recording adds. */
  const noSealGiven = ({ details }: SignedChange): void => {
    if (Object.hasOwn(details, 'stateFingerprint') || Object.hasOwn(details, 'stateKeyVersion')) {
      throw new AuditEventRefused(['details.stateFingerprint and details.stateKeyVersion are the seal, added here']);
    }
  };

  /** The event of a change that leaves the row as `row`, its state sealed. */
  const sealedEvent = (table: SignedStateTable, key: SignedRowKey, row: FoundRow, change: SignedChange): AuditEvent => {
    const subject = { type: table.subject, id: key.id, version: row.version };
    const seal = sealState(keys, { orgId: key.orgId, subject, fields: row.fields });
    return {
      actor: change.actor,
      action: change.action,
      subject,
      details: { ...change.details, ...stateSealDetails(seal) },
    };
  };

  /**
   * The row as its event's write pointed it, checked against `row` as sealed,
   * and kept as the state this transaction just recorded (P3b): sealed, logged
   * and read back here, the row and the head locked until commit, so no other
   * transaction moves either. Anything this one puts in since (or a savepoint
   * rolled back over it) fails the next write's compare.
   */
  const pointedState = (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    row: FoundRow,
    recorded: RecordedAuditEvent,
    along: readonly Readonly<Record<string, unknown>>[] | undefined,
  ): VerifiedState => {
    // None that read as rows is none taken: the row is then not as sealed, and the change fails with the alarm.
    const pointed = signedRowPointed(table, along ?? []);
    const sealed = new Map(row.fields);
    if (
      pointed.outcome !== 'found' ||
      pointed.version !== row.version ||
      pointed.eventId !== recorded.id.toLowerCase() ||
      !sameFields(pointed.fields, (column) => sealed.get(column))
    ) {
      return notApplied(table, key, "The row didn't take the pointer to its new state's event as sealed");
    }
    const state: VerifiedState = Object.freeze({
      outcome: 'verified',
      version: row.version,
      eventId: recorded.id.toLowerCase(),
      recordedAt: recorded.recordedAt,
      fields: sealed,
    });
    heldIn(tx).set(rowName(table, key), { lock: 'change', wrote: { table, state } });
    return state;
  };

  /** The row moved by its machine from the status sealed, locked for change: one statement when it still holds it (4D2d P8). */
  const movedFrom = async <State extends string, Event extends string>(
    tx: AuditTransaction,
    table: SignedStateTable & StatusTable<State, Event>,
    key: SignedRowKey,
    event: Event,
    fields: ReadonlyMap<string, string | null>,
  ) => {
    const sealedStatus = fields.get(STATUS) ?? undefined;
    const moved = await statuses.change(tx, table, key, event, sealedStatus).catch((error: unknown) => {
      // The row is verified and locked: its status can't be unreadable or
      // left unchanged unless something past the app is at work on it.
      if (error instanceof StatusChangeFailed) alarm(table.subject, key, 'status');
      throw error;
    });
    if (moved.outcome === 'missing') {
      return notApplied(table, key, 'The row verified and locked for change was missing when changed');
    }
    // The machine moved from the status the row held, which must be the one sealed: a state just written
    // isn't read again (P3b), so a status put in since, by this transaction, would else be moved from.
    if (moved.from !== sealedStatus) {
      alarm(table.subject, key, 'status');
      throw new SignedStateFailed('not_applied', "The row's status isn't the one its signed state holds");
    }
    return moved;
  };

  const recordChange = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    from: VerifiedState | 'new',
    set: SignedFieldValues,
    change: SignedChange,
  ): Promise<RecordedState> => {
    noSealGiven(change);
    const row = await written(tx, table, key, from, set);
    // The row pointed at its event in the event's own write (4D2d P8).
    const recorded = await trail.recordAlong(tx, key.orgId, sealedEvent(table, key, row, change), (eventId, gate) =>
      signedRowPointing(table, key, { version: row.version, eventId }, gate),
    );
    pointedState(tx, table, key, row, recorded, recorded.along);
    // An organisation's own row, created as its chain's first event: its hold may start here (startIntegrityHold).
    if (from === 'new' && key.id.toLowerCase() === key.orgId.toLowerCase() && recorded.seq === 1n) {
      created.set(tx, (created.get(tx) ?? new Set<string>()).add(key.orgId.toLowerCase()));
    }
    return Object.freeze({ version: row.version, eventId: recorded.id, seq: recorded.seq });
  };

  /**
   * The hold as its newest signed event holds it, and that event's version:
   * 0 when there is none to go on (no state, or none that can be believed).
   * The seal says which status it is: it matches one or neither.
   */
  const readHold = async (
    tx: AuditTransaction,
    orgId: string,
  ): Promise<{ readonly check: HoldCheck; readonly version: number }> => {
    const key = { orgId, id: orgId };
    let latest: LatestSignedState;
    try {
      latest = await trail.latestSignedState(tx, orgId, { type: HOLD_SUBJECT, id: orgId });
    } catch (error) {
      // Every event about the hold is a signed state of its own, so any after the newest signed one is tampering.
      if (error instanceof TooManyEventsAboutObject) return { check: alarm(HOLD_SUBJECT, key, 'log'), version: 0 };
      throw error;
    }
    if (latest.kind === 'none') return { check: alarm(HOLD_SUBJECT, key, 'unsigned'), version: 0 };
    if (latest.kind === 'broken') return { check: alarm(HOLD_SUBJECT, key, 'log', latest.seq), version: 0 };
    const subject = { type: HOLD_SUBJECT, id: orgId, version: latest.version };
    const status = INTEGRITY_HOLD.states.find((state) =>
      stateSealMatches(keys, { orgId, subject, fields: [[STATUS, state]] }, latest.seal),
    );
    if (status === undefined) return { check: alarm(HOLD_SUBJECT, key, 'seal'), version: latest.version };
    const outcome = status === 'HELD' ? 'held' : 'clear';
    return {
      check: Object.freeze({ outcome, version: latest.version, eventId: latest.id.toLowerCase() }),
      version: latest.version,
    };
  };

  /** Seals the hold's status at this version and adds its event to the chain. */
  const recordHold = async (
    tx: AuditTransaction,
    orgId: string,
    version: number,
    status: HoldStatus,
    change: SignedChange,
  ): Promise<RecordedState> => {
    const subject = { type: HOLD_SUBJECT, id: orgId, version };
    const seal = sealState(keys, { orgId, subject, fields: [[STATUS, status]] });
    const recorded = await recordHoldEvent(trail, tx, orgId, {
      actor: change.actor,
      action: change.action,
      subject,
      details: { ...change.details, ...stateSealDetails(seal) },
    });
    return Object.freeze({ version, eventId: recorded.id, seq: recorded.seq });
  };

  const integrityHold = async (tx: AuditTransaction, orgId: string, lock: 'none' | 'head'): Promise<HoldCheck> => {
    if (lock === 'head') {
      await lockChainHead(tx, orgId);
      headLocked.add(tx);
    }
    const { check } = await readHold(tx, orgId);
    const waiting = unrecorded(orgId);
    if (check.outcome !== 'clear' || waiting === undefined) return check;
    // Found, but not recorded yet (withSignedStates tries again once this transaction ends): denied meanwhile.
    return Object.freeze({ outcome: 'tampered', sign: waiting.sign });
  };

  const holdInvestigation = async (tx: AuditTransaction, orgId: string, id: string): Promise<InvestigationCheck> => {
    const found = await trail.recordedEvent(tx, orgId, { onlyAbout: { type: INVESTIGATION_SUBJECT, id } });
    if (found.kind === 'none') return MISSING;
    if (found.kind === 'broken') return alarm(INVESTIGATION_SUBJECT, { orgId, id }, 'log', found.seq);
    const investigation = investigationIn(found);
    return investigation === undefined ? MISSING : Object.freeze({ outcome: 'found', investigation });
  };

  /**
   * Each object verified as verifyAll does, locked `share`, by ID: the
   * findings, each with its alarm raised, in ID order. Read as verifiedStates
   * reads, so a few statements for each MOST_SIGNED_ROWS_READ objects, never
   * per row. Listed, as a row or in the log, yet neither a row nor a signed
   * state now: deleted, its seals with it (checksOf).
   */
  const judged = async (
    tx: AuditTransaction,
    orgId: string,
    table: SignedStateTable,
    ids: readonly string[],
  ): Promise<TamperFinding[]> => {
    const findings: TamperFinding[] = [];
    for (let start = 0; start < ids.length; start += MOST_SIGNED_ROWS_READ) {
      const batch = ids.slice(start, start + MOST_SIGNED_ROWS_READ);
      const checks = whole(await checksOf(tx, table, orgId, batch, true));
      for (const id of batch) {
        const check = checkOf(checks, id);
        if (check.outcome === 'tampered') {
          findings.push(
            Object.freeze({ orgId: orgId.toLowerCase(), subjectType: table.subject, objectId: id, sign: check.sign }),
          );
        }
      }
    }
    return findings;
  };

  const historyOf = async (tx: AuditTransaction, orgId: string, find: HistoryToRead): Promise<HistoryCheck> => {
    const asked = historyName(orgId, find);
    const gatheredRead = historiesGathered.get(tx)?.get(asked);
    historiesGathered.get(tx)?.delete(asked);
    const read = gatheredRead ?? (await trail.recordedEvents(tx, orgId, find));
    // The organisation's own history: the alarm names it, as no one object is to blame.
    if (read.kind === 'broken') return alarm('organisation', { orgId, id: orgId }, 'log', read.seq);
    return Object.freeze({ outcome: 'read', events: read.events });
  };

  const gatherHistories = async (tx: AuditTransaction, orgId: string, finds: readonly HistoryToRead[]) => {
    let reads: readonly RecordedEventsCheck[];
    try {
      reads = await trail.recordedHistories(tx, orgId, finds);
    } catch (error) {
      // Thrown after the statement ran, so the transaction goes on: each history is then read as it is asked.
      if (error instanceof TooManyEventsToRead) return;
      throw error;
    }
    const kept = historiesGathered.get(tx) ?? new Map<string, RecordedEventsCheck>();
    historiesGathered.set(tx, kept);
    for (const [index, find] of finds.entries()) {
      const read = reads[index];
      if (read !== undefined) kept.set(historyName(orgId, find), read);
    }
  };

  const eventOf = async (tx: AuditTransaction, orgId: string, find: EventToFind): Promise<EventRead> => {
    const found = await trail.recordedEvent(tx, orgId, find);
    // As historyOf: the organisation's own log, so the alarm names it.
    if (found.kind === 'broken') return alarm('organisation', { orgId, id: orgId }, 'log', found.seq);
    return Object.freeze({ outcome: 'read', event: found.kind === 'recorded' ? found : undefined });
  };

  const logPageOf = async (tx: AuditTransaction, orgId: string, find: LogPageToRead): Promise<LogPage> => {
    const read = await trail.logPage(tx, orgId, find);
    // As historyOf: the organisation's own log, so the alarm names it.
    if (read.kind === 'broken') return alarm('organisation', { orgId, id: orgId }, 'log', read.seq);
    return Object.freeze({ outcome: 'read', events: read.events, next: read.next });
  };

  /** The table's next objects, its rows' and the log's together (SignedStates.objectIds). */
  const objectIdsOf = async (
    tx: AuditTransaction,
    orgId: string,
    table: SignedStateTable,
    after: string | null,
    size: number,
  ) => {
    notTheHold(table);
    const rowIds = await signedRowIds(tx, table, orgId, size, after);
    const loggedIds = await trail.subjectIds(tx, orgId, table.subject, size, after);
    // Each list holds one more than `size` at most, so its first `size` of the two together are the next ones.
    const next = [...new Set([...rowIds, ...loggedIds])].sort();
    const ids = Object.freeze(next.slice(0, size));
    return Object.freeze({ ids, next: next.length > size ? (ids.at(-1) ?? null) : null });
  };

  return Object.freeze({
    verifiedState,
    gather,

    verifiedStates,
    pageStates,

    mismatch(subjectType: string, key: SignedRowKey): void {
      alarm(subjectType, key, 'holding');
    },

    async verifyAll(
      tx: AuditTransaction,
      orgId: string,
      tables: readonly CheckedTable[],
      limit: number,
    ): Promise<OrganisationCheck> {
      const findings: TamperFinding[] = [];
      let objects = 0;
      for (const table of tables) {
        notTheHold(table);
        const live = table.liveStatuses ?? null;
        const rowIds = await signedRowIds(tx, table, orgId, limit, null, live);
        // A growing table's log lists every object it ever had, ended ones too.
        const loggedIds = live === null ? await trail.subjectIds(tx, orgId, table.subject, limit) : [];
        const every = [...new Set([...rowIds, ...loggedIds])].sort();
        if (every.length > limit) return Object.freeze({ outcome: 'too_many', subjectType: table.subject });
        findings.push(...(await judged(tx, orgId, table, every)));
        objects += every.length;
      }
      if (findings.length > 0) return Object.freeze({ outcome: 'tampered', findings: Object.freeze(findings) });
      verifiedWhole.set(tx, (verifiedWhole.get(tx) ?? new Set<string>()).add(orgId.toLowerCase()));
      return Object.freeze({ outcome: 'verified', objects });
    },

    async checkHistoryBatch(
      tx: AuditTransaction,
      orgId: string,
      table: SignedStateTable,
      after: string | null,
      size: number,
    ): Promise<HistoryBatch> {
      const { ids: batch, next } = await objectIdsOf(tx, orgId, table, after, size);
      const findings = await judged(tx, orgId, table, batch);
      if (findings.length > 0) return Object.freeze({ outcome: 'tampered', findings: Object.freeze(findings) });
      return Object.freeze({
        outcome: 'checked',
        objects: batch.length,
        last: batch.at(-1) ?? after,
        done: next === null,
      });
    },

    objectIds: objectIdsOf,

    async latestInvestigation(tx: AuditTransaction, orgId: string, holdEventId: string): Promise<string | null> {
      const read = await historyOf(tx, orgId, {
        subjectTypes: [INVESTIGATION_SUBJECT],
        actions: ['integrity_hold.investigated'],
        limit: INVESTIGATIONS_READ,
      });
      if (read.outcome === 'tampered') return null;
      const held = holdEventId.toLowerCase();
      const ofIt = read.events.filter(({ event }) => event.details.holdEventId === held);
      return ofIt.at(-1)?.event.subject.id.toLowerCase() ?? null;
    },

    async recordHistoryChecked(
      tx: AuditTransaction,
      orgId: string,
      investigationId: string,
      objects: number,
    ): Promise<void> {
      if (!UUID.test(investigationId)) throw new RangeError('An investigation is named by its ID');
      if (!Number.isSafeInteger(objects) || objects < 0) throw new RangeError('A count of objects is a whole number');
      const investigation = await holdInvestigation(tx, orgId, investigationId);
      const hold = await integrityHold(tx, orgId, 'head');
      if (
        hold.outcome !== 'held' ||
        investigation.outcome !== 'found' ||
        investigation.investigation.holdEventId !== hold.eventId
      ) {
        throw new SignedStateFailed(
          'basis',
          'A history is recorded checked only while the hold stands in the HELD state its investigation is of',
        );
      }
      await recordHoldEvent(trail, tx, orgId, {
        actor: HISTORY_CHECKER,
        action: 'integrity_hold.history_checked',
        subject: { type: HISTORY_CHECK_SUBJECT, id: investigationId, version: 1 },
        details: { holdVersion: hold.version, holdEventId: hold.eventId, objects },
      });
    },

    async mayBeHeld(tx: AuditTransaction, orgId: string): Promise<boolean> {
      const newest = await trail.newestActionUnverified(tx, orgId, { type: HOLD_SUBJECT, id: orgId });
      return newest === 'integrity_hold.set';
    },

    async historyChecked(tx: AuditTransaction, orgId: string, investigationId: string): Promise<HistoryCheckRecord> {
      const id = investigationId.toLowerCase();
      const found = await trail.recordedEvent(tx, orgId, { onlyAbout: { type: HISTORY_CHECK_SUBJECT, id } });
      if (found.kind === 'broken') {
        alarm(HISTORY_CHECK_SUBJECT, { orgId, id }, 'log', found.seq);
        return 'tampered';
      }
      return found.kind === 'recorded' ? 'checked' : 'unchecked';
    },

    async record(
      tx: AuditTransaction,
      table: SignedStateTable,
      key: SignedRowKey,
      from: VerifiedState | 'new',
      set: SignedFieldValues,
      change: SignedChange,
    ): Promise<RecordedState> {
      // A status moves only along its machine, which changeStatus decides.
      if (from !== 'new' && Object.hasOwn(set, STATUS)) {
        throw new RangeError('A status changes through changeStatus');
      }
      return recordChange(tx, table, key, from, set, change);
    },

    async changeStatus<State extends string, Event extends string>(
      tx: AuditTransaction,
      table: SignedStateTable & StatusTable<State, Event>,
      key: SignedRowKey,
      event: NoInfer<Event>,
      change: SignedChange,
    ): Promise<SignedStatusChange<State>> {
      sealsStatus(table);
      const current = justWritten(tx, table, key) ?? (await verifiedState(tx, table, key, 'change'));
      if (current.outcome !== 'verified') return current;
      const moved = await movedFrom(tx, table, key, event, current.fields);
      if (moved.outcome === 'refused') return moved;
      const recorded = await recordChange(tx, table, key, current, { [STATUS]: moved.to }, withMove(change, moved));
      // recordChange keeps the state it recorded for the next change to go on from (P3b).
      const state = heldIn(tx).get(rowName(table, key))?.wrote?.state;
      if (state === undefined) throw new Error('A status change recorded no state');
      return Object.freeze({
        outcome: 'changed',
        from: moved.from,
        to: moved.to,
        version: recorded.version,
        eventId: recorded.eventId,
        state,
      });
    },

    async recordNewAndMove<State extends string, Event extends string>(
      tx: AuditTransaction,
      table: SignedStateTable & StatusTable<State, Event>,
      key: SignedRowKey,
      set: SignedFieldValues,
      change: SignedChange,
      event: NoInfer<Event>,
      moveChange: SignedChange,
    ): Promise<SignedStatusChanged<State>> {
      sealsStatus(table);
      noSealGiven(change);
      noSealGiven(moveChange);
      const first = await written(tx, table, key, 'new', set);
      const firstFields = new Map(first.fields);
      const moved = await movedFrom(tx, table, key, event, firstFields);
      // Nothing signed yet, and no new row is meant to be refused its first move: never a row left to commit unsigned.
      if (moved.outcome === 'refused') throw new RangeError("A new row's first move was refused by its machine");
      const row = await writtenOver(
        tx,
        table,
        key,
        { version: first.version, eventId: null, fields: firstFields },
        { [STATUS]: moved.to },
      );
      const { recorded, along } = await trail.recordAllAlong(
        tx,
        key.orgId,
        [sealedEvent(table, key, first, change), sealedEvent(table, key, row, withMove(moveChange, moved))],
        (eventId, gate) => signedRowPointing(table, key, { version: row.version, eventId }, gate),
      );
      const last = recorded.at(-1);
      if (last === undefined) throw new Error('Two events asked and none recorded');
      const state = pointedState(tx, table, key, row, last, along);
      return Object.freeze({
        outcome: 'changed',
        from: moved.from,
        to: moved.to,
        version: row.version,
        eventId: last.id,
        state,
      });
    },

    integrityHold,

    async anchorKept(tx: AuditTransaction, orgId: string, anchor: AnchorPoint): Promise<AnchorKept> {
      if (!headLocked.has(tx))
        throw new Error("The anchor is compared only once integrityHold has locked the chain's head");
      if (await trail.keepsAnchor(tx, orgId, anchor)) return KEPT;
      const held = orgId.toLowerCase();
      logger.child({ orgId: held }).error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'anchor',
        anchorSeq: anchor.seq,
      });
      onTamper(
        Object.freeze({
          orgId: held,
          subjectType: CHAIN_SUBJECT,
          objectId: held,
          sign: 'chain',
          chainFailure: 'anchor',
        }),
      );
      return Object.freeze({ outcome: 'tampered', sign: 'chain' });
    },

    async startIntegrityHold(tx: AuditTransaction, orgId: string, actor: AuditActor): Promise<RecordedState> {
      if (created.get(tx)?.delete(orgId.toLowerCase()) !== true) {
        throw new SignedStateFailed(
          'basis',
          "An integrity hold starts only in the transaction that created its organisation's own row as its chain's first event, once",
        );
      }
      return recordHold(tx, orgId, 1, INTEGRITY_HOLD.initial, {
        actor,
        action: 'integrity_hold.created',
        details: {},
      });
    },

    async holdRecord(tx: AuditTransaction, orgId: string): Promise<HoldRecord> {
      const check = await integrityHold(tx, orgId, 'none');
      if (check.outcome === 'tampered') return check;
      const found = await trail.recordedEvent(tx, orgId, { eventId: check.eventId });
      // The newest signed event was just read whole: gone or broken now is tampering in between.
      if (found.kind !== 'recorded') {
        return alarm(HOLD_SUBJECT, { orgId, id: orgId }, 'log', found.kind === 'broken' ? found.seq : undefined);
      }
      if (check.outcome === 'clear') {
        return Object.freeze({ outcome: 'clear', version: check.version, since: found.recordedAt });
      }
      const { reason, foundOn } = found.event.details;
      return Object.freeze({
        outcome: 'held',
        version: check.version,
        eventId: check.eventId,
        since: found.recordedAt,
        reason: typeof reason === 'string' ? reason : null,
        foundOn: typeof foundOn === 'string' ? foundOn : null,
      });
    },

    async recordInvestigation(
      tx: AuditTransaction,
      orgId: string,
      { id, actor, conclusion, reference }: Parameters<SignedStates['recordInvestigation']>[2],
    ): Promise<InvestigationRecording> {
      if (actor.type !== 'user') throw new RangeError('An investigation is recorded by a person');
      if (!isInvestigationConclusion(conclusion)) throw new RangeError('An investigation concludes as one of its own');
      if (!isIncidentReference(reference)) throw new RangeError("An investigation's reference is an incident's ID");
      const hold = await integrityHold(tx, orgId, 'head');
      if (hold.outcome === 'tampered') return hold;
      if (hold.outcome === 'clear') return MISSING_HOLD;
      const recorded = await recordHoldEvent(trail, tx, orgId, {
        actor,
        action: 'integrity_hold.investigated',
        subject: { type: INVESTIGATION_SUBJECT, id, version: 1 },
        details: { holdVersion: hold.version, holdEventId: hold.eventId, conclusion, reference },
      });
      return Object.freeze({
        outcome: 'recorded',
        investigation: Object.freeze({
          id: id.toLowerCase(),
          holdVersion: hold.version,
          holdEventId: hold.eventId,
          conclusion,
          reference,
          recordedBy: actor.id.toLowerCase(),
          recordedAt: recorded.recordedAt,
        }),
      });
    },

    holdInvestigation,

    historyOf,
    gatherHistories,
    eventOf,
    logPageOf,

    async clearIntegrityHold(
      tx: AuditTransaction,
      orgId: string,
      { actor, holdEventId, investigationId, stepUp }: Parameters<SignedStates['clearIntegrityHold']>[2],
    ): Promise<HoldClearing> {
      if (actor.type !== 'user') throw new RangeError('A hold is cleared by a person');
      if (!UUID.test(stepUp.stepUpChallengeId)) throw new RangeError('A hold is cleared with the step-up it names');
      if (verifiedWhole.get(tx)?.has(orgId.toLowerCase()) !== true) {
        throw new SignedStateFailed(
          'basis',
          "A hold is cleared only once verifyAll has found the organisation's records whole, in the same transaction",
        );
      }
      const hold = await integrityHold(tx, orgId, 'head');
      if (hold.outcome === 'tampered') return hold;
      if (hold.outcome === 'clear') return MISSING_HOLD;
      if (hold.eventId !== holdEventId.toLowerCase()) return MOVED_ON;
      const investigation = await holdInvestigation(tx, orgId, investigationId);
      if (investigation.outcome === 'tampered') return investigation;
      if (investigation.outcome === 'missing' || investigation.investigation.holdEventId !== hold.eventId) {
        return NO_INVESTIGATION;
      }
      const recorded = await recordHold(tx, orgId, hold.version + 1, 'CLEAR', {
        actor,
        action: 'integrity_hold.cleared',
        details: {
          statusFrom: 'HELD',
          statusTo: 'CLEAR',
          investigationId: investigation.investigation.id,
          ...stepUp,
        },
      });
      return Object.freeze({ outcome: 'cleared', version: recorded.version, eventId: recorded.eventId });
    },

    async hold(tx: AuditTransaction, finding: TamperFinding, findings: number): Promise<'set' | 'already'> {
      const { orgId } = finding;
      await lockChainHead(tx, orgId);
      const { check, version } = await readHold(tx, orgId);
      if (check.outcome === 'held') return 'already';
      await recordHold(tx, orgId, version + 1, 'HELD', {
        actor: HOLDER,
        action: 'integrity_hold.set',
        details: {
          // From a verified CLEAR, or over a hold that can't be believed.
          statusFrom: check.outcome === 'clear' ? 'CLEAR' : null,
          statusTo: 'HELD',
          reason: finding.sign,
          foundOn: finding.subjectType,
          objectId: finding.objectId,
          ...(finding.chainFailure === undefined ? {} : { chainFailure: finding.chainFailure }),
          findings,
        },
      });
      return 'set';
    },
  });
}
