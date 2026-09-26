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
import { sealState, stateSealDetails, stateSealMatches } from '@agentx/platform/audit-chain';
import {
  createStatusChanger,
  type FieldText,
  pointSignedRow,
  readSignedRow,
  type RowLock,
  type SignedFieldValues,
  type SignedRow,
  type SignedRowKey,
  signedRowIds,
  type SignedStateTable,
  StatusChangeFailed,
  type StatusTable,
  writeSignedRow,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type AuditActor, type AuditDetails, AuditEventRefused } from '../domain/event.ts';
import {
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
  type LatestSignedState,
  lockChainHead,
  type RecordedEventCheck,
  recordHoldEvent,
  TooManyEventsAboutObject,
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
 */
export type TamperSign = 'row' | 'deleted' | 'unsigned' | 'log' | 'pointer' | 'version' | 'seal' | 'status' | 'chain';

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

/** The row's state, matched with its latest signed event. */
export interface VerifiedState {
  readonly outcome: 'verified';
  readonly version: number;
  readonly eventId: string;
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
 * Every object of the tables checked (verifyAll): all verified, with how many
 * there were; some tampered with, each finding named (every alarm is already
 * raised); or more objects in one table than the limit, with none judged.
 */
export type OrganisationCheck =
  | { readonly outcome: 'verified'; readonly objects: number }
  | { readonly outcome: 'tampered'; readonly findings: readonly TamperFinding[] }
  | { readonly outcome: 'too_many'; readonly subjectType: string };

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
export type SignedStatusChange<State extends string> =
  | {
      readonly outcome: 'changed';
      readonly from: State;
      readonly to: State;
      readonly version: number;
      readonly eventId: string;
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

export interface SignedStates {
  /**
   * The row's state, verified against the log (ADR-012 §2), in the caller's
   * transaction, which must be withTenant's for the row's organisation. The
   * row stays locked as asked to the end of the transaction.
   */
  verifiedState(tx: AuditTransaction, table: SignedStateTable, key: SignedRowKey, lock: RowLock): Promise<StateCheck>;
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
   * table: `too_many`, with nothing more judged.
   */
  verifyAll(
    tx: AuditTransaction,
    orgId: string,
    tables: readonly SignedStateTable[],
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
}

const MISSING = Object.freeze({ outcome: 'missing' as const });
const MISSING_HOLD = Object.freeze({ outcome: 'not_held' as const });

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
  unrecorded = () => undefined,
}: {
  readonly keys: KeyProvider;
  readonly trail: AuditTrail;
  readonly logger: Logger;
  readonly onTamper: (finding: TamperFinding) => void;
  /** The finding of a hold this process couldn't record yet for the organisation, if one is waiting. */
  readonly unrecorded?: (orgId: string) => TamperFinding | undefined;
}): HoldingSignedStates {
  const statuses = createStatusChanger({ logger });
  const rowsHeld = new WeakMap<AuditTransaction, Map<string, Held>>();
  /** Organisations whose own row each transaction has created, whose hold it may start. */
  const created = new WeakMap<AuditTransaction, Set<string>>();
  /** Transactions holding their chain head's lock, after which no row is locked (ADR-006 §6). */
  const headLocked = new WeakSet<AuditTransaction>();

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

  /** The row matched with the log's latest signed event for it. */
  const compare = (
    table: SignedStateTable,
    key: SignedRowKey,
    row: FoundRow,
    latest: LatestSignedState,
  ): StateCheck => {
    if (latest.kind === 'none') return alarm(table.subject, key, 'unsigned');
    if (latest.kind === 'broken') return alarm(table.subject, key, 'log', latest.seq);
    if (row.eventId !== latest.id.toLowerCase()) return alarm(table.subject, key, 'pointer');
    if (row.version !== latest.version) return alarm(table.subject, key, 'version');
    const facts = {
      orgId: key.orgId,
      subject: { type: table.subject, id: key.id, version: row.version },
      fields: row.fields,
    };
    if (!stateSealMatches(keys, facts, latest.seal)) return alarm(table.subject, key, 'seal');
    const eventId = latest.id.toLowerCase();
    return Object.freeze({ outcome: 'verified', version: row.version, eventId, fields: new Map(row.fields) });
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
    if (held?.lock === 'share' && lock === 'change') throw lockOrder();
    if (held === undefined && headLocked.has(tx)) {
      throw new SignedStateFailed(
        'lock_order',
        "A row is locked before the chain head, never after it (ADR-006 §6): read the integrity hold with lock 'head' last",
      );
    }
    let row = await readSignedRow(tx, table, key, lock);
    rows.set(name, { lock: held?.lock ?? lock, ...(lock === 'share' && held?.from ? { from: held.from } : {}) });
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
    const checked = compare(table, key, row, latest);
    if (checked.outcome === 'verified' && lock === 'change') rows.set(name, { lock, from: { table, state: checked } });
    return checked;
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
    if (from === 'new') {
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

  const recordChange = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    from: VerifiedState | 'new',
    set: SignedFieldValues,
    change: SignedChange,
  ): Promise<RecordedState> => {
    if (Object.hasOwn(change.details, 'stateFingerprint') || Object.hasOwn(change.details, 'stateKeyVersion')) {
      throw new AuditEventRefused(['details.stateFingerprint and details.stateKeyVersion are the seal, added here']);
    }
    const row = await written(tx, table, key, from, set);
    const subject = { type: table.subject, id: key.id, version: row.version };
    const seal = sealState(keys, { orgId: key.orgId, subject, fields: row.fields });
    const recorded = await trail.record(tx, key.orgId, {
      actor: change.actor,
      action: change.action,
      subject,
      details: { ...change.details, ...stateSealDetails(seal) },
    });
    const pointed = await pointSignedRow(tx, table, key, { version: row.version, eventId: recorded.id });
    const sealed = new Map(row.fields);
    if (
      pointed.outcome !== 'found' ||
      pointed.version !== row.version ||
      pointed.eventId !== recorded.id.toLowerCase() ||
      !sameFields(pointed.fields, (column) => sealed.get(column))
    ) {
      return notApplied(table, key, "The row didn't take the pointer to its new state's event as sealed");
    }
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

  return Object.freeze({
    verifiedState,

    async verifyAll(
      tx: AuditTransaction,
      orgId: string,
      tables: readonly SignedStateTable[],
      limit: number,
    ): Promise<OrganisationCheck> {
      const findings: TamperFinding[] = [];
      let objects = 0;
      for (const table of tables) {
        notTheHold(table);
        const rowIds = await signedRowIds(tx, table, orgId, limit);
        const loggedIds = await trail.subjectIds(tx, orgId, table.subject, limit);
        const every = [...new Set([...rowIds, ...loggedIds])].sort();
        if (every.length > limit) return Object.freeze({ outcome: 'too_many', subjectType: table.subject });
        for (const id of every) {
          const key = { orgId, id };
          const check = await verifiedState(tx, table, key, 'share');
          // Listed, as a row or in the log, yet neither a row nor a signed state now: deleted, its seals with it.
          const found = check.outcome === 'missing' ? alarm(table.subject, key, 'deleted') : check;
          if (found.outcome === 'tampered') {
            findings.push(
              Object.freeze({ orgId: orgId.toLowerCase(), subjectType: table.subject, objectId: id, sign: found.sign }),
            );
          }
          objects += 1;
        }
      }
      if (findings.length > 0) return Object.freeze({ outcome: 'tampered', findings: Object.freeze(findings) });
      return Object.freeze({ outcome: 'verified', objects });
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
      // An unsealed status could be flipped unseen.
      if (!table.fields.some(({ column }) => column === STATUS)) {
        throw new RangeError('A signed status table seals its status');
      }
      const current = await verifiedState(tx, table, key, 'change');
      if (current.outcome !== 'verified') return current;
      const moved = await statuses.change(tx, table, key, event).catch((error: unknown) => {
        // The row is verified and locked: its status can't be unreadable or
        // left unchanged unless something past the app is at work on it.
        if (error instanceof StatusChangeFailed) alarm(table.subject, key, 'status');
        throw error;
      });
      if (moved.outcome === 'refused') return moved;
      if (moved.outcome === 'missing') {
        return notApplied(table, key, 'The row verified and locked for change was missing when changed');
      }
      const recorded = await recordChange(
        tx,
        table,
        key,
        current,
        { [STATUS]: moved.to },
        { ...change, details: { ...change.details, statusFrom: moved.from, statusTo: moved.to } },
      );
      return Object.freeze({
        outcome: 'changed',
        from: moved.from,
        to: moved.to,
        version: recorded.version,
        eventId: recorded.eventId,
      });
    },

    integrityHold,

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

    async holdInvestigation(tx: AuditTransaction, orgId: string, id: string): Promise<InvestigationCheck> {
      const found = await trail.recordedEvent(tx, orgId, { onlyAbout: { type: INVESTIGATION_SUBJECT, id } });
      if (found.kind === 'none') return MISSING;
      if (found.kind === 'broken') return alarm(INVESTIGATION_SUBJECT, { orgId, id }, 'log', found.seq);
      const investigation = investigationIn(found);
      return investigation === undefined ? MISSING : Object.freeze({ outcome: 'found', investigation });
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
