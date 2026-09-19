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
// and raises the integrity alarm (`audit.integrity_failed`, SEV-1). The
// integrity hold on the organisation joins it when organisations exist (B1).
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
  type SignedStateTable,
  StatusChangeFailed,
  type StatusTable,
  writeSignedRow,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type AuditActor, type AuditDetails, AuditEventRefused } from '../domain/event.ts';
import type { AuditTrail, AuditTransaction, LatestSignedState } from './audit-trail.ts';

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
 */
export type TamperSign = 'row' | 'deleted' | 'unsigned' | 'log' | 'pointer' | 'version' | 'seal' | 'status';

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
 * row never means "no limit", so a hold or a freeze is a status on a row that
 * always exists, never a row whose absence lifts it.
 */
export type StateCheck =
  VerifiedState | { readonly outcome: 'missing' } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

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
}

type FoundRow = Extract<SignedRow, { outcome: 'found' }>;

/** A row this transaction has read: the lock it holds, and the state it may record a change from. */
interface Held {
  lock: RowLock;
  from?: { readonly table: SignedStateTable; readonly state: VerifiedState };
}

const MISSING = Object.freeze({ outcome: 'missing' as const });
/** The status column, which only changeStatus writes on a row that exists. */
const STATUS = 'status';

const sameFields = (row: readonly FieldText[], expected: (column: string) => string | null | undefined): boolean =>
  row.every(([column, value]) => value === expected(column));

/**
 * Build one from the request's or job's logger, a child carrying its
 * correlation ID (Rule Book §8); each alarm adds the organisation. What it
 * knows of each transaction's rows (locks and verified states) is its own:
 * use one for the whole transaction.
 */
export function createSignedStates({
  keys,
  trail,
  logger,
}: {
  readonly keys: KeyProvider;
  readonly trail: AuditTrail;
  readonly logger: Logger;
}): SignedStates {
  const statuses = createStatusChanger({ logger });
  const rowsHeld = new WeakMap<AuditTransaction, Map<string, Held>>();

  const heldIn = (tx: AuditTransaction): Map<string, Held> => {
    const known = rowsHeld.get(tx) ?? new Map<string, Held>();
    rowsHeld.set(tx, known);
    return known;
  };
  const rowName = (table: SignedStateTable, { orgId, id }: SignedRowKey): string =>
    `${table.table}|${orgId.toLowerCase()}|${id.toLowerCase()}`;

  const alarm = (table: SignedStateTable, key: SignedRowKey, sign: TamperSign, seq?: bigint) => {
    logger.child({ orgId: key.orgId }).error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'state',
      reason: sign,
      subjectType: table.subject,
      objectId: key.id,
      ...(seq === undefined ? {} : { seq }),
    });
    return Object.freeze({ outcome: 'tampered' as const, sign });
  };

  /** Raises the alarm and fails: the locked row didn't hold what was just written to it. */
  const notApplied = (table: SignedStateTable, key: SignedRowKey, what: string): never => {
    alarm(table, key, 'row');
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
    if (latest.kind === 'none') return alarm(table, key, 'unsigned');
    if (latest.kind === 'broken') return alarm(table, key, 'log', latest.seq);
    if (row.eventId !== latest.id.toLowerCase()) return alarm(table, key, 'pointer');
    if (row.version !== latest.version) return alarm(table, key, 'version');
    const facts = {
      orgId: key.orgId,
      subject: { type: table.subject, id: key.id, version: row.version },
      fields: row.fields,
    };
    if (!stateSealMatches(keys, facts, latest.seal)) return alarm(table, key, 'seal');
    const eventId = latest.id.toLowerCase();
    return Object.freeze({ outcome: 'verified', version: row.version, eventId, fields: new Map(row.fields) });
  };

  const verifiedState = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    lock: RowLock,
  ): Promise<StateCheck> => {
    const rows = heldIn(tx);
    const name = rowName(table, key);
    const held = rows.get(name);
    if (held?.lock === 'share' && lock === 'change') {
      throw new SignedStateFailed(
        'lock_order',
        "A row read for a decision isn't read again for a change in the same transaction: lock it for the change first (ADR-006 §6)",
      );
    }
    let row = await readSignedRow(tx, table, key, lock);
    rows.set(name, { lock: held?.lock ?? lock, ...(lock === 'share' && held?.from ? { from: held.from } : {}) });
    if (row.outcome === 'unreadable') return alarm(table, key, 'row');
    let latest = await latestOf(tx, table, key);
    if (row.outcome === 'missing') {
      if (latest.kind === 'none') return MISSING;
      if (latest.kind === 'broken') return alarm(table, key, 'log', latest.seq);
      // The row commits with its first event, so with the event in the log,
      // the row is gone, unless it was created since it was read: read again.
      row = await readSignedRow(tx, table, key, lock);
      if (row.outcome === 'missing') return alarm(table, key, 'deleted');
      if (row.outcome === 'unreadable') return alarm(table, key, 'row');
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
    const rows = heldIn(tx);
    const name = rowName(table, key);
    if (from === 'new') {
      const read = await readSignedRow(tx, table, key, 'change');
      if (read.outcome === 'unreadable') {
        alarm(table, key, 'row');
        throw new SignedStateFailed('tampered', 'A row being created is not as the app writes one');
      }
      if (read.outcome !== 'found' || read.version !== 1 || read.eventId !== null) {
        throw new SignedStateFailed('basis', 'A new signed row is at version 1 and points at no event yet');
      }
      if ((await latestOf(tx, table, key)).kind !== 'none') {
        alarm(table, key, 'log');
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
    return Object.freeze({ version: row.version, eventId: recorded.id, seq: recorded.seq });
  };

  return Object.freeze({
    verifiedState,

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
        if (error instanceof StatusChangeFailed) alarm(table, key, 'status');
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
  });
}
