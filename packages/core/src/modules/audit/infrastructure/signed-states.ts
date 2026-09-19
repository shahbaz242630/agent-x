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
// the transaction will change it. A change must commit before a reader can
// lock the row, and it records its event in the same transaction, so a check
// never meets a row and a log from either side of one change.
//
// Every change records the new state: the row moves to its next version, its
// fields are read and sealed, the event goes to the audit chain (ADR-007 §1.3's
// history row, ADR-014 §8) and the row points at it. A change starts from a
// state verified for change in the same transaction, so a field tampered with
// can't be changed and sealed as if it were real. Events about an authority
// object are its state changes only: activity goes against other subjects.
import { sealState, stateSealDetails, stateSealMatches } from '@agentx/platform/audit-chain';
import {
  advanceSignedRow,
  createStatusChanger,
  pointSignedRow,
  readSignedRow,
  type RowLock,
  type SignedRow,
  type SignedRowKey,
  type SignedStateTable,
  StatusChangeFailed,
  type StatusTable,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type AuditActor, type AuditDetails, AuditEventRefused } from '../domain/event.ts';
import type { AuditTrail, AuditTransaction, LatestSignedState } from './audit-trail.ts';

/**
 * Where a row and its signed state part:
 * - `row`: the row can't be read as the app writes it, or, locked for a
 *   change, didn't take its new version or pointer as written
 * - `deleted`: the row is gone but its signed state is in the log (the app
 *   role can't delete)
 * - `unsigned`: the row exists but no event about it carries a seal
 * - `log`: its signed events can't be believed: the latest, or one after it,
 *   fails its own check, or one exists for a row being created
 * - `pointer`: the row points at another event than the latest signed one
 * - `version`: the row's version isn't the latest signed event's
 * - `seal`: the row's fields aren't the ones sealed
 * - `status`: a status change was rewritten on its way into the row
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
 * The row verified; no such row in this organisation; or tampered with, which
 * the caller denies (the alarm is already raised).
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
 * A signed state couldn't be recorded:
 * - `basis`: record was given a state not verified for change in this
 *   transaction for this row (or used once already), or `new` for a row that
 *   isn't new
 * - `not_applied`: the row didn't move or take its pointer as the change
 *   decided (the alarm is raised: the row was locked)
 * - `tampered`: the log already holds a signed state for a row being created
 * The caller's transaction must roll back: throwing out of withTenant does.
 */
export class SignedStateFailed extends Error {
  readonly reason: 'basis' | 'not_applied' | 'tampered';

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
   * Records the row's new state, after the caller changed its fields in this
   * transaction: from `basis`, the state verifiedState gave for change here
   * (each one used once), or `new` for a row the transaction has just
   * inserted at version 1, pointing nowhere. Takes the audit head's lock,
   * which comes last (ADR-006 §6).
   */
  record(
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    basis: VerifiedState | 'new',
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

/** What a verified state was verified for: the transaction and row record may use it on. */
interface Issued {
  readonly tx: AuditTransaction;
  readonly table: string;
  readonly orgId: string;
  readonly id: string;
}

const MISSING = Object.freeze({ outcome: 'missing' as const });

/**
 * Build it from the request's or job's logger, a child carrying its
 * correlation ID (Rule Book §8); each alarm adds the organisation.
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
  /** States verified for change and not yet used, each with where it may be used. */
  const issued = new WeakMap<VerifiedState, Issued>();

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
    let row = await readSignedRow(tx, table, key, lock);
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
    if (checked.outcome === 'verified' && lock === 'change') {
      issued.set(checked, { tx, table: table.table, orgId: key.orgId.toLowerCase(), id: key.id.toLowerCase() });
    }
    return checked;
  };

  /** The row at its new version, from the basis it moves on from. */
  const nextRow = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    basis: VerifiedState | 'new',
  ): Promise<FoundRow> => {
    if (basis === 'new') {
      const row = await readSignedRow(tx, table, key, 'change');
      if (row.outcome !== 'found' || row.version !== 1 || row.eventId !== null) {
        throw new SignedStateFailed('basis', 'A new signed row is at version 1 and points at no event yet');
      }
      if ((await latestOf(tx, table, key)).kind !== 'none') {
        alarm(table, key, 'log');
        throw new SignedStateFailed('tampered', 'The log already holds a signed state for a row being created');
      }
      return row;
    }
    const use = issued.get(basis);
    if (
      use?.tx !== tx ||
      use.table !== table.table ||
      use.orgId !== key.orgId.toLowerCase() ||
      use.id !== key.id.toLowerCase()
    ) {
      throw new SignedStateFailed('basis', 'A change is recorded from a state verified for change on its row, here');
    }
    issued.delete(basis);
    const row = await advanceSignedRow(tx, table, key, basis);
    if (row.outcome !== 'found' || row.version !== basis.version + 1 || row.eventId !== null) {
      // Locked since it was verified, so something past this step changed it.
      alarm(table, key, 'row');
      throw new SignedStateFailed('not_applied', "The row didn't move on from the version it was verified at");
    }
    return row;
  };

  const record = async (
    tx: AuditTransaction,
    table: SignedStateTable,
    key: SignedRowKey,
    basis: VerifiedState | 'new',
    change: SignedChange,
  ): Promise<RecordedState> => {
    if (Object.hasOwn(change.details, 'stateFingerprint') || Object.hasOwn(change.details, 'stateKeyVersion')) {
      throw new AuditEventRefused(['details.stateFingerprint and details.stateKeyVersion are the seal, added here']);
    }
    const row = await nextRow(tx, table, key, basis);
    const subject = { type: table.subject, id: key.id, version: row.version };
    const seal = sealState(keys, { orgId: key.orgId, subject, fields: row.fields });
    const recorded = await trail.record(tx, key.orgId, {
      actor: change.actor,
      action: change.action,
      subject,
      details: { ...change.details, ...stateSealDetails(seal) },
    });
    if (!(await pointSignedRow(tx, table, key, { version: row.version, eventId: recorded.id }))) {
      alarm(table, key, 'row');
      throw new SignedStateFailed('not_applied', "The row didn't take the pointer to its new state's event");
    }
    return Object.freeze({ version: row.version, eventId: recorded.id, seq: recorded.seq });
  };

  return Object.freeze({
    verifiedState,
    record,

    async changeStatus<State extends string, Event extends string>(
      tx: AuditTransaction,
      table: SignedStateTable & StatusTable<State, Event>,
      key: SignedRowKey,
      event: NoInfer<Event>,
      change: SignedChange,
    ): Promise<SignedStatusChange<State>> {
      // An unsealed status could be flipped unseen.
      if (!table.fields.some(({ column }) => column === 'status')) {
        throw new RangeError('A signed status table seals its status');
      }
      const current = await verifiedState(tx, table, key, 'change');
      if (current.outcome !== 'verified') return current;
      const moved = await statuses.change(tx, table, key, event).catch((error: unknown) => {
        // The locked row's update left another status: a trigger at work, past the app.
        if (error instanceof StatusChangeFailed && error.reason === 'not_applied') alarm(table, key, 'status');
        throw error;
      });
      if (moved.outcome === 'refused') return moved;
      if (moved.outcome === 'missing') {
        throw new SignedStateFailed('not_applied', 'The row verified and locked for change was missing when changed');
      }
      const recorded = await record(tx, table, key, current, {
        ...change,
        details: { ...change.details, statusFrom: moved.from, statusTo: moved.to },
      });
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
