// A status change on one row (ADR-007 §1.2), the same way for every table
// with a status: lock the row (`FOR NO KEY UPDATE`, ADR-006 §6), decide the
// move with the object's state machine, then compare and set: update the row
// only while it still holds the status the move was decided from.
//
// The SQL is written once here rather than in each module, so the lock mode
// and the compare-and-set can't be got wrong table by table. The module gives
// its table's name, a constant, and its machine; the change runs in the
// module's own transaction (withTenant), in the lock order's place for that
// object. Tables with a status have `org_id`, `id` and `status` columns, a
// key on (org_id, id), and the status guard (db/migrations/0004), which
// refuses any move the machine doesn't list, whoever writes it.
//
// The row is locked before it is read, so no other transaction can change it
// between the decision and the update. An update that then changes nothing
// means something past the app is at work on the row (a trigger, say), so it
// is an error, not a race to retry. While the lock holds, the update's
// `status = from` can't miss; it is kept (ADR-007's compare-and-set) so that a
// change which ever lost its lock would fail loudly rather than overwrite.
import { sql, type Transaction } from 'kysely';

import type { Logger } from '../observability/index.ts';

/** What a status change needs of a state machine: the shared-kernel's defineStateMachine gives one. */
export interface StatusRules<State extends string, Event extends string> {
  readonly name: string;
  transition(
    from: string,
    event: Event,
  ):
    | { readonly ok: true; readonly from: State; readonly to: State }
    | { readonly ok: false; readonly problem: 'not_allowed'; readonly from: State }
    | { readonly ok: false; readonly problem: 'unknown_state' };
}

/** A table with a status, and the machine that rules it: a constant in the module that owns the table. */
export interface StatusTable<State extends string, Event extends string> {
  /** Schema and table, as `schema.table`, in lower-case words. */
  readonly table: string;
  readonly rules: StatusRules<State, Event>;
}

/** The row: its organisation and its own ID. */
export interface StatusKey {
  readonly orgId: string;
  readonly id: string;
}

/**
 * What happened: the move made; refused, because the machine doesn't allow
 * the event from the row's status; or no such row in this organisation.
 */
export type StatusChange<State extends string> =
  | { readonly outcome: 'changed'; readonly from: State; readonly to: State }
  | { readonly outcome: 'refused'; readonly from: State }
  | { readonly outcome: 'missing' };

/**
 * The change couldn't be made, and nothing was changed:
 * - `bad_key`: the organisation or row ID isn't a UUID
 * - `unreadable`: the stored status isn't one of the machine's, or more than
 *   one row has the key; either means someone past the app changed the table
 * - `not_applied`: the locked row's update changed nothing (see above)
 */
export class StatusChangeFailed extends Error {
  readonly reason: 'bad_key' | 'unreadable' | 'not_applied';

  constructor(reason: StatusChangeFailed['reason'], message: string) {
    super(message);
    this.name = 'StatusChangeFailed';
    this.reason = reason;
  }
}

export interface StatusChanger {
  /**
   * Makes `event`'s move on the row, in the caller's transaction, which must
   * be withTenant's for the row's organisation: in any other, row security
   * hides the row and the answer is `missing`. The row's lock is held to the
   * end of the transaction.
   */
  change<Schema, State extends string, Event extends string>(
    tx: Transaction<Schema>,
    table: StatusTable<State, Event>,
    key: StatusKey,
    event: Event,
  ): Promise<StatusChange<State>>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * Schema and table in lower-case words: names from our migrations, never from
 * input. Checked on every change, since the name goes into the SQL as a name,
 * quoted, rather than as a bound value.
 */
const TABLE = /^[a-z][a-z0-9_]{0,62}\.[a-z][a-z0-9_]{0,62}$/;

export function createStatusChanger({ logger }: { readonly logger: Logger }): StatusChanger {
  return Object.freeze({
    async change<Schema, State extends string, Event extends string>(
      tx: Transaction<Schema>,
      { table, rules }: StatusTable<State, Event>,
      { orgId, id }: StatusKey,
      event: Event,
    ): Promise<StatusChange<State>> {
      if (!TABLE.test(table)) throw new RangeError('A status table is named schema.table, in lower-case words');
      if (!UUID.test(orgId) || !UUID.test(id)) {
        throw new StatusChangeFailed('bad_key', 'A status change needs the organisation and row IDs as UUIDs');
      }
      const log = logger.child({ orgId });
      const facts = { machine: rules.name, statusEvent: event, objectId: id };

      const { rows } = await sql<{ status: unknown }>`
        select status from ${sql.table(table)} where org_id = ${orgId} and id = ${id} for no key update
      `.execute(tx);
      const [row, ...others] = rows;
      if (row === undefined) {
        log.info('status.row_missing', facts);
        return { outcome: 'missing' };
      }
      const decided =
        typeof row.status === 'string' && others.length === 0 ? rules.transition(row.status, event) : undefined;
      if (decided === undefined || (!decided.ok && decided.problem === 'unknown_state')) {
        log.error('status.unreadable', facts);
        throw new StatusChangeFailed(
          'unreadable',
          `A ${rules.name} row holds a status its state machine doesn't have, or its key isn't unique`,
        );
      }
      if (!decided.ok) {
        log.info('status.change_refused', { ...facts, from: decided.from });
        return { outcome: 'refused', from: decided.from };
      }

      const { from, to } = decided;
      // The alias keeps the text after the table name from starting with SET,
      // which the lint rule against session-wide settings would take for one.
      const updated = await sql`
        update ${sql.table(table)} as target set status = ${to}
        where org_id = ${orgId} and id = ${id} and status = ${from}
      `.execute(tx);
      if (updated.numAffectedRows !== 1n) {
        log.error('status.change_not_applied', { ...facts, from, to });
        throw new StatusChangeFailed('not_applied', `The locked ${rules.name} row's status update changed nothing`);
      }
      log.info('status.changed', { ...facts, from, to });
      return { outcome: 'changed', from, to };
    },
  });
}
