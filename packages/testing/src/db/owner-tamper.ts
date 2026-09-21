// FX-TAMPER (Security-Test-Catalogue §1) as the database's owner: agentx_owner,
// the role the migration job logs in as, holding none of the app's keys. It is
// no superuser, but it owns every table, so it can do what the app role can't:
// delete a row, move a status the guard refuses by switching the guard off,
// rewrite the audit log's events and its head, add a policy. Row security is
// forced on every tenant table, which binds the owner too, so like anyone
// holding its password it first sets app.org_id to the organisation it is
// after (the S32 probe measured each of these on Postgres 16 and 18).
//
// The scripts are written once for any authority table, from its description
// (the module's SignedStateTable: its table and its subject type), so every
// new table meets the same attacks. What they can't do is what the keys are
// for: seal a state, or MAC an event or a head. Forging an event that is
// otherwise correctly chained needs the chain's hash, which lives in
// @agentx/platform, and this package can't depend on it, so the audit module's
// tests forge it themselves.
import pg from 'pg';

import type { TestClient, TestDatabase } from './test-database.ts';

/** What the scripts need of an authority table: the module's own SignedStateTable fits. */
export interface TamperTarget {
  /** Schema and table, as `schema.table`. */
  readonly table: string;
  /** The type its rows are recorded as in the audit trail. */
  readonly subject: string;
}

/** A row as the owner saved it, every column, to put back later. */
export interface SavedRow {
  readonly id: string;
  readonly columns: Readonly<Record<string, unknown>>;
}

/** The organisation's chain head as the owner saved it: once genuinely sealed by the app. */
export interface SavedHead {
  readonly seq: string;
  readonly hash: Buffer;
  readonly mac: Buffer;
  readonly macKeyVersion: number;
}

export interface OwnerTamper {
  readonly orgId: string;
  /** Runs one statement as the owner, inside the organisation. The text is fixed; values are bound. */
  query<Row extends object = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<Row[]>;
  /** Sets one column of the row: a status flipped, a role raised, a limit edited. */
  setColumn(id: string, column: string, value: string | number | null): Promise<void>;
  /** The row as it is now, to put back once the app has moved it on. */
  saveRow(id: string): Promise<SavedRow>;
  /** Puts every column but the key back as saved: the row rolled back to an older, validly signed state. */
  restoreRow(saved: SavedRow): Promise<void>;
  /** Runs `work` with the table's status guard switched off, then switches it back on, even if `work` fails. */
  withoutStatusGuard<T>(work: () => Promise<T>): Promise<T>;
  /** Deletes the row, which the app role can't. */
  deleteRow(id: string): Promise<void>;
  /** Takes the state seal out of every event about the row, keeping the rest of their details. */
  stripSeals(id: string): Promise<void>;
  /** Deletes every event about the row. */
  deleteEvents(id: string): Promise<void>;
  /** The chain's head as it is now. */
  saveHead(): Promise<SavedHead>;
  /** Deletes every event past a saved head and puts that head back: the chain wound back to an earlier sealed state. */
  windBack(saved: SavedHead): Promise<void>;
  /** Runs `work` with the events hidden from every reader by a policy of the owner's, then drops the policy. */
  withEventsHidden<T>(eventIds: readonly string[], work: () => Promise<T>): Promise<T>;
  /** Closes the owner's connection. */
  end(): Promise<void>;
}

const TABLE_NAME = /^[a-z][a-z0-9_]{0,62}\.[a-z][a-z0-9_]{0,62}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATE_SEAL = ['stateFingerprint', 'stateKeyVersion'] as const;

/** The table's name, quoted part by part, for statements that can't take it as a value. */
function quotedTable(table: string): string {
  if (!TABLE_NAME.test(table)) throw new RangeError('An authority table is named `schema.table`, in lower-case words');
  return table
    .split('.')
    .map((part) => pg.escapeIdentifier(part))
    .join('.');
}

/**
 * Opens a connection as agentx_owner, set to act inside the organisation, for
 * one test's tampering. `end()` closes it; the database's `drop()` does if the
 * test doesn't.
 */
export async function tamperAsOwner(database: TestDatabase, target: TamperTarget, orgId: string): Promise<OwnerTamper> {
  if (!UUID.test(orgId)) throw new RangeError('The organisation ID must be a UUID');
  const table = quotedTable(target.table);
  const owner: TestClient = await database.connect('owner');
  await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [orgId]);

  const aboutRow = (id: string) => [orgId, target.subject, id];

  return Object.freeze({
    orgId,
    query: <Row extends object>(text: string, values: readonly unknown[] = []) =>
      // eslint-disable-next-line agentx/no-string-built-sql -- This passes on the caller's text; the rule checks it where the caller writes `.query(...)`.
      owner.query<Row>(text, values),

    async setColumn(id: string, column: string, value: string | number | null) {
      // A column can't be a bound value: it is the table's own, quoted with escapeIdentifier.
      // eslint-disable-next-line agentx/no-string-built-sql -- The table and column are quoted, as the line above says.
      const statement = `update ${table} set ${pg.escapeIdentifier(column)} = $3 where org_id = $1 and id = $2`;
      // eslint-disable-next-line agentx/no-string-built-sql -- The statement is built just above, from quoted names only.
      await owner.query(statement, [orgId, id, value]);
    },

    async saveRow(id: string) {
      // eslint-disable-next-line agentx/no-string-built-sql -- The table is quoted by quotedTable.
      const statement = `select pg_catalog.to_jsonb(t) as saved from ${table} t where t.org_id = $1 and t.id = $2`;
      // eslint-disable-next-line agentx/no-string-built-sql -- The statement is built just above, from the quoted table only.
      const rows = await owner.query<{ saved: Record<string, unknown> }>(statement, [orgId, id]);
      const saved = rows[0]?.saved;
      if (saved === undefined) throw new Error('The owner found no such row to save');
      return Object.freeze({ id, columns: saved });
    },

    async restoreRow(saved: SavedRow) {
      const columns = Object.keys(saved.columns)
        .filter((column) => column !== 'org_id' && column !== 'id')
        .map((column) => pg.escapeIdentifier(column));
      const list = columns.join(', ');
      const from = columns.map((column) => `r.${column}`).join(', ');
      // eslint-disable-next-line agentx/no-string-built-sql -- The table is quoted by quotedTable, and each column by escapeIdentifier.
      await owner.query(
        `update ${table} as t set (${list}) = row(${from})
         from pg_catalog.jsonb_populate_record(null::${table}, $3::jsonb) as r
         where t.org_id = $1 and t.id = $2`,
        [orgId, saved.id, JSON.stringify(saved.columns)],
      );
    },

    async withoutStatusGuard<T>(work: () => Promise<T>): Promise<T> {
      // eslint-disable-next-line agentx/no-string-built-sql -- The table is quoted by quotedTable.
      await owner.query(`alter table ${table} disable trigger status_guard`);
      try {
        return await work();
      } finally {
        // eslint-disable-next-line agentx/no-string-built-sql -- The table is quoted by quotedTable.
        await owner.query(`alter table ${table} enable trigger status_guard`);
      }
    },

    async deleteRow(id: string) {
      // eslint-disable-next-line agentx/no-string-built-sql -- The table is quoted by quotedTable.
      await owner.query(`delete from ${table} where org_id = $1 and id = $2`, [orgId, id]);
    },

    async stripSeals(id: string) {
      await owner.query(
        `update audit.events set details = ((details::jsonb - $4::text) - $5::text)::text
         where org_id = $1 and subject_type = $2 and subject_id = $3`,
        [...aboutRow(id), ...STATE_SEAL],
      );
    },

    async deleteEvents(id: string) {
      await owner.query('delete from audit.events where org_id = $1 and subject_type = $2 and subject_id = $3', [
        ...aboutRow(id),
      ]);
    },

    async saveHead() {
      const rows = await owner.query<{ seq: string; hash: Buffer; mac: Buffer; mac_key_version: number }>(
        'select seq::text as seq, hash, mac, mac_key_version from audit.heads where org_id = $1',
        [orgId],
      );
      const head = rows[0];
      if (head === undefined) throw new Error('The owner found no chain head to save');
      return Object.freeze({ seq: head.seq, hash: head.hash, mac: head.mac, macKeyVersion: head.mac_key_version });
    },

    async windBack(saved: SavedHead) {
      await owner.query('delete from audit.events where org_id = $1 and seq > $2::bigint', [orgId, saved.seq]);
      await owner.query(
        'update audit.heads set seq = $2::bigint, hash = $3, mac = $4, mac_key_version = $5 where org_id = $1',
        [orgId, saved.seq, saved.hash, saved.mac, saved.macKeyVersion],
      );
    },

    async withEventsHidden<T>(eventIds: readonly string[], work: () => Promise<T>): Promise<T> {
      if (eventIds.length === 0 || !eventIds.every((id) => UUID.test(id))) {
        throw new RangeError('The events to hide are named by their UUIDs');
      }
      // A policy can't take bound values; each ID is a UUID, checked above.
      const hidden = eventIds.map((id) => `'${id}'::uuid`).join(', ');
      // eslint-disable-next-line agentx/no-string-built-sql -- Each ID in the list is checked to be a UUID above.
      await owner.query(`create policy tamper_hides on audit.events as restrictive using (id not in (${hidden}))`);
      try {
        return await work();
      } finally {
        await owner.query('drop policy tamper_hides on audit.events');
      }
    },

    end: () => owner.end(),
  });
}
