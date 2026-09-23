// What our schema is allowed to look like (ADR-005 §6, §8, §9): which tables
// may stand outside the tenant walls and what the app may do to them, what it
// may do in the audit trails' schemas, and the foreign keys that must stay.
//
// **It lives in the product, not in tooling, because two readers need it and
// they must never hold different lists** (the A3c-2 lesson):
//
// - CI-06 checks a freshly migrated database against it on every run
//   (tooling/checks/database-schema.db.test.ts, through @agentx/testing's
//   schemaProblems), as the migration role, on Postgres 16 and 18;
// - the live schema guard checks the **running** database against it, as the
//   app role, at start-up and on every anchor check (A3e-1b). The database is
//   what an owner-level attacker controls, so the expectation has to travel in
//   the image CI signs and the deploy verifies — never in the database itself.
//
// A table is listed under `globalTables` only with a reason and its exact
// columns, so a new global table, or a new column on one, is always a reviewed
// change to this file (SEC-TEN-08). An entry for a table that no longer exists
// fails CI-06, so the list can't go stale; the same holds for the append-only
// exceptions, the fill-in tables and the required foreign keys.

/** The rights on a table's rows the app role can be allowed. */
type RowRight = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';

/** A table with no org_id and no row-level security, allowed by name (ADR-005 §6). */
interface GlobalTable {
  /** Why it can't be a tenant table. */
  readonly reason: string;
  /** Every column it has, exactly: a new column is a reviewed entry (SEC-TEN-08). */
  readonly columns: readonly string[];
  /**
   * Every right the app role may hold on it, on the whole table or any of its
   * columns: nothing it needn't do, since no tenant wall stands behind a
   * global table (B1d-1). Named for every global table outside the
   * append-only schemas, and for none inside them, which their own rule holds
   * (CI-06 checks both).
   */
  readonly appMay?: readonly RowRight[];
}

/**
 * A foreign key the running database must still hold, validated (B1d-1): one a
 * check reaching across organisations rests on, which the owner could drop or
 * switch off without touching a row.
 */
interface RequiredForeignKey {
  /** Why it matters: what could happen without it. */
  readonly reason: string;
  /** The table it runs from, by schema-qualified name as Postgres quotes it. */
  readonly table: string;
  /** Its columns, in order. */
  readonly columns: readonly string[];
  /** The table it points at, named the same way. */
  readonly references: string;
  /** The columns it points at, in the same order. */
  readonly referencedColumns: readonly string[];
}

/** A tenant table the app adds rows to and reads, and changes only in the columns named. */
interface FillInTable {
  /** Why the app needs no more: what a row deleted, or another column changed, would allow. */
  readonly reason: string;
  /** Exactly the columns the app is granted UPDATE on, each on its own (CI-06 checks it). */
  readonly columns: readonly string[];
}

export interface SchemaPolicy {
  /**
   * The global tables, by schema-qualified name as Postgres quotes it
   * (`schema.table`). Every other table is a tenant table.
   */
  readonly globalTables: Readonly<Record<string, GlobalTable>>;
  /** Schemas whose tables the app role may only add to and read, such as the audit trail (SEC-EVD-01). */
  readonly appendOnlySchemas: readonly string[];
  /**
   * Tables in those schemas that the app may also change, by name, each with
   * its reason: a row the app locks and moves on, such as a chain head.
   */
  readonly appendOnlyExceptions: Readonly<Record<string, string>>;
  /**
   * Tenant tables outside those schemas that the app may add rows to and read,
   * and change only in the columns listed, never DELETE, by schema-qualified
   * name as Postgres quotes it: a row filled in once after it is added, such as
   * an idempotency key's result. Any other tenant table allows every row right.
   */
  readonly fillInTables: Readonly<Record<string, FillInTable>>;
  /**
   * Foreign keys that must be there, validated, with their
   * reasons. CI-06 checks each against the migrations; the live schema guard
   * checks the running database still holds it.
   */
  readonly requiredForeignKeys: readonly RequiredForeignKey[];
}

export const SCHEMA_POLICY: SchemaPolicy = {
  globalTables: {
    'directory.orgs': {
      reason:
        "The directory's list of organisations (ADR-005 §6): IDs only, read by work that runs across organisations (the anchor check, the retention sweeps) before it works inside each one's withTenant",
      columns: ['org_id'],
      // Added with its organisation and read; an entry changed or deleted
      // would be an organisation no anchor check or sweep reaches.
      appMay: ['SELECT', 'INSERT'],
    },
    'migrations.applied': {
      reason:
        'The migration ledger (runMigrations): one row per applied file, written only by the migration role at deploy time, never by the app',
      columns: ['name', 'checksum', 'applied_at'],
      appMay: [],
    },
    'platform_controls.audit_events': {
      reason:
        "The platform's own audit chain (ADR-011 §3, ADR-014 §8): events of no organisation, such as each start's config hash (SEC-OPS-05). Append-only for the app",
      columns: [
        'seq',
        'id',
        'recorded_at',
        'actor_type',
        'actor_id',
        'action',
        'details',
        'prev_hash',
        'hash',
        'mac',
        'mac_key_version',
      ],
    },
    'platform_controls.audit_head': {
      reason: "The platform audit chain's one head row, which the app locks and moves on with every event",
      columns: ['only_row', 'seq', 'hash', 'mac', 'mac_key_version'],
    },
  },
  // The audit trails' schemas (ADR-004 §4): the app role may only add audit rows and read them (ADR-005 §9).
  appendOnlySchemas: ['audit', 'platform_controls'],
  appendOnlyExceptions: {
    'audit.heads':
      "Each organisation's chain head: the app locks it and moves it on with every event it records (ADR-006 §6, ADR-011 §3)",
    'platform_controls.audit_head':
      "The platform chain's head: the app locks it and moves it on with every event it records (ADR-006 §6, ADR-011 §3)",
  },
  fillInTables: {
    'idempotency.keys': {
      reason:
        "Each write's idempotency key (ADR-007 §4): the app adds the key and fills in the write's result. A key deleted, or its namespace or hash changed, would let a retry do the write again",
      columns: ['result_status', 'result_id'],
    },
  },
  requiredForeignKeys: [
    {
      reason:
        "An organisation's row points at its directory entry (0008), so no organisation exists that the directory's list leaves out, and so none that the anchor check of every chain never reaches",
      table: 'organizations.organizations',
      columns: ['org_id'],
      references: 'directory.orgs',
      referencedColumns: ['org_id'],
    },
  ],
};
