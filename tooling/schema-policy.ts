import type { SchemaPolicy } from '../packages/testing/src/index.ts';

/**
 * CI-06's decisions about our schema (ADR-005 §6, §8, §9), checked on every
 * run against db/migrations (tooling/checks/database-schema.db.test.ts).
 *
 * Every table not listed under `globalTables` is a tenant table and must carry
 * the tenant walls. A table is listed only with a reason and its exact
 * columns, so a new global table, or a new column on one, is always a reviewed
 * change to this file (SEC-TEN-08). An entry for a table that no longer exists
 * fails the check, so the list can't go stale; the same holds for the
 * append-only exceptions.
 */
export const SCHEMA_POLICY: SchemaPolicy = {
  globalTables: {
    'migrations.applied': {
      reason:
        'The migration ledger (runMigrations): one row per applied file, written only by the migration role at deploy time, never by the app',
      columns: ['name', 'checksum', 'applied_at'],
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
};
