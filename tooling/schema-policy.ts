import type { SchemaPolicy } from '../packages/testing/src/index.ts';

/**
 * CI-06's decisions about our schema (ADR-005 §6, §8, §9), checked on every
 * run against db/migrations (tooling/checks/database-schema.db.test.ts).
 *
 * Every table not listed under `globalTables` is a tenant table and must carry
 * the tenant walls. A table is listed only with a reason and its exact
 * columns, so a new global table, or a new column on one, is always a reviewed
 * change to this file (SEC-TEN-08). An entry for a table that no longer exists
 * fails the check, so the list can't go stale.
 */
export const SCHEMA_POLICY: SchemaPolicy = {
  globalTables: {
    'migrations.applied': {
      reason:
        'The migration ledger (runMigrations): one row per applied file, written only by the migration role at deploy time, before any organisation exists',
      columns: ['name', 'checksum', 'applied_at'],
    },
  },
  // The audit module's schema (ADR-004 §4): the app role may only add audit rows and read them (ADR-005 §9).
  appendOnlySchemas: ['audit'],
};
